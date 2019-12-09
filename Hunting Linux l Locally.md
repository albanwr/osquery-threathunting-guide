# Linux Threathunting 101

This is simple guide to finding threats with osquery, based on my personal experience and modelled with active adversary simulation. This is designed to be a gentle slope into using OSQuery hunting and is a work in progress. 

## Enumeration

In order to begin hunting we need to understand the estate, the operating systems and the workloads. This aspect of managing your hosts and assets is important before beginning a hunt, we need to evaluate where our biggest risk is. 

Let's work out what we are working with:
```
select * from kernel_info; 
```
The Kernel info can be a little obtuse sometimes, let's check the operating system version table
```
select * from os_version; 
```
Let's look at the networks available to us (Hides loopback addresses)
```
select * from interface_addresses where interface <> "lo"; 
```

```
select cpu_brand, cpu_logical_cores, cpu_physical_cores, physical_memory 
from system_info;  
```

## Processes
Parent relationships are important to understand where a process spawned from
- Who ran it
- What was the context for it running?
- EDR

Let's find our process: 
```
select * from processes where name LIKE 'osqueryi%';
```

Let's find a process:
```
select pid, parent, name from processes;
```


Choose a pid of a process that looks interesting, with this can we create a nice basic EDR visualization:
```
WITH RECURSIVE rc(pid, parent, name) AS (
select pid, parent, name from processes WHERE pid = 447 UNION ALL
select p.pid, p.parent, p.name from processes AS p, rc WHERE p.pid = rc.parent
AND p.pid != 0 )
select pid, parent, name from rc LIMIT 20;
```
The output might look like this:

```
+-----+--------+---------+
| pid | parent | name    |
+-----+--------+---------+
| 447 | 1      | Siri    |
| 1   | 0      | launchd |
+-----+--------+---------+
```
We now know that launchd is the parent process for Siri. Find another process and try again.

One useful feature of threathunting using OSQuery is being able to list files and processes and examine their hashes.


Let's list out processes and get their hash so we can check the hash against VirusTotal. This is a simple check for standard issues but would be best scripted. 

```
select DISTINCT h.md5, p.name, u.username from processes AS p
INNER JOIN hash AS h ON h.path = p.path INNER JOIN users AS u ON u.uid = p.uid ORDER BY start_time DESC
LIMIT 5;
```
```
+----------------------------------+-------------------------+------------+
| md5                              | name                    | username   |
+----------------------------------+-------------------------+------------+
| 9c9ff84037527292f71ad2eace9df2cf | Slack Helper (GPU)      | craigjones |
| cf5bc6ced6cb920652cab38b96900b57 | Slack Helper (Renderer) | craigjones |
| c88802d42eaad7e1bd852b01f1bd8ef0 | Slack                   | craigjones |
| 0f577b720837e8d46a72922727d45b17 | mdworker_shared         | craigjones |
| f175ce860aa15024ba61a5367478b4aa | osqueryd                | craigjones |
+----------------------------------+-------------------------+------------+
```


Finding processes that are running whose binary has been deleted from the disk, attackers will often leave a malicious process running but delete the original binary. This query returns any process whose original binary has been deleted or modified (which could be an indicator of a suspicious process).
```
select name, path, pid from processes WHERE on_disk = 0;
```

Next we'll try a similar query:
```
select ps.pid, ps.name, ps.path, ps.cwd, ps.parent, ps.cmdline, pe.value AS env_path from processes AS ps LEFT JOIN process_envs AS pe ON ps.pid=pe.pid AND pe.key='PATH' ORDER BY ps.pid LIMIT 20;
```
This gives a similar result but includes the cmd path too. 

Lets find  processes are using all of our memory?
```
select pid, name, path, resident_size from processes; 
```
## Network
```
select DISTINCT process.name, listening.port, listening.address, process.pid from processes AS process JOIN listening_ports AS listening ON process.pid = listening.pid;

```
```
+----------------------------+-------+-----------+------+
| name                       | port  | address   | pid  |
+----------------------------+-------+-----------+------+
| UserEventAgent             | 0     |           | 300  |
| secd                       | 0     |           | 304  |
| rapportd                   | 49158 | 0.0.0.0   | 307  |
| rapportd                   | 49158 | ::        | 307  |
| rapportd                   | 0     | 0.0.0.0   | 307  |

```
Let's find processes that are listening on known ports and see if they deviate from the known expected port, in this example we’ll look for systems that have processes listening on port 22, in reality we should only have sshd. In some cases the attacker will hide running processes listening on standard ports, if an unusual service is listening on a port >1024 you can be sure that the attacker has root level access:
```
select DISTINCT processes.name, listening_ports.port, processes.pid from listening_ports JOIN processes USING (pid) WHERE listening_ports.port= '22'; 
```
On endpoints with well-defined behavior, the security team can use osquery to find any processes that do not fit within whitelisted network behavior, e.g. a process scp’ing traffic externally when it should only perform HTTP(s) connections outbound

```
select s.pid, p.name, local_address, remote_address, family, protocol, local_port, remote_port from process_open_sockets s join processes p on s.pid = p.pid where remote_port not in (80, 443) and family = 2;
```
All processes where the remote port is 443
```
select processes.pid, processes.name, remote_address, remote_port from process_open_sockets LEFT JOIN processes ON processes.pid = process_open_sockets.pid WHERE remote_address <> '' AND remote_address != '::' AND remote_address != '127.0.0.1' AND remote_address != '0.0.0.0' AND remote_port = 443 LIMIT 10;
```
Which should give us an output like this
```
+-----+----------------------+----------------+-------------+
| pid | name                 | remote_address | remote_port |
+-----+----------------------+----------------+-------------+
| 310 | cloudd               | 17.248.147.106 | 443         |
| 318 | nsurlsessiond        | 17.248.147.49  | 443         |
| 366 | Google Chrome Helper | 140.82.113.26  | 443         |
| 366 | Google Chrome Helper | 3.121.249.230  | 443         |
| 366 | Google Chrome Helper | 140.82.113.26  | 443         |
+-----+----------------------+----------------+-------------+
```

## Users
Who's logged into my host right now?
```
select * from logged_in_users; 
```
You'll get an output like this:
```
+------+------------+---------+------+------------+------+
| type | user       | tty     | host | time       | pid  |
+------+------------+---------+------+------------+------+
| user | craigjones | console |      | 1574804445 | 159  |
| user | craigjones | ttys000 |      | 1574804450 | 396  |
| user | craigjones | ttys001 |      | 1574808483 | 1190 |
+------+------------+---------+------+------------+------+

```
Who was logged into the host recently.?
```
select * from last;

```
List shadow users
```
select * from shadow;
```

## Keys

Let's find ssh keys on the host, this is a good exercise to see if people are keeping private keys on a server. This also allows us to see if people are using private keys 

```
select * from user_ssh_keys; 
select * from authorized_keys;
```


## Commands

Let's see what commands have been run
```
select * from shell_history LIMIT 20;
```
You'll get an output like this:
```
+-----+------+-----------------------------------------------------------------------------------------------------+--------------------------------+
| uid | time | command                                                                                             | history_file                   |
+-----+------+-----------------------------------------------------------------------------------------------------+--------------------------------+
| 501 | 0    | osqueryi                                                                                            | /Users/craigjones/.zsh_history |
| 501 | 0    | cd Downloads                                                                                        | /Users/craigjones/.zsh_history |
| 501 | 0    | ls                                                                                                  | /Users/craigjones/.zsh_history |
| 501 | 0    | cd Linux                                                                                            | /Users/craigjones/.zsh_history |
| 501 | 0    | ls                                                                                                  | /Users/craigjones/.zsh_history |
| 501 | 0    | ls -la                                                                                              | /Users/craigjones/.zsh_history |
```
Let's focus on commands that have been run as root
```
select * from shell_history WHERE uid=0 LIMIT 10; 
```

Next, let's see what's been scheduled on this host
```
select * from crontab; 
```
Finding new kernel modules that have loaded
Running this query periodically and diffing against older results can yield whether or not a new kernel module has loaded: kernel modules can be checked against a whitelist/blacklist and any changes can be scrutinized for rootkits.
```
select name from kernel_modules;
```
## Filesystem
Let's investigate folders in /etc/, each /% that we add to the query path will interate through another level of 
```
select * from file WHERE path LIKE '/etc/%'; 
```
Further help - https://osquery.readthedocs.io/

## Vulnerabilities
 On Linux we can query to see what repos are being used
- Which can show us what packages are installed
- We can see this information across all assets and know what's available to update cross platform
- Comparing versions
- Same can be done with NPM and python packages (if you have developers on staff)
- we could generate a query which pulls data from CVDB, exploit DB etc
- Same can be done with NPM and python packages (if you have devs)

```
select name, bundle_name, bundle_version from apps ORDER BY last_opened_time DESC LIMIT 5;
```
Increasing the limit can give us a wider view of the applications listed on the system. Look for bundle versions that are different to other systems of the same Operating System type and version. 

One example that I’d seen personally was a single system that had an older version of the sshd (SSH Daemon) listed, this binary was a trojanized version that was designed to push out any login and password in clear text to a hidden file as users logged into the server. 





## Application loads

Are we running apache?
```
select p.name, p.cmdline, u.username from processes p join users u
ON p.uid = u.uid where name like "%apache%";  
```
What files do we have under /var/www?
```
select * from file where path like ”/var/www/%";  
```
