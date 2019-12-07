# DeepSec 2019 Threat hunting and IR

Here's the exercises for the labs.


## ComplementaryResources

- https://kolide.com/ - Our interface of choice.
- https://github.com/OktaSecurityLabs/sgt - Large scale AWS orchestrated OSQuery.
- https://github.com/mwielgoszewski/doorman – Doorman is an open source fleet management solution for osquery for large scale.
- https://osquery.io/docs/packs/ - osquery packs; Bundled queries for detecting common threats (provided by Facebook)

## Alternatives
osquery isn’t by any means the only way of gathering this information and performing these kinds of detailed endpoint checks. There are other techniques and tools in the open source and commercial world, a few of which are listed below (Google for EDR tools to see more commercial ones). Some of these use a ‘continuous recording’ approach, while others are polling-oriented.

Auditd (Open Source, Linux only, continuous only)
OSSEC (Some continuous support (filesystem checks) and some polling only, e.g. will periodically query netstat (network state information) to check for new ports)
Querying the /proc filesystem directly (Linux only)
Sysdig (Linux only, commercial + open source, requires kernel module)
Threat Stack (commercial, continuous only, Linux only)

## More Reading & Other Resources

