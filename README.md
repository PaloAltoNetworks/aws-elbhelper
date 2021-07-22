This repository is archived as it reflects an older use case that is no longer relevant.

### ELBHelper
Elb helper is a targeted Python application that monitors changes in the ELB VIPs and updates NAT firewall rule 
if necessary.
This project is part 2 of Amazon security competency.

### Requirements
- 2 firewalls in 2 AWS zones
- 2 DP interfaces per firewall configured as Layer3 DHCP clients
- 2 layer 3 security zones 'external' and 'internal'
- ethernet1/1 member of 'external' and ethernet1/2 member of 'internal' zone
- security rule that permits service-http from external to internal
- must have FW1-eth1 address object defined that point to Firewall's eth1 private IP (This is used in the NAT rule ansembly).

#### Notes
- all Firewall must have and share the same password
- for 'poor-man-HA' must have 'aws' profile set in 
    >~/.aws/credentials
- MUST EDIT THE FOLLOWING ACCORDING TO YOUR ENVIRONMENT
    >vim ~/elbhelper/config/defaults.py
