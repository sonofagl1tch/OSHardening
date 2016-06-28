# OSHardening
This repo contains all of my OS hardening scripts

## SANS FOR518
This directory contains a snippet of my larger OS hardening scripts for the SANS FOR518 class. These changes are specific to OSX bashrc additional logging configuration.
- AdditionalOSXAppsIUse.csv
 - CSV list of the tools i install on a fresh OSX build to make my life easier 
- OSX_BashHistory_logging.sh
 - added additional logic to check if script is running with elevated privs or not. Script will now exit if it is not running with root privs.

## Centos 6
- CIS_Centos6_Audit.sh
 - This script will audit a centos 6 system and give you a CIS compliance score based on it's findings.
- CIS_Centos6_Hardening.sh 
 - This script will harden a fresh build Centos 6 minimal system to CIS compliance.

#### Additional Security Configurations
These are additional security configuration changes that i suggest be made to centos/RHEL linux systems. I have included these outside of the CIS hardening script in the event that you do not want to use CIS for compliance but want some benefits of locking down your system anyways.

- AdditionalSecurityLogging.sh
 - modifies bashrc for additional logging configurations that i have found useful
- ConfigureIptables.sh
 - Configures iptables to defend against common attacks
- ConfigureSSH.sh
 - Configures the SSH server for most common hardening settings

 
