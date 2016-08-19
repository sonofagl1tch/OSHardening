# OSHardening
This repo contains all of my OS hardening scripts

## SANS FOR518
This directory contains a snippet of my larger OS hardening scripts for the SANS FOR518 class. These changes are specific to OSX bashrc additional logging configuration.
- AdditionalOSXAppsIUse.csv
 - CSV list of the tools i install on a fresh OSX build to make my life easier
- OSX_BashHistory_logging.sh
 - added additional logic to check if script is running with elevated privs or not. Script will now exit if it is not running with root privs.

## Linux
### Centos 6
- CIS_Centos6_Audit.sh
 - This script will audit a centos 6 system and give you a CIS compliance score based on it's findings.
- CIS_Centos6_Hardening.sh
 - This script will harden a fresh build Centos 6 minimal system to CIS compliance.

### Additional Security Configurations
These are additional security configuration changes that i suggest be made to centos/RHEL linux systems. I have included these outside of the CIS hardening script in the event that you do not want to use CIS for compliance but want some benefits of locking down your system anyways.

- AdditionalSecurityLogging.sh
 - modifies bashrc for additional logging configurations that i have found useful
- ConfigureIptables.sh
 - Configures iptables to defend against common attacks
- ConfigureSSH.sh
 - Configures the SSH server for most common hardening settings
- doesUserExist.sh
 - simple test to see if a local user exists

## OSX
### OSX 10.10 Yosemite
- CIS_OSX_Yosemite_Server_Audit.sh
 - This script will audit a OSX 10.10 Yosemite system and give you a CIS compliance score based on it's findings.
- CIS_OSX_Yosemite_Server_Hardening.sh
 - This script will harden a fresh build OSX 10.10 Yosemite system to CIS compliance.

### OSX 10.11 El Capitan
- CIS_MacOSX_1011_Audit-Servers.sh
 - This script will audit a OSX 10.11 El Capitan system and give you a CIS compliance score based on it's findings.
- CIS_MacOSX_1011_Hardening-Servers.sh
 - This script will harden a fresh build OSX 10.11 El Capitan system to CIS compliance.

### Additional Security Configurations
These are additional scripts that i suggest be used on OSX systems. I have included these outside of the CIS hardening script in the event that you do not want to use CIS for compliance but want some benefits of locking down your system anyways.
- UseAppleScriptToTurnOffServices.sh
 - This script give examples of how to use applescript to emulate configuration of the OSX system that cannot be done via CLI. THis basically emulates a user clicking these items.
- instalDMGFromCLI.sh
 - This script demonstrates how to install a DMG from CLI or a bash script
- CreateMacAdmin.sh
 - This script is used to add a hidden admin user to an OSX system
- GetLastPasswordModificationTimeOfLocalUser.sh
 - This script is used to This script will query and OSX el capitan system for the last password modification timestamp in mac epoch format
