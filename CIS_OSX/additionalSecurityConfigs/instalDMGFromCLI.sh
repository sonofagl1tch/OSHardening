#!/bin/bash
# install a DMG from CLI
# Author Ryan Nolette
# Date Modified 06/26/2016
######################################################################
echo "hostname: "
read hostname
echo "DA username fo join: "
read DAuser

#join system to domain
dsconfigad -a $hostname -u $DAuser -ou "CN=Computers,DC=network,DC=bit9,DC=local" -domain bit9.local -mobile enable -localhome enable -groups "Domain Admins,Enterprise Admins" -alldomains enable


#mounting dmg
hdid package.dmg

#change directory
cd /Volumes/package/

#Install pkg
sudo /usr/sbin/installer -verbose -pkg package.pkg -target /

#unmounting dmg
hdiutil detach /Volumes/package