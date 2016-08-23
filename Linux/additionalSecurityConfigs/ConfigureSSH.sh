#!/bin/bash
# Configuring SSH script Centos 6
# Author Ryan Nolette
# Date Modified 06/26/2016
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
######################################################################
echo "--- Securing the SSH Daemon ---"
#echo "Backing up previous SSHd configurations"
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
/bin/cat << EOM > /etc/ssh/sshd_config
## Random SSH port
Port 22
## Sets listening address on server. default=0.0.0.0
#ListenAddress 192.168.0.1
## Enforcing SSH Protocol 2 only
Protocol 2
## Checks users on their home directority and rhosts, that they arent world-writable
StrictModes yes
## The option IgnoreRhosts specifies whether rhosts or shosts files should not be used -i in authentication
IgnoreRhosts yes
## Disable direct root login, with no you need to login with account, then "su" you into root
PermitRootLogin no
UsePrivilegeSeparation yes
UsePAM yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
AllowTcpForwarding yes
X11Forwarding no
PubkeyAuthentication yes
RSAAuthentication no
GSSAPIAuthentication no
KerberosAuthentication no
HostbasedAuthentication no
RhostsRSAAuthentication no
LogLevel INFO
PermitUserEnvironment no
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
ClientAliveInterval 300
ClientAliveCountMax 0
MaxAuthTries 4
PermitEmptyPasswords no
## Adds a login banner that the user can see
#Banner /etc/motd
PrintMotd yes
## Add users or groups that are allowed to log in
#AllowUsers serveradmin
AllowGroups admins users whomever
#if you run a command through SSH directly without going interactive (EX: ssh root@system COMMAND), the command won’t be logged anywhere.
#this line will fix that
ForceCommand if [[ -z \$SSH_ORIGINAL_COMMAND ]]; then bash; else printf "\x23\`date +%s\`\n\$SSH_ORIGINAL_COMMAND\n" >> .bash_history; bash -c "\$SSH_ORIGINAL_COMMAND"; fi
EOM
#start ssh services
#service sshd start
#configure sshd to start at boot
chkconfig --level 3 sshd on
chkconfig --level 5 sshd on
#Set Permissions on /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
#commit changes to sshd config
/etc/init.d/sshd restart