#!/bin/bash
# additional security logging script Centos 6
# Author Ryan Nolette
# Date Modified 06/26/2016
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
######################################################################
echo "Configuring Security Logging"
#backup /etc/audit/audit.rules
cp /etc/audit/audit.rules /etc/audit/audit.rules.bk
#reconfigure /etc/audit/audit.rules
echo "--- Configuring auditd ---"
echo " This configuration change will not work until after a reboot"
#backup pam modules
cp /etc/pam.d/login /etc/pam.d/login.bk
cp /etc/pam.d/gdm /etc/pam.d/gdm
#reconfigure pam
#This will allow auditd to get the calling user's uid correctly when calling sudo or su.
echo -e "session\trequired\tpam_loginuid.so" >> /etc/pam.d/login
echo -e "session\trequired\tpam_loginuid.so" >> /etc/pam.d/gdm
echo -e "session\trequired\tpam_loginuid.so" >> /etc/pam.d/sshd
#backup bashrc
for user in `ls /home`; do
	cp /home/$user/.bashrc /home/$user/.bashrc.bk
done
#reconfigure bashrc
echo "--- Enabling Real time bash history for all current users ---"
for user in `ls /home`; do
	echo 'export HISTCONTROL=ignoredups:erasedups  # no duplicate entries' >> /home/$user/.bashrc
	echo 'export HISTSIZE=100000                   # big big history' >> /home/$user/.bashrc
	echo 'export HISTFILESIZE=100000               # big big history' >> /home/$user/.bashrc
	echo 'export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp' >> /home/$user/.bashrc
	echo "shopt -s histappend                      # append to history, don't overwrite it" >> /home/$user/.bashrc
	echo '# After each command, append to the history file and reread it' >> /home/$user/.bashrc
	echo 'export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"' >> /home/$user/.bashrc
done
#backup bashrc for root
cp /root/.bashrc /root/.bashrc.bk
#reconfigure /root/bashrc
echo "--- Enabling Real time bash history for root ---"
/bin/cat << EOM > /root/.bashrc
# .bashrc
# User specific aliases and functions
alias rm='rm -i`
alias cp='cp -i`
alias mv='mv -i`
# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi
export HISTCONTROL=ignoredups:erasedups  # no duplicate entries
export HISTSIZE=100000                   # big big history
export HISTFILESIZE=100000               # big big history
export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp
shopt -s histappend                      # append to history, don't overwrite it
# After each command, append to the history file and reread it
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
EOM
#backup skel bashrc
cp /etc/skel/.bashrc /etc/skel/.bashrc.bk
#reconfigure /etc/skel/.bashrc
echo "--- Enabling Real time bash history for all future users ---"
/bin/cat << EOM > /etc/skel/.bashrc
# .bashrc
# User specific aliases and functions
alias rm='rm -i`
alias cp='cp -i`
alias mv='mv -i`
# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi
export HISTCONTROL=ignoredups:erasedups  # no duplicate entries
export HISTSIZE=100000                   # big big history
export HISTFILESIZE=100000               # big big history
export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp
shopt -s histappend                      # append to history, don't overwrite it
# After each command, append to the history file and reread it
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
EOM