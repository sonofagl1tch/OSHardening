#!/bin/bash
# Additional security logging features for OSX 10.10 Yosemite
# Author Ryan Nolette
# Date Modified 06/18/2016
################################################################################
# - configure security logging
#backup /etc/audit/audit.rules
cp /etc/audit/audit.rules /etc/audit/audit.rules.bk
#reconfigure /etc/audit/audit.rules
echo "--- Configuring advanced auditd logging ---"
#This configuration change will not work until after a reboot.
#This may not work in your OSX build. YMMV. Comment it out if you are worried.
#backup pam modules
cp /private/etc/pam.d/login /private/etc/pam.d/login.bk
cp /private/etc/pam.d/gdm /private/etc/pam.d/gdm
#reconfigure pam
#This will allow auditd to get the calling user's uid correctly when calling sudo or su.
echo -e "session\trequired\tpam_loginuid.so" >> /private/etc/pam.d/login
echo -e "session\trequired\tpam_loginuid.so" >> /private/etc/pam.d/gdm
echo -e "session\trequired\tpam_loginuid.so" >> /private/etc/pam.d/sshd
################################################################################
#backup bashrc
echo "--- Configuring bashrc for all users found on the system ---"
echo " This configuration change will not work until after a reboot"
for user in `ls /Users | grep -v .localized`; do
    cp /Users/$user/.bashrc /Users/$user/.bashrc.bk
done
#reconfigure bashrc
echo "--- Enabling Real time bash history for all current users ---"
for user in `ls /Users | grep -v .localized`; do
    echo 'export HISTCONTROL=ignoredups:erasedups  # no duplicate entries' >> /Users/$user/.bashrc
    echo 'export HISTSIZE=100000                   # big big history' >> /Users/$user/.bashrc
    echo 'export HISTFILESIZE=100000               # big big history' >> /Users/$user/.bashrc
    echo 'export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp' >> /Users/$user/.bashrc
    echo "shopt -s histappend                      # append to history, don't overwrite it" >> /Users/$user/.bashrc
    echo '# After each command, append to the history file and reread it' >> /Users/$user/.bashrc
    echo 'export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"' >> /Users/$user/.bashrc
done
#backup bashrc for root
cp /private/etc/bashrc /private/etc/bashrc.bk
#reconfigure /root/bashrc
echo "--- Enabling Real time bash history for root ---"
/bin/cat << EOM >> /private/etc/bashrc
# .bashrc
# User specific aliases and functions
alias rm='rm -i' # force interactive mode
alias cp='cp -i' # force interactive mode
alias mv='mv -i' # force interactive mode
# Source global definitions
if [ -f /private/etc/bashrc ]; then
        . /private/etc/bashrc
fi
export HISTCONTROL=ignoredups:erasedups  # no duplicate entries
export HISTSIZE=100000                   # big big history
export HISTFILESIZE=100000               # big big history
export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp
shopt -s histappend                      # append to history, don't overwrite it
# After each command, append to the history file and reread it
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
EOM
#complete
