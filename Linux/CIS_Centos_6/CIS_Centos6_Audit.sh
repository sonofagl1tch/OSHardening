#!/bin/bash
#
#CIS CentOS Linux 6 Benchmark
#v1.1.0 - 03-31-2015
#author Ryan Nolette
#date 03/18/2016
#version 1.0
#description:
#    This script will audit a system for compliance with the CIS V1.1.0 hardening guide for Centos 6
#additional information:
#    Level 1
#    Items in this profile intend to:
#    be practical and prudent;
#        provide a clear security benefit; and
#        not inhibit the technology beyond acceptable means.
#usage: ./CIS_Centos-6.py
#####################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
#####################################################################
function audit_WithOutput () {

	if [[ $2 ]]; then
	    echo "$1,pass" >> $filename
	else
	    echo "$1,fail" >> $filename
	fi
}
function audit_WithNoOutput () {

	if [[ $2 ]]; then
		echo "$1,fail" >> $filename
	else
		echo "$1,pass" >> $filename
	fi
}
function audit_Exception () {
	echo "$1,exception" >> $filename
}
#####################################################################
#get hostname
host=`hostname`
#get current date
dateTime=`date +"%m%d%y-%H%M"`
#create filename
filename="CIS_Centos6-"$host"-"$dateTime".csv"
#create new file
touch $filename
#####################################################################
#1 Install Updates, Patches and Additional Security Software 
#1.1 Filesystem Configuration
#1.1.1 Create Separate Partition for /tmp (Scored)
auditStep="1.1.1 Create Separate Partition for /tmp (Scored)"
auditCmd=`grep "[[:space:]]/tmp[[:space:]]" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.2 Set nodev option for /tmp Partition (Scored)
auditStep="1.1.2 Set nodev option for /tmp Partition (Scored)"
auditCmd=`grep "/tmp\|nodev" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.3 Set nosuid option for /tmp Partition (Scored)
auditStep="1.1.3 Set nosuid option for /tmp Partition (Scored)"
#auditCmd=`mount -o remount,nosuid /tmp`
#changed command to grep for nosuid in the file as mount is an unreliable command
auditCmd=`grep "/tmp\|nosuid" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.4 Set noexec option for /tmp Partition (Scored)
auditStep="1.1.4 Set noexec option for /tmp Partition (Scored)"
auditCmd=`grep "/tmp\|noexec" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.5 Create Separate Partition for /var (Scored)
auditStep="1.1.5 Create Separate Partition for /var (Scored)"
auditCmd=`grep "/var" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.6 Bind Mount the /var/tmp directory to /tmp (Scored)
auditStep="1.1.6 Bind Mount the /var/tmp directory to /tmp (Scored)"
auditCmd=`grep -e "/tmp\|/var/tmp" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.7 Create Separate Partition for /var/log (Scored)
auditStep="1.1.7 Create Separate Partition for /var/log (Scored)"
auditCmd=`grep "/var/log" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.8 Create Separate Partition for /var/log/audit (Scored)
auditStep="1.1.8 Create Separate Partition for /var/log/audit (Scored)"
#auditCmd=`grep "/var/log/audit" /etc/fstab`
#we are using a single /var/log partition for all /var/log/* stuff
auditCmd=`grep "/var/log" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.9 Create Separate Partition for /home (Scored)
auditStep="1.1.9 Create Separate Partition for /home (Scored)"
auditCmd=`grep "/home" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.10 Add nodev Option to /home (Scored)
auditStep="1.1.10 Add nodev Option to /home (Scored)"
auditCmd=`grep "/tmp\|noexec" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.11 Add nodev Option to Removable Media Partitions (Not Scored)
auditStep="1.1.11 Add nodev Option to Removable Media Partitions (Not Scored)"
#auditCmd=`grep "each removable media mountpoint" /etc/fstab`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#1.1.12 Add noexec Option to Removable Media Partitions (Not Scored)
auditStep="1.1.12 Add noexec Option to Removable Media Partitions (Not Scored)"
#auditCmd=`grep "each removable media mountpoint" /etc/fstab`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#1.1.13 Add nosuid Option to Removable Media Partitions (Not Scored)
auditStep="1.1.13 Add nosuid Option to Removable Media Partitions (Not Scored)"
#auditCmd=`grep "each removable media mountpoint" /etc/fstab`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#1.1.14 Add nodev Option to /dev/shm Partition (Scored)
auditStep="1.1.14 Add nodev Option to /dev/shm Partition (Scored)"
auditCmd=`grep "/dev/shm\|nosuid" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.15 Add nosuid Option to /dev/shm Partition (Scored)
auditStep="1.1.15 Add nosuid Option to /dev/shm Partition (Scored)"
auditCmd=`grep "/dev/shm\|nosuid" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.16 Add noexec Option to /dev/shm Partition (Scored)
auditStep="1.1.16 Add noexec Option to /dev/shm Partition (Scored)"
auditCmd=`grep "/dev/shm\|noexec" /etc/fstab`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.17 Set Sticky Bit on All World-Writable Directories (Scored)
auditStep="1.1.17 Set Sticky Bit on All World-Writable Directories (Scored)"
auditCmd=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null`
audit_WithNoOutput "$auditStep" "$auditCmd"
#1.1.18 Disable Mounting of cramfs Filesystems (Not Scored)
auditStep="1.1.18 Disable Mounting of cramfs Filesystems (Not Scored)"
auditCmd=`/sbin/modprobe -n -v cramfs && /sbin/lsmod | grep cramfs`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.19 Disable Mounting of freevxfs Filesystems (Not Scored)
auditStep="1.1.19 Disable Mounting of freevxfs Filesystems (Not Scored)"
auditCmd=`/sbin/modprobe -n -v freevxfs && /sbin/lsmod | grep freexvfs`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.20 Disable Mounting of jffs2 Filesystems (Not Scored)
auditStep="1.1.20 Disable Mounting of jffs2 Filesystems (Not Scored)"
auditCmd=`/sbin/modprobe -n -v jffs2 && /sbin/lsmod | grep jffs2`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.21 Disable Mounting of hfs Filesystems (Not Scored)
auditStep="1.1.21 Disable Mounting of hfs Filesystems (Not Scored)"
auditCmd=`/sbin/modprobe -n -v hfs && /sbin/lsmod | grep hfs`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.22 Disable Mounting of hfsplus Filesystems (Not Scored)
auditStep="1.1.22 Disable Mounting of hfsplus Filesystems (Not Scored)"
auditCmd=`/sbin/modprobe -n -v hfsplus && /sbin/lsmod | grep hfsplus`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.23 Disable Mounting of squashfs Filesystems (Not Scored)
auditStep="1.1.23 Disable Mounting of squashfs Filesystems (Not Scored)"
auditCmd=`/sbin/modprobe -n -v squashfs && /sbin/lsmod | grep squashfs`
audit_WithOutput "$auditStep" "$auditCmd"
#1.1.24 Disable Mounting of udf Filesystems (Not Scored)
auditStep="1.1.24 Disable Mounting of udf Filesystems (Not Scored)"
auditCmd=`/sbin/modprobe -n -v udf && /sbin/lsmod | grep udf`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#1.2 Configure Software Updates
#1.2.1 Verify CentOS GPG Key is Installed (Scored)
auditStep="1.2.1 Verify CentOS GPG Key is Installed (Scored)"
auditCmd=`rpm -qa --queryformat "%{SUMMARY}\n" gpg-pubkey`
audit_WithOutput "$auditStep" "$auditCmd"
#1.2.2 Verify that gpgcheck is Globally Activated (Scored)
auditStep="1.2.2 Verify that gpgcheck is Globally Activated (Scored)"
auditCmd=`grep "gpgcheck" /etc/yum.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#1.2.3 Obtain Software Package Updates with yum (Not Scored)
auditStep="1.2.3 Obtain Software Package Updates with yum (Not Scored)"
#auditCmd=`yum check-update`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#1.2.4 Verify Package Integrity Using RPM (Not Scored)
auditStep="1.2.4 Verify Package Integrity Using RPM (Not Scored)"
#auditCmd=`rpm -qVa | awk '$2 != "c" { print $0}'`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#1.3 Advanced Intrusion Detection Environment (AIDE)
#1.3.1 Install AIDE (Scored)
auditStep="1.3.1 Install AIDE (Scored)"
#auditCmd=`rpm -qa aide`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#1.3.2 Implement Periodic Execution of File Integrity (Scored)
auditStep="1.3.2 Implement Periodic Execution of File Integrity (Scored)"
#auditCmd=`if  [ -e "crontab" ] ; then crontab -u root -l | grep "aide"; else echo "file does not exist"; fi`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#1.4 Configure SELinux
#1.4.1 Enable SELinux in /etc/grub.conf (Scored)
auditStep="1.4.1 Enable SELinux in /etc/grub.conf (Scored)"
auditCmd=`grep "selinux=0\|enforcing=0" /etc/grub.conf`
audit_WithNoOutput "$auditStep" "$auditCmd"
#1.4.2 Set the SELinux State (Scored)
auditStep="1.4.2 Set the SELinux State (Scored)"
auditCmd=`grep "SELINUX=enforcing" /etc/selinux/config`
audit_WithOutput "$auditStep" "$auditCmd"
#1.4.3 Set the SELinux Policy (Scored)
auditStep="1.4.3 Set the SELinux Policy (Scored)"
auditCmd=`grep "SELINUXTYPE=targeted" /etc/selinux/config`
audit_WithOutput "$auditStep" "$auditCmd"
#1.4.4 Remove SETroubleshoot (Scored)
auditStep="1.4.4 Remove SETroubleshoot (Scored)"
auditCmd=`rpm -qa setroubleshoot`
audit_WithNoOutput "$auditStep" "$auditCmd"
#1.4.5 Remove MCS Translation Service (mcstrans) (Scored)
auditStep="1.4.5 Remove MCS Translation Service (mcstrans) (Scored)"
auditCmd=`rpm -qa mcstrans`
audit_WithNoOutput "$auditStep" "$auditCmd"
#1.4.6 Check for Unconfined Daemons (Scored)
auditStep="1.4.6 Check for Unconfined Daemons (Scored)"
auditCmd=`ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF }'`
#####################################################################
#1.5 Secure Boot Settings
#1.5.1 Set User/Group Owner on /etc/grub.conf (Scored)
auditStep="1.5.1 Set User/Group Owner on /etc/grub.conf (Scored)"
auditCmd=`stat -L -c "%u %g" /etc/grub.conf | egrep "0 0"`
audit_WithOutput "$auditStep" "$auditCmd"
#1.5.2 Set Permissions on /etc/grub.conf (Scored)
auditStep="1.5.2 Set Permissions on /etc/grub.conf (Scored)"
auditCmd=`stat -L -c "%a" /etc/grub.conf | egrep ".00"`
audit_WithOutput "$auditStep" "$auditCmd"
#1.5.3 Set Boot Loader Password (Scored)
auditStep="1.5.3 Set Boot Loader Password (Scored)"
#auditCmd=`grep "^password --md5" /etc/grub.conf`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#1.5.4 Require Authentication for Single-User Mode (Scored)
auditStep="1.5.4 Require Authentication for Single-User Mode (Scored)"
auditCmd=`grep "SINGLE=/sbin/sulogin" /etc/sysconfig/init && grep "PROMPT=no" /etc/sysconfig/init`
audit_WithOutput "$auditStep" "$auditCmd"
#1.5.5 Disable Interactive Boot (Scored)
auditStep="1.5.5 Disable Interactive Boot (Scored)"
auditCmd=`grep "^PROMPT=no" /etc/sysconfig/init`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#1.6 Additional Process Hardening
#1.6.1 Restrict Core Dumps (Scored)
auditStep="1.6.1 Restrict Core Dumps (Scored)"
auditCmd=`grep "* hard core 0" /etc/security/limits.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#1.6.2 Configure ExecShield (Scored)
auditStep="1.6.2 Configure ExecShield (Scored)"
auditCmd=`sysctl kernel.exec-shield`
audit_WithOutput "$auditStep" "$auditCmd"
#1.6.3 Enable Randomized Virtual Memory Region Placement (Scored)
auditStep="1.6.3 Enable Randomized Virtual Memory Region Placement (Scored)"
auditCmd=`sysctl kernel.randomize_va_space`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#1.7 Use the Latest OS Release (Not Scored)
auditStep="1.7 Use the Latest OS Release (Not Scored)"
#auditCmd=`uname -r`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#2 OS Services
#2.1 Remove Legacy Services
#2.1.1 Remove telnet-server (Scored)
auditStep="2.1.1 Remove telnet-server (Scored)"
auditCmd=`rpm -qa | grep telnet-server`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.2 Remove telnet Clients (Scored)
auditStep="2.1.2 Remove telnet Clients (Scored)"
auditCmd=`rpm -qa | grep telnet`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.3 Remove rsh-server (Scored)
auditStep="2.1.3 Remove rsh-server (Scored)"
auditCmd=`rpm -qa | grep rsh-server`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.4 Remove rsh (Scored)
auditStep="2.1.4 Remove rsh (Scored)"
auditCmd=`rpm -qa | grep rsh`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.5 Remove NIS Client (Scored)
auditStep="2.1.5 Remove NIS Client (Scored)"
auditCmd=`rpm -qa | grep ypbind`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.6 Remove NIS Server (Scored)
auditStep="2.1.6 Remove NIS Server (Scored)"
auditCmd=`rpm -qa | grep ypserv`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.7 Remove tftp (Scored)
auditStep="2.1.7 Remove tftp (Scored)"
auditCmd=`rpm -qa | grep tftp`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.8 Remove tftp-server (Scored)
auditStep="2.1.8 Remove tftp-server (Scored)"
auditCmd=`rpm -qa | grep tftp-server`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.9 Remove talk (Scored)
auditStep="2.1.9 Remove talk (Scored)"
auditCmd=`rpm -qa | grep talk`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.10 Remove talk-server (Scored)
auditStep="2.1.10 Remove talk-server (Scored)"
auditCmd=`rpm -qa | grep talk-server`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.11 Remove xinetd (Scored)
auditStep="2.1.11 Remove xinetd (Scored)"
auditCmd=`rpm -qa | grep xinetd`
audit_WithNoOutput "$auditStep" "$auditCmd"
#2.1.12 Disable chargen-dgram (Scored)
auditStep="2.1.12 Disable chargen-dgram (Scored)"
#auditCmd=`chkconfig --list chargen-dgram | grep -e "chargen-dgram: off\|No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#2.1.13 Disable chargen-stream (Scored)
auditStep="2.1.13 Disable chargen-stream (Scored)"
#auditCmd=`chkconfig --list chargen-stream | grep -e "chargen-stream: off\|No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#2.1.14 Disable daytime-dgram (Scored)
auditStep="2.1.14 Disable daytime-dgram (Scored)"
#auditCmd=`chkconfig --list daytime-dgram | grep -e "daytime-dgram: off\|No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#2.1.15 Disable daytime-stream (Scored)
auditStep="2.1.15 Disable daytime-stream (Scored)"
#auditCmd=`chkconfig --list daytime-stream | grep -e "daytime-stream: off\|No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#2.1.16 Disable echo-dgram (Scored)
auditStep="2.1.16 Disable echo-dgram (Scored)"
#auditCmd=`chkconfig --list echo-dgram | grep -e "echo-dgram: off\|No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#2.1.17 Disable echo-stream (Scored)
auditStep="2.1.17 Disable echo-stream (Scored)"
#auditCmd=`chkconfig --list echo-stream | grep -e "echo-stream: off\|No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#2.1.18 Disable tcpmux-server (Scored)
auditStep="2.1.18 Disable tcpmux-server (Scored)"
#auditCmd=`chkconfig --list tcpmux-server | grep -e "tcpmux-server: off\|No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#3 Special Purpose Services
#3.1 Set Daemon umask (Scored)
auditStep="3.1 Set Daemon umask (Scored)"
auditCmd=`grep "umask 027" /etc/sysconfig/init`
audit_WithOutput "$auditStep" "$auditCmd"
#3.2 Remove X Windows (Scored)
auditStep="3.2 Remove X Windows (Scored)"
#auditCmd=`grep "^id:3:initdefault" /etc/inittab && yum grouplist "X Window System" | grep "X Window System"`
auditCmd=`grep "^id:3:initdefault" /etc/inittab`
audit_WithOutput "$auditStep" "$auditCmd"
#3.3 Disable Avahi Server (Scored)
auditStep="3.3 Disable Avahi Server (Scored)"
#auditCmd=`chkconfig --list avahi-daemon | grep -E "avahi-daemon:\s+0:off\s+1:off\s+2:off\s+3:off\s+4:off\s+5:off\s+6:off" -e "No such file or directory"`
auditCmd=""
#audit_WithOutput "$auditStep" "$auditCmd"
#not installed on minimal
audit_Exception "$auditStep" "$auditCmd"
#3.4 Disable Print Server - CUPS (Not Scored)
auditStep="3.4 Disable Print Server - CUPS (Not Scored)"
auditCmd=`chkconfig --list cups | grep -E "cups\s+0:off\s+1:off\s+2:off\s+3:off\s+4:off\s+5:off\s+6:off"`
audit_WithOutput "$auditStep" "$auditCmd"
#3.5 Remove DHCP Server (Scored)
auditStep="3.5 Remove DHCP Server (Scored)"
auditCmd=`rpm -q dhcp | grep "package dhcp is not installed"`
audit_WithOutput "$auditStep" "$auditCmd"
#3.6 Configure Network Time Protocol (NTP) (Scored)
auditStep="3.6 Configure Network Time Protocol (NTP) (Scored)"
auditCmd=`grep "restrict default" /etc/ntp.conf && grep "restrict -6 default" /etc/ntp.conf && grep "^server" /etc/ntp.conf && grep "ntp:ntp" /etc/sysconfig/ntpd`
audit_WithOutput "$auditStep" "$auditCmd"
#3.7 Remove LDAP (Not Scored)
auditStep="3.7 Remove LDAP (Not Scored)"
auditCmd=`rpm -qa | grep openldap-servers && rpm -qa | grep openldap-clients`
audit_WithNoOutput "$auditStep" "$auditCmd"
#3.8 Disable NFS and RPC (Not Scored)
#making this an exception for now until i can figure it out
auditStep="3.8 Disable NFS and RPC (Not Scored)"
#auditCmd=`chkconfig --list nfslock | grep "nfslock: 0:off 1:off 2:off 3:off 4:off 5:off 6:off" && chkconfig --list rpcgssd | grep "rpcgssd: 0:off 1:off 2:off 3:off 4:off 5:off 6:off" && chkconfig --list rpcbind | grep "rpcbind: 0:off 1:off 2:off 3:off 4:off 5:off 6:off" && chkconfig --list rpcidmapd | grep "rpcidmapd: 0:off 1:off 2:off 3:off 4:off 5:off 6:off" && chkconfig --list rpcsvcgssd | grep "rpcsvcgssd: 0:off 1:off 2:off 3:off 4:off 5:off 6:off"`
#nfslock is not installed on the min image we use and neither is rpcgssd
#auditcmd=`chkconfig --list nfslock | grep -e "No such file or directory"`
#auditcmd2=`chkconfig --list rpcgssd | grep -e "No such file or directory"`
auditCmd=""
#audit_2CommandsWithOutput "$auditStep" "$auditCmd" "$auditCmd2"
audit_Exception "$auditStep" "$auditCmd"
#3.9 Remove DNS Server (Not Scored)
auditStep="3.9 Remove DNS Server (Not Scored)"
auditCmd=`rpm -qa | grep bind | grep -v samba`
audit_WithNoOutput "$auditStep" "$auditCmd"
#3.10 Remove FTP Server (Not Scored)
auditStep="3.10 Remove FTP Server (Not Scored)"
auditCmd=`rpm -qa | grep vsftpd`
audit_WithNoOutput "$auditStep" "$auditCmd"
#3.11 Remove HTTP Server (Not Scored)
auditStep="3.11 Remove HTTP Server (Not Scored)"
auditCmd=`rpm -qa | grep httpd`
audit_WithNoOutput "$auditStep" "$auditCmd"
#3.12 Remove Dovecot (IMAP and POP3 services) (Not Scored)
auditStep="3.12 Remove Dovecot (IMAP and POP3 services) (Not Scored)"
auditCmd=`rpm -qa | grep dovecot`
audit_WithNoOutput "$auditStep" "$auditCmd"
#3.13 Remove Samba (Not Scored)
auditStep="3.13 Remove Samba (Not Scored)"
#auditCmd=`rpm -qa | grep samba`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#3.14 Remove HTTP Proxy Server (Not Scored)
auditStep="3.14 Remove HTTP Proxy Server (Not Scored)"
auditCmd=`rpm -qa | grep squid`
audit_WithNoOutput "$auditStep" "$auditCmd"
#3.15 Remove SNMP Server (Not Scored)
auditStep="3.15 Remove SNMP Server (Not Scored)"
auditCmd=`rpm -qa | grep net-snmp`
audit_WithNoOutput "$auditStep" "$auditCmd"
#3.16 Configure Mail Transfer Agent for Local-Only Mode (Scored)
auditStep="3.16 Configure Mail Transfer Agent for Local-Only Mode (Scored)"
#postfix is not installed on these images
#auditCmd=`netstat -an | grep LIST | grep ":25[[:space:]]" | grep "tcp 0 0 127.0.0.1:25 0.0.0.0:* LISTEN"`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#4 Network Configuration and Firewalls
#4.1 Modify Network Parameters (Host Only)
#4.1.1 Disable IP Forwarding (Scored)
auditStep="4.1.1 Disable IP Forwarding (Scored)"
auditCmd=`grep -E "net.ipv4.ip_forward\s+=\s+0" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.1.2 Disable Send Packet Redirects (Scored)
auditStep="4.1.2 Disable Send Packet Redirects (Scored)"
auditCmd=`grep -E "net.ipv4.conf.all.send_redirects\s+=\s+0|net.ipv4.conf.default.send_redirects\s+=\s+0" /etc/sysctl.conf` 
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#4.2 Modify Network Parameters (Host and Router)
#4.2.1 Disable Source Routed Packet Acceptance (Scored)
auditStep="4.2.1 Disable Source Routed Packet Acceptance (Scored)"
auditCmd=`grep -E "net.ipv4.conf.all.accept_source_route\s+=\s+0|net.ipv4.conf.default.accept_source_route\s+=\s+0" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.2.2 Disable ICMP Redirect Acceptance (Scored)
auditStep="4.2.2 Disable ICMP Redirect Acceptance (Scored)"
auditCmd=`grep -E "net.ipv4.conf.all.accept_redirects\s+=\s+0|net.ipv4.conf.default.accept_redirects\s+=\s+0" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.2.3 Disable Secure ICMP Redirect Acceptance (Scored)
auditStep="4.2.3 Disable Secure ICMP Redirect Acceptance (Scored)"
auditCmd=`grep -E "net.ipv4.conf.all.secure_redirects\s+=\s+0|net.ipv4.conf.default.secure_redirects\s+=\s+0" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.2.4 Log Suspicious Packets (Scored)
auditStep="4.2.4 Log Suspicious Packets (Scored)"
auditCmd=`grep -E "net.ipv4.conf.all.log_martians\s+=\s+1|net.ipv4.conf.default.log_martians\s+=\s+1" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.2.5 Enable Ignore Broadcast Requests (Scored)
auditStep="4.2.5 Enable Ignore Broadcast Requests (Scored)"
auditCmd=`grep -E "net.ipv4.icmp_echo_ignore_broadcasts\s+=\s+1" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.2.6 Enable Bad Error Message Protection (Scored)
auditStep="4.2.6 Enable Bad Error Message Protection (Scored)"
auditCmd=`grep -E "net.ipv4.icmp_ignore_bogus_error_responses\s+=\s+1" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.2.7 Enable RFC-recommended Source Route Validation (Scored)
auditStep="4.2.7 Enable RFC-recommended Source Route Validation (Scored)"
auditCmd=`grep -E "net.ipv4.conf.all.rp_filter\s+=\s+1|net.ipv4.conf.default.rp_filter\s+=\s+1" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.2.8 Enable TCP SYN Cookies (Scored)
auditStep="4.2.8 Enable TCP SYN Cookies (Scored)"
auditCmd=`grep -E "net.ipv4.tcp_syncookies\s+=\s+1" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#4.3 Wireless Networking
#these are virtual servers and do not have wireless networking adapters
auditStep="4.3 Wireless Networking"
#auditCmd=`ifconfig -a`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#4.4 Disable IPv6
#4.4.1 Configure IPv6
#4.4.1.1 Disable IPv6 Router Advertisements (Not Scored)
auditStep="4.4.1.1 Disable IPv6 Router Advertisements net.ipv6.conf.all.accept_ra (Not Scored)"
auditCmd=`grep -E "net.ipv6.conf.all.accept_ra=0|net.ipv6.conf.default.accept_ra=0" /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.4.1.1 Disable IPv6 Router Advertisements (Not Scored)
# auditStep="4.4.1.1 Disable IPv6 Router Advertisements net.ipv6.conf.default.accept_ra (Not Scored)"
# auditCmd=`/sbin/sysctl net.ipv6.conf.default.accept_ra | grep -E "net.ipv6.conf.default.accept_ra/s+=/s+0"`
# audit_WithOutput "$auditStep" "$auditCmd"
#4.4.1.2 Disable IPv6 Redirect Acceptance (Not Scored)
auditStep="4.4.1.2 Disable IPv6 Redirect Acceptance (Not Scored)"
#auditCmd=`/sbin/sysctl net.ipv6.conf.all.accept_redirects | grep "net.ipv6.conf.all.accept_redirect = 0" && /sbin/sysctl net.ipv6.conf.default.accept_redirects | grep "net.ipv6.conf.default.accept_redirect = 0"`
auditCmd=`grep -E 'net.ipv6.conf.all.accept_redirects=0|net.ipv6.conf.default.accept_redirects=0' /etc/sysctl.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.4.2 Disable IPv6 (Not Scored)
auditStep="4.4.2 Disable IPv6 (Not Scored)"
auditCmd=`grep -E "NETWORKING_IPV6=no|IPV6INIT=no" /etc/sysconfig/network`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#4.5 Install TCP Wrappers
auditStep="4.5 Install TCP Wrappers"
auditCmd=`yum list tcp_wrappers | grep "tcp_wrappers."`
audit_WithOutput "$auditStep" "$auditCmd"
#4.5.2 Create /etc/hosts.allow (Not Scored)
auditStep="4.5.2 Create /etc/hosts.allow (Not Scored)"
# ALL: 10.0.0.0/255.0.0.0
# ALL: 172.16.0.0/255.240.0.0
# ALL: 192.168.0.0/255.255.0.0
auditCmd=`grep -E 'ALL:\s+10.0.0.0/255.0.0.0|ALL:\s+172.16.0.0/255.240.0.0|ALL:\s+192.168.0.0/255.255.0.0' /etc/hosts.allow`
audit_WithOutput "$auditStep" "$auditCmd"
#4.5.3 Verify Permissions on /etc/hosts.allow (Scored)
auditStep="4.5.3 Verify Permissions on /etc/hosts.allow (Scored)"
auditCmd=`/bin/ls -l /etc/hosts.allow | grep "\-rw\-r\-\-r\-\-"`
audit_WithOutput "$auditStep" "$auditCmd"
#4.5.4 Create /etc/hosts.deny (Not Scored)
auditStep="4.5.4 Create /etc/hosts.deny (Not Scored)"
auditCmd=`grep -E "ALL:\s+ALL" /etc/hosts.deny`
audit_WithOutput "$auditStep" "$auditCmd"
#4.5.5 Verify Permissions on /etc/hosts.deny (Scored)
auditStep="4.5.5 Verify Permissions on /etc/hosts.deny (Scored)"
auditCmd=`/bin/ls -l /etc/hosts.deny | grep "\-rw\-r\-\-r\-\-"`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#4.6 Uncommon Network Protocols
#4.6.1 Disable DCCP (Not Scored)
auditStep="4.6.1 Disable DCCP (Not Scored)"
auditCmd=`grep -E "install dccp\s+/bin/true" /etc/modprobe.d/CIS.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.6.2 Disable SCTP (Not Scored)
auditStep="4.6.2 Disable SCTP (Not Scored)"
auditCmd=`grep -E "install\s+sctp\s+/bin/true" /etc/modprobe.d/CIS.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.6.3 Disable RDS (Not Scored)
auditStep="4.6.3 Disable RDS (Not Scored)"
auditCmd=`grep -E "install\s+rds\s+/bin/true" /etc/modprobe.d/CIS.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#4.6.4 Disable TIPC (Not Scored)
auditStep="4.6.4 Disable TIPC (Not Scored)"
auditCmd=`grep -E "install\s+tipc\s+/bin/true" /etc/modprobe.d/CIS.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#4.7 Enable IPtables (Scored)
auditStep="4.7 Enable IPtables (Scored)" #grep -E "word +-c" abc.txt
auditCmd=`chkconfig --list iptables | grep -E "iptables\s+0:off\s+1:off\s+2:on\s+3:on\s+4:on\s+5:on\s+6:off"`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#4.8 Enable IP6tables (Not Scored)
auditStep="4.8 Enable IP6tables (Not Scored)"
auditCmd=`chkconfig --list ip6tables | grep -E "ip6tables\s+0:off\s+1:off\s+2:off\s+3:off\s+4:off\s+5:off\s+6:off"`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#5 Logging and Auditing
#5.1 Configure rsyslog
auditStep="5.1 Configure rsyslog"
#auditCmd=`rpm -q rsyslog | grep "rsyslog."`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#5.1.2 Activate the rsyslog Service (Scored)
auditStep="5.1.2 Activate the rsyslog Service (Scored)"
#auditCmd=`chkconfig --list syslog | grep -E "syslog\s+0:off\s+1:off\s+2:off\s+3:off\s+4:off\s+5:off\s+6:off" && chkconfig --list rsyslog | grep -E "rsyslog\s+0:off\s+1:off\s+2:on\s+3:on\s+4:on\s+5:on\s+6:off"`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#5.1.3 Configure /etc/rsyslog.conf (Not Scored)
auditStep="5.1.3 Configure /etc/rsyslog.conf (Not Scored)"
#auditCmd=`ls -l /var/log/`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#5.1.4 Create and Set Permissions on rsyslog Log Files (Scored)
#auditStep="5.1.4 Create and Set Permissions on rsyslog Log Files (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#5.1.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)
#*.* @@loghost.example.com
auditStep="5.1.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)"
#auditCmd=`grep -E "^*.*[^I][^I]*@" /etc/rsyslog.conf`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)
auditStep="5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)"
#auditCmd=`grep -E "$ModLoad\s+imtcp.so|$InputTCPServerRun 514" /etc/rsyslog.conf`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#5.2 Configure System Accounting (auditd)
#5.2.1 Configure Data Retention
#5.2.1.1 Configure Audit Log Storage Size (Not Scored)
auditStep="5.2.1.1 Configure Audit Log Storage Size (Not Scored)"
auditCmd=`grep "max_log_file = 100" /etc/audit/auditd.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.1.2 Disable System on Audit Log Full (Not Scored)
auditStep="5.2.1.2 Disable System on Audit Log Full (Not Scored)"
auditCmd=`grep -e 'space_left_action = email' -e 'action_mail_acct = root' -e 'admin_space_left_action = halt' /etc/audit/auditd.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.1.3 Keep All Auditing Information (Scored)
auditStep="5.2.1.3 Keep All Auditing Information (Scored)"
auditCmd=`grep "max_log_file_action = keep_logs" /etc/audit/auditd.conf`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.2 Enable auditd Service (Scored)
auditStep="5.2.2 Enable auditd Service (Scored)"
auditCmd=`chkconfig --list auditd | grep -E "auditd\s+0:off\s+1:off\s+2:on\s+3:on\s+4:on\s+5:on\s+6:off"`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.3 Enable Auditing for Processes That Start Prior to auditd (Scored)
auditStep="5.2.3 Enable Auditing for Processes That Start Prior to auditd (Scored)"
auditCmd="grep 'kernel\|audit=1' /etc/grub.conf"
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.4 Record Events That Modify Date and Time Information (Scored)
# Perform the following to determine if events where the system date and/or time has been modified are captured.
# On a 64 bit system, perform the following command and ensure the output is as shown. Note: "-a always,exit" may be specified as "-a exit,always".
# grep time-change /etc/audit/audit.rules
# -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
# -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
# -a always,exit -F arch=b64 -S clock_settime -k time-change
# -a always,exit -F arch=b32 -S clock_settime -k time-change
# -w /etc/localtime -p wa -k time-change
# Execute the following command to restart auditd
# pkill -P 1-HUP auditd
auditStep="5.2.4 Record Events That Modify Date and Time Information (Scored)"
auditCmd=`grep "time-change" /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#￼5.2.5 Record Events That Modify User/Group Information (Scored)
# grep identity /etc/audit/audit.rules
# -w /etc/group -p wa -k identity
# -w /etc/passwd -p wa -k identity
# -w /etc/gshadow -p wa -k identity
# -w /etc/shadow -p wa -k identity
# -w /etc/security/opasswd -p wa -k identity
auditStep="5.2.5 Record Events That Modify User/Group Information (Scored)"
auditCmd=`grep identity /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.6 Record Events That Modify the System's Network Environment
# grep system-locale /etc/audit/audit.rules
# -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
# -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
# -w /etc/issue -p wa -k system-locale
# -w /etc/issue.net -p wa -k system-locale
# -w /etc/hosts -p wa -k system-locale
# -w /etc/sysconfig/network -p wa -k system-locale
auditStep="5.2.6 Record Events That Modify the System's Network Environment"
auditCmd=`grep system-locale /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.7 Record Events That Modify the System's Mandatory Access Controls (Scored)
# grep MAC-policy /etc/audit/audit.rules
# -w /etc/selinux/ -p wa -k MAC-policy
auditStep="5.2.7 Record Events That Modify the System's Mandatory Access Controls (Scored)"
auditCmd=`grep MAC-policy /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.8 Collect Login and Logout Events (Scored)
# grep logins /etc/audit/audit.rules
# -w /var/log/faillog -p wa -k logins
# -w /var/log/lastlog -p wa -k logins
# -w /var/log/tallylog -p wa -k logins
auditStep="5.2.8 Collect Login and Logout Events (Scored)"
auditCmd=`grep logins /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.9 Collect Session Initiation Information (Scored)
# grep session /etc/audit/audit.rules
# -w /var/run/utmp -p wa -k session
# -w /var/log/wtmp -p wa -k session
# -w /var/log/btmp -p wa -k session
auditStep="5.2.9 Collect Session Initiation Information (Scored)"
auditCmd=`grep session /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.10 Collect Discretionary Access Control Permission Modification Events (Scored)
# grep perm_mod /etc/audit/audit.rules
# -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 \
# -F auid!=4294967295 -k perm_mod
# -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 \
# -F auid!=4294967295 -k perm_mod
# -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 \
# -F auid!=4294967295 -k perm_mod
# -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 \
# -F auid!=4294967295 -k perm_mod
# -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
# ￼￼￼lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
# -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \
# lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
auditStep="5.2.10 Collect Discretionary Access Control Permission Modification Events (Scored)"
auditCmd=`grep perm_mod /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)
# grep access /etc/audit/audit.rules
# -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate \
# -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
# -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate \
# -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
# -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate \
# -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
# -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate \
# -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
auditStep="5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)"
auditCmd=`grep access /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.12 Collect Use of Privileged Commands (Scored)
# Audit: Verify that an audit line for each setuid/setgid program identified in the find command appears in the audit file with the above attributes.
#find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }`
auditStep="5.2.12 Collect Use of Privileged Commands (Scored)"
#auditCmd="find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged\" }'"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#5.2.13 Collect Successful File System Mounts (Scored)
# grep mounts /etc/audit/audit.rules
# -a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
# -a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
auditStep="5.2.13 Collect Successful File System Mounts (Scored)"
auditCmd=`grep mounts /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.14 Collect File Deletion Events by User (Scored)
# grep delete /etc/audit/audit.rules
# -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \
# -F auid!=4294967295 -k delete
# -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \
# -F auid!=4294967295 -k delete
auditStep="5.2.14 Collect File Deletion Events by User (Scored)"
auditCmd=`grep delete /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.15 Collect Changes to System Administration Scope (sudoers) (Scored)
auditStep="5.2.15 Collect Changes to System Administration Scope (sudoers) (Scored)"
auditCmd=`grep "\-w /etc/sudoers \-p wa \-k scope" /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.16 Collect System Administrator Actions (sudolog) (Scored)
auditStep="5.2.16 Collect System Administrator Actions (sudolog) (Scored)"
auditCmd=`grep "\-w /var/log/sudo.log \-p wa \-k actions" /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.17 Collect Kernel Module Loading and Unloading (Scored)
# grep modules /etc/audit/audit.rules
# -w /sbin/insmod -p x -k modules
# -w /sbin/rmmod -p x -k modules
# -w /sbin/modprobe -p x -k modules
# For 32 bit systems
# -a always,exit -F arch=b32 -S init_module -S delete_module -k modules
# For 64 bit systems
# -a always,exit -F arch=b64 -S init_module -S delete_module -k modules
auditStep="5.2.17 Collect Kernel Module Loading and Unloading (Scored)"
auditCmd=`grep modules /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#5.2.18 Make the Audit Configuration Immutable (Scored)
auditStep="5.2.18 Make the Audit Configuration Immutable (Scored)"
auditCmd=`grep "^-e 2" /etc/audit/audit.rules`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#5.3 Configure logrotate (Not Scored)
auditStep="5.3 Configure logrotate (Not Scored)"
auditCmd="grep '{' /etc/logrotate.d/syslog | grep '/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {'"
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#6 System Access, Authentication and Authorization
#6.1 Configure cron and anacron
#6.1.1 Enable anacron Daemon (Scored)
auditStep="6.1.1 Enable anacron Daemon (Scored)"
auditCmd="rpm -q cronie-anacron | grep 'cronie-anacron.'"
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.2 Enable crond Daemon (Scored)
auditStep="6.1.2 Enable crond Daemon (Scored)"
auditCmd="chkconfig --list crond | grep 'crond: 0:off 1:off 2:on 3:on 4:on 5:on 6:off'"
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.3 Set User/Group Owner and Permission on /etc/anacrontab (Scored)
auditStep="6.1.3 Set User/Group Owner and Permission on /etc/anacrontab (Scored)"
#auditCmd=`stat -L -c "%a %u %g" /etc/anacrontab | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/anacrontab" ] ; then ls -l "/etc/anacrontab" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.4 Set User/Group Owner and Permission on /etc/crontab (Scored)
auditStep="6.1.4 Set User/Group Owner and Permission on /etc/crontab (Scored)"
#does not exist on minimal image
#auditCmd=`stat -L -c "%a %u %g" /etc/crontab | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/crontab" ] ; then ls -l "/etc/crontab" | grep -e "^-rw-------" | egrep ".00 0 0"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)
auditStep="6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)"
#auditCmd=`stat -L -c "%a %u %g" /etc/cron.hourly | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/cron.hourly" ] ; then ls -l "/etc/cron.hourly" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.6 Set User/Group Owner and Permission on /etc/cron.daily (Scored)
auditStep="6.1.6 Set User/Group Owner and Permission on /etc/cron.daily (Scored)"
#auditCmd=`stat -L -c "%a %u %g" /etc/cron.daily | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/cron.daily" ] ; then ls -l "/etc/cron.daily" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)
auditStep="6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)"
#auditCmd=`stat -L -c "%a %u %g" /etc/cron.weekly | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/cron.weekly" ] ; then ls -l "/etc/cron.weekly" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)
auditStep="6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)"
#auditCmd=`stat -L -c "%a %u %g" /etc/cron.monthly | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/cron.monthly" ] ; then ls -l "/etc/cron.monthly" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.9 Set User/Group Owner and Permission on /etc/cron.d (Scored)
auditStep="6.1.9 Set User/Group Owner and Permission on /etc/cron.d (Scored)"
#auditCmd=`stat -L -c "%a %u %g" /etc/cron.d | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/cron.d" ] ; then ls -l "/etc/cron.d" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.10 Restrict at Daemon (Scored)
auditStep="6.1.10 Restrict at Daemon /etc/at.deny (Scored)"
#auditCmd=`stat -L /etc/at.deny > /dev/null && stat -L -c "%a %u %g" /etc/at.allow | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/at.deny" ] ; then ls -l "/etc/at.deny" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.10 Restrict at Daemon (Scored)
auditStep="6.1.10 Restrict at Daemon /etc/at.allow (Scored)"
#auditCmd=`stat -L /etc/at.deny > /dev/null && stat -L -c "%a %u %g" /etc/at.allow | egrep ".00 0 0\|No such file or directory"`
auditcmd=`if  [ -e "/etc/at.allow" ] ; then ls -l "/etc/at.allow" | grep -e "^-rw-------"; else echo "file does not exist"; fi`
audit_WithOutput "$auditStep" "$auditCmd"
#6.1.11 Restrict at/cron to Authorized Users (Scored)
# ls -l /etc/cron.deny
#[no output returned]
# ls -l /etc/at.deny
#[no output returned]
auditStep="6.1.11 Restrict at/cron to Authorized Users (Scored)"
auditCmd=`ls -l /etc/cron.allow | grep -E "^-rw-------" && ls -l /etc/at.allow | grep -E "^-rw-------"`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#6.2 Configure SSH
#6.2.1 Set SSH Protocol to 2 (Scored)
auditStep="6.2.1 Set SSH Protocol to 2 (Scored)"
auditCmd=`grep "^Protocol 2" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.2 Set LogLevel to INFO (Scored)
auditStep="6.2.2 Set LogLevel to INFO (Scored)"
auditCmd=`grep "^LogLevel INFO" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)
auditStep="6.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)"
auditCmd=`/bin/ls -l /etc/ssh/sshd_config | grep "^-rw-------"`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.4 Disable SSH X11 Forwarding (Scored)
auditStep="6.2.4 Disable SSH X11 Forwarding (Scored)"
auditCmd=`grep "^X11Forwarding no" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)
auditStep="6.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)"
auditCmd=`grep "^MaxAuthTries 4" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.6 Set SSH IgnoreRhosts to Yes (Scored)
auditStep="6.2.6 Set SSH IgnoreRhosts to Yes (Scored)"
auditCmd=`grep "^IgnoreRhosts yes" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.7 Set SSH HostbasedAuthentication to No (Scored)
auditStep="6.2.7 Set SSH HostbasedAuthentication to No (Scored)"
auditCmd=`grep "^HostbasedAuthentication no" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.8 Disable SSH Root Login (Scored)
auditStep="6.2.8 Disable SSH Root Login (Scored)"
auditCmd=`grep "^PermitRootLogin no" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.9 Set SSH PermitEmptyPasswords to No (Scored)
auditStep="6.2.9 Set SSH PermitEmptyPasswords to No (Scored)"
auditCmd=`grep "^PermitEmptyPasswords no" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.10 Do Not Allow Users to Set Environment Options (Scored)
auditStep="6.2.10 Do Not Allow Users to Set Environment Options (Scored)"
auditCmd=`grep "^PermitUserEnvironment no" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.11 Use Only Approved Cipher in Counter Mode (Scored)
auditStep="6.2.11 Use Only Approved Cipher in Counter Mode (Scored)"
auditCmd=`grep "^Ciphers aes128-ctr,aes192-ctr,aes256-ctr" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.12 Set Idle Timeout Interval for User Login (Scored)
auditStep="6.2.12 Set Idle Timeout Interval for User Login (Scored)"
#extended session timeout from 300 seconds (5minutes) to 900 seconds (15 minutes)
auditCmd=`grep "^ClientAliveInterval 900" /etc/ssh/sshd_config && grep "^ClientAliveCountMax 0" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#6.2.13 Limit Access via SSH (Scored)
# grep "^AllowUsers" /etc/ssh/sshd_config
#AllowUsers <userlist>
# grep "^AllowGroups" /etc/ssh/sshd_config
#AllowGroups <grouplist>
# grep "^DenyUsers" /etc/ssh/sshd_config
#DenyUsers <userlist>
# grep "^DenyGroups" /etc/ssh/sshd_config
#DenyGroups <grouplist>
auditStep="6.2.13 Limit Access via SSH (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#6.2.14 Set SSH Banner (Scored)
auditStep="6.2.14 Set SSH Banner (Scored)"
auditCmd=`grep "^Banner" /etc/ssh/sshd_config`
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#6.3 Configure PAM
#6.3.1 Upgrade Password Hashing Algorithm to SHA-512 (Scored)
auditStep="6.3.1 Upgrade Password Hashing Algorithm to SHA-512 (Scored)"
auditCmd=`authconfig --test | grep hashing | grep sha512`
audit_WithOutput "$auditStep" "$auditCmd"
#6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)
auditStep="6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)"
auditCmd=`grep -E "password\s+required\s+pam_cracklib.so\s+try_first_pass\s+retry=3\s+minlen=14\s+dcredit=-1\s+ucredit=-1\s+ocredit=-1\s+lcredit=-1" /etc/pam.d/system-auth`
audit_WithOutput "$auditStep" "$auditCmd"
#6.3.3 Set Lockout for Failed Password Attempts (Not Scored)
auditStep="6.3.3 Set Lockout for Failed Password Attempts (Not Scored)"
auditCmd=`grep "pam_faillock" /etc/pam.d/password-auth`
audit_WithOutput "$auditStep" "$auditCmd"
#6.3.4 Limit Password Reuse (Scored)
auditStep="6.3.4 Limit Password Reuse (Scored)"
#auditCmd=`grep -E "password\s+sufficient\s+pam_unix.so\s+remember=5" /etc/pam.d/system-auth`
auditcmd=`grep -E "password\s+sufficient\s+pam_unix.so\s+sha512\s+shadow\s+nullok\s+try_first_pass\s+use_authtok\s+remember=5" /etc/pam.d/system-auth`
audit_WithOutput "$auditStep" "$auditCmd"
#6.4 Restrict root Login to System Console (Not Scored)
auditStep="6.4 Restrict root Login to System Console (Not Scored)"
auditCmd=`cat /etc/securetty`
audit_Exception "$auditStep" "$auditCmd"
#6.5 Restrict Access to the su Command (Scored)
auditStep="6.5 Restrict Access to the su Command (Scored)"
auditCmd=`grep -E "auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#7 User Accounts and Environment
#7.1 Set Shadow Password Suite Parameters (/etc/login.defs)
#7.1.1 Set Password Expiration Days (Scored)
#chage --list <user>
#Maximum number of days between password change:    90
auditStep="7.1.1 Set Password Expiration Days (Scored)"
auditCmd=`grep -E "PASS_MAX_DAYS\s+90" /etc/login.defs`
audit_WithOutput "$auditStep" "$auditCmd"
#7.1.2 Set Password Change Minimum Number of Days (Scored)
# chage --list <user>
#Miniumum number of days between password change:    7
auditStep="7.1.2 Set Password Change Minimum Number of Days (Scored)"
auditCmd=`grep -E "PASS_MIN_DAYS\s+7" /etc/login.defs`
audit_WithOutput "$auditStep" "$auditCmd"
#7.1.3 Set Password Expiring Warning Days (Scored)
# chage --list <user>
#Number of days of warning before password expires:    7
auditStep="7.1.3 Set Password Expiring Warning Days (Scored)"
auditCmd=`grep -E "PASS_WARN_AGE\s+7" /etc/login.defs`
audit_WithOutput "$auditStep" "$auditCmd"
#7.2 Disable System Accounts (Scored)
auditStep="7.2 Disable System Accounts (Scored)"
auditCmd=`egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}'`
audit_WithNoOutput "$auditStep" "$auditCmd"
#7.3 Set Default Group for root Account (Scored)
auditStep="7.3 Set Default Group for root Account (Scored)"
auditCmd=`grep "^root:" /etc/passwd | cut -f4 -d: | grep "0"`
audit_WithOutput "$auditStep" "$auditCmd"
#7.4 Set Default umask for Users (Scored)
auditStep="7.4 Set Default umask for Users (Scored)"
auditCmd=`grep "umask 077" /etc/bashrc`
audit_WithOutput "$auditStep" "$auditCmd"
#7.5 Lock Inactive User Accounts (Scored)
auditStep="7.5 Lock Inactive User Accounts (Scored)"
auditCmd=`useradd -D | grep "INACTIVE=35"`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
#8 Warning Banners
#8.1 Set Warning Banner for Standard Login Services (Scored)
auditStep="8.1 Set Warning Banner for Standard Login Services (Scored)"
auditCmd=`/bin/ls -l /etc/motd | grep "^-rw-r--r--" && ls /etc/issue | grep "^-rw-r--r--" && ls /etc/issue.net | grep "^-rw-r--r--"`
audit_WithOutput "$auditStep" "$auditCmd"
#8.2 Remove OS Information from Login Warning Banners /etc/issue (Scored)
auditStep="8.2 Remove OS Information from Login Warning Banners /etc/issue (Scored)"
auditCmd=`grep -e '(\\v|\\r|\\m|\\s)' /etc/issue`
audit_WithNoOutput "$auditStep" "$auditCmd"
#8.2 Remove OS Information from Login Warning Banners /etc/motd (Scored)
auditStep="8.2 Remove OS Information from Login Warning Banners /etc/motd (Scored)"
auditCmd=`grep -e '(\\v|\\r|\\m|\\s)' /etc/motd`
audit_WithNoOutput "$auditStep" "$auditCmd"
#8.2 Remove OS Information from Login Warning Banners /etc/issue.net (Scored)
auditStep="8.2 Remove OS Information from Login Warning Banners /etc/issue.net (Scored)"
auditCmd=`grep -e '(\\v|\\r|\\m|\\s)' /etc/issue.net`
audit_WithNoOutput "$auditStep" "$auditCmd"
#8.3 Set GNOME Warning Banner (Not Scored)
auditStep="8.3 Set GNOME Warning Banner (Not Scored)"
#auditCmd=`gconftool-2 --get /apps/gdm/simple-greeter/banner_message_text`
auditCmd=`echo "test"`
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#9 System Maintenance
#9.1 Verify System File Permissions
#9.1.1 Verify System File Permissions (Not Scored)
auditStep="9.1.1 Verify System File Permissions (Not Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.1.2 Verify Permissions on /etc/passwd (Scored)
auditStep="9.1.2 Verify Permissions on /etc/passwd (Scored)"
auditCmd=`/bin/ls -l /etc/passwd | grep "^-rw-r--r--"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.3 Verify Permissions on /etc/shadow (Scored)
auditStep="9.1.3 Verify Permissions on /etc/shadow (Scored)"
auditCmd=`/bin/ls -l /etc/shadow | grep "^----------"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.4 Verify Permissions on /etc/gshadow (Scored)
auditStep="9.1.4 Verify Permissions on /etc/gshadow (Scored)"
auditCmd=`/bin/ls -l /etc/gshadow | grep "^----------"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.5 Verify Permissions on /etc/group (Scored)
auditStep="9.1.5 Verify Permissions on /etc/group (Scored)"
auditCmd=`/bin/ls -l /etc/group | grep "^-rw-r--r--"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.6 Verify User/Group Ownership on /etc/passwd (Scored)
auditStep="9.1.6 Verify User/Group Ownership on /etc/passwd (Scored)"
auditCmd=`/bin/ls -l /etc/passwd | grep "^-rw-r--r--"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.7 Verify User/Group Ownership on /etc/shadow (Scored)
auditStep="9.1.7 Verify User/Group Ownership on /etc/shadow (Scored)"
auditCmd=`/bin/ls -l /etc/shadow | grep "^----------"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.8 Verify User/Group Ownership on /etc/gshadow (Scored)
auditStep="9.1.8 Verify User/Group Ownership on /etc/gshadow (Scored)"
auditCmd=`/bin/ls -l /etc/gshadow | grep "^----------"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.9 Verify User/Group Ownership on /etc/group (Scored)
auditStep="9.1.9 Verify User/Group Ownership on /etc/group (Scored)"
auditCmd=`/bin/ls -l /etc/group | grep "^-rw-r--r--"`
audit_WithOutput "$auditStep" "$auditCmd"
#9.1.10 Find World Writable Files (Not Scored)
auditStep="9.1.10 Find World Writable Files (Not Scored)"
#auditCmd=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.1.11 Find Un-owned Files and Directories (Scored)
auditStep="9.1.11 Find Un-owned Files and Directories (Scored)"
auditCmd=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls`
audit_WithNoOutput "$auditStep" "$auditCmd"
#9.1.12 Find Un-grouped Files and Directories (Scored)
auditStep="9.1.12 Find Un-grouped Files and Directories (Scored)"
auditCmd=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls`
audit_WithNoOutput "$auditStep" "$auditCmd"
#9.1.13 Find SUID System Executables (Not Scored)
auditStep="9.1.13 Find SUID System Executables (Not Scored)"
#auditCmd=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.1.14 Find SGID System Executables (Not Scored)
auditStep="9.1.14 Find SGID System Executables (Not Scored)"
#auditCmd=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print`
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#####################################################################
#9.2 Review User and Group Settings
#9.2.1 Ensure Password Fields are Not Empty (Scored)
auditStep="9.2.1 Ensure Password Fields are Not Empty (Scored)"
auditCmd=`/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}'`
audit_WithNoOutput "$auditStep" "$auditCmd"
#9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)
auditStep="9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)"
auditCmd=`/bin/grep '^+:' /etc/passwd`
audit_WithNoOutput "$auditStep" "$auditCmd"
#9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)
auditStep="9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)"
auditCmd=`/bin/grep '^+:' /etc/shadow`
audit_WithNoOutput "$auditStep" "$auditCmd"
#9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)
auditStep="9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)"
auditCmd=`/bin/grep '^+:' /etc/group`
audit_WithNoOutput "$auditStep" "$auditCmd"
#9.2.5 Verify No UID 0 Accounts Exist Other Than root (Scored)
auditStep="9.2.5 Verify No UID 0 Accounts Exist Other Than root (Scored)"
auditCmd=`/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' | grep 'root'`
audit_WithOutput "$auditStep" "$auditCmd"
#9.2.6 Ensure root PATH Integrity (Scored)
# #!/bin/bash
# if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
#     echo "Empty Directory in PATH (::)"
# fi
# if [ "`echo $PATH | bin/grep :$`"  != "" ]; then
#     echo "Trailing : in PATH"
# fi
# p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
# set -- $p
# while [ "$1" != "" ]; do
#     if [ "$1" = "." ]; then
#         echo "PATH contains ."
#         shift
#         continue
#     fi
#     if [ -d $1 ]; then
#         dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
#         if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
#             echo "Group Write permission set on directory $1"
#         fi
#         if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
#             echo "Other Write permission set on directory $1"
#         fi
#             dirown=`ls -ldH $1 | awk '{print $3}'`
#            if [ "$dirown" != "root" ] ; then
#              echo $1 is not owned by root
# fi else
#             echo $1 is not a directory
# ￼￼￼fi shift
# done
auditStep="9.2.6 Ensure root PATH Integrity (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.7 Check Permissions on User Home Directories (Scored)
# #!/bin/bash
# for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
#     /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
#         dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
#         if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
#             echo "Group Write permission set on directory $dir"
#         fi
# if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
#     echo "Other Read permission set on directory $dir"
# fi
# if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
#     echo "Other Write permission set on directory $dir"
# fi
# if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
#     echo "Other Execute permission set on directory $dir"
# fi
# done
auditStep="9.2.7 Check Permissions on User Home Directories (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.8 Check User Dot File Permissions (Scored)
# #!/bin/bash
# for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
# /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
#     for file in $dir/.[A-Za-z0-9]*; do
#         if [ ! -h "$file" -a -f "$file" ]; then
#             fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
#             if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
#                 echo "Group Write permission set on file $file"
#             fi
#             if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
# echo "Other Write permission set on file $file"
#             fi
# fi done
# done
auditStep="9.2.8 Check User Dot File Permissions (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.9 Check Permissions on User .netrc Files (Scored)
# #!/bin/bash
# for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
#     /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
#     for file in $dir/.netrc; do
#         if [ ! -h "$file" -a -f "$file" ]; then
#             fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
#             if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
#             then
#                 echo "Group Read set on $file"
#             fi
#             if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
#             then
#                 echo "Group Write set on $file"
#             fi
#             if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
#             then
#                 echo "Group Execute set on $file"
#             fi
#             if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
#             then
# echo "Other Read  set on $file"
#             fi
#             if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
#             then
#                 echo "Other Write set on $file"
#             fi
#             if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
#             then
#                 echo "Other Execute set on $file"
#             fi
# fi done
# done
auditStep="9.2.9 Check Permissions on User .netrc Files (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.10 Check for Presence of User .rhosts Files (Scored)
# #!/bin/bash
# for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
#     /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
#     for file in $dir/.rhosts; do
#         if [ ! -h "$file" -a -f "$file" ]; then
#             echo ".rhosts file in $dir"
# fi done done
auditStep="9.2.10 Check for Presence of User .rhosts Files (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.11 Check Groups in /etc/passwd (Scored)
# #!/bin/bash
# for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
# grep -q -P "^.*?:x:$i:" /etc/group
# if [ $? -ne 0 ]; then
# echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
# fi
# done
auditStep="9.2.11 Check Groups in /etc/passwd (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.12 Check That Users Are Assigned Valid Home Directories (Scored)
##!/bin/bash
# cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
# if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
# echo "The home directory ($dir) of user $user does not exist."
# fi
# done
auditStep="9.2.12 Check That Users Are Assigned Valid Home Directories (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.13 Check User Home Directory Ownership (Scored)
# #!/bin/bash
# cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
# if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
# owner=$(stat -L -c "%U" "$dir")
# if [ "$owner" != "$user" ]; then
# echo "The home directory ($dir) of user $user is owned by $owner."
# fi
# fi
# done
auditStep="9.2.13 Check User Home Directory Ownership (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.14 Check for Duplicate UIDs (Scored)
# #!/bin/bash
# echo "The Output for the Audit of Control 9.2.15 - Check for Duplicate UIDs is"
# /bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
#     while read x ; do
#     [ -z "${x}" ] && break
#     set - $x
#     if [ $1 -gt 1 ]; then
#         users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
#             /etc/passwd | /usr/bin/xargs`
#         echo "Duplicate UID ($2): ${users}"
#     fi
# done
auditStep="9.2.14 Check for Duplicate UIDs (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.15 Check for Duplicate GIDs (Scored)
# #!/bin/bash
# echo "The Output for the Audit of Control 9.2.16 - Check for Duplicate GIDs is"
# /bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
#     while read x ; do
#     [ -z "${x}" ] && break
#     set - $x
#     if [ $1 -gt 1 ]; then
#         grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
#             /etc/group | xargs`
#         echo "Duplicate GID ($2): ${grps}"
# fi done
auditStep="9.2.15 Check for Duplicate GIDs (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.16 Check for Duplicate User Names (Scored)
# #!/bin/bash
# echo "The Output for the Audit of Control 9.2.18 - Check for Duplicate User Names is"
# cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
#     while read x ; do
#     [ -z "${x}" ] && break
#     set - $x
#     if [ $1 -gt 1 ]; then
#         uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
#             /etc/passwd | xargs`
#         echo "Duplicate User Name ($2): ${uids}"
#     fi
# done
auditStep="9.2.16 Check for Duplicate User Names (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.17 Check for Duplicate Group Names (Scored)
# #!/bin/bash
# echo "The Output for the Audit of Control 9.2.19 - Check for Duplicate Group Names is"
# cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
#     while read x ; do
#     [ -z "${x}" ] && break
#     set - $x
#     if [ $1 -gt 1 ]; then
#         gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
#             /etc/group | xargs`
#         echo "Duplicate Group Name ($2): ${gids}"
# ￼￼￼fi done
auditStep="9.2.17 Check for Duplicate Group Names (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.18 Check for Presence of User .netrc Files (Scored)
# #!/bin/bash
# for dir in `/bin/cat /etc/passwd |\
#     /bin/awk -F: '{ print $6 }'`; do
#     if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#         echo ".netrc file $dir/.netrc exists"
#     fi
# done
auditStep="9.2.18 Check for Presence of User .netrc Files (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"
#9.2.19 Check for Presence of User .forward Files (Scored)
# #!/bin/bash
# for dir in `/bin/cat /etc/passwd |\
#     /bin/awk -F: '{ print $6 }'`; do
#     if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
#         echo ".forward file $dir/.forward exists"
#     fi
# done
auditStep="9.2.19 Check for Presence of User .forward Files (Scored)"
auditCmd=""
audit_Exception "$auditStep" "$auditCmd"


#####################################################################
# Additional hardening settings as required by Security
# Security.1 sudoers configuration
#this will find if the suders file is correctly configured with admins
auditStep="Security.1.1 admins Sudoers Audit"
auditCmd=`grep -e "^%admins ALL=(ALL:ALL) ALL" /etc/sudoers`
audit_WithOutput "$auditStep" "$auditCmd"
#this will find if the suders file is correctly configured with admins
auditStep="Security.1.2 No passwordless sudo"
auditCmd=`grep "NOPASSWD" /etc/sudoers | grep -v '#'`
audit_WithNoOutput "$auditStep" "$auditCmd"
#####################################################################
# Security.2 llow auditd to get the calling user's uid correctly when calling sudo or su
auditStep="Security.2.1 pam_loginuid.so in /etc/pam.d/login"
auditCmd=`grep -E "session\s+required\s+pam_loginuid.so" /etc/pam.d/login`
audit_WithOutput "$auditStep" "$auditCmd"
#This will allow auditd to get the calling user's uid correctly when calling sudo or su.
auditStep="Security.2.2 pam_loginuid.so in /etc/pam.d/gdm"
auditCmd=`grep -E "session\s+required\s+pam_loginuid.so" /etc/pam.d/gdm`
audit_WithOutput "$auditStep" "$auditCmd"
#This will allow auditd to get the calling user's uid correctly when calling sudo or su.
auditStep="Security.2.3 pam_loginuid.so in /etc/pam.d/sshd"
auditCmd=`grep -E "session\s+required\s+pam_loginuid.so" /etc/pam.d/sshd`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
# Security.3 bashrc configuration
userCounter=1
for user in `ls /home`; do
	#This will check if each user's bashrc is configured correctly
	auditStep="Security.3.$userCounter reconfigure bashrc for $user"
	auditCmd=`egrep "export HISTCONTROL=ignoredups:erasedups|export HISTSIZE=100000|export HISTFILESIZE=100000|export HISTTIMEFORMAT=\"%m/%d/%y %T \"|shopt -s histappend|export PROMPT_COMMAND=" /home/$user/.bashrc`
	audit_WithOutput "$auditStep" "$auditCmd"
	#increment Counter
	userCounter=$((userCounter+1))
done
#reconfigure /root/bashrc
userCounter=$((userCounter+1))
auditStep="Security.3.$userCounter reconfigure bashrc for Root"
auditCmd=`egrep "export HISTCONTROL=ignoredups:erasedups|export HISTSIZE=100000|export HISTFILESIZE=100000|export HISTTIMEFORMAT=\"%m/%d/%y %T \"|shopt -s histappend|export PROMPT_COMMAND=" /home/$user/.bashrc`
audit_WithOutput "$auditStep" "$auditCmd"
#reconfigure /etc/skel/.bashrc
userCounter=$((userCounter+1))
auditStep="Security.3.$userCounter reconfigure bashrc for skel"
auditCmd=`egrep "export HISTCONTROL=ignoredups:erasedups|export HISTSIZE=100000|export HISTFILESIZE=100000|export HISTTIMEFORMAT=\"%m/%d/%y %T \"|shopt -s histappend|export PROMPT_COMMAND=" /home/$user/.bashrc`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################
# Security.4 ssh configuration
#this will find if the sshd_config file is correctly configured with admins
#replace with the usernames of your choice
auditStep="Security.4.1 admins SSH Audit"
auditCmd=`grep -e "^AllowGroups admins users whomever" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#this will find if the sshd_config file is correctly configured using SSH protocol 2 only
auditStep="Security.4.2 admins SSH Audit"
auditCmd=`grep -e "^Protocol 2" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#this will find if the sshd_config file is correctly configured to not use empty passwords
auditStep="Security.4.3 PermitEmptyPasswords Audit"
auditCmd=`grep -e "^PermitEmptyPasswords no" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#this will find if the sshd_config file is correctly configured to not permit root login
auditStep="Security.4.4 PermitRootLogin Audit"
auditCmd=`grep -e "^PermitRootLogin no" /etc/ssh/sshd_config`
audit_WithOutput "$auditStep" "$auditCmd"
#####################################################################

