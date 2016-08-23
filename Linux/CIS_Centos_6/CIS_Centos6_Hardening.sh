#!/bin/bash
# hardening script Centos 6
# Author Ryan Nolette
# Date Modified 06/26/2016
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
############################
#1 Install Updates, Patches and Additional Security Software
#1.1 Filesystem Configuration
############################
# Configured as part of initial system build and OS install ############################
# #1.1.1 Create Separate Partition for /tmp
# #1.1.2 Set nodev option for /tmp Partition 
# #1.1.3 Set nosuid option for /tmp Partition 
# #1.1.4 Set noexec option for /tmp Partition 
# #1.1.5 Create Separate Partition for /var 
# #1.1.6 Bind Mount the /var/tmp directory to /tmp 
# #1.1.7 Create Separate Partition for /var/log 
# #1.1.8 Create Separate Partition for /var/log/audit 
# #1.1.9 Create Separate Partition for /home 
# #1.1.10 Add nodev Option to /home 
# #1.1.11 Add nodev Option to Removable Media Partitions 
# #1.1.12 Add noexec Option to Removable Media Partitions 
# #1.1.13 Add nosuid Option to Removable Media Partitions
# #1.1.14 Add nodev Option to /dev/shm Partition 
# #1.1.15 Add nosuid Option to /dev/shm Partition 
# #1.1.16 Add noexec Option to /dev/shm Partition 
############################
#1.1.17 Set Sticky Bit on All World-Writable Directories 
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs chmod a+t
#1.1.18 Disable Mounting of cramfs Filesystems 
#1.1.19 Disable Mounting of freevxfs Filesystems 
#1.1.20 Disable Mounting of jffs2 Filesystems 
#1.1.21 Disable Mounting of hfs Filesystems 
#1.1.22 Disable Mounting of hfsplus Filesystems 
#1.1.23 Disable Mounting of squashfs Filesystems 
#1.1.24 Disable Mounting of udf Filesystems 
touch /etc/modprobe.d/CIS.conf
/bin/cat << EOM > /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOM
############################
# 1.2 Configure Software Updates
#Current update mechanism excludes kernel updates so that updates do not break common applications
yum update -y --exclude=kernel*
# 1.2.1 Verify CentOS GPG Key is Installed
gpg --quiet --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6
# 1.2.2 Verify that gpgcheck is Globally Activated 
#Edit the /etc/yum.conf file and set the gpgcheck to 1 as follows: gpgcheck=1
sed -i 's/gpgcheck=0/gpgcheck=1/' /etc/yum.conf
# 1.2.3 Obtain Software Package Updates with yum
#previously used -i yum update -y --exclude=kernel*
# 1.2.4 Verify Package Integrity Using RPM 
#If any output shows up, you may have an integrity issue with that package
rpm -qVa | awk '$2 != "c" { print $0}' 
############################
# only do this if you do not already have endpoint security software you are deploying
# 1.3 Advanced Intrusion Detection Environment (AIDE)
# 1.3.1 Install AIDE 
#yum -y install aide
#Initialize AIDE:
#/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz`
#Note: The prelinking feature can interfere with AIDE because it alters binaries to speed up their start up 
#times. Set PRELINKING=no in /etc/sysconfig/prelink and run /usr/sbin/prelink -ua to restore the binaries 
#to their prelinked state, thus avoiding false positives from AIDE.
sed -i 's/PRELINKING=yes/PRELINKING=no/' /etc/sysconfig/prelink 
/usr/sbin/prelink -ua
# 1.3.2 Implement Periodic Execution of File Integrity 
#"Execute the following command: # crontab -u root -e
#Add the following line to the crontab: 0 5 * * * /usr/sbin/aide --check
#Note: The checking in this instance occurs every day at 5am. Alter the frequency and time of the checks in compliance with site policy."
#crontab -u root -e
#crontab -l > /tmp/crontmp
#echo "0 5 * * * /usr/sbin/aide --check" >> /tmp/crontmp
#crontab /tmp/crontmp
#rm /tmp/crontmp
############################
# 1.4 Configure SELinux
# 1.4.1 Enable SELinux in /etc/grub.conf 
# 1.4.1 Enable SELinux in /etc/grub.conf
#Remove all instances of selinux=0 and enforcing=0 from /etc/grub.conf.
sed -i 's/selinux=0/selinux=1/' /etc/grub.conf
sed -i 's/enforcing=0/enforcing=1/' /etc/grub.conf
# 1.4.2 Set the SELinux State 
#Edit the /etc/selinux/config file to set the SELINUX parameter: SELINUX=enforcing
sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config 
# 1.4.3 Set the SELinux Policy 
#Edit the /etc/selinux/config file to set the SELINUXTYPE parameter: SELINUXTYPE=targeted 
#Note: If your organization requires stricter policies, make sure they are added to the /etc/selinux/config file.
sed -i 's/SELINUXTYPE=mls/SELINUXTYPE=targeted/' /etc/selinux/config
# 1.4.4 Remove SETroubleshoot 
yum -y erase setroubleshoot
# 1.4.5 Remove MCS Translation Service (mcstrans)
yum -y erase mcstrans
# 1.4.6 Check for Unconfined Daemons 
#Perform the following to determine if unconfined daemons are running on the system. 
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' [no output produced]
############################
# 1.5 Secure Boot Settings
# 1.5.1 Set User/Group Owner on /etc/grub.conf 
chown root:root /etc/grub.conf
# 1.5.2 Set Permissions on /etc/grub.conf 
chmod og-rwx /etc/grub.conf
# 1.5.3 Set Boot Loader Password #only do this if the system is not a VM
#"Use grub-md5-crypt to produce an encrypted password: # grub-md5-crypt Password: Retype password: [Encrypted Password]
#Set the password parameter to[Encrypted Password] in /etc/grub.conf: password --md5 [Encrypted Password]"
# 1.5.4 Require Authentication for Single-User Mode 
#Run the following to edit /etc/sysconfig/init: sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init sed -i "/PROMPT/s/yes/no/" /etc/sysconfig/init
sed -i "/SINGLE/s/sushell/sulogin/" /etc/sysconfig/init 
sed -i "/PROMPT/s/yes/no/" /etc/sysconfig/init
# 1.5.5 Disable Interactive Boot 
#Set the PROMPT parameter in /etc/sysconfig/init to no. PROMPT=no
sed -i 's/PROMPT=yes/PROMPT=no/' /etc/sysconfig/init
############################
# 1.6 Additional Process Hardening
# 1.6.1 Restrict Core Dumps 
echo "* hard core 0" >> /etc/security/limits.conf
# 1.6.2 Configure ExecShield  - #done lower in the script
#echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
# 1.6.3 Enable Randomized Virtual Memory Region Placement - #done lower in the script
#echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf 
############################
# 1.7 Use the Latest OS Release 
echo "# 1.7 Use the Latest OS Release - not done"
############################
#2.1 Remove Legacy Services
#2.1.1 Remove telnet-server
yum -y erase telnet-server
#2.1.2 Remove telnet Clients 
yum -y erase telnet
#2.1.3 Remove rsh-server	
yum -y erase rsh-server
#2.1.4 Remove rsh 	
yum -y erase rsh
#2.1.5 Remove NIS Client 
yum -y erase ypbind
#2.1.6 Remove NIS Server 	
yum -y erase ypserv
#2.1.7 Remove tftp 	
yum -y erase tftp
#2.1.8 Remove tftp-server
yum -y erase tftp-server
#2.1.9 Remove talk 	
yum -y erase talk
#2.1.10 Remove talk-server 	
yum -y erase talk-server
#2.1.11 Remove xinetd 	
yum -y erase xinetd
#2.1.12 Disable chargen-dgram 	
chkconfig chargen-dgram off
#2.1.13 Disable chargen-stream 	
chkconfig chargen-stream off
#2.1.14 Disable daytime-dgram 	
chkconfig daytime-dgram off
#2.1.15 Disable daytime-stream 	
chkconfig daytime-stream off
#2.1.16 Disable echo-dgram 	
chkconfig echo-dgram off
#2.1.17 Disable echo-stream 	
chkconfig echo-stream off
#2.1.18 Disable tcpmux-server 	
chkconfig tcpmux-server off
############################
#3 Special Purpose Services	N/A
#3.1 Set Daemon umask 	
#Add the following line to the /etc/sysconfig/init file. umask 027
echo "umask 027" >> /etc/sysconfig/init
############################
#3.2 Remove X Windows 	
#"Edit the /etc/inittab file to set the default runlevel as follows: id:3:initdefault:
sed -i 's/id:5:initdefault:/id:3:initdefault:/' /etc/inittab
#Uninstall the X Windows system: 
yum groupremove ""X Window System""
############################
#3.3 Disable Avahi Server 	"
chkconfig avahi-daemon off
#In addition, edit the /etc/sysconfig/network file and remove zeroconf."
#zeroconf doesnt exist on the default install I tested against. no action to take.
############################
#3.4 Disable Print Server - CUPS 	
chkconfig cups off
############################
#3.5 Remove DHCP Server 	
yum -y erase dhcp
############################
#3.6 Configure Network Time Protocol (NTP)	
#"NTP is configured by default in CentOS 6. If for some reason, it is not configured on your system, set the following restrict parameters 
#in /etc/ntp.conf: restrict default kod nomodify notrap nopeer noquery restrict -6 default kod nomodify notrap nopeer noquery. 
#Also, make sure /etc/ntp.conf has an NTP server specified: server <ntp-server>
#Note: <ntp-server> is the IP address or hostname of a trusted time server. Configuring an NTP server is outside the scope of this benchmark."
#this command uses the built in package manager to install the NTP package and dependencies
yum -y install ntp ntpdate ntp-doc
#this turns the ntp daemon on
chkconfig ntpd on
#get time from this source
ntpdate 10.32.0.10
#restart ntp daemon now
/etc/init.d/ntpd restart
#backup ntpconf
cp /etc/ntp.conf /etc/ntp.conf.bk
#this will write the below content to the ntp configuration file
/bin/cat << EOM > /etc/ntp.conf
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
# line 19: add the network range you allow to receive requests
#this restricts requests to just the internal 10.x.x.x block
#you can also add 192.168.x.x and 172.16.x.x
restrict 10.0.0.0 mask 255.255.255.0 nomodify notrap
# change servers for synchronization
#server 0.rhel.pool.ntp.org
#server 1.rhel.pool.ntp.org
#server 2.rhel.pool.ntp.org
#use local NTP like the below example if possible
server 10.0.0.2
server 10.0.0.3
EOM
#restart ntp daemon now that everything is configured
/etc/rc.d/init.d/ntpd restart
############################
#3.7 Remove LDAP 
yum -y erase openldap-servers 
yum -y erase openldap-clients
############################
#3.8 Disable NFS and RPC
chkconfig nfslock off 
chkconfig rpcgssd off 
chkconfig rpcbind off 
chkconfig rpcidmapd off 
chkconfig rpcsvcgssd off
############################
#3.9 Remove DNS Server 	
yum -y erase bind
############################
#3.10 Remove FTP Server 	
yum -y erase vsftpd
############################
#3.11 Remove HTTP Server 	
yum -y erase httpd
############################
#3.12 Remove Dovecot (IMAP and POP3 services)	
yum -y erase dovecot
############################
#3.13 Remove Samba 	
yum -y erase samba
############################
#3.14 Remove HTTP Proxy Server 	
yum -y erase squid
############################
#3.15 Remove SNMP Server 	
yum -y erase net-snmp
############################
#3.16 Configure Mail Transfer Agent for Local-Only Mode 	
#Edit /etc/postfix/main.cf and add the following line to the RECEIVING MAIL section. 
#If the line already exists, change it to look like the line below. inet_interfaces = localhost 
# Execute the following command to restart postfix # service postfix restart
sed -i 's/inet_interfaces = all/inet_interfaces = localhost/' /etc/postfix/main.cf
sed -i 's/inet_interfaces = $myhostname/inet_interfaces = localhost/' /etc/postfix/main.cf
sed -i 's/inet_interfaces = $myhostname, localhost/inet_interfaces = localhost/' /etc/postfix/main.cf
#restart postfix service
service postfix restart
############################
#4.1 Modify Network Parameters (Host Only)
#4.1.1 Disable IP Forwarding 	
#4.1.2 Disable Send Packet Redirects 	
#4.2 Modify Network Parameters (Host and Router)
#4.2.1 Disable Source Routed Packet Acceptance 
#4.2.2 Disable ICMP Redirect Acceptance
#4.2.3 Disable Secure ICMP Redirect Acceptance
#4.2.4 Log Suspicious Packets
#4.2.5 Enable Ignore Broadcast Requests
#4.2.6 Enable Bad Error Message Protection
#4.2.7 Enable RFC-recommended Source Route Validation
#4.2.8 Enable TCP SYN Cookies
# /etc/sysctl.conf
cat << 'EOM' >> /etc/sysctl.conf
# Benchmark Adjustments
kernel.exec-shield=1                                  # 1.6.2
kernel.randomize_va_space=2                           # 1.6.3
net.ipv4.ip_forward=0                                 # 4.1.1
net.ipv4.conf.all.send_redirects=0                    # 4.1.2
net.ipv4.conf.default.send_redirects=0                # 4.1.2
net.ipv4.conf.all.accept_source_route=0               # 4.2.1
net.ipv4.conf.default.accept_source_route=0           # 4.2.1
net.ipv4.conf.all.accept_redirects=0                  # 4.2.2
net.ipv4.conf.default.accept_redirects=0              # 4.2.2
net.ipv4.conf.all.secure_redirects=0                  # 4.2.3
net.ipv4.conf.default.secure_redirects=0              # 4.2.3
net.ipv4.conf.all.log_martians=1                      # 4.2.4
net.ipv4.conf.default.log_martians=1                  # 4.2.4
net.ipv4.icmp_echo_ignore_broadcasts=1                # 4.2.5
net.ipv4.icmp_ignore_bogus_error_responses=1          # 4.2.6
net.ipv4.conf.all.rp_filter=1                         # 4.2.7
net.ipv4.conf.default.rp_filter=1                     # 4.2.7
net.ipv4.tcp_syncookies=1                             # 4.2.8
net.ipv6.conf.default.disable_ipv6=0				  # 4.4.1
net.ipv6.conf.all.disable_ipv6=0					  # 4.4.1
net.ipv6.conf.all.accept_ra=0 						  # 4.4.1.1
net.ipv6.conf.default.accept_ra=0					  # 4.4.1.1
net.ipv6.conf.all.accept_redirects=0				  # 4.4.1.2
net.ipv6.conf.default.accept_redirect=0				  # 4.4.1.2
net.ipv6.route.flush=1								  # 4.4.1.1
EOM
############################
#4.3 Wireless Networking
# not done since my servers dont have wireless
############################
#4.3.1 Deactivate Wireless Interfaces	
#ifconfig -a
#iwconfig
#ifdown interface
#rm /etc/sysconfig/network-scripts/ifcfg-
############################
#4.4 Disable IPv6
#4.4.1 Configure IPv6	
#turn off IPV6
#echo "net.ipv6.conf.default.disable_ipv6=0" >> /etc/sysctl.conf
#echo "net.ipv6.conf.all.disable_ipv6=0" >> /etc/sysctl.conf
#4.4.1.1 Disable IPv6 Router Advertisements 	
#"Set the net.ipv6.conf.all.accept_ra and net.ipv6.conf.default.accept_ra parameter to 0 in /etc/sysctl.conf: 
#net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
#Modify active kernel parameters to match: # 
/sbin/sysctl -w net.ipv6.conf.all.accept_ra=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_ra=0
/sbin/sysctl -w net.ipv6.route.flush=1
#4.4.1.2 Disable IPv6 Redirect Acceptance 	
#"Set the net.ipv6.conf.all.accept_redirects and net.ipv6.conf.default.accept_redirects parameters to 0 in /etc/sysctl.conf: 
#net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0
#Modify active kernel parameters to match: # 
/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0 
/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0 
/sbin/sysctl -w net.ipv6.route.flush=1
#4.4.2 Disable IPv6	
#"Edit /etc/sysconfig/network, and add the following line: NETWORKING_IPV6=no IPV6INIT=no
#Create the file /etc/modprobe.d/ipv6.conf and add the following lines: options ipv6 disable=1
#Perform the following command to turn ip6tables off: # /sbin/chkconfig ip6tables off"
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
touch /etc/modprobe.d/ipv6.conf 
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
/sbin/chkconfig ip6tables off
############################
#4.5 Install TCP Wrappers
#4.5.1 Install TCP Wrappers
yum -y install tcp_wrappers
#4.5.2 Create /etc/hosts.allow
# only allow internally routeable addresses
touch /etc/hosts.allow
echo "ALL: 10.0.0.0/255.0.0.0" >/etc/hosts.allow
echo "ALL: 172.16.0.0/255.240.0.0" >>/etc/hosts.allow
echo "ALL: 192.168.0.0/255.255.0.0" >>/etc/hosts.allow
#4.5.3 Verify Permissions on /etc/hosts.allow 	
#If the permissions of the /etc/hosts.allow file are incorrect, run the following command to correct them: # /bin/chmod 644 /etc/hosts.allow
/bin/chmod 644 /etc/hosts.allow
#4.5.4 Create /etc/hosts.deny 	
touch /etc/hosts.deny
echo "ALL: ALL" >> /etc/hosts.deny
#4.5.5 Verify Permissions on /etc/hosts.deny 
#"If the permissions of the /etc/hosts.deny file are incorrect, run the following command to correct them:
/bin/chmod 644 /etc/hosts.deny
############################
#4.6 Uncommon Network Protocols
#4.6.1 Disable DCCP 	# 
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
#4.6.2 Disable SCTP 	# 
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
#4.6.3 Disable RDS 	# 
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
#4.6.4 Disable TIPC 	# 
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
############################
#4.7 Enable IPtables 	"# 
service iptables restart 
chkconfig iptables on
#Note: The iptables firewall should be configured to only accept on required ports and services."
############################
#4.8 Enable IP6tables 	"# turning off IVP6 at every step
chkconfig --level 0123456 ip6tables off
service ip6tables restart 
#chkconfig ip6tables on
#Note: The ip6tables firewall should be configured to only accept on required ports and services."
############################
#5.1 Configure rsyslog
#5.1.1 Install the rsyslog package 	
yum -y install rsyslog
#5.1.2 Activate the rsyslog Service 	
chkconfig syslog off 
chkconfig rsyslog on
#5.1.3 Configure /etc/rsyslog.conf 	
#Edit the following lines in the /etc/rsyslog.conf file as appropriate for your environment:
echo "auth,user.* /var/log/messages" >> /etc/rsyslog.conf
echo "kern.* /var/log/kern.log" >> /etc/rsyslog.conf
echo "daemon.* /var/log/daemon.log" >> /etc/rsyslog.conf
echo "syslog.* /var/log/syslog" >> /etc/rsyslog.conf
echo "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log" >> /etc/rsyslog.conf
# Execute the following command to restart rsyslogd
pkill -HUP rsyslogd
#5.1.4 Create and Set Permissions on rsyslog Log Files 	
# touch <logfile>
# chown root:root <logfile> 
# chmod og-rwx <logfile>
touch /var/log/messages
chown root:root /var/log/messages
chmod og-rwx /var/log/messages
touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod og-rwx /var/log/kern.log
touch /var/log/daemon.log
chown root:root /var/log/daemon.log
chmod og-rwx /var/log/daemon.log
touch /var/log/syslog
chown root:root /var/log/syslog
chmod og-rwx /var/log/syslog
touch /var/log/unused.log
chown root:root /var/log/unused.log
chmod og-rwx /var/log/unused.log
#5.1.5 Configure rsyslog to Send Logs to a Remote Log Host 	 - not done. using splunk forwarder instead"
#"Edit the /etc/rsyslog.conf file and add the following line (where logfile.example.com is the name of your central log host). 
#*.* @@loghost.example.com # Execute the following command to restart rsyslogd # pkill -HUP rsyslogd
#Note: The double ""at"" sign (@@) directs rsyslog to use TCP to send log messages to the server, 
#which is a more reliable transport mechanism than the default UDP protocol."
#5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts 	 - not done. using splunk forwarder instead"
#"For hosts that are designated as log hosts, edit the /etc/rsyslog.conf file and un-comment the following lines: 
#$ModLoad imtcp.so $InputTCPServerRun 514
#Execute the following command to restart rsyslogd: # pkill -HUP rsyslogd"
############################
#5.2 Configure System Accounting (auditd)
#5.2.1 Configure Data Retention
#5.2.1.1 Configure Audit Log Storage Size 
#"Set the max_log_file parameter in /etc/audit/auditd.conf max_log_file = <MB>
#Note: MB is the number of MegaBytes the file can be"
sed -i 's/max_log_file = 6/max_log_file = 100/' /etc/audit/auditd.conf
#5.2.1.2 Disable System on Audit Log Full 	
echo "space_left_action = email action_mail_acct = root admin_space_left_action = halt" >> /etc/audit/auditd.conf 
#5.2.1.3 Keep All Auditing Information 	
#Add the following line to the /etc/audit/auditd.conf file. max_log_file_action = keep_logs
echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf 
#5.2.2 Enable auditd Service 	
chkconfig auditd on
#5.2.3 Enable Auditing for Processes That Start Prior to auditd 	
# ed /etc/grub.conf << END g/audit=1/s///g g/kernel/s/$/ audit=1/ w q END
ed /etc/grub.conf << END
g/audit=1/s///g
g/kernel/s/$/ audit=1/
w
q 
END
############################
# /etc/audit/audit.rules
cat << 'EOM' >> /etc/audit/audit.rules
# Benchmark Adjustments
# 5.2.4
-a always,exit -F arch=b64 -S adjtimex -S settimEOMday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimEOMday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# 5.2.5
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
#secops required
#These will track all commands run by root (euid=0).
#Why two rules? The execve syscall must be tracked in both 32 and 64 bit code.
-a exit,always -F arch=b64 -F euid=0 -S execve
-a exit,always -F arch=b32 -F euid=0 -S execve
# 5.2.6
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
# 5.2.7
-w /etc/selinux/ -p wa -k MAC-policy
# 5.2.8
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
# 5.2.9
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
# 5.2.10
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
# 5.2.11
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
# 5.2.13
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
# 5.2.14
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
# 5.2.15
-w /etc/sudoers -p wa -k scope
# 5.2.16
-w /var/log/sudo.log -p wa -k actions
# 5.2.17
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
EOM
# 5.2.12
echo "# 5.2.12" >> /etc/audit/audit.rules
find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules
# 5.2.18
echo "-e 2" >> /etc/audit/audit.rules
############################
#5.3 Configure logrotate
#Edit the /etc/logrotate.d/syslog file to include appropriate system logs: 
#/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {
cat << 'EOM' >> /etc/audit/audit.rules
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/boot.log 
/var/log/spooler
{
    sharedscripts
    postrotate
	/bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOM
############################
#6.1 Configure cron and anacron
#6.1.1 Enable anacron Daemon 	
yum -y install cronie-anacron
#6.1.2 Enable crond Daemon 	
chkconfig crond on
#6.1.3 Set User/Group Owner and Permission on /etc/anacrontab
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
#6.1.4 Set User/Group Owner and Permission on /etc/crontab 	
chown root:root /etc/crontab 
chmod og-rwx /etc/crontab
#6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly
chown root:root /etc/cron.hourly 
chmod og-rwx /etc/cron.hourly
#6.1.6 Set User/Group Owner and Permission on /etc/cron.daily 	
chown root:root /etc/cron.daily 
chmod og-rwx /etc/cron.daily
#6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly 	
chown root:root /etc/cron.weekly 
chmod og-rwx /etc/cron.weekly
#6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly 	
chown root:root /etc/cron.monthly 
chmod og-rwx /etc/cron.monthly
#6.1.9 Set User/Group Owner and Permission on /etc/cron.d 	
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
#6.1.10 Restrict at Daemon
rm /etc/at.deny 
touch /etc/at.allow 
chown root:root /etc/at.allow 
chmod og-rwx /etc/at.allow
#6.1.11 Restrict at/cron to Authorized Users 	
touch /etc/cron.allow 
touch /etc/at.allow
#Run the following to ensure cron.deny and at.deny are removed and permissions are set correctly: 
/bin/rm /etc/cron.deny 
/bin/rm /etc/at.deny 
chmod og-rwx /etc/cron.allow 
chmod og-rwx /etc/at.allow 
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
############################
#6.2 Configure SSH - configured later in script
# 6.2.1
# 6.2.2
# 6.2.3
# 6.2.4
# 6.2.5
# 6.2.6
# 6.2.7
# 6.2.8
# 6.2.9
# 6.2.10
# 6.2.11
# 6.2.12
# 6.2.13
# 6.2.14
############################
#6.3 Configure PAM
#6.3.1 Upgrade Password Hashing Algorithm to SHA-512
authconfig --passalgo=sha512 --update
#If it is determined that the password algorithm being used -i is not SHA-512, once it is changed, it is recommended that all userID's be 
#immediately expired and forced to change their passwords on next login. To accomplish that, the following commands can be used.
#Any system accounts that need to be expired should be carefully done separately by the system administrator to prevent any potential problems.
#the below query will print you a list
# echo "Accounts that need to be expired: "
# cat /etc/passwd | awk -F: '( $3 >=500 && $1 != "nfsnobody" ) { print $1 }' | xargs -n 1 chage -d 0
# 6.3.2
#sed -i 's/password.+requisite.+pam_cracklib.so/password required pam_cracklib.so try_first_pass retry=3 minlen=14,dcredit=-1,ucredit=-1,ocredit=-1 lcredit=-1/' /etc/pam.d/system-auth
cat << 'EOM' > /etc/pam.d/system-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so
account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so
password    required     pam_cracklib.so password required pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5
password    required      pam_deny.so
password    requisite     pam_passwdqc.so min=disabled,disabled,16,12,8
session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOM
# 6.3.3
#sed -i -e '/pam_cracklib.so/{:a;n;/^$/!ba;i\password    requisite     pam_passwdqc.so min=disabled,disabled,16,12,8' -e '}' /etc/pam.d/system-auth
cat << 'EOM' > /etc/pam.d/password-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so
# cat /etc/pam.d/system-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so
auth        required      pam_deny.so
account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     required      pam_permit.so
password    requisite     pam_cracklib.so try_first_pass retry=3 type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    required      pam_deny.so
session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
EOM
#6.3.4 Limit Password Reuse
#Set the pam_unix.so remember parameter to 5 in /etc/pam.d/system-auth: password sufficient pam_unix.so remember=5
sed -i 's/^\(password.*sufficient.*pam_unix.so.*\)$/\1 remember=5/' /etc/pam.d/system-auth
############################
#6.4 Restrict root Login to System Console - not done
#Audit:
#cat /etc/securetty
#Remediation:
#Remove entries for any consoles that are not in a physically secure location.
############################
# 6.5
sed -i 's/^#\(auth.*required.*pam_wheel.so.*\)$/\1/' /etc/pam.d/su
############################
#7 User Accounts and Environment
#7.1 Set Shadow Password Suite Parameters (/etc/login.defs)
#7.1.1 Set Password Expiration Days
#7.1.2 Set Password Change Minimum Number of Days
#7.1.3 Set Password Expiring Warning Days
# 7.1.1-7.1.3
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
#find all login users
## get UID limit ##
l=$(grep "^UID_MIN" /etc/login.defs)
## use awk to print if UID >= $UID_LIMIT ##
loginusers=`awk -F':' -v "limit=${l##UID_MIN}" '{ if ( $3 >= limit ) print $1}' /etc/passwd`
#loop through login user list and set password max age to 90 days
for user in $loginusers; do
        echo $user
        chage --maxdays 90 $user
        chage --mindays 7 $user
        chage --warndays 7 $user
done
############################
#7.2 Disable System Accounts
#Run the following script to determine if any system accounts can be accessed: There should be no results returned.
echo "7.2 - Determine if any system accounts can be accessed: There should be no results returned."
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}'
#Accounts that have been locked are prohibited from running commands on the system. Such accounts are not able to login to the system nor are they able to use scheduled execution facilities such as cron. To make sure system accounts cannot be accessed, using the following script:￼￼￼￼
touch /tmp/disable.sh
cat << 'EOM' > /tmp/disable.sh
#!/bin/bash
for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd`; do
   if [ $user != "root" ]
then
      /usr/sbin/usermod -L $user
      if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]
      then
         /usr/sbin/usermod -s /sbin/nologin $user
      fi
fi done
EOM
bash /tmp/disable.sh
############################
#7.3 Set Default Group for root Account
usermod -g 0 root
############################
#7.4 Set Default umask for Users
#Edit the /etc/bashrc and /etc/profile files (and the appropriate files for any other shell supported on your system) and 
#add the following the UMASK parameter as shown:
echo "umask 077" >> /etc/bashrc
echo "umask 077" >> /etc/profile
############################
#7.5 Lock Inactive User Accounts
useradd -D -f 35
############################
#8 Warning Banners
#8.1 Set Warning Banner for Standard Login Services
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
############################
#8.2 Remove OS Information from Login Warning Banners
egrep '(\\v|\\r|\\m|\\s)' /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/motd
egrep'(\\v|\\r|\\m|\\s)' /etc/issue.net
sed -i '/\v/d' /etc/issue
sed -i '/\r/d' /etc/issue
sed -i '/\m/d' /etc/issue
sed -i '/\s/d' /etc/issue
sed -i '/\v/d' /etc/motd
sed -i '/\r/d' /etc/motd
sed -i '/\m/d' /etc/motd
sed -i '/\s/d' /etc/motd
sed -i '/\v/d' /etc/issue.net
sed -i '/\r/d' /etc/issue.net
sed -i '/\m/d' /etc/issue.net
sed -i '/\s/d' /etc/issue.net
############################
#8.3 Set GNOME Warning Banner - not done because i removed xwindows. the isntallation of gnome would overwrite this setting anyways
############################
#9 System Maintenance
#9.1 Verify System File Permissions
#9.1.1 Verify System File Permissions - not done
#9.1.2 Verify Permissions on /etc/passwd
/bin/chmod 644 /etc/passwd
#9.1.3 Verify Permissions on /etc/shadow
/bin/chmod 000 /etc/shadow
#9.1.4 Verify Permissions on /etc/gshadow
/bin/chmod 000 /etc/gshadow
#9.1.5 Verify Permissions on /etc/group
/bin/chmod 644 /etc/group
#9.1.6 Verify User/Group Ownership on /etc/passwd
/bin/chown root:root /etc/passwd
#9.1.7 Verify User/Group Ownership on /etc/shadow
/bin/chown root:root /etc/shadow
#9.1.8 Verify User/Group Ownership on /etc/gshadow
/bin/chown root:root /etc/gshadow
#9.1.9 Verify User/Group Ownership on /etc/group
/bin/chown root:root /etc/group
#9.1.10 Find World Writable Files - not done
#9.1.11 Find Un-owned Files and Directories
echo "9.1.11 - Locate files that are owned by users or groups not listed in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate."
touch /tmp/unowned.sh
cat << 'EOM' > /tmp/unowned.sh
#!/bin/bash
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -
ls
EOM
bash /tmp/unowned.sh
#9.1.12 Find Un-grouped Files and Directories
echo "9.2.12 - Locate files that are owned by users or groups not listed in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate."
touch /tmp/ungrouped.sh
cat << 'EOM' > /tmp/ungrouped.sh
#!/bin/bash
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -
ls
EOM
bash /tmp/ungrouped.sh
#9.1.13 Find SUID System Executables - not done
#9.1.14 Find SGID System Executables
/bin/rpm -V `/bin/rpm -qf sudo`
############################
#9.2 Review User and Group Settings
#9.2.1 Ensure Password Fields are Not Empty
echo "#9.2.1 Ensure Password Fields are Not Empty"
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { /usr/bin/passwd -l $1}'
#9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File
echo "9.2.2 - Delete any entries that return"
/bin/grep '^+:' /etc/passwd
#9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File
echo "9.2.3 - Delete any entries that return"
/bin/grep '^+:' /etc/shadow
#9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File
echo "9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File"
echo "Delete any entries that return"
/bin/grep '^+:' /etc/group
#9.2.5 Verify No UID 0 Accounts Exist Other Than root
echo "#9.2.5 Verify No UID 0 Accounts Exist Other Than root"
echo "Delete any entries that return"
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }'
root
#9.2.6 Ensure root PATH Integrity
echo "#9.2.6 Ensure root PATH Integrity"
echo "Correct or justify any items discovered in the Audit step."
touch /tmp/rootpath.sh
cat << 'EOM' > /tmp/rootpath.sh
#!/bin/bash
if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | bin/grep :$`"  != "" ]; then
    echo "Trailing : in PATH"
fi
p=`echo $PATH | /bin/sed -i -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
        echo "PATH contains ."
        shift
        continue
    fi
    if [ -d $1 ]; then
        dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $1"
        fi
        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $1"
        fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
           if [ "$dirown" != "root" ] ; then
             echo $1 is not owned by root
fi else
            echo $1 is not a directory
fi shift
done
EOM
bash /tmp/rootpath.sh
#9.2.7 Check Permissions on User Home Directories
echo "#9.2.7 Check Permissions on User Home Directories"
echo "Correct or justify any items discovered in the Audit step."
touch /tmp/homedir.sh
cat << 'EOM' > /tmp/homedir.sh
#!/bin/bash
for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir"
        fi
if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
    echo "Other Read permission set on directory $dir"
fi
if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
    echo "Other Write permission set on directory $dir"
fi
if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
    echo "Other Execute permission set on directory $dir"
fi
done
EOM
bash /tmp/homedir.sh
#9.2.8 Check User Dot File Permissions
echo "#9.2.8 Check User Dot File Permissions"
echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user dot file permissions and determine the action to be taken in accordance with site policy."
touch /tmp/global.sh
cat << 'EOM' > /tmp/global.sh
#!/bin/bash
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file"
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
echo "Other Write permission set on file $file"
            fi
fi done
done
EOM
bash /tmp/global.sh
#9.2.9 Check Permissions on User .netrc Files
echo "#9.2.9 Check Permissions on User .netrc Files"
echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .netrc file permissions and determine the action to be taken in accordance with site policy."
touch /tmp/netrc.sh
cat << 'EOM' > /tmp/netrc.sh
#!/bin/bash
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file"
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file"
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file"
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
				echo "Other Read  set on $file"
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file"
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file"
            fi
fi done
done
EOM
bash /tmp/netrc.sh
#9.2.10 Check for Presence of User .rhosts Files
echo "#9.2.10 Check for Presence of User .rhosts Files"
echo "If any users have .rhosts files determine why they have them."
touch /tmp/rhosts.sh
cat << 'EOM' > /tmp/rhosts.sh
#!/bin/bash
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir"
		fi 
	done 
done
EOM
bash /tmp/rhosts.sh
#9.2.11 Check Groups in /etc/passwd
echo "#9.2.11 Check Groups in /etc/passwd"
echo "Analyze the output of the Audit step above and perform the appropriate action to correct any discrepancies found."
touch /tmp/passwd.sh
cat << 'EOM' > /tmp/passwd.sh
#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
	grep -q -P "^.*?:x:$i:" /etc/group
	if [ $? -ne 0 ]; then
		echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
	fi
done
EOM
bash /tmp/passwd.sh
#9.2.12 Check That Users Are Assigned Valid Home Directories
echo "#9.2.12 Check That Users Are Assigned Valid Home Directories"
echo "If any users' home directories do not exist, create them and make sure the respective user owns the directory. Users without an assigned home directory should be removed or assigned a home directory as appropriate."
touch /tmp/homedirs.sh
cat << 'EOM' > /tmp/homedirs.sh
#!/bin/bash
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
	if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
		echo "The home directory ($dir) of user $user does not exist."
	fi
done
EOM
bash /tmp/homedirs.sh
#9.2.13 Check User Home Directory Ownership
echo "#9.2.13 Check User Home Directory Ownership"
echo "Change the ownership any home directories that are not owned by the defined user to the correct user."
touch /tmp/homedirsowner.sh
cat << 'EOM' > /tmp/homedirsowner.sh
#!/bin/bash
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
	if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
		owner=$(stat -L -c "%U" "$dir")
	if [ "$owner" != "$user" ]; then
		echo "The home directory ($dir) of user $user is owned by $owner."
	fi
	fi
done
EOM
bash /tmp/homedirsowner.sh
#9.2.14 Check for Duplicate UIDs
echo "#9.2.14 Check for Duplicate UIDs"
echo "Based -i on the results of the script, establish unique UIDs and review all files owned by the shared UID to determine which UID they are supposed -i to belong to."
touch /tmp/dupUID.sh
cat << 'EOM' > /tmp/dupUID.sh
#!/bin/bash
echo "The Output for the Audit of Control 9.2.15 - Check for Duplicate UIDs is"
/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($2): ${users}"
    fi
done
EOM
bash /tmp/dupUID.sh
#9.2.15 Check for Duplicate GIDs
echo "#9.2.15 Check for Duplicate GIDs"
echo "Based -i on the results of the script, establish unique GIDs and review all files owned by the shared GID to determine which group they are supposed -i to belong to."
touch /tmp/dupGID.sh
cat << 'EOM' > /tmp/dupGID.sh
#!/bin/bash
echo "The Output for the Audit of Control 9.2.16 - Check for Duplicate GIDs is"
/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}"
fi 
done
EOM
bash /tmp/dupGID.sh
#9.2.16 Check for Duplicate User Names
echo "#9.2.16 Check for Duplicate User Names"
echo "Based -i on the results of the script, establish unique user names for the users. File ownerships will automatically reflect the change as long as the users have unique UIDs."
touch /tmp/dupusernames.sh
cat << 'EOM' > /tmp/dupusernames.sh
#!/bin/bash
echo "The Output for the Audit of Control 9.2.18 - Check for Duplicate User Names is"
cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"
    fi
done
EOM
bash /tmp/dupusernames.sh
#9.2.17 Check for Duplicate Group Names
echo "#9.2.17 Check for Duplicate Group Names"
echo "Based -i on the results of the script, establish unique names for the user groups. File group ownerships will automatically reflect the change as long as the groups have unique GIDs."
touch /tmp/dupgroupname.sh
cat << 'EOM' > /tmp/dupgroupname.sh
#!/bin/bash
echo "The Output for the Audit of Control 9.2.19 - Check for Duplicate Group Names is"
cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}"
	fi 
done
EOM
bash /tmp/dupgroupname.sh
#9.2.18 Check for Presence of User .netrc Files
echo "#9.2.18 Check for Presence of User .netrc Files"
echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .netrc files and determine the action to be taken in accordance with site policy."
touch /tmp/usernetrc.sh
cat << 'EOM' > /tmp/usernetrc.sh
#!/bin/bash
for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists"
    fi
done
EOM
bash /tmp/usernetrc.sh
#9.2.19 Check for Presence of User .forward Files
echo "#9.2.19 Check for Presence of User .forward Files"
echo "Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .forward files and determine the action to be taken in accordance with site policy."
touch /tmp/forward.sh
cat << 'EOM' > /tmp/forward.sh
#!/bin/bash
for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"
    fi
done
EOM
bash /tmp/forward.sh
#clean up tmp files
echo "#clean up tmp files"
rm -rf /tmp/*.sh
echo "###############################################################################"
echo "Run Additional haredning tasks"
#!/bin/bash
#get current directory
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
###############################################################################
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
##extended session timeout from 300 seconds (5minutes) to 900 seconds (15 minutes)
ClientAliveInterval 900
ClientAliveCountMax 0
MaxAuthTries 4
PermitEmptyPasswords no
## Adds a login banner that the user can see
#Banner /etc/motd
PrintMotd yes
## Add users or groups that are allowed to log in
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
##############################################################################
echo "configure firewall"
#opens http, https, ftp, and ssh
TCPPORTS=( 80 443 22 )
UDPPORTS=( 21 )
echo "--- Install and Clear IPTables Firewall  ---"
yum -y install -y iptables
chkconfig iptables on
/sbin/service iptables start
/sbin/iptables -F
/sbin/iptables -X
/etc/init.d/iptables save
echo "--- Running Firewall Configurations ---"
# By default reject all traffic
# /sbin/iptables -P INPUT DROP
# /sbin/iptables -P OUTPUT DROP
# /sbin/iptables -P FORWARD DROP
# Allow localhost
/sbin/iptables -A INPUT -i lo -j ACCEPT
/sbin/iptables -A OUTPUT -o lo -j ACCEPT
# Allow output for new, related and established connections
/sbin/iptables -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
echo "--- Blocking Common Attacks ---"
echo "Forcing SYN packets check"
/sbin/iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
echo "Forcing Fragments packets check"
/sbin/iptables -A INPUT -f -j DROP
echo "Dropping malformed XMAS packets"
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
echo "Drop all NULL packets"
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
echo "Limiting pings to 1 per second"
/sbin/iptables -N PACKET
/sbin/iptables -A DEFAULT_RULES -p icmp -m limit --limit 3/sec --limit-burst 25 -j ACCEPT
echo "Setup Connection Tracking"
/sbin/iptables -N STATE_TRACK
/sbin/iptables -A STATE_TRACK -m state --state RELATED,ESTABLISHED -j ACCEPT
/sbin/iptables -A STATE_TRACK -m state --state INVALID -j DROP
echo "Discouraging Port Scanning"
/sbin/iptables -N PORTSCAN
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ACK,FIN FIN -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ACK,PSH PSH -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ACK,URG URG -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL ALL -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL NONE -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
echo "--- configuring IPTables ---"
/sbin/iptables -N COMMON
/sbin/iptables -A COMMON -j STATE_TRACK
/sbin/iptables -A COMMON -j PORTSCAN
/sbin/iptables -A COMMON -j PACKET
/sbin/iptables -A INPUT -j COMMON
/sbin/iptables -A OUTPUT -j COMMON
/sbin/iptables -A FORWARD -j COMMON
/sbin/iptables -A FORWARD -j PACKET
/etc/init.d/iptables save
# Open TCP Ports
for port in ${TCPPORTS[@]}
	do
		echo "Opening TCP Port $port"
		/sbin/iptables -A INPUT -p tcp -m tcp --dport $port -j ACCEPT
	done
# Open UDP Ports
for port in ${UDPPORTS[@]}
	do
		echo "Opening UDP Port $port"
		/sbin/iptables -A INPUT -p udp -m udp --dport $port -j ACCEPT

	done
#save iptables config and restart iptables
/etc/init.d/iptables save
service iptables restart
##############################################################################
echo "Adding admins group to sudoers"
echo '%admins ALL=(ALL:ALL) ALL' >> /etc/sudoers
##############################################################################
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
##############################################################################
echo "##############################################################################"
echo "Completed. Please review script output for manual process"
