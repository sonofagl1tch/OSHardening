#!/bin/bash
# Configuring IPtables script Centos 6
# Author Ryan Nolette
# Date Modified 06/26/2016
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
######################################################################
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