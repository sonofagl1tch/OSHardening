#!/bin/bash
#####################################################################
#get hostname
host=`hostname`
#get current date
dateTime=`date +"%m%d%y-%H%M"`
#get curent username and not root
realUser=`sudo sh -c 'echo $SUDO_USER'`
#####################################################################
#are security services setup to start on boot in different usermodes
/usr/bin/cat /etc/*-release | grep -i "release 6." &> /dev/null
if [ $? == 0 ]; then
  chkconfig --list | grep -iE "serviceName" >> $dateTime"_"$host"_applications.txt"
fi
/usr/bin/cat /etc/*-release | grep -i "release 7." &> /dev/null
if [ $? == 0 ]; then
  chkconfig --list | grep -iE "serviceName" >> $dateTime"_"$host"_applications.txt"
  systemctl status serviceName >> $dateTime"_"$host"_applications.txt"
  systemctl status serviceName >> $dateTime"_"$host"_applications.txt"
  systemctl status serviceName >> $dateTime"_"$host"_applications.txt"
  systemctl status serviceName >> $dateTime"_"$host"_applications.txt"
  systemctl status serviceName >> $dateTime"_"$host"_applications.txt"
fi
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
#are security services currently running
ps aux | grep -iE "serviceName" >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
#is linuxusers enabled for ssh access to resecure servers? it should not be
grep -i "userName" /etc/ssh/sshd_config >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
# view ssh config file
cat /etc/ssh/sshd_config >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
# is admin user a member of the wheel group?
grep -i wheel /etc/sudoers >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
# view sudoers file
cat /etc/sudoers >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
# show me everything in /opt to make sure users arent abusing it
ls -lah /opt >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
#when was the lasttime the local user passwords where changed
#loop through all local Users
#For lines with UID>=500 (field 3) grab username
usrInfo=$(awk -F'[/:]' '{if ($3 >= 500) print $1}' /etc/passwd)
IFS=$'\n' #Use newline as delimiter for for-loop
for usrLine in $usrInfo
do
  #Do processing on each line
  #get last password change timestamp, remove leading whitespace, remove comma
  lastchangetime=$(chage -l $usrLine | grep 'Last password change' | cut -f2- -d':' | sed -e 's/^[ \t]*//' | sed 's/,//g')
  echo $usrLine,$lastchangetime >> $dateTime"_"$host"_applications.txt"
done
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
#view bashrc for root user
cat ~/.bashrc >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
#search for certificates on the file system
#ignore splunk, docker, pki, docs, and python directories as they have a bunch of cert examples
nohup find / -iname \*.pfx -o -iname \*.p12 -o -iname \*.cer -o -iname \*.csr -o -iname \*.crl -o -iname \*.crt -o -iname \*.der -o -iname \*.p7b -o -iname \*.p7r -o -iname \*.spc -o -iname \*.sst -o -iname \*.stl -o -iname \*.pem -o -iname \*.key -o -iname \*.pub | grep -v -E '/opt/splunkforwarder|/var/lib/docker|/etc/pki|/usr/share/doc|/usr/lib/python2.6|/usr/share/pki' >> $dateTime"_"$host"_findCerts.txt" &
######################################################################
#search for bit9/carbonblack email addresses on the file system
nohup grep -rsiEI "\@company.com|\@company2.com" /home/ >> $dateTime"_"$host"_grepEmail.txt" &
disown -h
#####################################################################
#search for cleartext passwords in the home directory of all users
nohup grep -irsEI 'pass=|pwd=|login=|pw=|passw=|passwd=|password=|pass:|password:|login:' /home/ | grep -v '.bash_history'  >> $dateTime"_"$host"_grepPasswords.txt" &
disown -h
#####################################################################
#search for all world writable files on the file system
nohup df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> $dateTime"_"$host"_worldWritable.txt" &
disown -h
#####################################################################
#sleep 5 seconds to allow for jobs to kick off in the background
sleep 5
#take ownership of all output files from script
chown $realUser:$realUser *
#list running jobs from background
jobs -l >> $dateTime"_"$host"_applications.txt"
echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
#running this command from / has some fallout effects that need to be manually adjusted.
#setfacl -R -m g:userGroup:r /var/log/
#echo "###########################################################" >> $dateTime"_"$host"_applications.txt"
