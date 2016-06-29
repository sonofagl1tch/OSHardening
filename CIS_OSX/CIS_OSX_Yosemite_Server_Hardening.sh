#!/bin/bash
# install a DMG from CLI
# Author Ryan Nolette
# Date Modified 06/26/2016
######################################################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
# this is required for enablement of filevault
# echo "Please enter the password for the localadmin user: "
# read localadminpassword
######################################################################
#1 Install Updates, Patches and Additional Security Software#################################################

echo "1 Install Updates, Patches and Additional Security Software"
echo "1.1 Verify all application software is current"
softwareupdate --install --all

echo "1.2 Enable Auto Update"
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -int 1

echo "1.3 Enable app update installs - requires a reboot to take effect"
defaults write /Library/Preferences/com.apple.storeagent AutoUpdate -int 1

echo "1.4 Enable system data files and security update installs"
defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true && defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
#####################################################################
#2 System Preferences#################################################
#no bluetooth on servers
# 
# echo "2 System Preferences"
# echo "2.1 Bluetooth"
# echo "2.1.1 Disable Bluetooth, if no paired devices exist"
# defaults write /Library/Preferences/com.apple.Bluetooth \ ControllerPowerState -int 0 
# killall -HUP blued
# echo "2.1.2 Disable Bluetooth \"Discoverable\" mode when not pairing devices"
# /usr/sbin/system_profiler SPBluetoothDataType | grep -i discoverable
# echo "If query returns \"Discoverable: On\" you need to turn discoverable off."
# echo "Starting with OS X (10.9) Bluetooth is only set to Discoverable when the Bluetooth System Preference is selected. To ensure that the computer is not Discoverable do not leave that preference open."
# echo "2.1.3 Show Bluetooth status in menu bar"	
# defaults write com.apple.systemuiserver menuExtras -array-add "/System/Library/CoreServices/Menu Extras/Bluetooth.menu"###############################
###############################
# echo "2.2 Date & Time"
systemsetup -f -setnetworktimeserver ntpServer.domain.local

#echo "2.2.2 Ensure time set is within appropriate limits"
#already completed in step 2.2
#systemsetup -f -getnetworktimeserver
###############################
echo "2.3 Desktop & Screen Saver"
echo "2.3.1 Set an inactivity interval of 20 minutes or less for the screen saver"
#set to 10 minutes
defaults -currentHost write com.apple.screensaver idleTime -int 600

#echo "2.3.2 Secure screen saver corners"
# Perform the following to implement the prescribed state:
# 	1. Open System Preferences
# 	2. Select Mission Control
# 	3. Select Hot Corners
# 	4. Remove any corners which are set to Disable Screen Saver
#below is an applescript equivalent of these steps
touch disableSharing.scpt
/bin/cat << EOM > disableSharing.scpt
property theSavedValues : {"Mission Control", "Desktop", "Dashboard", "Launchpad"} -- for example
tell application "System Preferences"
    activate
    set current pane to pane id "com.apple.preference.expose"
    tell application "System Events"
        tell window "Mission Control" of process "System Preferences"
            click button "Hot Corners…"
            tell sheet 1
                tell group 1
                    set theCurrentValues to value of pop up buttons
                    if theCurrentValues is {"-", "-", "-", "-"} then
                        --do nothing
                    else
                        copy theCurrentValues to theSavedValues
                        repeat with i from 1 to 4
                            tell pop up button i
                                click
                                click last menu item of menu 1
                            end tell
                        end repeat
                    end if
                end tell
                click button "OK"
            end tell
        end tell
    end tell
    quit
end tell
EOM
#Enable Access for Assistive Devices Command Line
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access VALUES('kTCCServiceAccessibility','com.apple.Terminal',0,1,1,NULL);"
#run applescript
osascript disableSharing.scpt
#Disable Access for Assistive Devices Command Line
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "delete from access where client='com.apple.Terminal';"
#remove script after usage
rm -r disableSharing.scpt

#echo "2.3.3 Verify Display Sleep is set to a value larger than the Screen Saver"
# In System Preferences: Energy Saver, drag the slider for "Put the display(s) to sleep..." to a reasonable number, but longer than the screen saver setting. The Mac will display a warning if the number is too short.
# Alternatively, use the following command: pmset -c displaysleep 0
# Note: The -c flag means "wall power." Different settings must be used for other power sources.
#pmset -c displaysleep 0

#echo "2.3.4 Set a screen corner to Start Screen Saver"	
# In System Preferences: Desktop & Screen Saver: Screen Saver: Hot Corners, make sure at least one Active Screen Corner is set to Start Screen Saver. Make sure the user knows about this feature.
# The screen corners can be set using the defaults command, but the permutations of combinations are many. The plist file to check is ~/Library/Preferences/com.apple.dock and the keys are wvous-bl-corner wvous-br-corner wvous-tl-corner wvous-tr-corner
# There are also modifier keys to check and various values for each of these keys. A value of 5 means the corner will start the screen saver. The corresponding wvous-xx-modifier key should be set to 0.

###############################
echo "2.4 Sharing"
echo "2.4.1 Disable Remote Apple Events"
systemsetup -f setremoteappleevents off

echo "2.4.2 Disable Internet Sharing"
echo "The file should not exist or Enabled = 0 for all network interfaces."
# Remediation:
# Perform the following to implement the prescribed state:
# 	1. Open System Preferences
# 	2. Select Sharing
# 	3. Uncheck Internet Sharing
#below is an applescript equivalent of these steps
touch disableSharing.scpt
/bin/cat << EOM > disableSharing.scpt
tell application "System Preferences" to set current pane to pane "com.apple.preferences.sharing"
tell application "System Events" to tell process "System Preferences"
    tell row 8 of table 1 of scroll area 1 of group 1 of window "Sharing"
        tell checkbox 1 to if value is 1 then click -- checkbox was not checked.
    end tell
end tell
ignoring application responses
    tell application "System Preferences" to quit
end ignoring
EOM
#Enable Access for Assistive Devices Command Line
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access VALUES('kTCCServiceAccessibility','com.apple.Terminal',0,1,1,NULL);"
#run applescript
osascript disableSharing.scpt
#Disable Access for Assistive Devices Command Line
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "delete from access where client='com.apple.Terminal';"
#remove script after usage
rm -r disableSharing.scpt


echo "2.4.3 Disable Screen Sharing"
echo "Verify the value returned is nothing found to load"
# Perform the following to implement the prescribed state:
# 	1. Open System Preferences
# 	2. Select Sharing
# 	3. Uncheck Screen Sharing
#below is an applescript equivalent of these steps
touch disableSharing.scpt
/bin/cat << EOM > disableSharing.scpt
tell application "System Preferences" to set current pane to pane "com.apple.preferences.sharing"
tell application "System Events" to tell process "System Preferences"
    tell row 2 of table 1 of scroll area 1 of group 1 of window "Sharing"
        tell checkbox 1 to if value is 1 then click -- checkbox was not checked.
    end tell
end tell
ignoring application responses
    tell application "System Preferences" to quit
end ignoring
EOM
#Enable Access for Assistive Devices Command Line
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access VALUES('kTCCServiceAccessibility','com.apple.Terminal',0,1,1,NULL);"
#run applescript
osascript disableSharing.scpt
#Disable Access for Assistive Devices Command Line
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "delete from access where client='com.apple.Terminal';"
#remove script after usage
rm -r disableSharing.scpt



echo "2.4.4 Disable Printer Sharing"
echo "The output should show \"Shared: No\" for all printers. If no printers are present, the above command will yield \"Status: The printers list is empty.\""
#Perform the following to implement the prescribed state:
#1. Open System Preferences
#2. Select Sharing
#3. Uncheck Printer Sharing
#below is an applescript equivalent of these steps
touch disableSharing.scpt
/bin/cat << EOM > disableSharing.scpt
tell application "System Preferences" to set current pane to pane "com.apple.preferences.sharing"
tell application "System Events" to tell process "System Preferences"
    tell row 4 of table 1 of scroll area 1 of group 1 of window "Sharing"
        tell checkbox 1 to if value is 1 then click -- checkbox was not checked.
    end tell
end tell
ignoring application responses
    tell application "System Preferences" to quit
end ignoring
EOM
#Enable Access for Assistive Devices Command Line
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access VALUES('kTCCServiceAccessibility','com.apple.Terminal',0,1,1,NULL);"
#run applescript
osascript disableSharing.scpt
#Disable Access for Assistive Devices Command Line
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "delete from access where client='com.apple.Terminal';"
#remove script after usage
rm -r disableSharing.scpt


#echo "2.4.5 Disable Remote Login"
#systemsetup -f -setremotelogin off

echo "2.4.6 Disable DVD or CD Sharing"	
echo "There should be no results"
# Perform the following to implement the prescribed state:
# 	1. Open System Preferences
# 	2. Select Sharing
# 	3. Uncheck DVD or CD Sharing
#below is an applescript equivalent of these steps
touch disableSharing.scpt
/bin/cat << EOM > disableSharing.scpt
tell application "System Preferences" to set current pane to pane "com.apple.preferences.sharing"
tell application "System Events" to tell process "System Preferences"
    tell row 1 of table 1 of scroll area 1 of group 1 of window "Sharing"
        tell checkbox 1 to if value is 1 then click -- checkbox was not checked.
    end tell
end tell
ignoring application responses
    tell application "System Preferences" to quit
end ignoring
EOM
#Enable Access for Assistive Devices Command Line
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access VALUES('kTCCServiceAccessibility','com.apple.Terminal',0,1,1,NULL);"
#run applescript
osascript disableSharing.scpt
#Disable Access for Assistive Devices Command Line
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "delete from access where client='com.apple.Terminal';"
#remove script after usage
rm -r disableSharing.scpt


echo "2.4.7 Disable Bluetooth Sharing"
echo "Verify that all values are Disabled"
system_profiler SPBluetoothDataType | grep State
# Perform the following to implement the prescribed state:
# 	1. Open System Preferences
# 	2. Select Sharing
# 	3. Uncheck Bluetooth Sharing
#below is an applescript equivalent of these steps
touch disableSharing.scpt
/bin/cat << EOM > disableSharing.scpt
tell application "System Preferences" to set current pane to pane "com.apple.preferences.sharing"
tell application "System Events" to tell process "System Preferences"
    tell row 9 of table 1 of scroll area 1 of group 1 of window "Sharing"
        tell checkbox 1 to if value is 1 then click -- checkbox was not checked.
    end tell
end tell
ignoring application responses
    tell application "System Preferences" to quit
end ignoring
EOM
#Enable Access for Assistive Devices Command Line
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access VALUES('kTCCServiceAccessibility','com.apple.Terminal',0,1,1,NULL);"
#run applescript
osascript disableSharing.scpt
#Disable Access for Assistive Devices Command Line
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "delete from access where client='com.apple.Terminal';"
#remove script after usage
rm -r disableSharing.scpt

echo "2.4.8 Disable File Sharing"
#Run the following command in Terminal to turn off AFP from the command line:
launchctl unload -w /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist
#Run the following command in Terminal to turn off SMB sharing from the CLI:
launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist

echo "2.4.9 Disable Remote Management"
# In System Preferences: Sharing, turn off Remote Management.
#below is an applescript equivalent of these steps
touch disableSharing.scpt
/bin/cat << EOM > disableSharing.scpt
tell application "System Preferences" to set current pane to pane "com.apple.preferences.sharing"
tell application "System Events" to tell process "System Preferences"
    tell row 6 of table 1 of scroll area 1 of group 1 of window "Sharing"
        tell checkbox 1 to if value is 1 then click -- checkbox was not checked.
    end tell
end tell
ignoring application responses
    tell application "System Preferences" to quit
end ignoring
EOM
#Enable Access for Assistive Devices Command Line
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "INSERT INTO access VALUES('kTCCServiceAccessibility','com.apple.Terminal',0,1,1,NULL);"
#run applescript
osascript disableSharing.scpt
#Disable Access for Assistive Devices Command Line
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "delete from access where client='com.apple.Terminal';"
#remove script after usage
rm -r disableSharing.scpt
###############################
# echo "2.5 Energy Saver"
# echo "2.5.1 Disable \"Wake for network access\""
# pmset -a womp 0

echo "2.5.2 Disable sleeping the computer when connected to power"	
pmset -c sleep 0
###############################
echo "2.6 Security & Privacy"
# echo "2.6.1 Enable FileVault"
# echo "On a booted system the Logical Volume should show as both Encrypted and unlocked"
# echo "Encryption Status: Unlocked"
# echo "Encryption Type: AES-XTS"
# diskutil cs list | grep -i encryption
# # Perform the following to implement the prescribed state:
# # 	1. Open System Preferences
# # 	2. Select Security & Privacy
# # 	3. Select FileVault
# # 	4. Select Turn on FileVault
# #scripted out for the above steps
# touch fdesetup.plist
# /bin/cat << EOM > fdesetup.plist
# <?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
# <dict>
# <key>Username</key>
# <string>localadmin</string>
# <key>Password</key>
# <string>$localadminpassword</string>
# </dict>
# </plist>
# EOM
# fdesetup enable -inputplist < fdesetup.plist &> fdekey.txt
# rm -f fdesetup.plist
# #disabled filevault
# #fdesetup disable

echo "2.6.2 Enable Gatekeeper"
spctl --master-enable

echo "2.6.3 Enable Firewall"
#Where <value> is:
	# 1 = on for specific services
	# 2 = on for essential services
defaults write /Library/Preferences/com.apple.alf globalstate -int 1

#echo "2.6.4 Enable Firewall Stealth Mode"
#/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# echo "2.6.5 Review Application Firewall Rules"
# echo "List all firewall exceptions"
# /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
# Edit and run the following command in Terminal to remove specific applications: /usr/libexec/ApplicationFirewall/socketfilterfw --remove </Applications/badapp.app>
# Where </Applications/badapp.app> is the one to be removed	
###############################
# echo "2.7 iCloud"
# echo "2.7.1 iCloud configuration"
# echo "2.7.2 iCloud keychain"
# echo "2.7.3 iCloud Drive"
# defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
###############################
echo "2.8 Pair the remote control infrared receiver if enabled"
#are there IR recievers
#system_profiler 2>/dev/null | egrep "IR Receiver"
# echo "Verify the value returned for DeviceEnabled = 0; If the value returned is DeviceEnabled = 1, then verify the value returned for the UIDFilter does not equal none"
# defaults read /Library/Preferences/com.apple.driver.AppleIRController
#Disable the remote control infrared receiver:
	# 1. Open System Preferences
	# 2. Select Security & Privacy
	# 3. Select the General tab
	# 4. Select Advanced
	# 5. Check Disable remote control infrared receiver
defaults write /Library/Preferences/com.apple.driver.AppleIRController.plist DeviceEnabled -bool NO
###############################
echo "2.9 Enable Secure Keyboard Entry in terminal.app"
echo "verify the value returned is 1"
/usr/bin/defaults write -app Terminal SecureKeyboardEntry 1
#1. Open Terminal
# 2. Select Terminal
# 3. Select Secure Keyboard Entry
###############################
# echo "2.10 Java 6 is not the default Java runtime"
# echo "The output of the above command should not return a result with Java 6:"
# #echo "Java version 1.6.0_x"
# #echo "Java(TM) SE Runtime Environment (build 1.6.0_x)"
# java -version
###############################
echo "2.11 Configure Secure Empty Trash"
echo "Make sure the value returned for each user is 1"
#1. Select Finder
# 2. Select Preferences
# 3. Select Advanced
# 4. Check Empty Trash Securely
#3 Logging and Auditing
defaults write com.apple.finder EmptyTrashSecurely -bool true
#################################################

echo "3 Logging and Auditing"
echo "3.1 Configure asl.conf"
echo "3.1.1 Retain system.log for 90 or more days"
/usr/bin/sed -i.bak 's/^>\ system\.log.*/>\ system\.log\ mode=640\ format=bsd\ rotate=seq\ ttl=90/' /etc/asl.conf

echo "3.1.2 Retain appfirewall.log for 90 or more days"
/usr/bin/sed -i.bak 's/^\?\ \[=\ Facility\ com.apple.alf.logging\]\ .*/\?\ \[=\ Facility\ com.apple.alf.logging\]\ file\ appfirewall.log\ rotate=seq\ ttl=90/' /etc/asl.conf

echo "3.1.3 Retain authd.log for 90 or more days "
/usr/bin/sed -i.bak 's/^\*\ file\ \/var\/log\/authd\.log.*/\*\ file\ \/var\/log\/authd\.log\ mode=640\ format=bsd\ rotate=seq\ ttl=90/' /etc/asl/com.apple.authd
###############################
echo "3.2 Enable security auditing"
if [[ "$(/bin/launchctl list | grep -i auditd | awk '{ print $3 }')" = "com.apple.auditd" ]]; then
    ScriptLogging "  Security Auditing enabled."
else
    /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
fi
###############################
echo "3.3 Configure Security Auditing Flags"
# echo "Ensure at least the following flags are present:"
# echo "lo - audit successful/failed login/logout events"
# echo "ad - audit successful/failed administrative events"
# echo "fd - audit successful/failed file deletion events"
# echo "fm - audit successful/failed file attribute modification events"
# echo "-all - audit all failed events across all audit classes"
#Perform the following to implement the prescribed state:
# 1. Open a terminal session and edit the /etc/security/audit_control file
# 2. Find the line beginning with "flags"
# 3. Add the following flags: lo, ad, fd, fm, -all.
# 4. Save the file.
/usr/bin/sed -i '' 's/^flags:.*/flags:lo,ad,fd,fm,-all/' /etc/security/audit_control
/usr/bin/sed -i '' 's/^expire-after:.*/expire-after:90d\ AND\ 1G/' /etc/security/audit_control

###############################
#echo "3.4 Enable remote logging for Desktops on trusted networks"
###############################
echo "3.5 Retain install.log for 365 or more days"
/usr/bin/sed -i.bak 's/^\*\ file\ \/var\/log\/install\.log.*/\*\ file\ \/var\/log\/install\.log\ mode=640\ format=bsd\ rotate=seq\ ttl=365/' /etc/asl/com.apple.install
##############################################################
#4 Network Configurations

echo "4 Network Configurations"
#echo "4.1 Enable \"Show Wi-Fi status in menu bar\""
# echo "Verify the value returned is: /System/Library/CoreServices/Menu Extras/AirPort.menu"
# defaults read com.apple.systemuiserver menuExtras | grep AirPort.menu
#Perform the following to implement the prescribed state:
# 1. Open System Preferences
# 2. Select Network
# 3. Check Show Wi-Fi status in menu bar
###############################
#echo "4.2 Create network specific locations"
###############################
echo "4.3 Ensure http server is not running"
#stop web server
apachectl stop
#stop web server from auto start at boot
defaults write /System/Library/LaunchDaemons/org.apache.httpd Disabled -bool true
###############################
echo "4.4 Ensure ftp server is not running"
-s launchctl unload -w /System/Library/LaunchDaemons/ftp.plist
###############################
echo "4.5 Ensure nfs server is not running"
nfsd disable
rm /etc/export
##############################################################
#5 System Access, Authentication and Authorization	
echo "5 System Access, Authentication and Authorization"
echo "5.1 File System Permissions and Access Controls"
echo "5.1.1 Secure Home Folders"
#Perform the following to implement the prescribed state:
# 1. Run one of the following commands in Terminal:
# chmod -R og-rwx /Users/<username>
# 2. chmod -R og-rw /Users/<username>
# 3. Substitute user name in <username>.
# 4. This command has to be run for each user account with a local home folder.
for users in `ls /Users/`; do
  #echo $users
  sudo chmod -R og-rwx /Users/$users
done
###############################
#echo "5.1.2 Repair permissions regularly to ensure binaries and other System files have appropriate permissions "
#diskutil repairPermissions /
###############################
echo "5.1.3 Check System Wide Applications for appropriate permissions"
#Change permissions so that "Others" can only execute
#chmod -R o-w /Applications/Bad\ Permissions.app/
for files in `sudo find /Applications -iname "*\.app" -type d -perm -2 -ls`; do
    sudo chmod -R o-w $files
done
###############################
echo "5.1.4 Check System folder for world writable files"
#Change permissions so that "Others" can only execute
#chmod -R o-w /Bad/Directory
for files in `sudo find /System -type d -perm -2 -ls | grep -v "Public/Drop Box"`; do
    sudo chmod -R o-w $files
done
###############################
echo "5.1.5 Check Library folder for world writable files"
#Change permissions so that "Others" can only execute
#chmod -R o-w /Bad/Directory
for files in `sudo find /Library -type d -perm -2 -ls | grep -v Caches`; do
    sudo chmod -R o-w $files
done
###############################
echo "5.2 Reduce the timeout period - requires reboot"
/bin/cat << EOM > /etc/sudoers
## sudoers file.
##
## This file MUST be edited with the 'visudo' command as root.
## Failure to use 'visudo' may result in syntax or file permission errors
## that prevent sudo from running.
##
## See the sudoers man page for the details on how to write a sudoers file.
##

##
## Host alias specification
##
## Groups of machines. These may include host names (optionally with wildcards),
## IP addresses, network numbers or netgroups.
# Host_Alias    WEBSERVERS = www1, www2, www3

##
## User alias specification
##
## Groups of users.  These may consist of user names, uids, Unix groups,
## or netgroups.
# User_Alias    ADMINS = millert, dowdy, mikef

##
## Cmnd alias specification
##
## Groups of commands.  Often used to group related commands together.
# Cmnd_Alias    PROCESSES = /usr/bin/nice, /bin/kill, /usr/bin/renice, \
#               /usr/bin/pkill, /usr/bin/top

##
## Defaults specification
##

Defaults    env_reset
Defaults    env_keep += "BLOCKSIZE"
Defaults    env_keep += "COLORFGBG COLORTERM"
Defaults    env_keep += "__CF_USER_TEXT_ENCODING"
Defaults    env_keep += "CHARSET LANG LANGUAGE LC_ALL LC_COLLATE LC_CTYPE"
Defaults    env_keep += "LC_MESSAGES LC_MONETARY LC_NUMERIC LC_TIME"
Defaults    env_keep += "LINES COLUMNS"
Defaults    env_keep += "LSCOLORS"
Defaults    env_keep += "SSH_AUTH_SOCK"
Defaults    env_keep += "TZ"
Defaults    env_keep += "DISPLAY XAUTHORIZATION XAUTHORITY"
Defaults    env_keep += "EDITOR VISUAL"
Defaults    env_keep += "HOME MAIL"
Defaults timestamp_timeout=0

Defaults    lecture_file = "/etc/sudo_lecture"

##
## Runas alias specification
##

##
## User privilege specification
##
root ALL=(ALL) ALL
%admin  ALL=(ALL) ALL
%localadmin ALL=(ALL) ALL

## Uncomment to allow members of group wheel to execute any command
# %wheel ALL=(ALL) ALL

## Same thing without a password
# %wheel ALL=(ALL) NOPASSWD: ALL

## Uncomment to allow members of group sudo to execute any command
# %sudo ALL=(ALL) ALL

## Uncomment to allow any user to run sudo if they know the password
## of the user they are running the command as (root by default).
# Defaults targetpw  # Ask for the password of the target user
# ALL ALL=(ALL) ALL  # WARNING: only use this together with 'Defaults targetpw'

## Read drop-in files from /private/etc/sudoers.d
## (the '#' here does not indicate a comment)
#includedir /private/etc/sudoers.d
EOM
###############################
#echo "5.3 Automatically lock the login keychain for inactivity"
#echo "Verify that a value is returned below 6 hours: Keychain \"<NULL>\" timeout=21600s"
#security show-keychain-info
#Perform the following to implement the prescribed state:
# 1. Open Utilities
# 2. Select Keychain Access
# 3. Select a keychain
# 4. Select Edit
# 5. Select Change Settings for keychain <keychain_name>
# 6. Authenticate, if requested.
# 7. Change the Lock after # minutes of inactivity setting for the Login Keychain to an
# approved value that should be longer than 6 hours or 3600 minutes or based on the access frequency of the security credentials included in the keychain for other keychains.
###############################
#echo "5.4 Ensure login keychain is locked when the computer sleeps"
#echo "Verify that the value returned contains: Keychain \"<NULL>\" lock-on-sleep"
#security show-keychain-info
# Perform the following to implement the prescribed state:
# 1. Open Utilities
# 2. Select Keychain Access
# 3. Select a keychain
# 4. Select Edit
# 5. Select Change Settings for keychain <keychain_name>
# 6. Authenticate, if requested.
# 7. Select Lock when sleeping setting
###############################
echo "5.5 Enable OCSP and CRL certificate checking"
defaults write com.apple.security.revocation CRLStyle -string RequireIfPresent
defaults write com.apple.security.revocation OCSPStyle -string RequireIfPresent
###############################
echo "5.6 Do not enable the \"root\" account"
#Open System Preferences, Uses & Groups. Click the lock icon to unlock it. In the Network Account Server section, click Join or Edit. Click Open Directory Utility. Click the lock icon to unlock it. Select the Edit menu > Disable Root User.
#correctly configured by default on installs. no hardening step required. 
###############################
echo "5.7 Disable automatic login"
sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser
###############################
echo "5.8 Require a password to wake the computer from sleep or screen saver - requires reboot"
defaults write com.apple.screensaver askForPassword -int 1
###############################
echo "5.9 Require an administrator password to access system-wide preferences"
#security authorizationdb write system.preferences allow
#security authorizationdb read system.preferences > /tmp/system.preferences.plist
#defaults write /tmp/system.preferences.plist shared -bool false
#security authorizationdb write system.preferences < /tmp/system.preferences.plist
#echo Set Preferences...
security authorizationdb read system.preferences > /tmp/system.preferences.plist
sleep 1
defaults write /tmp/system.preferences.plist shared -bool false
sleep 1
sudo security authorizationdb write system.preferences < /tmp/system.preferences.plist
sleep 1
#echo Done.
###############################
echo "5.10 Disable ability to login to another user's active and locked session"
echo "No results will be returned if the system is configured as recommended."
#Perform the following to implement the prescribed state:
# 1. vi /etc/pam.d/screensaver
# 2. Locate account required pam_group.so no_warn group=admin,wheel fail_safe
# 3. Remove "admin,"
# 4. Save
sed -ie "s/group=admin,wheel/group=wheel/" /etc/pam.d/screensaver

###############################
echo "5.11 Complex passwords must contain an Alphabetic Character"
echo "5.12 Complex passwords must contain a Numeric Character"
echo "5.13 Complex passwords must contain a Symbolic Character"
echo "5.14 Set a minimum password length"
echo "5.15 Configure account lockout threshold"
pwpolicy -setglobalpolicy "maxFailedLoginAttempts=5 minChars=12 requiresNumeric=1 requiresAlpha=1 requiresSymbol=1"

#echo "5.16 Create a custom message for the Login Screen"
# since the systems will be on the domain, we are not doing this step
# Perform the following to implement the prescribed state:
# 1. To add text with elevated privileges:
# defaults write /Library/Preferences/com.apple.loginwindow \LoginwindowText "your text here"
# To remove the text with elevated privileges:
# defaults delete /Library/Preferences/com.apple.loginwindow \LoginwindowText
###############################

#echo "5.17 Create a Login window banner"
# since the systems will be on the domain, we are not doing this step
# Run the following command to see the login window text:
# cat /Library/Security/PolicyBanner.txt
# Remediation:
# Place a file named PolicyBanner.txt in/Library/Security/
###############################
#echo "5.18 Do not enter a password-related hint"
# since the systems will be on the domain, we are not doing this step
# 	Remediation:
# 1. Open System Preferences
# 2. Select Users & Groups
# 3. Highlight the user
# 4. Select Change Password
# 5. Verify that no text is entered in the Password hint box
###############################

echo "5.19 Disable Fast User Switching"	
# since the systems will be on the domain, we are not doing this step
#In System Preferences: Accounts, Login Options, make sure the "Enable fast user switching" checkbox is off.
defaults write /Library/Preferences/.GlobalPreferences MultipleSessionEnabled -bool 'NO'

###############################
#echo "5.20 Secure individual keychain items"
#small value add in security for large user inconvience.
# 	Remediation:
# 1. Open Utilities
# 2. Select Keychain Access
# 3. Double-click keychain
# 4. Select Access Control
# 5. Check box next to "Ask for Keychain Password"
###############################

#echo "5.21 Create specialized keychains for different purposes"
#small value add in security for large user inconvience.
# 	Remediation:
# 1. Open Utilities
# 2. Select Keychain Access
# 3. Select File
# 4. Select New Keychain
# 5. Input name of new keychain next to Save As
# 6. Select Create
# 7. Drag and drop desired keychain items into new keychain from login keychain
##############################################################
#6 User Accounts and Environment#################################################
echo "6 User Accounts and Environment"
echo "6.1 Accounts Preferences Action Items"
echo "6.1.1 Display login window as name and password"
defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool yes

echo "6.1.2 Disable \"Show password hints\""
defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0

echo "6.1.3 Disable guest account login"
defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool NO

echo "6.1.4 Disable \"Allow guests to connect to shared folders\""
#For AFP sharing:
defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool no
#For SMB sharing:
defaults write \ /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool no
###############################
echo "6.2 Turn on filename extensions"
defaults write NSGlobalDomain AppleShowAllExtensions -bool true
###############################
echo "6.3 Disable the automatic run of safe files in Safari"
defaults write com.apple.Safari AutoOpenSafeDownloads -boolean no
###############################
#echo "6.4 Use parental controls for systems that are not centrally managed"
#Remediation:
# 1. Open System Preferences
# 2. Select Users & Groups
# 3. Highlight managed user
# 4. Check box next to Enable parental controls
# 5. Select Open Parental Controls
# 6. Select items within the Parental Controls feature that should be restricted.
##############################################################
#7 Appendix: Additional Considerations#################################################

# echo "7 Appendix: Additional Considerations"
# echo "7.1 Wireless Adapters on Mobile Clients"
# echo "7.2 iSight Camera Privacy and Confidentiality Concerns"
# echo "7.3 Computer Name Considerations"
# echo "7.4 Software Inventory Considerations"
# echo "7.5 Firewall Consideration"
# echo "7.6 Automatic Actions for Optical Media"
# echo "7.7 App Store Automatically download apps purchased on other Macs Considerations"
# echo "7.8 Extensible Firmware Interface (EFI) password"
# echo "7.9 Apple ID password reset"
##############################################################
############Security applications
#Security 1.1 - join system to domain
#Security 1.3 - modify hosts.allow
touch /etc/hosts.allow
echo "ALL: 10.0.0.0/255.0.0.0" >/etc/hosts.allow
echo "ALL: 172.16.0.0/255.240.0.0" >>/etc/hosts.allow
echo "ALL: 192.168.0.0/255.255.0.0" >>/etc/hosts.allow
/bin/chmod 644 /etc/hosts.allow
#Security 1.4 - modify hosts.deny
touch /etc/hosts.deny
echo "ALL: ALL" >> /etc/hosts.deny
/bin/chmod 644 /etc/hosts.deny
#Security 1.5 - configure ssh
mv /etc/sshd_config /etc/sshd_config.bak
/bin/cat << EOM > /etc/sshd_config
SyslogFacility AUTHPRIV
AuthorizedKeysFile  .ssh/authorized_keys
UsePrivilegeSeparation sandbox      # Default for new installations.
AcceptEnv LANG LC_*
# override default of no subsystems
Subsystem   sftp    /usr/libexec/sftp-server
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
#PubkeyAuthentication yes
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
AllowGroups admin localadmin
#if you run a command through SSH directly without going interactive (EX: ssh root@system COMMAND), the command won’t be logged anywhere.
#this line will fix that
ForceCommand if [[ -z \$SSH_ORIGINAL_COMMAND ]]; then bash; else printf "\x23\`date +%s\`\n\$SSH_ORIGINAL_COMMAND\n" >> .bash_history; bash -c "\$SSH_ORIGINAL_COMMAND"; fi
EOM
##############################################################
#Security 3.1 - configure security logging
# echo "Configuring Security Logging"
# #backup /etc/audit/audit.rules
# cp /etc/audit/audit.rules /etc/audit/audit.rules.bk
# #reconfigure /etc/audit/audit.rules
# echo "--- Configuring auditd ---"
# echo " This configuration change will not work until after a reboot"
# #backup pam modules
# cp /private/etc/pam.d/login /private/etc/pam.d/login.bk
# cp /private/etc/pam.d/gdm /private/etc/pam.d/gdm
# #reconfigure pam
# #This will allow auditd to get the calling user's uid correctly when calling sudo or su.
# echo -e "session\trequired\tpam_loginuid.so" >> /private/etc/pam.d/login
# echo -e "session\trequired\tpam_loginuid.so" >> /private/etc/pam.d/gdm
# echo -e "session\trequired\tpam_loginuid.so" >> /private/etc/pam.d/sshd
# #backup bashrc
# for user in `ls /Users | grep -v .localized`; do
#     cp /Users/$user/.bashrc /Users/$user/.bashrc.bk
# done
# #reconfigure bashrc
# echo "--- Enabling Real time bash history for all current users ---"
# for user in `ls /Users | grep -v .localized`; do
#     echo 'export HISTCONTROL=ignoredups:erasedups  # no duplicate entries' >> /Users/$user/.bashrc
#     echo 'export HISTSIZE=100000                   # big big history' >> /Users/$user/.bashrc
#     echo 'export HISTFILESIZE=100000               # big big history' >> /Users/$user/.bashrc
#     echo 'export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp' >> /Users/$user/.bashrc
#     echo "shopt -s histappend                      # append to history, don't overwrite it" >> /Users/$user/.bashrc
#     echo '# After each command, append to the history file and reread it' >> /Users/$user/.bashrc
#     echo 'export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"' >> /Users/$user/.bashrc
# done
# #backup bashrc for root
# cp /private/etc/bashrc /private/etc/bashrc.bk
# #reconfigure /root/bashrc
# echo "--- Enabling Real time bash history for root ---"
# /bin/cat << EOM > /private/etc/bashrc
# # .bashrc
# # User specific aliases and functions
# alias rm='rm -i'
# alias cp='cp -i'
# alias mv='mv -i'
# # Source global definitions
# if [ -f /private/etc/bashrc ]; then
#         . /private/etc/bashrc
# fi
# export HISTCONTROL=ignoredups:erasedups  # no duplicate entries
# export HISTSIZE=100000                   # big big history
# export HISTFILESIZE=100000               # big big history
# export HISTTIMEFORMAT="%m/%d/%y %T "     # Add timestamp
# shopt -s histappend                      # append to history, don't overwrite it
# # After each command, append to the history file and reread it
# export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
# EOM
#complete
echo "-------------------complete---------------"