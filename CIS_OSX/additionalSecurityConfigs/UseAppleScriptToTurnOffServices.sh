#!/bin/bash
# install a DMG from CLI
# Author Ryan Nolette
# Date Modified 06/26/2016
######################################################################
#Secure screen saver corners
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

#2.4.2 Disable Internet Sharing
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