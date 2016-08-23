#!/bin/bash
#
#Create batman
#v1.1.0 - 08-08-2015
#author rnoloette
#date 08/08/2016
#version 1.0
#description:
#     This script will check if the local hidden user batman exists the if the
#     script find that batman does not exist or is unable to authenticate as
#     batman, it will create a local batman account.
#additional information:
#
#
#####################################################################
# This function creates a new hidden user called batman
function createbatman () {
  # prompt user for batman password to use
  #echo "Please enter the password for the batman user: "
  #read batmanpassword
  # Create the batman user manually
  dscl . -create /Users/batman #create new user object
  dscl . -create /Users/batman UserShell /bin/bash #set shell
  dscl . -create /Users/batman RealName "Bruce Wayne" #set real name of user
  dscl . -create /Users/batman UniqueID "499" #any user below 500 is a hidden user in osx
  dscl . -create /Users/batman PrimaryGroupID 20 #group 20 is (staff)
  dscl . -create /Users/batman NFSHomeDirectory /private/var/batman #create user directory outside of the normal location
  dscl . -create /Users/batman IsHidden 1 #hide user from login page and preferences
  #dscl . -passwd /Users/batman $batmanpassword
  dscl . -passwd /Users/batman B@tmanPa55wordz123! #set password
  dscl . -append /Groups/admin GroupMembership batman #create user group
}
# This function checks for the existance of the user batman
# If batman is not found it will be created
# If batman is found the script will exit
function checkForbatman () {
  #if user batman has UniqueID of 499 which is a hidden user
  #> is for redirect
  # /dev/null is a black hole where any data sent, will be discarded
  # 2 is the file descriptor for Standard Error
  # > is for redirect
  # & is the symbol for file descriptor (without it, the following 1 would be considered a filename)
  # 1 is the file descriptor for Standard Out
  # Therefore >/dev/null 2>&1 is redirect the output of your program to /dev/null. Include both the Standard Error and Standard Out.
  if id -u batman = 499 >/dev/null 2>&1; then #write command output to
    #echo "user exists as desired"
    # Will exit with status of last command.
    exit
  else
    #echo "user does not exist"
    #start fresh by deleting existing batman user if it exists
    cleanup
    # create batman user
    createbatman
  fi
}
# This function deleting an existing batman user
function cleanup () {
  #remove existing previous batman user and directory if it exists
  if [ -d "/Users/batman" >/dev/null 2>&1 ]; then #redirect the output of your program to /dev/null
    dscl . -delete /Users/batman #delete user and setting using native osx tool
    rm -rf /Users/batman #delete old batman user directory
  fi
}
#############################################
#check to see if script is being run as root
if [ "$EUID" -ne 0 ] #if userID does not equal 0 (aka root)
  then echo "Please run as root"
  exit
fi
# Does the batman user exist?
checkForbatman
