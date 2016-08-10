#!/bin/bash
#
#get the last modification time of a local user in OSX
#v1.1.0 - 08-10-2016
#author rnolette
#date 06/06/2016
#version 1.0
#description: This script will query and OSX el capitan system for the last
#             password modification timestamp in mac epoch format
#####################################################################
#query local user data via Directory Service command line utility
#grep result for "passwordLastSetTime" string plus the next Line
#remove the "passwordLastSetTime" result line from the results
#remove the "<real>" and ""</real>" strings from the result
#remaining string is the mac epoch timestamp
#The difference between the Unix timestamp epoch (1970) and the Mac timestamp
#epoch (1904) is 2082844800 seconds.
dscl . read /Users/batman | grep -A1 'passwordLastSetTime' | grep -v 'passwordLastSetTime' | sed -e 's/\<real\>\(.*\)\<\/real\>/\1/'
