#!/bin/bash
if id -u localuserName  >/dev/null 2>&1; then
	echo "user exists"
else
	echo "user does not exist"
fi
