<#
Script: Windows Audit Script
Author: Ryan Nolette
Date: 09/18/2016
Version: 1.0
Description:
  This script will be run on systems to collect system information for auditing
  purposes.
#>
####################################################
#set powershell execution mode to allow for scripts to run
#set-executionpolicy remotesigned
####################################################
$hostname=$env:computername
$date =Get-Date -format MMddyyyy_HHmmss
$scriptPath=split-path -parent $MyInvocation.MyCommand.Definition
#$UserDesktop=[Environment]::GetFolderPath("Desktop")
#$outputFile="$UserDesktop\$hostname-$date.txt"
$outputFile="$scriptPath\$hostname-$date.txt"
####################################################
#start transcript
#$ErrorActionPreference = "Continue"
#Start-Transcript -path $USerDesktop\transcript.txt -append
####################################################
#create file and write out hostname and date to file
"hostname,$hostname" 2>&1 | out-file -Filepath $outputFile
"Date,$date" 2>&1 | out-file -Filepath $outputFile -append
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#query all users and what groups they are in
echo "Users and what groups they are in" 2>&1 | out-file -Filepath $outputFile -append
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
	$groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
	$_ | Select-Object @{n='UserName';e={$_.Name}},@{n='Groups';e={$groups -join ';'}} 2>&1 | out-file -Filepath $outputFile -append
}
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#is service running
$processName="service"
$ProcessActive = Get-Process $processName -ErrorAction SilentlyContinue
if($ProcessActive -eq $null)
{
	"$processName not running" 2>&1 | out-file -Filepath $outputFile -append
}
else
{
	"$processName is running" 2>&1 | out-file -Filepath $outputFile -append
}
#is EMET running
$processName="EMET_Service"
$ProcessActive = Get-Process $processName -ErrorAction SilentlyContinue
if($ProcessActive -eq $null)
{
	"$processName not running" 2>&1 | out-file -Filepath $outputFile -append
}
else
{
	"$processName is running" 2>&1 | out-file -Filepath $outputFile -append
}
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#is system on domain
if ((gwmi win32_computersystem).partofdomain -eq $true) {
    "I am domain joined!" 2>&1 | out-file -Filepath $outputFile -append
} else {
    "I am not on the domain" 2>&1 | out-file -Filepath $outputFile -append
}
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#list files in Directories
echo "list files in directories" 2>&1 | out-file -Filepath $outputFile -append
#root C
Get-ChildItem -Path c:\ 2>&1 | out-file -Filepath $outputFile -append
#appdata
$users=Get-ChildItem -Path c:\Users\
Foreach ($user IN $users)
{
	#C:\Users\master\AppData\Local
	Get-ChildItem -Path "c:\Users\$user\AppData -ErrorAction SilentlyContinue" 2>&1 | out-file -Filepath $outputFile -append
	Get-ChildItem -Path "c:\Users\$user\AppData\Roaming -ErrorAction SilentlyContinue"  2>&1 | out-file -Filepath $outputFile -append
	Get-ChildItem -Path "c:\Users\$user\AppData\local -ErrorAction SilentlyContinue" 2>&1 | out-file -Filepath $outputFile -append
	Get-ChildItem -Path "c:\Users\$user\AppData\locallow -ErrorAction SilentlyContinue" 2>&1 | out-file -Filepath $outputFile -append
  Get-ChildItem -Path "c:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup -ErrorAction SilentlyContinue" 2>&1 | out-file -Filepath $outputFile -append
}
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#This command uses the CodeSigningCert and Recurse parameters of the Get-ChildItem
#cmdlet to get all of the certificates on the computer that have code-signing authority.
#Because the full path is specified, this command can be run in any Windows PowerShell drive.
echo "look for code signing cert type" 2>&1 | out-file -Filepath $outputFile -append
#Get-ChildItem -path cert:\ -Recurse -ErrorAction SilentlyContinue 2>&1 | out-file -Filepath $outputFile -append
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#search for loose certs by extension
echo "search for loose certs by extension" 2>&1 | out-file -Filepath $outputFile -append
$extensions = '*.pfx', '*.p12', '*.cer', '*.csr', '*.crl', '*.crt', '*.der', '*.p7b', '*.p7r', '*.spc', '*.sst', '*.stl', '*.pem', '*.key'
Get-Childitem "c:\Users" -Include $extensions -Recurse -Force -ErrorAction SilentlyContinue 2>&1 | out-file -Filepath $outputFile -append
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#search for emails
echo "search for emails" 2>&1 | out-file -Filepath $outputFile -append
$ErrorActionPreference = "SilentlyContinue"
Get-ChildItem “c:\Users" -recurse | Select-String -pattern '(@company.com)|(@company2.com)' -ErrorAction SilentlyContinue | group path | select name 2>&1 | out-file -Filepath $outputFile -append
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#search for cleartext passwords
echo "search for cleartext passwords" 2>&1 | out-file -Filepath $outputFile -append
$ErrorActionPreference = "SilentlyContinue"
Get-ChildItem “c:\Users" -recurse -ErrorAction SilentlyContinue | Select-String -pattern '(pass=)|(pwd=)|(login=)|(pw=)|(passw=)|(passwd=)|(password=)|(pass:)|(password:)|(login:)' | group path | select name 2>&1 | out-file -Filepath $outputFile -append
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
echo "search for over priveleged files in user directories" 2>&1 | out-file -Filepath $outputFile -append

$ErrorActionPreference = "SilentlyContinue"
$rootFolder = 'C:\Users\'

$directory = Get-ChildItem $rootFolder -Recurse
foreach($item in $directory) {
    if ((get-acl $item.fullname).access.identityreference -match 'Everyone') {
       echo $item.fullname 2>&1 | out-file -Filepath $outputFile -append
    }
}

$rootFolder = 'C:\'
echo "search for over priveleged files in root c directory" 2>&1 | out-file -Filepath $outputFile -append

$directory = Get-ChildItem $rootFolder
foreach($item in $directory) {
    if ((get-acl $item.fullname).access.identityreference -match 'Everyone') {
        echo $item.fullname 2>&1 | out-file -Filepath $outputFile -append
    }
}
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#get system GPO settings
echo "get system GPO settings" 2>&1 | out-file -Filepath $outputFile -append
gpresult /Scope User /v 2>&1 | out-file -Filepath $outputFile -append
gpresult /Scope Computer /v 2>&1 | out-file -Filepath $outputFile -append
"####################################################" 2>&1 | out-file -Filepath $outputFile -append
#set powershell execution mode back to default
#Set-ExecutionPolicy restricted 2>&1 | out-file -Filepath $outputFile -append
####################################################
#stop transcript
#Stop-Transcript | out-null
####################################################
