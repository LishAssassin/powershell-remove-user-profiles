What is this?
=============

This is a small script I use when I need to remove large numbers of profiles remotely, and on
demand, from Windows computers.

Requirements
============

* Powershell v2.0
* This script uses the Win32_UserProfile WMI class, so it can only be used on computers
running Windows Vista or later.  

Get help
========

In order to see detailed explanations of the command line parameters for this script, you
can run:

    Get-Help .\Remove-UserProfiles.ps1 -detailed

Usage examples
==============

    .\Remove-UserProfiles.ps1 -whatIf

    .\Remove-UserProfiles.ps1 -computerNames COMPUTER1 -confirm:$false

    .\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1

    .\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1 -excludedUsers domain\user1,domain\user2

    .\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1 -excludedUsersInputFile c:\userlist.txt

    .\Remove-UserProfiles.ps1 -computerNames COMPUTER1,COMPUTER1,COMPUTER1 -logFile c:\logfile.txt
