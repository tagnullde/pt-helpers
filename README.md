# Whats this?

This is a collection of small scripts and notes to help me during the early stages of a pentest.

## Backup Script
- Steals Desktop and Documents Folder of a User
- Idea is to run this as a scheduled task in the permission context of the user
- Saved the Data to a SMB Share
- Could yield sensitive information like password-lists and at least a hash to crack.

## LAPS-Script
- If you have the permissions (or found a user with READLAPSPassword Permission) you can exfil LAPS passwords
- Designed to run without AD-PowerShell Module
- Writes Passwords to a SMB Share

## Portscanner
- Easy interface for scanning a network when nmap isn't available or to noisy
- Can resolve DNS Names
- Can Scan subnets
- Can Scan multiple ports at once
