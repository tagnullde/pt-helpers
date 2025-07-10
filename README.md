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
- basic: tested
- adv: untested as of yet

## Portscanner
- Easy interface for scanning a network when nmap isn't available or to noisy
- Can resolve DNS Names
- Can Scan subnets
- Can Scan multiple ports at once

## LNK Creator

This script will create a folder on the current users Desktop called "LNKs".
Within the folder three files will be created:

1. !SMB-Auth.lnk 
2. !HTTP-Auth.lnk 
3. !WebDAV.searchConnector-ms

These files will enable at least the following attacks:

1. NTLM Relay via SMB
2. NTLM Relay via HTTP
3. Capture Hashes for offline cracking
4. Enables "WebDAV" on clients which have the WebDAV service installed but not already running
