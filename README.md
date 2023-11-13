# Whats this?

These scripts helps me during the early stages of a pentest.

1. domain_info.sh
2. initial_scan.sh

# How?

The scripts should be run one after another. Depending on the situation.

## domain_info.sh

```
./domain_info.sh -u <user> -p <password> -h <dc-ip>
```

I assume the following setup:

1. We have: AD-User credentials
2. We have: dc-ip
3. nxc    : is installed
4. hosts file: contains DC and Domain of target domain 

The script does:

- Get Subnets (File will be used by **initial_scan.sh**)
- Grab Password-Policy
- Create Bloodhound.zip
- Grab User-Descriptions
- Find common vulns: PetitPotam, ZeroLogon, NoPac
- List all shares the user has access to
- Get gpp_autologin (soon)
- Get gpp_password (soon)

## initial_scan.sh

```
./initial_scan.sh <subnet-file>
```

I assume the following setup:

1. nmap is installed
2. eyewitness is installed

At the moment it does the following:

- Do a fast nmap scan over all provided ("in-scope") subnets.
- Get all hosts that are up and do a full scan (only top 2000 ports).
- Use the nmap XML output to feed "eyewitness" to screenshot most HTTP Services to get a lay of the land.

# That's all?

For now that's it. Any wishes?

# ToDo

- Right now all files are just dumped into the same folder. I need to add some organization.
- `gpp_autologin` and `gpp_password` are not yet implemented.
- Probably killing some bugs...
