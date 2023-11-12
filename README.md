# What?

This script helps me during the early stages of a pentest.

# How?

At the moment it does the following:

1. Do a fast nmap scan over all provided ("in-scope") subnets.
2. Get all hosts that are up and do a full scan (only top 2000 ports).
3. Use the nmap XML output to feed "eyewitness" to screenshot most HTTP Services to get a lay of the land.

# That's all?

For now it is. I will add more features over time.

# Like what?

I will put the most common tasks I do into this script if I can. Like bulk nxc checks:

- PetitPotam
- ZeroLogon
- Password Policy
- GPP-Passwords
- User Desc
- etc.
