# Whats this?

This should become a collection of small scripts and notes to help me during the early stages of a pentest.

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

# Notes

I removed the other script, because there's already a tool that does what I tried to do, but better.

- [linWinPwn](https://github.com/lefayjey/linWinPwn)
