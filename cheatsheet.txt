# Get all subnets from sites and services. Perfect for the nmap script.
nxc ldap <ip> -u <user> -p <pass> -M subnets | grep Subnet: | cut -d '(' -f 2 | cut -d ')' -f 1 | cut -d ':' -f 2

# get bloodhound data (set domain and dc in hostfile first)
nxc ldap <ip> -u <user> -p <pass> --bloodhound -ns <ns-ip> --collection All

# Export in hashcat format (sort of)
nxcdb creds export hashcat "filename"

# Prepare NTLM for hashcat
sed 's/:[^:]*:/:/g' filename > newfilename

# hashcat for NTLM (DCSync)
sudo hashcat --username -a 0 -m 1000 hashes /usr/share/wordlists/rockyou.txt -r ~/tools/OneRuleToRuleThemStill/OneRuleToRuleThemStill.rule -O -w 4 --force
sudo hashcat --username -a 0 -m 1000 hashes --show
sudo hashcat --username -a 0 -m 1000 hashes --show | sed "s/^/DOMAIN.TLD\\\\/" > crackhound_input.txt

# Add shit to Bloodhound
crackhound.py -f crackhound_input.txt -u neo4j -p toor -plaintext -addpw
