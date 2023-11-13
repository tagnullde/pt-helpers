#!/bin/bash

while getopts ":u:p:h:" opt; do
  case $opt in
    u)
      user="$OPTARG"
      ;;
    p)
      passwd="$OPTARG"
      ;;
    h)
      dc="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Display help if arguments are missing
if [ -z "$user" ] || [ -z "$passwd" ] || [ -z "$dc" ]; then
  echo "Usage: $0 -u <user> -p <password> -h <dc-ip>"
  exit 1
fi


# get all subnets from sites and services
echo "[!] Creating Subnets.txt"

nets=$(nxc ldap $dc -u $user -p $passwd -M subnets | grep Subnet: | cut -d '(' -f 2 | cut -d ')' -f 1 | cut -d ':' -f 2) 

for net in "${nets[@]}"; do
  echo "$net"
done > subnets.txt

echo -e "[+] Done: subnets.txt \n"


# get password policy
echo "[!] Grabbing Password Policy"
nxc smb $dc -u $user -p $passwd --pass-pol | grep -v -e "[*]" -e "[+]" -e "[-]" | cut -d " " -f 28- > password-policy.txt
echo -e "[+] Done: password-policy.txt \n"

# get bloodhound data (set domain and dc in hostfile first)
echo "[!] Gathering Bloodhound Data"
bh=$(nxc ldap $dc -u $user -p $passwd --bloodhound -ns $dc --collection All | grep "Compressing" | cut -d " " -f 30)
echo -e "[+] Done: $bh \n"

# get vulns
echo "[!] Searching for AD-Vulnerabilities"
nxc ldap $dc -u $user -p $passwd -M get-desc-users | grep "User: " | cut -d " " -f 20- > user-descriptions.txt

nxc smb $dc -u $user -p $passwd -M petitpotam | grep "VULNERABLE" > ad-vulns.txt
nxc smb $dc -u $user -p $passwd -M zerologon | grep "VULNERABLE" >> ad-vulns.txt
nxc smb $dc -u $user -p $passwd -M nopac | grep "VULNERABLE" >> ad-vulns.txt
echo "[+] Done: user-descriptions.txt"
echo -e "[+] Done: ad-vulns.txt \n"

# get ADCS
echo "[!] Searching for Certificate Authority"
nxc ldap $dc -u $user -p $passwd -M adcs | grep -v -e "[*]" -e "[+]" -e "[-]" | cut -d" " -f 53 > adcs.txt
echo -e "[+] Done: adcs.txt \n"

# get shares
echo "[!] Getting Shares."
for net in "${nets[@]}"; do
   nxc --no-progress smb $net -u $user -p $passwd --shares | grep -v -e "[*]" -e "[+]" -e "[-]" >> shares.txt
   echo -e "------------------ \n" >> shares.txt
done
echo -e "[+] Done: shares.txt \n"

# get gpp_autologin and gpp_password (Not done yet.)
#nxc smb $dc -u $user -p $passwd -M gpp_autologin | grep -v -e "[*]" -e "[+]" -e "[-]"
#nxc smb $dc -u $user -p $passwd -M gpp_password | grep -v -e "[*]" -e "[+]" -e "[-]"
