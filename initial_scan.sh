#!/bin/bash

# Check if the input file is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 subnet_file.txt"
    exit 1
fi

subnet_file="$1"

# Check if the file exists
if [ ! -f "$subnet_file" ]; then
    echo "Error: Subnet file '$subnet_file' not found."
    exit 1
fi

# Variables:
#
# Create a timestamp for unique output files
timestamp=$(date +%Y%m%d%H%M%S)

# Name of outputfile containing all up hosts
targets="targets.txt"

echo "[+] Performing the 1st nmap scan on each subnet..."
echo ""
while IFS= read -r subnet; do
    output_file="scan_${subnet//\//_}_${timestamp}"
    sudo nmap -sn -T4 --min-parallelism 100 $subnet -oA $output_file
    grep "Up" $output_file.gnmap | awk -F" " '{print $2}' >> $targets
done < "$subnet_file"
echo ""

echo "[+] Perform the 2nd nmap scan on all targets found to be up..."
echo ""
sudo nmap -sC -sV -O --top-ports 2000 --script-timeout 5m --min-hostgroup 64 -iL $targets -oA full_scan_${timestamp}
echo ""

echo "[+] nmap scans completed..."
echo ""

echo "[+] Starting Eyewitness on scanned hosts..."
eyewitness -x full_scan_${timestamp}.xml --no-prompt
echo ""
