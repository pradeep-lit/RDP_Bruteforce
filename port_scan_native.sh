nmap -p 3389 --open -Pn 62.164.177.0/24 -oG rdp_scan.txt
grep "/open/" rdp_scan.txt | awk '{print $2}' > open_rdp_hosts.txt
