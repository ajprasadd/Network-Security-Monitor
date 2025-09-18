This repository contains artifacts, evidence and configuration used for a Network Security Monitoring (NSM) lab built in VMware using Snort (IDS) and Splunk (Universal Forwarder / Indexer). The full step-by-step lab guide is included as a PDF in docs/ and was used to perform the setup and testing in this project. See the lab guide: 

Step by step guide to perform N…

Goals

Install and configure Snort on the victim VM.
Install and configure Splunk Universal Forwarder to forward Snort and system logs to Splunk.
Generate controlled attack traffic from attacker VM (nmap, ping, curl, nping, etc.).
Create Splunk searches, dashboards and alerts to detect the attack scenarios.
Collect screenshots and logs as evidence for submission.


Quick start — what a reviewer should do

Open docs/screenshots/ to view visual evidence (dashboards, Snort console, UF logs).
Read the step-by-step lab guide in docs/Step by step guide to perform NETWORK SECURITY MONITORING USING SPLUNK AND SNORT.pdf for full installation steps and screenshots. 
Step by step guide to perform N…
Review config/local.rules for the Snort detection rules used in the lab (these are sanitized examples).
Review attacks/attack_commands.md for the exact commands and timestamps used to generate logs.
Use the Splunk dashboard export in dashboards/ to import panels into a Splunk instance (optional).
Setup summary (high-level)
Detailed, stepwise installation and initialization is available in the included PDF lab guide. 
Step by step guide to perform N…
Victim (Ubuntu)
Install Snort:
sudo apt update && sudo apt install snort
Configure $HOME_NET and ensure include $RULE_PATH/local.rules in snort.conf.
Add detection rules to /etc/snort/rules/local.rules.
Start Snort for testing:
sudo snort -c /etc/snort/snort.conf -i <interface> -A console
Install Splunk Universal Forwarder:
Install UF package, accept license and enable boot-start.
Configure outputs.conf to point to indexer: <SPLUNK_INDEXER_IP>:9997.


Attacker (Linux)

Tools used: nmap, nping, ping, curl, gobuster, hping3 (installed via package manager).
Example test commands are in attacks/attack_commands.md.
Snort rules (examples)
Place these (sanitized/tuned) rules in config/local.rules or /etc/snort/rules/local.rules:
# local.rules (examples)
alert icmp any any -> $HOME_NET any (msg:"LAB - ICMP flood suspected"; icmp_type:8; detection_filter:track by_src, count 20, seconds 10; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"LAB - SSH brute force suspected"; flags:S; detection_filter:track by_src, count 10, seconds 60; sid:1000004; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"LAB - Possible SQLi attempt"; flow:to_server,established; content:"' OR '1'='1"; nocase; http_uri; sid:1000006; rev:1;)


Tune detection_filter thresholds for your lab traffic and $HOME_NET settings in snort.conf.
Splunk searches & dashboards (examples)
Events per minute for victim host:
index=* host="<VICTIM_HOST>" | timechart span=1m count


Top alerting signatures (Snort):
index=* sourcetype=snort:alert | top msg limit=10
Failed SSH attempts:
index=* sourcetype=linux:auth "Failed password" | stats count by src_ip, user | where count > 5
Import the JSON in dashboards/splunk_dashboard_export.json via Splunk Web → Dashboards → Import.
Attack commands (examples included in repo)
All attack commands used for testing are recorded in attacks/attack_commands.md. They include (lab-only, low intensity) examples such as:
ping -c 50 <VICTIM_IP>
sudo nmap -sS --top-ports 500 -T4 <VICTIM_IP>
sudo nping --tcp -p 80 --rate 200 --count 1000 <VICTIM_IP>
for i in {1..25}; do ssh -o ConnectTimeout=3 invalid@<VICTIM_IP> exit || true; done
curl "http://<VICTIM_IP>/vuln.php?id=1' OR '1'='1"
Replace real IPs by placeholders or redact them before publishing publicly.
Evidence & screenshots
Include the following annotated screenshots in docs/screenshots/:
snort_alerts.png — Snort console or tail -f /var/log/snort/alert showing detection lines (with timestamp).
splunk_dashboard.png — Splunk dashboard showing event spikes (with query and timestamp visible).
uf_console.png — UF splunkd.log showing successful forwarding.
attack_console_*.png — attacker terminal showing the commands run and timestamp.


Safety & privacy notes

This repository contains only sanitized configs and screenshots. Do not include private keys, credentials, or full raw logs containing PII.

All attack commands must only be executed in authorized lab environments (your VMs). Running these against external systems is illegal and unethical.
