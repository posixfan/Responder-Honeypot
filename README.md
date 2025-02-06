# Responder-Honeypot
Script for detection LLMNR, mDNS poisoning

Author: Andrew Razuvaev <posixfan87@yandex.ru>

# How does this script work?
Several technologies can be used to detect multicast protocol poisoning. The basic premise is to issue fake LLMNR and mDNS requests that should not receive any legitimate answers, as the requested resources do not exist. Any host that does answer the bait requests is assumed to be performing a malicious multicast protocol poisoning attack and should be alerted on. 

# Features
- mDNS Poisoning Detection
- LLMNR Poisoning Detection

# Preparing for launch
The Scapy library is required for the script to work.

Installing Scapy for Debian/Ubuntu: <pre>$ sudo apt install python3-scapy</pre>
Or you can use pip <pre>$ pip install scapy</pre>

Grant the script execution rights.
<pre>$ chmod u+x responder_honeypot.py</pre>

# Usage
<pre>$ ./responder_honeypot.py -h
usage: ./responder_honeypot [options]

Detects poisoning of the LLMNR and mDNS protocols.

options:
  -h, --help         show this help message and exit
  --name NAME        The name that LLMNR/mDNS is requesting (short name, not FQDN). By default, a string of 6 digits is generated.
  --timeout TIMEOUT  Timeout between requests (the default is 10 seconds)
  --logs LOGS        A file for saving events of detected attacks</pre>

# Examples
Launch without options. Request every 10 seconds, random name, no logs recorded.
<pre>$ sudo ./responder_honeypot.py</pre>
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/no_options.png)
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/no_options_res.png)

Using options
<pre>sudo ./responder_honeypot.py --name Im_a_victim --timeout 2 --logs honeypot.txt</pre>
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/with_options.png)
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/with_options_res.png)

# Acknowledgements
https://en.wikipedia.org/wiki/Multicast_DNS

https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution

https://github.com/lgandx/Responder
