# Responder-Honeypot
Tool for detection LLMNR, mDNS poisoning

Author: Andrew Razuvaev <posixfan87@yandex.ru>

# How does this script work?
Several technologies can be used to detect multicast protocol poisoning. The basic premise is to issue fake LLMNR and mDNS requests that should not receive any legitimate answers, as the requested resources do not exist. Any host that does answer the bait requests is assumed to be performing a malicious multicast protocol poisoning attack and should be alerted on. 

# Features
- mDNS Poisoning Detection
- LLMNR Poisoning Detection
- Email notification
- Telegram notifications

# Preparing for launch
The following command installs packages in bulk according to the configuration file requirements.txt. In some environments, use pip3 instead of pip.
<pre>
$ pip install -r requirements.txt
</pre>
Install the additional libpcap library for Debian/Ubuntu.
<pre>
$ sudo apt install libpcap0.8
</pre>

# New versions of Ubuntu and Debian use VENV
What is VENV => https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/

Quick Start Guide
<pre>
~/Responder-Honeypot$ sudo apt install python3-pip
~/Responder-Honeypot$ sudo apt install python3-venv
~/Responder-Honeypot$ sudo apt install libpcap0.8
~/Responder-Honeypot$ python3 -m venv venv 
~/Responder-Honeypot$ source venv/bin/activate
~/Responder-Honeypot$ pip install -r requirements.txt
~/Responder-Honeypot$ venv/bin/python3 honeypot.py -h
~/Responder-Honeypot$ deactivate
</pre>

# Usage
<pre>
$ venv/bin/python3 honeypot.py -h
usage: ./responder_honeypot [options]

Detects poisoning of the LLMNR and mDNS protocols.

options:
  -h, --help         show this help message and exit
  --name NAME        The name that LLMNR/mDNS is requesting (short name, not FQDN). By default, randomly generated name.
  --timeout TIMEOUT  Timeout between requests (the default is 10 seconds)
  --email            Send email notifications
  --telegram         Send Telegram notifications
  --logs LOGS        A file for saving events of detected attacks
</pre>

# Email notifications (--email)
If you want to use the email notification, you need to make edits to the source code. (see the screenshot below). \
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/email_notification.png) \
\
Additional information => https://docs.python.org/3/library/smtplib.html# \
The tool can work without sending mail. You decide whether to configure this option or not.

# Examples
Launch without options. Request every 10 seconds, random name, no logs recorded, no email notifications.
<pre>$ sudo ./responder_honeypot.py</pre>
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/no_options.png)
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/no_options_res.png)

Using options
<pre>sudo ./responder_honeypot.py --name Im_a_victim --timeout 2 --logs honeypot.txt</pre>
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/with_options.png)
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/with_options_res.png)

# To understand better
https://en.wikipedia.org/wiki/Multicast_DNS \
https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution \
https://github.com/lgandx/Responder \
https://scapy.readthedocs.io/en/latest/introduction.html#about-scapy
