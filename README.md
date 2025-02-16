# Responder Honeypot

A Python-based honeypot designed to detect and log LLMNR (Link-Local Multicast Name Resolution) and mDNS (Multicast DNS) poisoning attacks. This tool sends out LLMNR and mDNS queries and monitors for malicious responses, alerting you when an attack is detected. It can also send notifications via email or Telegram and log events to a file.

## Features

- Detects LLMNR and mDNS spoofing attacks.
- Sends email and Telegram notifications when an attack is detected.
- Logs detected attacks to a file for further analysis.
- Customizable query name and timeout between requests.
- Runs as a background process with graceful shutdown on `Ctrl+C`.

## Requirements

- Python 3.x
- Root privileges (required for packet sniffing and sending)
- External dependencies:
  - `scapy` (for packet manipulation)
  - `requests` (for Telegram notifications)
  - `smtplib` (for email notifications)

## Preparing for launch
<pre>
$ pip install -r requirements.txt
</pre>
Install the additional libpcap library for Debian/Ubuntu.
<pre>
$ sudo apt install libpcap0.8
</pre>

## New versions of Ubuntu and Debian use VENV
What is VENV => https://www.freecodecamp.org/news/how-to-setup-virtual-environments-in-python/

Quick Start Guide
<pre>
~/Responder-Honeypot$ sudo apt install python3-pip
~/Responder-Honeypot$ sudo apt install python3-venv
~/Responder-Honeypot$ sudo apt install libpcap0.8
~/Responder-Honeypot$ python3 -m venv venv 
~/Responder-Honeypot$ source venv/bin/activate
~/Responder-Honeypot$ pip install -r requirements.txt
~/Responder-Honeypot$ venv/bin/python3 responder_honeypot.py -h
~/Responder-Honeypot$ deactivate
</pre>

## Usage
<pre>
./responder_honeypot -h
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

## Email notifications (`--email`)
To enable email notifications, modify the `send_email` function with your SMTP server details, login credentials, and recipient email address. \
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/email_notification.png) \
\
[Additional information (smtplib)](https://docs.python.org/3/library/smtplib.html#) \
The tool can work without sending mail. You decide whether to configure this option or not.

## Telegram notifications (`--telegram`)
To enable Telegram notifications, update the `send_telegram` function with your bot's API token and chat ID. \
\
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/telegram_fix.png) \
\
[How to create a telegram bot](https://t.me/BotFather) \
The tool can work without Telegram. You decide whether to configure this option or not.

## Logging
If the `--logs` argument is provided, all detected attacks will be appended to the specified file.
<pre>$sudo ./responder_honeypot.py --email --telegram --logs attacks.log</pre>

## Examples
Launch without options. Request every 10 seconds, random name, no logs recorded, no email notifications, no telegram notifications.
<pre>$ sudo ./responder_honeypot.py</pre>
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/no_options.png)
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/no_options_res.png)

Using options
<pre>sudo ./responder_honeypot.py --name Robocop --timeout 2 --logs honeypot.txt</pre>
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/with_options.png)
![alt text](https://github.com/posixfan/Responder-Honeypot/blob/main/img/with_options_res.png)

## Contributing
Feel free to contribute to this project by opening issues or submitting pull requests. Any improvements or suggestions are welcome!

### Author
Andrew Razuvaev - [GitHub](https://github.com/posixfan) | <posixfan87@yandex.ru>

## To understand better
https://en.wikipedia.org/wiki/Multicast_DNS \
https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution \
https://github.com/lgandx/Responder \
https://scapy.readthedocs.io/en/latest/introduction.html#about-scapy
