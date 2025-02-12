#!/usr/bin/env python3
# https://github.com/posixfan/Responder-Honeypot
import smtplib as smtp
from email.mime.text import MIMEText
from email.header import Header
from argparse import ArgumentParser
from os import getuid
from threading import Event, Thread
from time import time, sleep, strftime
from requests import post
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRResponse, LLMNRQuery

parser = ArgumentParser(description='Detects poisoning of the LLMNR and mDNS protocols.',
                        usage='./responder_honeypot [options]')
parser.add_argument('--name', type=str,
                    help='The name that LLMNR/mDNS is requesting (short name, not FQDN). '
                         'By default, randomly generated name.')
parser.add_argument('--timeout', type=int, default=10,
                    help='Timeout between requests (the default is 10 seconds)')
parser.add_argument('--email', action='store_true',
                    help='Send email notifications')
parser.add_argument('--telegram', action='store_true',
                    help='Send Telegram notifications')
parser.add_argument('--logs', type=str,
                    help='A file for saving events of detected attacks')
args = parser.parse_args()

stop_event = Event()

def is_running_as_root():
    return getuid() == 0

def log_to_file(line):
    with open(args.logs, 'a') as file:
        file.write(line + '\n')

def send_email(line):
    try:
        login = 'honeypot@example.com'
        server = smtp.SMTP('mx.mycorp.com', 25)
        subject = 'Alert! Hacker detected!'
        email = 'iss@example.com'
        text = line

        mime = MIMEText(text, 'plain', 'utf-8')
        mime['Subject'] = Header(subject, 'utf-8')

        server.sendmail(login, email, mime.as_string())
    except Exception as error:
        print(f'\033[31m[!]\033[0m Error sending an email: {error}')

def send_telegram(line):
    api_token = ''
    hook_url = f'https://api.telegram.org/bot{api_token}/sendMessage'
    CHAT_ID = ''
    msg_data = {}
    msg_data['chat_id'] = CHAT_ID
    msg_data['text'] = line
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

    post(hook_url, headers=headers, data=json.dumps(msg_data, ensure_ascii=False))

def generate_random_name():
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(10))
    return f'WIN-{random_string}'

def timer(start_time):
    execution_time = int(time.time() - start_time)
    hours = execution_time // 3600
    minutes = (execution_time % 3600) // 60
    seconds = execution_time % 60
    return f'{hours:02}:{minutes:02}:{seconds:02}'

def send_queries():
    start_time = time.time()
    packet_count = 0
    while not stop_event.is_set():
        mdns_query = (Ether(dst='01:00:5e:00:00:fb') / IP(dst='224.0.0.251') /
                      UDP(dport=5353) / DNS(qd=DNSQR(qname=f'{random_name}.local',
                                                     qtype='A')))
        sendp(mdns_query, verbose=False)

        llmnr_query = (Ether(dst='01:00:5e:00:00:fc') / IP(dst='224.0.0.252') /
                       UDP(dport=5355) / LLMNRQuery(id=RandShort(), qdcount=1) /
                       DNSQR(qname=random_name, qtype='A', qclass='IN'))
        sendp(llmnr_query, verbose=False)

        packet_count += 2
        print(f'\033[32m[+]\033[0m Program execution time: {timer(start_time)} | '
              f'Sending requests: {packet_count} packets', end='\r')
        sleep(args.timeout)

def handle_llmnr_packet(packet):
    try:
        if packet.haslayer(LLMNRResponse):
            if random_name in packet[LLMNRResponse].an.rrname.decode():
                line = (f'[{strftime("%d/%m/%Y %H:%M:%S")}] LLMNR Spoofing detected! '
                    f'Answer sent from {packet[IP].src} for name '
                    f'{packet[LLMNRResponse].an.rrname.decode()}')
                print('\033[31m[!]\033[0m ' + line)

                if args.email:
                    send_email(line)
                if args.telegram:
                    send_telegram(line)
                if args.logs:
                    log_to_file(line)
    except:
        return

def handle_mdns_packet(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            if hasattr(packet[DNS], 'an') and random_name in packet[DNS].an.rrname.decode():
                line = (f'[{strftime("%d/%m/%Y %H:%M:%S")}] mDNS Spoofing detected! '
                        f'Answer sent from {packet[IP].src} for name '
                        f'{packet[DNS].an.rrname.decode()}')
                print('\033[31m[!]\033[0m ' + line)

                if args.email:
                    send_email(line)
                if args.telegram:
                    send_telegram(line)
                if args.logs:
                    log_to_file(line)
    except:
        return

def handle_packet(packet):
    handle_llmnr_packet(packet)
    handle_mdns_packet(packet)

def sniff_responses():
    sniff(prn=handle_packet, filter='udp port 5353 or udp port 5355', store=0,
          stop_filter=lambda x: stop_event.is_set())

def main():
    global random_name

    if not is_running_as_root():
        print('\033[31m[-]\033[0m Root rights are required')
        return

    if args.logs:
        try:
            with open(args.logs, 'a'):
                pass
        except FileNotFoundError:
            print(f'\033[31m[-]\033[0m No such file or directory: {args.logs}')
            return

    if not args.name:
        random_name = generate_random_name()
    else:
        random_name = args.name

    query_thread = Thread(target=send_queries)
    query_thread.daemon = True
    query_thread.start()

    sniff_thread = Thread(target=sniff_responses)
    sniff_thread.daemon = True
    sniff_thread.start()

    try:
        while query_thread.is_alive() and sniff_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n\033[33m[!]\033[0m Detected Ctrl+C! Stopping the script...')
        stop_event.set()
        query_thread.join(timeout=1)
        sniff_thread.join(timeout=1)
        print('\033[32m[+]\033[0m Script stopped gracefully.')
    finally:
        if query_thread.is_alive():
            query_thread.join(timeout=1)
        if sniff_thread.is_alive():
            sniff_thread.join(timeout=1)

if __name__ == '__main__':
    main()
