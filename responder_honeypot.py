#!/usr/bin/python3
import smtplib as smtp
from email.mime.text import MIMEText
from email.header import Header
from argparse import ArgumentParser
from os import getuid
from random import randint
from threading import Event, Thread
from time import time, ctime, sleep
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRResponse, LLMNRQuery

parser = ArgumentParser(description='Detects poisoning of the LLMNR and mDNS protocols.',
                        usage='./responder_honeypot [options]')
parser.add_argument('--name', type=str,
                    help='The name that LLMNR/mDNS is requesting (short name, not FQDN). '
                         'By default, a string of 6 digits is generated.')
parser.add_argument('--timeout', type=int, default=10,
                    help='Timeout between requests (the default is 10 seconds)')
parser.add_argument('--email', action='store_true',
                    help='Send an email alert')
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
        print('[+] An email has been sent.')
    except Exception as error:
        print(f'[-] Error sending an email: {error}')

def generate_random_name():
    return f'{randint(100000, 999999)}'

def send_queries():
    while not stop_event.is_set():
        mdns_query = (Ether(dst='01:00:5e:00:00:fb') / IP(dst='224.0.0.251') /
                      UDP(dport=5353) / DNS(qd=DNSQR(qname=f'{random_name}.local',
                                                     qtype='A')))
        sendp(mdns_query, verbose=False)

        llmnr_query = (Ether(dst='01:00:5e:00:00:fc') / IP(dst='224.0.0.252') /
                       UDP(dport=5355) / LLMNRQuery(id=RandShort(), qdcount=1) /
                       DNSQR(qname=random_name, qtype='A', qclass='IN'))
        sendp(llmnr_query, verbose=False)

        print(f'\n[-->] [{ctime()}] Sent query for random name: {random_name}')
        sleep(args.timeout)

def handle_llmnr_packet(packet):
    if packet.haslayer(LLMNRResponse):
        if random_name in packet[LLMNRResponse].an.rrname.decode():
            line = (f'[!] [{ctime()}] [LLMNR] Spoofing detected! '
                    f'IP {packet[IP].src}, responded to the random name request: '
                    f'{packet[LLMNRResponse].an.rrname.decode()}')
            print(line)

            if args.email:
                send_email(line)

            if args.logs:
                log_to_file(line)

def handle_mdns_packet(packet):
    try:
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            if hasattr(packet[DNS], 'an') and random_name in packet[DNS].an.rrname.decode():
                line = (f'[!] [{ctime()}] [mDNS] Spoofing detected! '
                        f'IP {packet[IP].src}, responded to the random name request: '
                        f'{packet[DNS].an.rrname.decode()}')
                print(line)

                if args.email:
                    send_email(line)

                if args.logs:
                    log_to_file(line)
    except AttributeError:
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
        print('Root rights are required')
        return

    if args.logs:
        try:
            with open(args.logs, 'a'):
                pass
        except FileNotFoundError:
            print(f'No such file or directory: {args.logs}')
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
        print('\n[!] Detected Ctrl+C! Stopping the script...')
        stop_event.set()
        query_thread.join(timeout=1)
        sniff_thread.join(timeout=1)
        print('[+] Script stopped gracefully.')
    finally:
        if query_thread.is_alive():
            query_thread.join(timeout=1)
        if sniff_thread.is_alive():
            sniff_thread.join(timeout=1)

if __name__ == '__main__':
    main()
