#!/bin/python3
import os
while True:
    try:
        from scapy.all import *
        from scapy.layers.l2   import Ether
        from scapy.layers.inet import IP
        from scapy.layers.inet import UDP
        from scapy.layers.dhcp import DHCP
        from scapy.layers.dhcp import BOOTP
        break
    except ModuleNotFoundError:
        # Scapy happens to be installed locally, but this script has to run as sudo...
        os.sys.path.append('/home/' + os.getlogin() + '/.local/lib/python3.8/site-packages')
        # print(os.sys.path)

# DHCP discover
pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / 
    UDP(sport=68, dport=67) / 
    BOOTP(chaddr='00:11:22:33:44:55') / # Requiring the MAC of sending device
    DHCP(options=[("message-type", "discover"), "end"])
    )
# pkt = DHCP()

sendp(pkt, iface='ens3f0', loop=1, inter=1)
# sendp(pkt, iface='ens3f1', loop=1, inter=1)