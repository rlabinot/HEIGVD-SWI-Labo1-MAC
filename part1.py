#!/usr/bin/env python
# Authors : Labinot Rashiti & Hamel Dylan
# Date : 13.03.2019
# Remark : This script sniff the WiFi network and find a client by his MAC address

from scapy.all import Dot11, sniff
import sys

# checking if there is only one valid argument
if len(sys.argv) < 2 or sys.argv[1] == "":
	print("One MAC address argument is needed")
	exit(1)


macAddress = sys.argv[1] # get the first argument wich is the mac Address

# Definition of the packets to found and manipulate to found the client
def handle_packet(packet):
	if packet.haslayer(Dot11):
		if packet.type == 0 and packet.subtype == 4: # Packet subtype 4 for probe request
			if macAddress.upper() == packet.addr2.upper():
				print("Device with MAC : %s is found!" %(packet.addr2.upper()))
				exit(0)

# Begin of the sniffing
sniff(iface="wlan0mon", prn=handle_packet)
