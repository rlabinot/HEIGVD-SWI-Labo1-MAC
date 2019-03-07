#!/usr/bin/env python

from scapy.all import Dot11, sniff
import sys

# checking if there is only one valid argument
if len(sys.argv) < 2 or sys.argv[1] == "":
	print("One MAC address argument is needed")
	exit(1)


macAddress = sys.argv[1] # get the first argument wich is the mac Address

def handle_packet(packet):
	if packet.haslayer(Dot11):
		if packet.type == 0 and packet.subtype == 4: # Packet type 0 for wifi and subtype 4 for probe request
			if macAddress.upper() == packet.addr2.upper():
				print("Device with MAC : %s is found!" %(packet.addr2.upper()))
				exit(0)

# Begin of the sniffing
sniff(iface="wlan0mon", prn=handle_packet)
