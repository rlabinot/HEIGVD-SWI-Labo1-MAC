#!/usr/bin/env python

from scapy.all import Dot11, sniff

def handle_packet(packet) :
	if packet.haslayer(Dot11) :
		if packet.type == 0 and packet.subtype == 4 :
			print("Client MAC : %s \t SSID : %s \t SSID MAC : %s " %(packet.addr2.upper(), packet.info.upper(), packet.addr1.upper()))


sniff(iface="wlan0mon", prn=handle_packet)
