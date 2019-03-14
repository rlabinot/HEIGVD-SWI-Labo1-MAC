#!/usr/bin/env python
# Authors : Labinot Rashiti & Hamel Dylan
# Date : 13.03.2019
# Remark : This script sniff the WiFi network and register the SSIDs for each MAC address

from scapy.all import Dot11, sniff
import requests
import json

# Link to the MAC API
MAC_URL = 'http://macvendors.co/api/%s'

# LIST FOR MAC AND SSID
mapClients = dict()
listClients = list()

# Function to display the MAC of the client and his SSIDs
def myPrint(MAC, SSID):
	# Get MAC vendor from the client
	responseClient = requests.get(MAC_URL %(MAC))
        jsonClient = responseClient.json()
	
	# Check if the company is known from the API
	try: 
		vendor = jsonClient['result']['company']
	except:
		vendor = "unknown vendor"
	

	# Display
	print("{} ({}) - {}".format(MAC, vendor, ", ".join(SSID)))


# Definition of the packets to found and manipulate
def handle_packet(packet) :	
	if packet.haslayer(Dot11) :
		# We take care only to probe requests frames (subtype = 4)
		if packet.type == 0 and packet.subtype == 4 :
			# Discard frames without SSID
			if packet.info != "" :
				# Check if the client is known or not
				if packet.addr2 in listClients :
					# Check if the SSID of this client is known or not
					if packet.info not in mapClients[packet.addr2] :
						# Add the new SSID and display it
						mapClients[packet.addr2].add(packet.info)
						#print("Adding a SSID to a MAC client")
						myPrint(packet.addr2, mapClients[packet.addr2])
				else:
					# Add the new client and his SSID
					listClients.append(packet.addr2)
					mapClients[packet.addr2] = {packet.info}
					#print("Adding a MAC client")
					myPrint(packet.addr2, mapClients[packet.addr2])

# Launch the sniffer
sniff(iface="wlan0mon", prn=handle_packet)
