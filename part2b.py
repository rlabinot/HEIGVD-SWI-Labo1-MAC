#!/usr/bin/env python

from scapy.all import Dot11, sniff
import requests
import json

# lien de l'API pour les infos MAC
MAC_URL = 'http://macvendors.co/api/%s'

# definition du type de paquet et actions a effectuer
def handle_packet(packet) :
	if packet.haslayer(Dot11) :
		# On prend en compte uniquement les probes requests avec le subtype = 4
		if packet.type == 0 and packet.subtype == 4 :
			# Recuperation des informations MAC du client et extraction du json
			responseClient = requests.get(MAC_URL %(packet.addr2))
			jsonClient = responseClient.json()

			# Recuperation des infos MAC du SSID et extraction du json
			responseSSID = requests.get(MAC_URL %(packet.addr1))
                        jsonSSID = responseClient.json()

			# Affichage des resultats selon l'exemple du professeur
			print("%s (%s) - %s" %(packet.addr2, jsonClient['result']['company'], jsonSSID['result']['address']))

			
# Lancement du sniffer selon un type de packet cible
sniff(iface="wlan0mon", prn=handle_packet)
