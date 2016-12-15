#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.all import sniff, ARP
import sys
import netifaces

#COLORS
HEADER = '\033[95m'
BLUE = '\033[94m'
GREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = "\033[1m"

class NetworkPree:

	macs = dict()

	def ifSame(self, packet):
		if (packet[ARP].hwsrc in self.macs):
			if(	self.macs[packet[ARP].hwsrc] == packet[ARP].psrc	):
				return 'known'
			else:
				#If Same Mac shows with Different IP
				return 2
		elif(packet[ARP].psrc in self.macs.values() ):
			#If Same IP shows with Different Mac
			return 3
		else:
			return "new"

	def _checkPackage(self, packet):
		if(packet[ARP].op == 2):
			check = self.ifSame(packet)
			if(check == "new"):
				self.macs[packet[ARP].hwsrc] = packet[ARP].psrc
				print GREEN + "New Machine Identified" + ENDC
				print BLUE + "IP: " + str(packet[ARP].psrc) + ENDC
				print BLUE + "MAC: " + str(packet[ARP].hwsrc) + ENDC
			elif(check == "known"):
				pass
			elif(check == 2):
				print  WARNING + "PREE THIS" + ENDC
				print FAIL + BOLD + "IP: " + str(packet[ARP].psrc)  + ENDC
				print FAIL + BOLD + "MAC: " + str(packet[ARP].hwsrc)+ ENDC
				print FAIL + "IP SPOOFED, Possible MITM ATTACK" + ENDC
			elif( check == 3):
				print  WARNING + "PREE THIS" + ENDC
				print FAIL + BOLD + "IP: " + str(packet[ARP].psrc)  + ENDC
				print FAIL + BOLD + "MAC: " + str(packet[ARP].hwsrc)+ ENDC
				print FAIL + "MAC SPOOFED, Possible MITM ATTACK" + ENDC
	def main(self):
		interface_list = netifaces.interfaces()
		print BLUE + " _   _      _                      _      ____                 " + ENDC
		print BLUE + "| \ | | ___| |___      _____  _ __| | __ |  _ \ _ __ ___  ___  " + ENDC
		print BLUE + "|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / | |_) | '__/ _ \/ _ \ " + ENDC
		print BLUE + "| |\  |  __/ |_ \ V  V / (_) | |  |   <  |  __/| | |  __/  __/ " + ENDC
		print BLUE + "|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |_|   |_|  \___|\___| " + ENDC

 		print HEADER + BOLD + "Select Interface to Pree" +ENDC
 		for x in interface_list:
 			print str(interface_list.index(x)) + " " + x
 		option = int(raw_input())
 		_interface = interface_list[option]
 		print _interface + " A Get Pree"
 		'''
		filter = arp
		count = 0 some bug here
		store = 0 
		iface = interface i.e wlan0 etc
		prn 
 		'''
		sniff(filter = 'arp', count = 0, store = 0, iface = _interface, prn = self._checkPackage)
	

if __name__ == '__main__':
	NetworkPree().main()
