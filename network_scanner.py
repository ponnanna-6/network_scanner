#!/usr/bin/env python

import scapy.all as scapy
import optparse


class NetworkScanner:
    def __init__(self, ip):
            self.scan_result = self.scan(ip)

    def scan(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        clients_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)
        return clients_list

    def print_result(self, result_list):
        print("_"*40+"\n"+"IP"+"\t\t\t"+"MAC\n"+"_"*40)
        for client in result_list:
            print(client["ip"]+"\t"+" "*5+client["mac"])

    def run(self):
        self.print_result(self.scan_result)


ip_range = raw_input("Enter IP range ")
my_scanner = NetworkScanner(ip_range)
my_scanner.run()

