#!/usr/bin/env python
import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_req = broadcast / arp_request
    answered = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[0]

    client_list = []
    for i in answered:
        client_dict = {"ip": i[1].psrc, "mac_addr": i[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_list(results):
    print("IP ADDRESS\t\tMAC ADDRESS\n------------------------------------------")
    for client in results:
        print(client["ip"] + "\t\t" + client["mac_addr"])

scan_result = scan("192.168.202.1/24")
print_list(scan_result)


