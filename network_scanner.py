#!/usr/bin/env python #the shebang defines the absolute path for the code interpreter (python)
import scapy.all as scapy #imports everything in the scapy module as "scapy"

#This scan functions creates ARP requests for the specified IP and broadcasts them on the network
def scan(ip): 
    arp_request = scapy.ARP(pdst=ip) #defines the ARP request packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #defines the broadcast ethernet frame
    broadcast_arp_req = broadcast / arp_request #broadcasts the ARP request by appending it to the ethernet frame
    answered = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[0] #this captures the ARP response from the client; it times out after 1 second if no response is received

    client_list = [] #define an empty list that will be filled in with key:value pairs of the IP & MAC addresses
    for i in answered: #for each element in the answered list...
        client_dict = {"ip": i[1].psrc, "mac_addr": i[1].hwsrc} #creates a dictionary of the IP and MAC address
        client_list.append(client_dict) #this appends the client dictionary to the client list
    return client_list 

#This print list function will print out the ARP cache table
def print_list(results): #the function will pass through a results dictionary
    print("IP ADDRESS\t\tMAC ADDRESS\n------------------------------------------") #table header
    for client in results: #for each client in the results list dictionary...
        print(client["ip"] + "\t\t" + client["mac_addr"]) #print the IP and MAC address

scan_result = scan("192.168.202.1/24") #Here I run the scan function with my local subnet
print_list(scan_result) #Next it will take those scan results and run them through the print list function to generate the ARP cache table


