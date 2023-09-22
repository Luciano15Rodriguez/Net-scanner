import scapy.all as scapy 

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=True)[0]

    print("IP\t\t\tMAC address\n-------------------")
    clients_list = []
    for element in answered_list:
        client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dictionary)
    return(clients_list)

def print_result(results_list):
    print("IP\t\t\tMAC address\n-------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

scan_result = scan("IP address here")
print_result(scan_result)