import scapy.all as scapy 
import optparse
# import argparse




print(""" \033[32m

 #     # #     # #     #    #    #######    #    #    # 
 ##   ## #     # #  #  #   # #   #         # #   #   #  
 # # # # #     # #  #  #  #   #  #        #   #  #  #   
 #  #  # #     # #  #  # #     # #####   #     # ###    
 #     # #     # #  #  # ####### #       ####### #  #   
 #     # #     # #  #  # #     # #       #     # #   #  
 #     #  #####   ## ##  #     # #       #     # #    #  
                Network Scanner
          """ 
)









# 1 ) using the argparse module

# # Get the arguments from the command line
# def get_arguments():
# 	parser = argparse.ArgumentParser()
# 	parser.add_argument("-t", "--target", dest="ip", help="Enter IP address or IP address range of target network")
# 	options = parser.parse_args()
# 	if not options.ip:
# 		parser.error("[-] Please specify an IP address or IP address range, use --help for more info")
# 	return options



# 2 )using the optparse module

# get the arguments 
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i","--ip ","--target", dest = "Network_ip", help = "to enter device ip or network range" )
    (option , arguments) = parser.parse_args()

    if not option.Network_ip:
        parser.error("\033[31m[-] Please specify an ip address or ip address range , type --help for more info.")
    return option


# scan the network
def scan(network_ip):
    # ARP request generation 
    arp_request = scapy.ARP(pdst = network_ip)
    # dst MAC Address for ARP broadcast
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    # merge frames for sending the packet
    arp_request_broadcast = arp_request/broadcast
    # send the packet and get the responce
    broadcast_message = scapy.srp(arp_request_broadcast , timeout=1 , verbose =False )[0]

    #get the MAC Address an ip of the target
    packet_list = []
    for i in broadcast_message:
        packet_dict = {"ip :" + i[1].psrc + "MAC Add :" + i[1].hwsrc}
        packet_list.append(packet_dict)
    return packet_list

#print the result
def print_result(result_list):
    print("ip\t\t\tMAC Address\n- - -- - - - - - - - - - - - - - - - - - - ")
    for i in result_list:
        print(i["ip"] + "\t" + i["MAC"])

#main function
options = get_arguments()
scan_result = scan(options.Network_ip)
print_result(scan_result)


