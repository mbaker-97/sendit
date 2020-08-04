"""Demonstrates how to create a basic ARP Daemon"""
#!/usr/bin/python3
# Runs basic ARP Daemon
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.helper_functions.helper import *
from sendit.handlers.ethernet_handler import Ethernet_Listener
from sendit.handlers.arp_handler import ARP_Listener
from sendit.helper_functions.helper import BROADCAST_MAC, get_ip, get_MAC

if __name__ == "__main__":
    interface = "wlan0"
    my_mac = get_MAC(interface)
    mappings = {get_ip(interface): my_mac, "192.168.1.154": my_mac} 

    arp_listener = ARP_Listener(interface=interface, mappings=mappings)

    protocols = {my_mac: [arp_listener], BROADCAST_MAC: [arp_listener]} 
    listener = Ethernet_Listener(interface, protocols)
    listener.listen()


