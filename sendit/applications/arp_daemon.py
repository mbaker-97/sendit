#!/bin/python3
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.4"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.helper_functions.helper import *
from sendit.handlers.ethernet_handler import Ethernet_Listener
from sendit.helper_functions.helper import *

if __name__ == "__main__":
    interface = "wlan0"
    my_mac = get_MAC(interface)
    macs = [my_mac, BROADCAST_MAC]
    mappings = {get_ip(interface): my_mac, "192.168.1.154": my_mac} 
    listener = Ethernet_Listener(macs,interface, ipv4=False, arp_reply=True, arp_mappings = mappings) 
    listener.listen()


