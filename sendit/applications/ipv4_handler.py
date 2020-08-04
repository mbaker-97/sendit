#!/usr/bin/python3
""" Provides example of how to listen for IPv4 objects"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.helper_functions.helper import *
from sendit.handlers.ethernet_handler import Ethernet_Listener
from sendit.handlers.ipv4_handler import IPv4_Listener
from sendit.helper_functions.helper import BROADCAST_MAC, get_ip, get_MAC, BROADCAST_IPV4

if __name__ == "__main__":
    interface = "wlan0"
    my_mac = get_MAC(interface)
    ipv4_listener = IPv4_Listener(["192.168.1.164", BROADCAST_IPV4])

    protocols = {my_mac: [ipv4_listener], BROADCAST_MAC: [ipv4_listener]} 
    listener = Ethernet_Listener(interface, protocols)
    listener.listen()


