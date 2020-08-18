"""Demonstrates how to create a basic ARP Daemon"""
#!/usr/bin/python3
# Runs basic ARP Daemon
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.helper_functions.helper import *
from sendit.handlers.ethernet_handler import Ethernet_Handler
from sendit.handlers.arp_handler import ARP_Handler
from sendit.helper_functions.helper import BROADCAST_MAC, get_IP, get_MAC
from sendit.handlers.raw_nic import Async_Raw_NIC
from sendit.handlers.bytes_handler import Bytes_Handler
from asyncio import Queue

if __name__ == "__main__":

    interface = "wlp1s0"
    my_mac = get_MAC(interface)

    #ARP Listener stuff
    mappings = {get_IP(interface): my_mac, "192.168.1.154": my_mac} 
    arp_ethernet_down_queue = Queue()
    arp_handler = ARP_Handler(interface=interface, mappings=mappings, send_queue=arp_ethernet_down_queue)

    #Ethernet Listener stuff
    protocols = {my_mac + "_arp" : arp_listener.recv_queue, BROADCAST_MAC + "_arp" : arp_listener.recv_queue} 

    ethernet_bytes_down_queue = Queue()
    ehandler = Ethernet_Handler(queue_mappings=protocols, send_queue=ethernet_bytes_down_queue, incoming_higher_queue=arp_ethernet_queue)

    #Bytes Listener stuff
    bytes_raw_nic_down_queue
    bytes_handler = Bytes_Handler(send_queue=


    araw_nic = Async_Raw_NIC(interface, elistener.recv_queue, incoming_higher_queue )
    listener.listen()


