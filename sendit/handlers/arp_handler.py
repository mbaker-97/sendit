#!/usr/bin/python3
""" Creates class that listens and responds to ARP messages"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit import *
from queue import Queue
from sendit.handlers.raw_nic import Raw_NIC
from sendit.protocols.arp import ARP
from sendit.protocols.etherframe import EtherFrame
from sendit.helper_functions.helper import is_valid_MAC
from ipaddress import ip_address, AddressValueError

class ARP_Listener():
    
    """
    :param interface: string name of interface to respond to ARP messages
                        on, defaults to None
    :type interface: String
    :param reply: boolean of whether to answer ARP requests, defaults to True
    :type reply: Boolean
    :param mappings: dictionary mapping MAC addresses to IPv4 addressses \ 
        defaults to None. Required if reply is True
    :type mappings: dictionary with String keys and values, defaults to None
    :raise ValueError: when reply is set to true but mappings is not defined \
        or when keys in mappings are not valid IPv4 addresses \
        or when values in mappings are not valid MAC addresses
    """

    def __init__(self, interface=None, reply=True, mappings=None):
        """Constructor for ARP_Listener """
        if reply and mappings is None:
            raise ValueError("When reply is set  to True, mappings must be provided")
        # Check that all keys of mappngs dictionary are valid IPv4 addresses
        for ip in mappings.keys():
            try:
                ip_address(ip)
            except AddressValueError:
                raise ValueError("All keys of mapping dictionary must be valid IPv4 addresses")
        
        #Check that all values in mappings dictionary are valid MAC addresses
        for mac in mappings.values():
            if not is_valid_MAC(mac):
                raise ValueError("All values of mapping dictionary must be valid MAC addresses")

        self.reply = reply
        self.mappings = mappings
        self.interface = interface

    def listen(self, queue):
        """
        listens and responds for ARP messages coming in on queue, put there by
        an ethernet_handler
        :param queue: Queue which will contain EtherFrames with ARP messages \
            in them
        :type queue: Queue
        """
        if self.reply:
           nic = Raw_NIC(self.interface)
        while True:
            if not queue.empty():
                frame = queue.get()
                arp = ARP.arp_parser(frame.payload)
                mac = self.mappings.get(arp.tpa)
                if mac is not None and self.reply and arp.op == 1:
                    reply = ARP(mac, arp.tpa, arp.sha, arp.spa, op=2)
                    reply_frame = EtherFrame(frame.src, mac, reply, ethertype = "arp")
                    nic.send(reply_frame)
                    print(arp)
                

