# Creates class that listens and responds to ARP messages
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.5"
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
    
    def __init__(self, interface=None, reply=True, mappings=None):
        """
        Constructor for ARP_Listener 
        :param interface: - string name of interface to respond to ARP messages
                            on - default None
        :param reply: - boolean of whether to answer ARP requests - default True
        :param mappings: - dictionary mapping MAC addresses to IPv4 addressses -
                           default is None. Required if reply is True
        :raise ValueError: when reply is set to true but mappings is not defined
        :raise ValueError: when keys in mappings are not valid IPv4 addresses
        :raise ValueError: when values in mappings are not valid MAC addresses
        """
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
        :param queue: a Queue object which will contain EtherFrames with ARP
                      messages in them
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
                

