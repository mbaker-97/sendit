__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.4"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit import *
from time import sleep
from sendit.protocols.arp import *
from queue import Queue
from threading import *
from ipaddress import ip_address, AddressValueError
from sendit.helper_functions.helper import *
from sendit.handlers.raw_nic import Raw_NIC
from sendit.protocols.arp import ARP
from sendit.protocols.etherframe import EtherFrame
class ARP_Listener():
    
    def __init__(self, queue, interface=None, reply=True, mappings=None):
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
        self.queue = queue
        self.mappings = mappings
        self.interface = interface

    def listen(self):
       #  arp =  ARP.arp_parser(arp_bytes) 
        if self.reply:
           nic = Raw_NIC(self.interface)
        while True:
            if not self.queue.empty():
                arp = self.queue.get()
                mac = self.mappings.get(arp.tpa)
                if mac is not None and self.reply and arp.op == 1:
                    reply = ARP(mac, arp.tpa, arp.sha, arp.spa, op=2)
                    frame = EtherFrame(arp.sha, mac, reply, ethertype = "arp")
                    nic.send(frame)
                    print(arp)
                

