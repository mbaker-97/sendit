__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.4"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.protocols.etherframe import EtherFrame
from sendit.helper_functions.helper import *
from sendit.handlers.raw_nic import Raw_NIC
from threading import Thread, enumerate
from sendit.handlers.ipv4_handler import IPv4_Listener
from sendit.handlers.ipv6_handler import IPv6_Listener
from sendit.handlers.arp_handler import ARP_Listener
from sendit.protocols.arp import ARP

from queue import Queue

class Ethernet_Listener():

    def __init__(self, macs, interface, ipv4=True, ipv6=False, arp=True, arp_reply=False, arp_mappings=None):
        if arp_reply and arp_mappings is None:
            raise ValueError("When arp_reply is set  to True, arp_mappings must be provided")
        self.macs = macs
        self.interface = interface
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.arp = arp
        self.threads = dict()
        self.queues = dict()
        self.arp_reply = arp_reply
        self.arp_mappings = arp_mappings

        for mac in self.macs:
            self.create_threads(mac)

    def create_threads(self, mac):
        #  if self.ipv4:
            #  ipv4_list = IPv4_Listener()
            #  thread = Thread(target=ipv4_list.listen(), args = (), name=mac+"_ipv4")
            #  thread.start()
            #  threads[thread.name, thread]
            #  queues[thread.name, queue]
        #  if self.ipv6:
            #  ipv6_list = IPv6_Listener()
            #  thread = Thread(target=ipv6.listen(), args = (), name=mac+"_ipv6")
            #  thread.start()
            #  threads[thread.name, thread]
            #  queues[thread.name, queue]
        if self.arp:
            queue = Queue(maxsize=0)
            arp_list = ARP_Listener(queue, interface=self.interface,  reply=self.arp_reply, mappings=self.arp_mappings)
            thread = Thread(target=arp_list.listen, name=mac+"_arp")
            thread.start()
            self.threads[thread.name] =  thread
            self.queues[thread.name] =  queue

    def listen(self):
        #Raw Nic will be created here
        nic = Raw_NIC(self.interface)
        print(enumerate())
        while True:
            # Receive maximum amount of bytes
            data = nic.recv(1518)
            frame = EtherFrame.etherframe_parser(data,recursive=False)
            # Check if destination MAC is in list of macs to listen for 
            if frame.dst in self.macs  :
                #TODO pass payloads to proper handlers
                if frame.etype == "ipv4" and self.ipv4:
                    pass
                if frame.etype == "ipv6" and self.ipv6:
                    pass
                if frame.etype == "arp" and self.arp:
                    q = self.queues.get( frame.dst + "_arp")
                    q.put(ARP.arp_parser(frame.payload))

    def add_MAC(self, mac):
        if helper.is_valid_mac(mac):
            self.macs.append(mac)
            create_threads(mac)
        else:
            raise ValueError("Provided mac address is not valid")

    def remove_MAC(self, mac):
        if helper.is_valid_mac(mac):
            try:
                # TODO - delete associated threads
                # TODO - delete associated queues
                self.macs.remove(mac)
            except ValueError:
                print("That MAC address was not in the current list")
        else:
            raise ValueError("Provided mac address is not valid")

    def set_on(self, protocol):
        """
        turns on handling of designated protocol
        :param protocol: next layer protocol to turn on
        """
        lower = protocol.lower()
        if lower == "ipv4":
            self.ipv4 = True
            ipv4_list = IPv4_Listener()
            thread = Thread(target=ipv4_list.lister(), args = (), name=mac+"_ipv4")
            self.threads.append(thread)
        elif lower == "ipv6":
            self.ipv6 = True
            ipv6_list = IPv6_Listener()
            thread = Thread(target=ipv4_list.lister(), args = (), name=mac+"_ipv6")
            self.threads.append(thread)
        elif lower == "arp":
            self.arp = True
            arp_list = ARP_Listener()
            thread = Thread(target=ipv4_list.lister(), args = (), name=mac+"_arp")
            self.threads.append(thread)
        else:
            raise ValueError(protocol + " is not a currently supported protocol for Ethernet_Listener")


    def set_off(self, protocol):
        """
        turns off handling of designated protocol
        :param protocol: next layer protocol to turn off
        """
        # TODO - delete associated threads and queues
        lower = protocol.lower()
        if lower == "ipv4":
            self.ipv4 = False
        elif lower == "ipv6":
            self.ipv6= False
        elif lower == "arp":
            self.arp = False
        else:
            raise ValueError(protocol + " is not a currently supported protocol for Ethernet_Listener")

