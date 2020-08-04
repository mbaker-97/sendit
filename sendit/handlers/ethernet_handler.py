#!/usr/bin/python3
""" Creates class that listens and responds to Layer2 Etherframes """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.protocols.etherframe import EtherFrame
from sendit.helper_functions.helper import *
from sendit.handlers.raw_nic import Raw_NIC
from threading import Thread, enumerate
from queue import Queue

class Ethernet_Listener():
    """
    :param interface: Interface to be listening on
    :type interface: String
    :param protocols: dictonary where keys are MACs, values are list of \
        layer 3 protocol listeners
    :type protocols: dictionary
    """

    def __init__(self, interface, protocols): 
        """Constructor for Ethernet_Listener"""
        self.interface = interface
        self.threads = dict() # dictionary that maps <MAC_protocol> to thread 
        #object - example: AA:BB:CC:11:22:33_arp
        self.queues = dict()# dictionary that maps <MAC_protocol> to queue
        #object - example: AA:BB:CC:11:22:33_arp
        self.protocols = protocols
        self.macs = list(self.protocols.keys())
        
        for key in self.protocols.keys():
            self.create_threads(key, self.protocols.get(key))

    def create_threads(self, mac, protocols):
        """
        creates threads for each upper layer listener provided in protocols
        list. Also appends threads and queues created to self.threads and 
        self.queues
        :param mac: string mac address to create thread and queue for
        :type mac: String
        :param protocols: list of higher layer protocol listeners that need \
            threads and queues instantiated
        :type protocols: list
        """
        for protocol in protocols:
            name = mac + "_" + type(protocol).__name__.split("_")[0].lower()
            # Determine if this listener already has a thread established, 
            # likely with a different MAC
            for mac_ in self.protocols.keys():
                for proto in self.protocols.get(mac_):
                    
                    # Check if this is lhe same listener as we are attempting 
                    #  to make threads for
                    if proto is protocol:
                        q = self.queues.get( mac_.upper() + "_" +  
                                type(protocol).__name__.split("_")[0].lower())
                        # check if this found listener already has a started 
                        #  thread and queues
                        if q is not None:
                            # Assign thread and queue already established for
                            # this listener to dict values in self.threads
                            # and self.queue
                            thread  = self.threads.get( mac_.upper() + "_" +  
                                type(protocol).__name__.split("_")[0].lower())
                            self.threads[name] = thread
                            self.queues[name] = q

                            return
            # This executes if this listener does not already have thread and 
            # queue instantiated. Therefore, they must be instantiated before
            # adding to self.threads and self.queues
            queue = Queue(maxsize=0)
            thread = Thread(target=protocol.listen, args=(queue,), name=name)
            thread.start()
            self.threads[name] = thread
            self.queues[name] = queue

    def listen(self):
        """
        listens in on self.interface with a raw_nic
        if incoming etherframe has destination of a mac in self.macs to
        listen for, the frames etype field is checked to see if there
        is a corresponding listener for this mac and protocol
        if there is, the frame is passed into the corresponding queue for
        that mac/protocol thread
        if not, frame is discarded
        """
#Raw Nic will be created here
        nic = Raw_NIC(self.interface)
        print(enumerate())
        while True:
            # Receive maximum amount of bytes
            data = nic.recv(1518)
            frame = EtherFrame.etherframe_parser(data,recursive=False)
            # Check if destination MAC is in list of macs to listen for 
            if frame.dst.upper() in self.macs:
                q = self.queues.get( frame.dst.upper() + "_" + frame.etype.lower() )
                # Check if there is a listener for this protocol in this
                # MAC. If there is, pass frame to the proper queue
                # Otherwise do nothing
                if q is not None: 
                    q.put(frame)

    def remove_MAC(self, mac):
        """
        Remove MAC address from list of macs that listener will listen for
        Removes corresponding entries in self.mac, self.queues, and self.threads
        :param mac: string of mac address to remove
        :type mac: String
        """
        if helper.is_valid_mac(mac):
            try:
                mac = mac.upper()
                
                self.protocols.pop(mac)
                self.macs.remove(mac)
                queue_keys = self.queues.keys()
                thread_keys = self.threads.keys()

                # Remove queues and threads from dictionary 
                for key in thread_keys:
                    if key[0:18] == mac:
                        self.threads.pop(key)
                for key in queue_keys:
                    if key[0:18] == mac:
                        self.queues.pop(key)

            except ValueError:
                print("That MAC address was not in the current list")
        else:
            raise ValueError("Provided mac address is not valid")
    
    def remove_listener(self, mac, protocol):
        """
        Remove upper layer listener from Ethernet_Listener
        Removes corresponding entries in self.threads and self.queues, and if no more entries for a particular mac, corresponding mac is also removed from self.macs
        :param mac: string of mac address to remove corresponding listener
        :type mac: String
        :param protocol: protocol of listener to remove
        :type protocol: String
        :raise ValueError: if mac not valid MAC address
        """
        mac = mac.upper()
        protocol = protocol.lower()
        if not is_valid_MAC(mac):
            raise ValueError("mac must be valid MAC address")

        # This mac is not in the protocols dictionary
        if mac not in self.protocols.keys():
            pass # Decide if an error should be raised here
        # This mac is currently in the protocols dictionary
        else:
            protocols = self.protocols.get(mac)
            for protocol_listener in protocols:
                name = type(protocol_listener).__name__.split("_")[0]
                # Check if this is the protocol listener we want to listen for 
                if name == protocol:
                # Determine if we want to raise error if protocol no in list
                    # remove associated entries in protocols, macs, and threads
                    self.protocols.remove(protocol_listener)
                    self.queues.remove(mac + protocol)
                    self.threads.remove(mac + protocol)

                    # If there is no more listeners associated with partucular mac, remove mac key from protocols dictionary and from macs list
                    if len(protocols) == 0:
                        self.protocols.pop(mac)
                        self.macs.remove(mac)

    def add_listener(self, mac, listener):
        """
        Add a higher protocol layer listener into ethernet listener for management
        :param mac: mac address to listen on
        :type mac: String
        :param listener: listener object to add
        :type listener: Protocol Listener Object such as IPv4_Listener,\
                ARP_Listener, IPv6_Listener
        """

        if not is_valid_MAC(mac):
            raise ValueError("mac must be valid MAC address")

        # This mac is not in the protocols dictionary yet
        if mac not in self.protocols.keys():
            self.protocols[mac] = [listener] 
            self.macs.append(mac)
        # This mac is currently in the protocols dictionary
        else:
            self.protocols.get(mac).append(listener)

        create_threads(mac, [listener])

            
