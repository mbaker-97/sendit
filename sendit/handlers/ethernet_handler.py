#!/usr/bin/python3
""" Creates class that listens and responds to Layer2 Etherframes """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.7"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.handlers.listener import Listener
from sendit.helper_functions.helper import *
import asyncio

class EtherFrame_Listener(Listener):
    """
    Asynchronously listens for Etherframes in own queue placed there by Bytes_Listener 
    Creates EtherFrames from raw bytes, places those in async queues based on MAC mappings in queue_mappings

    :param send_queue: asyncio.Queue that will be used to put frames in to send
    :type send_queue: asyncio.Queue
    :param queue_mappings: Dictionary mapping async queues to protocol names, defaults None
    :type queue_mappings: Dictionary where keys are strings of protocol names, values are lists of asyncio.queue
    :param incoming_higher_queue: asyncio.Queue that will receive frames from \
        higher layers that require computation at current layer to be ready to \
        sent. Will then be passed to send_queue, which will be the lower layer's
        incoming_higher_queue
    :type incoming_higher_queue: asyncio.Queue
    """

    def __init__(self, queue_mappings=None, send_queue=None, incoming_higher_queue= None): 
        """Constructor for Ethernet_Listener"""
        super().__init__(send_queue = send_queue, incoming_higher_queue = incoming_higher_queue)
        # Keys contain protocol names, values contain list of async queues to place frames in
        self.queue_mappings = queue_mappings

    async def listen(self):
        """
        Asynchronously listen for etherframes put in self.recv_queue
        If the protocols in the frame match one of the keys in self.queue_mappings
        Pass that frame on to all queues in corresponding list
        """
        # Grab this into local scope to reduce dictionary lookups
        mappings = self.queue_mappings
        recv_queue = self.recv_queue

        while True:
            frame = await recv_queue.get()
            print(frame)
            # Check if queue_mappings was provided
            if mappings is not None:
                # Check if destination address is a MAC to be listening for
                queues = mappings.get(frame.etype)
                if queues is not None:
                    for queue in queues:
                        # Await placing bytes in queue
                        print("Sending to queue {}".format(frame.etype))
                        await queue.put(frame)

    def remove_protocol(self, protocol):
        """
        Remove protocol from list of protocols that listener will listen for

        :param protocol: string of protocol to remove
        :type protocol: String
        """
        if helper.is_valid_mac(mac):
            pass
        else:
            raise ValueError("Provided mac address is not valid")
    
    def remove_queue(self, mac, protocol):
        """
        Remove upper layer queue from Ethernet_Listener

        :param mac: string of mac address to remove corresponding listener
        :type mac: String
        :param protocol: protocol of listener to remove
        :type protocol: String
        :raise ValueError: if mac not valid MAC address
        """
        pass

    def add_queue(self, mac, queue):
        """
        Add a higher protocol layer queue into ethernet listener for management

        :param mac: mac address to listen on
        :type mac: String
        :param listener: listener object to add
        :type listener: Protocol Listener Object such as IPv4_Listener,\
                ARP_Listener, IPv6_Listener
        """
    async def await_from_higher(self):
        """
        Wait for frames from higher layers that needs IPv4 header adjusted
        Swaps src and destination
        """
        frame = await self.incoming_higher_queue.get()
        # Swap source and destination
        frame.dst, frame.src = frame.src, frame.dst
        await self.send_queue.put(frame)








