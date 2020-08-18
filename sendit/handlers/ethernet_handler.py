#!/usr/bin/python3
""" Creates class that listens and responds to Layer2 Etherframes """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.handlers.handler import Handler
from sendit.helper_functions.helper import *
import asyncio

class EtherFrame_Handler(Handler):
    """
    Asynchronously listens for Etherframes in own queue placed there by Bytes_Handler
    Creates EtherFrames from raw bytes, places those in async queues based on MAC mappings in queue_mappings

    :param send_up: asyncio.Queue OR dictionary of queues to put items in to go to higher layers, dictionary mapping async queues to protocol names
    :type send_up: Dictionary where keys are strings in format mac_protocol, values are lists of asyncio.queue, Dictionary where keys are strings in format mac_protocol, values are lists of asyncio.queue

    :param send_down: asyncio.Queue to put items in to go to lower layers
    :type send_down: asyncio.Queue
    :param recv_up: asyncio.Queue to receive items from higher layers
    :type recv_up: asyncio.Queue
    :param recv_down: asyncio.Queue to receive items from lower layers
    :type recv_down: asyncio.Queue
    """

    def __init__(self, send_up=None, send_down=None, recv_up=None, recv_down=None): 
        """Constructor for Ethernet_Handler"""
        super().__init__(send_up=send_up, send_down=send_down, recv_up=recv_up, recv_down=recv_down)
        # Keys contain protocol names, values contain list of async queues to place frames in

    async def listen(self):
        """
        Asynchronously listen for etherframes put in self.recv_queue
        If the protocols in the frame match one of the keys in self.queue_mappings
        Pass that frame on to all queues in corresponding list
        """
        # Grab this into local scope to reduce dictionary lookups
        recv_queue = self.recv_down
        send_queues = self.send_up

        while True:
            frame = await recv_queue.get()
            print(frame)
            # Check if queue_mappings was provided
            if send_queues is not None:
                # Check if destination address is a MAC to be listening for
                queues = send_queues.get(frame.etype)
                if queues is not None:
                    for queue in queues:
                        # Await placing bytes in queue
                        #  print("Sending to queue {}".format(frame.etype))
                        await queue.put(frame)

    #TODO
    def remove_protocol(self, protocol):
        """
        Remove protocol from list of protocols that handler will handler for

        :param protocol: string of protocol to remove
        :type protocol: String
        """
        if helper.is_valid_mac(mac):
            pass
        else:
            raise ValueError("Provided mac address is not valid")
    
    #TODO
    def remove_queue(self, mac, protocol):
        """
        Remove upper layer queue from Ethernet_Handler

        :param mac: string of mac address to remove corresponding handler
        :type mac: String
        :param protocol: protocol of handler to remove
        :type protocol: String
        :raise ValueError: if mac not valid MAC address
        """
        pass

    #TODO
    def add_queue(self, mac, queue):
        """
        Add a higher protocol layer queue into ethernet handler for management

        :param mac: mac address to listen on
        :type mac: String
        """
        pass

    async def await_from_higher(self):
        """
        Wait for frames from higher layers that needs Ethernet Header adjusted
        Swaps src and destination
        """
        recv_queue = self.recv_up
        send_queue = self.send_down
        while True:
            frame = await self.recv_queue.get()

            # Swap source and destination
            # If arp reply, don't use old frame src for new frame dst - this will be
            # broadcast address
            if frame.etype == "arp" and frame.payload.op == 2:
                frame.dst, frame.src = frame.src, frame.payload.sha
            else:
                frame.dst, frame.src = frame.src, frame.dst

            await self.send_down.put(frame)

