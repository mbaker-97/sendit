#!/usr/bin/python3
""" Creates class that listens and responds to raw bytes put in queue by \
        Async_Raw_NIC"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.7"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.protocols.etherframe import EtherFrame
from sendit.handlers.listener import Listener
import asyncio

class Bytes_Listener(Listener):
    """
    Asynchronously listens for bytes in own queue placed there by Async_Raw_NIC
    Creates EtherFrames from raw bytes, places those in async queues based on 
    MAC mappings in queue_mappings

    :param send_queue: asyncio.Queue that will be used to put frames in to send
    :type send_queue: asyncio.Queue
    :param queue_mappings: Dictionary mapping async queues to MAC addresses, defaults to None
    :type queue_mappings: Dictionary where keys are strings of MACs, values are lists of asyncio.queue
    """

    def __init__(self, send_queue=None, queue_mappings=None): 
        """Constructor for Bytes_Listener"""
        # this creates queue to listen on
        super().__init__(send_queue = send_queue)
        # Keys contain MACs to send on, values contain list of async queues to place those bytes in 
        self.queue_mappings = queue_mappings 

    async def listen(self):
        """
        Asynchronously waits for bytes in self.recv_queue \
        if incoming etherframe has destination of a mac in \
        self.queue_mappings.keys(), this is sent to all queues contained in 
        corresponding value in dict
        """
        # Grab this into local scope to reduce dictionary lookups
        mappings = self.queue_mappings
        while True:
            # Wait for bytes to show up in queue
            byte = await self.recv_queue.get()
            print("Got bytes in byte receiver")
            frame = EtherFrame.etherframe_parser(byte, recursive=False)

            # Check if queue_mappings was provided
            if mappings is not None:
                queues = mappings.get(frame.dst)
                # Check if destination address is a MAC to be listening for
                if queues is not None:

                    for queue in queues:
                        # Await placing bytes in queue
                        await queue.put(frame)


    def remove_MAC(self, mac):
        """
        Remove MAC from self.queue_mappings

        :param mac: string of mac address to remove
        :type mac: String
        :raise ValueError: If mac is not valid MAC Address or if mac not \
            currently in queue_mappings.keys()
        """
        if helper.is_valid_mac(mac):
            mac = mac.upper()
            # Try to remove that mac from the dictionary
            try:
                self.queue_mappings.pop(mac)
            # If that key does not exist, raise Value Error
            except KeyError:
                raise ValueError("That MAC address was not in the current list")
        # If mac not valid MAC, raise Value Error
        else:
            raise ValueError("Provided MAC address is not valid")
    
    def remove_queue(self, mac, queue):
        """
        Removes queue from list of queues associated to provided mac in
        self.queue_mappings. 
        Result is frames with that destination MAC is no longer sent to that
        queue

        :param mac: MAC address to remove queue from
        :type mac: String
        :param queue: Asyncio.queue object to remove
        :type queue: Asyncio.queue
        :raise ValueError: If MAC not valid or if MAC not currently in \
            self.queue_mappings
        """
        # Check if mac is valid
        mac = mac.upper()
        if helper.is_valid_mac(mac):
            queues = self.queue_mappings.get(mac)

            # Check if there is entry for that mac in self.queues_mapping
            if queues is None:
                raise ValueError("Provided MAC address is not in current list")
            else:
                # Try to remove the provided queue from the list of queues
                try:
                    queues.remove(queue)

                    # If we removed the last queue for that mac address, remove
                    # MAC in self.queues_mapping
                    if len(queues) == 0:
                        self.queue_mappings.pop(mac)

                # If this queue was not in list, raise ValueError
                except ValueError:
                    raise ValueError("This queue is not provided for that MAC")
        else:
            raise ValueError("Provided MAC address is not valid")

    def add_queue(self, mac, queue):
        """
        Adds queue from list of queues associated to provided mac in
        self.queue_mappings. 
        Result is frames with that destination MAC are now sent to this
        queue

        :param mac: MAC address to add queue to
        :type mac: String
        :param queue: Asyncio.queue object to add
        :type queue: Asyncio.queue
        """
        # Check if mac is valid
        mac = mac.upper()
        if helper.is_valid_mac(mac):
            queues = self.queue_mappings.get(mac)

            # Check if there is entry for that mac in self.queues_mapping
            if queues is None:
                queues[mac] = [queue]
            else:
                # Make sure queue not already in self.queue_mappings
                if queue not in queues:
                    queues.append(queue)
        else:
            raise ValueError("Provided MAC address is not valid")
