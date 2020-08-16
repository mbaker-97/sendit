#!/usr/bin/python3
""" Creates class that listens and responds to Layer 3 IPv6"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.7"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.ipv6 import IPv6
from sendit.handlers.listener import Listener
class IPv6_Listener(Listener):
    """
    IPv6 Listener that is child class of Listener
    :param mappings: dictionary mapping MAC addresses to IPv6 addressses \ 
        defaults to None
    :type mappings: dictionary with String keys and values, defaults to None
    :param send_queue: asyncio.Queue that will be used to put frames in to send
    :type send_queue: asyncio.Queue
    :param incoming_higher_queue: asyncio.Queue that will receive frames from \
        higher layers that require computation at current layer to be ready to \
        sent. Will then be passed to send_queue, which will be the lower layer's
        incoming_higher_queue
    :type incoming_higher_queue: asyncio.Queue
    """
    def __init__(self, queue_mappings=None, send_queue = None, incoming_higher_queue = None):
        """
        Constructor for IPv6_listener
        """
        if queue_mappings is not None:
            for ip in queue_mappings:
                print(ip)
                try:
                    ip_address(ip)
                except AddressValueError:
                    raise ValueError("All keys of mapping dictionary must be valid IPv4 addresses")
        super().__init__(send_queue=send_queue, incoming_higher_queue = incoming_higher_queue)
        self.queue_mappings = queue_mappings

    async def listen(self):
        """
        Listen for frames coming in on queue to parse the IPv6 objects inside
        Asynchronous
        """
        mappings = self.queue_mappings
        while True:
            frame = await self.recv_queue.get()
            frame.payload = IPv6.ipv6_parser(frame.payload, recursive=False)
            if mappings is not None:
                # Check if there is an entry in self.queue_mappings for l4 protocol
                queues = mappings.get(frame.payload.protocol.lower())
                if queues is not None:
                    for queue in queues:
                        await queue.put(frame)

    async def await_from_higher(self):
        """
        Wait for frames from higher layers that needs IPv6 header adjusted
        Swaps src and destination and resets length and checksum
        """

        frame = await self.incoming_higher_queue.get()
        # Swap source and destination
        frame.payload.dst, frame.payload.src = frame.payload.src, frame.payload.dst
        # Reset length and checksum fields so that they will be calculated when sent
        frame.payload.reset_calculated_fields()
        await self.send_queue.put(frame)
