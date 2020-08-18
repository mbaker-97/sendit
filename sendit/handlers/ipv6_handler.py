#!/usr/bin/python3
""" Creates class that listens and responds to Layer 3 IPv6"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.ipv6 import IPv6
from sendit.handlers.handler import Handler
class IPv6_Handler(Handler):
    """
    IPv6 Handler that is child class of Handler

    :param send_up: asyncio.Queue OR dictionary of queues to put items in to go to higher layers
    :type send_up: asyncio.Queue or dictionary of asyncio.queues
    :param send_down : asyncio.Queue to put items in to go to lower layers
    :type send_down: asyncio.Queue
    :param recv_up: asyncio.Queue to receive items from higher layers
    :type recv_up: asyncio.Queue
    :param recv_down: asyncio.Queue to receive items from lower layers
    :type recv_down: asyncio.Queue
    """
    def __init__(self, send_up=None, send_down=None, recv_up=None, recv_down=None): 
        """
        Constructor for IPv6_Handler
        """
        #  if queue_mappings is not None:
            #  for ip in queue_mappings:
                #  print(ip)
                #  try:
                    #  ip_address(ip)
                #  except AddressValueError:
                    #  raise ValueError("All keys of mapping dictionary must be valid IPv4 addresses")
        super().__init__(send_up=send_up, send_down=send_down, recv_up=recv_up, recv_down=recv_down)

    async def listen(self):
        """
        Listen for frames coming in on queue to parse the IPv6 objects inside
        Asynchronous
        """
        mappings = self.send_up
        recv_queue = self.recv_down
        while True:
            frame = await recv_queue.get()
            frame.payload = IPv6.ipv6_parser(frame.payload, recursive=False)
            print(frame.payload)
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
