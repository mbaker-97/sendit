#!/usr/bin/python3
"""Set of classes that creates abstraction for dealing with raw_sockets"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from socket import *
import asyncio
class Raw_NIC(socket):
    """
    Child Class of Socket
    Creates Raw Socket, binds to provided interface
    Implements send method that works with rest of library

    :param interface: string name of network interface \
        ex: eth0, wlan0. Not sure? Call ifconfig and look at interface names
    :type interface: String
    """

    def __init__(self, interface):
        """Inits Raw_NIC as raw Socket bound to interface"""
        super().__init__(AF_PACKET, SOCK_RAW, htons(3))
        super().bind((interface, 0))

    def send(self, frame):
        """
        Overrides Socket send method
        Attempts to use as_bytes() method that is provided by all protocol classes in this library
        If not a class in this libary, calls str.encode on provided frame
        Them sends on raw socket

        :param frame: frame to send on Raw_NIC
        :type frame: L2 object that has as_bytes function, such as Etherframe
        """

        try:
            payload_bytes = frame.as_bytes()
        except AttributeError:
            payload_bytes = str.encode(frame)

        super().send(payload_bytes)


#  TODO rewrite send async
class Async_Raw_NIC(socket):
    """
    Child Class of Socket
    Creates Asynchronous Raw Socket, binds to provided interface
    Implements send method that works with rest of library

    :param interface: string name of network interface \
        ex: eth0, wlan0. Not sure? Call ifconfig and look at interface names
    :type interface: String
    """

    def __init__(self, interface):
        """Inits Raw_NIC as raw Socket bound to interface"""
        super().__init__(AF_PACKET, SOCK_RAW, htons(3))
        super().bind((interface, 0))
        # Add for async:
        super.setblocking(False)

    def send(self, frame, n_bytes):
        """
        Overrides Socket send method
        Attempts to use as_bytes() method that is provided by all protocol classes in this library
        If not a class in this libary, calls str.encode on provided frame
        Them sends on raw socket

        :param frame: frame to send on Raw_NIC
        :type frame: L2 object that has as_bytes function, such as Etherframe
        """

        try:
            payload_bytes = frame.as_bytes()
        except AttributeError:
          payload_bytes = str.encode(frame)

        super().send(payload_bytes)

    async def recv(self, n_bytes, queues = None):
        """
        Asynchronously receive bytes
        
        :param queues: queues to send raw bytes to 
        :type queue: asyncio.queue
        :param n_bytes: Number of bytes to receive
        :type n_bytes: int
        """
        loop = asyncio.get_event_loop()

        while True:
            byte = await loop.sock_recv(this, n_bytes)
            if queues is not None:
                for queue in queues:
                    await queue.put(byte)


