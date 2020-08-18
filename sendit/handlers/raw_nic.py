#!/usr/bin/python3
"""Set of classes that creates abstraction for dealing with raw_sockets"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from socket import *
import asyncio
from sendit.handlers.handler import Handler
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


class Async_Raw_NIC(Handler):
    """
    Child Class of Handler
    Creates Asynchronous Raw Socket, binds to provided interface
    Implements send method that works with rest of library

    :param interface: string name of network interface \
        ex: eth0, wlan0. Not sure? Call ifconfig and look at interface names
    :type interface: String
    :param queue: asyncio queue to send raw bytes too
    :type queue: asyncio.Queue
    :param queue: asyncio queue to receive outgoing bytes from
    :type queue: asyncio.Queue
    """

    def __init__(self, interface, send_up=None, recv_up=None):
        """Inits Raw_NIC as raw Socket bound to interface"""
        super().__init__(send_up=send_up, recv_up=recv_up)

        self.sock = socket(AF_PACKET, SOCK_RAW, htons(3))
        self.sock.bind((interface, 0))
        # Add for async:
        self.sock.setblocking(False)
        self.send_up = send_up
        self.recv_up = recv_up
        


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

        self.sock.send(payload_bytes)

    async def a_recv(self, n_bytes):
        """
        Asynchronously receive bytes
        
        :param n_bytes: Number of bytes to receive
        :type n_bytes: int
        """
        loop = asyncio.get_event_loop()

        while True:
            byte = await loop.sock_recv(self.sock, n_bytes)
            # Pass on bytes to queue that belongs to bytes_listener
            await self.send_up.put(byte)

    async def sendall_from_queue(self):

        #TODO 
        # Assert that self.incoming_higher_queue  is not None
        # Otherwise raise Assertion Error
        while True:
            payload_bytes = await self.incoming_higher_queue.get()
            await loop.sock_sendall(self.sock, payload_bytes)

