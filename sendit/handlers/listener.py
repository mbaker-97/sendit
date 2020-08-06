#!/usr/bin/python3
""" Creates Listener Class """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.protocols.etherframe import EtherFrame
import asyncio

class Listener():
    """
    Creates Listener Class. This will serve as parent class to all other listeners

    :param send_queue: asyncio.Queue to put frames to be sent in, defaults to None
    """

    def __init__(self, send_queue = None): 
        """Constructor for Listener"""
        # this creates queue to listen on
        self.send_queue = send_queue
        self.recv_queue = asyncio.Queue()

    async def listen(self):
        """
        Placeholder for listen coroutine
        """
        while True:
            await asyncio.sleep(1)

    async def send(self, frame):
        """
        Puts frame into self.send_queue

        :param frame: frame to send
        :type frame: EtherFrame
        """
        await self.send_queue.put(frame)
        
