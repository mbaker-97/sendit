#!/usr/bin/python3
""" Creates Listener Class """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.7"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.protocols.etherframe import EtherFrame
import asyncio

class Listener():
    """
    Creates Listener Class. This will serve as parent class to all other listeners

    :param send_queue: asyncio.Queue to put frames to be sent in, defaults to None
    :type send_queue: asyncio.Queue
    :param incoming_higher_queue: asyncio.Queue that will receive frames from \
        higher layers that require computation at current layer to be ready to \
        sent. Will then be passed to send_queue, which will be the lower layer's
        incoming_higher_queue
    :type incoming_higher_queue: asyncio.Queue
    """

    def __init__(self, send_queue = None, incoming_higher_queue= None): 
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
        
