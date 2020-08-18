#!/usr/bin/python3
""" Creates Handler Class """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.protocols.etherframe import EtherFrame
import asyncio

class Handler():
    """
    Creates Handler Class. This will serve as parent class to all other handlers

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
        """Constructor for Listener"""
        self.send_up = send_up
        self.send_down = send_down
        self.recv_up = recv_up
        self.recv_down = recv_down

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
        
