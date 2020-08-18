#!/usr/bin/python3
""" Creates class that listens and responds to ARP messages"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.handlers.handler import Handler
from sendit.protocols.arp import ARP
from sendit.protocols.etherframe import EtherFrame
from sendit.helper_functions.helper import is_valid_MAC
from ipaddress import ip_address, AddressValueError

class ARP_Handler(Handler):
    
    """
    Creates class that listens and responds to ARP messages. Child class of Handler

    :param reply: boolean of whether to answer ARP requests, defaults to True
    :type reply: Boolean
    :param mappings: dictionary mapping MAC addresses to IPv4 addressses \ 
        defaults to None. Required if reply is True
    :type mappings: dictionary with String keys and values, defaults to None
    :param send_queue: asyncio.Queue that will be used to put frames in to send
    :type send_queue: asyncio.Queue
    :raise ValueError: when reply is set to true but mappings is not defined \
        or when keys in mappings are not valid IPv4 addresses \
        or when values in mappings are not valid MAC addresses
    """

    def __init__(self, reply=True, mappings=None, send_down=None, recv_up=None):
        """Constructor for ARP_Handler"""
        super().__init__(send_down=send_down, recv_up=recv_up)
        if reply and mappings is None:
            raise ValueError("When reply is set  to True, mappings must be provided")
        if reply and send_queue is None:
            raise ValueError("When reply is set  to True, send_queue must be set")
        if mappings is not None:
            # Check that all keys of mappngs dictionary are valid IPv4 addresses
            for ip in mappings.keys():
                try:
                    ip_address(ip)
                except AddressValueError:
                    raise ValueError("All keys of mapping dictionary must be valid IPv4 addresses")
            
            #Check that all values in mappings dictionary are valid MAC addresses
            for mac in mappings.values():
                if not is_valid_MAC(mac):
                    raise ValueError("All values of mapping dictionary must be valid MAC addresses")

        self.reply = reply
        self.mappings = mappings

    async def listen(self):
        """
        listens and responds for ARP messages coming in on recv_queue, put there by
        an ethernet_handler

        """
        recv_queue = self.recv_up
        send_queue = self.send_down
        while True:
            frame = await recv_queue.get()
            arp = ARP.arp_parser(frame.payload)
            print(arp)
            if self.reply:
                mac = self.mappings.get(arp.tpa)
                if mac is not None and arp.op == 1:
                    reply = ARP(mac, arp.tpa, arp.sha, arp.spa, op=2)
                    frame.payload = reply
                    await self.send_queue.put(reply_frame)
            
