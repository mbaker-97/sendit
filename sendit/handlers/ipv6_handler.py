#!/usr/bin/python3
""" Creates class that listens and responds to Layer 3 IPv6"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.ipv6 import IPv6
class IPv6_Listener():
    """
    :param ips: list of IPs to listen for
    :type ips: List of Strings
    :param listeners: dictionary mapping list of upper layer listeners to IPv6 \
            addresses to forward frames to, defaults to None
    :type listeners: dictionary with keys of String IPv6 addresses and values \
            are upper layer listeners
    """
    def __init__(self, ips, listeners=None):
        """
        Constructor for IPv6_listener
        """
        for ip in ips:
            print(ip)
            try:
                ip_address(ip)
            except AddressValueError:
                raise ValueError("All keys of mapping dictionary must be valid IPv4 addresses")
        self.ips = ips
        self.listeners = listeners

    def listen(self, queue):
        """
        Listen for frames coming in on queue to parse the IPv6 objects inside
        :param queue: Queue to listen in on
        :type queue: Queue object
        """
        while True:
            frame = queue.get()
            frame.payload = IPv6.ipv6_parser(frame.payload, recursive=False)
            if frame.payload.dst  in self.ips:
                print(frame.payload)


