__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.5"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.ipv6 import IPv6
class IPv6_Listener():

    def __init__(self, ips, listeners=None):
        """
        Constructor for IPv6_listener
        :param ips: - list of ips to listen for
        :param listeners: default of None, dictionary mapping list of upper
        layer listeners to IPv6 addresses to forward frames to
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
        while True:
            frame = queue.get()
            frame.payload = IPv6.ipv6_parser(frame.payload, recursive=False)
            if frame.payload.dst  in self.ips:
                print(frame.payload)


