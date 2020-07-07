# Class that extends Socket, creating a raw socket 
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from socket import *
class Raw_NIC(socket):
    """
    Child Class of Socket
    Creates Raw Socket, binds to provided interface
    Implements send method that works with rest of library

    :param interface: string name of network interface
    ex: eth0, wlan0. Not sure? Call ifconfig and look at interface names
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
        """

        # try:
        payload_bytes = frame.as_bytes()
        # except AttributeError:
        #    payload_bytes = str.encode(frame)

        super().send(payload_bytes)

