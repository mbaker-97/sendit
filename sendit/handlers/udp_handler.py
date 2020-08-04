"""  Creates class that listens and responds to Layer 4 UDP """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.udp import UDP
class UDP_Listener():

    """
    :param ports: - list of ports to listen on
    :param listeners: default of None, dictionary mapping list of upper \
        layer listeners to UDP to forward frames to
    """

    def __init__(self, ports, listeners=None):
        """
        Constructor for UDP_Listener
        """
        self.ports = ports
        self.listeners = listeners

    def listen(self, queue):
        """
        Listen for frames coming in on queue to parse the UDP objects inside
        :param queue: Queue to listen in on
        :type queue: Queue object
        """
        while True:
            frame = queue.get()
            frame.payload.payload = UDP.udp_parser(frame.payload.payload, recursive=False)

            if frame.payload.payload.dst_prt in ports:
                print(frame.payload.payload.payload)


