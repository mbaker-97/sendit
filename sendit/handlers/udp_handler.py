"""  Creates class that listens and responds to Layer 4 UDP """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.udp import UDP
from sendit.handlers.handler import Handler



class UDP_Handler(Handler):

    """
    :param ports: - list of ports to listen on
    :type ports: list of ints

    :param send_up: asyncio.Queue OR dictionary of queues to put items in to go to higher layers
    :type send_up: asyncio.Queue or dictionary of asyncio.queues
    :param send_down : asyncio.Queue to put items in to go to lower layers
    :type send_down: asyncio.Queue
    :param recv_up: asyncio.Queue to receive items from higher layers
    :type recv_up: asyncio.Queue
    :param recv_down: asyncio.Queue to receive items from lower layers
    :type recv_down: asyncio.Queue
    """

    # TODO - provide ability to have range of ports
    def __init__(self, ports, send_up=None, send_down=None, recv_up=None, recv_down=None):
        """
        Constructor for UDP_Handler
        """
        self.ports = ports
        super().__init__(send_up=send_up, send_down=send_down, recv_up=recv_up, recv_down=recv_down)

    async def listen(self):
        """
        Listen for frames coming in on queue to parse the UDP objects inside

        :param queue: Queue to listen in on
        :type queue: Queue object
        """
        recv_queue = self.recv_down
        while True:
            frame = await recv_queue.get()
            segment = frame.payload.payload 
            segment = UDP.udp_parser(segment, recursive=False)
            print(segment)

            if segment.dst_prt in self.ports:
                pass

    async def await_from_higher(self):
        """
        Wait for frames from higher layers that needs UDP header adjusted
        Swaps src and destination ports and ips (for checksum) \
                and resets length and checksum
        """

        frame = await self.incoming_higher_queue.get()
        # Swap source and destination
        frame.payload.payload.payload.dst_prt, frame.payload.payload.src_prt = frame.payload.payload.src_prt, frame.payload.payload.dst_prt
        frame.payload.payload.payload.dst_ip, frame.payload.payload.src_ip = frame.payload.payload.src_ip, frame.payload.payload.dst_ip
        # Reset length and checksum fields so that they will be calculated when sent
        frame.payload.payload.reset_calculated_fields()
        await self.send_queue.put(frame)
