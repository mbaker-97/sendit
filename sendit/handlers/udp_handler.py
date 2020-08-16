"""  Creates class that listens and responds to Layer 4 UDP """
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.7"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.udp import UDP
from sendit.handlers.listener import Listener



class UDP_Listener(Listener):

    """
    :param ports: - list of ports to listen on
    :type ports: list of ints
    :param incoming_higher_queue: asyncio.Queue that will receive frames from \
        higher layers that require computation at current layer to be ready to \
        sent. Will then be passed to send_queue, which will be the lower layer's
        incoming_higher_queue
    :type incoming_higher_queue: asyncio.Queue
    """

    # TODO - provide ability to have range of ports
    def __init__(self, ports, send_queues = None, incoming_higher_queue = None):
        """
        Constructor for UDP_Listener
        """
        self.ports = ports
        super().__init__(send_queue=send_queue, incoming_higher_queue = incoming_higher_queue)

    async def listen(self, queue):
        """
        Listen for frames coming in on queue to parse the UDP objects inside

        :param queue: Queue to listen in on
        :type queue: Queue object
        """
        while True:
            frame = await self.recv_queue.get()
            frame.payload.payload = UDP.udp_parser(frame.payload.payload, recursive=False)

            if frame.payload.payload.dst_prt in ports:
                print(frame.payload.payload.payload)

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
