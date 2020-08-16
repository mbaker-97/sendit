#!/usr/bin/python3
""" Creates class that listens and responds to Layer 3 IPv4"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.7"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.ipv4 import IPv4
from collections import defaultdict
from sendit.handlers.listener import Listener

# TODO - keep track of last sequence number.... 
class IPv4_Listener(Listener):
    """ 
    IPv4 Listener that is child class of Listener
    :param mappings: dictionary mapping MAC addresses to IPv4 addressses \ 
        defaults to None. 
    :type mappings: dictionary with String keys and values, defaults to None
    :param send_queue: asyncio.Queue that will be used to put frames in to send
    :type send_queue: asyncio.Queue
    :param incoming_higher_queue: asyncio.Queue that will receive frames from \
        higher layers that require computation at current layer to be ready to \
        sent. Will then be passed to send_queue, which will be the lower layer's
        incoming_higher_queue
    :type incoming_higher_queue: asyncio.Queue
    """
    def __init__(self, queue_mappings=None, send_queue = None, incoming_higher_queue = None):
        """
        Constructor for IPv6_listener
        """
        if queue_mappings is not None:
            for ip in queue_mappings.keys():
                try:
                    ip_address(ip)
                except AddressValueError:
                    raise ValueError("All keys of mapping dictionary must be valid IPv4 addresses")

        super().__init__(send_queue=send_queue, incoming_higher_queue = None)
        self.queue_mappings = queue_mappings

        # This dictionary will map a list of pieces of data to a IP_PacketID
        self.frag_data = defaultdict(lambda: [0] * 100000)

        # This dictionary will map a list of holes in data to a IP_PacketID
        self.frag_holes = defaultdict(lambda: [(0, 100000)])

    

    def ip_fragmentation_handler(self, frame):
        """
        This pieces back together fragmented packets. \
        This is a modified version of the algorithm defined in RFC 815 \
        https://tools.ietf.org/html/rfc815

        :param frame: ethernet frame that contains fragmented packet
        :type frame: EtherFrame
        :return: returns None if packet not completely defragmented, or IPv4 of\
            defragged packet
        :rtype:: IPv4 or None
        """
        entry_name =str(frame.payload.src) + "_" +  str(frame.payload.dst) + "_" + str(frame.payload.protocol) + "_" + str(frame.payload.id)
        
        # If entry does not exist, we default to holes being list containing tuple of 0 to large number
        # and data being a long list of all 0s
        holes = self.frag_holes[entry_name]
        data = self.frag_data[entry_name]

        frag_first = frame.payload.offset
        frag_last = (frame.payload.offset + frame.payload.length + frame.payload.ihl * 4) - 1


        # Step 1 of Algorithm - go through holes
        for hole in holes:

            hole_first, hole_last  = hole[0], hole[1]
            # Steps 2 and 3, see if this fragment fits in this hole
            if frag_first > hole_last or frag_last < hole_first: 
                continue
            else:
                # Step 4
                holes.remove(hole)

                # Step 5
                if frag_first > hole_first:
                    holes.append((hole_first, frag_first - 1))

                # Step 6
                if frag_last < hole_last and frame.payload.mf:
                    holes.append((frag_last + 1, hole_last))
                # Not in algorithm, used to determine length of finished packet
                else:
                    data[-1] = frag_last
                # Step 7
                # Place Data in buffer and implicit continue
                data[frag_first:frag_last] = frame.payload.payload

        # Step 8
        # Packet is compete
        if len(holes) == 0:

            # Set IPv4 payload of received frame to defragged packet
            # Since we are storing the length of defragged packet in the last
            # space in buffer, we reference that below
            frame.payload.payload = data[:data[-1]]
            frame.payload.reset_calculated_fields()
            # Set IPv4 length to length of completed packet plus length of header
            frame.payload.length = data[-1] + frame.payload.ihl * 4
            self.frag_data.pop(entry_name)
            self.frag_holes.pop(entry_name)
            return frame
        else:
            return None


    async def listen(self):
        """
        Listens for frames coming in from queue, placed there by a Layer2 Listener
        If incoming frame contains IPv4 address destination contained in self.ips
        they are then passed to their respective higher level listeners
        Otherwise, they are discarded
        If frames come in with IPv4 fragmented, they are sent to ip_fragmentation_handler
        to be handled

        """
        mappings = self.queue_mappings
        while True:
            frame = await self.recv_queue.get()
            frame.payload = IPv4.ipv4_parser(frame.payload, recursive=False)
            if frame.payload.mf or frane.payload.offset !=0:
                frame.payload = self.ip_fragmentation_handler(frame.payload, recursive)

            if mappings is not None and frame.payload is not None:
                # Check if there is an entry in self.queue_mappings for l4 protocol
                queues = mappings.get(frame.payload.protocol.lower())
                if queues is not None:
                    for queue in queues:
                        await queue.put(frame)

    async def await_from_higher(self):
        """
        Wait for frames from higher layers that needs IPv4 header adjusted
        Swaps src and destination and resets length and checksum
        """

        frame = await self.incoming_higher_queue.get()
        # Swap source and destination
        frame.payload.dst, frame.payload.src = frame.payload.src, frame.payload.dst
        # Reset length and checksum fields so that they will be calculated when sent
        frame.payload.reset_calculated_fields()
        await self.send_queue.put(frame)

