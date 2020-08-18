#!/usr/bin/python3
""" Creates class that listens and responds to Layer 3 IPv4"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.ipv4 import IPv4
from collections import defaultdict
from sendit.handlers.handler import Handler

# TODO - keep track of last sequence number.... 
class IPv4_Handler(Handler):
    """ 
    IPv4 Handler that is child class of Handler

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
        """
        Constructor for IPv4_Handler
        """
        #TODO Value check send_up

        super().__init__(send_down=send_down, send_up=send_up, recv_up=recv_up, recv_down=recv_down)

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
        packet = frame.payload
        entry_name =str(packet.src) + "_" +  str(packet.dst) + "_" + str(packet.protocol) + "_" + str(packet.id)
        
        # If entry does not exist, we default to holes being list containing tuple of 0 to large number
        # and data being a long list of all 0s
        holes = self.frag_holes[entry_name]
        data = self.frag_data[entry_name]

        frag_first = packet.offset
        frag_last = (packet.offset + packet.length + packet.ihl * 4) - 1


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
                if frag_last < hole_last and packet.mf:
                    holes.append((frag_last + 1, hole_last))
                # Not in algorithm, used to determine length of finished packet
                else:
                    data[-1] = frag_last
                # Step 7
                # Place Data in buffer and implicit continue
                data[frag_first:frag_last] = packet.payload

        # Step 8
        # Packet is compete
        if len(holes) == 0:

            # Set IPv4 payload of received frame to defragged packet
            # Since we are storing the length of defragged packet in the last
            # space in buffer, we reference that below
            packet.payload = data[:data[-1]]
            packet.reset_calculated_fields()
            # Set IPv4 length to length of completed packet plus length of header
            packet.length = data[-1] + packet.ihl * 4
            self.frag_data.pop(entry_name)
            self.frag_holes.pop(entry_name)
            return frame
        else:
            return None


    async def listen(self):
        """
        Listens for frames coming in from queue, placed there by a Layer2 Handler
        If incoming frame contains IPv4 address destination contained in self.ips
        they are then passed to their respective higher level listeners
        Otherwise, they are discarded
        If frames come in with IPv4 fragmented, they are sent to ip_fragmentation_handler
        to be handled

        """
        mappings = self.send_up
        recv_down = self.recv_down
        while True:
            frame = await recv_down.get()
            frame.payload = IPv4.ipv4_parser(frame.payload, recursive=False)
            packet = frame.payload
            print(packet)
            if packet.mf or packet.offset !=0:
                frame = self.ip_fragmentation_handler(frame)

            if mappings is not None and frame is not None:
                packet = frame.payload
                # Check if there is an entry in self.queue_mappings for l4 protocol
                queues = mappings.get(packet.dst + "_" + packet.protocol.lower())
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

