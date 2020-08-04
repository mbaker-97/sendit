#!/usr/bin/python3
""" Creates class that listens and responds to Layer 3 IPv4"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.ipv4 import IPv4
from collections import defaultdict


class IPv4_Listener():
    """ 
    :param ips: list of ips to listen for
    :type ips: list of Strings
    :param listeners: dictionary mapping list of upper layer listeners to IPv4 \
            addresses to forward frames to, defaults to None
    :type listeners: dictionary where keys are strings of IPv4 addresses, \
            values are Layer 4 protocol listener objects
    """
    def __init__(self, ips, listeners=None):
        """
        Constructor for IPv6_listener
        """
        for ip in ips:
            try:
                ip_address(ip)
            except AddressValueError:
                raise ValueError("All keys of mapping dictionary must be valid IPv4 addresses")
        self.ips = ips
        self.listeners = listeners
        # This dictionary will map a list of pieces of data to a IP_PacketID
        self.frag_data = defaultdict(lambda: [0] * 30000)

        # This dictionary will map a list of holes in data to a IP_PacketID
        self.frag_holes = defaultdict(lambda: [(0, 30000)])

    

    def ip_fragmentation_handler(self, frame):
        """
        Piece back together fragmented packets
        This is a modified version of the algorithm defined in RFC 815
        https://tools.ietf.org/html/rfc815
        :param frame: ethernet frame that contains fragmented packet
        :type frame: EtherFrame
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



    # TODO - add in L4 handlers
    def listen(self, queue):
        """
        Listens for frames coming in from queue, placed there by a Layer2 Listener
        If incoming frame contains IPv4 address destination contained in self.ips
        they are then passed to their respective higher level listeners
        Otherwise, they are discarded
        If frames come in with IPv4 fragmented, they are sent to ip_fragmentation_handler
        to be handled
        :param queue: Queue object to listen for incoming frames on
        :type queue: Queue object
        """
        while True:
            frame = queue.get()
            frame.payload = IPv4.ipv4_parser(frame.payload, recursive=False)
            # Check if the destination is an IP we are looking for
            if frame.payload.dst in self.ips:
                # Check if this packet is fragmented
                if frame.payload.mf or frame.payload.offset != 0:
                    # Returns only when packet completely pieced back together
                    frame  = self.ip_fragmentation_handler(frame)
                print(frame.payload)
                            

