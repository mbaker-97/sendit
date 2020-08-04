"""Creates IPv6 object and provides methods to parse bytes to IPv6 and create 
bytes to IPv6 object"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from sendit.protocols.tcp import TCP
from sendit.protocols.udp import UDP
from ipaddress import *
from sendit.helper_functions.helper import *
class IPv6:
    """
    Creates IPv6 object from parameters
    :param src: source IPv6 address
    :type src: String
    :param dst: destination IPv6 address
    :type dst: String
    :param payload: payload to be encapsulated inside IPv6 packet
    :type payload: TCP or UDP object, or String
    :param next: next header protocol,  defaults to "tcp". "udp" and "icmp" \
            also supported
    :type next: String
    :param limit: hop count limit - 0 to 255 inclusive
    :type limit: int
    :param flow_label: label for which flow packet belongs to, defaults to 0 - \
            which is not flow
    :type flow_label: int
    :param ds: Differentiated Services field, defaults to 0
    :type ds: int
    :param ecn:  Explicit Congestion Notification value, defaults to 0
    :type ecn: int
    :param version: IP version, defaults to 6
    :type version: int
    :param length: length of IPv6 packet, defaults to 0 and calculated in \
            as_bytes function. If IPv6 object created with parser method, will \
            take value of IPv6 packet captured, and will NOT be calculated in \
            as_bytes unless reset manually to 0 or with reset_calculated_fields\
            function
    :type length: int
    """
    
    #TODO - do more value checking
    def __init__(self, src, dst, payload, next="tcp", limit=64, flow_label=0, ds=0, ecn=0, version=6, length=0):
        """init for IPv6"""
        # Check validity of addresses
        try:
            IPv6Address(src)
        except AddressValueError:
            raise ValueError("src must be valid IPv6 address")
        try:
            IPv6Address(dst)
        except AddressValueError:
            raise ValueError("dst must be valid IPv6 address")

        # Check validity of hop limit
        if limit > 255 or limit < 0:
            raise ValueError("limit should be value between 0 and 255 inclusive")

        # Check validity of ecn
        if ecn < 0 or ecn > 3:
            raise ValueError("ecn should be value between 0 and 3 inclusive")

        self.next = next

        self.src = src
        self.dst = dst
        self.limit = limit
        self.version = version
        self.ds = ds
        self.ecn = ecn
        self.flow_label = flow_label
        self.length = length
        self.payload = payload

    def as_bytes(self):
        """
        Converts IPv6 to proper format of payload bytes to send set as EtherFrame payload
        If self.payload is TCP or UDP object, their as_bytes function is called, providing the conversion of payload
        to properly formated bytes to be inserted into packet
        If self.payload is not TCP or UDP object, self.payload is converted to bytes with str.encode(self.payload)
        :return: bytes representation of IPv6 Packet
        :rtype: bytes
        """
        first_byte = ((self.version << 4) + (self.ds >> 2))
        second_byte = (((self.ds % 4) << 6) + (self.ecn << 4) + (self.flow_label >> 16))
        flow_label_bytes = (self.flow_label % 65536)

        # Convert payload
        # try to call as_bytes function for layer 4 - if protocol not supported, payload treated as ascii string.
        # If payload not string, it is assumed payload is already in bytes
        try:
            payload = self.payload.as_bytes()
        except AttributeError:
            try:
                payload = self.payload.encode()
            except AttributeError:
                payload = self.payload

        # Set total length of packet if not manually set
        if self.length == 0:
            self.length = len(payload)

        nxt = protocols_to_int.get(str(self.next).lower())

        # Until time for error handling, trust users custom input
        if nxt is None:
            nxt = self.next
        limit_bytes = self.limit.to_bytes(1, 'big')
        src_bytes = IPv6Address(self.src).packed
        dst_bytes = IPv6Address(self.dst).packed
        return pack('!BBHHBB', first_byte, second_byte, flow_label_bytes, self.length, nxt, self.limit) + \
               src_bytes + dst_bytes + payload

    def reset_calculated_fields(self):
        """
        Resets all calulated fields for IPv6 - resets length
        """
        self.length = 0

    @classmethod
    def ipv6_parser(cls, data, recursive=True):
        """
        Class Method that parses group of bytes to create IPv6 Object
        :param data: IPv6 packet passed in as bytes
        :type data: bytes
        If protocol is "TCP", payload will be TCP object created
        If protocol is "UDP", payload will be UDP object created
        :return: IPv6 instance that contains the values that was in data
        :rtype: IPv6 
        """
        version = int.from_bytes(data[0:1], 'big') >> 4
        traffic_class = int.from_bytes(data[0:2], 'big')
        ds = (traffic_class % 4096) >> 6
        ecn = (traffic_class % 64) >> 4
        flow_label = int.from_bytes(data[1:4], 'big') % 1048576
        length = int.from_bytes(data[4:6], 'big')
        next = int.from_bytes(data[6:7], 'big')
        limit = int.from_bytes(data[7:8], 'big')
        src = int.from_bytes(data[8:24], 'big')
        dst = int.from_bytes(data[24:40], 'big')

        protocol = int_to_protocol.get(next)

        # If protocol not currently defined in class
        if protocol is None:
            protocol = next


        returnable = IPv6(src, dst, data[40:], next=protocol, limit=limit, flow_label=flow_label, ds=ds, ecn=ecn,
                          version=version, length=length)
        
        if recursive:
            returnable.parse_further_layers()

        return returnable

    def parse_further_layers(self, recursive=True):
        """
        Method that parses higher layers
        :param recursive: boolean value of whether parsing funciton should
        :type return: Boolean
        be called recursively through all layers
        """

        if self.next == "udp":
            self.payload = UDP.udp_parser(self.payload, recursive)
        elif self.next == "tcp":
            self.payload = TCP.tcp_parser(self.payload, recursive)
        else:
            try:
                self.payload = self.payload.decode("ascii")
            except UnicodeDecodeError:
                pass 

    def __str__(self):
        """
        Create string representation of IPv6 object
        :return: String representation
        :rtype: String
        """
        header = "*" * 20 + "_IPv6_" + "*" * 20
        source = "Source Address: " + str(ip_address(self.src)).upper()
        dest = "Destination Address: " + str(ip_address(self.dst)).upper()
        length = "Payload Length: " + str(self.length) + " bytes"
        nxt = "Next Header: " + str(self.next).upper()
        limit = "Hop Limit: " + str(self.limit)
        label = "Flow Label: " + str(self.flow_label)
        differ = "Differentiated Services: " + hex(self.ds)[2:]
        ecn = "Explicit Congestion Notification: " + str(self.ecn)
        if self.ecn == 0:
            ecn = " ".join((ecn,("(Non-ECN Capable)")))
        if self.ecn == 1 or self.ecn == 2 :
            ecn = " ".join((ecn,("(ECN Capable)")))
        if self.ecn == 3:
            ecn = " ".join((ecn,("(Congestion Encountered)")))
        version = "Version: " + str(self.version)
        trailer = "*" * 46

        return "\n".join((header, source, dest, length, nxt, limit, label, differ, ecn, version, trailer))


