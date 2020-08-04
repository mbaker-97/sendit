"""Creates IPv4 object and provides methods to parse bytes to IPv4 create bytes
to IPv4 object"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from socket import inet_aton, inet_ntoa
from sendit.protocols.tcp import TCP
from sendit.protocols.udp import UDP
from sendit.helper_functions.helper import *
class IPv4:
    """
    Creates IPv4 object from parameters
    :param src: source IP address
    :type src: String
    :param dst: destination IP address
    :type dst: String
    :param payload: payload of the packet 
    :type payload: TCP or UDP objects of String
    :param id: identification number of packet, defaults to 0
    :type id: int
    :param length:total  length of IP packet in bytes - header + data together.\
            ,defaults to 0, calculated when as_bytes called. If IPv4 object \
            created from parser function, takes value of captured IPv4 packet,\
                   and NOT calculated in as_bytes unless reset to 0 manually \
                   with reset_calculated_fields
    :type length: int
    :param df: do not fragment flag, default to False
    :type df: Boolean
    :param mf: more fragments flag - deafult to False
    :type mf: Boolean
    :param offset: frag offset of packet, default to 0
    :type offset: int
    :param ttl: time to live, default to 64
    :type ttl: int
    :param protocol: string name of protocol carried in packet.currently \
            supported values: "tcp", "udp", "icmp", custom int value accepted \
            IF valid
    :type protocol: String or int
    :param dscp: differentiated services value - default of 0
    :type dscp: int
    :param ecn: explicit congestion notification - default of 0
    :type ecn: int
    :param version: version of IP
    :type version: int
    :param checksum: checksum of packet. By default, not calculated and set to \
            0 and to be calculated when as_bytes called. Set when IPv4 object \
            created from parser function, and unless reset manually or with \
            reset_calculated_fields function, will NOT be recalculated when \
            as_bytes is called
    :type checksum: int
    """

    def __init__(self, src, dst, payload, id=0, length=0, df=False, mf=False, offset=0, ttl=64, protocol="tcp", dscp=0,
                 ecn=0, version=4, checksum=0):
        """init for IPv4"""
        if ttl > 255 or ttl < 0:
            raise ValueError("ttl should be value between 0 and 255 inclusive")

        self.version = version
        # How many 32 bit words in header - currently options at end of header not supported
        self.ihl = 5
        self.dscp = dscp
        self.ecn = ecn
        self.length = length

        self.id = id
        self.df = df
        self.mf = mf
        self.ttl = ttl
        self.offset = offset
        self.protocol = protocol

        self.src = src
        self.dst = dst
        self.payload = payload

        self.checksum = checksum

    def as_bytes(self):
        """
        Converts IPv4 to proper format of payload bytes to send set as EtherFrame payload
        If self.payload is TCP or UDP object, their as_bytes function is called, providing the conversion of payload
        to properly formated bytes to be inserted into packet
        If self.payload is not TCP or UDP object, self.payload is converted to bytes with str.encode(self.payload) if
        possible. Otherwise, it is assumed payload is already bytes
        :return: bytes representation of IPv4 Packet
        :rtype: Bytes
        """
        first_byte = int(bin(self.version)[2:].zfill(4) + bin(self.ihl)[2:].zfill(4), 2)
        second_byte = int(bin(self.dscp)[2:].zfill(6) + bin(self.ecn)[2:].zfill(2), 2)

        # Set flags
        flags = 0
        if self.df:
            flags += 2
        if self.mf:
            flags += 1

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

        # Total length of packet, header included
        # Check if length explicitly set, if not, will be calculated
        if self.length == 0:
            try:
                self.length = len(payload.as_bytes()) + self.ihl * 4
            except AttributeError:
                self.length = len(payload) + self.ihl * 4

        frag_bytes = int(bin(flags)[2:].zfill(3) + bin(self.offset/8)[2:].zfill(13), 2)
        protocol = protocols_to_int.get(str(self.protocol).lower())

        # Until time for error handling, trust users custom input
        if protocol is None:
            protocol = self.protocol

        # Convert IPv4 addresses
        src = inet_aton(self.src)
        dst = inet_aton(self.dst)

        # Calculate Checksum if not manually set
        if self.checksum == 0:
            self.checksum = checksum(pack('!BBHHHBB', first_byte, second_byte, self.length, self.id, frag_bytes,
                                                 self.ttl, protocol) + src + dst)
        return pack('!BBHHHBBH', first_byte, second_byte, self.length, self.id, frag_bytes, self.ttl, protocol,
                           self.checksum) + src + dst + payload

    def parse_further_layers(self, recursive = True):
        """
        Method that parses higher layers
        :param recursive: Whether parsing function should be called recursively\
            through all layers, defaults to True
        type recursive: Boolean
        """
        if self.protocol == "udp":
            self.payload = UDP.udp_parser(self.payload, recursive)
        elif self.protocol == "tcp":
            self.payload = TCP.tcp_parser(self.payload, recursive)
        else:
            try:
                self.payload = self.payload.decode("ascii")
            except UnicodeDecodeError:
                pass

    @classmethod
    def ipv4_parser(cls, data, recursive=True):
        """
        Class Method that parses group of bytes to create IPv4 Object
        :param recursive: boolean of whether to parse recursively to higher \
        layers, defaults to True \
        If protocol is "TCP", payload will be TCP object created \
        If protocol is "UDP", payload will be UDP object created \
        :type recursive: Boolean
        :return: IPv4 instance that contains the values that was in data
        :rtype: IPv4 object
        """
        version = int.from_bytes(data[0:1], 'big') >> 4
        ihl = int.from_bytes(data[0:1], 'big') % 64
        dscp = int.from_bytes(data[1:2], 'big') >> 5
        ecn = int.from_bytes(data[1:2], 'big') % 4
        length = int.from_bytes(data[2:4], 'big')
        id = int.from_bytes(data[4:6], 'big')
        df = int.from_bytes(data[6:7], 'big') >> 6
        mf = (int.from_bytes(data[6:7], 'big') >> 5) % 2
        offset = (int.from_bytes(data[6:8], 'big') % 8192) * 8
        ttl = int.from_bytes(data[8:9], 'big')

        protocol_num = int.from_bytes(data[9:10], 'big')
        protocol = int_to_protocol.get(protocol_num)

        # If protocol not currently defined in class
        if protocol is None:
            protocol = protocol_num

        checksum = int.from_bytes(data[10:12], 'big')
        src = inet_ntoa(data[12:16])
        dst = inet_ntoa(data[16:20])
        if df == 1:
            df_bool = True
        else:
            df_bool = False

        if mf == 1:
            mf_bool = True
        else:
            mf_bool = False

        returnable = IPv4(src, dst, data[20:], id=id, df=df_bool, mf=mf_bool, offset=offset, ttl=ttl, protocol=protocol,
                          length=length, dscp=dscp, ecn=ecn, version=version, checksum=checksum)

        if recursive:
            returnable.parse_further_layers()

        returnable.ihl = ihl

        return returnable
    
    def reset_calculated_fields(self):
        """
        Resets calculated fields for IPv4 - resets length and checksum
        """
        self.checksum = 0
        self.length = 0

    def __str__(self):
        """
        Create string representation of IPv4 object
        :return: String of IPv4
        :rtype: String
        """
        header = "*" * 20 + "_IPv4_" + "*" * 20
        source = "Source Address: " + self.src
        dest = "Destination Address: " + self.dst
        length = "Length: " + str(self.length) + " bytes"
        protocol = "Protocol: " + str(self.protocol)
        ttl = "TTL: " + str(self.ttl)
        flags = "Flags: Don't Fragment: " + str(self.df) + " More Fragments: " + str(self.mf)
        offset = "Fragment Offset: " + str(self.offset) + " bytes"
        ident = "ID: " + str(self.id)
        ecn = "Explicit Congestion Notification: " + str(self.ecn)
        if self.ecn == 0:
            ecn = " ".join((ecn,("(Non-ECN Capable)")))
        if self.ecn == 1 or self.ecn == 2 :
            ecn = " ".join((ecn,("(ECN Capable)")))
        if self.ecn == 3:
            ecn = " ".join((ecn,("(Congestion Encountered)")))
        differ = "Differentiated Services: " + hex(self.df)[2:]
        hl = "Header length: " + str(self.ihl)
        checksum = "Checksum: " + hex(self.checksum)[2:]
        version = "Version: "  + str(self.version)
        trailer = "*" * 46
        return "\n".join((header, source, dest, length, protocol, ttl, flags,
                          offset, ident, ecn, differ, checksum,  hl, version, trailer))



