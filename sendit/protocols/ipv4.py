# Provide object of IPv4 protocol
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from socket import inet_aton, inet_ntoa
from sendit.protocols.tcp import TCP
from sendit.protocols.udp import UDP
from sendit.helper_functions.helper import checksum 
class IPv4:
    """
    Creates IPv4 object from parameters
    :param src: source IP address
    :param dst: destination IP address
    :param payload: payload of the packet - can be TCP or UDP objects, or a string
    :param id: identification number of packet - default of 0
    :param length: length of IP packet in bytes - header and data together. Default set to 0 and calculated when
                   as_bytes called. If IPv4 object created from parser function, takes value of captured IPv4 packet,
                   and NOT calculated in as_bytes unless reset to 0 manually of with reset_calculated_fields
    :param df: do not fragment flag - default of False
    :param mf: more fragments flag - deafult of False
    :param offset: frag offset of packet - default of 0
    :param ttl: time to live - default of 64
    :param protocol: string name of protocol carried in packet.
                     currently supported values: "tcp", "udp", "icmp", custom int value accepted IF valid
    :param dscp: differentiated services value - default of 0
    :param ecn: explicit congestion notification - default of 0
    :param version: version of IP
    :param checksum: checksum of packet. By default, not calculated and set to 0 and to be calculated when as_bytes
                     called. Set when IPv4 object created from parser function, and unless reset manually or with
                     reset_calculated_fields function, will NOT be recalculated when as_bytes is called
    """
    protocols_to_int = {"icmp": 1, "tcp": 6, "udp": 17}
    int_to_protocol = {1: "icmp", 6: "tcp", 17: "udp"}

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
        :return: - bytes representation of IPv4 Packet
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

        frag_bytes = int(bin(flags)[2:].zfill(3) + bin(self.offset)[2:].zfill(13), 2)
        protocol = IPv4.protocols_to_int.get(str(self.protocol).lower())

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

    @classmethod
    def ipv4_parser(cls, data, recursive=True):
        """
        Class Method that parses group of bytes to create IPv4 Object
        :param data: ipv4 packet passed in as bytes
        If protocol is "TCP", payload will be TCP object created
        If protocol is "UDP", payload will be UDP object created
        :return: IPv4 instance that contains the values that was in data
        """
        version = int.from_bytes(data[0:1], 'big') >> 4
        ihl = int.from_bytes(data[0:1], 'big') % 64
        dscp = int.from_bytes(data[1:2], 'big') >> 5
        ecn = int.from_bytes(data[1:2], 'big')
        length = int.from_bytes(data[2:4], 'big')
        id = int.from_bytes(data[4:6], 'big')
        df = int.from_bytes(data[6:7], 'big') >> 6
        mf = (int.from_bytes(data[6:7], 'big') >> 5) % 2
        offset = int.from_bytes(data[6:8], 'big') % 8092
        ttl = int.from_bytes(data[8:9], 'big')

        protocol_num = int.from_bytes(data[9:10], 'big')
        protocol = IPv4.int_to_protocol.get(protocol_num)

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
        if recursive:
            if protocol == "udp":
                payload = UDP.udp_parser(data[20:])
            elif protocol == "tcp":
                payload = TCP.tcp_parser(data[20:])
            else:
                try:
                     payload = data[20:].decode("ascii")
                except UnicodeDecodeError:
                    payload = data[20:]
        else:
            payload = data[20:]

        returnable = IPv4(src, dst, payload, id=id, df=df_bool, mf=mf_bool, offset=offset, ttl=ttl, protocol=protocol,
                          length=length, dscp=dscp, ecn=ecn, version=version, checksum=checksum)
        returnable.ihl = ihl
        return returnable

    def reset_calculated_fields(self):
        """
        Resets calculated fields for IPv4 - resets length and checksum
        """
        self.checksum = 0
        self.length = 0
