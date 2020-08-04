"""Creates UDP object and provides methods to parse bytes to UDP create bytes
to UDP object"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from sendit.helper_functions.helper import checksum, form_pseudo_header
class UDP:
    """
    Creates UDP object from parameters
    UDP checksum is optional and therefore not currently supported
    
    :param src_prt: source port
    :type src_prt: int
    :param dst_prt: destination port
    :type dst_prt: int
    :param src_ip: source IP address - used for creating pseudoheader to \
        calculate checksum
    :type src_ip: String
    :param dst_ip: destination IP address - used for creating pseudoheader to \
        calculate checksum
    :type dst_ip: String
    :param version: version of IP being carried in - used for calculating \
        checksum
    :version type: int
    :param length: length of segment, defaults to 0, calculated when as_bytes \
        called if 0. If UDP object created from parser function, set to \
        length of captured segment and NOT recalculated in as_bytes unless \
        set to 0 manually or by calling reset_calculated_fields function
    :type length: int
    :param checksum: default set to 0 and calculated when as_bytes called if 0 \
        If UDP object created from parser function, set to checksum of \
        captured segment and NOT recalculated in as_bytes unless set to 0 \
        manually or by calling reset_calculated_fields function
    :type checksum: int
    :param payload: payload to be carried UDP
    :type payload: bytes

    :raise ValueError: if src_prt or dst_prt is between 0 and 65535 inclusive
    """

    def __init__(self, src_prt, dst_prt, src_ip, dst_ip, payload, version=4, length=0, checksum=0):

        if src_prt > 65535 or src_prt < 0:
            raise ValueError("src_prt must be valid UDP port")
        if dst_prt > 65535 or dst_prt < 0:
            raise ValueError("dst_prt must be valid UDP port")

        self.src_prt = src_prt
        self.dst_prt = dst_prt
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload
        self.length = length
        self.version = version
        # Set to zero
        self.checksum = checksum

    def as_bytes(self):
        """
        Converts UDP to proper format of payload bytes to send
        self.payload is converted to bytes with str.encode(self.payload)
        :return: bytes representation of UDP
        :rtype: bytes
        """

        # Calculate length if not manually set Convert payload try to call as_bytes function for application layer -
        # if protocol not supported, payload treated as ascii string. If payload not string, it is assumed payload is
        # already in bytes
        try:
            payload = self.payload.as_bytes()
        except AttributeError:
            try:
                payload = self.payload.encode()
            except AttributeError:
                payload = self.payload

        if self.length == 0:
            self.length = len(payload) + 8

        pseudo = form_pseudo_header(self.src_ip, self.dst_ip, self.length, "udp", version=self.version)

        if self.checksum == 0:
            self.checksum = checksum(pseudo + pack('!HHH', self.src_prt, self.dst_prt, self.length) + payload)

        return pack('!HHHH', self.src_prt, self.dst_prt, self.length, self.checksum) + payload

    @classmethod
    def udp_parser(cls, data, recursive=True):
        """
        Class method that creates UDP object
        :param data: UDP segment passed in as bytes
        :type data: bytes
        :return: UDP object created from values in data
        :rtype: UDP
        """

        src = int.from_bytes(data[0:2], 'big')
        dst = int.from_bytes(data[2:4], 'big')
        length = int.from_bytes(data[4:6], 'big')
        checksum = int.from_bytes(data[6:8], 'big')
        returnable = UDP(src, dst, "0.0.0.0", "0.0.0.0", data[8:], length=length, checksum=checksum)

        if recursive:
            returnable.parse_further_layers()

        return returnable

    def parse_further_layers(self, recursive=True):
        """
        Method that parses higher layers
        :param recursive: boolean value of whether parsing funciton should - default of True
        :type recursive: boolean
        be called recursively through all layers
        """
        try:
            self.payload = self.payload.decode("ascii")
        except UnicodeDecodeError:
            pass

    def reset_calculated_fields(self):
        """
        Resets calcualted fields for UDP - resets checksum and length
        """
        self.checksum = 0
        self.length = 0

    def __str__(self):
        """
        Create string representation of UDP object
        :return: string of UDP
        :rtype: String
        """
        header = "*" * 20 + "_UDP_" + "*" * 20
        src = "Source: " + str(self.src_prt)
        dst = "Destination: "  + str(self.dst_prt)
        length = "Length:" + str(self.length)
        trailer = "*" * 45
        return "\n".join((header, src, dst, length, trailer))






