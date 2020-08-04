"""Creates Etherframe object and provides methods to parse bytes to Etherframe 
create bytes to EtherFrame object"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from sendit.helper_functions.helper import *
from sendit.protocols.arp import ARP
from sendit.protocols.ipv4 import IPv4
from sendit.protocols.ipv6 import IPv6
class EtherFrame:
    """
    Holds all data of Etherframe


    :param dst: string of destination MAC address ex: "AB:CD:EF:01:23:45"
    :type dst: String     
    :param src: string of source MAC Address ex: "AB:CD:EF:01:23:45"
    :type src: String
    :param payload: data to put into Etherframe
    :type payload: ARP, IPv4, IPv6, or any or any object str.encode(payload) can be called
    :param ethertype: String representing ethertype - defaults to "ipv4". Can \
        be ipv4, ipv6, arp, or rarp,  or a custom value consisting of 4 hex \
        string ascii chars, such as "8035"
    :type ethertype: String 
    :raise ValueError: if dst not valid MAC address, if src not valid MAC \
        address, or ethertype not supported builtin AND is not 2 bytes of a \
        string of hex characters
    """

    # For ethertype to bytes lookup, and reverse lookup
    ethertype_to_bytes = {"ipv4": b'\x08\x00', "ipv6": b'\x86\xdd', "arp": b'\x08\x06', "rarp": b'\x80\x35'}
    bytes_to_ethertype = {b'\x08\x00': "ipv4", b'\x86\xdd': "ipv6", b'\x08\x06': "arp", b'\x80\x35': "rarp"}

    def __init__(self, dst, src, payload, ethertype="ipv4"):
        """Init for EtherFrame"""

        # Check MAC Address validity
        if not is_valid_MAC(dst):
            raise ValueError("dst must me valid MAC address")
        if not is_valid_MAC(src):
            raise ValueError("src must me valid MAC address")

        if str(ethertype).lower() not in EtherFrame.ethertype_to_bytes.keys() and (
                len(str(ethertype)) != 4 or not is_hex(str(ethertype))):
            raise ValueError(ethertype, "Expecting 2 Bytes in hex")

        self.dst = dst
        self.src = src
        self.etype = ethertype
        self.payload = payload

    def as_bytes(self):
        """
        Converts EtherFrame to proper format of payload bytes to send on Raw_NIC
        If self.payload is IPv4 or ARP object, their as_bytes function is called, providing the conversion of payload
        to properly formated bytes to be inserted into frame to be sent on Raw_NIC
        If self.payload is not IPv4 or ARP object, self.payload is conver
        :return: bytes representation of EtherFrame
        :rtype: bytes
        """
        dst = addr_to_bytes(self.dst)
        src = addr_to_bytes(self.src)
        etype = EtherFrame.ethertype_to_bytes.get(self.etype)
        # If custom ethertype
        if etype is None:
            etype = bytes.fromhex(self.etype)

        try:
            payload = self.payload.as_bytes()
        except AttributeError:
            payload = self.payload

        payload_len = len(payload)

        # Determine Padding
        padding = None
        if payload_len < 46:
            zero = 0
            padding = zero.to_bytes(46 - payload_len, 'big')
        if padding is None:
            return dst + src + etype + payload
        else:
            return dst + src + etype + payload + padding

    def parse_further_layers(self, recursive=True):
        """
        Method that parses higher layer information contained in payload
        :param recursive:  boolean value of whether parsing function should \
            be called recursively through all layers
        :type recursive: boolean
        :return: Object representation of payload if possible to parse, if not \
                returns self.payload
        :rtype: ARP, IPv4, IPv6, or bytes
        """
        # If ARP, parse ARP
        if self.etype == "arp":
            return ARP.arp_parser(self.payload)
        # If IPv4, parse IPv4
        elif self.etype == "ipv4":
            return  IPv4.ipv4_parser(self.payload, recursive=recursive)
        elif self.etype == "ipv6":
            return IPv6.ipv6_parser(self.payload, recursive=recursive)
        else:
            return self.payload

    @classmethod
    def etherframe_parser(cls, data, recursive=True):
        """
        Class Method that parses group of bytes to create EtherFrame Object
        :param data: etherframe passed in as bytes \
            If IPv4 is type of frame, payload will be IPv4 object created \
            If ARP is type of frame, payload will be ARP object created
        :type data: EtherFrame
        :param recursive: boolean of whether to parse recursively to higher \
            layers, defaults to True \
        If protocol is "IPv4", payload will be IPv4 object created \
        If protocol is "IPv6", payload will be IPv6 object created \
        If protocol is "ARP", payload will be ARP object created \
        :type recursive: Boolean
        :return: EtherFrame instance that contains the values that was in data
        :rtype: EtherFrame
        """
        dst = bytes_to_MAC(data[0:6])
        src = bytes_to_MAC(data[6:12])
        type_bytes = data[12:14]

        etype = EtherFrame.bytes_to_ethertype.get(type_bytes)

        # Type not currently built in to EtherFrame class
        if etype is None:
            etype = hex(int.from_bytes(type_bytes, 'big'))[2:]
        rest = data[14:]

        payload = data[14:]

        returnable = EtherFrame(dst, src, payload, ethertype=etype)
        if recursive:
            returnable.payload = returnable.parse_further_layers()
        return returnable

    def __str__(self):
        """
        Create string representation of EtherFrame
        :return: String representation of EtherFrame
        :rtype: String
        """
        header = "*" * 20 + "_Ethernet Frame_" + "*" * 20
        source = "Source address: " + self.src.upper()
        dest = "Destination address: " + self.dst.upper()
        etype = "Type: " + self.etype.upper()
        trailer = "*" * 56

        return "\n".join((header, source, dest, etype, trailer))





