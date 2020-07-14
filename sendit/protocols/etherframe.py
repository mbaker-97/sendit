# Provide object of EthernetII protocol
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from sendit.helper_functions.helper import bytes_to_MAC, is_valid_MAC, addr_to_bytes
from sendit.protocols.arp import ARP
from sendit.protocols.ipv4 import IPv4
from sendit.protocols.ipv6 import IPv6
class EtherFrame:
    """
    Holds all data of Etherframe


    :param dst: string of destination MAC address
           ex: "AB:CD:EF:01:23:45"
    :param src: string of source MAC Address
           ex: "AB:CD:EF:01:23:45"
    :param payload: ARP object, IPv4 object, or object by which str.encode(payload) can be called
    :param ethertype: string representing ethertype. Default value is ipv4
            Can take custom value consisting of 4 hex string asciis characters
            ex: "8035"
            Can take values of "ipv4", "ipv6", "arp", or "rarp" and convert them to correct ethertype code
            Default value is "ipv4"
    :raise ValueError if dst not valid MAC address
    :raise ValueError if src not valid MAC address
    :raise ValueError if ethertype is not supported builtin AND is not 2 bytes of a string of hex characters
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
        :return: - bytes representation of EtherFrame
        """
        dst = addr_to_bytes(self.dst)
        src = addr_to_bytes(self.src)
        etype = EtherFrame.ethertype_to_bytes.get(self.etype)
        # If custom ethertype
        if etype is None:
            etype = bytes.fromhex(str(self.etype))

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

    @classmethod
    def etherframe_parser(cls, data, recursive=True):
        """
        Class Method that parses group of bytes to create EtherFrame Object
        :param data: etherframe passed in as bytes
        If IPv4 is type of frame, payload will be IPv4 object created
        If ARP is type of frame, payload will be ARP object created
        :return: EtherFrame instance that contains the values that was in data
        """
        dst = bytes_to_MAC(data[0:6])
        src = bytes_to_MAC(data[6:12])
        type_bytes = data[12:14]

        type = EtherFrame.bytes_to_ethertype.get(type_bytes)

        # Type not currently built in to EtherFrame class
        if type is None:
            type = int(hex(int.from_bytes(type_bytes, 'big'))[2:])
        rest = data[14:]

        if recursive:
             # If ARP, parse ARP
            if type == "arp":
                 payload = ARP.arp_parser(rest)
            # If IPv4, parse IPv4
            elif type == "ipv4":
                payload = IPv4.ipv4_parser(rest)
            elif type == "ipv6":
                 payload = IPv6.ipv6_parser(rest)
            else:
                payload = data[14:]
        else:
            payload = data[14:]

                

        returnable = EtherFrame(dst, src, payload, ethertype=type)
        return returnable

