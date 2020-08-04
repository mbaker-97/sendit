"""Creates ARP  object and provides methods to parse bytes to ARP create bytes
to ARP object"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.6"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from socket import *
from sendit.helper_functions.helper import addr_to_bytes, bytes_to_MAC
class ARP:
    """
    Holds all data for ARP

    :param sha: Source MAC  address
    :type sha: String, formatted as "XX:XX:XX:XX:XX:XX"
    :param spa: string of source IP address
    :type spa: String, formated as "XXX.XXX.XXX.XXX"
    :param tha: string of target MAC address
    :type tha: String, formatted as "XX:XX:XX:XX:XX:XX"
    :param tpa: string of target IP address"
    :type tpa: String, formated as "XXX.XXX.XXX.XXX"
    :param hrd: hardware code, defaults to 1 for ethernet
    :type hrd: int 
    :param pro: type of protocol address - corresponds to Ethertype values, defaults to 2048 for IPv4
    :type pro: int
    :param hln: length of hardware address in bytes, defaults to 6 for MAC length
    :type hln: int
    :param pln: length of protocol address in bytes, defaults to 4 for IPv4 length
    :type pln: int
    :param op: opcode of arp message, defaults to 1 for request
    :type op: int
    :raise ValueError: if opcode, hrd, or  pln is not between 0 and 65535 \
            inclusive or hln or pln is not between 0 and 255 inclusive
    """

    def __init__(self, sha, spa, tha, tpa, hrd=1, pro=2048, hln=6, pln=4, op=1):
        """Init for ARP"""
        if op < 0 or op > 65535:
            # INVALID VALUE
            raise ValueError("op must be valid 16 bit int, 0-65535 inclusive")
        if hrd < 0 or hrd  > 65535:
            # INVALID VALUE
            raise ValueError("hrd must be valid 16 bit int, 0-65535 inclusive")
        if pro < 0 or pro  > 65535:
            # INVALID VALUE
            raise ValueError("pro must be valid 16 bit int, 0-65535 inclusive")
        if hln < 0  or hln > 255:
            # INVALID VALUE
            raise ValueError("hln must be valid 8 bit int, 0-255 inclusive")
        if pln < 0  or pln > 255:
            # INVALID VALUE
            raise ValueError("pln be valid 8 bit int, 0-255 inclusive")

        self.hrd = hrd  # default is ethernet
        self.pro = pro  # default is IPv4
        self.hln = hln  # length of MAC is 6 bytes
        self.pln = pln  # length of IPv4 is 4 bytes
        self.op = op
        self.spa = spa
        self.sha = sha
        self.tha = tha
        self.tpa = tpa

    def as_bytes(self):
        """
        Converts ARP to proper format of payload bytes
        :return: bytes representation of ARP message
        :rtype: bytes
        """
        spa = inet_aton(self.spa)
        sha = addr_to_bytes(self.sha)
        tha = addr_to_bytes(self.tha)
        tpa = inet_aton(self.tpa)

        return pack('!HHBBH', self.hrd, self.pro, self.hln, self.pln, self.op) + sha + spa + tha + tpa

    @classmethod
    def arp_parser(cls, data):
        """
        Class Method that parses group of bytes to create ARP object
        :param data: ARP message to parse passed in as bytes
        :type data: bytes
        :return: ARP instance that contains the values that was in data
        :rtype: ARP object
        """
        hrd = int.from_bytes(data[0:2], 'big')
        pro = int.from_bytes(data[2:4], 'big')
        hln = int.from_bytes(data[4:5], 'big')
        pln = int.from_bytes(data[5:6], 'big')
        op = int.from_bytes(data[6:8], 'big')
        sha = bytes_to_MAC(data[8:14])
        spa = inet_ntoa(data[14:18])
        tha = bytes_to_MAC(data[18:24])
        tpa = inet_ntoa(data[24:28])

        return ARP(sha, spa, tha, tpa, hrd=hrd, pro=pro, hln=hln, pln=pln, op=op)

    def __str__(self):
        """
        Gives string representation of ARP object
        :return: String representation of ARP object
        :rtype: String
        """
        header = "*" * 20 + "__ARP__" + "*" * 20
        sha = "Source Hardware Address: " + self.sha
        tha = "Target Hardware Address: " + self.tha
        spa = "Source Protocol Address: " + self.spa
        tpa = "Target Protocol Address: " + self.tpa
        hln = "Hardware Length: " + str(self.hln) + " bytes"
        pln = "Protocol Length: " + str(self.pln) + " bytes"
        op = "Operation: " + str(self.op)
        if self.op == 1:
            op = " ".join((op, "(request)"))
        elif self.op == 2:
            op = " ".join((op, "(reply)"))
        pro = "Protocol Address type: " + str(self.pro)
        if self.pro == 2048:
            pro = " ".join((pro, "(IPv4)"))
        hrd = "Hardware Address type: " + str(self.hrd)
        if self.hrd == 1:
            hrd = " ".join((hrd, "(Ethernet)"))
        trailer = "*" * 47
        return "\n".join((header, sha, tha, spa, tpa, hln, pln, op, pro, hrd, trailer))

        
