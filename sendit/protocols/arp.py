# Creates object of ARP protocol
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from socket import *
from sendit.helper_functions.helper import addr_to_bytes, bytes_to_MAC
class ARP:
    """
    Holds all data for ARP

    :param sha: string of source MAC address
    :param spa: string of source IP address
    :param tha: string of target MAC address
    :param tpa: string of target IP address
    :param hrd: hardware code, defaul to 1 for ethernet
    :param pro: type of protocol address - default to 2048 for IPv4 - corresponds to Ethertype values
    :param hln: length of hardware address in bytes - default to 6 for MAC length
    :param pln: length of protocol address in bytes - default to 4 for IPv4 length
    :param op: opcode of arp message - default to 1 for request
    :raise ValueError if opcode is not between 1 and 9 inclusive
    """

    def __init__(self, sha, spa, tha, tpa, hrd=1, pro=2048, hln=6, pln=4, op=1):
        """Init for ARP"""
        if op > 9 or op < 1:
            # INVALID VALUE
            raise ValueError("op must be valid ARP op code, 1-9")
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
        :return: ARP instance that contains the values that was in data
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

