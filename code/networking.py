#!/usr/bin/python3
"""
Creates library from which custom networking solutions can be built providing absolute control from layer 2 to layer 4

"""
import re
import random
import time
import subprocess
import sys
from socket import *
from threading import Thread
from ipaddress import IPv6Address, AddressValueError
import csv

__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"

# TODO
# Value check parameters

BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
BROADCAST_IPV4 = "255.255.255.255"


# Brute Force search .... sort csv and FIX!
def MAC_to_manufacturer(address):
    """
    Takes a MAC Address and searches through CSV files from IEEE to find manufacturer they belong to
    :param address: MAC Address in string format, bytes separated with colon (:)
    :return: String of manufacturer of device with provided MAC Address
             "Unknown" if not found
    """

    addr = "".join(address.split(":")).upper()
    # Look in 16 million host block assignment csv
    with open('mal.csv', newline='') as mal:
        reader = csv.DictReader(mal)
        for row in reader:
            if row['Assignment'] == addr[:6]:
                # Exists in other csvs - handed out in smaller blocks of addresses
                if row['Organization Name'] == "IEEE Registration Authority":
                    break
                return row['Organization Name']

    # Look in 1 million host block assignment csv
    with open('mam.csv', newline='') as mam:
        reader = csv.DictReader(mam)
        for row in reader:
            if row['Assignment'] == addr[:7]:
                return row['Organization Name']

    # Look in 4096 host block assignment csv
    with open('mas.csv', newline='') as mas:
        reader = csv.DictReader(mas)
        for row in reader:
            if row['Assignment'] == addr[:9]:
                return row['Organization Name']

    return "Unknown Manufacturer"


def manufacturer_to_MAC(manufacturer):
    """
    Provides a list of MAC prefixes based off provided manufacturer
    :param manufacturer: string of manufacturer name
    :return: list of strings of 3 byte MAC prefixes registered to that manufacturer
    """
    macs = list()
    with open('mal.csv', newline='') as mal:
        reader = csv.DictReader(mal)
        for row in reader:
            if row['Organization Name'].lower().find(manufacturer.lower()) != -1:
                macs.append(row['Assignment'])
    return macs


def is_hex(string):
    """
    Determines if string consists solely of ascii characters that are hexidecimal characters
    :param string: string to check if hex
    :return: boolean representing if the string consists of only hex ascii characters
    """
    return all(c in 'abcdef0123456789' for c in string.lower())


def get_mac(interface):
    """
    Finds MAC address of a network interface on the host
    Uses Unix tools ifconfig and grep
    Not supported on all Operating Systems, or all kernels
    :param interface: string of the interface to look for
    :return: string representing MAC address of interface
             if OS does not support commands or interface not found, program exits with code 1
    """
    try:
        val = subprocess.check_output("ifconfig " + interface + " | grep -Eo ..\\(\\:..\\){5}", shell=True,
                                      stderr=subprocess.STDOUT).decode('ascii')

    except subprocess.CalledProcessError as e:

        if e.output.decode().find("Device not found") > -1:
            print(interface + " not found")
        else:
            print("Sorry, your Operating System is currently not supported.")

        sys.exit(1)
    return val.strip()


def get_ip(interface):
    """
    Finds IP of a network interface on the host
    Uses UNIX tools ifconfig, grep, and awk
    Not supported on all Operating Systems or all kernels
    :param interface: string of the interface to look for
    :return: string representing MAC address of interface
             if OS does not support commands or interface not found, program exits with code 1
    """
    try:
        val = subprocess.check_output("ifconfig " + interface + " | grep -w inet | awk '{ print $2}'", shell=True,
                                      stderr=subprocess.STDOUT).decode('ascii')

    except subprocess.CalledProcessError as e:

        if e.output.decode().find("Device not found") > -1:
            print(interface + " not found")
        else:
            print("Sorry, your Operating System is currently not supported.")

        sys.exit(1)
    return val.strip()


# Works with MAC and IPv6
def addr_to_bytes(address):
    """
    Takes address represented in string consisting of hex characters, MAC or IPv6, and converts to bytes
    :param address:  addrss to convert
    :return: bytes form of address
    """
    return bytes.fromhex(address.replace(':', '').replace('.', '').replace('-', ''))


def bytes_to_MAC(address):
    """
    Converts bytes form of MAC address to String form of MAC address
    :param address: Bytes form of MAC address
    :return: String form of MAC Address
    """
    addr = address.hex()
    return (addr[0:2] + ":" + addr[2:4] + ":" + addr[4:6] + ":" + addr[6:8] + ":" + addr[8:10] + ":" + addr[
                                                                                                       10:12]).upper()

def is_valid_ipv4(address):
    """
    Determines if address if valid IPv4 address
    Checks that there are 4 octets, and values are between 0 and 255, inclusive
    :param address: value to check if valid IPv4 address
    :return: boolean representing if address is a valid IPv4 address
    """
    #   Finds when non numeric values input
    try:
        octets = [int(addr) for addr in re.split(r'[.:-]', address)]
    except ValueError:
        return False
    #   Determines if there are 4 octets
    if len(octets) != 4:
        return False

    #   Determines if each octet is in the correct range from 0 to 255 inclusive
    for octet in octets:

        if octet > 255 or octet < 0:
            return False

    return True


def is_valid_MAC(address):
    """
    Determines if address if valid MAC address
    Checks that there are 12 characters, and all are Hex values
    :param address: value to check if valid MAC address
    :return: boolean representing if address is a valid MAC address
    """
    hexed = "".join([addr for addr in re.split(r'[.:-]', address)])

    # Check if length 12
    if len(hexed) != 12:
        return False
    # Check if all Hex Values
    try:
        int(hexed, 16)
        return True
    except ValueError:
        return False


def ip_to_int(address):
    """
    Converts string IP addrss to an int
    :param address: string IP address
    :raise ValueError if address is not  valid IPv4 addrss
    :return: int representing IP address
    """
    if not is_valid_ipv4(address):
        raise ValueError("address must be valid IPv4 address")
    octets = address.split(".")
    number = 0
    for i in range(4):
        number = number + int(octets[i]) * pow(256, 3 - i)

    return number


def int_to_ip(number):
    """
    Converts int to string IPv4 address
    :param number: int to convert to string IPv4 address
    :return: String of IPv4 address
    """
    if number > 4294967295 or number < 0:
        raise ValueError
    address = list()
    for i in range(4):
        octet = str(number % 256)
        number = int(number / 256)
        address.insert(0, octet)
    return ".".join(address)


def checksum(message):
    """
    Calculates 16 bit checksum by 1's compliment addition between all 16 bit words in message,
    and then taking the 1's compliment of the sum
    Formula same as defined for IPv4, TCP, and UDP
    :param message: takes header to create checksum
    :return: 16 bit checksum
    """
    # Split message into 16 bit words
    words = [message[i:i + 2] for i in range(0, len(message), 2)]
    total = 0
    # Perform 1's comliment addition per word
    for word in words:
        # Check if full 16 bits
        if len(word) == 2:
            total += int.from_bytes(word, 'big')
        # If not full 16 bits, message has odd number of bytes, add extra padding at end for calculation
        else:
            total += (int.from_bytes(word, 'big') << 8)
        # Check for carry bit
        if total > 65535:
            total = (total + 1) % 65536

    # Perform 1's compliment on total, return value
    return total ^ 65535


def form_pseudo_header(src_ip, dst_ip, length, protocol, version=4):
    """
    Form TCP/UDP pseudoheader for checksum calculation
    :param version: IP version - default is 4
    :param protocol: L4 Protocol - currently only support tcp and udp
    :param src_ip: source ip
    :param dst_ip: destination ip
    :param length: length of tcp segment, header included
    :return: pseudoheader in bytes
    """
    ip_protocol = IPv4.protocols_to_int.get(protocol.lower())
    if version == 4:
        return inet_aton(src_ip) + inet_aton(dst_ip) + ip_protocol.to_bytes(2, 'big') + length.to_bytes(2, 'big')
    elif version == 6:
        return IPv6Address(src_ip).packed + IPv6Address(dst_ip).packed + length.to_bytes(
            4, 'big') + ip_protocol.to_bytes(2, 'big')
    else:
        raise ValueError("Invalid version number")


class Raw_NIC(socket):
    """
    Child Class of Socket
    Creates Raw Socket, binds to provided interface
    Implements send method that works with rest of library

    :param interface: string name of network interface
    ex: eth0, wlan0. Not sure? Call ifconfig and look at interface names
    """

    def __init__(self, interface):
        """Inits Raw_NIC as raw Socket bound to interface"""
        super().__init__(AF_PACKET, SOCK_RAW, htons(3))
        super().bind((interface, 0))

    def send(self, frame):
        """
        Overrides Socket send method
        Attempts to use to_payload() method that is provided by all protocol classes in this library
        If not a class in this libary, calls str.encode on provided frame
        Them sends on raw socket
        :param frame: frame to send on Raw_NIC
        """

        try:
            payload_bytes = frame.to_payload()
        except AttributeError:
            payload_bytes = str.encode(frame)

        super().send(payload_bytes)


class EtherFrame:
    """
    Holds all data of Etherframe
    In normal usage, should be outermost encapsulation of data, can be used with Raw_NIC.send(frame)

    :param dst: string of destination MAC address
           ex: "AB:CD:EF:01:23"
    :param src: string of source MAC Address
           ex: "AB:CD:EF:01:23"
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
        # TODO

        if str(ethertype).lower() not in EtherFrame.ethertype_to_bytes.keys() and (
                len(str(ethertype)) != 4 or not is_hex(str(ethertype))):
            raise ValueError(ethertype, "Expecting 2 Bytes in hex")

        self.dst = dst
        self.src = src
        self.etype = ethertype
        self.payload = payload

    def to_payload(self):
        """
        Converts EtherFrame to proper format of payload bytes to send on Raw_NIC
        If self.payload is IPv4 or ARP object, their to_payload function is called, providing the conversion of payload
        to properly formated bytes to be inserted into frame to be sent on Raw_NIC
        If self.payload is not IPv4 or ARP object, self.payload is converted to bytes with str.encode(self.payload)
        :return: - bytes representation of EtherFrame
        """
        dst = addr_to_bytes(self.dst)
        src = addr_to_bytes(self.src)
        etype = EtherFrame.ethertype_to_bytes.get(self.etype)
        # If custom ethertype
        if etype is None:
            etype = bytes.fromhex(str(self.etype))

        try:
            payload = self.payload.to_payload()
            payload_len = len(self.payload.to_payload())
        except AttributeError:
            payload = str.encode(self.payload)
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
    def etherframe_parser(cls, data):
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

        returnable = EtherFrame(dst, src, payload, ethertype=type)
        return returnable


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

    def to_payload(self):
        """
        Converts ARP to proper format of payload bytes
        :return: bytes representation of ARP message
        """
        hrd = self.hrd.to_bytes(2, 'big')
        pro = self.pro.to_bytes(2, 'big')
        hln = self.hln.to_bytes(1, 'big')
        pln = self.pln.to_bytes(1, 'big')

        op_code = self.op.to_bytes(2, 'big')
        spa = inet_aton(self.spa)
        sha = addr_to_bytes(self.sha)
        tha = addr_to_bytes(self.tha)
        tpa = inet_aton(self.tpa)

        return hrd + pro + hln + pln + op_code + sha + spa + tha + tpa

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


class IPv4:
    """
    Creates IPv4 object from parameters
    :param src: source IP address
    :param dst: destination IP address
    :param payload: payload of the packet - can be TCP or UDP objects, or a string
    :param id: identification number of packet - default of 0
    :param df: do not fragment flag - default of False
    :param mf: more fragments flag - deafult of False
    :param offset: offset of packet - default of 0
    :param ttl: time to live - default of 64
    :param protocol: protocol carried in packet.
                     currently supported values: "tcp", "udp", "icmp", custom int value accepted IF valid
    :param dscp: differentiated services value - default of 0
    :param ecn: explicit congestion notification - deafult of 0
    :param version: version of IP
    """
    protocols_to_int = {"icmp": 1, "tcp": 6, "udp": 17}
    int_to_protocol = {1: "icmp", 6: "tcp", 17: "udp"}

    def __init__(self, src, dst, payload, id=0, df=False, mf=False, offset=0, ttl=64, protocol="tcp", dscp=0, ecn=0,
                 version=4):
        """init for IPv4"""
        if ttl > 255 or ttl < 0:
            raise ValueError("ttl should be value between 0 and 255 inclusive")

        self.version = version
        # How many 32 bit words in header - currently options at end of header not supported
        self.ihl = 5
        self.dscp = dscp
        self.ecn = ecn
        # Total length of packet, header included
        try:
            self.length = len(payload.to_payload()) + self.ihl * 4
        except AttributeError:
            self.length = len(payload) + self.ihl * 4

        self.id = id
        self.df = df
        self.mf = mf
        self.ttl = ttl
        self.offset = offset

        self.protocol = IPv4.protocols_to_int.get(str(protocol).lower())
        # Until time for error handling, trust users custom input
        if self.protocol is None:
            self.protocol = protocol

        self.src = src
        self.dst = dst
        self.payload = payload

        self.checksum = 0

    def to_payload(self):
        """
        Converts IPv4 to proper format of payload bytes to send set as EtherFrame payload
        If self.payload is TCP or UDP object, their to_payload function is called, providing the conversion of payload
        to properly formated bytes to be inserted into packet
        If self.payload is not TCP or UDP object, self.payload is converted to bytes with str.encode(self.payload)
        :return: - bytes representation of IPv4 Packet
        """
        first_byte = int(bin(self.version)[2:].zfill(4) + bin(self.ihl)[2:].zfill(4), 2).to_bytes(1, 'big')
        second_byte = int(bin(self.dscp)[2:].zfill(6) + bin(self.ecn)[2:].zfill(2), 2).to_bytes(1, 'big')
        length = self.length.to_bytes(2, 'big')
        identification = self.id.to_bytes(2, 'big')

        # Set flags
        flags = 0
        if self.df:
            flags += 2
        if self.mf:
            flags += 1

        frag_bytes = int(bin(flags)[2:].zfill(3) + bin(self.offset)[2:].zfill(13), 2).to_bytes(2, 'big')

        time_to_live = self.ttl.to_bytes(1, 'big')
        protocol = self.protocol.to_bytes(1, 'big')

        # Convert IPv4 addresses
        src = inet_aton(self.src)
        dst = inet_aton(self.dst)
        try:
            payload = self.payload.to_payload()
        except AttributeError:
            payload = str.encode(self.payload)
        # Calculate Checksum
        self.checksum = checksum(first_byte + second_byte + length + identification + frag_bytes + time_to_live +
                                 protocol + src + dst)
        check = self.checksum.to_bytes(2, 'big')
        return first_byte + second_byte + length + identification + frag_bytes + time_to_live + protocol + check + src \
               + dst + payload

    @classmethod
    def ipv4_parser(cls, data):
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

        if protocol == "udp":
            payload = UDP.udp_parser(data[20:])
        elif protocol == "tcp":
            payload = TCP.tcp_parser(data[20:])
        else:
            payload = data[20:].decode("ascii")

        returnable = IPv4(src, dst, payload, id=id, df=df_bool, mf=mf_bool, offset=offset, ttl=ttl, protocol=protocol,
                          dscp=dscp, ecn=ecn, version=4)
        returnable.length = length
        returnable.version = version
        returnable.ihl = ihl
        returnable.checksum = checksum
        return returnable


class IPv6:
    """
    Creates IPv6 object from parameters
    :param src: source IPv6 address
    :param dst: destination IPv6 address
    :param next: next header - string - default "tcp". "udp" and "icmp" also supported
    :param limit: hop count limit - 0 to 255 inclusive
    :param flow_label: label for which flow packet belongs to - default is 0 - none
    :param ds: Differentiated Services field
    :param ecn: - Explicit Congestion Notification value
    :param version: IP version: default of 6
    """

    def __init__(self, src, dst, payload, next="tcp", limit=64, flow_label=0, ds=0, ecn=0, version=6):
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
        try:
            self.length = len(payload.to_payload())
        except AttributeError:
            self.length = len(payload)

        self.next = IPv4.protocols_to_int.get(str(next).lower())
        # Until time for error handling, trust users custom input - must be integer
        if self.next is None:
            self.next = next

        self.src = src
        self.dst = dst
        self.limit = limit
        self.version = version
        self.ds = ds
        self.ecn = ecn
        self.flow_label = flow_label
        self.length = 0
        self.payload = payload

    def to_payload(self):
        """
        Converts IPv6 to proper format of payload bytes to send set as EtherFrame payload
        If self.payload is TCP or UDP object, their to_payload function is called, providing the conversion of payload
        to properly formated bytes to be inserted into packet
        If self.payload is not TCP or UDP object, self.payload is converted to bytes with str.encode(self.payload)
        :return: - bytes representation of IPv6 Packet
        """
        first_byte = ((self.version << 4) + (self.ds >> 2)).to_bytes(1, 'big')
        second_byte = (((self.ds % 4) << 6) + (self.ecn << 4) + (self.flow_label >> 16)).to_bytes(1, 'big')
        flow_label_bytes = (self.flow_label % 65536).to_bytes(2, 'big')
        # Total length of packet, header included
        try:
            self.length = len(self.payload.to_payload())
        except AttributeError:
            self.length = len(self.payload)

        length_bytes = self.length.to_bytes(2, 'big')
        next_bytes = self.next.to_bytes(1, 'big')
        limit_bytes = self.limit.to_bytes(1, 'big')
        src_bytes = IPv6Address(self.src).packed
        dst_bytes = IPv6Address(self.dst).packed
        try:
            payload = self.payload.to_payload()
        except AttributeError:
            payload = str.encode(self.payload)
        return first_byte + second_byte + flow_label_bytes + length_bytes + next_bytes + limit_bytes + src_bytes + \
               dst_bytes + payload

    @classmethod
    def ipv6_parser(cls, data):
        """
        Class Method that parses group of bytes to create IPv6 Object
        :param data: ipv6 packet passed in as bytes
        If protocol is "TCP", payload will be TCP object created
        If protocol is "UDP", payload will be UDP object created
        :return: IPv6 instance that contains the values that was in data
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

        protocol = IPv4.int_to_protocol.get(next)

        # If protocol not currently defined in class
        if protocol is None:
            protocol = next

        if protocol == "udp":
            payload = UDP.udp_parser(data[40:])
        elif protocol == "tcp":
            payload = TCP.tcp_parser(data[40:])
        else:
            payload = data[40:].decode("ascii")
        returnable = IPv6(src, dst, payload, next=protocol, limit=limit, flow_label=flow_label, ds=ds, ecn=ecn,
                          version=version)
        returnable.length = length

        return returnable

class UDP:
    """
    Creates IPv4 object from parameters
    UDP checksum is optional and therefore not currently supported
    TODO: provide checksum with psuedo header
    :param src: source port
    :param dst: destination port
    :param payload: payload to be carried UDP
    :raise ValueError if src is not valid src port number
    :raise ValueError if dst is not valid dst port number
    """

    def __init__(self, src_prt, dst_prt, src_ip, dst_ip, payload, version=4):

        if src_prt > 65535 or src_prt < 0:
            raise ValueError("src_prt must be valid UDP port")
        if dst_prt > 65535 or dst_prt < 0:
            raise ValueError("dst_prt must be valid UDP port")

        self.src_prt = src_prt
        self.dst_prt = dst_prt
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload
        # Length of payload + header
        # Header is 8 bytes long
        self.length = (len(self.payload) + 8)

        # Set to zero
        self.checksum = 0
        self.version = version

    def to_payload(self):
        """
        Converts UDP to proper format of payload bytes to send
        self.payload is converted to bytes with str.encode(self.payload)
        checksum is currently 0 - not implemented
        :return: - bytes representation of UDP
        """
        src_prt = self.src_prt.to_bytes(2, 'big')
        dst_prt = self.dst_prt.to_bytes(2, 'big')
        length = self.length.to_bytes(2, 'big')
        payload = self.payload.encode()
        pseudo = form_pseudo_header(self.src_ip, self.dst_ip, self.length, "udp", version=self.version)

        if self.checksum == 0:
            self.checksum = checksum(pseudo + src_prt + dst_prt + length + payload)

        checksum_bytes = self.checksum.to_bytes(2, 'big')

        return src_prt + dst_prt + length + checksum_bytes + payload

    @classmethod
    def udp_parser(cls, data):
        """
        Class method that creates UDP object
        :param data: UDP segment passed in as bytes
        :return: UDP object created from values in data
        """

        src = int.from_bytes(data[0:2], 'big')
        dst = int.from_bytes(data[2:4], 'big')
        length = int.from_bytes(data[4:6], 'big')
        checksum = int.from_bytes(data[6:8], 'big')
        payload = data[8:].decode("ascii")

        returnable = UDP(src, dst, "0.0.0.0", "0.0.0.0", payload)
        returnable.length = length
        returnable.checksum = checksum
        return returnable


class TCP:
    """
    Forms TCP Object from parameters
    :param src_prt: source TCP port
    :param dst_prt: destination TCP port
    :param window: window size
    :param payload: payload - in string format
    :param src_ip: source IP, used to calculate checksum
    :param dst_ip: destination IP, used to calculate checksum
    :param sqn:  sequence Number
    :param ack_num: Acknowledgement Number
    :param offset: byte offset of where data starts
    :param ns: ns flag - default of False
    :param cwr: cwr flag - default of False
    :param ece: ece flag - default of False
    :param urg: urg flag - default of False
    :param ack: ack flag - default of False
    :param psh: psh flag - default of False
    :param rst: rst flag - default of False
    :param syn: syn flag - default of False
    :param fin: fin flag - default of False
    :param urg_pnt: offset of where urgent data stops

    :raise ValueError when src_prt not between 0 and 65535 inclusive
    :raise ValueError when dst_port not between 0 and 65535 inclusive
    :raise ValueError when sqn not between 0 and 4294967295 inclusive
    :raise ValueError when ack_number not between 0 and 4294967295 inclusive
    :raise ValueError when window not between 0 and 4294967295 inclusive
    :raise ValueError when urg_pnt not between 0 and 4294967295 inclusive

    """

    def __init__(self, src_prt, dst_prt, src_ip, dst_ip, window, payload, sqn=0, ack_num=0, offset=5, ns=False,
                 cwr=False, ece=False, urg=False, ack=False, psh=False, rst=False, syn=False, fin=False, urg_pnt=0,
                 version=4):
        """init for TCP"""
        if src_prt > 65535 or src_prt < 0:
            raise ValueError("src_prt must be valid TCP port")
        if dst_prt > 65535 or dst_prt < 0:
            raise ValueError("dst_prt must be valid TCP port")
        if sqn > 4294967295 or sqn < 0:
            raise ValueError("sqn must be valid sequence number")
        if ack_num > 4294967295 or ack_num < 0:
            raise ValueError("ack_num must be valid acknowledgement number")
        if window > 4294967295 or window < 0:
            raise ValueError("window must be valid window size")
        if urg_pnt > 4294967295 or urg_pnt < 0:
            raise ValueError("urg_pnt must be valid urgent pointer number")
        self.src_prt = src_prt
        self.dst_prt = dst_prt
        self.window = window
        self.seq = sqn
        self.ack_num = ack_num
        self.offset = offset
        self.ns = ns
        self.cwr = cwr
        self.ece = ece
        self.urg = urg
        self.ack = ack
        self.psh = psh
        self.rst = rst
        self.syn = syn
        self.fin = fin
        self.urg_pnt = urg_pnt

        self.payload = payload

        # For pseudo header to calculate checksum
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.checksum = 0

        self.version = version

    def to_payload(self):
        """
        Converts TCP to proper format of payload bytes to send
        self.payload is converted to bytes with str.encode(self.payload)
        :return: - bytes representation of TCP
        """
        src_prt = self.src_prt.to_bytes(2, 'big')
        dst_prt = self.dst_prt.to_bytes(2, 'big')
        sqn = self.seq.to_bytes(4, 'big')
        ack_num = self.ack_num.to_bytes(4, 'big')

        offset = self.offset << 4
        if self.ns:
            offset += 1

        offset_byte = offset.to_bytes(1, 'big')

        flags = 0
        if self.fin:
            flags += 1
        if self.syn:
            flags += 2
        if self.rst:
            flags += 4
        if self.psh:
            flags += 8
        if self.ack:
            flags += 16
        if self.urg:
            flags += 32
        if self.ece:
            flags += 64
        if self.cwr:
            flags += 128

        flags_bytes = flags.to_bytes(1, 'big')
        window_bytes = self.window.to_bytes(2, 'big')
        urgent_pnt_bytes = self.urg_pnt.to_bytes(2, 'big')

        # Create pseudo header
        # Assume length of tcp header is 20 bytes
        pseudo = form_pseudo_header(self.src_ip, self.dst_ip, len(self.payload) + 20, "tcp", version=self.version)
        payload = self.payload.encode()
        # Check if checksum has been manually set
        if self.checksum == 0:
            self.checksum = checksum(
                pseudo + src_prt + dst_prt + sqn + ack_num + offset_byte + flags_bytes + window_bytes +
                urgent_pnt_bytes + payload)

        checksum_bytes = self.checksum.to_bytes(2, 'big')

        return src_prt + dst_prt + sqn + ack_num + offset_byte + flags_bytes + window_bytes + checksum_bytes + \
               urgent_pnt_bytes + payload

    @classmethod
    def tcp_parser(cls, data):
        """
        Class method that creates TCP object
        :param data: TCP segment passed in as bytes
        :return: TCP object created from values in data
        """

        src = int.from_bytes(data[0:2], 'big')
        dst = int.from_bytes(data[2:4], 'big')
        sqn = int.from_bytes(data[4:8], 'big')
        ack_num = int.from_bytes(data[8:12], 'big')
        # Binary operations to get flags:
        offset = int.from_bytes(data[12:13], 'big') >> 4

        # Grab flags ... binary math
        flags = [0] * 9
        flags[0] = int.from_bytes(data[12:13], 'big') % 2
        flags[1] = (int.from_bytes(data[13:14], 'big') >> 7) % 2
        flags[2] = (int.from_bytes(data[13:14], 'big') >> 6) % 2
        flags[3] = (int.from_bytes(data[13:14], 'big') >> 5) % 2
        flags[4] = (int.from_bytes(data[13:14], 'big') >> 4) % 2
        flags[5] = (int.from_bytes(data[13:14], 'big') >> 3) % 2
        flags[6] = (int.from_bytes(data[13:14], 'big') >> 2) % 2
        flags[7] = (int.from_bytes(data[13:14], 'big') >> 1) % 2
        flags[8] = int.from_bytes(data[13:14], 'big') % 2

        # List comprehension to find if if flags are true
        flag_bool = [x == 1 for x in flags]

        window = int.from_bytes(data[14:16], 'big')
        checksum = int.from_bytes(data[16:18], 'big')
        urg_pnt = int.from_bytes(data[18:20], 'big')
        data = data[20:].decode("ascii")

        returnable = TCP(src, dst, "0.0.0.0", "0.0.0.0", window, data, sqn=sqn, ack_num=ack_num, offset=offset,
                         ns=flag_bool[0], cwr=flag_bool[1], ece=flag_bool[2], urg=flag_bool[3], ack=flag_bool[4],
                         psh=flag_bool[5], rst=flag_bool[6], syn=flag_bool[7], fin=flag_bool[8], urg_pnt=urg_pnt)
        returnable.checksum = checksum

        return returnable


if __name__ == '__main__':
    """ main method provided to show example usage"""
    print("Example usage here: ")
    # Example usage:

    # Example 1: Standard Usage

    # To find your interface name use sudo ifconfig
    # Need help?
    # ethernet interfaces often in format of eth0
    # wireless interfaces often in format of wlan0
    # To find your MAC: sudo ifconfig <interface> | grep -Eo ..\(\:..\){5}
    # Or call provided method get_mac(interface)
    # To find your IP: sudo ifconfig eth0 | grep -w inet | awk '{print $2}'
    # Or call provided method get_ip(interface)

    # Uncomment code from here
    # payload = "The quick brown fox jumps over the lazy dog"  # String payload
    # nic = Raw_NIC("wlan0")  # Create Raw_NIC - replace interface name with your interface
    # Creates TCP segment. IPs needed to calcualte checksum:
    # l4_tcp = TCP(50000, 50001, "192.168.1.1", "192.168.1.2", 1024, payload)  # Change 1st ip to yours, 2nd to target.
    # Creates IPv4 packet:
    # l3 = IPv4("192.168.1.1", "192.168.1.2", l4_tcp, protocol="tcp")  # Change 1st ip to yours, 2nd to target
    # Creates Etherframe:
    # l2 = EtherFrame("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55", l3)  # Change 1st mac to yours, 2nd to target
    # nic.send(l2)  # Send payload - open up Wireshark to see your payload
    # To Here

    # Example 2 - change payload to use UDP

    # Uncomment code from here
    # l4_udp = UDP(50000, 50001, "192.168.1.1", "192.168.1.2", payload)  # Create UDP object
    # l2.payload.payload = l4_udp  # Change l3 (and IPv4 packet) payload to new UDP object
    # l2.payload.protocol = IPv4.protocols_to_int.get("udp")  # Change l3 protocol to now say payload contains UDP segment
    # nic.send(l2)  # Send new frame with UDP segment
    # To Here

    # Example 3 - change payload to send ARP request

    # Uncomment code from here
    # Creates ARP request to find IP Change 1st MAC to your MAC, 1st IP to yours, 2nd IP to IP you are asking about
    # arp = ARP("AA:BB:CC:DD:EE:FF", "192.168.1.1", BROADCAST_MAC, "192.168.1.2")
    # l2.payload = arp # Sets l2 payload to ARP
    # l2.type = "arp" # Sets Ethertype to ARP
    # nic.send(l2) # Send new frame with ARP Request - open Wireshark to look for response!
    # To Here