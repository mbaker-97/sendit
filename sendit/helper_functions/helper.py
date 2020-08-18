# Provide helper functions to the sendit library
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
import re
import random
import time
import subprocess
import sys
from threading import Thread
from ipaddress import IPv6Address, AddressValueError
import csv
from socket import *
import pathlib
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
BROADCAST_IPV4 = "255.255.255.255"
def create_ip_protocols_to_int():
    path = str(pathlib.Path(__file__).parent.absolute())
    protocols_to_int = dict()
    with open(path + '/ip_protocols.csv', newline='') as protocols:
        reader = csv.DictReader(protocols)
        for row in reader:
            num = row['Decimal']
            protocol = row['Keyword']
            # Change to int, unless it is a range
            try:
                num = int(num)
                protocols_to_int[protocol.lower()] = num
            except ValueError:
                range_ints = num.split('-')
                for i in range(int(range_ints[0]), int(range_ints[1]) + 1):
                    protocols_to_int[protocol] = i
        return protocols_to_int


def create_ip_int_to_protocols():
    path = str(pathlib.Path(__file__).parent.absolute())
    int_to_protocols = dict()
    with open(path + '/ip_protocols.csv', newline='') as protocols:
        reader = csv.DictReader(protocols)
        for row in reader:
            num = row['Decimal']
            protocol = row['Keyword']
            # Change to int, unless it is a range
            try:
                num = int(num)
                int_to_protocols[num] = protocol.lower()
            except ValueError:
                range_ints = num.split('-')
                for i in range(int(range_ints[0]), int(range_ints[1]) + 1):
                    int_to_protocols[i] = protocol
        return int_to_protocols

# Brute Force search .... sort csv and FIX!
def MAC_to_manufacturer(address):
    """
    Takes a MAC Address and searches through CSV files from IEEE to find 
    manufacturer they belong to

    :param address: MAC Address, bytes separated with colon (:)
    :type address: String
    :return: String of manufacturer of device with provided MAC Address \
        Unknown if not found
    :rtype: String
    """
    path = str(pathlib.Path(__file__).parent.absolute())
    addr = "".join(address.split(":")).upper()
    # Look in 16 million host block assignment csv
    with open(path + '/mal.csv', newline='') as mal:
        reader = csv.DictReader(mal)
        for row in reader:
            if row['Assignment'] == addr[:6]:
                # Exists in other csvs - handed out in smaller blocks of 
                #  addresses
                if row['Organization Name'] == "IEEE Registration Authority":
                    break
                return row['Organization Name']

    # Look in 1 million host block assignment csv
    with open(path + '/mam.csv', newline='') as mam:
        reader = csv.DictReader(mam)
        for row in reader:
            if row['Assignment'] == addr[:7]:
                return row['Organization Name']

    # Look in 4096 host block assignment csv
    with open(path + '/mas.csv', newline='') as mas:
        reader = csv.DictReader(mas)
        for row in reader:
            if row['Assignment'] == addr[:9]:
                return row['Organization Name']

    return "Unknown Manufacturer"


def manufacturer_to_MAC(manufacturer):
    """
    Provides a list of MAC prefixes based off provided manufacturer

    :param manufacturer: Name of manufacturer
    :type manufacturer: String
    :return: list of strings of 3 byte MAC prefixes registered to that \
        manufacturer
    :rtype: list of Strings
    """
    macs = list()
    with open(path + '/mal.csv', newline='') as mal:
        reader = csv.DictReader(mal)
        for row in reader:
            if row['Organization Name'].lower().find(manufacturer.lower()) != -1:
                macs.append(row['Assignment'])
    return macs


def is_hex(string):
    """
    Determines if string consists solely of ascii characters that are \
        hexidecimal characters

    :param string: string to check if hex
    :type string: String
    :return: boolean representing if the string consists of only hex ascii \
        characters
    :rtype: Boolean
    """
    return all(c in 'abcdef0123456789' for c in string.lower())


def get_MAC(interface):
    """
    Finds MAC address of a network interface on the host
    Uses Unix tools ifconfig and grep
    Not supported on all Operating Systems, or all kernels

    :param interface: string of the interface to look for
    :type interface: String
    :return: string representing MAC address of interface \
    if OS does not support commands or interface not found, program \
    exits with code 1
    :rtype: String
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
    return val.strip().upper()


def get_IP(interface):
    """
    Finds IP of a network interface on the host
    Uses UNIX tools ifconfig, grep, and awk
    Not supported on all Operating Systems or all kernels

    :param interface: string of the interface to look for
    :type interface: String
    :return: string representing MAC address of interface \
    if OS does not support commands or interface not found, program exits with code 1
    :rtype: String
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

def get_IPv6(interface):
    """
    Finds IPv6 of a network interface on the host
    Uses UNIX tools ifconfig, grep, and awk
    Not supported on all Operating Systems

    :param interface: string of the interface to look for
    :type interface: String
    :return: string representing MAC address of interface \
    if OS does not support commands or interface not found, program exits with code 1
    :rtype: String
    """
    try:
        val = subprocess.check_output("ifconfig " + interface + " | grep -w inet6 | awk '{ print $2}'", shell=True,
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
    Takes address represented in string consisting of hex characters, MAC or 
    IPv6, and converts to bytes

    :param address:  addrss to convert
    :type address: String
    :return: bytes form of address
    :rtype: bytes
    """
    return bytes.fromhex(address.replace(':', '').replace('.', '').replace('-', ''))


def bytes_to_MAC(address):
    """
    Converts bytes form of MAC address to String form of MAC address

    :param address: Bytes form of MAC address
    :type address: bytes
    :return: String form of MAC Address
    :rtype: String
    """
    addr = address.hex()
    return (addr[0:2] + ":" + addr[2:4] + ":" + addr[4:6] + ":" + addr[6:8] + ":" + addr[8:10] + ":" + addr[
                                                                                                       10:12]).upper()


def is_valid_ipv4(address):
    """
    Determines if address if valid IPv4 address
    Checks that there are 4 octets, and values are between 0 and 255, inclusive

    :param address: value to check if valid IPv4 address
    :type address: String
    :return: boolean representing if address is a valid IPv4 address
    :rtype: Boolean
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
    :type address: String
    :return: boolean representing if address is a valid MAC address
    :rtype: Boolean
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
    :type address: String
    :return: int representing IP address
    :rtype: int
    :raise ValueError: if address is not  valid IPv4 addrss
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
    :type number: int
    :return: String of IPv4 address
    :rtype: String
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
    Calculates 16 bit checksum by 1's compliment addition between all 16 bit \
    words in message, and then taking the 1's compliment of the sum
    Formula same as defined for IPv4, TCP, and UDP

    :param message: takes header to create checksum
    :type message: bytes
    :return: 16 bit checksum
    :rtype: int
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

    :param src_ip: source ip
    :type src_ip: String
    :param dst_ip: destination ip
    :type dst_ip: String
    :param length: length of tcp segment, header included
    :type length: int
    :param protocol: L4 Protocol - currently only support tcp and udp
    :type protocol: String
    :param version: IP version, defaults to 4
    :type version: int
    :return: pseudoheader in bytes
    :rtype: bytes
    """
    ip_protocol = protocols_to_int.get(protocol.lower())
    if version == 4:
        return inet_aton(src_ip) + inet_aton(dst_ip) + ip_protocol.to_bytes(2, 'big') + length.to_bytes(2, 'big')
    elif version == 6:
        return IPv6Address(src_ip).packed + IPv6Address(dst_ip).packed + length.to_bytes(
            4, 'big') + ip_protocol.to_bytes(2, 'big')
    else:
        raise ValueError("Invalid version number")



# define these below the functions they are calling
protocols_to_int = create_ip_protocols_to_int()
int_to_protocol = create_ip_int_to_protocols()



