#!/usr/bin/python3
# Running on Class A network stores about 1GB of addresses!
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"

import os
import time
from sendit.protocols.arp import ARP
from sendit.protocols.etherframe import EtherFrame
from sendit.helper_functions.helper import MAC_to_manufacturer,is_valid_ipv4, is_valid_MAC, ip_to_int, get_MAC, get_ip, BROADCAST_MAC
from sendit.handlers.raw_nic import Raw_NIC
from socket import inet_ntoa
from threading import Thread
import random
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"

def ARP_recv(nic):
    """
    Function that receives and prints out ARP replies:  MAC address, IP address, and Manufacturer of MAC
    """
    print("MAC\t\t\tIP\t\tManufacturer")
    while True:
        data = nic.recv(1024)
        # Determine if we should more thourougly look through frame
        ethertype = data[12:14]
        # x08x06 is ARP
        if ethertype == b'\x08\x06':
            frame = EtherFrame.etherframe_parser(data)
            # Determine if reply
            if frame.payload.op == 2:
                mac = frame.payload.sha
                ip = frame.payload.spa
                print(mac + "\t" + ip + "\t" + MAC_to_manufacturer(mac))


def ARP_map(network, prefix, interface, mac, ip, rand=False, delay=0.0):
    """
    Sends out ARP requests across a network, effectively allowing a user to map out hosts on local subnet
    Can be used to root out hosts with duplicate IPs
    :param interface: String interface to send ARPs out of
    :param network: String of network IP address
    :param prefix: prefix of subnet
    :param mac: string MAC address of intended source of ARP requests
                Usually MAC of host sending out requests
                Could be spoofed MAC of another host for purpose of DOS, or so that sender and receiver are
                separate hosts working together
    :param ip: string IP address of intended source of ARP requests
                Usually IP of host sending out requests
                Can be spoofed for same reasons as MAC
    :param rand: boolean of whether to send ARP requests to targets randomly or in order
    :param delay: delay between requests in seconds. Be aware of host operating system's limitations on minimum sleep
                    time
    :raise TypeError if sock not valid Socket object
    :raise ValueError if prefix not between 8 and 32 inclusive
    :raies ValueError if delay is negative value
    :raise ValueError if network is not valid IPv4 addersss
    :raise ValueError if ip is not valid IPv4 address
    :raise ValueError if mac is not valid MAC address
    :return: None
    """
    # Do value and type checking:

    # Check if valid prefix
    if prefix < 8 or prefix > 32:
        raise ValueError("Prefix must be between 8 and 32")
    # Check if valid delay time
    if delay < 0:
        raise ValueError("delay must be non-negative")
    try:
        net = ip_to_int(network)
    except ValueError:
        raise ValueError("network must be valid ipv4 address")
    # Check if MAC is valid MAC address
    if not is_valid_MAC(mac):
        raise ValueError("MAC must be valid MAC address")
    if not is_valid_ipv4(ip):
        raise ValueError("ip must be valid ipv4 address")
    # Create two Raw_NICS, one to send and one to listen on
    nic_send = Raw_NIC(interface)
    nic_listen = Raw_NIC(interface)

    # Make list of all target IPs
    # Depending on prefix, may have to wait briefly, uses 1GB of RAM for class A networks (prefix=8)
    address_total = pow(2, 32 - prefix)
    addresses = list()
    for i in range(address_total):
        addresses.append(inet_ntoa((net + i).to_bytes(4, 'big')))

    # Start listening for responses
    Thread(target=ARP_recv, args=(nic_listen,)).start()
    # Wait 1 second for listener socket to be ready
    time.sleep(1)

    # Send arps
    frame = EtherFrame(BROADCAST_MAC, mac, "payload_here", ethertype="arp")
    if not rand:
        for address in addresses:
            payload = ARP(mac, ip, BROADCAST_MAC, address)
            frame.payload = payload
            nic_send.send(frame)

            if delay != 0:
                time.sleep(delay)
    # if random set
    else:
        for i in range(address_total):

            index = random.randint(0, address_total - i - 1)
            payload = ARP(mac, ip, BROADCAST_MAC, addresses[index])
            frame.payload = payload
            nic_send.send(frame)
            addresses.pop(index)

            if delay != 0:
                time.sleep(delay)

def print_banner():
    """
    prints pretty banner for ARP MAP
    """
    os.system("clear")
    print("\u001b[35;1m####################################################################")
    print("#####/  _  \\\______   \______   \###/     \\####/  _  \\\\______   \\###")
    print("####/  /_\  \|       _/|     ___/##/  \ /  \##/  /_\  \|     ___/###")
    print("###/    |    \    |   \|    |#####/    Y    \/    |    \    |#######")
    print("###\____|__  /____|_  /|____|#####\____|__  /\____|__  /____|#######")
    print("###########\/#######\/####################\/#########\/#############\u001b[0m")


if __name__ == "__main__":
    """
    Prints ARP MAP banner, asks for details needed to run, sends ARP requests to provided network
    Prints IP, MAC, and Manufactureer of machines that respond
    """
    print_banner()
    interface = input("\u001b[31;1mInterface: \u001b[32;1m")
    network = input("\u001b[31;1mNetwork: \u001b[32;1m")
    prefix = int(input("\u001b[31;1mPrefix: \u001b[32;1m"))
    rand = input("\u001b[31;1mRandom[y/n]: \u001b[32;1m")
    delay = float(input("\u001b[31;1mDelay (s): \u001b[32;1m"))

    rand_bool = rand.lower() == 'y'

    mac = get_MAC(interface)
    ip = get_ip(interface)

    ARP_map(network, prefix, interface, mac, ip, rand=rand_bool, delay=delay)
