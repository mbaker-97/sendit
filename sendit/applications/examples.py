# Provides example usage of the sendit module
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.handlers import raw_nic
from sendit.protocols.tcp import TCP
from sendit.protocols.udp import UDP
from sendit.protocols.arp import ARP
from sendit.protocols.ipv4 import IPv4
from sendit.protocols.ipv6 import IPv6
from sendit.protocols.etherframe import EtherFrame
from sendit.helper_functions.helper import *
if __name__ == '__main__':
    # Example usage here:
    # Need help?
    # ethernet interfaces often in format of eth0
    # wireless interfaces often in format of wlan0
    # To find your MAC: sudo ifconfig <interface> | grep -Eo ..\(\:..\){5}
    # Or call provided method get_mac(interface)
    # To find your IP: sudo ifconfig eth0 | grep -w inet | awk '{print $2}'
    # Or call provided method get_ip(interface)
    # To find your interface name use sudo ifconfig or sudo ip addr show

    # Example 1: Standard Usage

    # Uncomment code from here
    payload = "The quick brown fox jumps over the lazy dog"  # String payload
    nic = raw_nic.Raw_NIC("lo")  # Create Raw_NIC - replace interface name with your interface
    # Creates TCP segment. IPs needed to calculate checksum:
    l4_tcp = TCP(50000, 50001, "127.0.0.1", "127.0.0.1", 1024, payload, mss=62500, scaling = 127, sack_permitted=True)  # Change 1st ip to yours, 2nd to target.
    # Creates IPv4 packet:
    l3 = IPv4("127.0.0.1", "127.0.0.1", l4_tcp, protocol="tcp")  # Change 1st ip to yours, 2nd to target
    # Creates Etherframe:
    l2 = EtherFrame("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55", l3)  # Change 1st mac to yours, 2nd to target
    nic.send(l2)  # Send payload - open up Wireshark to see your payload
    # To Here
    l22 = EtherFrame.etherframe_parser(l2.as_bytes())
    nic.send(l22)  # Check that recreated parsed data looks the same

    # Example 2 - change payload to use UDP

    # Uncomment code from here
    l4_udp = UDP(50000, 50001, "127.0.0.1", "127.0.0.1", payload)  # Create UDP object
    l2.payload.payload = l4_udp  # Assign UDP object as Etherframe's payload's payload - payload of IPv4 object
    l2.payload.reset_calculated_fields()  # Reset calculated fields for IPv4 object - length and checksum
    l2.payload.protocol = "udp"  # Set IPv4 object's protocol to udp
    nic.send(l2)  # Send new frame with UDP segment
    # To Here

    # Example 3 - demonstrate as_bytes and parser functions
    # as_bytes turns objects into bytes ready to be sent on wire
    # Each class' parser function creates a new object from a byte string - usually raw bytes captured from nic
    # Each parser function parses its layers bytes, and passes the remaining bytes to the parser function of the next
    # layer, where the final layer finally returns, similiar to recursion
    # Each as_bytes function works the same way, where each object's to payload converts it's information to bytes,
    # and then calls the next layer's (the current layer's payload) as_bytes function
    # Uncomment from here
    l22 = EtherFrame.etherframe_parser(l2.as_bytes())
    nic.send(l22)  # Check that recreated parsed data looks the same
    # To Here

    # Example 4 - change payload to send ARP request

    # Uncomment code from here
    # Creates ARP request to find IP Change 1st MAC to your MAC, 1st IP to yours, 2nd IP to IP you are asking about
    arp = ARP("AA:BB:CC:DD:EE:FF", "192.168.1.1", BROADCAST_MAC, "192.168.1.2")
    l2.payload = arp # Sets l2 payload to ARP
    l2.etype = "arp" # Sets Ethertype to ARP
    nic.send(l2) # Send new frame with ARP Request - open Wireshark to look for response!
    # To Here

    # Example 5 - change payload to use tcp over IPv6
    # Uncomment from here
    l4_tcp.reset_calculated_fields()  # reset calculated fields of TCP (length, checksum)
    l4_tcp.version = 6  # Switch IP version TCP is set to. If creating new TCP object, can be set on creation
    l4_tcp.src_ip = "::1"  # Set IPv6 Source address for UDP pseudoheader creation
    l4_tcp.dst_ip = "::1"  # Set IPv6 Destination address for UDP pseudoheader creation
    l3_6 = IPv6("0000:0000:0000:0000:0000:0000:0000:0001", "::1", l4_tcp)  # Create IPv6 object. Note capable of taking IPv6 addresses in different formats
    l2.payload = l3_6  # switch payload of EtherFrame to IPv6 object
    l2.etype = "ipv6"  # switch ethertype of etherframe to IPv6 type
    nic.send(l2)  # Send it!
    # To here

    # Example 6 - change payload to use udp over IPv6
    # Uncomment from here
    l4_udp.reset_calculated_fields()  # Reset calculated fields (length, checksum)
    l4_udp.version = 6  # Switch IP version UDP is set to. If creating new UDP object, can be set on creation
    l4_udp.src_ip = "::1"  # Set IPv6 Source address for UDP pseudoheader creation
    l4_udp.dst_ip = "::1"  # Set IPv6 Destination address for UDP pseudoheader creation
    l3_6.payload = l4_udp  # Assign the UDP object as the IPv6 object's payload
    l3_6.next = "udp"  # Switch the protocol held within IPv6 object
    l3_6.reset_calculated_fields()  # Reset calculated fields (length)
    nic.send(l2)  # Send it!
    # To here

