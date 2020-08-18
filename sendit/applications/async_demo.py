import asyncio

from asyncio import Queue
from sendit.handlers.raw_nic import Async_Raw_NIC
from sendit.handlers.bytes_handler import Bytes_Handler
from sendit.handlers.ethernet_handler import EtherFrame_Handler
from sendit.handlers.arp_handler import  ARP_Handler
from sendit.handlers.ipv4_handler import IPv4_Handler
from sendit.handlers.ipv6_handler import IPv6_Handler
from sendit.handlers.udp_handler import UDP_Handler
from sendit.handlers.tcp_handler import TCP_Handler
from sendit.helper_functions.helper import get_MAC, get_IP

async def main():

    ###############################Create Queues Here###########################
    # Used as nic.send_up and byte.recv_down
    nic_to_bytes = asyncio.Queue()
    # Used as nic.recv_up and byte.send_down
    bytes_to_nic = asyncio.Queue()
    
    # Used as bytes.send_up and ether.recv_down
    bytes_to_ether = asyncio.Queue()
    # Used as bytes.recv_up and ether.send_down
    ether_to_bytes = asyncio.Queue()

    # Used as ether.send_up and ipv4.recv_down
    ether_to_ipv4 = asyncio.Queue()
    # Used as ether.recv_up and ipv4.send_down
    ipv4_to_ether = asyncio.Queue()

    # Used as ether.send_up and ipv6.recv_down
    ether_to_ipv6 = asyncio.Queue()
    # Used as ether.recv_up and ipv6.send_down
    ipv6_to_ether = ipv4_to_ether

    arp_to_ether = ipv4_to_ether
    ether_to_arp = asyncio.Queue()

    udp_to_ipv4 = asyncio.Queue()
    ipv4_to_udp = asyncio.Queue()


    tcp_to_ipv4 = udp_to_ipv4
    ipv4_to_tcp = asyncio.Queue()

    
    ############################################################################


    interface = "wlp1s0"
    ip = get_IP(interface)
    mac = get_MAC(interface)

    TCP_handler = TCP_Handler(ports=[22,80,443], send_down = tcp_to_ipv4, recv_down = ipv4_to_tcp)
    UDP_handler = UDP_Handler(ports=[53], send_down = udp_to_ipv4, recv_down = ipv4_to_udp)

    ipv4_mappings = {ip + "_udp": [ipv4_to_udp], ip + "_tcp": [ipv4_to_tcp]}
    
    IPv4_handler = IPv4_Handler(send_down=ipv4_to_ether, recv_down=ether_to_ipv4, send_up=ipv4_mappings)
    IPv6_handler = IPv6_Handler(send_down=ipv6_to_ether, recv_down=ether_to_ipv6)

    mappings = {ip: mac}
    ARP_handler = ARP_Handler(mappings=mappings, reply=False, recv_up=ether_to_arp, send_down = arp_to_ether) 

    # Create EtherFrame_Listner and grab its queue mappings
    queue_mappings = {"arp": [ether_to_arp], "ipv4": [ether_to_ipv4], "ipv6": [ether_to_ipv6]} 

    E_Handler = EtherFrame_Handler(send_up=queue_mappings, recv_down=bytes_to_ether, send_down=ether_to_bytes )

    # Create Bytes_Listener and grab its queue
    bmapping = {"FF:FF:FF:FF:FF:FF": [bytes_to_ether], mac:[bytes_to_ether]}
    B_Handler = Bytes_Handler(send_up = bmapping, send_down = bytes_to_nic, recv_up = ether_to_bytes, recv_down = nic_to_bytes)

    # Create Async_Raw_NIC
    nic = Async_Raw_NIC(interface, send_up=nic_to_bytes, recv_up=bytes_to_nic)

    await asyncio.gather(TCP_handler.listen(), UDP_handler.listen(), IPv4_handler.listen(), IPv6_handler.listen(), ARP_handler.listen(), E_Handler.listen(), B_Handler.listen(), nic.a_recv(1518))

if __name__ == "__main__":

    asyncio.run(main())

