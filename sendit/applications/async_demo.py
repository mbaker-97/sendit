import asyncio
from sendit.handlers.raw_nic import Async_Raw_NIC
from sendit.handlers.bytes_handler import Bytes_Listener
from sendit.handlers.ethernet_handler import EtherFrame_Listener
from sendit.handlers.arp_handler import  ARP_Listener
from sendit.handlers.ipv4_handler import IPv4_Listener
from sendit.helper_functions.helper import get_MAC, get_ip

async def main():
    loop = asyncio.get_event_loop()
    
    IPv4Listen = IPv4_Listener()
    ipv4_queue = IPv4Listen.recv_queue

    mappings = {get_ip("wlan0"): get_MAC("wlan0")}
    ARPListen = ARP_Listener(mappings=mappings, reply=False) 
    aqueue = ARPListen.recv_queue

    # Create EtherFrame_Listner and grab its queue
    queue_mappings = {"arp": [aqueue], "ipv4": [ipv4_queue]} 

    EListen = EtherFrame_Listener(queue_mappings = queue_mappings )
    equeue = EListen.recv_queue

    # Create Bytes_Listener and grab its queue
    bmapping = {"FF:FF:FF:FF:FF:FF": [equeue], get_MAC("wlan0"): [equeue]}
    BytesListen = Bytes_Listener(queue_mappings = bmapping)
    bqueue = BytesListen.recv_queue

    # Create Async_Raw_NIC
    nic = Async_Raw_NIC("wlan0", bqueue)
    await asyncio.gather(IPv4Listen.listen(), ARPListen.listen(), EListen.listen(), BytesListen.listen(), nic.a_recv(1518))

if __name__ == "__main__":

    asyncio.run(main())


