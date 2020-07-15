__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.4"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit import *
from time import sleep
from sendit.protocols.arp import *
from queue import Queue
from threading import *
class ARP_Listener():
    
    def __init__(self,queue, reply=True):
        self.reply = reply
        self.queue = queue

    def listen(self):
       #  arp =  ARP.arp_parser(arp_bytes) 
        while True:
            if not self.queue.empty():
                arp = self.queue.get()
                print(arp)
            # TODO implement reply
            # Will likely use arugments of mac to ip mappings for reply

