#!/bin/python3
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.4"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from sendit.helper_functions.helper import *
from sendit.handlers.ethernet_handler import Ethernet_Listener
from sendit.helper_functions.helper import *

if __name__ == "__main__":
    interface = "wlan0"
    macs = [get_MAC(interface), BROADCAST_MAC]
    listener = Ethernet_Listener(macs,ipv4=False)
    listener.listen(interface)


