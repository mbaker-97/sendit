Sendit Documentation
==================================
Sendit is a Python library for handcrafting, sending, and receiving packets. You can modify any value in Ethernet, ARP, IPv4, IPv6, TCP, and UDP protocols and send it. This allows you to send and receive data as a different MAC and/or IP address, do things such as mapping out a network using ARP, modify values to prevent OS fingerprinting, and so much more. While Sendit works at layers 2 to 4, meaning we are working with frames, packets, and segments, for purposes of simplicity in this documentation all units of data will be referred to as packets, their layer specified by the protocol being discussed. 

.. toctree::
   :maxdepth: 3
   :caption: Contents:

Project Info
============
* Github: https://github.com/mbaker-97/sendit
* PyPi: https://pypi.org/project/sendit/


Installing
==========
Install with pip

.. code-block:: bash

    pip install sendit==1.0.6

Basics
======
Every protocol layer is its own object. To create a datagram, we start by creating the highest layer object we are working with, then creating the next highest, and passing the first object to the second, and so on.
For example:

.. code-block:: python

    from sendit.protocols.EtherFrame import EtherFrame
    from sendit.protocols.IPv4 import IPv4
    from sendit.protocols.TCP import TCP

    payload = "The quick brown fox jumps over the lazy dog"  # String payload
    l4_tcp = TCP(50000, 50001, "127.0.0.1", "127.0.0.1", 1024, payload)  # Change 1st ip to yours, 2nd to target.
    # Creates IPv4 packet:
    l3 = IPv4("127.0.0.1", "127.0.0.1", l4_tcp, protocol="tcp")  # Change 1st ip to yours, 2nd to target
    # Creates Etherframe:
    l2 = EtherFrame("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55", l3)  # Change 1st mac to yours, 2nd to target

In the above example, l2, the EtherFrame, contains l4_tcp, a TCP object, inside l3, an IPv4 object.

Sending Data
============
Now that you know how to create the data, how do you send it? Sendit has a class called Raw_NIC. Raw_NIC is a wrapper class around a raw socket. All protocols have a as_bytes() function, which turns the data contained in the objects into their properly formatted bytes ready to send on the line. Calling a lower protocol's as_bytes function calls all higher protocols as_bytes functions. To take the above example, and to expand it. Using a Raw_NIC's send function automatically calls the as_bytes function of the object passed into it,

.. code-block:: python

    from sendit.protocols.EtherFrame import EtherFrame
    from sendit.protocols.IPv4 import IPv4
    from sendit.protocols.TCP import TCP
    from sendit.handlers.raw_nic import Raw_NIC

    payload = "The quick brown fox jumps over the lazy dog"  # String payload
    l4_tcp = TCP(50000, 50001, "127.0.0.1", "127.0.0.1", 1024, payload)  # Change 1st ip to yours, 2nd to target.
    # Creates IPv4 packet:
    l3 = IPv4("127.0.0.1", "127.0.0.1", l4_tcp, protocol="tcp")  # Change 1st ip to yours, 2nd to target
    # Creates Etherframe:
    l2 = EtherFrame("AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55", l3)  # Change 1st mac to yours, 2nd to target
    nic = Raw_NIC("lo") # Creates raw_nic on loopback interface
    nic.send(l2)

Advanced Usage
==================

For advanced usage, please read through the documentation of the modules to get a full idea of what each class offers

* :ref:`genindex`
* :ref:`modindex`
