"""Creates class that listens and responds to Layer 4 TCP"""
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.8"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from ipaddress import ip_address, AddressValueError
from sendit.protocols.tcp import TCP
from sendit.handlers.handler import Handler
from os import urandom

class TCP_Handler(Handler):

    """
    Class that handles the TCP protocol
    :param ports: list of ports to listen on
    :type ports: list of ints
    :param conns: list of ports that this handler already has a connection with, defualts to 0
    :type conns: list of tuples in form of (src ip, dst_ip, src_prt, dst_prt)
    :param send_up: asyncio.Queue OR dictionary of queues to put items in to go to higher layers
    :type send_up: asyncio.Queue or dictionary of asyncio.queues
    :param send_down : asyncio.Queue to put items in to go to lower layers
    :type send_down: asyncio.Queue
    :param recv_up: asyncio.Queue to receive items from higher layers
    :type recv_up: asyncio.Queue
    :param recv_down: asyncio.Queue to receive items from lower layers
    :type recv_down: asyncio.Queue
    """

    # TODO - provide ability to have range of ports
    def __init__(self, ports, send_up=None, send_down=None, recv_up=None, recv_down=None, conns = list()):
        """
        Constructor for TCP_Handler
        """
        self.ports = ports
        # list of ports that have a full connection
        self.conns = conns

        # dictionary mapping connection states to port numbers
        # syn - has syn of 3 way handshake
        # synack - has syn+ack
        # full - handshake has been succesfully performed
        # TODO - add teardown states
        self.conn_states = dict()

        super().__init__(send_up=send_up, send_down=send_down, recv_up=recv_up, recv_down=recv_down)

    # TODO - Find way to determine options
    # TODO - Find way to handle incoming options
    async def handle_handshake(self, frame):
        """
        This handles TCP handshake
        :param frame: EtherFrame that contains TCP object to handle 
        :type frame: EtherFrame
        """
        packet = frame.payload
        segment = packet.payload
        dst_prt = segment.dst_prt
        src_prt = segment.src_prt
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip

        # Flag used to note that we just received final ack, let higher queue know
        # Instead of sending frame in send_queue
        finished = False

        connection_descriptor = (src_ip, dst_ip, src_prt, dst_prt)
        conn = self.conn_states.get(connection_descriptor)

        # Swap port numbers and ips for checksum
        segment.dst_prt, segment.src_prt = segment.src_prt, segment.dst_prt
        segment.dst_ip, segment.src_ip = segment.src_ip, segment.dst_ip

        if conn is None:
            if segment.syn and not segment.ack:
                # Update connection status for when we send syn/ack
                self.conn_states[connection_descriptor] = "synack"

                # Get cryptographically secure random int for sqn number
                sqn = int.from_bytes(urandom(4), 'big')
                # Set sequence number to above number, set ack_num to incoming
                # sqn + 1
                segment.sqn, segment.ack_num = sqn, segment.sqn + 1

                # set ack
                segment.ack = True

                # Reset calculated fields
                segment.reset_calculated_fields()
            else:
                # Send reset
                segment.rst, segment.syn, segment.ack = True, False, True

        # Syn has already been sent, check if this is syn ack
        elif conn == "syn":
            if segment.syn and segment.ack:

                self.conn_states[connection_descriptor] = "full"
                self.conn.append(connection_descriptor)

                # Set sqn to false, set sqn and ack_num
                segment.syn = False
                segment.ack_num, segment.sqn = segment.sqn + 1, segment.ack_num
                

            else:
                # Send reset
                segment.rst, segment.syn = True, False 

        # We already have synack, should be receiving final ack of handshake
        elif conn == "synack":
            if not segment.syn and segment.ack:
                self.conn_states[connection_descriptor] = "full"
                self.conn.append(connection_descriptor)
                finished = True

            else:
                # Send reset
                segment.rst, segment.ack = True, False 

        if not finished:
            await self.send_down.put(frame)
        else:
            # Put some kind of info in queue for higher layer that connection is ready
            pass

        

    async def listen(self):
        """
        Listen for frames coming in on queue to parse the TCP objects inside

        :param queue: Queue to listen in on
        :type queue: Queue object
        """
        recv_queue = self.recv_down
        while True:
            frame = await recv_queue.get()
            packet = frame.payload
            segment = packet.payload
            segment = TCP.tcp_parser(segment, recursive=False)
            port_num = segment.dst_prt

            # Check if we should be listening on this port number
            print(segment)
            if port_num in self.ports:
                # Check if we have a connection
                src_ip = packet.src
                dst_ip = pack.dst
                src_prt = segment.dst
                dst_prt = port_num

                connection_descriptor = (src_ip, dst_ip, src_prt, dst_prt)

                if connection_descriptor in self.conns:
                    pass

                # There is no full connection. Check state of connection
                # TODO - handle when send_queue not provided in constructor
                else:
                    
                    conn_state = self.conn_states.get(connection_descriptor)
                    # Another machine is sending data without having a connection
                    if conn_state is None and not segment.sync:
                        # TODO - send reset? Have to decide... maybe param if reset or not
                        pass
                    # Set up connection
                    else:
                        handle_handshake(frame)


    async def await_from_higher(self):
        """
        Wait for frames from higher layers that needs TCP header adjusted
        Swaps src and destination ports and ips (for checksum) \
                and resets length and checksum
        """

        frame = await self.incoming_higher_queue.get()
        segment = frame.payload.payload
        # Swap source and destination
        segment.dst_prt, segment.src_prt = segment.src_prt, segment.dst_prt
        segment.dst_ip, segment.src_ip = segment.src_ip, segment.dst_ip
        # Reset length and checksum fields so that they will be calculated when sent
        segment.reset_calculated_fields()
        await self.send_queue.put(frame)

