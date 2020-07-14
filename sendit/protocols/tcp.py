# Provides object of TCP protocol
__author__ = "Matt Baker"
__credits__ = ["Matt Baker"]
__license__ = "GPL"
__version__ = "1.0.2"
__maintainer__ = "Matt Baker"
__email__ = "mbakervtech@gmail.com"
__status__ = "Development"
from struct import pack, unpack
from sendit.helper_functions.helper import checksum, form_pseudo_header
class TCP:
    """
    Forms TCP Object from parameters
    :param src_prt: source TCP port
    :param dst_prt: destination TCP port
    :param src_ip: source IP address - used for creating pseudoheader to calculate checksum
    :param dst_ip: destination IP address - used for creating pseudoheader to calculate checksum
    :param window: window size
    :param payload: payload - in string format
    :param sqn:  sequence Number
    :param ack_num: Acknowledgement Number
    :param offset: byte offset of where data starts - default of 5
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
    :param mss: maximum segment size TCP option
    :param scaling: window scaling factor TCP option
    :param sack_permitted: boolean value of whether selective acknowledgments allowed - TCP option
    :param sack: tuple containing bytes, in order, to be passes as selective acknowledgments TCP option
    :param stamp: tuple containing timestamp value and time stamp error
    :param checksum - default set to 0 and calculated when as_bytes called if 0. If TCP object created from
                   parser function, set to checksum of captured segment and NOT recalculated in as_bytes unless set to 0
                   manually or by calling reset_calculated_fields function
    :raise ValueError when src_prt not between 0 and 65535 inclusive
    :raise ValueError when dst_port not between 0 and 65535 inclusive
    :raise ValueError when sqn not between 0 and 4294967295 inclusive
    :raise ValueError when ack_number not between 0 and 4294967295 inclusive
    :raise ValueError when window not between 0 and 4294967295 inclusive
    :raise ValueError when urg_pnt not between 0 and 4294967295 inclusive
    :raise ValueError when length of sack greater than 8
    :raise ValueError when sack contains odd number of values

    """

    def __init__(self, src_prt, dst_prt, src_ip, dst_ip, window, payload, sqn=0, ack_num=0, ns=False,
                 cwr=False, ece=False, urg=False, ack=False, psh=False, rst=False, syn=False, fin=False, urg_pnt=0,
                 version=4, mss=None, scaling=None, sack_permitted=None, stamp=None, sack=None, offset=5, checksum=0):

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
        if sack is not None:
            if len(sack) > 8:
                raise ValueError("sack must contain 8 or fewer values")
            if sack % 2 != 0:
                raise ValueError("sack must contain and even number of values - each pair the start and end values of "
                                 "a block")

        self.src_prt = src_prt
        self.dst_prt = dst_prt
        self.window = window
        self.sqn = sqn
        self.ack_num = ack_num
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
        self.checksum = checksum

        self.version = version
        self.offset = offset

        self.mss = mss
        self.scaling = scaling
        self.sack_permitted = sack_permitted
        self.stamp = stamp
        self.sack = sack

    def create_tcp_options(self):
        """
        Set TCP Header options
        mss, sack_permitted, and scaling only used during syn and ack of handshake
        sack (selective acknowledgment) value cannot be set during handhake
        Header option combinations are:
        mss, sack_permitted, scaling, and stamp (timestamp) during handshake - any combination of these 4
        timestamp and selective acknowledgement value during regular transmissions - any combination of these 2
        Depending on what combination of these are set depends on what order they are arranged in, along with
        nop (No-op) bytes to fit in 32 bit word

        TODO handle sack value
        :return: tuple consisting of bytes of options for this TCP segment and increase to options header
        """

        nop = 1  # nop value
        options = bytearray()
        offset_increase = 0
        # Exactly one 32-bit word, if set will always be firt
        if self.mss is not None:
            offset_increase += 1
            type = 2
            length = 4
            options += pack('!BBH', type, length, self.mss)

        # Format of options if sack_permitted and timestamp used
        if self.sack_permitted and self.stamp is not None:
            offset_increase  += 3
            # Add sack permitted first
            type = 4
            length = 2
            options += pack('!BB', type, length)


            # Add timestamp
            type = 8
            length = 10
            options += pack('!BBIIB', type, length, self.stamp[0], self.stamp[1], nop)


            # Format of options if scaling also used
            if self.scaling is not None:
                offset_increase += 1
                # Add scaling
                type = 3
                length = 3
                options += pack('!BBBB', nop, type, length, self.scaling)

        # Options format if sack_permitted and window scaling used but not timestamp
        if self.sack_permitted and self.scaling is not None and self.stamp is None:
            offset_increase += 2

            # Add sack permitted first
            type = 4
            length = 2
            options += pack('!BBBB', type, length, nop, nop)

            # Add window scaling
            type = 3
            length = 3
            options += pack('!BBBB', type, length, self.scaling, nop)

        # Options format if timestamp used but not sack_permitted and not sack (value)
        if self.stamp is not None and all(option is None for option in [self.sack_permitted, self.sack]):
            offset_increase += 3
            # Add timestamp
            type = 8
            length = 10
            options += pack('!BBIIBB', type, length, self.stamp[0], self.stamp[1], nop, nop)

            # Add window scaling if set
            if self.scaling is not None:
                type = 3
                length = 3
                options += pack('!BBBB', type, length, self.scaling, nop)

        # sack_permitted used by not window scaling or timestamp
        if self.sack_permitted and all(option is None for option in [self.scaling, self.stamp]):
            offset_increase += 1
            type = 4
            length = 2
            options += pack('!BBBB', type, length, nop, nop)

        # Scaling used but not timestamp or sack_permitted
        if self.scaling is not None and all(option is None for option in [self.scaling, self.stamp]):
            type = 3
            length = 3
            options += pack('!BBIIB', type, length, self.scaling, nop)

        # Selective Acknowledgment only is used
        if self.sack is not None and self.stamp is None:
            pass

        return (options, offset_increase) 

    def as_bytes(self):
        """
        Converts TCP to proper format of payload bytes to send
        self.payload is converted to bytes with str.encode(self.payload)
        :return: - bytes representation of TCP
        """

        # Creates bytes object of options, modifies offset value
        options = self.create_tcp_options()
        # Check if offset is manually set or set to default of 5
        # If set to default of 5, add in increase due to header options
        if self.offset == 5:
            self.offset += options[1]

        # Create int that holds offset and ns flag
        offset = self.offset << 4
        if self.ns:
            offset += 1

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

        # Convert payload
        # try to call as_bytes function for application layer - if protocol not supported, payload treated as ascii string.
        # If payload not string, it is assumed payload is already in bytes
        try:
            payload = self.payload.as_bytes()
        except AttributeError:
            try:
                payload = self.payload.encode()
            except AttributeError:
                payload = self.payload
        # Create pseudo header
        pseudo = form_pseudo_header(self.src_ip, self.dst_ip, len(payload) + (self.offset * 4), "tcp",
                                    version=self.version)

        # Check if checksum has been manually set

        if self.checksum == 0:
            self.checksum = checksum(pseudo + pack('!HHIIBBHH', self.src_prt, self.dst_prt, self.sqn,
                                                          self.ack_num, offset, flags, self.window, self.urg_pnt) +
                                                          options[0] + payload)
        return pack('!HHIIBBHHH', self.src_prt, self.dst_prt, self.sqn, self.ack_num, offset, flags, self.window, self.checksum, self.urg_pnt) + options[0] + payload


    def parse_options(option_bytes):
        # list of options to return. Values are, in order,
        # MSS, Window Scale, sack permitted, sack values, timestamp
        options = [None, None, None, None, None]
        i = 0
        while i < len(option_bytes):
            type_num = int.from_bytes(option_bytes[i:i+1], 'big' )
            # if type is end of options list
            if type_num == 0:
                i += 1
                continue
            # if type is noop
            elif type_num == 1:
                i +=1
                continue
            # if type is Maximum Segment size
            elif type_num == 2:
                options[0] = int.from_bytes(option_bytes[i+2:i+4], 'big')
                i +=4
                continue
            # if type is Window scale
            elif type_num == 3:
                options[1] = int.from_bytes(option_bytes[i+2:i+3], 'big')
                i+=3
                continue
            # if type is sack permitted
            elif type_num == 4:
                options[2] = True
                i+= 2
                continue
            # if type is sack. Currently is not supported
            elif type_num == 5:
                length = int.from_bytes(option_bytes[i+1:i+2], 'big')
                i+=length
                continue
            # if type is timestamp:
            elif type_num == 8:
                tstamp = (int.from_bytes(option_bytes[i+2:i+6], 'big'), int.from_bytes(option_bytes[i+6:i+1], 'big'))
                options[4] = tstamp
                i+= 10
        return options



    @classmethod
    def tcp_parser(cls, data, recursive=True):
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
        # Data starts after offset*4
        # If offset is 5, there are no options
        if offset != 5:
            option_bytes = data[20:(offset*4)]
            options = cls.parse_options(option_bytes)
        else:
            options = (None,None,None,None,None)

        if recursive:
            try:
                payload = data[offset*4:].decode("ascii")
            except UnicodeDecodeError:
                payload = data[offset*4:]
        else:
            payload = data[offset*4:]

        returnable = TCP(src, dst, "0.0.0.0", "0.0.0.0", window, payload, sqn=sqn, ack_num=ack_num,
                         ns=flag_bool[0], cwr=flag_bool[1], ece=flag_bool[2], urg=flag_bool[3], ack=flag_bool[4],
                         psh=flag_bool[5], rst=flag_bool[6], syn=flag_bool[7], fin=flag_bool[8], urg_pnt=urg_pnt,
                         checksum=checksum, offset=offset, mss=options[0], scaling=options[1], sack_permitted=options[2],
                         sack=options[3],stamp=options[4])

        return returnable
    
    def reset_calculated_fields(self):
        """
        Resets calculated fields for TCP - resets checksum and length
        """
        self.checksum = 0
        self.offset = 5
