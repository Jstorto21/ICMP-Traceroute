# Name: Joseph Storto
# Class: cs 372
# Tracerout Project

# Source References
# https://stackoverflow.com/questions/68198688/whats-a-good-starting-value-for-a-min-or-max-variable
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-0
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
# https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-11
# https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python
# https://medium.com/%40davho/understanding-traceroute-a-concise-guide-python-implementation-using-scapy-9a2221c9a50c
# https://www.redhat.com/en/blog/ping-traceroute-netstat


import os
from socket import *
import struct
import time
import select


class IcmpHelperLibrary:
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

    """Class helps with sending Echo Request, calculating statistics RTT and ping statistics"""

    def __init__(self):
        self.__RTT_list = []  # save all round RRT's for average
        self.__RTTSum = 0
        self.__RTTMax = float('-inf')  # saves max RRT
        self.__RTTMin = float('inf')  # save min RTT
        self.__packetsSent = 0  # count packets sent
        self.__packetsReceived = 0  # count packets received

    def incrementPacketsSent(self):
        self.__packetsSent += 1
        # print(f"[DEBUG] Packet Sent Count: {self.__packetsSent}")

    def incrementPacketsReceived(self):
        self.__packetsReceived += 1
        # print(f"[DEBUG] Packet Received Count: {self.__packetsReceived}")

    def updateRTT(self, RTT):
        """ Updates all RRT variables """
        self.__RTT_list.append(RTT)
        self.__RTTSum += RTT
        self.__RTTMax = max(self.__RTTMax, RTT)
        self.__RTTMin = min(self.__RTTMin, RTT)

    def calculatePacketLoss(self):
        """ Set % of packet loss """
        if self.__packetsSent == 0:
            return 100

        packetsLost = max(0, self.__packetsSent - self.__packetsReceived)
        return (packetsLost / self.__packetsSent) * 100

    def printRTTStats(self):
        """ Prints RTT statistics """
        lossRate = self.calculatePacketLoss()

        if len(self.__RTT_list) > 0:  # if there are RTT values
            avgRTT = self.__RTTSum / len(self.__RTT_list)  # get ave RTT
            print(f"\nPing Statistics:")
            print(
                f"  Packets: Sent = {self.__packetsSent}, Received = {self.__packetsReceived},"
                f" Lost = {self.__packetsSent - self.__packetsReceived} ({lossRate:.2f}% loss)")
            print(f"  RTT Stats: Min = {self.__RTTMin:.2f} ms, Max = {self.__RTTMax:.2f} ms, Avg = {avgRTT:.2f} ms")
        else:
            print("\nPing Statistics:")
            print(
                f"  Packets: Sent = {self.__packetsSent}, Received = {self.__packetsReceived}, "
                f"Lost = {self.__packetsSent - self.__packetsReceived} ({lossRate:.2f}% loss)")
            print("  No RTT data collected.")

    def sendPing(self, targetHost):
        """ Sends multiple ping requests and records statistics. """
        print(f"\nPinging {targetHost} with ICMP Echo Requests:")
        self.__sendIcmpEchoRequest(targetHost)  # sends echo type icmp to target
        self.printRTTStats()  # Print results after all pings

    class IcmpPacket:

        # IcmpPacket Class Scope Variables                                                                             #

        __icmpTarget = ""  # Remote Host
        __destinationIpAddress = ""  # Remote Host IP Address
        __header = b''  # Header after byte packing
        __data = b''  # Data after encoding
        __dataRaw = ""  # Raw string data before encoding
        __icmpType = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 225  # Time to live

        def __init__(self, icmpHelperInstance):
            """ variables for the helper instance """
            self._IcmpPacket__header = None  # saves icmp header
            self._IcmpPacket__data = None  # saves icmp raw data
            self.__icmpHelper = icmpHelperInstance  # reference

        __DEBUG_IcmpPacket = False  # Allows for debug output

        def getIcmpPacketHeader(self):
            return self._IcmpPacket__header

        def getIcmpPacketData(self):
            return self._IcmpPacket__data

        def getHeader(self):
            return self.__header

        def getData(self):
            return self.__data

        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #

        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #

        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)  # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum  # Rotate and add

            answer = ~checksum  # Invert bits
            answer = answer & 0xffff  # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  #  8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  #  8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()  # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()  # packHeader() and encodeData() transfer data to their respective bit
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()  # Result will set new checksum value
            self.__packHeader()  # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            # sequence number

            # set debug original data - sequence num, raw data, packet identifier
            icmpReplyPacket.setOriSeqNum(self.getPacketSequenceNumber())
            icmpReplyPacket.setOriRawData(self.getDataRaw())
            icmpReplyPacket.setOriPackIden(self.getPacketIdentifier())

            # set debug received data - sequence num, raw data, packet identifier
            icmpReplyPacket.setRecSeqNum(icmpReplyPacket.getIcmpSequenceNumber())
            icmpReplyPacket.setRecRawData(icmpReplyPacket.getIcmpData())
            icmpReplyPacket.setRecPackIden(icmpReplyPacket.getIcmpIdentifier())

            valid_res = True

            if icmpReplyPacket.getIcmpSequenceNumber() != self.getPacketSequenceNumber():
                print(f'Sequence number Error Expected: {self.getPacketSequenceNumber()} '
                      f'Received{icmpReplyPacket.getIcmpSequenceNumber()} ')
                valid_res = False
            else:
                icmpReplyPacket.setIsSeqNumValid(True)
            # packet identifier
            if icmpReplyPacket.getIcmpIdentifier() != self.getPacketIdentifier():
                print(f'Identifier number Error Expected: {self.getPacketIdentifier()} '
                      f'Received: {icmpReplyPacket.getIcmpIdentifier()}')
                valid_res = False
            else:
                icmpReplyPacket.setIsPacketIdentValid(True)
            # raw data
            if icmpReplyPacket.getIcmpData() != self.getDataRaw():
                print(f'Raw Data Error Expected: {self.getDataRaw()} Received: {icmpReplyPacket.getIcmpData()}')
                valid_res = False
            else:
                icmpReplyPacket.setIsRawDataValid(True)

            icmpReplyPacket.setIsValidResponse(valid_res)
            pass

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #

        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            """ Sends an ICMP Echo Request and processes the response. """

            if not self.__icmpTarget.strip() or not self.__destinationIpAddress.strip():
                self.setIcmpTarget("127.0.0.1")  # Default to localhost if target is invalid

            print(f"Pinging {self.__icmpTarget} ({self.__destinationIpAddress})")

            try:
                mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                mySocket.settimeout(self.__ipTimeout)
                mySocket.bind(("", 0))
                mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Set TTL

                # Send ICMP Echo Request
                try:
                    mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                except error as e:
                    print(f"Error sending packet: {e}")
                    return

                pingStartTime = time.time()

                # Wait for a response
                whatReady = select.select([mySocket], [], [], self.__ipTimeout)
                if not whatReady[0]:  # If no response received within the timeout
                    print("  Request timed out.")
                    return

                # Receive response
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                icmpType, icmpCode = struct.unpack("BB", recvPacket[20:22])

                # Dictionary of ICMP types and corresponding messages
                icmp_messages = {
                    0: "Echo Reply Successful",
                    3: {
                        0: "Destination Network Unreachable",
                        1: "Destination Host Unreachable",
                        2: "Protocol Unreachable",
                        3: "Port Unreachable",
                        4: "Fragmentation Needed",
                        5: "Source Route Failed",
                    },
                    11: {
                        0: "TTL expired in transit",
                        1: "Fragment reassembly time exceeded",
                    }
                }

                # Check if ICMP Type exists in dictionary
                if icmpType in icmp_messages:
                    if isinstance(icmp_messages[icmpType], dict):  # If it's a dict, check the code too
                        message = icmp_messages[icmpType].get(icmpCode, "Unknown ICMP Code")
                    else:
                        message = icmp_messages[icmpType]

                    print(
                        f"  TTL={self.getTtl()}    RTT={(timeReceived - pingStartTime) * 1000:.0f} ms    "
                        f"Type={icmpType}    Code={icmpCode}  {addr[0]} ({message})")

                    if icmpType == 0:  # type 0 increment count
                        self.__icmpHelper.incrementPacketsReceived()  # Track received packets
                        RTT = (timeReceived - pingStartTime) * 1000  # Calculate RTT
                        self.__icmpHelper.updateRTT(RTT)  # Update RTT statistics

                else:
                    print(f"  ICMP Type {icmpType} received, but it's not handled.")

            except timeout:
                print("  Request timed out.")
            except error as e:
                print(f"Socket error: {e}")
            finally:
                mySocket.close()  # close socket

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i + 1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #

    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #

        __recvPacket = b''
        __isValidResponse = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #

        def __init__(self, recvPacket, IcmpHelperInstance):
            self.__recvPacket = recvPacket
            self.__isSeqNumValid = False
            self.__isPackIdentValid = False
            self.__isRawDataValid = False
            self.__OriSeqNum = 0
            self.__OriRawData = 0
            self.__OriPackIden = 0
            self.__RecSeqNum = 0
            self.__RecRawData = 0
            self.__RecPackIden = 0
            self.__icmpHelper = IcmpHelperInstance

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters

        def getOriSeqNum(self):
            return self.__OriSeqNum

        def getOriRawData(self):
            return self.__OriRawData

        def getOriPackIden(self):
            return self.__OriPackIden

        def getRecSeqNum(self):
            return self.__RecSeqNum

        def getRecRawData(self):
            return self.__RecRawData

        def getRecPackIden(self):
            return self.__RecPackIden

        def getIsSeqNumValid(self):
            return self.__isSeqNumValid

        def getIsPacketIdentValid(self):
            return self.__isPackIdentValid

        def getIsRawDataValid(self):
            return self.__isRawDataValid

        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters

        def setOriSeqNum(self, oriSeqNum):
            self.__OriSeqNum = oriSeqNum

        def setOriRawData(self, oriRawData):
            self.__OriRawData = oriRawData

        def setOriPackIden(self, oriPackIden):
            self.__OriPackIden = oriPackIden

        def setRecSeqNum(self, recSeqNum):
            self.__RecSeqNum = recSeqNum

        def setRecRawData(self, recRawData):
            self.__RecRawData = recRawData

        def setRecPackIden(self, recPackIden):
            self.__RecPackIden = recPackIden

        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIsSeqNumValid(self, booleanValue):
            self.__isSeqNumValid = booleanValue

        def setIsPacketIdentValid(self, booleanValue):
            self.__isPackIdentValid = booleanValue

        def setIsRawDataValid(self, booleanValue):
            self.__isRawDataValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #

        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #

        def printResultToConsole(self, ttl, timeReceived, addr):
            """Prints results from ICMP packet, includes stats for TTL, RRT, Type, code identifier sequence number.
            Also has checks for packet errors"""
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            RTT = (timeReceived - timeSent) * 1000

            self.__icmpHelper.updateRTT(RTT)

            print(f"  TTL={ttl}    RTT={RTT:.0f} ms    Type={self.getIcmpType()}    Code={self.getIcmpCode()}  "
                  f"Identifier={self.getIcmpIdentifier()}    Sequence Number={self.getIcmpSequenceNumber()}   "
                  f"{addr[0]}")
            (
                ttl,
                (timeReceived - timeSent) * 1000,
                self.getIcmpType(),
                self.getIcmpCode(),
                self.getIcmpIdentifier(),
                self.getIcmpSequenceNumber(),
            )
            # check for seqnum error
            if self.getIsSeqNumValid() is False:
                print(f'[ERROR]  Sequence number mismatch! Expected: {self.getOriSeqNum()}, '
                      f'Received: {self.getIcmpSequenceNumber()}')
            # check for raw data error
            if self.getIsRawDataValid() is False:
                print(f'[ERROR]  Raw data mismatch! Expected: {self.getOriRawData()}, '
                      f'Received: {self.getIcmpData()}')
            # check for packet ident error
            if self.getIsPacketIdentValid() is False:
                print(f'[ERROR] Packet Identifier mismatch! Expected: {self.getOriPackIden()}, '
                      f'Received: {self.getIcmpIdentifier()}')

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = True  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for i in range(4):
            # Build packet
            icmpPacket = self.IcmpPacket(self)

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()  # Build IP

            self.incrementPacketsSent()

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

    def __sendIcmpTraceRoute(self, host):
        """Preforms traceroute functionality, calls send ICMP function, increases TTl and iterates RTT"""
        print(f"\nStarting Traceroute to {host}...\n")

        try:
            destination_ip = gethostbyname(host)  # Resolve target hostname to IP
        except error as e:
            print(f"Unable to resolve host: {e}")
            return

        max_hops = 225  # max ttl
        ttl = 1  # Start TTL at 1
        stop = False  # Condition to stop the loop

        # List to track RTTs for summary statistics
        rtt_list = []

        print(f"Traceroute to {host} ({destination_ip}), {max_hops} hops max\n")

        # creates new packet and loops until we hit hax hops or target IP
        while not stop and ttl <= max_hops:
            icmp_packet = IcmpHelperLibrary.IcmpPacket(self)  # create new icmp
            icmp_packet.setIcmpTarget(destination_ip)  # sent target IP
            icmp_packet.setTtl(ttl)  # set current TTL

            packet_identifier = os.getpid() & 0xffff  # Use process ID as identifier
            packet_sequence_number = ttl  # Use TTL as sequence number

            #  construct ICMP Echo Request packet
            icmp_packet.buildPacket_echoRequest(packet_identifier, packet_sequence_number)

            # Create sockets for sending and receiving
            receiver = self.__createReceiver()
            sender = self.__createSender(ttl)

            # Record time before sending packet
            start_time = time.time()

            try:  # send icmp to echo request
                sender.sendto(b''.join([icmp_packet.getIcmpPacketHeader(), icmp_packet.getIcmpPacketData()]),
                              (destination_ip, 0))  # format IMCP packet
                whatReady = select.select([receiver], [], [], 5)

                if not whatReady[0]:  # If no response
                    print(f"TTL={ttl:<3} *    *    *    Request timed out")
                else:  # recieve and record infor/stats
                    recvPacket, addr = receiver.recvfrom(1024)
                    time_received = time.time()
                    rtt = (time_received - start_time) * 1000  # Convert to ms
                    rtt_list.append(rtt)

                    icmpType, icmpCode = struct.unpack("BB", recvPacket[20:22])

                    # Handle different ICMP types
                    if icmpType == 0:  # Echo Reply (Destination reached)
                        print(f"TTL={ttl:<3} RTT={rtt:.2f} ms    {addr[0]}  (Destination Reached)")
                        stop = True  # Stop traceroute when destination is reached

                    elif icmpType == 11:  # Time Exceeded
                        print(
                            f"TTL={ttl:<3} RTT={rtt:.2f} ms    Type=11  Code={icmpCode}  (Time Exceeded)    {addr[0]}")

                    elif icmpType == 3:  # Destination Unreachable
                        error_messages = {
                            0: "Network Unreachable",  # RFC 792
                            1: "Host Unreachable",  # RFC 792
                            2: "Protocol Unreachable",  # RFC 792
                            3: "Port Unreachable",  # RFC 792
                            4: "Fragmentation Needed and Don't Fragment was Set",  # RFC 792
                            5: "Source Route Failed",  # RFC 792
                            6: "Destination Network Unknown",  # RFC 1122
                            7: "Destination Host Unknown",  # RFC 1122
                            8: "Source Host Isolated",  # RFC 1122
                            9: "Communication with Destination Network is Administratively Prohibited",  # RFC 1122
                            10: "Communication with Destination Host is Administratively Prohibited",  # RFC 1122
                            11: "Destination Network Unreachable for Type of Service",  # RFC 1122
                            12: "Destination Host Unreachable for Type of Service",  # RFC 1122
                            13: "Communication Administratively Prohibited",  # RFC 1812
                            14: "Host Precedence Violation",  # RFC 1812
                            15: "Precedence Cutoff in Effect"  # RFC 1812
                        }
                        print(
                            f"TTL={ttl:<3} RTT={rtt:.2f} ms    Type=3   Code={icmpCode}  "
                            f"({error_messages.get(icmpCode, 'Unreachable Error')})    {addr[0]}"
                        )

                        if addr[0] == destination_ip:
                            stop = True  # stop if unreliable message is from Target

                    else:
                        print(
                            f"TTL={ttl:<3} RTT={rtt:.2f} ms    Unknown ICMP Type={icmpType}  Code={icmpCode} {addr[0]}")

            except timeout:
                print(f"TTL={ttl:<3} *    *    *    Request timed out (Timeout Exception)")
            except error as e:
                print(f"Socket error: {e}")
            finally:
                receiver.close()
                sender.close()

            ttl += 1  # Increment TTL to move to the next TTL

        # Display stats
        if rtt_list:
            print("\nTraceroute Statistics:")
            print(f"Min RTT: {min(rtt_list):.2f} ms")
            print(f"Max RTT: {max(rtt_list):.2f} ms")
            print(f"Avg RTT: {sum(rtt_list) / len(rtt_list):.2f} ms")

        print("\nTraceroute complete.\n")

    def __createReceiver(self):
        """Creates a receiver socket for listening to ICMP replies"""
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        sock.settimeout(2)  # 2-second timeout
        try:
            sock.bind(("", 0))
        except error as e:
            print(f"Error binding receiver socket: {e}")
        return sock

    def __createSender(self, ttl):
        """Creates a sender socket for sending ICMP requests"""
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)  #
        sock.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))  # Set TTL
        return sock

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("200.10.227.250")  # type 11 and 3 appear
    icmpHelperPing.traceRoute("gaia.cs.umass.edu")  # just type 11
    # icmpHelperPing.traceRoute("33.11.0.200")
    # icmpHelperPing.traceRoute("172.67.20.89")  # type 11 then type 0
    # icmpHelperPing.traceRoute("210.152.243.243")


if __name__ == "__main__":
    main()
