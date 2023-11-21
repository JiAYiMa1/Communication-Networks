"""A Receiver for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201


import os
import argparse
import time
from scapy.packet import Packet
from scapy.fields import BitEnumField, BitField, ShortField, ByteField, ConditionalField
from udpsocket import receiver as udp_receiver
from udpsocket import log
from copy import deepcopy


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: DATA or ACK
        fin: FIN flag
        sack: sack support
        len: payload length
        hlen: header length
        num: sequence/ACK number
        win: sender/receiver window size
    """

    name = "GBN"
    fields_desc = [
        BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
        BitField("padding", 0, 5),
        BitField("fin", 0, 1),
        BitField("sack", 0, 1),
        ShortField("len", None),
        ByteField("hlen", 0),
        ByteField("num", 0),
        ByteField("win", 0),
        ConditionalField(ByteField("num_blocks", 0), lambda pkt: pkt.hlen > 6),
        ConditionalField(ByteField("left_edge1", 0), lambda pkt: pkt.hlen > 6),
        ConditionalField(ByteField("block_len1", 0), lambda pkt: pkt.hlen > 6),
        ConditionalField(ByteField("padding2", 0), lambda pkt: pkt.hlen > 9),
        ConditionalField(ByteField("left_edge2", 0), lambda pkt: pkt.hlen > 9),
        ConditionalField(ByteField("block_len2", 0), lambda pkt: pkt.hlen > 9),
        ConditionalField(ByteField("padding3", 0), lambda pkt: pkt.hlen > 12),
        ConditionalField(ByteField("left_edge3", 0), lambda pkt: pkt.hlen > 12),
        ConditionalField(ByteField("block_len3", 0), lambda pkt: pkt.hlen > 12),
    ]


class GBNReceiver:
    """Receiver implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        socket: UDP Socket with the already established connection
        n_bits: number of bits used to encode sequence number
        out_file: Name of output file
        timeout: timeout before retransmitting the final FIN+ACK.
        max_win: The maximum receiver window, used only for Congestion Control (Task 4)
        chunk_size: Size of a payload.
    """

    def __init__(self, socket, n_bits, out_file, timeout, max_win, chunk_size):
        """Initialize the automaton."""
        self.socket = socket
        self.win = 0
        self.max_win = max_win
        self.n_bits = n_bits
        self.next = 0
        self.out_file = out_file
        self.timeout_duration = timeout
        self.timeout_at = None

        ############### auxiliary variables ###############
        self.o3buffer = {}    # out-of-order buffer
        self.fin_mark = 0
        self.count = 0
        self.SACK = 0
        self.left_edge = []
        self.block_len = []
        self.win_start_fin = 0
        self.win_end_fin = 0
        self.received_fin = 0

    def send(self, pkt):
        """Send a packet to the receiver via the UDP connection."""
        self.socket.send(pkt)

    def run(self):
        """Run the state machine."""
        state, *args = (self.BEGIN,)
        try:
            while True:
                ret = state(*args)
                state, *args = ret if isinstance(ret, tuple) else (ret,)
        except StopIteration:
            pass

    def BEGIN(self):
        """Start state of the automaton."""
        return self.WAIT_SEGMENT

    def END(self):
        """End state of the automaton."""
        log("Receiver closed")
        raise StopIteration("State machine reached the final state.")

    def WAIT_SEGMENT(self):
        """Waiting state for new packets."""
        pkt = self.socket.receive()

        # check if we have received a new packet
        if pkt is not None:
            return self.DATA_IN, GBN(pkt)

        # sleep for a short amount of time, to reduce the stress on the system.
        # please, leave this as it is!
        time.sleep(0.001)
        return self.WAIT_SEGMENT

    ######## auxiliary function for task 2.1 ########
    def distance(self, u: int, v: int) -> int:
        """
        This function calculates the "distance" between the two packets with the segment number u and v.

        input: u : int, the sequence number of the packet transmitted beforehand
               v : int, the sequence number of the packet transmitted afterwards
    
        output: dist: int, the distance between the two payloads in packets when they are stored in queue.
        """       
        if u >= v:
            v += (1 << self.n_bits)
        dist = v - u
        return dist
    #################################################


    def DATA_IN(self, pkt):
        """State for incoming data."""
        

        num = pkt.getlayer(GBN).num
        payload = bytes(pkt.getlayer(GBN).payload)
        self.fin_mark = pkt.getlayer(GBN).fin

        # check if segment is a data segment
        if pkt.getlayer(GBN).type != 0:
            # we received an ACK while we are supposed to receive only
            # data segments
            log.error("ERROR: Received ACK segment: %s", pkt.show())
            return self.WAIT_SEGMENT

        # update the window
        self.win = pkt.getlayer(GBN).win

        # update the SACK mode
        self.SACK = pkt.getlayer(GBN).sack 

        ################################################################
        # Task 1.3:                                                    #
        # Check if the sequence number is the next expected sequence   #
        # number. If so, increment the next expected sequence number   #
        # and write the content to the output file. In order to append #
        # data to a file, use the following code:                      #
        #                                                              #
        #     with open(self.out_file, "ab") as file:                  #
        #         file.write(payload)                                  #
        #                                                              #
        ################################################################
        if num == self.next:
            self.next = (self.next + 1) % (1 << self.n_bits)
            with open(self.out_file, "ab") as file:
                file.write(payload)
            while self.next in self.o3buffer.keys():
                log("have oyou enter this?")
                next_payload, next_fin = self.o3buffer[self.next]
                with open(self.out_file, "ab") as file:
                    file.write(next_payload)
                del self.o3buffer[self.next]
                self.next = (self.next + 1) % (1 << self.n_bits)
                if next_fin == 1:     # why not ? => and not self.o3buffer:
                    self.fin_mark = 1
                    break
                else:
                    self.fin_mark = 0

        ################################################################
        # Task 2.1:                                                    #
        # Implement an out-of-order buffer to store segments that we   #
        # can use in the future. When receiving in-order segments,     #
        # check the out-of-order buffer if the following segments are  #
        # already received. If so, write them to the file and remove   #
        # them from the out-of-order buffer.                           #
        # Also adapt the FIN+ACK part to support cases in which e.g.,  #
        # the second-to-last packet is lost but you already received   #
        # the last packet with the FIN flag.                           #
        ################################################################
        elif self.distance(self.next, num) < pkt.getlayer(GBN).win:
            if num not in self.o3buffer.keys():
                if self.received_fin:
                    if self.win_start_fin < self.win_end_fin:
                        if num >= self.win_start_fin and num <= self.win_end_fin:
                            self.o3buffer[num] = (payload, pkt.getlayer(GBN).fin)
                    elif self.win_start_fin > self.win_end_fin:
                        if num >= self.win_start_fin or num <= self.win_end_fin:
                            self.o3buffer[num] = (payload, pkt.getlayer(GBN).fin)
                else:
                    if pkt.getlayer(GBN).fin:
                        self.received_fin = 1
                        self.win_end_fin = num
                        self.win_start_fin = (num + (1 << self.n_bits) - pkt.getlayer(GBN).win + 1) % (1 << self.n_bits)
                    self.o3buffer[num] = (payload, pkt.getlayer(GBN).fin)
            #else:
            #   assert(payload == self.o3buffer[num])  # why not? 
            self.fin_mark = 0

        else:
            self.fin_mark = 0  
        ################################################################
        # Task 3.1:                                                    #
        # First add the optional SACK header from the assignment text  #
        # in the GBN class.                                            #
        # If the SACK flag is set on the packet, compute the SACK      #
        # header and answer with that specific header.                 #
        ################################################################

        if self.fin_mark == 1:
            # The data packet has the FIN flag set. Send a FIN ACK back, and change to the
            # FIN_WAIT state.

            log("Sending FIN+ACK: %s", self.next)
            self.send(GBN(type="ack", fin=1, sack=0, len=0, hlen=6, num=self.next, win=self.max_win))

            ################################################################
            # Task 1.5:                                                    #
            # Setup the retransmission timeout.                            #
            ################################################################
            self.timeout_at = time.time() + self.timeout_duration 
            # transition to WAIT_SEGMENT to receive next segment
            return self.FIN_WAIT
        
        else:
            if self.SACK:
                # add optional headers
                buffer = deepcopy(self.o3buffer)
                le = self.next  # detect left edge
                bl = 1          # accumulate block length
                while len(buffer) > 0 and len(self.left_edge) < 3:
                    while le not in buffer.keys():
                        le = (le + 1) % (1 << self.n_bits)
                    self.left_edge.append(le)
                    del buffer[le]   
                    while True:
                        next_seq_num = (le + bl) % (1 << self.n_bits)
                        if next_seq_num not in buffer.keys():
                            break
                        else:
                            bl += 1
                            del buffer[next_seq_num]
                    self.block_len.append(bl)
                    le = le + bl
                    bl = 1
                assert (len(self.block_len) == len(self.left_edge))
                # log("len(self.left_edge): %d", len(self.left_edge))
                
                

                hlen = 6 + 3 * len(self.left_edge)
                match hlen:
                    case 6:
                        ack_pkt = GBN(type="ack", fin=0, sack=self.SACK, len=0, hlen=hlen, num=self.next, win=self.max_win)
                    case 9:
                        ack_pkt = GBN(type="ack", fin=0, sack=self.SACK, len=0, hlen=hlen, num=self.next, win=self.max_win,
                                      num_blocks = 1, left_edge1 = self.left_edge[0], block_len1 = self.block_len[0])
                    case 12:
                        ack_pkt = GBN(type="ack", fin=0, sack=self.SACK, len=0, hlen=hlen, num=self.next, win=self.max_win,
                                      num_blocks = 2, left_edge1 = self.left_edge[0], block_len1 = self.block_len[0],
                                      left_edge2 = self.left_edge[1], block_len2 = self.block_len[1])
                    case 15:
                        ack_pkt = GBN(type="ack", fin=0, sack=self.SACK, len=0, hlen=hlen, num=self.next, win=self.max_win,
                                      num_blocks = 3, left_edge1 = self.left_edge[0], block_len1 = self.block_len[0],
                                      left_edge2 = self.left_edge[1], block_len2 = self.block_len[1],
                                      left_edge3 = self.left_edge[2], block_len3 = self.block_len[2])
                    case _:
                        raise ValueError("hlen could not be this value!")

                self.send(ack_pkt)
                
                self.left_edge.clear()
                self.block_len.clear()
                return self.WAIT_SEGMENT
            else:
                # Send the normal ACK and change to the wait segment state..
                log("Sending ACK: %s", self.next)

                self.send(GBN(type="ack", fin=0, sack=0, len=0, hlen=6, num=self.next, win=self.max_win))

                # transition to WAIT_SEGMENT to receive next segment
                return self.WAIT_SEGMENT

    def FIN_WAIT(self):
        """Waiting state for new packets."""

        # check for timeout
        if self.timeout_at < time.time():
            return self.FIN_RETRANSMIT

        # receive new packets
        pkt = self.socket.receive()

        # check if we have received a new packet
        if pkt is not None:
            return self.FIN_DATA_IN, GBN(pkt)

        # sleep for a short amount of time, to reduce the stress on the system.
        # please, leave this as it is!
        time.sleep(0.001)
        return self.FIN_WAIT

    def FIN_DATA_IN(self, pkt):
        """State for incoming data while waiting for the final FIN+ACK packet."""
        # We are expecting a FIN + ACK with all other bytes set to zero. However, due to Postel's
        # law, we only require that the packet has set the ACK flag. If we receive any other kind
        # of packet, simply re-send the FIN+ACK packet.

        if pkt.getlayer(GBN).type == 1:
            # We have received an ack, and we can safely close the receiver
            self.count, self.timeout_at = 0, None
            return self.END

        else:
            # Received a data packet. Resend the FIN+ACK packet.
            log("Sending ACK: %s", self.next)
            self.send(GBN(type="ack", fin=1, sack=0, len=0, hlen=6, num=self.next, win=self.max_win))

            # continue waiting.
            return self.FIN_WAIT

    def FIN_RETRANSMIT(self):
        """State to retransmit the final FIN+ACK packet."""

        ################################################################
        # Task 1.5:                                                    #
        # Resend the last FIN+ACK packet. At the third timeout,        #
        # immediately transition to the END state without waiting for  #
        # confirmation from the sender.                                #
        #                                                              #
        # Only reset the timeout on a retransmission, but not when we  #
        # receive any packet from the sender.                          #
        ################################################################
        self.count += 1
        if self.count >= 4:
            self.count, self.timeout_at = 0, None
            return self.END
        else:
            self.send(GBN(type="ack", fin=1, sack=0, len=0, hlen=6, num=self.next, win=self.max_win))   # Resend the last FIN+ACK packet
            self.timeout_at = time.time() + self.timeout_duration

        # back to FIN_WAIT state
        time.sleep(0.001)  # This sleep can be removed after task 1.5
        return self.FIN_WAIT


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser("GBN receiver")
    parser.add_argument("snd_ip", type=str, help="The IP address of the sender")
    parser.add_argument("snd_port", type=str, help="The UDP port of the sender")
    parser.add_argument("rcv_ip", type=str, help="The IP address of the receiver")
    parser.add_argument("rcv_port", type=str, help="The UDP port of the receiver")
    parser.add_argument("output_file", type=str, help="File to store the received data")
    parser.add_argument("n_bits", type=int, help="n_bits to encode the sequence number")
    parser.add_argument("max_win", type=int, help="maximum window size")
    parser.add_argument("--timeout", type=float, help="Timeout in seconds", default=1.0)

    args = parser.parse_args()

    assert args.n_bits <= 8

    # delete previous output file (if it exists)
    if os.path.exists(args.output_file):
        os.remove(args.output_file)

    with udp_receiver(args.snd_ip, args.snd_port, args.rcv_ip, args.rcv_port) as socket:
        # initial setup of automaton
        GBN_receiver = GBNReceiver(
            socket,
            args.n_bits,
            args.output_file,
            args.timeout,
            args.max_win,
            2 ** 6,
        )
        # start automaton
        GBN_receiver.run()
