"""A Sender for the GBN protocol."""

import argparse
import queue as que
import time
import math
from scapy.packet import Packet
from scapy.fields import BitEnumField, BitField, ShortField, ByteField, ConditionalField
from udpsocket import sender as udp_sender
from udpsocket import log


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


class GBNSender:
    """Sender implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        socket: UDP Socket with the already established connection
        n_bits: number of bits used to encode sequence number
        payloads: List of bytestrings to send.
        win: Window size of the sender.
        srep: Is Selective Repeat used?
        sack: Is SACK used?
        cc: Is congestion control used?
        timeout: retransmission timeout.
    """

    def __init__(self, socket, n_bits, payloads, win, srep, sack, cc, timeout):
        """Initialize Automaton."""
        self.socket = socket

        self.win = win
        self.n_bits = n_bits
        assert self.win < 2 ** self.n_bits
        self.q = que.Queue()
        for item in payloads:
            self.q.put(item)

        # The buffer stores the payload, as well as a flag to remember
        # if the payload is the last one to be sent.
        self.buffer = {}
        self.current = 0
        self.unack = 0
        self.timeout_duration = timeout
        self.timeout_at = time.time() + self.timeout_duration

        self.SREP = srep
        self.SACK = sack
        self.CC = cc

        ############### auxiliary variables ###############
        self.init_win = win
        self.win_update = win
        self.ssthresh = -1
        self.MAX = (1 << self.n_bits) - 1
        self.count = 0
        self.retransmit = []

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
        return self.SEND

    def END(self):
        """End state of the automaton."""
        log("All packets successfully transmitted and the connection is closed!")
        raise StopIteration("State machine reached the final state.")
    
    ######## auxiliary function for task 2.1 ########
    def fall_in(self, value, unack, current):
        if unack < current:
            if value >= unack and value < current:
                return True
            else:
                return False
        elif current < unack:
            assert(value <= self.MAX)
            if value >= unack:
                return True
            elif value < current:
                return True
            else:
                return False
            
    def congestion_control(self, win, ssthresh, max_win):
        if ssthresh == -1:
            win = win * 2
        else:
            if win < ssthresh:
                win = win * 2
            else:
                win += 1 / win
        win = min(win, max_win)
        return win 
    

    def update_win(self, win_update, ssthresh, miss_num, unack_start, unack_end):
        if unack_start > unack_end:
            unack_end += (1 << self.n_bits)
        unack_num = unack_end - unack_start
        percentage = miss_num / (unack_num + 0.1)
        if ssthresh == -1:
            # win_update -= (win_update - self.init_win) * percentage
            ssthresh = math.floor(min(win_update / 2, self.init_win))
            win_update = ssthresh
        else:
            if win_update <= ssthresh:
                ssthresh = ssthresh / 2
                win_update = self.init_win
            else:
                win_update = ssthresh - (ssthresh - self.init_win) * percentage
        return win_update, ssthresh

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


    def update_retransmit(self):
        for num in self.retransmit:
            if self.distance(num, self.unack) < (1 << (self.n_bits - 1)) - 1:
                self.retransmit.remove(num)
    ##################################################


    def SEND(self):
        """Main state of sender.

        New packets are transmitted to the receiver as long as there is space
        in the window.
        """
        # check for timeout
        if self.timeout_at < time.time():
            return self.RETRANSMIT
        
        # log("self.count: %d", self.count)
        if self.SREP and self.count >= 3:
            self.count = 0
            # re-send the next unacknowledged segment
            payload_resend, last_payload_resend = self.buffer[self.unack]
            pkt_resend = GBN(type = 'data', fin = last_payload_resend , sack = self.SACK, len = len(payload_resend), hlen = 6, num = self.unack, win=self.win) / payload_resend
            self.send(pkt_resend)
            return self.SEND

        # check if you still can send new packets to the receiver
        if len(self.buffer) < self.win:
            # check if there are still some packets to be sent
            if not self.q.empty():
                # get next payload (automatically removes it from queue)
                payload = self.q.get(block=False)
                last_payload = 1 if self.q.empty() else 0
                log("Sending packet num: %s (last: %s)", self.current, last_payload)

                # add the current segment to the buffer
                self.buffer[self.current] = (payload, last_payload)
                log("Current buffer size: %s", len(self.buffer))
                ###############################################################
                # Task 1.1:                                                   #
                # Create a GBN header with the correct header field values.   #
                # Send a packet to the receiver containing the created header #
                # and the corresponding payload                               #
                ###############################################################
                pkt = GBN(type = 'data', fin = last_payload , sack = self.SACK, len = len(payload), hlen = 6, num = self.current, win=self.win) / payload
                self.send(pkt)
                # sequence number of next packet
                self.current = (self.current + 1) % (1 << self.n_bits)

        # check if we have received a new packet
        pkt = self.socket.receive()

        # check if we have received a new packet
        if pkt is not None:
            pkt = GBN(pkt)
            log("Received packet: %s" % pkt.getlayer(GBN).num)
            return self.ACK_IN, pkt

        # sleep for a short amount of time, to reduce the stress on the system.
        # please, leave this as it is!
        time.sleep(0.001)
        return self.SEND

    def ACK_IN(self, pkt):
        """State for received ACK."""
        ################################################################
        # Task 1.4:                                                    #
        # Make sure to reset the timeout, once an ACK is received that #
        # does advance the window. To update the timeout, you can look #
        # at the example in the function `__init__`.                   #
        ################################################################

        # check if type is ACK
        if pkt.getlayer(GBN).type == 0:
            log("Error: data type received instead of ACK %s", pkt)
            return self.SEND

        log("Received ACK %s (fin: %s)", pkt.getlayer(GBN).num, pkt.getlayer(GBN).fin)
    
        
        ################################################################
        # Task 3.2:                                                    #
        # When receiving an ACK with some optional SACK blocks, then   #
        # compute the missing packets and send only those. For these   #
        # packets do not set the SACK flag to prevent a huge number    #
        # of retransmissions.                                          #
        ################################################################

        ################################################################
        # Task 4:                                                      #
        # Update the window size to implement congestion control.      #
        # Implement Additive-Increase Multiplicative-Decrease (AIMD).  #
        # If an entire window was transmitted without any packet loss, #
        # increase the window size by 1. If you notice any packet      #
        # loss, then divide the window size by 2.                      #
        #                                                              #
        # How exactly you implement congestion control, i.e., how to   #
        # detect packet loss, is up to you. Just make sure that you    #
        # allow reordering of acknowledgements. Also, do not decrease  #
        # the window size for any single failure, just for the first   #
        # failure in any given window.                                 #
        ################################################################

        ################################################################
        # Task 1.2:                                                    #
        # Remove all the acknowledged sequence numbers from the buffer #
        # make sure that you can handle a sequence number overflow.    #
        # Also, once receiving a packet with the FIN flag set, answer  #
        # by sending the appropriate message, and close the stream.    #
        ################################################################

        # self.MAX = (1 << self.n_bits) - 1
        if pkt.getlayer(GBN).type == 1:
    
            seq = pkt.getlayer(GBN).num     # The next expected sequence number
            rev_win = pkt.getlayer(GBN).win

            assert(seq <= self.MAX)
            # first check whether the fin bit is set 
             
            # if the fin flag is set to 1
            if pkt.getlayer(GBN).fin:    
                # check whether it is reasonable to finish this session
                prev = (seq + self.MAX) % (1 << self.n_bits)
                if prev not in self.buffer.keys():
                    return self.SEND
                _ , if_last = self.buffer[prev]
                if self.q.empty() and seq == self.current and if_last:   # if and only if all segments have been transmitted and this ACK corresponds to the last segment 
                    ACK_pkt = GBN(type = 'ack', fin = 1 , sack = 0, len = 0, hlen = 6, num = 0, win=0) 
                    self.send(ACK_pkt)                       # transmit the FIN+ACK package
                    return self.END                          # transition to the END state
                # else just ignore
                # else: 
                    # raise ValueError('set fin bit wrongly!')
                    # return self.SEND

            # if the FIN flag is not set 

            if seq == self.unack:         # When we receive duplicated ACKs
                if self.SREP:
                    self.count += 1                       # only if the self.SREP attribute is set to 1, increment by 1
                    return self.SEND

             
            # not occuring overflow            
            ##########################################
            #      ____________________self.current  #
            #     |                       |   ⬇      #
            #  0  |   1     2     3     4 |   5      #
            #     |___⬆___________________|          #                   
            #      self.unack                        #
            ##########################################

            if self.unack < self.current:
                if seq > self.unack and seq <= self.current:  # check whether the next expected sequence number fall into current sender window 
                    while self.unack < seq:           # In case that the ACK message may lost and the ACK doesn't not arrived sequentially
                        if self.unack in self.buffer.keys():
                            del self.buffer[self.unack]
                        self.unack +=  1
                        assert(self.unack <= self.MAX)
                    self.timeout_at = time.time() + self.timeout_duration    # for task 1.4 reset the timer
                    self.count = 1
                    if self.CC:
                        self.win_update = self.congestion_control(self.win_update, self.ssthresh, rev_win)
                        self.win = math.floor(self.win_update)
                # else:                                 Outside the sender window, just ignore
            
            # occuring overflow 

            #######################################################
            # __self.current                ___________________   #
            #     |   ⬇                    |                      #
            #  0  |   1     2     3     4  |   5     6     7      #
            # ____|                        |___⬆_______________   #                   
            #                            self.unack               #
            #######################################################
            elif self.unack > self.current:
                if seq > self.unack:
                    while self.unack < seq:  
                        if self.unack in self.buffer.keys():       
                            del self.buffer[self.unack]
                        self.unack +=  1
                        assert(self.unack <= self.MAX)
                    self.timeout_at = time.time() + self.timeout_duration     # reset the timer
                    self.count = 1
                    if self.CC:
                        self.win_update = self.congestion_control(self.win_update, self.ssthresh, rev_win)
                        self.win = math.floor(self.win_update)
                elif seq <= self.current:
                    while self.unack <= self.MAX: 
                        if self.unack in self.buffer.keys():                         
                            del self.buffer[self.unack]
                        self.unack = self.unack + 1
                    self.unack = 0
                    while self.unack < seq:
                        if self.unack in self.buffer.keys():                             
                            del self.buffer[self.unack]
                        self.unack = (self.unack + 1) % (1 << self.n_bits)
                    self.timeout_at = time.time() + self.timeout_duration     # reset the timer
                    self.count = 1 
                    if self.CC:
                        self.win_update = self.congestion_control(self.win_update, self.ssthresh, rev_win)
                        self.win = math.floor(self.win_update)
                # else:
            else:             
                raise ValueError("unack and current can not have same value") 

            self.update_retransmit()

            if pkt.getlayer(GBN).sack:   # if containing a SACK header
                block_num = int((pkt.getlayer(GBN).hlen - 6) / 3)
                miss_num = 0
                match block_num:
                    case 0:
                        log("don't contain optional header")
                    case 1:
                        left_edge_list = [pkt.getlayer(GBN).left_edge1] 
                        block_len_list = [pkt.getlayer(GBN).block_len1]
                        for left_edge in left_edge_list:
                            if self.fall_in(left_edge, self.unack, self.current):
                                resend = self.unack
                                assert(pkt.getlayer(GBN).num_blocks == 1)
                                if resend > left_edge:
                                    left_edge += (1 << self.n_bits)
                                while resend < left_edge:
                                    if resend >= (1 << self.n_bits):
                                        resend_cal = resend - (1 << self.n_bits)  # calibrate the resend value
                                    else:
                                        resend_cal = resend 

                                    if self.fall_in(resend_cal, self.unack, self.current):    
                                        # resend should always fall into the range of sender window 
                                        assert(resend_cal in self.buffer.keys())
                                        if self.CC:
                                            if resend_cal not in self.retransmit:
                                                resend_payload, resend_last_payload = self.buffer[resend_cal]
                                                pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                                self.send(pkt_resend)
                                                self.retransmit.append(resend_cal)
                                        else:
                                            resend_payload, resend_last_payload = self.buffer[resend_cal]
                                            pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                            self.send(pkt_resend)
                                        miss_num += 1
                                        resend += 1
                        if self.CC:
                            for i in range(len(left_edge_list)):
                                left_edge = left_edge_list[i]
                                block_len = block_len_list[i]
                                for j in range(block_len):
                                    resend = (left_edge + j) % (1 << self.n_bits)
                                    if self.fall_in(resend, self.unack, self.current):
                                        if resend in self.buffer.keys():
                                            del self.buffer[resend]
                    case 2:
                        left_edge_list = [pkt.getlayer(GBN).left_edge1, pkt.getlayer(GBN).left_edge2] 
                        block_len_list = [pkt.getlayer(GBN).block_len1, pkt.getlayer(GBN).block_len2]
                        if self.fall_in(pkt.getlayer(GBN).left_edge1, self.unack, self.current):
                            resend = self.unack
                            left_edge = pkt.getlayer(GBN).left_edge1
                            assert(pkt.getlayer(GBN).num_blocks == 2)
                            if resend > left_edge:
                                left_edge += (1 << self.n_bits)
                            while resend < left_edge:
                                if resend >= (1 << self.n_bits):
                                    resend_cal = resend - (1 << self.n_bits)  # calibrate the resend value
                                else:
                                    resend_cal = resend 

                                if self.fall_in(resend_cal, self.unack, self.current):    
                                    assert(resend_cal in self.buffer.keys())
                                    if self.CC:
                                        if resend_cal not in self.retransmit:
                                            resend_payload, resend_last_payload = self.buffer[resend_cal]
                                            pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                            self.send(pkt_resend)
                                            self.retransmit.append(resend_cal)
                                    else:
                                        resend_payload, resend_last_payload = self.buffer[resend_cal]
                                        pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                        self.send(pkt_resend)
                                    resend += 1
                                    miss_num += 1

                        if self.fall_in(pkt.getlayer(GBN).left_edge2, self.unack, self.current):
                            resend += pkt.getlayer(GBN).block_len1
                            left_edge = pkt.getlayer(GBN).left_edge2
                            resend = resend % (1 << self.n_bits)
                            if resend > left_edge:
                                left_edge += (1 << self.n_bits)
                            while resend < left_edge:
                                # assert resend should always fall into the range of sender window 
                                if resend >= (1 << self.n_bits):
                                    resend_cal = resend - (1 << self.n_bits)  # calibrate the resend value
                                else:
                                    resend_cal = resend 

                                if self.fall_in(resend_cal, self.unack, self.current):    
                                    assert(resend_cal in self.buffer.keys())
                                    if self.CC:
                                        if resend_cal not in self.retransmit:
                                            resend_payload, resend_last_payload = self.buffer[resend_cal]
                                            pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                            self.send(pkt_resend)
                                            self.retransmit.append(resend_cal)
                                    else:
                                        resend_payload, resend_last_payload = self.buffer[resend_cal]
                                        pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                        self.send(pkt_resend)
                                    resend += 1
                                    miss_num += 1


                        if self.CC:
                            for i in range(len(left_edge_list)):
                                left_edge = left_edge_list[i]
                                block_len = block_len_list[i]
                                for j in range(block_len):
                                    resend = (left_edge + j)  % (1 << self.n_bits)
                                    if self.fall_in(resend, self.unack, self.current):
                                        if resend in self.buffer.keys():
                                            del self.buffer[resend]
                            
                    case 3:
                        left_edge_list = [pkt.getlayer(GBN).left_edge1, pkt.getlayer(GBN).left_edge2, pkt.getlayer(GBN).left_edge3] 
                        block_len_list = [pkt.getlayer(GBN).block_len1, pkt.getlayer(GBN).block_len2, pkt.getlayer(GBN).block_len3]
                        if self.fall_in(pkt.getlayer(GBN).left_edge1, self.unack, self.current):
                            resend = self.unack
                            left_edge = pkt.getlayer(GBN).left_edge1
                            assert(pkt.getlayer(GBN).num_blocks == 3)
                            if resend > left_edge:
                                left_edge += (1 << self.n_bits)
                            while resend < left_edge:
                                # assert resend should always fall into the range of sender window 
                                if resend >= (1 << self.n_bits):
                                    resend_cal = resend - (1 << self.n_bits)  # calibrate the resend value
                                else:
                                    resend_cal = resend 

                                if self.fall_in(resend_cal, self.unack, self.current):    
                                    assert(resend_cal in self.buffer.keys())
                                    if self.CC:
                                        if resend_cal not in self.retransmit:
                                            resend_payload, resend_last_payload = self.buffer[resend_cal]
                                            pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                            self.send(pkt_resend)
                                            self.retransmit.append(resend_cal)
                                    else:
                                        resend_payload, resend_last_payload = self.buffer[resend_cal]
                                        pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                        self.send(pkt_resend)
                                    resend += 1
                                    miss_num += 1


                        # log("left_edge2: %d", pkt.getlayer(GBN).left_edge2)
                        # log("self.unack: %d", self.unack)
                        # log("self.current: %d", self.current)
                        if self.fall_in(pkt.getlayer(GBN).left_edge2, self.unack, self.current):
                            resend += pkt.getlayer(GBN).block_len1
                            left_edge = pkt.getlayer(GBN).left_edge2
                            resend = resend % (1 << self.n_bits)
                            if resend > left_edge:
                                left_edge += (1 << self.n_bits)
                            while resend < left_edge:
                                # assert resend should always fall into the range of sender window 
                                if resend >= (1 << self.n_bits):
                                    resend_cal = resend - (1 << self.n_bits)  # calibrate the resend value
                                else:
                                    resend_cal = resend 
                                if self.fall_in(resend_cal, self.unack, self.current):    
                                    assert(resend_cal in self.buffer.keys())
                                    if self.CC:
                                        if resend_cal not in self.retransmit:
                                            resend_payload, resend_last_payload = self.buffer[resend_cal]
                                            pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                            self.send(pkt_resend)
                                            self.retransmit.append(resend_cal)
                                    else:
                                        resend_payload, resend_last_payload = self.buffer[resend_cal]
                                        pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                        self.send(pkt_resend)
                                    resend += 1
                                    miss_num += 1


                        if self.fall_in(pkt.getlayer(GBN).left_edge3, self.unack, self.current):
                            resend += pkt.getlayer(GBN).block_len2
                            left_edge = pkt.getlayer(GBN).left_edge3
                            resend = resend % (1 << self.n_bits)
                            if resend > left_edge:
                                left_edge += (1 << self.n_bits)
                            while resend < left_edge:
                                # assert resend should always fall into the range of sender window 
                                if resend >= (1 << self.n_bits):
                                    resend_cal = resend - (1 << self.n_bits)  # calibrate the resend value
                                else:
                                    resend_cal = resend 
                                if self.fall_in(resend_cal, self.unack, self.current):    
                                    assert(resend_cal in self.buffer.keys())
                                    if self.CC:
                                        if resend_cal not in self.retransmit:
                                            resend_payload, resend_last_payload = self.buffer[resend_cal]
                                            pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                            self.send(pkt_resend)
                                            self.retransmit.append(resend_cal)
                                    else:
                                        resend_payload, resend_last_payload = self.buffer[resend_cal]
                                        pkt_resend = GBN(type = 'data', fin = resend_last_payload , sack = 0, len = len(resend_payload), hlen = 6, num = resend_cal, win=self.win) / resend_payload
                                        self.send(pkt_resend)
                                    resend += 1
                                    miss_num += 1

                        if self.CC:
                            for i in range(len(left_edge_list)):
                                left_edge = left_edge_list[i]
                                block_len = block_len_list[i]
                                for j in range(block_len):
                                    resend = (left_edge + j) % (1 << self.n_bits)
                                    if self.fall_in(resend, self.unack, self.current):
                                        if resend in self.buffer.keys():
                                            del self.buffer[resend]
                    case _:
                        raise ValueError("The value of hlen is invalid") 
                if miss_num and self.CC:
                    self.win_update, self.ssthresh = self.update_win(self.win_update, self.ssthresh, miss_num, self.unack, self.current)
                    self.win = math.floor(self.win_update)
        ################################################################
        # Task 2.2:                                                    #
        # Implement Selective Repeat by checking if this ack is the    #
        # third consecutive ACK with the same sequence number. If so,  #
        # only send out the respective packet. Also, reset the counter #
        # of consecutive ACKs.                                         #
        ################################################################

        
        log("win: %d", self.win)
        # back to SEND state
        return self.SEND

    def RETRANSMIT(self):
        """State for retransmitting packets."""

        ################################################################
        # Task 1.4:                                                    #
        # retransmit all the unacknowledged packets (all the packets   #
        # currently in self.buffer).                                   #
        ################################################################

        for key in self.buffer:
            payload, last_payload = self.buffer[key]
            pkt = GBN(type = 'data', fin = last_payload , sack = self.SACK, len = len(payload), hlen = 6, num = key , win=self.win) / payload  # retransmit all the packets in the buffer
            self.send(pkt)

        self.timeout_at = time.time() + self.timeout_duration


        if self.CC:   # if congestion control is acticated
            half_win = math.floor(self.win / 2)
            self.ssthresh = max(half_win, self.init_win)
            self.win = self.init_win
        # back to SEND state
        time.sleep(0.001) # This sleep can be removed after task 1.4
        return self.SEND


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser("GBN sender")
    parser.add_argument("snd_ip", type=str, help="The IP address of the sender")
    parser.add_argument("snd_port", type=str, help="The UDP port of the sender")
    parser.add_argument("rcv_ip", type=str, help="The IP address of the receiver")
    parser.add_argument("rcv_port", type=str, help="The UDP port of the receiver")
    parser.add_argument("input_file", type=str, help="Path to the input file")
    parser.add_argument("n_bits", type=int, help="n_bits to encode the sequence number")
    parser.add_argument("window_size", type=int, help="The window size of the sender")
    parser.add_argument("srep", type=int, help="Task 2: Use Selective Repeat")
    parser.add_argument("sack", type=int, help="Task 3: Use Selective Acknowledgments")
    parser.add_argument("cc", type=int, help="Task 4: Perform congestion control")
    parser.add_argument("--timeout", type=float, help="Timeout in seconds", default=1.0)

    args = parser.parse_args()

    assert args.n_bits <= 8

    # list for binary payload
    payload_to_send_bin = list()
    chunk_size = 2 ** 6

    # fill payload list
    with open(args.input_file, "rb") as file_in:
        while True:
            chunk = file_in.read(chunk_size)
            if not chunk:
                break
            payload_to_send_bin.append(chunk)

    with udp_sender(args.snd_ip, args.snd_port, args.rcv_ip, args.rcv_port) as socket:
        # initial setup of automaton
        GBN_sender = GBNSender(
            socket,
            args.n_bits,
            payload_to_send_bin,
            args.window_size,
            args.srep,
            args.sack,
            args.cc,
            args.timeout,
        )

        # start automaton
        GBN_sender.run()
        
    

       
