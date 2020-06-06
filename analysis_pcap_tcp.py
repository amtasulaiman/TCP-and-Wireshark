import time
import dpkt

file_name = open("assignment3.pcap", 'rb')
pcap = dpkt.pcap.Reader(file_name)
end = False
turns = 4
count, f_seq, s_seq, t_seq, num, once, data, thru, t1, t2 = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
begin = True
triple = 0
my_list = []    # use to store all the sequence numbers for packets
my_set = set()  # use to store only the unique ones (excluding retransmitted ones)

for timestamp, buf in pcap:

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)

    # Make sure the Ethernet data contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n', eth.data.__class__.__name__)
        continue

    # Now grab the data within the Ethernet frame (the IP packet)
    ip = eth.data

    # Check for TCP in the transport layer
    if isinstance(ip.data, dpkt.tcp.TCP):
        # Set the TCP data
        tcp = ip.data
        if tcp.dport == 80:
            my_list.append(tcp.seq)
            my_set.add(tcp.seq)

        if tcp.seq < 10 or tcp.ack < 10:
            print("DUPLICATE ACK: ", tcp.seq, tcp.ack)

        if len(tcp) > 0 and tcp.dport == 80:
            if f_seq == tcp.seq:
                f_seq = tcp.ack
                print("Seq Number: ", tcp.seq)
                print("Ack Number: ", tcp.ack)
                print("Receive Window size: ", tcp.win)
                if begin:
                    t1 = time.time()
                    begin = False

            elif s_seq == tcp.seq:
                s_seq = tcp.ack
                print("Seq Number: ", tcp.seq)
                print("Ack Number: ", tcp.ack)
                print("Receive Window size: ", tcp.win)
                if begin:
                    t1 = time.time()
                    begin = False
            elif t_seq == tcp.seq:
                t_seq = tcp.ack
                print("Seq Number: ", tcp.seq)
                print("Ack Number: ", tcp.ack)
                print("Receive Window size: ", tcp.win)
                if begin:
                    t1 = time.time()
                    begin = False
        # Packet consisting of SYN/ACK
        if (tcp.flags & dpkt.tcp.TH_SYN != 0) and (tcp.flags & dpkt.tcp.TH_ACK != 0):
            print("SYN/ACK is achieved ", tcp.seq, tcp.ack, tcp.dport)
            print("\n")
            if begin:
                t1 = time.time()
                begin = False
            num = num + 1
            if num == 1:
                f_seq = tcp.ack
            elif num == 2:
                s_seq = tcp.ack
            elif num == 3:
                t_seq = tcp.ack
        # Packet consisting of SYN only
        if (tcp.flags & dpkt.tcp.TH_SYN != 0) and not (tcp.flags & dpkt.tcp.TH_ACK != 0):
            print("SYN is achieved", tcp.seq, tcp.ack)
            print("\n")
        # Packet consisting of FIN, marks the end of TCP flow
        if (tcp.flags & dpkt.tcp.TH_FIN != 0) and tcp.sport == 80:
            count = count + 1
            t2 = time.time()
            thru = t2 - t1
            print("TCP FLOW completed #: ", count)
            print("FIN is achieved", tcp.seq, tcp.ack, tcp.sport)
            print("Throughput(in seconds) for data sent from sender to receiver: ", round(1480 / thru, 3))
            begin = True
            print("\n")

        # Test case used to answer the questions in pdf about seq #, ack # and window size
        if once < 15 and ((t_seq == tcp.ack) or (s_seq == tcp.ack) or (f_seq == tcp.ack)) and tcp.dport == 80:
            print("***Seq Number: ", tcp.seq)
            print("Ack Number: ", tcp.ack)
            print("Receive Window size: ", tcp.win)
            once = once + 1

# Test for loss rate
loss = (len(my_list)-len(my_set))/len(my_list)*100
print("The loss rate is: ", loss)


