# TCP-and-Wireshark

Part A Analysis of TCPdump:

To write a program `` analysis_pcap_tcp” that analyzes a Wireshark/TCPdump trace
to characterize the TCP flows in the trace. A TCP flow starts with a TCP “SYN” and ends at a TCP
“FIN”.
You may use a PCAP library to analyze the trace. You may only use the PCAP library to get each
packet in byte format. The PCAP library can be used to figure out where the first packet ends
and the second packet starts. You need to then write code to analyze the bytes to get the
information about the packet.
We have captured packets sent between 130.245.145.12 and 128.208.2.198. Node 130.245.145.12 establishes the
connection (let’s call it sender) with 128.208.2.198 (let’s call is receiver) and then sends data.
The trace was captured at the sender. Use your `` analysis_pcap_tcp” code to analyze
assignment3.pcap and answer the following questions (Ignore any traffic that is not TCP). Each
of these needs to be done empirically:
1. Count the number of TCP flows initiated from the sender
2. For each TCP flow
(a) For the first 2 transactions after the TCP connection is set up (from sender to receiver),
get the values of the Sequence number, Ack number, and Receive Window size. Explain
these values.
(b) Compute the sender throughput for data sent from sender to receiver. The throughput is
the total amount of data sent by the sender over the period of time. The period is the time
between sending the first byte to receiving the last acknowledgement.
(c) Compute the loss rate for each flow. Loss rate is the number of packets not received
divided by the number of packets sent. Loss rate is an application layer metric.

Part B Congestion control:

For each TCP flow:
(1) Print the first five congestion window sizes (or till the end of the flow, if there are less than
five congestion windows). The congestion window is estimated at the sender. What is the size
of the initial congestion window. You need to estimate the congestion window size empirically
since the information is not available in the packet. Comment on how the congestion window
size grows. Remember that your estimation may not be perfect, but that is ok. Congestion
window sizes are estimated per RTT.
(2) Compute the number of times a retransmission occurred due to triple duplicate ack and the
number of time a retransmission occurred due to timeout.
