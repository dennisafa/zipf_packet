from scapy.all import *
import numpy as np
import sys

num_flows = 100
init_num_packets = 1000.0
res = 0
zipf_dist = []
packets = []
summation = 0

for i in range (0, num_flows):
    res = init_num_packets * (1.0/(i+1))
    summation += res
    zipf_dist.append(int(res))

for i in range(num_flows):
    ip_src = RandIP()._fix()
    ip_dest = RandIP()._fix()
    flow_packet = Ether()/IP(src = ip_src, dst = "10.0.0.0")/UDP(dport = 80, sport = 80)
    for j in range(zipf_dist[i]):
        packets.append(flow_packet)

np.random.shuffle(packets)
wrpcap("udp_zipf_test.pcap", packets)
