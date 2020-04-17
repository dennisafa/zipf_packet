import numpy as np
from scapy.all import *

num_flows = 100
total_packets = 16000
summation = 0
res = 0
zipf_dist = []
packets = []

for i in range(0, num_flows):
    summation += 1.0/(i+1)

init_num_packets = total_packets/summation
print(init_num_packets)
for i in range (0, num_flows):
    res = init_num_packets * (1.0/(i+1))
    zipf_dist.append(int(res))

for i in range(num_flows):
    ip_src = RandIP()._fix()
    ip_dest = RandIP()._fix()
    flow_packet = Ether()/IP(src = ip_src, dst = "10.0.0.0")/UDP(dport = 80, sport = 80)
    for j in range(zipf_dist[i]):
        packets.append(flow_packet)

np.random.shuffle(packets)
wrpcap("udp_zipf_test.pcap", packets, append = False)
