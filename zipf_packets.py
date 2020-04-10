from scapy.all import *

num_flows = 100
init_num_packets = 1000.0
res = 0
zipf_dist = []
packets = []
pkt_dump = PcapWriter("udp_zipf_test.pcap", append=True, sync=True)

for i in range (0, num_flows):
    res = init_num_packets * (1.0/(i+1))
    zipf_dist.append(int(res))

print(zipf_dist)
for i in range(num_flows):
    ip_src = RandIP()._fix()
    ip_dest = RandIP()._fix()
    flow_packet = Ether()/IP(src = ip_src, dst = "10.0.0.0")/UDP(dport = 80, sport = 80)
    for j in range(zipf_dist[i]):
        pkt_dump.write(flow_packet)

