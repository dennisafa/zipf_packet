import numpy as np
import getopt
import sys
from scapy.all import *

def generate_zipf_pcap(num_flows, total_packets, packet_size, power):
    summation = 0
    res = 0
    zipf_dist = []
    packets = []

    for i in range(1, num_flows+1):
        summation += 1.0/i**power

    init_num_packets = total_packets/summation
    for i in range (1, num_flows+1):
        res = init_num_packets * (1.0/i**power)
        zipf_dist.append(int(res))

    print("generate_zipf_pcap: # of packets in first flow = %d" % (zipf_dist[0]))
    for i in range(num_flows):
        ip_src = RandIP()._fix()
        ip_dest = RandIP()._fix()
        flow_packet = Ether()/IP(src = ip_src, dst = "10.0.0.0")/UDP(dport = 80, sport = 80)/Raw(RandString(size=packet_size - 42))
        for j in range(zipf_dist[i]):
            packets.append(flow_packet)

    np.random.shuffle(packets)
    wrpcap("udp_zipf_test.pcap", packets, append = False)


if __name__ == "__main__":
    argv = sys.argv[1:]

    try:
        opts, args = getopt.getopt(argv, "f:p:s:e:")
        if len(opts) != 4:
            print("Usage: -f <number of flows> -p <number of packets> -s <size of packet in bytes> -e <exponent greater than 1>")
            sys.exit(1)
        for opt, arg in opts:
            if opt == '-f':
                f = int(arg)
            if opt == '-p':
                p = int(arg)
            if opt == '-s':
                s = int(arg)
            if opt == '-e':
                e = float(arg)
        print("Main: Number of flows = %d Number of packets = %d Size of packets = %d Zipf exponent = %f" % (f, p, s, e))
        generate_zipf_pcap(f, p, s, e)

    except getopt.GetoptError:
        print("Usage: -f <number of flows> -p <number of packets> -s <size of packet in bytes> -e <exponent greater than 1>")


