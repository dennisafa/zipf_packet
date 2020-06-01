import numpy as np
import getopt
import sys
from scapy.all import *

def generate_uni_pcap(num_flows, total_packets, packet_size):
    summation = 0
    res = 0
    packets = []
    uni_distr = total_packets / num_flows
    print("Number of packets per flow: %d" % (uni_distr))

    for i in range(num_flows):
        ip_src = RandIP()._fix()
        ip_dest = RandIP()._fix()
        flow_packet = Ether()/IP(src = ip_src, dst = "10.0.0.0")/UDP(dport = 80, sport = 80)/Raw(RandString(size=packet_size - 42))
        for j in range(uni_distr):
            packets.append(flow_packet)

    np.random.shuffle(packets)
    wrpcap("udp_uni_test.pcap", packets, append = False)

if __name__ == "__main__":
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "f:p:s:")
        if len(opts) != 3:
            print("Usage: -f <number of flows> -p <number of packets> -s <size of packet in bytes>")
            sys.exit(1)
        for opt, arg in opts:
            if opt == '-f':
                f = int(arg)
            if opt == '-s':
                s = int(arg)
            if opt == '-p':
                p = int(arg)
        print("Main: Number of flows = %d Number of packets = %d Size of packets = %d" % (f, p, s))
        generate_uni_pcap(f, p, s)

    except getopt.GetoptError:
        print("Usage: -f <number of flows> -p <number of packets> -s <size of packet in bytes>")


