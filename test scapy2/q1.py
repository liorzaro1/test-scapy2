from scapy.all import *

packets=rdpcap('CaptureFile.cap')

def print_pkt(packets):
    if IP in packets:
        ip_src=packets[IP].src
        ip_dst=packets[IP].dst

        print "IP src" + str(ip_src)
        print "IP dst" + str(ip_dst)

sniff(filter="ip", prn=print_pkt)
