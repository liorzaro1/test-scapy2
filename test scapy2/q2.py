from scapy.all import *

packets=rdpcap('CaptureFile.cap')

def print_pkt(packets):
    if TCP in packets:
        tcp_dport=packets[TCP].dport
            for i in range(len(packets)) if packets[i][TCP].dport is max
    return None

    print "TCP dport"+ str(tcp_dport)


sniff(lfilter=lambda packets: TCP in packets)