from scapy.all import *

packets=rdpcap('CaptureFile.cap')

packet_counts = 0

def custom_action(packet):
    global packet_counts
    packet_counts +=1
    return f"Packet #{packet_counts}: {packet[IP].src}"

sniff(filter="ip", prn=custom_action)