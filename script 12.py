from scapy.all import sniff
from collections import Counter
from prettytable import PrettyTable
import socket

# A simple mapping of IP protocol numbers to names
# This is not exhaustive but covers some common protocols
PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

# Global list to store packets
packets = []

# Callback function for processing packets
def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        proto = packet['IP'].proto
        # Use the PROTOCOL_MAP to get the protocol name; default to the number if unknown
        protocol_name = PROTOCOL_MAP.get(proto, str(proto))
        # Accumulate the packet info in the counter
        packets.append((ip_src, ip_dst, protocol_name))

# This function will create a pretty table from the packet data
def create_pretty_table(packet_data):
    table = PrettyTable(["Occurs", "SRC", "DST", "Protocol"])
    for data, count in packet_data.items():
        src, dst, protocol_name = data
        table.add_row([count, src, dst, protocol_name])
    print(table)

def main():
    print("Starting packet capture... Press Ctrl+C to stop or wait for the timeout.")
    try:
        # Start sniffing the network with a timeout (e.g., 60 seconds)
        sniff(filter="ip", prn=packet_callback, timeout=60)
    except KeyboardInterrupt:
        print("\nStopped packet capture by user.")

    # Count the occurrences of each packet type
    packet_counts = Counter(packets)

    # Create and display the pretty table
    create_pretty_table(packet_counts)

    if len(packets) == 0:
        print("No packets captured.")

if __name__ == "__main__":
    main()
