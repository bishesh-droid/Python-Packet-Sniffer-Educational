import argparse
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

class PacketSniffer:
    """
    A packet sniffer that captures and analyzes network packets.
    """

    def __init__(self, interface, filter, count, output_file):
        """
        Initializes the PacketSniffer.

        :param interface: The network interface to sniff on.
        :param filter: The BPF filter for capturing packets.
        :param count: The number of packets to capture.
        :param output_file: The file to save the captured packets.
        """
        self.interface = interface
        self.filter = filter
        self.count = count
        self.output_file = output_file
        self.packets = []

    def packet_callback(self, packet):
        """
        Callback function to process each captured packet.
        """
        print("--- New Packet ---")
        self.packets.append(packet)

        # Ethernet Layer
        if packet.haslayer(Ether):
            eth_layer = packet.getlayer(Ether)
            print(f"[Ethernet] Src: {eth_layer.src}, Dst: {eth_layer.dst}")

        # IP Layer
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            print(f"[IP] Src: {ip_layer.src}, Dst: {ip_layer.dst}, Proto: {ip_layer.proto}")

            # TCP Layer
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                print(f"[TCP] Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}, Flags: {tcp_layer.flags}")
                if tcp_layer.payload:
                    print(f"[Payload] {tcp_layer.payload.original[:30]}...")

            # UDP Layer
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                print(f"[UDP] Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
                if udp_layer.payload:
                    print(f"[Payload] {udp_layer.payload.original[:30]}...")

            # ICMP Layer
            elif packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                print(f"[ICMP] Type: {icmp_layer.type}, Code: {icmp_layer.code}")

    def start(self):
        """
        Starts the packet sniffer.
        """
        print(f"Sniffing on interface {self.interface}...")
        sniff(iface=self.interface, filter=self.filter, count=self.count, prn=self.packet_callback, store=0)

        if self.output_file:
            print(f"\nSaving captured packets to {self.output_file}...")
            wrpcap(self.output_file, self.packets)
            print("Done.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple packet sniffer.")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on.")
    parser.add_argument("-f", "--filter", default="", help="BPF filter for capturing packets.")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited).")
    parser.add_argument("-o", "--output", help="File to save the captured packets (PCAP format).")
    args = parser.parse_args()

    sniffer = PacketSniffer(args.interface, args.filter, args.count, args.output)
    sniffer.start()