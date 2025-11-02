
import unittest
from unittest.mock import patch, MagicMock
from packet_sniffer.main import PacketSniffer
from scapy.all import Ether, IP, TCP, UDP, ICMP # Import necessary layers for creating dummy packets

class TestPacketSniffer(unittest.TestCase):
    """
    Unit tests for the PacketSniffer class.
    """

    def test_initialization(self):
        """
        Test that the PacketSniffer is initialized correctly.
        """
        sniffer = PacketSniffer(interface="eth0", filter="tcp", count=10, output_file="test.pcap")
        self.assertEqual(sniffer.interface, "eth0")
        self.assertEqual(sniffer.filter, "tcp")
        self.assertEqual(sniffer.count, 10)
        self.assertEqual(sniffer.output_file, "test.pcap")

    @patch('packet_sniffer.main.sniff')
    @patch('packet_sniffer.main.wrpcap')
    def test_packet_callback_processing(self, mock_wrpcap, mock_sniff):
        """
        Test that the packet_callback processes packets correctly.
        """
        sniffer = PacketSniffer(interface="eth0", filter="tcp", count=1, output_file="test.pcap")
        
        # Create a dummy packet
        dummy_packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80)
        
        # Configure the mock sniff to call the packet_callback with our dummy packet
        mock_sniff.side_effect = lambda iface, filter, count, prn, store: prn(dummy_packet)

        # Capture print statements
        with patch('builtins.print') as mock_print:
            sniffer.start()
            
            # Verify sniff was called correctly
            mock_sniff.assert_called_once_with(iface="eth0", filter="tcp", count=1, prn=sniffer.packet_callback, store=0)
            
            # Verify wrpcap was called if output_file is provided
            mock_wrpcap.assert_called_once_with("test.pcap", [dummy_packet])

            # Verify that print was called with expected output from packet_callback
            mock_print.assert_any_call("--- New Packet ---")
            mock_print.assert_any_call(f"[Ethernet] Src: {dummy_packet.getlayer(Ether).src}, Dst: {dummy_packet.getlayer(Ether).dst}")
            mock_print.assert_any_call(f"[IP] Src: {dummy_packet.getlayer(IP).src}, Dst: {dummy_packet.getlayer(IP).dst}, Proto: {dummy_packet.getlayer(IP).proto}")
            mock_print.assert_any_call(f"[TCP] Src Port: {dummy_packet.getlayer(TCP).sport}, Dst Port: {dummy_packet.getlayer(TCP).dport}, Flags: {dummy_packet.getlayer(TCP).flags}")
            self.assertIn(dummy_packet, sniffer.packets)

if __name__ == "__main__":
    unittest.main()
