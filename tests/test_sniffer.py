
import unittest
import os
from unittest.mock import patch, MagicMock, ANY
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from scapy.layers.http import HTTPRequest

from packet_sniffer.main import PacketSniffer
from packet_sniffer.utils import hexdump

class TestPacketSniffer(unittest.TestCase):
    """
    Unit tests for the PacketSniffer class.
    """

    def setUp(self):
        """
        Set up a test environment.
        """
        self.sniffer = PacketSniffer(
            interface="lo",
            filter="icmp",
            count=1,
            output_file="test.pcap"
        )

    def test_initialization(self):
        """
        Test that the PacketSniffer is initialized correctly.
        """
        self.assertEqual(self.sniffer.interface, "lo")
        self.assertEqual(self.sniffer.filter, "icmp")
        self.assertEqual(self.sniffer.count, 1)
        self.assertEqual(self.sniffer.output_file, "test.pcap")

    def test_packet_callback_icmp(self):
        """
        Test the packet_callback with an ICMP packet.
        """
        packet = Ether()/IP()/ICMP()
        with patch('builtins.print') as mock_print:
            self.sniffer.packet_callback(packet)
            mock_print.assert_any_call("[ICMP] Type: 8, Code: 0")

    def test_packet_callback_tcp(self):
        """
        Test the packet_callback with a TCP packet.
        """
        packet = Ether()/IP()/TCP()/Raw(load="testload")
        with patch('builtins.print') as mock_print:
            self.sniffer.packet_callback(packet)
            mock_print.assert_any_call(f"[TCP] Src Port: 80, Dst Port: 80, Flags: S")
            mock_print.assert_any_call("[Payload]")
            mock_print.assert_any_call(hexdump("testload"))

    def test_packet_callback_udp(self):
        """
        Test the packet_callback with a UDP packet.
        """
        packet = Ether()/IP()/UDP()/Raw(load="testload")
        with patch('builtins.print') as mock_print:
            self.sniffer.packet_callback(packet)
            mock_print.assert_any_call(f"[UDP] Src Port: 53, Dst Port: 53")
            mock_print.assert_any_call("[Payload]")
            mock_print.assert_any_call(hexdump("testload"))

    def test_packet_callback_dns(self):
        """
        Test the packet_callback with a DNS packet.
        """
        packet = Ether()/IP()/UDP()/DNS(qd=DNSQR(qname="google.com"))
        with patch('builtins.print') as mock_print:
            self.sniffer.packet_callback(packet)
            mock_print.assert_any_call("[DNS Query] google.com")

    def test_packet_callback_http(self):
        """
        Test the packet_callback with an HTTP packet.
        """
        packet = Ether()/IP()/TCP()/HTTPRequest(Host="www.google.com", Path="/")
        with patch('builtins.print') as mock_print:
            self.sniffer.packet_callback(packet)
            mock_print.assert_any_call("[HTTP] Host: www.google.com, Path: /")

    def test_live_analysis_callback(self):
        """
        Test the live_analysis_callback.
        """
        mock_callback = MagicMock()
        self.sniffer.live_analysis_callback = mock_callback
        packet = Ether()/IP()/ICMP()
        self.sniffer.packet_callback(packet)
        mock_callback.assert_called_once_with(packet)

    @patch('packet_sniffer.main.wrpcap')
    @patch('packet_sniffer.main.sniff')
    def test_start_and_save(self, mock_sniff, mock_wrpcap):
        """
        Test the start method and saving to a pcap file.
        """
        # Simulate sniffing one packet
        packet = Ether()/IP()/ICMP()
        self.sniffer.packets = [packet]
        self.sniffer.start()
        mock_sniff.assert_called_once_with(iface='lo', filter='icmp', count=1, prn=self.sniffer.packet_callback, stop_filter=ANY, store=0)
        mock_wrpcap.assert_called_once_with("test.pcap", [packet])

    def tearDown(self):
        """
        Clean up the test environment.
        """
        if os.path.exists("test.pcap"):
            os.remove("test.pcap")

if __name__ == "__main__":
    unittest.main()
