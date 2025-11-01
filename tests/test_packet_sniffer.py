
import unittest
from packet_sniffer.main import PacketSniffer

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

if __name__ == "__main__":
    unittest.main()
