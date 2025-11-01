# Python Packet Sniffer for Educational Purposes

This project is a simple packet sniffer written in Python using the `scapy` library. It is designed for educational purposes to help users understand network traffic analysis and how packet sniffers work.

> **Disclaimer:** This tool is intended for educational purposes ONLY. Using this software to capture network packets on any network without the owner's explicit permission is illegal and unethical. The author is not responsible for any damage or misuse of this software.

## Ethical Considerations

Packet sniffing technology is powerful and comes with significant ethical responsibilities. This project is meant to facilitate learning in a controlled and ethical environment.

- **Authorization is Required:** Only use this packet sniffer on a network that you own or for which you have received explicit, written permission to monitor.
- **Respect Privacy:** Do not attempt to capture or inspect private data. Focus on understanding network protocols and headers.
- **Educational Focus:** The goal is to learn about network security, not to engage in surveillance or malicious activities.
- **Know the Law:** Be aware of local and national laws regarding network monitoring and privacy before using this tool.

## Features

- **Live Packet Capture:** Captures network packets in real-time on a specified interface.
- **Protocol Analysis:** Decodes and displays information for various protocols (Ethernet, IP, TCP, UDP, ICMP).
- **Customizable Filtering:** Uses BPF syntax to filter for specific types of packets.
- **PCAP File Output:** Saves captured packets to a `.pcap` file for offline analysis with tools like Wireshark.

## Project Structure

```
.
├── packet_sniffer/
│   ├── __init__.py
│   └── main.py
├── tests/
│   ├── __init__.py
│   └── test_sniffer.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Prerequisites

- Python 3.7+
- `pip` for installing dependencies
- A compatible packet capture library:
    - **Linux:** `libpcap` (usually installed via your package manager, e.g., `sudo apt-get install libpcap-dev`)
    - **Windows:** `Npcap` (download from the [Npcap website](https://npcap.com/))
    - **macOS:** `libpcap` is typically pre-installed.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/Python-Packet-Sniffer-Educational.git
    cd Python-Packet-Sniffer-Educational
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Running the packet sniffer requires root/administrator privileges to access the network interface in promiscuous mode.

```bash
sudo python packet_sniffer/main.py -i <interface>
```

### Command-Line Arguments

- `-i`, `--interface`: The network interface to sniff on (e.g., `eth0`, `en0`, `Wi-Fi`).
- `-f`, `--filter`: BPF filter for capturing specific packets (e.g., `"tcp port 80"`).
- `-c`, `--count`: The number of packets to capture (default is 0, for unlimited).
- `-o`, `--output`: The file to save the captured packets in PCAP format.

### Examples

- **Sniff 10 TCP packets on interface `eth0`:**
  ```bash
  sudo python packet_sniffer/main.py -i eth0 -f "tcp" -c 10
  ```

- **Capture all DNS traffic on interface `en0` and save it to a file:**
  ```bash
  sudo python packet_sniffer/main.py -i en0 -f "udp port 53" -o dns_traffic.pcap
  ```

## Testing

To run the automated tests, execute the following command from the project's root directory:

```bash
python -m unittest discover tests
```

## Contributing

Contributions are welcome! If you have ideas for improvements or have found a bug, please open an issue or submit a pull request.

1.  **Fork the repository.**
2.  **Create a new branch:** `git checkout -b feature/your-feature-name`
3.  **Make your changes and commit them:** `git commit -m 'Add some feature'`
4.  **Push to the branch:** `git push origin feature/your-feature-name`
5.  **Open a pull request.**

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
