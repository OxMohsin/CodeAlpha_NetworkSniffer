# CodeAlpha Task 1 — Network Sniffer

A Python-based network packet sniffer built with Scapy. Captures live traffic and displays protocol-level details for each packet.

## Features

- Captures live packets on a specified network interface
- Parses and displays:
  - ARP (sender/target IP)
  - TCP and UDP (source/destination IP and port)
  - ICMP (type and code)
  - Other IP protocols (IGMP, IPv6, GRE, ESP, AH, OSPF) identified by protocol number
- Optional packet count limit (or run indefinitely until stopped)
- Optional `.pcap` file export for later analysis in Wireshark

## Requirements

- Python 3
- Scapy (`pip install scapy`)
- Root/administrator privileges (raw socket access)

## Usage

```bash
sudo python3 Task_1.py -i <interface> -c <count> -o <output.pcap>
```

**Arguments:**

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--iface` | Network interface to sniff on | Scapy auto-selected |
| `-c`, `--count` | Number of packets to capture (0 = infinite) | 0 |
| `-o`, `--pcap` | Save captured packets to a `.pcap` file | Not saved |

**Example:**

```bash
sudo python3 Task_1.py -i wlan0 -c 20 -o capture.pcap
```

## Sample Output

```
Packet..........
Source IP: 192.168.0.107
Destination IP: 142.250.202.165
Protocol: TCP
Source Port: 49660
Destination Port: 443

Packet..........
Source IP: 192.168.0.107
Destination IP: 192.168.0.1
Protocol: UDP
Source Port: 42319
Destination Port: 53
```

## Design Notes

- Packet parsing (`extract_packet_info`) and display logic (`display_packet`) are kept separate, so captured data can be reused for logging, filtering, or export without touching the print logic.
- Unrecognized non-IP, non-ARP frames are skipped (`extract_packet_info` returns `None`).
- Script exits cleanly on `Ctrl+C`, permission errors, and invalid interface names instead of dumping a stack trace.

