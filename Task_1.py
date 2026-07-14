import argparse
from scapy.all import sniff, wrpcap, IP
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.l2 import ARP


def extract_packet_info(packet):
    info = {}

    if packet.haslayer(ARP):
        info["protocol"] = "ARP"
        info["sender_ip"] = packet[ARP].psrc
        info["target_ip"] = packet[ARP].pdst

    elif packet.haslayer(IP):
        info["source_ip"] = packet[IP].src
        info["destination_ip"] = packet[IP].dst

        if packet.haslayer(TCP):
            info["protocol"] = "TCP"
            info["source_port"] = packet[TCP].sport
            info["destination_port"] = packet[TCP].dport

        elif packet.haslayer(UDP):
            info["protocol"] = "UDP"
            info["source_port"] = packet[UDP].sport
            info["destination_port"] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            info["protocol"] = "ICMP"
            info["type"] = packet[ICMP].type
            info["code"] = packet[ICMP].code

        elif packet[IP].proto == 2:
            info["protocol"] = "IGMP"

        elif packet[IP].proto == 41:
            info["protocol"] = "IPv6"

        elif packet[IP].proto == 47:
            info["protocol"] = "GRE"

        elif packet[IP].proto == 50:
            info["protocol"] = "ESP (IPsec)"

        elif packet[IP].proto == 51:
            info["protocol"] = "AH (IPsec)"

        elif packet[IP].proto == 89:
            info["protocol"] = "OSPF"

        else:
            info["protocol"] = f"OTHER [{packet[IP].proto}]"

    else:
        return None

    return info


def display_packet(info):
    if info is None:
        return

    print("Packet..........")

    if info["protocol"] == "ARP":
        print(f"Protocol: {info['protocol']}")
        print(f"Sender IP: {info['sender_ip']}")
        print(f"Target IP: {info['target_ip']}")

    else:
        print(f"Source IP: {info['source_ip']}")
        print(f"Destination IP: {info['destination_ip']}")
        print(f"Protocol: {info['protocol']}")

        if info["protocol"] in ["TCP", "UDP"]:
            print(f"Source Port: {info['source_port']}")
            print(f"Destination Port: {info['destination_port']}")

        elif info["protocol"] == "ICMP":
            print(f"Type: {info['type']}")
            print(f"Code: {info['code']}")

    print()


def packet_info(packet):
    info = extract_packet_info(packet)
    display_packet(info)


def main():
    parser = argparse.ArgumentParser(description="Simple network sniffer using Scapy")
    parser.add_argument("-i", "--iface", help="Interface to sniff on (default: Scapy auto-select)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-o", "--pcap", help="Save captured packets to a .pcap file")
    args = parser.parse_args()

    captured = []

    def handler(packet):
        packet_info(packet)
        if args.pcap:
            captured.append(packet)

    try:
        sniff(prn=handler, iface=args.iface, count=args.count, store=False)
    except PermissionError:
        print("Permission denied. Run this script with sudo/root privileges.")
        return
    except OSError as e:
        print(f"Interface error: {e}")
        return
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        if args.pcap and captured:
            wrpcap(args.pcap, captured)
            print(f"Saved {len(captured)} packets to {args.pcap}")


if __name__ == "__main__":
    main()