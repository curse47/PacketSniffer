#!/usr/bin/env python3
"""
Basic Network Sniffer
----------------------
Captures live packets and displays useful info: source/destination IPs,
protocol, ports, and a preview of the payload.

Requires root/administrator privileges to open a raw socket.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Simple counters for a summary at the end
packet_count = 0
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}


def get_protocol_name(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "Other"


def process_packet(packet):
    """Callback executed for every captured packet."""
    global packet_count

    if not packet.haslayer(IP):
        return  # Skip non-IP packets (e.g. ARP) for this basic version

    packet_count += 1
    ip_layer = packet[IP]
    proto = get_protocol_name(packet)
    protocol_counts[proto] += 1

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Base info line
    info = f"[{timestamp}] #{packet_count} {proto:5s} {src_ip} -> {dst_ip}"

    # Add port info for TCP/UDP
    if packet.haslayer(TCP):
        info += f"  Port: {packet[TCP].sport} -> {packet[TCP].dport}"
        flags = packet[TCP].flags
        info += f"  Flags: {flags}"
    elif packet.haslayer(UDP):
        info += f"  Port: {packet[UDP].sport} -> {packet[UDP].dport}"

    print(info)

    # Show a short preview of the payload, if any
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            decoded = payload.decode("utf-8", errors="replace")
            preview = decoded[:80].replace("\n", " ").replace("\r", "")
        except Exception:
            preview = str(payload[:40])
        print(f"    Payload preview: {preview}")

    print(f"    Packet size: {len(packet)} bytes")
    print("-" * 70)


def print_summary():
    print("\n" + "=" * 70)
    print("CAPTURE SUMMARY")
    print("=" * 70)
    print(f"Total packets captured: {packet_count}")
    for proto, count in protocol_counts.items():
        print(f"  {proto}: {count}")
    print("=" * 70)


def main():
    print("Starting network sniffer... Press Ctrl+C to stop.\n")
    print("-" * 70)

    try:
        # count=0 means capture indefinitely until Ctrl+C
        # Add filter="tcp" or filter="udp port 53" etc. to narrow capture
        sniff(prn=process_packet, store=False, count=0)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\nError: You need root/administrator privileges to sniff packets.")
        print("Try running with: sudo python3 sniffer.py")
    finally:
        print_summary()


if __name__ == "__main__":
    main()