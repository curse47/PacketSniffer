# PacketSniffer
A Python packet sniffer built with **Scapy** that captures live network
traffic in real time and breaks it down into readable, structured output.
It identifies protocols (TCP/UDP/ICMP), extracts source and destination
IPs and ports, previews unencrypted payloads, and prints a summary of
captured traffic by protocol type — a practical, hands-on way to learn
how data actually moves across a network and the basics of common
protocols.

## Features
- Live packet capture using Scapy
- Protocol identification (TCP, UDP, ICMP)
- Source/destination IP and port extraction
- TCP flag inspection
- Payload preview for unencrypted traffic
- Capture summary with per-protocol packet counts

## Tech Stack
- Python 3
- Scapy
- Npcap (Windows) - required for raw packet capture

- ## ⚠️ Disclaimer
This project is for educational purposes only. Only capture and monitor
traffic on networks and devices you own or have explicit authorization
to test. Unauthorized packet sniffing may be illegal in your jurisdiction.
