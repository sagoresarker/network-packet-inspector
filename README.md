# Network Packet Inspector using syscall

Network Packet Inspector is a Go-based tool for capturing and analyzing network packets implemeted without any pre-existing packet capture library rather using direct syscall. It provides a low-level interface to capture packets from network interfaces and analyze their contents across different OSI model layers.

*Note: This tool is only supported on Linux.*

## Dataflow Diagram

![Dataflow](/docs/images/network-packet-inspector-using-syscall.png)

## Features

- Capture packets from specified network interfaces
- Analyze packets at Link, Network, Transport, and Application layers
- Display detailed information about each captured packet
- List available network interfaces

## Prerequisites

- Go 1.22 or higher
- Linux operating system (the current implementation uses raw sockets, which are specific to Linux)
- Root privileges (required for packet capturing)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/sagoresarker/network-packet-inspector.git
   cd network-packet-inspector
   ```

2. Build the project:

   ```bash
   go build -o network-inspector ./cmd/inspector
   ```

## Usage

### List available network interfaces

```bash
sudo ./network-inspector -list
```

### Capture and analyze packets

```bash
sudo ./network-inspector -interface=<interface_name>
```

Replace `<interface_name>` with the name of the network interface you want to capture packets from (e.g., eth0, wlan0).

## Example Output

```
Timestamp: 2023-05-10T15:30:45Z
Link Layer:
Type: Ethernet
Source MAC: 00:1A:2B:3C:4D:5E
Destination MAC: FF:FF:FF:FF:FF:FF

Network Layer:
Type: IPv4
Source IP: 192.168.1.100
Destination IP: 192.168.1.1

Transport Layer:
Type: TCP
Source Port: 54321
Destination Port: 80

Application Layer:
Payload Length: 1024 bytes
Protocol: HTTP
```

## Note

This tool requires root privileges to capture packets. Always use it responsibly and in compliance with applicable laws and regulations.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.