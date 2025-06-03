# Network Scanner

A powerful and user-friendly network scanning tool that discovers devices on a local network using ARP requests. This tool is designed to be a comprehensive solution for network discovery, with features like IP validation, detailed output formatting, and result export capabilities.

## Features

- **Network Discovery**: Scan your local network to find all connected devices
- **User-Friendly Output**: Clear, formatted display of discovered devices
- **Flexible Scanning**: Adjustable timeout settings for different network environments
- **Result Export**: Save scan results to CSV files for further analysis
- **Verbose Mode**: Detailed output with additional information about the scanning process
- **Input Validation**: Robust validation of IP ranges and other inputs
- **Error Handling**: Comprehensive error handling for a smooth user experience
- **Privilege Checking**: Automatic verification of required permissions

## Requirements

- Python 3.6 or higher
- Scapy library
- Root/Administrator privileges (required for sending raw packets)

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24
```

### Command Line Arguments

- `-t, --target`: Target IP address or IP range (CIDR notation) [required]
- `-v, --verbose`: Enable verbose output
- `-o, --output`: Save results to a file (specify filename)
- `--timeout`: Timeout for ARP requests in seconds (default: 1.0)

### Examples

Scan a specific IP range with verbose output:

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24 -v
```

Scan with a longer timeout (useful for slower networks):

```bash
sudo python3 network_scanner.py -t 10.0.0.0/24 --timeout 2.5
```

Save scan results to a file:

```bash
sudo python3 network_scanner.py -t 172.16.0.0/16 -o network_scan_results.csv
```

## How It Works

The Network Scanner uses ARP (Address Resolution Protocol) requests to discover devices on a local network. Here's how it works:

1. The script sends ARP requests to all IP addresses in the specified range
2. Devices that are online respond with their MAC addresses
3. The script collects these responses and displays the results
4. If specified, results can be saved to a file for later analysis

## Technical Details

- Uses Scapy for packet crafting and sending
- Implements proper error handling for various scenarios
- Validates input to prevent incorrect usage
- Formats output for better readability
- Provides detailed logging in verbose mode

## Security Considerations

Network scanning can be considered intrusive in some environments. Always ensure you have permission to scan the target network. This tool should only be used on networks you own or have explicit permission to scan.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Scapy library for making packet manipulation easy
- All contributors to the project
