
# !/usr/bin/env python3
"""
Network Scanner

A tool for discovering devices on a local network using ARP requests.
This script scans the specified IP range and displays the IP and MAC addresses
of all responsive devices on the network.

Author:Mr.Robot 
"""

import sys
import time
import ipaddress
from typing import Dict, List, Optional, Tuple, Union
import argparse
import scapy.all as scapy


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command line arguments

    Raises:
        SystemExit: If required arguments are missing or invalid
    """
    parser = argparse.ArgumentParser(
        description="Network Scanner - Discover devices on your network",
        epilog="Example: sudo python3 network_scanner.py -t 192.168.1.0/24"
    )

    parser.add_argument(
        "-t", "--target",
        dest="target",
        help="Target IP address or IP range (CIDR notation, e.g., 192.168.1.0/24)",
        required=True
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "-o", "--output",
        help="Save results to a file (specify filename)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout for ARP requests in seconds (default: 1.0)"
    )

    return parser.parse_args()


def validate_ip_range(ip_range: str) -> bool:
    """
    Validate if the provided IP range is in correct CIDR notation.

    Args:
        ip_range (str): IP range in CIDR notation (e.g., 192.168.1.0/24)

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def scan_network(ip_range: str, timeout: float = 1.0, verbose: bool = False) -> List[Dict[str, str]]:
    """
    Scan the network for devices using ARP requests.

    Args:
        ip_range (str): IP range in CIDR notation (e.g., 192.168.1.0/24)
        timeout (float): Timeout for ARP requests in seconds
        verbose (bool): Whether to print verbose output during scanning

    Returns:
        List[Dict[str, str]]: List of dictionaries containing IP and MAC addresses
                             of discovered devices

    Raises:
        PermissionError: If the script doesn't have sufficient privileges
        RuntimeError: If the scan fails for other reasons
    """
    if verbose:
        print(f"[*] Scanning network range: {ip_range}")
        print(f"[*] Timeout set to: {timeout} seconds")
        start_time = time.time()

    try:
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=ip_range)

        # Create Ethernet frame with broadcast MAC
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine Ethernet frame and ARP request
        arp_request_broadcast = broadcast/arp_request

        # Send packets and receive responses
        if verbose:
            print("[*] Sending ARP requests...")

        # srp returns answered and unanswered packets
        answered, _ = scapy.srp(
            arp_request_broadcast,
            timeout=timeout,
            verbose=False
        )

        # Process results
        clients_list = []
        for sent, received in answered:
            clients_list.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })

        if verbose:
            scan_time = time.time() - start_time
            print(f"[+] Scan completed in {scan_time:.2f} seconds")
            print(f"[+] Discovered {len(clients_list)} devices")

        return clients_list

    except PermissionError:
        raise PermissionError("Insufficient privileges. Try running with sudo.")
    except Exception as e:
        raise RuntimeError(f"Scan failed: {str(e)}")


def format_mac_address(mac: str) -> str:
    """
    Format MAC address for better readability.

    Args:
        mac (str): MAC address

    Returns:
        str: Formatted MAC address
    """
    return mac.upper()


def display_results(results: List[Dict[str, str]], verbose: bool = False) -> None:
    """
    Display scan results in a formatted table.

    Args:
        results (List[Dict[str, str]]): List of dictionaries containing IP and MAC addresses
        verbose (bool): Whether to display additional information
    """
    if not results:
        print("No devices found.")
        return

    # Sort results by IP address for better readability
    results.sort(key=lambda x: [int(part) for part in x["ip"].split(".")])

    # Calculate column widths based on content
    ip_width = max(len("IP Address"), max(len(client["ip"]) for client in results))
    mac_width = max(len("MAC Address"), max(len(client["mac"]) for client in results))

    # Print header
    header = f"{'IP Address':<{ip_width}} | {'MAC Address':<{mac_width}}"
    separator = "-" * len(header)
    print(separator)
    print(header)
    print(separator)

    # Print results
    for client in results:
        formatted_mac = format_mac_address(client["mac"])
        print(f"{client['ip']:<{ip_width}} | {formatted_mac:<{mac_width}}")

    print(separator)

    if verbose:
        print(f"\nTotal devices discovered: {len(results)}")

        # Count unique manufacturers (first 6 digits of MAC address)
        manufacturers = {}
        for client in results:
            mac_prefix = client["mac"].replace(":", "")[:6].upper()
            if mac_prefix in manufacturers:
                manufacturers[mac_prefix] += 1
            else:
                manufacturers[mac_prefix] = 1

        print(f"Unique MAC address prefixes: {len(manufacturers)}")


def save_results_to_file(results: List[Dict[str, str]], filename: str) -> None:
    """
    Save scan results to a file.

    Args:
        results (List[Dict[str, str]]): List of dictionaries containing IP and MAC addresses
        filename (str): Name of the file to save results to

    Raises:
        IOError: If the file cannot be written
    """
    try:
        with open(filename, "w") as f:
            f.write("IP Address,MAC Address\n")
            for client in results:
                f.write(f"{client['ip']},{client['mac']}\n")
        print(f"[+] Results saved to {filename}")
    except IOError as e:
        print(f"[!] Error saving results to file: {str(e)}")


def check_privileges() -> bool:
    """
    Check if the script is running with sufficient privileges.

    Returns:
        bool: True if running with sufficient privileges, False otherwise
    """
    try:
        # Try to create a raw socket, which requires root privileges
        s = scapy.conf.L3socket()
        s.close()
        return True
    except OSError:
        return False


def main() -> int:
    """
    Main function to execute the network scanner.

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    print("Network Scanner v1.0")
    print("--------------------")

    # Check privileges
    if not check_privileges():
        print("[!] Error: This script requires root/administrator privileges.")
        print("[!] Please run with sudo or as administrator.")
        return 1

    try:
        # Parse arguments
        args = parse_arguments()

        # Validate IP range
        if not validate_ip_range(args.target):
            print(f"[!] Error: Invalid IP range format: {args.target}")
            print("[!] Please use CIDR notation (e.g., 192.168.1.0/24)")
            return 1

        # Scan network
        print(f"[*] Scanning target: {args.target}")
        scan_results = scan_network(
            args.target,
            timeout=args.timeout,
            verbose=args.verbose
        )

        # Display results
        print("\nScan Results:")
        display_results(scan_results, verbose=args.verbose)

        # Save results if output file specified
        if args.output:
            save_results_to_file(scan_results, args.output)

        return 0

    except PermissionError as e:
        print(f"[!] Error: {str(e)}")
        return 1
    except RuntimeError as e:
        print(f"[!] Error: {str(e)}")
        return 1
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return 130
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
