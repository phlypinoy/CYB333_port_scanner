"""
Port Scanner Module

This module provides the PortScanner class for scanning and identifying open ports
on specified hosts. It follows PEP 8 standards and includes comprehensive error handling.

"""

import socket
import sys
from typing import List, Dict, Tuple


class PortScanner:
    """
    A class to scan and identify open ports on a specified host.

    Attributes:
        host (str): The hostname or IP address to scan.
        common_ports (List[int]): List of ports to scan (default: common ports).
        timeout (float): Timeout value for socket connections in seconds.
        results (Dict): Dictionary to store scanning results.
    """

    # Common ports to scan if user doesn't specify
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
        993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 27017
    ]

    def __init__(
        self,
        host: str,
        timeout: float = 2.0,
        ports: List[int] | None = None
    ) -> None:
        """
        Initialize the PortScanner.

        Args:
            host: Hostname or IP address to scan.
            timeout: Socket timeout in seconds (default: 2.0).
            ports: List of ports to scan (default: COMMON_PORTS).

        Raises:
            ValueError: If host is empty or invalid.
        """
        if not host or not isinstance(host, str):
            raise ValueError("Host must be a non-empty string")

        self.host = host
        self.timeout = timeout
        self.ports = ports if ports else self.COMMON_PORTS
        self.results: Dict[int, bool] = {}

    def _validate_host(self) -> bool:
        """
        Validate that the host can be resolved.

        Returns:
            bool: True if host is valid, False otherwise.
        """
        try:
            socket.gethostbyname(self.host)
            return True
        except socket.gaierror:
            print(f"Error: Cannot resolve hostname '{self.host}'")
            return False

    def _is_port_open(self, port: int) -> bool:
        """
        Check if a single port is open on the host.

        Args:
            port: Port number to check.

        Returns:
            bool: True if port is open, False otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.host, port))
                return result == 0
        except socket.timeout:
            return False
        except socket.error as e:
            print(f"Socket error on port {port}: {e}")
            return False

    def scan(self, verbose: bool = True) -> Dict[int, bool]:
        """
        Scan all specified ports on the host.

        Args:
            verbose: If True, print progress updates during scan.

        Returns:
            Dict: Dictionary mapping port numbers to their open status.

        Raises:
            RuntimeError: If host validation fails.
        """
        if not self._validate_host():
            raise RuntimeError(f"Unable to validate host: {self.host}")

        print(f"\nScanning host: {self.host}")
        print(f"Scanning {len(self.ports)} ports...")
        print("-" * 50)

        for port in self.ports:
            is_open = self._is_port_open(port)
            self.results[port] = is_open

            if is_open:
                print(f"Port {port:5d} : OPEN")
            elif verbose:
                print(f"Port {port:5d} : CLOSED")

        return self.results

    def get_open_ports(self) -> List[int]:
        """
        Get a list of all open ports found during the scan.

        Returns:
            List[int]: List of open port numbers.
        """
        return [port for port, is_open in self.results.items() if is_open]

    def get_summary(self) -> str:
        """
        Get a summary of the scan results.

        Returns:
            str: Formatted summary of scan results.
        """
        if not self.results:
            return "No scan results available. Run scan() first."

        open_ports = self.get_open_ports()
        total_ports = len(self.results)
        open_count = len(open_ports)

        summary = f"\n{'=' * 50}\n"
        summary += f"Scan Summary for {self.host}\n"
        summary += f"{'=' * 50}\n"
        summary += f"Total ports scanned: {total_ports}\n"
        summary += f"Open ports found: {open_count}\n"
        summary += f"Closed ports: {total_ports - open_count}\n"

        if open_ports:
            summary += f"\nOpen Ports: {', '.join(map(str, sorted(open_ports)))}\n"
        else:
            summary += "\nNo open ports found.\n"

        summary += f"{'=' * 50}\n"

        return summary

    def __str__(self) -> str:
        """Return string representation of the PortScanner."""
        return f"PortScanner(host={self.host}, ports={len(self.ports)})"
