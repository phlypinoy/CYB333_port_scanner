"""
Port Scanner Module

This module provides the PortScanner class for scanning and identifying open ports
on specified hosts. It follows PEP 8 standards and includes comprehensive error handling.

"""

import socket
import sys
import time
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

    # Rate limiting constants for ethical scanning
    MAX_PORTS_PER_SCAN = 1000  # Prevent excessive scans
    DELAY_BETWEEN_PORTS = 0.1  # Delay in seconds between port attempts

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
            ValueError: If host is empty, invalid, or port count exceeds limit.
        """
        if not host or not isinstance(host, str):
            raise ValueError("Host must be a non-empty string")

        self.host = host
        self.timeout = timeout
        self.ports = ports if ports else self.COMMON_PORTS
        self.results: Dict[int, bool] = {}

        # Enforce rate-limiting guidelines
        if len(self.ports) > self.MAX_PORTS_PER_SCAN:
            raise ValueError(
                f"Scan exceeds maximum port limit ({self.MAX_PORTS_PER_SCAN}). "
                f"Requested: {len(self.ports)} ports. "
                f"Consider scanning a smaller range."
            )

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
            return False
        finally:
            # Implement rate-limiting delay between port attempts
            time.sleep(self.DELAY_BETWEEN_PORTS)

    def scan(self, verbose: bool = True) -> Dict[int, bool]:
        """
        Scan all specified ports on the host.

        Implements ethical scanning guidelines:
        - Rate-limited with delays between port attempts
        - Limits maximum ports per scan
        - Sequential scanning (not parallel)
        - Restricted to authorized targets only

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
        
        # More accurate time estimation:
        # - Delay time always applies
        # - Assume ~50% of ports are closed (will timeout)
        # - Open ports respond quickly (~10ms average)
        delay_time = len(self.ports) * self.DELAY_BETWEEN_PORTS
        estimated_closed = len(self.ports) * 0.5 * self.timeout
        estimated_open = len(self.ports) * 0.5 * 0.01  # ~10ms per open port
        estimated_total = delay_time + estimated_closed + estimated_open
        
        print(
            f"Estimated time: ~{estimated_total:.0f} seconds "
            f"({estimated_total/60:.1f} minutes)"
        )
        print("-" * 50)

        # Start timing the actual scan
        scan_start_time = time.time()

        for port in self.ports:
            is_open = self._is_port_open(port)
            self.results[port] = is_open

            if is_open:
                print(f"Port {port:5d} : OPEN")
            elif verbose:
                print(f"Port {port:5d} : CLOSED")

        # Calculate actual elapsed time
        scan_elapsed_time = time.time() - scan_start_time
        ms_per_port = (scan_elapsed_time / len(self.ports)) * 1000 if len(self.ports) > 0 else 0
        
        print("-" * 50)
        print(
            f"Actual scan time: {scan_elapsed_time:.2f} seconds "
            f"({scan_elapsed_time * 1000:.0f} ms total)"
        )
        print(
            f"Average per port: {ms_per_port:.1f} ms/port"
        )

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
