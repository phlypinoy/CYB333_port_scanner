#!/usr/bin/env python3
"""
Port Scanner Application

Main entry point for the port scanner application. This script orchestrates
the user interface and port scanning functionality.

Author: Network Security Team
Version: 1.0
Python: 3.12+
License: MIT

Usage:
    python3 main.py
"""

import sys
from port_scanner import PortScanner
from menu import MenuManager


def main() -> None:
    """
    Main application function.

    Orchestrates the menu system and port scanning operations.
    Handles all user interactions and errors.
    """
    try:
        while True:
            # Display main menu
            MenuManager.display_main_menu()

            # Get user choice
            choice = MenuManager.get_user_choice()

            # Handle exit
            if choice == "3":
                MenuManager.display_exit_message()
                break

            # Get target information
            target_info = MenuManager.get_target_by_choice(choice)
            if target_info is None:
                print("Invalid selection. Please try again.")
                continue

            host, target_name = target_info

            # Get port selection
            ports = MenuManager.get_port_input()

            # Create and execute scanner
            try:
                if ports:
                    scanner = PortScanner(host, ports=ports)
                else:
                    scanner = PortScanner(host)

                print(f"\nStarting port scan on {target_name}...")
                print("This may take a moment...\n")

                # Perform the scan, verbose output gives progress
                scanner.scan(verbose=True)

                # Display summary
                print(scanner.get_summary())

                # Ask if user wants to scan again or exit
                while True:
                    again = input(
                        "Perform another scan? (yes/no): "
                    ).strip().lower()

                    if again in ["yes", "y"]:
                        break
                    elif again in ["no", "n"]:
                        MenuManager.display_exit_message()
                        return
                    else:
                        print("Please enter 'yes' or 'no'.")

            except RuntimeError as e:
                print(f"\nScan Error: {e}")
                print("Please try again with a valid target.\n")
            except Exception as e:
                print(f"\nUnexpected error during scan: {e}")
                print("Please try again.\n")

    except KeyboardInterrupt:
        print("\n\nApplication interrupted by user.")
        print("Exiting...\n")
        sys.exit(0)
    except Exception as e:
        print(f"\nCritical error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
