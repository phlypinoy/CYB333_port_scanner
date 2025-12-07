"""
Menu Module

This module provides the user interface menu for the port scanner application.
It handles user input validation and target selection.

Author: Network Security Team
Version: 1.0
Python: 3.12+
"""

from typing import Tuple


class MenuManager:
    """
    A class to manage the user interface menu for the port scanner.

    Attributes:
        AUTHORIZED_TARGETS (Dict): Dictionary of authorized scan targets.
    """

    AUTHORIZED_TARGETS = {
        "1": {
            "name": "localhost (127.0.0.1)",
            "host": "127.0.0.1",
            "description": "Scan your local machine"
        },
        "2": {
            "name": "scanme.nmap.org",
            "host": "scanme.nmap.org",
            "description": "Scan the authorized nmap test server"
        }
    }

    @staticmethod
    def display_main_menu() -> None:
        """Display the main menu options to the user."""
        print("\n" + "=" * 60)
        print("PORT SCANNER - Main Menu")
        print("=" * 60)
        print("\nAuthorized Scan Targets:\n")

        for key, target in MenuManager.AUTHORIZED_TARGETS.items():
            print(f"  {key}. {target['name']}")
            print(f"     {target['description']}\n")

        print("  3. Exit\n")
        print("=" * 60)

    @staticmethod
    def get_user_choice() -> str:
        """
        Get and validate user input for menu selection.

        Returns:
            str: Valid user choice (1, 2, or 3).
        """
        valid_choices = ["1", "2", "3"]

        while True:
            try:
                choice = input("\nEnter your choice (1-3): ").strip()

                if choice not in valid_choices:
                    print(
                        f"Invalid choice. Please enter 1, 2, or 3."
                    )
                    continue

                return choice

            except KeyboardInterrupt:
                print("\n\nOperation cancelled by user.")
                return "3"
            except Exception as e:
                print(f"Error reading input: {e}")
                continue

    @staticmethod
    def get_target_by_choice(choice: str) -> Tuple[str, str] | None:
        """
        Get the target host information based on user choice.

        Args:
            choice: User's menu choice.

        Returns:
            Tuple[str, str] | None: (host, description) if valid choice,
                                     None if user chose to exit.
        """
        if choice == "3":
            return None

        if choice in MenuManager.AUTHORIZED_TARGETS:
            target = MenuManager.AUTHORIZED_TARGETS[choice]
            return (target["host"], target["name"])

        return None

    @staticmethod
    def get_port_input() -> list[int] | None:
        """
        Get port input from user (optional).

        Returns:
            list[int] | None: List of ports if user provides them,
                              None to use default common ports.
        """
        print("\n" + "-" * 60)
        print("Port Selection Options:")
        print("-" * 60)
        print("1. Scan common ports (default)")
        print("2. Enter custom ports")
        print("-" * 60)

        choice = input("\nEnter your choice (1-2): ").strip()

        if choice == "2":
            while True:
                try:
                    port_input = input(
                        "\nEnter ports (comma-separated, e.g., 22,80,443): "
                    ).strip()

                    if not port_input:
                        print("Port input cannot be empty.")
                        continue

                    ports = [
                        int(p.strip())
                        for p in port_input.split(",")
                        if p.strip()
                    ]

                    # Validate port numbers
                    for port in ports:
                        if not 1 <= port <= 65535:
                            print(
                                f"Invalid port: {port}. "
                                "Ports must be between 1 and 65535."
                            )
                            raise ValueError()

                    print(f"Selected ports: {sorted(ports)}")
                    return ports

                except ValueError as e:
                    print(f"Error parsing ports: {e}")
                    continue
                except KeyboardInterrupt:
                    print("\n\nPort selection cancelled.")
                    return None
                except Exception as e:
                    print(f"Unexpected error: {e}")
                    continue

        return None  # Use default common ports

    @staticmethod
    def display_exit_message() -> None:
        """Display exit message."""
        print("\n" + "=" * 60)
        print("Thank you for using Port Scanner!")
        print("Scan complete. Exiting...")
        print("=" * 60 + "\n")
