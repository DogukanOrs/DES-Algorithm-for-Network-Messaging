#!/usr/bin/env python3
"""
DES Receiver Process
CMSE456/CMPE455 - Lab 2 - DES on Two Computers

This process:
1. Listens for a sender connection
2. Receives and decrypts multiple messages
3. Connection stays open until sender disconnects
"""

import socket
import sys
from des import des_decrypt


def main():
    print("=" * 50)
    print("  DES RECEIVER")
    print("=" * 50)

    # Config
    listen_ip = input("\n  listen ip (default:[0.0.0.0]): ").strip()
    if not listen_ip:
        listen_ip = "0.0.0.0"

    port_str = input("  Port (default:[65432]): ").strip()
    port = int(port_str) if port_str else 65432

    key_hex = input("  Key (default:133457799BBCDFF1): ").strip()
    if not key_hex:
        key_hex = "133457799BBCDFF1"

    if len(key_hex) != 16:
        print(" Key must be 16 hex characters.")
        sys.exit(1)

    key = bytes.fromhex(key_hex)

    print(f"\n  Key:        {key_hex.upper()}")
    print(f"  Listening:  {listen_ip}:{port}")

   #Server side 
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((listen_ip, port))
        server.listen(1)

        print(f"\n  Waiting for sender...")

        conn, addr = server.accept()
        print(f"  Sender connected from {addr[0]}:{addr[1]}")
        print(f"  Waiting for messages...\n")

        msg_count = 0
        buffer = ""

        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    print("  Sender disconnected.")
                    break

                buffer += chunk.decode('utf-8')

                # Process complete messages (newline-separated)
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()

                    if not line:
                        continue

                    if line == "__EXIT__":
                        print("  Sender disconnected.")
                        raise StopIteration

                    msg_count += 1

                    try:
                        ciphertext = bytes.fromhex(line)

                        # Decrypt with DES
                        plaintext = des_decrypt(ciphertext, key)
                        message = plaintext.decode('utf-8')

                        # Display the result
                        print(f"  Message #{msg_count}")
                        print(f"  Ciphertext: {line}")
                        print(f"  Decrypted:  {message}")
                        print()

                        # Send acknowledgment
                        ack = f"ACK #{msg_count}: \"{message}\""
                        conn.sendall((ack + "\n").encode('utf-8'))

                    except Exception as e:
                        print(f"  ERROR on message #{msg_count}: {e}")
                        conn.sendall(f"ERROR: {e}\n".encode('utf-8'))

        except StopIteration:
            pass
        except KeyboardInterrupt:
            print("\n  Interrupted.")
        finally:
            conn.close()
            server.close()

    except OSError as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    print(f"\n  {msg_count} message(s) received. Done.")


if __name__ == "__main__":
    main()
