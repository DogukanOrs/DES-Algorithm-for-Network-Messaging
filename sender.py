import socket
import sys
from des import des_encrypt


def main():
    print("=" * 50)
    print("  DES SENDER")
    print("=" * 50)

    # config
    receiver_ip = input("\n  Enter receiver IP [default: 127.0.0.1]: ").strip()
    if not receiver_ip:
        receiver_ip = "127.0.0.1"

    port_str = input("  Port [default: 65432]: ").strip()
    port = int(port_str) if port_str else 65432

    key_hex = input("  Key [default: 133457799BBCDFF1]: ").strip()
    if not key_hex:
        key_hex = "133457799BBCDFF1"

    if len(key_hex) != 16:
        print(" Key must be 16 hex characters.")
        sys.exit(1)

    key = bytes.fromhex(key_hex)

    print(f"\n  Key:    {key_hex.upper()}")
    print(f"  Target: {receiver_ip}:{port}")

    # server side
    print(f"\n  Connecting to {receiver_ip}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((receiver_ip, port))
        print("  exit to quit.\n")
    except ConnectionRefusedError:
        print(f"  can not connect")
        sys.exit(1)
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    msg_count = 0

    try:
        while True:
            message = input(" Message: ").strip()

            if not message:
                continue
            if message.lower() in ('exit', 'quit'):
                sock.sendall(b"__EXIT__\n")
                print("  disconnected")
                break

            msg_count += 1
            plaintext = message.encode('utf-8')

            # Encrypt the message with DES
            ciphertext = des_encrypt(plaintext, key)

            # Show what is being sent
            print(f"  Plaintext:  {message}")
            print(f"  Ciphertext: {ciphertext.hex().upper()}")

            # Send ciphertext as hex string
            hex_data = ciphertext.hex().upper() + "\n"
            sock.sendall(hex_data.encode('utf-8'))
            print("  Sent!")

            # Wait for acknowledgment
            ack = sock.recv(4096).decode('utf-8').strip()
            if ack:
                print(f"  Receiver: {ack}")
            print()

    except (BrokenPipeError, ConnectionResetError):
        print("\n  Connection lost!")
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        try:
            sock.sendall(b"__EXIT__\n")
        except:
            pass
    finally:
        sock.close()

    print(f"\n  {msg_count} message(s) sent. Done.")


if __name__ == "__main__":
    main()
