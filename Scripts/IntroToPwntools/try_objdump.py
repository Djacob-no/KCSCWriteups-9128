#!/usr/bin/env python3
from pwn import *
import base64
import os
import subprocess

# Set up context
context.arch = 'amd64'
context.log_level = 'critical'

# Connect to the server
conn = remote('zerodayheroes-072d21aa-pwnintro.kongsberg-ctf.com', 1337, ssl=True)

# Get ready prompt and send yes
conn.recvuntil(b'[yes/no] ')
conn.sendline(b'yes')

# Get the base64 binary data
data = conn.recvuntil(b'> ', timeout=30)

# Extract base64 from the data
base64_start = data.find(b'Base64 ELF: ')
base64_start += len(b'Base64 ELF: ')
base64_end = data.find(b'[?]', base64_start)
actual_base64 = data[base64_start:base64_end].strip()

# Decode the binary
binary_data = base64.b64decode(actual_base64)

# Save and make executable
binary_path = '/tmp/challenge_binary_objdump'
with open(binary_path, 'wb') as f:
    f.write(binary_data)
os.chmod(binary_path, 0o755)

# Run the binary to get output
proc = process(binary_path)
output = proc.recvall(timeout=2).strip()
proc.close()

# Use objdump to get symbols
try:
    result = subprocess.run(['objdump', '-t', binary_path], 
                          capture_output=True, text=True, timeout=5)
    print("Objdump symbols:")
    print(result.stdout)
    
    # Look for win_function in the objdump output
    for line in result.stdout.split('\n'):
        if 'win_function' in line:
            print(f"Win function line: {line}")
            # Extract address from the line
            parts = line.split()
            if len(parts) > 0:
                addr_str = parts[0]
                try:
                    addr_int = int(addr_str, 16)
                    print(f"Address from objdump: {addr_str}")
                except:
                    pass
except Exception as e:
    print(f"Objdump failed: {e}")

# Also try nm
try:
    result = subprocess.run(['nm', binary_path], 
                          capture_output=True, text=True, timeout=5)
    print("\nNm symbols:")
    print(result.stdout)
    
    for line in result.stdout.split('\n'):
        if 'win_function' in line:
            print(f"Win function from nm: {line}")
            parts = line.split()
            if len(parts) > 0:
                addr_str = parts[0]
                print(f"Trying nm address: {addr_str}")
except Exception as e:
    print(f"nm failed: {e}")

# Get win_function address using pwntools
elf = ELF(binary_path, checksec=False)
win_address = elf.symbols['win_function']

# Send first answer
conn.sendline(output)

# Wait for second question and try the nm address if available
conn.recvuntil(b'> ', timeout=5)

# Try to extract from nm output
try:
    result = subprocess.run(['nm', binary_path], 
                          capture_output=True, text=True, timeout=2)
    for line in result.stdout.split('\n'):
        if 'win_function' in line:
            parts = line.split()
            if len(parts) > 0:
                nm_addr = parts[0]
                print(f"Sending nm address: {nm_addr}")
                conn.sendline(nm_addr.encode())
                break
    else:
        # Fallback to pwntools address
        conn.sendline(f"{win_address:x}".encode())
except:
    conn.sendline(f"{win_address:x}".encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()