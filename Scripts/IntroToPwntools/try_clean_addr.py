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
binary_path = '/tmp/challenge_binary_clean'
with open(binary_path, 'wb') as f:
    f.write(binary_data)
os.chmod(binary_path, 0o755)

# Run the binary to get output
proc = process(binary_path)
output = proc.recvall(timeout=2).strip()
proc.close()

# Get address using nm and clean it up
result = subprocess.run(['nm', binary_path], capture_output=True, text=True, timeout=5)
nm_addr = None
for line in result.stdout.split('\n'):
    if 'win_function' in line:
        parts = line.split()
        if len(parts) > 0:
            nm_addr = parts[0]
            # Remove leading zeros
            nm_addr_clean = nm_addr.lstrip('0')
            if not nm_addr_clean:  # If all zeros, keep one
                nm_addr_clean = '0'
            print(f"Original: {nm_addr}, Cleaned: {nm_addr_clean}")
            break

# Send first answer
conn.sendline(output)

# Wait for second question
conn.recvuntil(b'> ', timeout=5)

# Try the cleaned address
if nm_addr_clean:
    print(f"Sending cleaned address: {nm_addr_clean}")
    conn.sendline(nm_addr_clean.encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()