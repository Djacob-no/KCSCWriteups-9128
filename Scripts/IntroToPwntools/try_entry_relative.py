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
binary_path = '/tmp/challenge_binary_readelf'
with open(binary_path, 'wb') as f:
    f.write(binary_data)
os.chmod(binary_path, 0o755)

# Run the binary to get output
proc = process(binary_path)
output = proc.recvall(timeout=2).strip()
proc.close()

# Try readelf to get more info about the ELF
print("=== READELF HEADERS ===")
try:
    result = subprocess.run(['readelf', '-h', binary_path], 
                          capture_output=True, text=True, timeout=5)
    print(result.stdout)
except:
    pass

print("=== READELF SYMBOLS ===")
try:
    result = subprocess.run(['readelf', '-s', binary_path], 
                          capture_output=True, text=True, timeout=5)
    print(result.stdout)
    
    # Look for win_function
    for line in result.stdout.split('\n'):
        if 'win_function' in line:
            print(f"Win function readelf: {line}")
except:
    pass

# Get pwntools info
elf = ELF(binary_path, checksec=False)
print(f"=== PWNTOOLS INFO ===")
print(f"Entry point: 0x{elf.entry:x}")
print(f"Base address: 0x{elf.address:x}")
print(f"Win function: 0x{elf.symbols['win_function']:x}")

# Try different calculations based on entry point
entry_relative = elf.symbols['win_function'] - elf.entry
print(f"Win function relative to entry: 0x{entry_relative:x}")

# Send first answer
conn.sendline(output)

# Wait for second question
conn.recvuntil(b'> ', timeout=5)

# Try entry-relative address
print(f"Sending entry-relative: {entry_relative:x}")
conn.sendline(f"{entry_relative:x}".encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()