#!/usr/bin/env python3
from pwn import *
import base64
import os
import subprocess

# Set up context
context.arch = 'amd64'
context.log_level = 'critical'

# Connect to the server
conn = remote('zerodayheroes-f8bde251-pwnintro.kongsberg-ctf.com', 1337, ssl=True)

# Get ready prompt and send yes
conn.recvuntil(b'[yes/no] ')
conn.sendline(b'yes')

# Get the base64 binary data - but this time, let's be more careful about timing
data = conn.recvuntil(b'> ', timeout=30)

# Extract base64 from the data
base64_start = data.find(b'Base64 ELF: ')
base64_start += len(b'Base64 ELF: ')
base64_end = data.find(b'[?]', base64_start)
actual_base64 = data[base64_start:base64_end].strip()

# Decode the binary
binary_data = base64.b64decode(actual_base64)

# Save and make executable
binary_path = '/tmp/challenge_binary_final_test'
with open(binary_path, 'wb') as f:
    f.write(binary_data)
os.chmod(binary_path, 0o755)

# Run the binary to get output
proc = process(binary_path)
output = proc.recvall(timeout=2).strip()
proc.close()

# Get the exact symbol table address
result = subprocess.run(['readelf', '-s', binary_path], 
                      capture_output=True, text=True, timeout=5)

win_addr_full = None
for line in result.stdout.split('\n'):
    if 'win_function' in line:
        parts = line.split()
        if len(parts) >= 2:
            win_addr_full = parts[1]  # The Value column
            break

print(f"Full address from readelf: {win_addr_full}")

if win_addr_full:
    # Try variations of this address
    variations = [
        win_addr_full,                    # Full: 00000a761afe903c
        win_addr_full.lstrip('0'),        # No leading zeros: a761afe903c  
        win_addr_full[-3:],               # Last 3: 03c
        win_addr_full[-4:],               # Last 4: 903c
        win_addr_full[-8:],               # Last 8: afe903c
        "0x" + win_addr_full.lstrip('0'), # With 0x prefix
    ]
    
    print(f"Address variations to try: {variations}")

# Send first answer
conn.sendline(output)

# Wait for second question  
conn.recvuntil(b'> ', timeout=5)

# Try the last 4 characters approach (common pattern: ???03c where 3c is offset)
test_addr = win_addr_full[-4:] if win_addr_full else "103c"
print(f"Trying: {test_addr}")
conn.sendline(test_addr.encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()