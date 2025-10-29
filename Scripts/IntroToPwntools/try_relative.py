#!/usr/bin/env python3
from pwn import *
import base64
import os

# Set up context
context.arch = 'amd64'
context.log_level = 'critical'

# Connect to the server
conn = remote('zerodayheroes-f8bde251-pwnintro.kongsberg-ctf.com', 1337, ssl=True)

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
binary_path = '/tmp/challenge_binary_rel'
with open(binary_path, 'wb') as f:
    f.write(binary_data)
os.chmod(binary_path, 0o755)

# Run the binary to get output
proc = process(binary_path)
output = proc.recvall(timeout=2).strip()
proc.close()

# Get win_function address
elf = ELF(binary_path, checksec=False)
win_address = elf.symbols['win_function']
base_address = elf.address

# Calculate relative address
relative_addr = win_address - base_address
print(f"Trying relative address: {relative_addr:x}")

# Send first answer
conn.sendline(output)

# Wait for second question and send relative address
conn.recvuntil(b'> ', timeout=5)
conn.sendline(f"{relative_addr:x}".encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()