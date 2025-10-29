#!/usr/bin/env python3
from pwn import *
import base64
import os

# Set up context
context.arch = 'amd64'
context.log_level = 'info'

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
binary_path = '/tmp/challenge_binary_fast'
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
print(f"Full win_function address: 0x{win_address:x}")
win_address_hex = hex(win_address)[2:]  # Remove '0x'
print(f"Sending address as: {win_address_hex}")

# Send first answer
print(f"Sending output: {output}")
conn.sendline(output)

# Wait for second question and send address
conn.recvuntil(b'> ', timeout=5)
print(f"Sending address: {win_address_hex}")
conn.sendline(win_address_hex.encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()