#!/usr/bin/env python3
from pwn import *
import base64
import os

# Set up context
context.arch = 'amd64'
context.log_level = 'critical'  # Minimize output for speed

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
binary_path = '/tmp/challenge_binary_final'
with open(binary_path, 'wb') as f:
    f.write(binary_data)
os.chmod(binary_path, 0o755)

# Run the binary to get output
proc = process(binary_path)
output = proc.recvall(timeout=2).strip()
proc.close()

# Get win_function address - try different approaches
elf = ELF(binary_path, checksec=False)

# Print all symbols to debug
print(f"All symbols: {elf.symbols}")

win_address = elf.symbols['win_function']
base_address = elf.address

print(f"Binary output: {output}")
print(f"Base address: 0x{base_address:x}")
print(f"Win function absolute: 0x{win_address:x}")
print(f"Win function relative: 0x{win_address - base_address:x}")

# Try different calculations
formats = [
    f"{win_address:x}",                    # absolute
    f"{win_address - base_address:x}",     # relative to base
    f"{win_address & 0xFFFFFFFF:x}",       # 32-bit mask
    f"0x{win_address:x}",                  # with 0x prefix
]

print("Address formats to try:")
for i, addr in enumerate(formats):
    print(f"  {i+1}: {addr}")

# Send first answer
print(f"Sending output: {output}")
conn.sendline(output)

# Wait for second question
response = conn.recvuntil(b'> ', timeout=5)
print(f"Server asks: {response.decode().strip()}")

# Try format 1 first (absolute without 0x)
addr_to_send = f"{win_address:x}"
print(f"Sending address: {addr_to_send}")
conn.sendline(addr_to_send.encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()