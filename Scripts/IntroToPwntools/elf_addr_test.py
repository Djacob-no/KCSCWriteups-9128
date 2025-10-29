#!/usr/bin/env python3
from pwn import *
import base64
import os

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
binary_path = '/tmp/challenge_binary_elf_addr'
with open(binary_path, 'wb') as f:
    f.write(binary_data)
os.chmod(binary_path, 0o755)

# Run the binary to get output
proc = process(binary_path)
output = proc.recvall(timeout=2).strip()
proc.close()

# Use pwntools ELF analysis with different approaches
elf = ELF(binary_path, checksec=False)

# Method 1: Use elf.address (which might be 0 if PIE is disabled)
elf.address = 0x400000  # Standard non-PIE base
win_func_addr_method1 = elf.symbols['win_function']
print(f"Method 1 (with elf.address = 0x400000): 0x{win_func_addr_method1:x}")

# Method 2: Calculate manually
# First get the raw symbol address
with open(binary_path, 'rb') as f:
    elf_data = f.read()

# Let's see the symbol table offset  
import struct
# This is getting complex - let me try a simpler approach

# Method 3: Maybe they want just the offset within the .text section
# Common CTF pattern: win function is at base + small offset
offset_from_entry = elf.symbols['win_function'] - elf.entry
print(f"Offset from entry: 0x{offset_from_entry:x}")

# Method 4: Maybe it's the virtual address they want
# Let's try setting elf.address to a common base and see what happens
original_base = elf.address
print(f"Original ELF base: 0x{original_base:x}")

# Try with common bases
bases_to_try = [0x400000, 0x401000, 0x0]
for base in bases_to_try:
    elf.address = base
    addr = elf.symbols['win_function']
    print(f"With base 0x{base:x}: win_function = 0x{addr:x}")

# Send first answer
conn.sendline(output)

# Wait for second question
conn.recvuntil(b'> ', timeout=5)

# Try the standard CTF format: 0x401000 base + offset  
elf.address = 0x401000
standard_addr = elf.symbols['win_function']
addr_to_send = f"{standard_addr:x}"
print(f"Sending standard format: {addr_to_send}")
conn.sendline(addr_to_send.encode())

# Get the result
result = conn.recvall(timeout=5)
print(f"Result: {result.decode()}")

# Cleanup
os.remove(binary_path)
conn.close()