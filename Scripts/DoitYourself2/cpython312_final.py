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

print("\n=== CPython 3.12 Dict Structure Analysis ===")

reads_used = 0
max_reads = 45

# According to the webpage and CPython source, PyDictObject has this structure:
# typedef struct {
#     PyObject_HEAD                    // +0x00: refcnt (8) + type_ptr (8) = 16 bytes
#     Py_ssize_t ma_used;             // +0x10: number of used slots (8 bytes)
#     uint64_t ma_version_tag;        // +0x18: version tag (8 bytes)  
#     PyDictKeysObject *ma_keys;      // +0x20: pointer to keys object (8 bytes)
#     PyObject **ma_values;           // +0x28: pointer to values array (8 bytes, NULL for combined dicts)
# } PyDictObject;

print("Reading PyDictObject structure:")
dict_obj_data = {}
for field_name, offset in [
    ("refcount", 0x00),
    ("type_ptr", 0x08), 
    ("ma_used", 0x10),
    ("ma_version_tag", 0x18),
    ("ma_keys", 0x20),
    ("ma_values", 0x28)
]:
    data = read_memory(dict_obj_addr + offset)
    reads_used += 1
    
    if data:
        val = u64(data)
        dict_obj_data[field_name] = val
        print(f"  {field_name} (+{offset:#x}): {val:#x}")

# Extract ma_keys pointer
ma_keys_ptr = dict_obj_data.get('ma_keys')
if not ma_keys_ptr or ma_keys_ptr < 0x1000:
    print("Invalid ma_keys pointer")
    io.close()
    exit(1)

print(f"\nAnalyzing PyDictKeysObject at {ma_keys_ptr:#x}")

# PyDictKeysObject structure (from the webpage research):
# - PyObject_VAR_HEAD (similar to PyObject_HEAD but for variable-size objects)
# - dk_refcnt, dk_log2_size, dk_log2_index_bytes, dk_kind, dk_version, dk_usable, dk_nentries
# - dk_indices[] array
# - dk_entries[] array (PyDictKeyEntry structs)

# Read key fields from PyDictKeysObject
keys_data = {}
for field_name, offset in [
    ("keys_refcnt", 0x00),
    ("keys_type_ptr", 0x08),
    ("keys_size", 0x10),      # This might be the variable size field
    ("dk_refcnt", 0x18),
    ("dk_log2_size", 0x20), 
    ("dk_log2_index_bytes", 0x28),
    ("dk_kind", 0x30),
    ("dk_version", 0x38),
    ("dk_usable", 0x40),
    ("dk_nentries", 0x48)
]:
    data = read_memory(ma_keys_ptr + offset)
    reads_used += 1
    
    if data:
        val = u64(data)
        keys_data[field_name] = val
        print(f"  {field_name} (+{offset:#x}): {val:#x} ({val})")

# Extract critical values
dk_nentries = keys_data.get('dk_nentries', 0)
dk_log2_size = keys_data.get('dk_log2_size', 0)

# Sanity check - flag should have reasonable number of characters
if not (10 <= dk_nentries <= 100):
    print(f"Warning: dk_nentries={dk_nentries} seems unrealistic for a flag")

print(f"\nDict contains {dk_nentries} entries")

# Calculate where dk_entries starts
# dk_entries comes after dk_indices array
# Size of indices array depends on dict size
dict_size = 1 << min(dk_log2_size, 10)  # Cap it to prevent overflow
indices_size = dict_size  # Assume 1-byte indices for small dicts

# dk_entries starts after the PyDictKeysObject header + indices
dk_entries_offset = 0x50 + indices_size  # Start after header fields + indices
dk_entries_addr = ma_keys_ptr + dk_entries_offset

print(f"Dict size: {dict_size}, indices size: {indices_size}")
print(f"Estimated dk_entries at: {dk_entries_addr:#x}")

# Read dictionary entries
# PyDictKeyEntry structure:
# typedef struct {
#     Py_hash_t me_hash;    // Hash value (8 bytes)
#     PyObject *me_key;     // Key object pointer (8 bytes) 
#     PyObject *me_value;   // Value object pointer (8 bytes)
# } PyDictKeyEntry;  // Total: 24 bytes per entry

print(f"\nExtracting flag from {min(dk_nentries, 15)} dictionary entries:")
flag_chars = {}

for i in range(min(int(dk_nentries), 15)):  # Limit entries to avoid too many reads
    if reads_used >= max_reads - 5:
        break
        
    entry_addr = dk_entries_addr + i * 24  # 24 bytes per PyDictKeyEntry
    
    print(f"\n--- Entry {i} at {entry_addr:#x} ---")
    
    # Read me_key pointer (the index in original flag)
    key_ptr_data = read_memory(entry_addr + 8)  # Skip me_hash
    reads_used += 1
    
    # Read me_value pointer (the character)
    value_ptr_data = read_memory(entry_addr + 16)  # Skip me_hash + me_key
    reads_used += 1
    
    if key_ptr_data and value_ptr_data:
        key_ptr = u64(key_ptr_data)
        value_ptr = u64(value_ptr_data)
        
        print(f"  Key ptr: {key_ptr:#x}, Value ptr: {value_ptr:#x}")
        
        # Read the character from the value object (PyUnicodeObject)
        if 0x400000 < value_ptr < 0x800000000000 and reads_used < max_reads - 2:
            # Python string objects have the actual string data after the header
            # Try reading from different offsets to find the character
            for str_offset in [0x30, 0x38, 0x40, 0x48]:  # Common string data offsets
                char_data = read_memory(value_ptr + str_offset)
                reads_used += 1
                
                if char_data:
                    # Look for a single printable character
                    for b in char_data:
                        if 32 <= b <= 126:  # Printable ASCII
                            char = chr(b)
                            print(f"    Found char '{char}' at offset {str_offset:#x}")
                            flag_chars[i] = char
                            break
                    if i in flag_chars:
                        break

print(f"\n=== Results (used {reads_used}/{max_reads} reads) ===")

if flag_chars:
    print("Extracted flag characters:")
    for idx in sorted(flag_chars.keys()):
        print(f"  Position {idx}: '{flag_chars[idx]}'")
    
    # Reconstruct flag
    max_idx = max(flag_chars.keys())
    flag_reconstruction = ''
    for i in range(max_idx + 1):
        flag_reconstruction += flag_chars.get(i, '?')
    
    print(f"\nFlag reconstruction: {flag_reconstruction}")
    
    # Also try concatenating just the found characters
    found_chars = ''.join(flag_chars[i] for i in sorted(flag_chars.keys()))
    print(f"Found characters: {found_chars}")
    
    # Look for flag patterns
    if any(pattern in found_chars.upper() for pattern in ['KCSC', 'FLAG', 'CTF']):
        print("*** FLAG PATTERN DETECTED ***")
else:
    print("No flag characters extracted. Structure parsing may need adjustment.")

io.close()