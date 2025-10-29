#!/usr/bin/env python3
from pwn import *
import base64
import os
import subprocess

# Set up context
context.arch = 'amd64'
context.log_level = 'debug'  # Full debug to see everything

print("=== STARTING FINAL DEBUG ATTEMPT ===")

# Connect to the server
conn = remote('zerodayheroes-f8bde251-pwnintro.kongsberg-ctf.com', 1337, ssl=True)

try:
    # Get ready prompt and send yes
    print("Waiting for prompt...")
    conn.recvuntil(b'[yes/no] ')
    print("Sending yes...")
    conn.sendline(b'yes')

    # Get ALL data until we see the first question
    print("Receiving all data until first question...")
    data = conn.recvuntil(b'> ')
    
    print(f"Full data received ({len(data)} bytes):")
    print(repr(data))

    # Extract base64 from the data
    base64_start = data.find(b'Base64 ELF: ')
    if base64_start == -1:
        print("ERROR: Could not find 'Base64 ELF:' marker!")
        exit(1)
        
    base64_start += len(b'Base64 ELF: ')
    base64_end = data.find(b'[?]', base64_start)
    if base64_end == -1:
        print("ERROR: Could not find end of base64!")
        exit(1)
        
    actual_base64 = data[base64_start:base64_end].strip()
    print(f"Extracted base64 ({len(actual_base64)} bytes): {actual_base64[:100]}...")

    # Decode the binary
    try:
        binary_data = base64.b64decode(actual_base64)
        print(f"Successfully decoded {len(binary_data)} bytes")
    except Exception as e:
        print(f"Base64 decode error: {e}")
        exit(1)

    # Save and make executable
    binary_path = '/tmp/final_debug_binary'
    with open(binary_path, 'wb') as f:
        f.write(binary_data)
    os.chmod(binary_path, 0o755)
    print(f"Binary saved to {binary_path}")

    # Run the binary to get output
    print("Running binary...")
    proc = process(binary_path)
    output = proc.recvall(timeout=5).strip()
    proc.close()
    print(f"Binary output: {output}")

    # Analyze the binary thoroughly
    print("\n=== BINARY ANALYSIS ===")
    
    # ELF analysis
    elf = ELF(binary_path, checksec=False)
    print(f"ELF entry point: 0x{elf.entry:x}")
    print(f"ELF base address: 0x{elf.address:x}")
    print(f"All symbols: {elf.symbols}")
    
    win_address = elf.symbols['win_function']
    print(f"Win function address (pwntools): 0x{win_address:x}")
    
    # nm analysis
    print("\n--- nm output ---")
    result = subprocess.run(['nm', binary_path], capture_output=True, text=True, timeout=5)
    print(result.stdout)
    
    # readelf analysis
    print("\n--- readelf symbols ---")
    result = subprocess.run(['readelf', '-s', binary_path], capture_output=True, text=True, timeout=5)
    print(result.stdout)
    
    # hexdump to look for any patterns
    print("\n--- hexdump (first 200 bytes) ---")
    result = subprocess.run(['hexdump', '-C', binary_path], capture_output=True, text=True, timeout=5)
    lines = result.stdout.split('\n')[:20]
    for line in lines:
        print(line)

    # Send first answer
    print(f"\n=== SENDING ANSWERS ===")
    print(f"Sending binary output: {output}")
    conn.sendline(output)

    # Wait for second question with more details
    print("Waiting for second question...")
    response = conn.recv(timeout=10)
    print(f"Server response: {repr(response)}")
    
    # If we got the second question, try to extract any hints from it
    if b'address' in response.lower():
        print("Got address question!")
        
        # Try the simplest approach first - just the offset
        simple_offset = win_address - elf.entry
        print(f"Trying simple offset: 0x{simple_offset:x}")
        conn.sendline(f"{simple_offset:x}".encode())
    else:
        print("Unexpected response - sending default")
        conn.sendline(b"103c")

    # Get final result
    final_result = conn.recvall(timeout=10)
    print(f"Final result: {final_result.decode()}")

except Exception as e:
    print(f"Exception occurred: {e}")
    import traceback
    traceback.print_exc()

finally:
    if 'binary_path' in locals() and os.path.exists(binary_path):
        os.remove(binary_path)
    conn.close()

print("=== DEBUG SESSION COMPLETE ===")