#!/usr/bin/env python3
from pwn import *
import base64
import os

# Multiple attempts with different formats
attempts = [
    "103c",      # relative to base
    "3c",        # relative to entry  
    "40103c",    # with 401000 base
    "40003c",    # with 400000 base
    "1000103c",  # with different base
    "0x103c",    # with 0x prefix
    "0x40103c",  # with 0x and base
]

for i, addr_format in enumerate(attempts):
    print(f"\n=== ATTEMPT {i+1}: {addr_format} ===")
    
    # Set up context
    context.arch = 'amd64'
    context.log_level = 'critical'

    # Connect to the server
    conn = remote('zerodayheroes-072d21aa-pwnintro.kongsberg-ctf.com', 1337, ssl=True)

    try:
        # Get ready prompt and send yes
        conn.recvuntil(b'[yes/no] ')
        conn.sendline(b'yes')

        # Get the base64 binary data
        data = conn.recvuntil(b'> ', timeout=30)

        # Extract base64 from the data
        base64_start = data.find(b'Base64 ELF: ')
        base64_start += len(b'Base64 ELF: ')
        base64_end = data.find(b'[?]', base64_start)
        actual_base64 = data[base64_start:base64_end].strip()

        # Decode the binary
        binary_data = base64.b64decode(actual_base64)

        # Save and make executable
        binary_path = f'/tmp/challenge_binary_{i}'
        with open(binary_path, 'wb') as f:
            f.write(binary_data)
        os.chmod(binary_path, 0o755)

        # Run the binary to get output
        proc = process(binary_path)
        output = proc.recvall(timeout=2).strip()
        proc.close()

        # Send first answer
        conn.sendline(output)

        # Wait for second question
        conn.recvuntil(b'> ', timeout=5)

        # Send our test address
        print(f"Sending: {addr_format}")
        conn.sendline(addr_format.encode())

        # Get the result
        result = conn.recvall(timeout=5)
        result_text = result.decode()
        print(f"Result: {result_text}")
        
        if "Correct" in result_text or "flag" in result_text.lower() or "KCSC{" in result_text:
            print(f"SUCCESS! The correct format is: {addr_format}")
            break
            
        # Cleanup
        os.remove(binary_path)
        
    except Exception as e:
        print(f"Error in attempt {i+1}: {e}")
    finally:
        conn.close()
        
    # Small delay between attempts
    import time
    time.sleep(1)

print("\nAll attempts completed")