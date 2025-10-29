#!/usr/bin/env python3
from pwn import *
import base64
import os

# Simple approach - just try various formats systematically but faster
def test_address_format(addr_format):
    try:
        # Set up context
        context.arch = 'amd64'
        context.log_level = 'critical'

        # Connect to the server
        conn = remote('zerodayheroes-f8bde251-pwnintro.kongsberg-ctf.com', 1337, ssl=True)

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
        binary_path = '/tmp/test_bin'
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
        conn.sendline(addr_format.encode())

        # Get the result
        result = conn.recvall(timeout=5)
        result_text = result.decode()
        
        success = "Correct!" in result_text or "flag" in result_text.lower() or "KCSC{" in result_text or "congratulations" in result_text.lower()
        
        print(f"Format '{addr_format}': {'SUCCESS' if success else 'FAIL'}")
        if success:
            print(f"WINNER! Result: {result_text}")
            return True
            
        # Cleanup
        os.remove(binary_path)
        conn.close()
        return False
        
    except Exception as e:
        print(f"Error testing {addr_format}: {e}")
        return False

# Test many different formats
formats_to_test = [
    # Basic offsets
    "1000", "103c", "203c", "303c", "403c", "503c", "603c", "703c", "803c", "903c", "a03c", "b03c", "c03c", "d03c", "e03c", "f03c",
    
    # With common bases  
    "401000", "401003", "40100c", "401030", "40103c", "401040", "401050",
    "400000", "400003", "40000c", "400030", "40003c", "400040", "400050",
    
    # Just the offset
    "0", "3c", "60", "100", 
    
    # With 0x
    "0x3c", "0x103c", "0x40103c", "0x401000",
    
    # Decimal equivalents
    "60", "4156", "4195388",
]

print("Testing address formats...")
for addr_format in formats_to_test:
    if test_address_format(addr_format):
        break
    import time
    time.sleep(0.5)  # Small delay between attempts

print("All tests completed.")