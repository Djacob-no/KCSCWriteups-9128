from pwn import *
import base64
import os

# Set up context for 64-bit (most CTF binaries are 64-bit, adjust if needed)
context.arch = 'amd64'
context.log_level = 'critical'  # Minimize logging for speed

# Connect to the server
conn = remote('zerodayheroes-072d21aa-pwnintro.kongsberg-ctf.com', 1337, ssl=True)

# Get ready prompt and send yes
conn.recvuntil(b'[yes/no] ')
conn.sendline(b'yes')

try:
    # Receive the base64-encoded binary
    print("[*] Waiting for base64 binary data...")
    base64_data = conn.recvuntil(b'[!] Time exceeded.', timeout=30, drop=True).strip()
    print(f"[*] Received data length: {len(base64_data)} bytes")
    print(f"[*] First 100 chars of data: {base64_data[:100]}")
    
    if not base64_data:
        print("[!] No base64 data received, trying alternative method...")
        # Try to receive all available data
        all_data = conn.recvall(timeout=10)
        print(f"[*] Alternative data received: {all_data}")
        exit(1)

    # Extract the actual base64 data - it starts after "Base64 ELF: " and ends with the question
    base64_start = base64_data.find(b'Base64 ELF: ')
    if base64_start != -1:
        base64_start += len(b'Base64 ELF: ')
        # Find where the base64 ends (before the question)
        base64_end = base64_data.find(b'[?]', base64_start)
        if base64_end != -1:
            actual_base64 = base64_data[base64_start:base64_end].strip()
        else:
            actual_base64 = base64_data[base64_start:].strip()
        
        print(f"[*] Extracted base64 length: {len(actual_base64)} bytes")
        print(f"[*] First 100 chars of extracted base64: {actual_base64[:100]}")
    else:
        print("[!] Could not find 'Base64 ELF:' marker")
        actual_base64 = base64_data

    # Decode the base64 data
    print("[*] Decoding base64 data...")
    binary_data = base64.b64decode(actual_base64)
    print(f"[+] Successfully decoded {len(binary_data)} bytes of binary data")

except Exception as e:
    print(f"[!] Error receiving/decoding binary: {e}")
    try:
        remaining = conn.recv(timeout=2)
        print(f"[*] Remaining data: {remaining}")
    except:
        pass
    conn.close()
    exit(1)

# Save the binary to a temporary file
binary_path = '/tmp/challenge_binary'
with open(binary_path, 'wb') as f:
    f.write(binary_data)

# Make the binary executable
import os
os.chmod(binary_path, 0o755)

try:
    # Question 1: Run the binary and get its output
    print("[*] Running the binary...")
    proc = process(binary_path)
    output = proc.recvall(timeout=2).strip()  # Capture all output
    proc.close()
    print(f"[*] Binary output: {output}")

    # Question 2: Get the address of win_function
    print("[*] Analyzing binary for win_function...")
    elf = context.binary = ELF(binary_path, checksec=False)
    win_address = elf.symbols.get('win_function', 0)
    if win_address == 0:
        print("[!] win_function not found, listing all symbols...")
        print(f"[*] Available symbols: {list(elf.symbols.keys())}")
        exit(1)
    
    print(f"[+] Found win_function at address: 0x{win_address:x}")
    
    # Convert address to hex string (without '0x' prefix, as servers often expect this)
    win_address_hex = hex(win_address)[2:]

    # The questions are already in the base64_data we received
    # Let's look for the question prompts we already got
    if b'What is the output from running the binary?' in base64_data:
        print("[+] Found first question already received")
        print(f"[*] Sending binary output: {output}")
        conn.sendline(output)
        
        # Wait for next question 
        print("[*] Waiting for second question...")
        next_response = conn.recvuntil(b'> ', timeout=10)
        print(f"[*] Next server response: {next_response}")
        
        if b'address' in next_response.lower() or b'win_function' in next_response.lower():
            print(f"[*] Sending win_function address: {win_address_hex}")
            conn.sendline(win_address_hex.encode())
        else:
            # Fallback - send the address anyway
            print(f"[*] Sending win_function address anyway: {win_address_hex}")
            conn.sendline(win_address_hex.encode())
    
    # Receive and print the flag (or any remaining output)
    print("[*] Waiting for final response...")
    final_response = conn.recvall(timeout=10)
    print(f"[+] Final server response: {final_response.decode()}")

except Exception as e:
    print(f"[!] Error during execution: {e}")
    try:
        remaining = conn.recv(timeout=2)
        print(f"[*] Remaining data: {remaining}")
    except:
        pass

finally:
    # Clean up
    if os.path.exists(binary_path):
        os.remove(binary_path)
    conn.close()