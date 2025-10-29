# C2@Home CTF Challenge Writeup

### First Look at the PCAP
I started by examining the file structure in Wireshark. Initially i just noticed one interesting thing, the key_exchange request. I tried putting that into cyberchef but quickly realised thers more to it. I really wanted my trusty AI to help me analyse the content but i was using wireshark so i could not immediately do that. But we whipped up a quick script to let the AI parse the PCAP directly. From there on I enlisted my trusty agent with analysing the traffic and it revealed 61 packets with several interesting patterns: 

### Key Observations

1. **TCP Connection to C2 Server**: Initial connection from `192.168.1.100` to `51.12.250.2` on port 80
2. **Suspicious DNS Queries**:
   - `vg-hidden0.from.work.com` through `vg-hidden4.from.work.com`
   - `outside.knoggsberg10.com` through `outside.knoggsberg14.com`
3. **HTTP C2 Communications**:
   - GET request to `/key_exchange`
   - Multiple GET requests to `/execute`
   - Various responses including encrypted data

### Initial Failed Attempts

#### Attempt 1: DNS-based Steganography
I found it funny that this was the AI's first go to. "My first instinct was that the suspicious domain names might contain encoded data":

```python
# Domain analysis
vg_hidden = ['vg-hidden0', 'vg-hidden1', 'vg-hidden2', 'vg-hidden3', 'vg-hidden4']
knoggsberg = ['outside.knoggsberg10', 'outside.knoggsberg11', 'outside.knoggsberg12', 
              'outside.knoggsberg13', 'outside.knoggsberg14']

# Extract numbers: [0,1,2,3,4] and [10,11,12,13,14]
# Convert to ASCII: '01234' and 'ABCDE'
```
#### Attempt 2: User-Agent String Decoding
The `/execute` requests contained suspicious User-Agent strings:
- `0361`
- `0c76833df934903ec0eee04fa9733d`
- `0c73d76efa3b833c9adcf757`

I tried decoding these as hex, but they didn't produce meaningful ASCII text.

## Directing the AI

The key breakthrough came when I directed the AI to extract the actual HTTP response bodies from the C2 server. Most responses were benign "Hello, World!" messages, but three responses contained encrypted data.

### Initial Parsing Issues

The first attempt at parsing the HTTP responses had offset calculation errors, leading to incorrect hex values:

```python
# WRONG - Initial incorrect extraction
responses_hex = [
    "773c233451793b0a6027322f",      # Incorrect!
    "2c7a20327b4662201632212438657a2b", # Incorrect!
    "24510d14047c251001763722"       # Incorrect!
]
```

These values didn't decrypt properly with XOR, leading to more failed attempts.

### Correct Payload Extraction

I had to whip the AI to parse the PCAP more carefully, accounting for proper packet header offsets and Content-Length headers:

```python
def extract_http_payloads_carefully():
    # Skip PCAP global header (24 bytes)
    # Read packet header (16 bytes)
    # Find HTTP responses with 'text/plain'
    # Extract exact body using Content-Length
```

This revealed the correct encrypted responses:

1. **Response 1**: `1c77c03cf923a434d8ccea51c7793bb90a60e527f032cc2fccdc` (26 bytes)
2. **Response 2**: `2c7ac220fb32867bd0c1fd46ae6220a31632d721bc248738c6cdfb65a27a2bb41d` (33 bytes)
3. **Response 3**: `2451f00de714d004d298fd7ca02510e50176fc37ac229f` (23 bytes)

## The Encryption Key

The key exchange request i identified early on came in handy when i realised i needed a key to decrypt the message:

```
GET /key_exchange HTTP/1.1
Host: 51.12.250.2
Accept-Language: 6f12a34e9c57e25bb4a88f23cd164fd1
```

This 32-character hex string represented a 16-byte encryption key: `6f12a34e9c57e25bb4a88f23cd164fd1`

## Final Solution: XOR Decryption

With the correct response data and the encryption key, I let the AI implement XOR decryption:

```python
key_hex = "6f12a34e9c57e25bb4a88f23cd164fd1"
key_bytes = bytes.fromhex(key_hex)

# XOR each response with the repeating key
for resp_hex in responses_hex:
    resp_bytes = bytes.fromhex(resp_hex)
    xor_result = bytes(
        resp_bytes[j] ^ key_bytes[j % len(key_bytes)]
        for j in range(len(resp_bytes))
    )
    print(xor_result.decode('ascii'))
```

### Decrypted Results

1. **Response 1**: `secretFolder\notherFile.txt` - Directory listing
2. **Response 2**: `Changed directory to secretFolder` - Command execution feedback
3. **Response 3**: `KCSC{C2_f0r_m3_4nd_y0u}` - **The Flag!**

## Key Learnings
1. **First PCAP**: This was my first time analysing pcap files and using wireshark.
2. **Directing AI**: Directing AI helps alot. Its often very good at recognising patterns and encryptions but it has a tendency to veer off in a wrong direction. 
3. **Working with AI** This required implementing manual binary parsing, this was done so that the AI could quicker analyse what i was seeing in wireshark. 

## Tools and Scripts Used

1. **PowerShell** - Basic file analysis and hex viewing
2. **Python** - Custom PCAP parser and XOR decryption
3. **Manual analysis** - Packet structure and HTTP protocol understanding

The complete solution required about 4 different Python scripts and multiple iterations to get the parsing and decryption correct.
