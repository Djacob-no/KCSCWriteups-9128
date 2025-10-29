# Slider Challenge Writeup

## Challenge Description

We were provided with a binary file called `slider` that appeared to be some kind of password-protected program. The challenge hinted that it required correct "password" input to reveal the flag.

## Initial Analysis

### File Investigation

First, we examined what type of file we were dealing with:

```bash
wsl file slider
```

Output: `slider: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped`

This told us:
- 64-bit Linux executable
- Statically linked (larger file, all libraries included)
- Not stripped (debugging symbols still present - good for analysis!)

### Running the Program

We tested the program's behavior:

```bash
wsl ./slider
```

Output:
```
Hello! If you tell me what I want to hear I will do something really cool for you ༼ つ ◕_◕ ༽つ
>> test
Sorry, that was not what I wanted to hear. Try again ╰（‵□′）╯
```

The program clearly expected some specific input to proceed. Given that this was the only file in the challenge it was clear that the password could be extracted with reverse engineering. 

## Reverse Engineering Approach

### Symbol Analysis

Since the binary wasn't stripped, we could examine the function symbols:

```bash
wsl nm slider
```

This revealed several interesting functions:
- `_start` (entry point)
- `check_password` (password validation)
- `decrypt_flag` (decrypts the flag)
- `print_flag` (displays the flag)
- `password1` and `password2` (password data)
- `key` (encryption key)

### Memory Layout Analysis

First i used IDA to look at the structure and saw a fair bit of code, however the very start contained a check passwords function, i focused on that.:
```bash
check_password:
mov     rax, cs:password1
xor     rax, cs:password2
cmp     rax, cs:__bss_start
```
```bash
wsl objdump -s --start-address=0x402800 --stop-address=0x402840 slider
```

This revealed:
- **Key** (at 0x402800): `10cb86cf95069576dd2db4460f32940869a8649f413f9a41f074d9e63c062074ff7f9c0173ab84415e93e9ebb4ce5e8b`
- **password1** (at 0x402830): `6f5027f53a341dc6` 
- **password2** (at 0x402838): `1c3c4e9c535d79a3`

### Understanding the Password Check

The disassembly showed:
1. Load `password1` into rax
2. XOR it with `password2`
3. Compare result with user input
4. If match, call `decrypt_flag`; else call `print_wrong`

### Calculating the Correct Password

Using Python to compute the XOR of the two password values:

```bash
wsl python3 -c "
p1 = bytes.fromhex('6f5027f53a341dc6')
p2 = bytes.fromhex('1c3c4e9c535d79a3')
result = bytes(a ^ b for a, b in zip(p1, p2))
print('Expected password (hex):', result.hex())
print('Expected password (ascii):', repr(result))
print('Expected password (as string):', result.decode('ascii', errors='ignore'))
"
```

Result: The password was **"sliiiide"**

## The Solution

### Testing the Password

```bash
echo "sliiiide" | wsl ./slider
```

### The Flag Reveal

When we entered the correct password, the program executed a spectacular sliding ASCII art animation that revealed the flag piece by piece. The animation showed large ASCII art characters sliding across the screen, ultimately spelling out the flag
