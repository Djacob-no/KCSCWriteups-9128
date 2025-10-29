import platform, random, ctypes, sys

# read the flag 
flag = bytearray(*open("flag.txt", "rb"))

# shuffle the flag a little 🪇
flag_dict = {i: chr(flag[i]) for i in random.sample(range(len(flag)), len(flag))}

# scrub the original flag from memory 
flag[:]= b'\0' * len(flag); flag = None

print(f"flag is over at {hex(id(flag_dict))}. just read it yourself.")
print("btw here is some info for you nerds:", platform.python_implementation(), sys.version)

def peek(addr, n=8):
    print(f"0x{addr:012x}: {ctypes.string_at(addr, n).hex()}")

for _ in range(50):
    try: peek(int(input("read from: "), 16))
    except: quit(print(f"illegal memory address"))

print("hope you found it! 👋")
