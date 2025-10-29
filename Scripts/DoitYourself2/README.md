Exploit helper for Do It Yourself - 2

This repository contains the challenge files and a quick pwntools script (`exploit.py`) that will connect to the remote service, parse the printed `flag_dict` address, and perform a small automated memory probe to look for printable ASCII fragments.

How to run

Use the pwntools Python environment provided on your machine (you mentioned it lives in your home directory). Example usage if pwntools is available in your PATH:

python3 exploit.py

If pwntools is not in your default environment, run the script using the environment you have that contains pwntools.

Notes

- The service allows 50 reads. The script currently uses a small heuristic probe; you may need to tune scanning offsets or perform interactive probing after the automated scan to reconstruct the flag precisely.
- `chall.py` stores the flag's characters as separate Python `str` objects and then scrubs the original. The exploit reads raw process memory (via the service's `ctypes.string_at`) so the goal is to find pointers inside the `dict` to the `str` objects and then read the character bytes.

Suggested next steps

1. Run `python3 exploit.py` to see the automatic probes and any printable fragments found.
2. If the automatic scan finds pointer candidates, follow them manually with more focused reads to reconstruct characters in order — the keys are the original indices, but `flag_dict` is shuffled; you may need to reassemble the characters by their keys.
3. If more targeted automation is desired, extend the script to parse `PyDictKeysObject` layout to pull `dk_entries` and extract exact value pointers.
