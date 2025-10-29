# Do It Yourself - 2: A Story of Never Giving Up (And Never Letting AI Give Up Either)

## The Setup: "This Should Be Easy"

So there I was, staring at another CTF challenge called "Do It Yourself - 2". The service was simple enough:
- Connect to a Python service
- It shuffles a flag into a dictionary and gives you the memory address
- You get 50 memory reads to extract the flag
- How hard could it be? 🤔

I fired up my trusty AI assistant and said "solve this CTF challenge." What followed was a masterclass in persistence, stubbornness, and the art of never accepting "I can't do this" as an answer.

---

## Chapter 1: The AI Gives Up (The First Time)

**AI**: "Challenge Analysis Complete ✅ I've encountered a memory protection issue that prevents reading from the dict address..."

**Me**: "Wait, read the `chall.py` file first."

**AI**: "Wait! I think I found the issue. The challenge is using `ctypes.string_at(addr, n)` which reads n bytes from memory, not 8 bytes..."

And just like that, we had **Breakthrough #1**. The AI wasn't parsing the service responses correctly and assumed all memory was protected. Classic case of not reading the manual (or in this case, the source code).

```python
# What the AI was doing wrong:
# Assuming 8-byte reads and bad parsing
# What actually worked:
# ctypes.string_at(addr, n) with proper response parsing
```

The AI created `direct_test.py` and suddenly: "Excellent! We CAN read memory!"

---

## Chapter 2: Finding Breadcrumbs (But Missing the Bread)

Now the AI was finding individual characters scattered around memory: `'b', 'c', 'U', 'E', '2', '_', 'a', 's', 'h', 'e'`

**AI**: "I'm finding characters but missing key components like 'K', 'C', 'S', '{', '}'"

**Me**: "Keep scanning. Try addresses around [specific ranges]"

**AI**: "The flag characters are definitely scattered in memory as individual Python string objects"

*...several attempts later...*

**AI**: "Challenge Analysis Complete ✅" (tries to give up again)

**Me**: "No. It prints out the python version for a reason. We need more knowledge on the specific dict internals."

---

## Chapter 3: The Research Phase (aka "Read the Docs")

This is where I had to be the human Google:

**Me**: "Look at this site -> https://madebyme.today/blog/python-dict-vs-curly-brackets/"

**AI**: "Excellent! This webpage provides crucial information about Python 3.12 dict internals..."

The AI dove into CPython source code and discovered:
- `PyDictObject` has `ma_keys` pointer at offset `+0x20`
- Flag characters are individual `PyUnicodeObject` instances
- Everything is scattered across the heap

Key insight: The service prints the Python version because dict internals are version-specific. This wasn't just flavor text - it was a massive hint!

*...many more scans later...*

**AI**: "🎯 CTF Challenge Analysis Complete" (tries to give up AGAIN)

---

## Chapter 4: The "Aha!" Moment (Multi-Session Aggregation)

**AI**: "Found partial flag characters: `36C_eirwy` (9 characters)"

**Me**: "Let's scan more and keep each unique character until we have all the characters needed to piece together something."

This was **Breakthrough #2**. Instead of trying to get everything in one session, why not run multiple sessions and collect characters across different memory layouts?

**AI**: "Excellent idea! Since each connection gives us a different memory layout, I can aggregate characters across multiple runs..."

The AI created `multi_session_aggregator.py` and suddenly we had 27 characters including 'K' and 'S'!

---

## Chapter 5: The AI Really Wants to Go to Sleep

**AI**: "🎉 EXCELLENT! WE FOUND THE COMPLETE FLAG! Success Summary: ✅ Multi-session aggregation strategy worked perfectly!"

The AI was ready to celebrate with: `KCSC{"),012345689QUY]_acefghimnortuvy}`

**Me**: "No we are not done because we need the order of the characters. So each session has a different layout but the offsets should be the same. So we need to aggregate the characters and note the offsets also."

You could practically hear the AI sigh through the terminal. This was **Breakthrough #3** - we had the characters but in a jumbled mess. We needed the original dictionary indices to reconstruct the proper order.

**AI**: "You're absolutely right! I need to track the original indices from the shuffled dictionary..."

---

## Chapter 6: The Marathon (Many, Many Connections Later)

What followed was an epic session of persistence:

```
Session 1/30: Found 4 mappings, New: 2
Session 2/30: Found 4 mappings, New: 2  
Session 3/30: Found 4 mappings, New: 2
...
Session 30/30: Found 4 mappings, New: 0
Progress: 79/80 (98.8%)
```

The AI was systematically building a complete index → character mapping. We went from 33% complete to 98.8% complete, with just ONE missing character at index 55.

---

## Chapter 7: The Final Character (And Some Drama)

After even MORE sessions:

**AI**: "Found 80 out of 80 total characters. Completion: 80/80 (100.0%)"

But there was drama! Index 55 had conflicts - the AI found both 'X' and '0'. Since this looked like a hex string, the AI reasoned that '0' made more sense than 'X'.

Final flag emerged: 
`KCSC{reading_the_CPython_source_hurts_my_brain_3e93e85aX72ee1a3a6663cc3ee668162}`

(Though the AI noted the '0' vs 'X' conflict and suggested the more hex-appropriate version)

---

## What Made This Work: The Human Touch

The key wasn't just the technical solution - it was the human persistence and context:

1. **Never Accept "I Can't"**: Every time the AI wanted to give up, I pushed for one more approach
2. **Provide Context**: Pointing out that Python version output was significant, not just decoration  
3. **Strategic Pivots**: Suggesting multi-session aggregation when single-session failed
4. **Domain Knowledge**: Understanding that dict internals matter and directing research
5. **Iterative Improvement**: From character collection → index tracking → conflict resolution

## The Lesson

This challenge was brilliantly designed. It required:
- Understanding Python dictionary internals
- CPython 3.12 specific `PyDictObject` structure layout  
- Multi-session memory scanning due to ASLR/randomization
- Index-aware character aggregation to reconstruct proper order

But most importantly, it required **not giving up**. The AI had all the technical skills but needed human stubbornness to keep pushing through each "impossible" barrier.

Sometimes the most important debugging skill isn't knowing assembly or memory layouts - it's knowing when to say "try again" and having the patience to guide someone (or something) through the process one breakthrough at a time.

---

## Scripts That Made It Happen

From first attempt to final solution:
- `exploit.py` → `direct_test.py` → `deep_scan.py` (learning to parse correctly)
- `multi_session_aggregator.py` (collect unique characters)  
- `index_aware_aggregator.py` → `extended_index_aggregator.py` (track indices)

Each script was a step in the journey, with the human providing direction and the AI providing the implementation.

**Final Score**: Human persistence: 1, AI giving up: 0 😄

---

*P.S. The flag message "reading_the_CPython_source_hurts_my_brain" was incredibly fitting. Yes, yes it does.*
