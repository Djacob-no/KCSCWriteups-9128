## Challenge Description

A few days before the CTF started we noticed that the lovely on-demand CTF solution we stole borrowed was still fully in Norwegian!

Our live reaction: https://www.youtube.com/watch?v=bFHy61erVyQ&t=383s

Thankfully we fixed it. It's not a pretty solution though... Please don't check the page source.

## Initial Analysis

The challenge description immediately gave us several important clues:

1. **"still fully in Norwegian"** - indicates there was a translation issue
2. **"we fixed it"** - suggests some kind of patching or modification was done
3. **"It's not a pretty solution though"** - hints at a hacky or inelegant fix
4. **"Please don't check the page source"** - strongly suggesting we should examine the source code

The YouTube link seemed like a red herring, as it was uploaded 7 years ago and unlikely to contain the actual solution.

## Approach

Since this was described as a web-based challenge about a translation fix with no link to a website and the description hinted at the actual ctf site, the strategy was to:

1. Examine the kongsberg-ctf.com website for clues
2. Look for any JavaScript or source code that might reveal the "not pretty solution"
3. Search for Norwegian words that weren't properly translated

## Investigation

### Initial Web Exploration

I started by examining the main CTF website at https://kongsberg-ctf.com. Initially i didnt find much, however, the challenge hints strongly suggested looking at page source. So i wanted to analyze it with an AI which would be much quicker. The challenge was that the ai could not access it due to needing to be logged in. So i quickly made a site dump and loaded it into vs code. 

### Site Dump

Dump of the website content in the project directory structure:
```
C:\Projects\CTFWEEK\sliderF\
├── index.html
└── themes\
    └── core-beta\
        └── static\
            └── assets\
                ├── challenges.bf350543.js
                ├── color_mode_switcher.52334129.js  
                ├── index.8a9f40f.js
                └── main.e9ec7884.css
```

### Initial JavaScript Analysis

We examined the `challenges.bf350543.js` file which contained the OneDemand system code. This revealed Norwegian words that hadn't been properly translated:

```javascript
// Norwegian words found:
let buttonText = "Start Instanse"  // should be "Start Instance" 
buttonText = "Starter..."          // should be "Starting..."
buttonText = "Stopper..."          // should be "Stopping..." 
buttonText = "Stop Instanse"       // should be "Stop Instance"
```

However, this wasn't enough for the flag - these were just examples of the translation problem, not the actual solution.

### The Key Discovery: Obfuscated JavaScript

The breakthrough came when examining the main `index.html` file. We found a heavily obfuscated JavaScript block:

```javascript
<script>(()=>{const d=document,e=d.documentElement,M=MutationObserver,R=requestAnimationFrame||setTimeout;function g(i){var b=g.b||(g.b=atob('DgAhobLD1AAgiavN7wABE1eb3wADJGis4AAFC63wDQAC/u36zgBJ3q2+7wAOwAHQDQAKEjRWeAANyv66vgAOC63A3gAL3v7I7QANuq3wDQAV8A36zl1QoFY5LIomqVxS1EKwnZFhTgSzwvoyninqCcb8/L1J5lL1mHS58LW7Z5347w7BOAxUFD1wSmMsfbKuBjtKSgTzHqLx/4kpZaD9rI3+UyoZ6xpSD178qUMS9adbJeHZRbmS/zOW5y4wxY7uxDW4XLxZ80lVxz9YUdnfI2tPbVUE6lK3wvrbyXtVP1JtTaswFgX0Ac7DusNC39YYkW5tIeA59idePxD8Fi8Gl62OSbP11Flu4I4A6pZ8Ie+pszWGg7vpnqOxrarDZl9APH0dusWQavk3SlBbbI1KqniMyG/f8RM6M/h/HPKRJEzdgK7FyX/g5fxarw9qEdJIyvmV3K3bZvmOEgdSya+0vRSYf9S/o46XUL95B1sKqstc+zbN83lh3RQAzEzfwpCyey2zkBvl42HI0cs+JzE7UsNGO/8D9zf4l26WJwReHvqglV4O73NbgfeFDnXRi3wjdrjUExCKoqwpRb33TXJV4zksKeNpRMmMtDL2Q7TkfuKA5d3y1IGKPCjmnhscx8agtPoSsXmVO/nTKrv8A8toa6JOwEZSoj6OAeXsUltNszAVBeEBnPGi3iBRJvLEZi6fDBc6mIHDnsNz/JxDoXGiMQlNQ7RYnnaI6/YuH5UM0b24Ww+a/cENA7EgsXjVABQ='));
// ... more obfuscated code
</script>
```

This was clearly "not a pretty solution" as mentioned in the challenge! And heavily obfuscated code is always interesting.

## Reverse Engineering the Obfuscation

### Understanding the Obfuscation

The obfuscated code structure showed:

1. **Base64 encoded data:** A long base64 string containing encoded information
2. **Decoding function `g(i)`:** A function that decodes strings from the encoded data using:
   - XOR operations with a linear congruential generator (LCG)
   - Bit manipulation for extracting length and offset information
3. **DOM manipulation:** The decoded strings were used to find and replace Norwegian text with English

### Decoding Process

We extracted the obfuscation algorithm and created a decoder:

```javascript
function g(i) {
    var b = atob('DgAhobLD1AAgiavN7wABE1eb3wADJGis4AAFC63wDQAC/u36zgBJ3q2+7wAOwAHQDQAKEjRWeAANyv66vgAOC63A3gAL3v7I7QANuq3wDQAV8A36zl1QoFY5LIomqVxS1EKwnZFhTgSzwvoyninqCcb8/L1J5lL1mHS58LW7Z5347w7BOAxUFD1wSmMsfbKuBjtKSgTzHqLx/4kpZaD9rI3+UyoZ6xpSD178qUMS9adbJeHZRbmS/zOW5y4wxY7uxDW4XLxZ80lVxz9YUdnfI2tPbVUE6lK3wvrbyXtVP1JtTaswFgX0Ac7DusNC39YYkW5tIeA59idePxD8Fi8Gl62OSbP11Flu4I4A6pZ8Ie+pszWGg7vpnqOxrarDZl9APH0dusWQavk3SlBbbI1KqniMyG/f8RM6M/h/HPKRJEzdgK7FyX/g5fxarw9qEdJIyvmV3K3bZvmOEgdSya+0vRSYf9S/o46XUL95B1sKqstc+zbN83lh3RQAzEzfwpCyey2zkBvl42HI0cs+JzE7UsNGO/8D9zf4l26WJwReHvqglV4O73NbgfeFDnXRi3wjdrjUExCKoqwpRb33TXJV4zksKeNpRMmMtDL2Q7TkfuKA5d3y1IGKPCjmnhscx8agtPoSsXmVO/nTKrv8A8toa6JOwEZSoj6OAeXsUltNszAVBeEBnPGi3iBRJvLEZi6fDBc6mIHDnsNz/JxDoXGiMQlNQ7RYnnaI6/YuH5UM0b24Ww+a/cENA7EgsXjVABQ=');
    // ... decoding algorithm implementation
    return decodedString;
}
```

### The Revelation

Running our decoder on all possible string indices revealed:

```
g(0): "span[name=onedemand-protocol-tcp]"
g(1): "span[name=onedemand-button-text]"  
g(2): "p"
g(3): "div"
g(4): "eller"              // Norwegian for "or"
g(5): "or"                 // English translation
g(6): "This challenge is a OneDemand™ challenge.<br>You can connect either with:"
g(7): "start instanse"     // Norwegian  
g(8): "starter..."         // Norwegian
g(9): "stop instanse"      // Norwegian
g(10): "Start Instance"    // English translation
g(11): "Starting..."       // English translation  
g(12): "Stop Instance"     // English translation
g(13): "KCSC{m0nk3y_p4tch1ng}"  // THE FLAG!
```

## Solution

**Flag:** `KCSC{m0nk3y_p4tch1ng}`

## Tools Used

- Web browser developer tools for initial source inspection
- Node.js for running the JavaScript decoder
- Text analysis for identifying obfuscation patterns
- Manual reverse engineering of the decoding algorithm

