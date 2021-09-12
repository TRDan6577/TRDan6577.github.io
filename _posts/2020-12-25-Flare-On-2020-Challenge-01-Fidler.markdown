---
title: "Flare-On 2020: 01 - Fidler"
date: 2020-12-25 00:01:00
header:
  image: /assets/images/01Fidler/header.png
  teaser: /assets/images/01Fidler/header.png
  caption: "[credit](https://www.fireeye.com/content/dam/fireeye-www/blog/images/flareon7/FLARE-On%207.png)"
---
# Challenge 1 - Fidler
> Welcome to the Seventh Flare-On Challenge!
>
> This is a simple game. Win it by any means necessary and the victory screen will reveal the flag. Enter the flag here on this site to score and move on to the next level.
>
> This challenge is written in Python and is distributed as a runnable EXE and matching source code for your convenience. You can run the source code directly on any Python platform with PyGame if you would prefer.

Fantastic! The source code is provided to us in Python. Let's take a look at fidler.py for the flag.

![1.1.jpg](/assets/images/01Fidler/1.1.jpg)

This function seems promising! Backtracing through the code to see where it's called, we can see a possible call stack of: `game_screen() --> victory_screen(int(current_coins / 10**8)) --> decode_flag(token)`

![1.2.jpg](/assets/images/01Fidler/1.2.jpg)

In order to call `victory_screen()` from `game_screen()`, we need to reach the target amount of coins. `current_coins` is passed from `game_screen()` all the way to `decode_flag()` as the token without any modification. It looks like we can reach `victory_screen()` by reaching the target amount (though theoretically due to rounding, `int(current_coins/10**8)` just needs to equal 1030). Using the following code, we can set our wealth arbitrarily (the IRL dream) and extract the flag:

```python
def decode_flag(frob):
    last_value = frob
    encoded_flag = [1135, 1038, 1126, 1028, 1117, 1071, 1094, 1077, 1121, 1087, 1110, 1092, 1072, 1095, 1090, 1027,
                    1127, 1040, 1137, 1030, 1127, 1099, 1062, 1101, 1123, 1027, 1136, 1054]
    decoded_flag = []
    
    for i in range(len(encoded_flag)):
        c = encoded_flag[i]
        val = (c - ((i%2)*1 + (i%3)*2)) ^ last_value
        decoded_flag.append(val)
        last_value = c
    
    return ''.join([chr(x) for x in decoded_flag])


print(decode_flag(int((2**36 + 2**35)/10**8)))
```

This gives us the flag: `idle_with_kitty@flare-on.com`
