---
title: "Flare-On 2020: 03 - Wednesday"
date: 2020-12-25 00:03:00
header:
  image: /assets/images/03Wednesday/3.1.jpg
  teaser: /assets/images/03Wednesday/3.1.jpg
tags: [reversing, ctf, flareon]
---
# Challenge 3 - Wednesday
>                        --- BE THE WEDNESDAY ---
>
>                                   S
>                                   M
>                                   T
>                                  DUDE
>                                   T
>                                   F
>                                   S
>
>                --- Enable accelerated graphics in VM ---
>                  --- Attach sound card device to VM ---
>                    --- Only reverse mydude.exe ---
>                       --- Enjoy it my dudes ---

Alrighty my dudes, unlike the first challenge, we aren't provided the source code to this one so let's start with simply running the program.

![3.1](/assets/images/03Wednesday/3.1.jpg)

![3.2](/assets/images/03Wednesday/3.2.jpg)

We're presented with a game where we have to jump over blocks if Wednesday comes before that day of the week, and duck under blocks if Wednesday comes after that day of the week. Each successful dodge, duck, dip, dive, and dodge earns you one point and it's not clear how many points you need to win the game. Fifteen minutes of attempts earns me am enviable high score of 8. Time to figure out how the game works.

Firing up the IDA, we check out the strings table for any interestings finds:

![3.3](/assets/images/03Wednesday/3.3.jpg)

And there are no references to them in the code. The same was true for any other interesting string I found. There are 753 different functions in the code as well so I'm not going to skim them to find something interesting.

I had heard about [Cheat Engine (CE)](https://cheatengine.org/) in the past, but never used it or spent time to figure out how it works. I decided I'd use this challenge as an opportunity to become familiar with it. After going through the very helpful tutorial included with the software, I launched mydude.exe and attached CE to it.

Using cheat engine, I found the address of the high score variable in memory by first identifying the score variable in memory. The included basic tutorial Cheat Engine has walks you through how to identify simple variables like this by scanning memory for a given value, having you update the value in the game, then scanning for the updated value using the list of addresses from the first scan. Once I found the score this way, I then looked through the code for references to the score address and eventually found a memory address labeled "high\_score":

![3.4](/assets/images/03Wednesday/3.4.jpg)

Lower in the same function, we see the following:

![3.5](/assets/images/03Wednesday/3.5.jpg)

This looks like the condition we need to fulfill relates to the number 296. This is likely the score we need to beat the game. Our next move is to figure out how to manipulate our score to give us the winning screen. But how does our score increase? Let's look back at the section of code where we identified the high score variable. Right above that is a variable called "score". 

![3.6](/assets/images/03Wednesday/3.6.jpg)

If we look at the locations that it's used in, only one of those locations moves something into score. Let's jump there.

![3.7](/assets/images/03Wednesday/3.7.jpg)

Nice, we found where the score increases! Now we just need to figure out how to always take this code branch to increase the score. To do this, let's look at the code at the root of the branch, 0x432344, while the game is running in CE by setting a breakpoint at that address. The code at that address can be see below in the IDA screenshot.

![3.7.5.jpg](/assets/images/03Wednesday/3.7.5.jpg)

We hit the breakpoint when the frog runs into, jumps over, or ducks under an obstacle. I disabled the breakpoint (as every time the program paused, my frog would hit a tile) and used CE to watch the values pointed to by edx and eax in 0x432356 and see how they were impacted when I played the game. I discovered that edx contained the expected action (example: I was _expected_ to duck under "M" or "Monday" tiles) and eax contained the action I took. The following demonstrates how the value in a register corresponded to the action I took or expected action I was to take:

* 0 == duck
* 1 == jump
* 2 == walk (never an expected action)

So as long as the expected action and the real action are exactly the same, we'll always score a point. Let's set eax (the real action) to always be the expected action by replacing the code at location 0x43234f with `movsx eax, byte ptr [esi+000000f8]`. I did this by using an online assembler to determine the what bytes were equivalent to the assembly statement, and using CE to change the code. Now, I can hold the down key, ducking under each obstacle and earning a point every time! Eventually, we hit the score 296 and are presented with the well deserved victory screen.

![3.8](/assets/images/03Wednesday/3.8.jpg)

Flag: `1t_i5_wEdn3sd4y_mY_Dud3s@flare-on.com`

{% for post in site.posts -%}
 {% if post.title contains "Flare-On 2020 Challenges" %}
   [Click here]({{- post.url  -}}) to return to the Flare-On 2020 overview page.
 {% endif %}
{%- endfor %}
