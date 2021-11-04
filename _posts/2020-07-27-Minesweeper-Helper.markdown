---
title: Cheating at Minesweeper
header:
  image: /assets/images/MinesweeperHelper/Figure5.jpg
  teaser: /assets/images/MinesweeperHelper/Figure5.jpg
tags: [hacking, c, windows, reversing]
---
As I began looking for resources on where to start with learning reverse engineering, I came across [a blog post](https://medium.com/bugbountywriteup/haxing-minesweeper-e79ece9f5d16) where Osanda Malith Jayathissa noted that they were struck with inspiration to reverse minesweeper. I read the first three introduction paragraphs and thought, "Wait. I could probably do this myself". If you're new to reversing and are thinking the same thing, stop reading now and give it a shot. You'll learn so much more than if you read this post.

The version of minesweeper I used is available [here](http://www.minesweeper.info/downloads/WinmineXP.html) ([VirusTotal](https://www.virustotal.com/gui/file/bcff89311d792f6428468e813ac6929a346a979f907071c302f418d128eaaf41/detection)). This is the version of minesweeper that comes with Windows XP.

All the code snippets you see here can be found in [the github repository for this post](https://github.com/TRDan6577/Minesweeper-Helper)

### Printing the minefield
I wasn't really sure where to start when I began reversing minesweeper, so I did what anyone would do to figure out a starting point and played a few games =). Honestly this was more to procrastinate than to begin reverse engineering. Once I had my fun, I started by looking at the import address table to see what external functions winmine.exe called. To do this, I used [PEView](http://wjradburn.com/software/). My main goal at this point was to find out how the minefield was stored in memory. In my mind, the best way to find the minefield would be to look for imported function calls that might relate to interacting with the minefield. With this in mind, I gave the function calls a quick skim and I knew exactly what to do:

Read the MSDN documentation for every single function call. Well, not EVERY one. Just the ones related to graphics display. I know that there must be some sort of interaction with the minefield when I click a tile and something new pops up so if I find the address where a new tile is drawn when I click a tile, I can back trace to the minefield. I tried setting breakpoints on a handful of functions that sounded interesting without any luck and when I stumbled across the `BitBlt` function in the gdi32.dll library. It performs a bit-block transfer of the color data corresponding to a rectangle of pixels from the specified source device context into a destination device context (taken straight from the [MSDN page](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-bitblt)). Basically copies rectangles from somewhere to somewhere else. I started minesweeper (winmine.exe), attached olydbg to my new game, set breakpoints on calls to this function everywhere it appeared in winmine.exe, then left clicked on a tile.

![Figure 1](/assets/images/MinesweeperHelper/Figure1.jpg)
Figure 1

OllyDbg stopped here in winmine.exe. As soon as I took the next step in the debugger, the tile I clicked on changed.

![Figure 2](/assets/images/MinesweeperHelper/Figure2.jpg)
Figure 2

As you can see, there's not much else in this function other than the call to `BitBlt`, so I'm going to label this function `UpdateClickedTileImage()` (`0x1003410`). I stepped out of this function and took a look at the calling function only to notice that the arguments to `UpdateClickedTileImage()` were two simple numbers.

![Figure 3](/assets/images/MinesweeperHelper/Figure3.jpg)
Figure 3

Looking over at the minefield, I noticed these corresponded to the x,y coordinates of the tile I clicked, with the origin at the top left of the minefield (and positive Y direction being dowards, just as any sane person would label their graphs).

If you notice in figure 3, there's a function called right before `UpdateCLickedTileImage()` which is passed the same arguments. I set a breakpoint there, ran the program, and clicked another tile to get to the start of the function.

![Figure 4](/assets/images/MinesweeperHelper/Figure4.jpg)
Figure 4

In the first four instructions, the function multiples the Y variable (EAX or ESP + 8) by 32 (SHL EAX,5 or EAX*2^5) and adds the X and Y coordinates together. This is typically indicative of a 2D array, so I checked out `0x1005340` in the memory dump and BAM!

![Figure 5](/assets/images/MinesweeperHelper/Figure5.jpg)
Figure 5

It looks like we found the minefield (it's easier to see in the ascii representation of the dump).

I did some work figuring out what each byte in the array represents. These are my findings:
* Mine = `0x80`
* Clicked space = `0x40` (then + 0 through 8 depending on how many mines are around the tile. Example, `0x40` is a blank clicked tile and `0x43` is a clicked tile with 3 mines around it)
* Unclicked space = `0x0F`
* Flag = `0x0E`
* Question mark = `0x0D`
* Exploded mine = `0xCC`
* Wrong mine = `0x0B` (you put a flag over this tile. Then you started clicking around willy nilly and clicked on a mine. This byte reveals your shame and shows you were wrong about a mine being on this tile)
* Revealed mine = `0x0A` (at the end of the game, all mines are revealed, this byte is that revealed mine)
* Note that you can have combinations of some of these. For example, you can have a mine on an unclicked space resulting in `0x8F`

Now that we know the location of the minefield and how different data is represented in memory, we can write code to print out where all the mines are to the user! Because [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) isn't enabled for this binary, minesweeper is loaded at the same address in memory every time. This means we can hard code the address. One of my objectives with this project was to learn more about the Windows API so instead of hard coding, I wrote some generic functions that can:
* Take the name of a process and return the PID
* Take the name of a module and a PID and return the base address of that module

Printing the minefield is very straightfoward. Our steps are:
1) Get a handle to minesweeper with at least read privileges
2) Read the minefield from `0x1005340`
3) Translate each byte to something more readable (for example, use B for bomb/mine instead of `0x8F`) and print the output

```c
#define MINE                   0x80    // A mine in memory
#define REVEALED_TILE          0x40    // A tile that's been clicked on that's not a bomb
#define UNCLICKED_SPACE        0x0F    // An unclicked tile in memory
#define FLAG                   0x0E    // A flag in memory
#define QUESTION_MARK          0x0D    // A question mark in memory
#define EXPLODED_MINE          0xCC    // The mine you clicked on to lose the game
#define WRONG_MINE             0x0B    // You put a flag over something that wasn't a mine
#define REVEALED_MINE          0x0A    // Value of the least significant byte in memory when all mines are revealed

void PrintMineField(unsigned char* field, DWORD height, DWORD width) {
/**
 * Purpose: Prints out the given minefield. This should be the same minefield
 *          that was read from memory
 * @param field : unsigned char* - the minefield
 * @param height : DWORD - the height of the minefield
 * @param width : DWORD - the width of the minefield
 * @return : void - zip. nada.
 */

    // Each row (width) is 32 bytes so heigh must be *32 to get the proper index
    height = height * 32;
    unsigned char currPos;

    // Print out the legend
    printf("Legend:\n------\nB: Unexploded bomb\n_: Blank clicked tile\n"
           "*: exploded bomb\n?: Question mark\n : (space) Blank unclicked tile\n"
           "F: Flag\nX: Incorrectly placed flag. Only shows up after you lose\n\n   ");

    // Print out the X axis
    for (DWORD x = 1; x <= width; x++) {
        printf(" %2d", x);
    }
    
    // Print out the border
    printf("\n   ");
    for (DWORD x = 1; x <= width; x++) {
        printf("---");
    }
    printf("--\n");

    // Print out the minefield
    for (DWORD y = 32; y <= height; y+=32) {

        // But first print out the Y axis and border
        printf("%2d |", y/32);

        // Print out the specific tile
        for (DWORD x = 1; x <= width; x++) {
            
            currPos = field[x + y];

            // Map out each tile position
            if ((currPos & EXPLODED_MINE) == EXPLODED_MINE) printf(" * ");
            else if ((currPos & MINE) == MINE) {
                if ((currPos & FLAG) == FLAG && !((currPos ^ MINE) > FLAG)) printf(" BF");
                else if ((currPos & QUESTION_MARK) == QUESTION_MARK && !((currPos ^ MINE) > QUESTION_MARK)) printf(" B?");
                else printf(" B ");
            }
            else if ((currPos & REVEALED_TILE) == REVEALED_TILE) {
                if (currPos > REVEALED_TILE) printf(" %d ", currPos ^ REVEALED_TILE);
                else printf(" _ ");
            }
            else if ((currPos & UNCLICKED_SPACE) == UNCLICKED_SPACE) printf("   ");
            else if ((currPos & FLAG) == FLAG) printf("  F");
            else if ((currPos & QUESTION_MARK) == QUESTION_MARK) printf("  ?");
            else if ((currPos & WRONG_MINE) == WRONG_MINE) printf(" X ");
        }

        printf("\n");
    }

    return;
}
```

### Flagging the mines
Once I finished having my fun with reversing parts of the left click function, decided to challenge myself and write code to interact with the program, rather than just read its memory. Other than a college class and two personal projects, I don't have much experience with the C language, much less C on Windows, but given my situtation (stuck inside reversing a 15+ year old program while the country decends into chaos during the summer of 2020), this was a perfect opportunity to learn. I decided to write code to flag all of the mines in the minefield. Unfortunately, I would later find out near the end of the project that this was half the work to winning the game. I figured this out as I smashed the left click button using both hands as quickly as possible to uncover all the remaining tiles - the other condition to fulfill in order to win Minesweeper.

At first, I tried just changing the mines in memory from `0x8F` (an unclicked mine) to `0x8E` (a flagged mine) but I was causing minesweeper to crash. I realized that there are three things that happen when a mine is flagged:
1) The image of a flag is drawn on the tile
2) The number of mines remaining counter is decremented
3) Sets the tile to `0x8E` (a flagged mine)

So I would either need to write code to perform these three actions or find code in winmine.exe to perform these tasks for me. I've been reading about process injection in the past, but haven't had the opportunity to perform process injection myself so I decided to search for code in winmime.exe that does all this work for me.

To find out how to flag a mine, I used the same methodology that I implemented to find out what left clicking a tile does. I set a breakpoint on all references to `BitBlt` and right clicked a tile (on a blank tile, this draws a flag). Interestingly enough, our breakpoint stops us at exactly the address we stopped at in figure 1. I stepped out of the function that called `BitBlt` and saw the assembly in the image below.

![Figure 6](/assets/images/MinesweeperHelper/Figure6.jpg)
Figure 6

This function sets the least significant part of the byte of the tile we clicked to `0xE` or `0xD` (flag or question mark, respectively, depending on what the value of the byte was before it was right clicked) and calls the draw function, which accomplishes two of the three requirements above. I stepped out of this function to look at the calling function and was presented with the assembly seen below.

![Figure 7](/assets/images/MinesweeperHelper/Figure7.jpg)
Figure 7

This function has a LOT going on so I put it comments inline to describe what's going on. The gist of this function is:
* Determine what value is currently assigned to the right clicked tile.
* If it's currently blank or a flag, the number of remaining mines will need to be updated (numMines++ if it's currently a flag, numMines-- if it's currently a blank tile) and the image displaying the number of remaining mines will need to be re-drawn.
* Draw the new image over the tile
* It takes the x,y coordinates as arguments

This function, along with the functions it calls, accomplishes all three tasks that need to be done to flag a mine and all we need to do is pass the x,y coordinates as arguments. This is the function we'll call to flag mines.

I used [`CreateRemoteThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) to execute this function remotely. This is almost perfect as I wouldn't need to allocate any room for shellcode... except `CreateRemoteThread` only accepts a single void pointer as an argument and the function I want to call requires two integers. I solved this problem by:
* Creating a struct that holds two integers
* Creating a wrapper function that accepts a pointer to this structure and calls another function that takes two integers as parameters
* Compiling the code for this ^^ and saving it as shellcode in my program
* Writing the shellcode to winmime.exe during runtime and executing it

The code I used to compile and base my shellcode off of
```c
// To pass two or more arguments to CreateRemoteThread, we'll use a struct
// to put two DWORDs on the stack
struct parameters_s {
    int x;
    int y;
};

void aSecondDeeperTestFunction_oooo_spooky(int x, int y) {
/**
 * Purpose: This is meant to emulate the function I actually
 *          want to call in winmine.exe. It's only in this test
 *          file so I can call a function with similar parameters.
 * @param x : int - the x coord
 * @param y : int - the y coord
 * @return void
 */
    x = x + y; // Make compiler warnings go away
    exit(0);
}

void testFunction(struct parameters_s* param) {
/**
 * Purpose: The meat of the shellcode will be the compiled
 *          result of this function. This is what I will write to memory and
 *          call in CreateRemoteThread.
 * @param param : struct parameters_s* - a pointer to a parameters_s structure
 * @return void
 */
    aSecondDeeperTestFunction_oooo_spooky(param->x, param->y);
    return;
}

    
int main(void) {
    
    struct parameters_s param;
    param.x = 6;
    param.y = 4;

    testFunction(&param);

    return 0;
}
```

Function to flag all the mines. See minefinder.c
```c
int FlagAllMines(HANDLE hMineSweeper, DWORD baseAddr, DWORD width, \
                 DWORD height, unsigned char* mineField, DWORD numMines) {
/**
 * Purpose: Puts a flag over every mine
 * @param hMineSweeper : HANDLE - process handle to minesweeper
 * @param baseAddr : DWORD - the base address of the minesweeper process in memory
 * @param width : DWORD - the width of the minefield
 * @param height : DWORD - the height of the minefield
 * @param mineField : unsigned char* - the minefield in memory
 * @return : int - 0 on success, 1 on failure
 */

    // To pass two or more arguments to CreateRemoteThread, we'll use a struct
    // to put two ints on the stack
    struct parameters_s {
        int x;
        int y;
    };

    // Local variables
    unsigned char buff = (unsigned char)(MINE | UNCLICKED_SPACE);
    struct parameters_s *mineLocations = (struct parameters_s*)malloc(sizeof(struct parameters_s)*numMines);
    DWORD minesFound = 0;         // Number of mines found
    DWORD foundExplodedMine = 0;  // Did we find an exploded mine?
    int errorCode = 0;            // A better name would have been "returnCode"
    SIZE_T bytesWritten;          // Receives the number of bytes WriteProcessMemory wrote
    int currOffset;               // The current mine we're dealing with
    HANDLE hThread;               // Handle to the remote thread created by CreateRemoteThread

    // Our shellcode to call with CreateRemoteThread. Allows us to
    // pass multiple parameters via use of a pointer to a structure
    unsigned char shellcode[] = "\x55\x8B\xEC\x8B\x45\x08\x8B\x48\x04"  // ASM pre-amble, pushing x + y coords on stack
                                "\x51\x8B\x55\x08\x8B\x02\x50\xE8\x00"  // calling the right click function in winmine
                                "\x00\x00\x00\x5D\xC3";                 // poping EBP and returning. Lesson learned here
                                                                        // is that threads don't exit properly if you're
                                                                        // debugging them

    // Iterate through the minefield finding the location of all mines
    for (DWORD y = 32; y <= height*32; y+=32) {
        for (DWORD x = 1; x <= width; x++) {

            // Did we find an exploded mine?
            if ((mineField[x + y] & EXPLODED_MINE) == EXPLODED_MINE) {
                foundExplodedMine = 1;
                break;
            }

            // Did we find a mine?
            if ((mineField[x + y] & MINE) == MINE) {
                mineLocations[minesFound].x = (int)x;
                mineLocations[minesFound].y = (int)y/32;
                minesFound++;
            }
        }

        // Did we find an exploded mine?
        if (foundExplodedMine) { break; }
    }

    // If the game isn't over, flag all the mines
    if (!foundExplodedMine) {

        // Allocate space in the remote process for our shellcode
        LPVOID spaceForShellcode = VirtualAllocEx(hMineSweeper, NULL, SHELLCODE_LENGTH, \
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!spaceForShellcode) {
            printf("Error allocating space for the shellcode: %d\n", GetLastError());
            free(mineLocations);
            return 1;
        }

        // Allocate space in the remote process for us to write our arguments to
        LPVOID spaceForParameter = VirtualAllocEx(hMineSweeper, NULL, sizeof(struct parameters_s), \
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!spaceForParameter) {
            printf("Error allocating space for the shellcode parameters: %d\n", GetLastError());
            free(mineLocations);
            VirtualFreeEx(hMineSweeper, spaceForShellcode, SHELLCODE_LENGTH, MEM_RELEASE);
            return 1;
        }

        // Dynamically calculate the operand for the CALL instruction in the shellcode
        int callOpOffset = ((int)baseAddr + FLAG_TILE_FUNCTION) \
                           - ((int)spaceForShellcode + INST_AFTER_CALL_OFFSET);
        
        // Copy the bytes over to an unsigned char array. No need to reverse the byte
        // ordering as they're already reversed in memory
        memcpy(shellcode + SHELLCODE_CALL_OFFSET, &callOpOffset, sizeof(int));

        // Write the shellcode to memory
        if (!WriteProcessMemory(hMineSweeper, spaceForShellcode, (LPCVOID)shellcode, SHELLCODE_LENGTH, \
                                &bytesWritten)) {
            printf("Error calling WriteProcessMemory: %d\n", GetLastError());
            free(mineLocations);
            VirtualFreeEx(hMineSweeper, spaceForShellcode, SHELLCODE_LENGTH, MEM_RELEASE);
            VirtualFreeEx(hMineSweeper, spaceForParameter, sizeof(struct parameters_s), MEM_RELEASE);
            return 1;
        }

        // For each mine location, mark it as flagged
        for (int i = 0; i < (int)numMines; i++) {

            // Get the location of the mine relative to the start of the mine
            // field in the target process
            currOffset = mineLocations[i].x + mineLocations[i].y*32;

            // First make sure the tile doesn't already have a flag
            if (mineField[currOffset] == (FLAG | MINE)) continue;

            // Change the mine to a blank tile if it's a question mark
            if (mineField[currOffset] == (MINE | QUESTION_MARK)) {
                if (!WriteProcessMemory(hMineSweeper, \
                                       (LPVOID)(baseAddr + MINEFIELD_OFFSET + currOffset), \
                                       (LPCVOID)&buff, 1, &bytesWritten)) {
                    printf("Error calling WriteProcessMemory: %d\n", GetLastError());
                    free(mineLocations);
                    errorCode = 1;
                    break;
                }
            }

            // Call the function in minesweeper to add a flag. Will need to allocate memory in
            // the target process, write a struct containing x, y coord to mem, pass the struct as the param
            if (!WriteProcessMemory(hMineSweeper, spaceForParameter, &(mineLocations[i]), \
                                    sizeof(struct parameters_s), &bytesWritten)) {
                printf("Error calling WriteProcessMemory: %d\n", GetLastError());
                errorCode = 1;
                break;
            }

            // Create the remote thread and wait for it to finish executing.
            // Otherwise, we could overwrite spaceForParameter before the
            // thread gets a chance to use it.
            hThread = CreateRemoteThread(hMineSweeper, NULL, 0, (LPTHREAD_START_ROUTINE)spaceForShellcode,\
                                         spaceForParameter, 0, NULL);
            if (!hThread) {
                printf("Error calling CreateRemoteThread: %d\n", GetLastError());
                errorCode = 1;
                break;
            }
            WaitForSingleObject(hThread, 1000);
            CloseHandle(hThread);
        }
        VirtualFreeEx(hMineSweeper, spaceForShellcode, SHELLCODE_LENGTH, MEM_RELEASE);
        VirtualFreeEx(hMineSweeper, spaceForParameter, sizeof(struct parameters_s), MEM_RELEASE);
    } // END if (!foundExplodedMine)
    else {
        printf("Found an exploded mine. The game is already over. Start a new game first\n");
    }

    // "-STEP ON YOUR RIGHT FOOT- FREE YOUR MEMORY ALLOCATIONS, DON'T FORGET IT"
    //     - Spongebob Squarepants on dynamic memory allocation
    free(mineLocations);

    return errorCode;
}
```

I put in a little more effort and the result is an interactive menu that allows you to display information about the current game, print the minefield, or flag all the mines in the minefield. Included in [my repository](https://github.com/TRDan6577/Minesweeper-Helper) is a 32-bit complied version of minefinder.c
