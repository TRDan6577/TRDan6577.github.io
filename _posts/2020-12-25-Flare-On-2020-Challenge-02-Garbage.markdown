---
title: "Flare-On 2020: 02 - Garbage"
date: 2020-12-25 00:02:00
header:
  image: /assets/images/02Garbage/2.1.jpg
  teaser: /assets/images/02Garbage/2.1.jpg
tags: [ctf, reversing, flareon]
---
# Challenge 2 - Garbage

> One of our team members developed a Flare-On challenge but accidentally deleted it. We recovered it using extreme digital forensic techniques but it seems to be corrupted. We would fix it but we are too busy solving today's most important information security threats affecting our global economy. You should be able to get it working again, reverse engineer it, and acquire the flag.

"Garbage". It's both the name of the challenge and how I felt about myself while doing it. We're given a broken executable and we need to figure out what's wrong and fix it to reveal the flag.

Simply running the executable results in an error message from Windows:

![2.1.jpg](/assets/images/02Garbage/2.1.jpg)

Let's open it with PEView to get a little more information about the file.

![2.2.jpg](/assets/images/02Garbage/2.2.jpg)

Looks like this file is packed with [upx](https://github.com/upx/upx)! Maybe we can get a better understanding of the error if we unpack the file. Using the [latest in upx technology](https://github.com/upx/upx/releases/tag/v3.96), we run `upx.exe -d garbage.exe` to extract our file to a more readable format:

![2.3.jpg](/assets/images/02Garbage/2.3.jpg)

Crap. What the hell's an "overlay size"?? We can find our error message in the [source code for upx](https://github.com/upx/upx/blob/d7ba31cab8ce8d95d2c10e88d2ec787ac52005ef/src/packer.cpp#L577), hosted graciously by the upx overlords on github:
```cpp
void Packer::checkOverlay(unsigned overlay)
{
    if ((int)overlay < 0 || (off_t)overlay > file_size)
        throw OverlayException("invalid overlay size; file is possibly corrupt");
    if (overlay == 0)
        return;
    info("Found overlay: %d bytes", overlay);
    if (opt->overlay == opt->SKIP_OVERLAY)
        throw OverlayException("file has overlay -- skipped; try '--overlay=copy'");
}
```

While the first portion of the if statement doesn't help us, the comparison to the file size tells us that the error message could be indicating a difference between the actual size of the file and the expected size of the file. Let's take a look at the PE headers to see how big they say the file is and compare it with the actual size of the file. I used [PEView](http://wjradburn.com/software/) to examine the section headers and recorded the results below.

UPX0 starts at file offset 0x400 and has a size on disk of 0x0
UPX1 starts at file offset 0x400 and has a size on disk of 0x9a00
RSRC starts at file offset 0x9e00 and has a size on disk of 0x400
Actual size on disk: 0x9f24
Total size as indicated by the section headers: 0xa200

By appending zeroes to the end of the file, I can make the actual file size the same as expected by the headers and decompresses the file properly:

![2.4](/assets/images/02Garbage/2.4.jpg)

Now let's run it and get our flag!

![2.5](/assets/images/02Garbage/2.5.jpg)

😭 NOOOOOOOOOOOOOOOO 😭 . After using Google for a bit to determine what a side-by-side configuration is, I found [this article](https://www.codeproject.com/Articles/43681/Side-by-Side-Configuration-Incorrect) which mentions "A side-by-side assembly contains a collection of resources—a group of DLLs, Windows classes, COM servers, type libraries, or interfaces—that are always provided to applications together. These are described in the assembly manifest". Microsoft mentions [three ways to install an assembly manifest](https://docs.microsoft.com/en-us/windows/win32/sbscs/assembly-manifests). Two of these methods involve having another file in the directory (we only have our executable in the directory) and the last one mentions installing the assembly manifest in the resource section of the executable. [Resource hacker](http://angusj.com/resourcehacker/) confirms our suspicions!

![2.6](/assets/images/02Garbage/2.6.jpg)

We have only a portion of the manifest in the resource section. I have no clue how to build these so lets try overwritting the whole thing with zeros. According to PEView, the resource section starts at physical file offset 0x12600 and is 0x200 bytes big.

![2.7](/assets/images/02Garbage/2.7.jpg)

"Hey! A new error message! That's always a good thing!", he said, in a pathetic attempt to keep positive after hours of slamming his head against the desk. Alright, this is a little weird. It seems like there's no DLL names in the executable for Windows to find. Let's go back to our only companion in this dark time, PEVeiw.

![2.8](/assets/images/02Garbage/2.8.jpg)

[Mircosoft has some pretty good documentation on this](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN#import-directory-table), so I'll quote them:
>The import directory table contains address information that is used to resolve fixup references to the entry points within a DLL image. The import directory table consists of an array of import directory entries, one entry for each DLL to which the image refers. The last directory entry is empty (filled with null values), which indicates the end of the directory table.

We can see from the screenshot there are 3 entries, so the binary imports two DLLs. The import directory table contains a field called the Name Relative Virtual Address (RVA). This field is a pointer to the ascii string that contains the name of the the DLL. Let's convert both these RVAs to physical offsets with the formula `PhysicalOffset = SomeGivenRVA - VirtualAddressOfSection + RawOffsetOfSection`. In our case,  the RVA for both DLLs is in the .rdata section which has an RVA of 0xd000 and a physical offset of 0xC200. This gives us:

Offset1 = 0x12434 - 0xd000 + 0xc200 = 0x11634
Offset2 = 0x12452 - 0xd000 + 0xc200 = 0x11652

![2.9](/assets/images/02Garbage/2.9.jpg)

Our hex editor shows that these locations are empty! It can't find the DLLs because they aren't named. We know there are two DLLs and based on the functions listed in the import address table, those two are kernel32.dll and shell32.dll. In the import address table, the kernel32 API functions are listed first and the shell32 function is last so let's set offset1 to kernel32.dll and offset2 to shell32.dll.

![2.10](/assets/images/02Garbage/2.10.jpg)

Now when we run it, we don't get any error messages! The downside is that nothing's happening. Using procmon to help diagnose, we see that our executable is launching WerFault and exiting, suggesting that there's still an unresolved error.

![2.11](/assets/images/02Garbage/2.11.jpg)

Using a debugger and hitting "run", we get a memory violation error. The program is trying to read memory address 0x413004 but nothing in memory is loaded at that address. Looking at the hard coded memory addresses in the code above and below where the fault occurred shows a bunch of memory addresses pointing to 0x400000 - 0x413000. This is because these memory addresses were never changed when the binary was loaded into memory at a different base address than the one indicated in the PE header due to ASLR! PEView confirms that the relocation section of the PE is entirely empty.

The ASLR flag is located in the DLL Characteristics field of the optional header. 0x40 indicates that the binary is ASLR enabled while 0x00 indicates that it is not. Our binary has it enabled.

![2.12](/assets/images/02Garbage/2.12.jpg)

Changing this to 0x00 and running the binary presents us with a glorious message box:

![2.13](/assets/images/02Garbage/2.13.jpg)

Our flag is `C0rruptGarbag3@flare-on.com`.

{% for post in site.posts -%}
 {% if post.title contains "Flare-On 2020 Challenges" %}
   [Click here]({{- post.url  -}}) to return to the Flare-On 2020 overview page.
 {% endif %}
{%- endfor %}
