---
title: "Flare-On 2020: 04 - Report"
date: 2020-12-25 00:04:00
header:
  image: /assets/images/04Report/header.png
  teaser: /assets/images/04Report/header.png
  caption: "[credit](https://www.fortinet.com/content/dam/fortinet-blog/new-images/uploads/microsoft-excel-files-increasingly-used-to-spread-malware-1421.png)"
---
# Challenge 4 - Report

> Nobody likes analysing infected documents, but it pays the bills. Reverse this macro thrill-ride to discover how to get it to show you the key.

For this challenge, we have to get macros within an office document to give us the flag. Let's start by using [oletool's](https://github.com/decalage2/oletools) [olevba](https://github.com/decalage2/oletools/wiki/olevba) to extract the macros `olevba report.xls > output.txt`. As usual, this dumps out all of the macros plus a very helpful analysis chart for us:

```
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Put                 |May write to a file (if combined with Open)  |
|Suspicious|Open                |May open a file                              |
|Suspicious|Lib                 |May run code from a DLL                      |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |wininet.dll         |Executable file name                         |
|IOC       |winmm.dll           |Executable file name                         |
|Suspicious|VBA Stomping        |VBA Stomping was detected: the VBA source    |
|          |                    |code and P-code are different, this may have |
|          |                    |been used to hide malicious code             |
+----------+--------------------+---------------------------------------------+
```

Of particular note is the last detection - the VBA Stomping. I had never heard of this before this challenge and found [this](https://github.com/bontchev/pcodedmp) was a great resource. To summarize that link, there are two ways that VBA code generally exists in an office document (a third exists but is less common):

* Source code: This is what most tools look at when analyzing macros however it is usually ignored by Office when the macros are executed. An Office document will only execute macros in this form if the version of Office used to open the file uses a different VBA version than the one used to create the document. If the versions differ, the Office document will compile the source code into p-code and execute that (for backwards compatibility reasons).
* P-Code: A compiled version of VBA that's stored in an Office document. This is what's executed when an office document is opened

This is a hint to us to compare the p-code and source code to confirm there's a difference and if so, analyze the p-code instead of the source code. If you miss this detection and ignore the p-code section, you're not alone - I did the same thing. Ignoring the p-code section, if you remove all the unnecessary checks and widdle the code down to the core of its logic, you get the following:

```vb
Sub test()
    Dim xertz As Variant
    Dim mf As String
    Dim wabbit() As Byte
    Dim fn As Integer: fn = FreeFile
    Dim onzo() As String
    
    onzo = Split(F.L, ".")
    xertz = Array(&H11, &H22, &H33, &H44, &H55, &H66, &H77, &H88, &H99, &HAA, &HBB, &HCC, &HDD, &HEE)
    
    wabbit = canoodle(F.T.Text, 0, 168667, xertz)
    mf = Environ("AppData") & "\Microsoft\stomp.mp3"
    Open mf For Binary Lock Read Write As #fn
        Put #fn, , wabbit
    Close #fn
 
 End Sub
 ```

This mp3 file that it generates doesn't actually play anything (but, in my opinion, should have played some sad violin music). Inside the mp3, the author of the challenge tells us we're going down the wrong rabbit hole and polietly directs us to examine the p-code.

![4.3.jpg](/assets/images/04Report/4.3.jpg)

Now confidently back on track, examining the p-code and comparing it to the source code tell us that all the functions except for the end of `folderol()` (the function that's called when macros are enabled) are exactly the same. There's no guide that I could find for reversing p-code but after comparing a few lines of p-code to source code, it's fairly intuitive and I was able to figure it out on the fly.

After reversing the p-code, trimming the unnecessary fat, and adding a touch of our own code, we're left with the following:

```vb
Sub test()
    Dim test As String
    Dim xertz As Variant
    Dim mf As String
    Dim wabbit() As Byte
    Dim fn As Integer: fn = FreeFile
    Dim buff(0 To 7) As Byte
    Dim FileNum As Integer
    Dim DataLine As String
    Dim Data As String
    
    Data = ""
    
    FileNum = FreeFile()
    Open "C:\Users\evilMalware\Desktop\raw.txt" For Input As #FileNum
    
    While Not EOF(FileNum)
        Line Input #FileNum, DataLine
        Data = Data + DataLine
    Wend
    
    Close
    
    firkin = "FLARE-ON"
    n = Len(firkin)
    For i = 1 To n
        buff(n - i) = Asc(Mid(firkin, i, 1))
    Next
    
    wabbit = canoodle(Data, 2, 285729, buff)
    mf = Environ("AppData") & "\Microsoft\v.png"
    Open mf For Binary Lock Read Write As #fn
        Put #fn, , wabbit
    Close #fn
    
    Set panuding = Sheet1.Shapes.AddPicture(mf, False, True, 12, 22, 600, 310)
 End Sub
 ```

where "raw.txt" is the full content of F.T.Text which can be found in the olevba dump we did earlier. Running this code generates an image file with the flag:


![4.4.jpg](/assets/images/04Report/4.4.jpg)


Flag: `thi5_cou1d_h4v3_b33n_b4d@flare-on.com`

{% for post in site.posts -%}
 {% if post.title contains "Flare-On 2020 Challenges" %}
   [Click here]({{- post.url  -}}) to return to the Flare-On 2020 overview page.
 {% endif %}
{%- endfor %}
