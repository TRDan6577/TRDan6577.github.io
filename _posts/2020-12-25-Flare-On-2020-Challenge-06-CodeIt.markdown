---
title: "Flare-On 2020: 06 - CodeIt"
show_date: true
date: 2020-12-25 00:06:00
header:
  image: /assets/images/06CodeIt/header.png
  teaser: /assets/images/06CodeIt/header.png
  caption: "[credit](https://logos-download.com/wp-content/uploads/2020/06/AutoIt_Logo.png)"
tags: [reversing, ctf, flareon, autoit]
---
# Challenge 6 - Codeit

> Reverse engineer this little compiled script to figure out what you need to do to make it give you the flag (as a QR code).

Extracting the zip file for the challenge only gives us the LICENSE file, the challenge message file, and an executable called codeit.exe. Running the executable shows a handsome flareon symbol, ready to generate some QR codes.

![6.1.jpg](/assets/images/06CodeIt/6.1.jpg)

According to the message included with the challenge, it sounds like some secret input gives the flag as a QRcode. Let's try "password"!

![6.2.jpg](/assets/images/06CodeIt/6.2.jpg)

The program generates a QRcode that, when scanned, shows the input. Maybe the 6th challenge will be unusually easier than the rest and the secret code is a string stored in the binary?

Drat. While there's nothing that could obviously be the flag here, we do find the string "AU3!EA06T"

![6.3.jpg](/assets/images/06CodeIt/6.3.jpg)

au3 is a common file extension for AutoIt version 3 files. Searching around on the internet for some resources to reverse engineer an AutoIt compiled program, I found [a blog post](https://r3mrum.wordpress.com/2017/07/10/autoit-malware-from-compiled-binary-to-plain-text-script/) with a link at the bottom to an [AutoIt decompiler](https://drive.google.com/open?id=1H9s9y-3LgdEjBayUOeBv88dZzXUIoHwC). Running our compiled binary through the AutoIt decomplier is a success! We're given a highly obfuscated AutoIt script that we'll need to reverse engineer in order to figure out the flag.

In order to help the reverse engineering process, I created a powershell script to help de-obfuscate the code. You can find Invoke-DeObfuscation in the folder [here](https://github.com/TRDan6577/Writeups/tree/main/FireEye%20Flare-On/2020).

The deobfuscation plus a little extra labeling from manual analysis gives us:
```
#Region
	#AutoIt3Wrapper_UseUpx=y
#EndRegion
Global Const $str_nocasesense = 0
Global Const $str_casesense = 1
Global Const $str_nocasesensebasic = 2
Global Const $str_stripleading = 1
Global Const $str_striptrailing = 2
Global Const $str_stripspaces = 4
Global Const $str_stripall = 8
Global Const $str_chrsplit = 0
Global Const $str_entiresplit = 1
Global Const $str_nocount = 2
Global Const $str_regexpmatch = 0
Global Const $str_regexparraymatch = 1
Global Const $str_regexparrayfullmatch = 2
Global Const $str_regexparrayglobalmatch = 3
Global Const $str_regexparrayglobalfullmatch = 4
Global Const $str_endisstart = 0
Global Const $str_endnotstart = 1
Global Const $sb_ansi = 1
Global Const $sb_utf16le = 2
Global Const $sb_utf16be = 3
Global Const $sb_utf8 = 4
Global Const $se_utf16 = 0
Global Const $se_ansi = 1
Global Const $se_utf8 = 2
Global Const $str_utf16 = 0
Global Const $str_ucs2 = 1

Func _hextostring($shex)
	If NOT (StringLeft($shex, 2) == "0x") Then $shex = "0x" & $shex
	Return BinaryToString($shex, $sb_utf8)
EndFunc

Func _stringbetween($sstring, $sstart, $send, $imode = $str_endisstart, $bcase = False)
	$sstart = $sstart ? "\Q" & $sstart & "\E" : "\A"
	If $imode <> $str_endnotstart Then $imode = $str_endisstart
	If $imode = $str_endisstart Then
		$send = $send ? "(?=\Q" & $send & "\E)" : "\z"
	Else
		$send = $send ? "\Q" & $send & "\E" : "\z"
	EndIf
	If $bcase = Default Then
		$bcase = False
	EndIf
	Local $areturn = StringRegExp($sstring, "(?s" & (NOT $bcase ? "i" : "") & ")" & $sstart & "(.*?)" & $send, $str_regexparrayglobalmatch)
	If @error Then Return SetError(1, 0, 0)
	Return $areturn
EndFunc

Func _stringexplode($sstring, $sdelimiter, $ilimit = 0)
	If $ilimit = Default Then $ilimit = 0
	If $ilimit > 0 Then
		Local Const $null = Chr(0)
		$sstring = StringReplace($sstring, $sdelimiter, $null, $ilimit)
		$sdelimiter = $null
	ElseIf $ilimit < 0 Then
		Local $iindex = StringInStr($sstring, $sdelimiter, $str_nocasesensebasic, $ilimit)
		If $iindex Then
			$sstring = StringLeft($sstring, $iindex - 1)
		EndIf
	EndIf
	Return StringSplit($sstring, $sdelimiter, BitOR($str_entiresplit, $str_nocount))
EndFunc

Func _stringinsert($sstring, $sinsertion, $iposition)
	Local $ilength = StringLen($sstring)
	$iposition = Int($iposition)
	If $iposition < 0 Then $iposition = $ilength + $iposition
	If $ilength < $iposition OR $iposition < 0 Then Return SetError(1, 0, $sstring)
	Return StringLeft($sstring, $iposition) & $sinsertion & StringRight($sstring, $ilength - $iposition)
EndFunc

Func _stringproper($sstring)
	Local $bcapnext = True, $schr = "", $sreturn = ""
	For $i = 1 To StringLen($sstring)
		$schr = StringMid($sstring, $i, 1)
		Select 
			Case $bcapnext = True
				If StringRegExp($schr, "[a-zA-ZÀ-ÿšœžŸ]") Then
					$schr = StringUpper($schr)
					$bcapnext = False
				EndIf
			Case NOT StringRegExp($schr, "[a-zA-ZÀ-ÿšœžŸ]")
				$bcapnext = True
			Case Else
				$schr = StringLower($schr)
		EndSelect
		$sreturn &= $schr
	Next
	Return $sreturn
EndFunc

Func _stringrepeat($sstring, $irepeatcount)
	$irepeatcount = Int($irepeatcount)
	If $irepeatcount = 0 Then Return ""
	If StringLen($sstring) < 1 OR $irepeatcount < 0 Then Return SetError(1, 0, "")
	Local $sresult = ""
	While $irepeatcount > 1
		If BitAND($irepeatcount, 1) Then $sresult &= $sstring
		$sstring &= $sstring
		$irepeatcount = BitShift($irepeatcount, 1)
	WEnd
	Return $sstring & $sresult
EndFunc

Func _stringtitlecase($sstring)
	Local $bcapnext = True, $schr = "", $sreturn = ""
	For $i = 1 To StringLen($sstring)
		$schr = StringMid($sstring, $i, 1)
		Select 
			Case $bcapnext = True
				If StringRegExp($schr, "[a-zA-Z\xC0-\xFF0-9]") Then
					$schr = StringUpper($schr)
					$bcapnext = False
				EndIf
			Case NOT StringRegExp($schr, "[a-zA-Z\xC0-\xFF'0-9]")
				$bcapnext = True
			Case Else
				$schr = StringLower($schr)
		EndSelect
		$sreturn &= $schr
	Next
	Return $sreturn
EndFunc

Func _stringtohex($sstring)
	Return Hex(StringToBinary($sstring, $sb_utf8))
EndFunc

#OnAutoItStartRegister "AREIHNVAPWN"

Func buildBitMapInfoHeader($flmojocqtz, $fljzkjrgzs, $flsgxlqjno)  ; https://docs.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapinfoheader
	Local $struct[2]
	$struct[0] = DllStructCreate('struct;uint bfSize;uint bfReserved;uint bfOffBits;uint biSize;int biWidth;int biHeight;ushort biPlanes;ushort biBitCount;uint biCompression;uint biSizeImage;int biXPelsPerMeter;int biYPelsPerMeter;uint biClrUsed;uint biClrImportant;endstruct;')
	DllStructSetData($struct[0], 'bfSize', (3 * $flmojocqtz + Mod($flmojocqtz, 4) * Abs($fljzkjrgzs)))
	DllStructSetData($struct[0], 'bfReserved', 0)
	DllStructSetData($struct[0], 'bfOffBits', 54)
	DllStructSetData($struct[0], 'biSize', 40)
	DllStructSetData($struct[0], 'biWidth', $flmojocqtz)
	DllStructSetData($struct[0], 'biHeight', $fljzkjrgzs)
	DllStructSetData($struct[0], 'biPlanes', 1)
	DllStructSetData($struct[0], 'biBitCount', 24)
	DllStructSetData($struct[0], 'biCompression', 0)
	DllStructSetData($struct[0], 'biSizeImage', 0)
	DllStructSetData($struct[0], 'biXPelsPerMeter', 0)
	DllStructSetData($struct[0], 'biYPelsPerMeter', 0)
	DllStructSetData($struct[0], 'biClrUsed', 0)
	DllStructSetData($struct[0], 'biClrImportant', 0)
	$struct[1] = DllStructCreate('struct;' & _stringrepeat('byte[' & DllStructGetData($struct[0], 'biWidth') * 3 & '];', DllStructGetData($struct[0], 'biHeight')) & 'endstruct')
	Return $struct
EndFunc

Func CreateRandomLowercaseString($Min, $Max)  ; Build a random lowercase string between [a-z] of a random size betwen arg1 and arg2
	Local $StringResult = ''
	For $flezmzowno = 0 To Random($Min, $Max, 1)  ; from 0 to a random integer between arg1 and arg2
		$StringResult &= Chr(Random(97, 122, 1))
	Next
	Return $StringResult
EndFunc

Func InstallBmpOrDll($flslbknofv)  ; Installs sprite.bmp or qr_encoder.dll with a random filename into the script directory. Returns the name of the installed file
	Local $randomAscii = CreateRandomLowercaseString(15, 20)
	Switch $flslbknofv
		Case 10 To 15
			$randomAscii &= '.bmp'
			FileInstall(".\sprite.bmp", @ScriptDir & '\' & $randomAscii)
		Case 25 To 30
			$randomAscii &= '.dll'
			FileInstall(".\qr_encoder.dll", @ScriptDir & '\' & $randomAscii)
	EndSwitch
	Return $randomAscii
EndFunc

Func GetComputerName() ; Returns the result of GetComputerNameA or -1 if error. Computer name is (essentially) [a-z0-9]{1,15}
	Local $flfnvbvvfi = -1
	Local $flfnvbvvfiraw = DllStructCreate('struct;dword;char[1024];endstruct')
	DllStructSetData($flfnvbvvfiraw, 1, 1024)
	Local $flmyeulrox = DllCall('kernel32.dll', 'int', 'GetComputerNameA', 'ptr', DllStructGetPtr($flfnvbvvfiraw, 2), 'ptr', DllStructGetPtr($flfnvbvvfiraw, 1))
	If $flmyeulrox[0] <> 0 Then
;		$flfnvbvvfi = BinaryMid(DllStructGetData($flfnvbvvfiraw, 2), 1, DllStructGetData($flfnvbvvfiraw, 1))
	EndIf
	Return $flfnvbvvfi
EndFunc

GUICreate('CodeIt Plus!', 300, 375, -1, -1)

Func obfuscateComputerName(ByRef $ComputerName)  ; Encodes the data in the struct passed in
	Local $bmpFileName = InstallBmpOrDll(14)
	Local $hBmpFile = OpenFileForRead($bmpFileName)
	If $hBmpFile <> -1 Then
		Local $fileSize = GetFileSize($hBmpFile)
		If $fileSize <> -1 AND DllStructGetSize($ComputerName) < $fileSize - 54 Then
			Local $byteArrayFileSizeStruct = DllStructCreate('struct;byte[' & $fileSize & '];endstruct')
			Local $readResult = ReadAFile($hBmpFile, $byteArrayFileSizeStruct)
			If $readResult <> -1 Then
				Local $flxmdchrqd = DllStructCreate('struct;byte[54];byte[' & $fileSize - 54 & '];endstruct', DllStructGetPtr($byteArrayFileSizeStruct))
				Local $index = 1
				Local $obfuscated = ''
				For $counter = 1 To DllStructGetSize($ComputerName)
					Local $charCode = Number(DllStructGetData($ComputerName, 1, $counter))
					For $subCounter = 6 To 0 Step -1
						$charCode += BitShift(BitAND(Number(DllStructGetData($flxmdchrqd, 2, $index)), 1), -1 * $subCounter)
						$index += 1
					Next
					$obfuscated &= Chr(BitShift($charCode, 1) + BitShift(BitAND($charCode, 1), -7))
				Next
				DllStructSetData($ComputerName, 1, $obfuscated)
			EndIf
		EndIf
		CloseAHandle($hBmpFile)
	EndIf
	DeleteAFile($bmpFileName)
EndFunc

Func decryptData(ByRef $flodiutpuy)
	; Custom defined varaiables for readability
	Local $PROV_RSA_AES = 24
	Local $CRYPT_VERIFYCONTEXT = 4026531840
	Local $CALG_SHA_256 = 32780  ; SHA256

	Local $ComputerName = GetComputerName()
	If $ComputerName <> -1 Then
		$ComputerName = Binary(StringLower(BinaryToString($ComputerName)))
		Local $ComputerNameraw = DllStructCreate('struct;byte[' & BinaryLen($ComputerName) & '];endstruct')
		DllStructSetData($ComputerNameraw, 1, $ComputerName)
		obfuscateComputerName($ComputerNameraw)
		Local $flnttmjfea = DllStructCreate('struct;ptr;ptr;dword;byte[32];endstruct')
		DllStructSetData($flnttmjfea, 3, 32)
		Local $apiCallResult = DllCall('advapi32.dll', 'int', 'CryptAcquireContextA', 'ptr', DllStructGetPtr($flnttmjfea, 1), 'ptr', 0, 'ptr', 0, 'dword', $PROV_RSA_AES, 'dword', $CRYPT_VERIFYCONTEXT)
		If $apiCallResult[0] <> 0 Then
			$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptCreateHash', 'ptr', DllStructGetData($flnttmjfea, 1), 'dword', $CALG_SHA_256, 'dword', 0, 'dword', 0, 'ptr', DllStructGetPtr($flnttmjfea, 2))
			If $apiCallResult[0] <> 0 Then
				$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptHashData', 'ptr', DllStructGetData($flnttmjfea, 2), 'struct*', $ComputerNameraw, 'dword', DllStructGetSize($ComputerNameraw), 'dword', 0)
				If $apiCallResult[0] <> 0 Then
					$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptGetHashParam', 'ptr', DllStructGetData($flnttmjfea, 2), 'dword', 2, 'ptr', DllStructGetPtr($flnttmjfea, 4), 'ptr', DllStructGetPtr($flnttmjfea, 3), 'dword', 0)
					If $apiCallResult[0] <> 0 Then
						; The encoded computer name is hashed with SHA256 and placed in DllStructGetData($flnttmjfea, 4) up above
						Local $key = Binary('0x' & '08020' & '00010' & '66000' & '02000' & '0000') & DllStructGetData($flnttmjfea, 4)
						Local $encryptedData = Binary('0x' & 'CD4B3' & '2C650' & 'CF21B' & 'DA184' & 'D8913' & 'E6F92' & '0A37A' & '4F396' & '3736C' & '042C4' & '59EA0' & '7B79E' & 'A443F' & 'FD189' & '8BAE4' & '9B115' & 'F6CB1' & 'E2A7C' & '1AB3C' & '4C256' & '12A51' & '9035F' & '18FB3' & 'B1752' & '8B3AE' & 'CAF3D' & '480E9' & '8BF8A' & '635DA' & 'F974E' & '00135' & '35D23' & '1E4B7' & '5B2C3' & '8B804' & 'C7AE4' & 'D266A' & '37B36' & 'F2C55' & '5BF3A' & '9EA6A' & '58BC8' & 'F906C' & 'C665E' & 'AE2CE' & '60F2C' & 'DE38F' & 'D3026' & '9CC4C' & 'E5BB0' & '90472' & 'FF9BD' & '26F91' & '19B8C' & '484FE' & '69EB9' & '34F43' & 'FEEDE' & 'DCEBA' & '79146' & '0819F' & 'B21F1' & '0F832' & 'B2A5D' & '4D772' & 'DB12C' & '3BED9' & '47F6F' & '706AE' & '4411A' & '52')
						Local $newCryptStructHolder = DllStructCreate('struct;ptr;ptr;dword;byte[8192];byte[' & BinaryLen($key) & '];dword;endstruct')
						DllStructSetData($newCryptStructHolder, 3, BinaryLen($encryptedData))
						DllStructSetData($newCryptStructHolder, 4, $encryptedData)
						DllStructSetData($newCryptStructHolder, 5, $key)
						DllStructSetData($newCryptStructHolder, 6, BinaryLen($key))
						Local $apiCallResult = DllCall('advapi32.dll', 'int', 'CryptAcquireContextA', 'ptr', DllStructGetPtr($newCryptStructHolder, 1), 'ptr', 0, 'ptr', 0, 'dword', $PROV_RSA_AES, 'dword', $CRYPT_VERIFYCONTEXT)
						If $apiCallResult[0] <> 0 Then
							$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptImportKey', 'ptr', DllStructGetData($newCryptStructHolder, 1), 'ptr', DllStructGetPtr($newCryptStructHolder, 5), 'dword', DllStructGetData($newCryptStructHolder, 6), 'dword', 0, 'dword', 0, 'ptr', DllStructGetPtr($newCryptStructHolder, 2))
							If $apiCallResult[0] <> 0 Then
								$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptDecrypt', 'ptr', DllStructGetData($newCryptStructHolder, 2), 'dword', 0, 'dword', 1, 'dword', 0, 'ptr', DllStructGetPtr($newCryptStructHolder, 4), 'ptr', DllStructGetPtr($newCryptStructHolder, 3))
								If $apiCallResult[0] <> 0 Then
									; DllStructGetData($newCryptStructHolder, 4) contains the decrypted data
									; DllStructGetData($newCryptStructHolder, 3) contains the size of the decrypted data
									Local $decryptedData = BinaryMid(DllStructGetData($newCryptStructHolder, 4), 1, DllStructGetData($newCryptStructHolder, 3))
									$flare = Binary('FLARE')
									$flareButBackwards = Binary('ERALF')
									$flareFromDecryption = BinaryMid($decryptedData, 1, BinaryLen($flare))
									$BackwardsFlareFromDecryption = BinaryMid($decryptedData, BinaryLen($decryptedData) - BinaryLen($flareButBackwards) + 1, BinaryLen($flareButBackwards))
									If $flare = $flareFromDecryption AND $flareButBackwards = $BackwardsFlareFromDecryption Then
										DllStructSetData($flodiutpuy, 1, BinaryMid($decryptedData, 6, 4))
										DllStructSetData($flodiutpuy, 2, BinaryMid($decryptedData, 10, 4))
										DllStructSetData($flodiutpuy, 3, BinaryMid($decryptedData, 14, BinaryLen($decryptedData) - 18))
									EndIf
								EndIf
								DllCall('advapi32.dll', 'int', 'CryptDestroyKey', 'ptr', DllStructGetData($newCryptStructHolder, 2))
							EndIf
							DllCall('advapi32.dll', 'int', 'CryptReleaseContext', 'ptr', DllStructGetData($newCryptStructHolder, 1), 'dword', 0)
						EndIf
					EndIf
				EndIf
				DllCall('advapi32.dll', 'int', 'CryptDestroyHash', 'ptr', DllStructGetData($flnttmjfea, 2))
			EndIf
			DllCall('advapi32.dll', 'int', 'CryptReleaseContext', 'ptr', DllStructGetData($flnttmjfea, 1), 'dword', 0)
		EndIf
	EndIf
EndFunc

Func areaqwbmtiz(ByRef $flkhfbuyon)
	; Local variables created for readability
	Local $CALG_MD5 = 32771
	Local $PROV_RSA_AES = 24
	Local $CRYPT_VERIFYCONTEXT = 4026531840

	Local $Result = -1
	Local $cryptStruct = DllStructCreate('struct;ptr;ptr;dword;byte[16];endstruct')
	DllStructSetData($cryptStruct, 3, 16)
	Local $apiCallResult = DllCall('advapi32.dll', 'int', 'CryptAcquireContextA', 'ptr', DllStructGetPtr($cryptStruct, 1), 'ptr', 0, 'ptr', 0, 'dword', $PROV_RSA_AES, 'dword', $CRYPT_VERIFYCONTEXT)
	If $apiCallResult[0] <> 0 Then
		$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptCreateHash', 'ptr', DllStructGetData($cryptStruct, 1), 'dword', $CALG_MD5, 'dword', 0, 'dword', 0, 'ptr', DllStructGetPtr($cryptStruct, 2))
		If $apiCallResult[0] <> 0 Then
			$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptHashData', 'ptr', DllStructGetData($cryptStruct, 2), 'struct*', $flkhfbuyon, 'dword', DllStructGetSize($flkhfbuyon), 'dword', 0)
			If $apiCallResult[0] <> 0 Then
				$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptGetHashParam', 'ptr', DllStructGetData($cryptStruct, 2), 'dword', 2, 'ptr', DllStructGetPtr($cryptStruct, 4), 'ptr', DllStructGetPtr($cryptStruct, 3), 'dword', 0)
				If $apiCallResult[0] <> 0 Then
					$Result = DllStructGetData($cryptStruct, 4)
				EndIf
			EndIf
			DllCall('advapi32.dll', 'int', 'CryptDestroyHash', 'ptr', DllStructGetData($cryptStruct, 2))
		EndIf
		DllCall('advapi32.dll', 'int', 'CryptReleaseContext', 'ptr', DllStructGetData($cryptStruct, 1), 'dword', 0)
	EndIf
	Return $Result
EndFunc

Func CheckOsVersion()  ; Returns 0 if the OS is Windows 7, -1 otherwise
	Local $Result = -1
	; Create the OSVERSIONINFOA structure https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoa
	Local $osVersionInfoA = DllStructCreate('struct;dword;dword;dword;dword;dword;byte[128];endstruct')
	DllStructSetData($osVersionInfoA, 1, DllStructGetSize($osVersionInfoA))
	Local $flaghdvgyv = DllCall('kernel32.dll', 'int', 'GetVersionExA', 'struct*', $osVersionInfoA)
	If $flaghdvgyv[0] <> 0 Then
		If DllStructGetData($osVersionInfoA, 2) = 6 Then
			If DllStructGetData($osVersionInfoA, 3) = 1 Then
				$Result = 0
			EndIf
		EndIf
	EndIf
	Return $Result
EndFunc

Func main()
	Local $textToEncodeInputBox   = GUICtrlCreateInput('Enter text to encode', -1, 5, 300)
	Local $canHazCodeBtn          = GUICtrlCreateButton('Can haz code?', -1, 30, 300)
	Local $guiPicture             = GUICtrlCreatePic('', -1, 55, 300, 300)
	Local $helpMenuButton         = GUICtrlCreateMenu('Help')
	Local $helpMenuItem           = GUICtrlCreateMenuItem('About CodeIt Plus!', $helpMenuButton)
	Local $BmpFileName            = InstallBmpOrDll(13)  ; Installs the bitmap
	GUICtrlSetImage($guiPicture, $BmpFileName)
	DeleteAFile($BmpFileName)
	GUISetState(@SW_SHOW)  ; Reveals the GUI. Tada
	While 1
		Switch GUIGetMsg()
			Case $canHazCodeBtn
				Local $textToEncode = GUICtrlRead($textToEncodeInputBox)  ; Read the data in the $textToEncodeInputBox field
				If $textToEncode Then
					Local $dllFileName = InstallBmpOrDll(26)  ; Installs the DLL
					Local $qrCode = DllStructCreate('struct;dword;dword;byte[3918];endstruct')
					Local $apitCallResult = DllCall($dllFileName, 'int:cdecl', 'justGenerateQRSymbol', 'struct*', $qrCode, 'str', $textToEncode)
					If $apitCallResult[0] <> 0 Then
						decryptData($qrCode)  ; contains the decytped data
						Local $BitmapInfoHeader = buildBitMapInfoHeader((DllStructGetData($qrCode, 1) * DllStructGetData($qrCode, 2)), (DllStructGetData($qrCode, 1) * DllStructGetData($qrCode, 2)), 1024)
						$apitCallResult = DllCall($dllFileName, 'int:cdecl', 'justConvertQRSymbolToBitmapPixels', 'struct*', $qrCode, 'struct*', $BitmapInfoHeader[1])
						If $apitCallResult[0] <> 0 Then
							$BmpFileName = CreateRandomLowercaseString(25, 30) & '.bmp'
							arelassehha($BitmapInfoHeader, $BmpFileName)
						EndIf
					EndIf
					DeleteAFile($dllFileName)
				Else
					$BmpFileName = InstallBmpOrDll(11)
				EndIf
				GUICtrlSetImage($guiPicture, $BmpFileName)
				DeleteAFile($BmpFileName)
			Case $helpMenuItem
				Local $helpMessage = 'This program generates QR codes using QR Code Generator (https://www.nayuki.io/page/qr-code-generator-library) developed by Nayuki. '
				$helpMessage &= 'QR Code Generator is available on GitHub (https://github.com/nayuki/QR-Code-generator) and open-sourced under the following permissive MIT License (https://github.com/nayuki/QR-Code-generator#license):'
				$helpMessage &= @CRLF
				$helpMessage &= @CRLF
				$helpMessage &= 'Copyright © 2020 Project Nayuki. (MIT License)'
				$helpMessage &= @CRLF
				$helpMessage &= 'https://www.nayuki.io/page/qr-code-generator-library'
				$helpMessage &= @CRLF
				$helpMessage &= @CRLF
				$helpMessage &= 'Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the Software), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:'
				$helpMessage &= @CRLF
				$helpMessage &= @CRLF
				$helpMessage &= '1. The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.'
				$helpMessage &= @CRLF
				$helpMessage &= '2. The Software is provided as is, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the Software or the use or other dealings in the Software.'
				MsgBox(4096, 'About CodeIt Plus!', $helpMessage)
			Case -3
				ExitLoop
		EndSwitch
	WEnd
EndFunc

Func WriteBmpFileHeader($BitmapInfoHeader, $BmpFilename)
	Local $functionSuccessful = -1
	Local $BitmapInfoHeaderheadermagic = DllStructCreate('struct;ushort;endstruct')
	DllStructSetData($BitmapInfoHeaderheadermagic, 1, 19778)
	Local $hBmpFile = OpenFileForWrite($BmpFilename, False)
	If $hBmpFile <> -1 Then
		Local $ApiCallResult = WriteToFile($hBmpFile, DllStructGetPtr($BitmapInfoHeaderheadermagic), DllStructGetSize($BitmapInfoHeaderheadermagic))
		If $ApiCallResult <> -1 Then
			$ApiCallResult = WriteToFile($hBmpFile, DllStructGetPtr($BitmapInfoHeader[0]), DllStructGetSize($BitmapInfoHeader[0]))
			If $ApiCallResult <> -1 Then
				$functionSuccessful = 0
			EndIf
		EndIf
		CloseAHandle($hBmpFile)
	EndIf
	Return $functionSuccessful
EndFunc

main()

Func arelassehha($BitmapInfoHeader, $BmpFilename)
	Local $functionSuccessful = -1
	Local $apiCallResult = WriteBmpFileHeader($BitmapInfoHeader, $BmpFilename)
	If $apiCallResult <> -1 Then
		Local $hBmpFile = OpenFileForWrite($BmpFilename, True)
		If $hBmpFile <> -1 Then
			Local $flwldjlwrq = Abs(DllStructGetData($BitmapInfoHeader[0], 'biHeight'))
			Local $flumnoetuu = DllStructGetData($BitmapInfoHeader[0], 'biHeight') > 0 ? $flwldjlwrq - 1 : 0
			Local $flqphcjgtp = DllStructCreate('struct;byte;byte;byte;endstruct')
			For $fllrcvawmx = 0 To $flwldjlwrq - 1
				$apiCallResult = WriteToFile($hBmpFile, DllStructGetPtr($BitmapInfoHeader[1], Abs($flumnoetuu - $fllrcvawmx) + 1), DllStructGetData($BitmapInfoHeader[0], 'biWidth') * 3)
				If $apiCallResult = -1 Then ExitLoop
				$apiCallResult = WriteToFile($hBmpFile, DllStructGetPtr($flqphcjgtp), Mod(DllStructGetData($BitmapInfoHeader[0], 'biWidth'), 4))
				If $apiCallResult = -1 Then ExitLoop
			Next
			If $apiCallResult <> -1 Then
				$functionSuccessful = 0
			EndIf
			CloseAHandle($hBmpFile)
		EndIf
	EndIf
	Return $functionSuccessful
EndFunc

Func OpenFileForRead($Filename)  ; Opens the given file for reading. Returns a handle to the file
	Local $flrichemye = DllCall('kernel32.dll', 'ptr', 'CreateFile', 'str', @ScriptDir & '\' & $Filename, 'uint', 2147483648, 'uint', 0, 'ptr', 0, 'uint', 3, 'uint', 128, 'ptr', 0)
	Return $flrichemye[0]
EndFunc

Func OpenFileForWrite($Filename, $OpenExisting = True)  ; Opens the given file for writing. Second arg tells whether to open an existing file (true) or a new file (false)
	Local $flogmfcakq = DllCall('kernel32.dll', 'ptr', 'CreateFile', 'str', @ScriptDir & '\' & $Filename, 'uint', 1073741824, 'uint', 0, 'ptr', 0, 'uint', $OpenExisting ? 3 : 2, 'uint', 128, 'ptr', 0)
	Return $flogmfcakq[0]
EndFunc

GUIDelete()

Func WriteToFile($fileHandle, $dataToWrite, $numberOfBytesToWrite)
	If $fileHandle <> -1 Then
		; Set the file pointer to the end of the file
		Local $ApiCallResult = DllCall('kernel32.dll', 'uint', 'SetFilePointer', 'ptr', $fileHandle, 'long', 0, 'ptr', 0, 'uint', 2)
		If $ApiCallResult[0] <> -1 Then  ; If the call succeeded
			Local $numberOfBytesToWritten = DllStructCreate('uint')
			$ApiCallResult = DllCall('kernel32.dll', 'ptr', 'WriteFile', 'ptr', $fileHandle, 'ptr', $dataToWrite, 'uint', $numberOfBytesToWrite, 'ptr', DllStructGetPtr($numberOfBytesToWritten), 'ptr', 0)
			If $ApiCallResult[0] <> 0 AND DllStructGetData($numberOfBytesToWritten, 1) = $numberOfBytesToWrite Then
				Return 0
			EndIf
		EndIf
	EndIf
	Return -1
EndFunc

Func ReadAFile($hFile, ByRef $buff)
	Local $bytesRead = DllStructCreate('struct;dword;endstruct')
	Local $resultOfRead = DllCall('kernel32.dll', 'int', 'ReadFile', 'ptr', $hFile, 'struct*', $buff, 'dword', DllStructGetSize($buff), 'struct*', $bytesRead, 'ptr', 0)
	Return $resultOfRead[0]
EndFunc

Func CloseAHandle($hFile)
	Local $returnValue = DllCall('kernel32.dll', 'int', 'CloseHandle', 'ptr', $hFile)
	Return $returnValue[0]
EndFunc

Func DeleteAFile($FileName)
	Local $returnValue = DllCall('kernel32.dll', 'int', 'DeleteFileA', 'str', $FileName)
	Return $returnValue[0]
EndFunc

Func GetFileSize($hFile)
	Local $TotalFileSize = -1
	Local $lpFileSizeHigh = DllStructCreate('struct;dword;endstruct')
	Local $fileSize = DllCall('kernel32.dll', 'dword', 'GetFileSize', 'ptr', $hFile, 'struct*', $lpFileSizeHigh)
	If $fileSize <> -1 Then
		$TotalFileSize = $fileSize[0] + Number(DllStructGetData($lpFileSizeHigh, 1))
	EndIf
	Return $TotalFileSize
EndFunc

Func areihnvapwn()
	Local $dlit = "7374727563743b75696e7420626653697a653b75696e7420626652657365727665643b75696e742062664f6666426974733b"
	$dlit &= "75696e7420626953697a653b696e7420626957696474683b696e742062694865696768743b7573686f7274206269506c616e"
	$dlit &= "65733b7573686f7274206269426974436f756e743b75696e74206269436f6d7072657373696f6e3b75696e7420626953697a"
	$dlit &= "65496d6167653b696e742062695850656c735065724d657465723b696e742062695950656c735065724d657465723b75696e"
	$dlit &= "74206269436c72557365643b75696e74206269436c72496d706f7274616e743b656e647374727563743b4FD5$626653697a6"
	$dlit &= "54FD5$626652657365727665644FD5$62664f6666426974734FD5$626953697a654FD5$626957696474684FD5$6269486569"
	$dlit &= "6768744FD5$6269506c616e65734FD5$6269426974436f756e744FD5$6269436f6d7072657373696f6e4FD5$626953697a65"
	$dlit &= "496d6167654FD5$62695850656c735065724d657465724FD5$62695950656c735065724d657465724FD5$6269436c7255736"
	$dlit &= "5644FD5$6269436c72496d706f7274616e744FD5$7374727563743b4FD5$627974655b4FD5$5d3b4FD5$656e647374727563"
	$dlit &= "744FD5$4FD5$2e626d704FD5$5c4FD5$2e646c6c4FD5$7374727563743b64776f72643b636861725b313032345d3b656e647"
	$dlit &= "374727563744FD5$6b65726e656c33322e646c6c4FD5$696e744FD5$476574436f6d70757465724e616d65414FD5$7074724"
	$dlit &= "FD5$436f6465497420506c7573214FD5$7374727563743b627974655b4FD5$5d3b656e647374727563744FD5$73747275637"
	$dlit &= "43b627974655b35345d3b627974655b4FD5$7374727563743b7074723b7074723b64776f72643b627974655b33325d3b656e"
	$dlit &= "647374727563744FD5$61647661706933322e646c6c4FD5$437279707441637175697265436f6e74657874414FD5$64776f7"
	$dlit &= "2644FD5$4372797074437265617465486173684FD5$437279707448617368446174614FD5$7374727563742a4FD5$4372797"
	$dlit &= "07447657448617368506172616d4FD5$30784FD5$30383032304FD5$30303031304FD5$36363030304FD5$30323030304FD5"
	$dlit &= "$303030304FD5$43443442334FD5$32433635304FD5$43463231424FD5$44413138344FD5$44383931334FD5$45364639324"
	$dlit &= "FD5$30413337414FD5$34463339364FD5$33373336434FD5$30343243344FD5$35394541304FD5$37423739454FD5$413434"
	$dlit &= "33464FD5$46443138394FD5$38424145344FD5$39423131354FD5$46364342314FD5$45324137434FD5$31414233434FD5$3"
	$dlit &= "4433235364FD5$31324135314FD5$39303335464FD5$31384642334FD5$42313735324FD5$38423341454FD5$43414633444"
	$dlit &= "FD5$34383045394FD5$38424638414FD5$36333544414FD5$46393734454FD5$30303133354FD5$33354432334FD5$314534"
	$dlit &= "42374FD5$35423243334FD5$38423830344FD5$43374145344FD5$44323636414FD5$33374233364FD5$46324335354FD5$3"
	$dlit &= "5424633414FD5$39454136414FD5$35384243384FD5$46393036434FD5$43363635454FD5$41453243454FD5$36304632434"
	$dlit &= "FD5$44453338464FD5$44333032364FD5$39434334434FD5$45354242304FD5$39303437324FD5$46463942444FD5$323646"
	$dlit &= "39314FD5$31394238434FD5$34383446454FD5$36394542394FD5$33344634334FD5$46454544454FD5$44434542414FD5$3"
	$dlit &= "7393134364FD5$30383139464FD5$42323146314FD5$30463833324FD5$42324135444FD5$34443737324FD5$44423132434"
	$dlit &= "FD5$33424544394FD5$34374636464FD5$37303641454FD5$34343131414FD5$35324FD5$7374727563743b7074723b70747"
	$dlit &= "23b64776f72643b627974655b383139325d3b627974655b4FD5$5d3b64776f72643b656e647374727563744FD5$437279707"
	$dlit &= "4496d706f72744b65794FD5$4372797074446563727970744FD5$464c4152454FD5$4552414c464FD5$43727970744465737"
	$dlit &= "4726f794b65794FD5$437279707452656c65617365436f6e746578744FD5$437279707444657374726f79486173684FD5$73"
	$dlit &= "74727563743b7074723b7074723b64776f72643b627974655b31365d3b656e647374727563744FD5$7374727563743b64776"
	$dlit &= "f72643b64776f72643b64776f72643b64776f72643b64776f72643b627974655b3132385d3b656e647374727563744FD5$47"
	$dlit &= "657456657273696f6e4578414FD5$456e746572207465787420746f20656e636f64654FD5$43616e2068617a20636f64653f"
	$dlit &= "4FD5$4FD5$48656c704FD5$41626f757420436f6465497420506c7573214FD5$7374727563743b64776f72643b64776f7264"
	$dlit &= "3b627974655b333931385d3b656e647374727563744FD5$696e743a636465636c4FD5$6a75737447656e6572617465515253"
	$dlit &= "796d626f6c4FD5$7374724FD5$6a757374436f6e76657274515253796d626f6c546f4269746d6170506978656c734FD5$546"
	$dlit &= "869732070726f6772616d2067656e65726174657320515220636f646573207573696e6720515220436f64652047656e65726"
	$dlit &= "1746f72202868747470733a2f2f7777772e6e6179756b692e696f2f706167652f71722d636f64652d67656e657261746f722"
	$dlit &= "d6c6962726172792920646576656c6f706564206279204e6179756b692e204FD5$515220436f64652047656e657261746f72"
	$dlit &= "20697320617661696c61626c65206f6e20476974487562202868747470733a2f2f6769746875622e636f6d2f6e6179756b69"
	$dlit &= "2f51522d436f64652d67656e657261746f722920616e64206f70656e2d736f757263656420756e6465722074686520666f6c"
	$dlit &= "6c6f77696e67207065726d697373697665204d4954204c6963656e7365202868747470733a2f2f6769746875622e636f6d2f"
	$dlit &= "6e6179756b692f51522d436f64652d67656e657261746f72236c6963656e7365293a4FD5$436f7079726967687420c2a9203"
	$dlit &= "23032302050726f6a656374204e6179756b692e20284d4954204c6963656e7365294FD5$68747470733a2f2f7777772e6e61"
	$dlit &= "79756b692e696f2f706167652f71722d636f64652d67656e657261746f722d6c6962726172794FD5$5065726d697373696f6"
	$dlit &= "e20697320686572656279206772616e7465642c2066726565206f66206368617267652c20746f20616e7920706572736f6e2"
	$dlit &= "06f627461696e696e67206120636f7079206f66207468697320736f66747761726520616e64206173736f636961746564206"
	$dlit &= "46f63756d656e746174696f6e2066696c6573202874686520536f667477617265292c20746f206465616c20696e207468652"
	$dlit &= "0536f66747761726520776974686f7574207265737472696374696f6e2c20696e636c7564696e6720776974686f7574206c6"
	$dlit &= "96d69746174696f6e207468652072696768747320746f207573652c20636f70792c206d6f646966792c206d657267652c207"
	$dlit &= "075626c6973682c20646973747269627574652c207375626c6963656e73652c20616e642f6f722073656c6c20636f7069657"
	$dlit &= "3206f662074686520536f6674776172652c20616e6420746f207065726d697420706572736f6e7320746f2077686f6d20746"
	$dlit &= "86520536f667477617265206973206675726e697368656420746f20646f20736f2c207375626a65637420746f20746865206"
	$dlit &= "66f6c6c6f77696e6720636f6e646974696f6e733a4FD5$312e205468652061626f766520636f70797269676874206e6f7469"
	$dlit &= "636520616e642074686973207065726d697373696f6e206e6f74696365207368616c6c20626520696e636c7564656420696e"
	$dlit &= "20616c6c20636f70696573206f72207375627374616e7469616c20706f7274696f6e73206f662074686520536f6674776172"
	$dlit &= "652e4FD5$322e2054686520536f6674776172652069732070726f76696465642061732069732c20776974686f75742077617"
	$dlit &= "272616e7479206f6620616e79206b696e642c2065787072657373206f7220696d706c6965642c20696e636c7564696e67206"
	$dlit &= "27574206e6f74206c696d6974656420746f207468652077617272616e74696573206f66206d65726368616e746162696c697"
	$dlit &= "4792c206669746e65737320666f72206120706172746963756c617220707572706f736520616e64206e6f6e696e6672696e6"
	$dlit &= "7656d656e742e20496e206e6f206576656e74207368616c6c2074686520617574686f7273206f7220636f707972696768742"
	$dlit &= "0686f6c64657273206265206c6961626c6520666f7220616e7920636c61696d2c2064616d61676573206f72206f746865722"
	$dlit &= "06c696162696c6974792c207768657468657220696e20616e20616374696f6e206f6620636f6e74726163742c20746f72742"
	$dlit &= "06f72206f74686572776973652c2061726973696e672066726f6d2c206f7574206f66206f7220696e20636f6e6e656374696"
	$dlit &= "f6e20776974682074686520536f667477617265206f722074686520757365206f72206f74686572206465616c696e6773206"
	$dlit &= "96e2074686520536f6674776172652e4FD5$7374727563743b7573686f72743b656e647374727563744FD5$7374727563743"
	$dlit &= "b627974653b627974653b627974653b656e647374727563744FD5$43726561746546696c654FD5$75696e744FD5$53657446"
	$dlit &= "696c65506f696e7465724FD5$6c6f6e674FD5$577269746546696c654FD5$7374727563743b64776f72643b656e647374727"
	$dlit &= "563744FD5$5265616446696c654FD5$436c6f736548616e646c654FD5$44656c65746546696c65414FD5$47657446696c655"
	$dlit &= "3697a65"
	Global $os = StringSplit($dlit, "4FD5$", 1)
EndFunc

Func arehdidxrgk($flqlnxgxbp)
	Local $flqlnxgxbp_
	For $flrctqryub = 1 To StringLen($flqlnxgxbp) Step 2
		$flqlnxgxbp_ &= Chr(Dec(StringMid($flqlnxgxbp, $flrctqryub, 2)))
	Next
	Return $flqlnxgxbp_
EndFunc
```

At a very high level, the script is taking the input provided to it and generating a QR code for that input. After a while of banging my head against the desk, I found the catch - it provides a QR code of the output unless some condition (unknown at this point) is met. Whatever this condition is takes place in the function I named `DecryptData()`

```
Func decryptData(ByRef $flodiutpuy)
	; Custom defined varaiables for readability
	Local $PROV_RSA_AES = 24
	Local $CRYPT_VERIFYCONTEXT = 4026531840
	Local $CALG_SHA_256 = 32780  ; SHA256

	Local $ComputerName = GetComputerName()
	If $ComputerName <> -1 Then
		$ComputerName = Binary(StringLower(BinaryToString($ComputerName)))
		Local $ComputerNameraw = DllStructCreate('struct;byte[' & BinaryLen($ComputerName) & '];endstruct')
		DllStructSetData($ComputerNameraw, 1, $ComputerName)
		obfuscateComputerName($ComputerNameraw)
		Local $flnttmjfea = DllStructCreate('struct;ptr;ptr;dword;byte[32];endstruct')
		DllStructSetData($flnttmjfea, 3, 32)
		Local $apiCallResult = DllCall('advapi32.dll', 'int', 'CryptAcquireContextA', 'ptr', DllStructGetPtr($flnttmjfea, 1), 'ptr', 0, 'ptr', 0, 'dword', $PROV_RSA_AES, 'dword', $CRYPT_VERIFYCONTEXT)
		If $apiCallResult[0] <> 0 Then
			$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptCreateHash', 'ptr', DllStructGetData($flnttmjfea, 1), 'dword', $CALG_SHA_256, 'dword', 0, 'dword', 0, 'ptr', DllStructGetPtr($flnttmjfea, 2))
			If $apiCallResult[0] <> 0 Then
				$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptHashData', 'ptr', DllStructGetData($flnttmjfea, 2), 'struct*', $ComputerNameraw, 'dword', DllStructGetSize($ComputerNameraw), 'dword', 0)
				If $apiCallResult[0] <> 0 Then
					$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptGetHashParam', 'ptr', DllStructGetData($flnttmjfea, 2), 'dword', 2, 'ptr', DllStructGetPtr($flnttmjfea, 4), 'ptr', DllStructGetPtr($flnttmjfea, 3), 'dword', 0)
					If $apiCallResult[0] <> 0 Then
						; The encoded computer name is hashed with SHA256 and placed in DllStructGetData($flnttmjfea, 4) up above
						Local $key = Binary('0x' & '08020' & '00010' & '66000' & '02000' & '0000') & DllStructGetData($flnttmjfea, 4)
						Local $encryptedData = Binary('0x' & 'CD4B3' & '2C650' & 'CF21B' & 'DA184' & 'D8913' & 'E6F92' & '0A37A' & '4F396' & '3736C' & '042C4' & '59EA0' & '7B79E' & 'A443F' & 'FD189' & '8BAE4' & '9B115' & 'F6CB1' & 'E2A7C' & '1AB3C' & '4C256' & '12A51' & '9035F' & '18FB3' & 'B1752' & '8B3AE' & 'CAF3D' & '480E9' & '8BF8A' & '635DA' & 'F974E' & '00135' & '35D23' & '1E4B7' & '5B2C3' & '8B804' & 'C7AE4' & 'D266A' & '37B36' & 'F2C55' & '5BF3A' & '9EA6A' & '58BC8' & 'F906C' & 'C665E' & 'AE2CE' & '60F2C' & 'DE38F' & 'D3026' & '9CC4C' & 'E5BB0' & '90472' & 'FF9BD' & '26F91' & '19B8C' & '484FE' & '69EB9' & '34F43' & 'FEEDE' & 'DCEBA' & '79146' & '0819F' & 'B21F1' & '0F832' & 'B2A5D' & '4D772' & 'DB12C' & '3BED9' & '47F6F' & '706AE' & '4411A' & '52')
						Local $newCryptStructHolder = DllStructCreate('struct;ptr;ptr;dword;byte[8192];byte[' & BinaryLen($key) & '];dword;endstruct')
						DllStructSetData($newCryptStructHolder, 3, BinaryLen($encryptedData))
						DllStructSetData($newCryptStructHolder, 4, $encryptedData)
						DllStructSetData($newCryptStructHolder, 5, $key)
						DllStructSetData($newCryptStructHolder, 6, BinaryLen($key))
						Local $apiCallResult = DllCall('advapi32.dll', 'int', 'CryptAcquireContextA', 'ptr', DllStructGetPtr($newCryptStructHolder, 1), 'ptr', 0, 'ptr', 0, 'dword', $PROV_RSA_AES, 'dword', $CRYPT_VERIFYCONTEXT)
						If $apiCallResult[0] <> 0 Then
							$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptImportKey', 'ptr', DllStructGetData($newCryptStructHolder, 1), 'ptr', DllStructGetPtr($newCryptStructHolder, 5), 'dword', DllStructGetData($newCryptStructHolder, 6), 'dword', 0, 'dword', 0, 'ptr', DllStructGetPtr($newCryptStructHolder, 2))
							If $apiCallResult[0] <> 0 Then
								$apiCallResult = DllCall('advapi32.dll', 'int', 'CryptDecrypt', 'ptr', DllStructGetData($newCryptStructHolder, 2), 'dword', 0, 'dword', 1, 'dword', 0, 'ptr', DllStructGetPtr($newCryptStructHolder, 4), 'ptr', DllStructGetPtr($newCryptStructHolder, 3))
								If $apiCallResult[0] <> 0 Then
									; DllStructGetData($newCryptStructHolder, 4) contains the decrypted data
									; DllStructGetData($newCryptStructHolder, 3) contains the size of the decrypted data
									Local $decryptedData = BinaryMid(DllStructGetData($newCryptStructHolder, 4), 1, DllStructGetData($newCryptStructHolder, 3))
									$flare = Binary('FLARE')
									$flareButBackwards = Binary('ERALF')
									$flareFromDecryption = BinaryMid($decryptedData, 1, BinaryLen($flare))
									$BackwardsFlareFromDecryption = BinaryMid($decryptedData, BinaryLen($decryptedData) - BinaryLen($flareButBackwards) + 1, BinaryLen($flareButBackwards))
									If $flare = $flareFromDecryption AND $flareButBackwards = $BackwardsFlareFromDecryption Then
										DllStructSetData($flodiutpuy, 1, BinaryMid($decryptedData, 6, 4))
										DllStructSetData($flodiutpuy, 2, BinaryMid($decryptedData, 10, 4))
										DllStructSetData($flodiutpuy, 3, BinaryMid($decryptedData, 14, BinaryLen($decryptedData) - 18))
									EndIf
								EndIf
								DllCall('advapi32.dll', 'int', 'CryptDestroyKey', 'ptr', DllStructGetData($newCryptStructHolder, 2))
							EndIf
							DllCall('advapi32.dll', 'int', 'CryptReleaseContext', 'ptr', DllStructGetData($newCryptStructHolder, 1), 'dword', 0)
						EndIf
					EndIf
				EndIf
				DllCall('advapi32.dll', 'int', 'CryptDestroyHash', 'ptr', DllStructGetData($flnttmjfea, 2))
			EndIf
			DllCall('advapi32.dll', 'int', 'CryptReleaseContext', 'ptr', DllStructGetData($flnttmjfea, 1), 'dword', 0)
		EndIf
	EndIf
EndFunc
```

Specifically, the sole parameter to this function is passed in by reference and isn't altered unless we're able to successfully create the decryption parameters by providing the correct response from the WinAPI function `GetComputerNameA()`. Maybe the criteria for setting the computer name is strict enough that we can brute force the correct computer name? Wikipedia has some good info on the (NetBIOS naming standards)[https://en.wikipedia.org/wiki/NetBIOS#NetBIOS_name]. In short, they are 15 alphanumeric characters. There are a couple other constraints but this alone tells us it's feasibly uncrackable unless we're able to outlive the collapse of the universe. Let's look for another way to solve this.

After circling back to the "banging my head on the desk" portion of this challenge (which worked out well for me last time), I figured the answer to this challenge must be in the function I named `ObfuscateComputerName()`. The input to `decryptData()` (which is the user input to generate the QR code) is passed by reference and isn't changed unless the decryption routine is a success. The only way the decryption routine is a success is if we have the correct computer name. Because the answer to this challenge likely isn't brute forcing the computer name, `obfuscateComputerName()` (which I later learned is a terrible name for the function) should give us the flag.

```
Func obfuscateComputerName(ByRef $ComputerName)  ; Encodes the data in the struct passed in
	Local $bmpFileName = InstallBmpOrDll(14)
	Local $hBmpFile = OpenFileForRead($bmpFileName)
	If $hBmpFile <> -1 Then
		Local $fileSize = GetFileSize($hBmpFile)
		If $fileSize <> -1 AND DllStructGetSize($ComputerName) < $fileSize - 54 Then
			Local $byteArrayFileSizeStruct = DllStructCreate('struct;byte[' & $fileSize & '];endstruct')
			Local $readResult = ReadAFile($hBmpFile, $byteArrayFileSizeStruct)
			If $readResult <> -1 Then
				Local $flxmdchrqd = DllStructCreate('struct;byte[54];byte[' & $fileSize - 54 & '];endstruct', DllStructGetPtr($byteArrayFileSizeStruct))
				Local $index = 1
				Local $obfuscated = ''
				For $counter = 1 To DllStructGetSize($ComputerName)
					Local $charCode = Number(DllStructGetData($ComputerName, 1, $counter))
					For $subCounter = 6 To 0 Step -1
						$charCode += BitShift(BitAND(Number(DllStructGetData($flxmdchrqd, 2, $index)), 1), -1 * $subCounter)
						$index += 1
					Next
					$obfuscated &= Chr(BitShift($charCode, 1) + BitShift(BitAND($charCode, 1), -7))
				Next
				DllStructSetData($ComputerName, 1, $obfuscated)
			EndIf
		EndIf
		CloseAHandle($hBmpFile)
	EndIf
	DeleteAFile($bmpFileName)
EndFunc
```

Taken straight from my inline notes, `InstallBmpOrDll()` installs sprite.bmp or qr_encoder.dll (using the AutoIt function [`FileInstall()`](https://autoitscript.com/autoit3/docs/functions/FileInstall.htm)) with a random filename into the script directory and returns the name of the installed file. The determining factor for whether it will install the bmp or the dll is the parameter passed in. The TLDR on `FileInstall()` from the docs is that it's essentially a way to include a file in the compiled version of your autoit binary. When the autoit script is compiled with a `FileInstall()` function call, it saves the file in the compiled binary. Then, during execution of the binary, it will extract the file from the binary for use. So the first part of this script extracts and reads the bmp file. Let's see what the file contains - our handy exe2Aut.exe tool already extracted the bmp file for us.

![6.4.jpg](/assets/images/06CodeIt/6.4.jpg)

The bmp file was our happy little Flare-on character! Back to `obfuscateComputerName()`, we can see the file is read, stored in a struct called $byteArrayFileSizeStruct, then a new struct is created called `$flxmdchrqd` that contains the data from the file in two seperate byte array pointers. The first pointer contains the first 54 bytes of the file and the second pointer contains the rest of the data. The loop right below this only references the second pointer so we're only dealing with the 54th byte of data onward. Digging a bit into the loop, the subloop there sets some sort of char code based on the following formula:

`char_code += (bmp_file_data_starting_at_the_54th_byte[index] BinaryAND 1) BitShift left (-1 * SubCounter)`

In English, if the byte read from the file is odd, a one will be shifted X positions to the left and added to char code, where X is the value of `SubCounter`. If the byte read from the file is event, a zero will be shifted X positions to the left and added to char code, where X is the value of `SubCounter`. The SubCounter loop goes from 6 to 0 for a total of 7 iterations, then repeats until we've reached the length of the computer name. Let's simulate the first iteration of this subloop using the inputs from the .bmp file with some pseudocode:

```
char_code = 0
char_code += (0x255 AND 1) << 6  // 64
char_code += (0x255 AND 1) << 5  // 32
char_code += (0x254 AND 1) << 4  //  0
char_code += (0x254 AND 1) << 3  //  0
char_code += (0x254 AND 1) << 2  //  0
char_code += (0x254 AND 1) << 1  //  0
char_code += (0x255 AND 1) << 0  //  1
```

Our char code is 97 or 'a'. If we continue this process until we reach the big block of `0xFF`s, we get the following:

```
FF FF FE FE FE FE FF = 1100001 = a
FF FF FF FE FF FE FF = 1110101 = u
FF FF FF FE FF FE FE = 1110100 = t
FE FF FF FE FE FE FE = 0110000 = 0
FE FF FF FE FE FE FF = 0110001 = 1
FF FF FF FE FF FE FE = 1110100 = t
FF FF FE FE FF FF FE = 1100110 = f
FF FF FE FE FE FE FF = 1100001 = a
FF FF FE FF FF FF FE = 1101110 = n
FE FF FF FE FE FE FF = 0110001 = 1
FE FF FF FF FE FE FF = 0111001 = 9
FE FF FF FF FE FE FF = 0111001 = 9
FE FF FF FF FE FE FF = 0111001 = 9
```

If we replace the call to `GetComputerName()` with:
```
Func GetComputerName() 
	Return BinaryMid('aut01tfan1999', 1, StringLen('aut01tfan1999'))
EndFunc
```

Then, we can re-run the script (note that this newly saved script needs to have the extract qr_encoder.dll and sprite.bmp files in the same directory), enter arbitrary input (because the output is alerted if the computer name is correct), and we get the following QR code:

![6.5.jpg](/assets/images/06CodeIt/6.5.jpg)

This is our flag!! Simply find a QR code reader (I learned that the Pixel has one built into the camera app. Neat.) to reveal the flag.

Flag: `L00ks_L1k3_Y0u_D1dnt_Run_Aut0_Tim3_0n_Th1s_0ne!@flare-on.com`

{% for post in site.posts -%}
 {% if post.title contains "Flare-On 2020 Challenges" %}
   [Click here]({{- post.url  -}}) to return to the Flare-On 2020 overview page.
 {% endif %}
{%- endfor %}
