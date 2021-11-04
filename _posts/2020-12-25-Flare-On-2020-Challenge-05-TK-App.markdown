---
title: "Flare-On 2020: 05 - TKApp"
date: 2020-12-25 00:05:00
header:
  image: /assets/images/05TKApp/header.png
  teaser: /assets/images/05TKApp/header.png
  caption: "[credit](https://licc.org.uk/app/uploads/2020/05/Tiger-King-Web-MJ-Edit-700x540.png)"
tags: [reversing, ctf, flareon, csharp]
---
# Challenge 5 - TKApp

> Now you can play Flare-On on your watch! As long as you still have an arm left to put a watch on, or emulate the watch's operating system with sophisticated developer tools.

Ok, all we're given for this challenge is a .tpk file. A quick search in Google tells us this is related to smart watch software. A hex editor (and [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)) tells us that this is simply a ZIP file given the file magic of `50 4b 03 04`. Our zip extraction with 7zip reveals a bunch of files, the most interesting of which (given the name) is TKApp/bin/TKApp.dll

Let's try to get some information about this binary by using [PEiD](https://www.aldeid.com/wiki/PEiD)

![5.1.jpg](/assets/images/05TKApp/5.1.jpg)

PEiD tells us that this dll was written in C#. This means we can throw it into [ILSpy](https://github.com/icsharpcode/ILSpy) and have it decompile it for us!

After searching around for a while, learning the interface, and understanding the code, the function `GetImage()` seems of interest.

```csharp
private bool GetImage(object sender, EventArgs e)
{
	if (string.IsNullOrEmpty(App.Password) || string.IsNullOrEmpty(App.Note) || string.IsNullOrEmpty(App.Step) || string.IsNullOrEmpty(App.Desc))
	{
		btn.Source = "img/tiger1.png";
		btn.Clicked -= Clicked;
		return false;
	}
	string text = new string(new char[45]
	{
		App.Desc[2],
		App.Password[6],
		App.Password[4],
		App.Note[4],
		App.Note[0],
		App.Note[17],
		App.Note[18],
		App.Note[16],
		App.Note[11],
		App.Note[13],
		App.Note[12],
		App.Note[15],
		App.Step[4],
		App.Password[6],
		App.Desc[1],
		App.Password[2],
		App.Password[2],
		App.Password[4],
		App.Note[18],
		App.Step[2],
		App.Password[4],
		App.Note[5],
		App.Note[4],
		App.Desc[0],
		App.Desc[3],
		App.Note[15],
		App.Note[8],
		App.Desc[4],
		App.Desc[3],
		App.Note[4],
		App.Step[2],
		App.Note[13],
		App.Note[18],
		App.Note[18],
		App.Note[8],
		App.Note[4],
		App.Password[0],
		App.Password[7],
		App.Note[0],
		App.Password[4],
		App.Note[11],
		App.Password[6],
		App.Password[4],
		App.Desc[4],
		App.Desc[3]
	});
	byte[] key = SHA256.Create().ComputeHash(Encoding.get_ASCII().GetBytes(text));
	byte[] bytes = Encoding.get_ASCII().GetBytes("NoSaltOfTheEarth");
	try
	{
		App.ImgData = Convert.FromBase64String(Util.GetString(Runtime.Runtime_dll, key, bytes));
		return true;
	}
	catch (Exception ex)
	{
		Toast.DisplayText("Failed: " + ex.Message, 1000);
	}
	return false;
}
```

To create the image, we'll need to find out how `App.Desc`, `App.Password`, `App.Step`, and `App.Note` are generated

## App.Desc
For each of these variables, the process will be fairly similar. ILSpy provides us with an "Analyze" function that can track where a particular variable is used or set.

![5.2.jpg](/assets/images/05TKApp/5.2.jpg)

In the case of the Desc variable, let's follow this to `IndexPage_CurrentPageChanged()`.

```csharp
private void IndexPage_CurrentPageChanged(object sender, EventArgs e)
{
	if (base.Children.IndexOf(base.CurrentPage) == 4)
	{
		using (ExifReader exifReader = new ExifReader(Path.Combine(Application.get_Current().get_DirectoryInfo().get_Resource(), "gallery", "05.jpg")))
		{
			if (exifReader.GetTagValue(ExifTags.ImageDescription, out string result))
			{
				App.Desc = result;
			}
		}
	}
	else
	{
		App.Desc = "";
	}
}
```

Looks like this function reads the ImageDescription tag on the image TKApp/res/gallery/05.jpg and stores the result in Desc. In less than a minute, we have our first variable assigned a value: "water"

![5.3.jpg](/assets/images/05TKApp/5.3.jpg)

## App.Password

![5.4.jpg](/assets/images/05TKApp/5.4.jpg)

We see password is set in `OnLoginButtonClicked()`. Below is that function:
```csharp
private async void OnLoginButtonClicked(object sender, EventArgs e)
{
	if (IsPasswordCorrect(passwordEntry.Text))
	{
		App.IsLoggedIn = true;
		App.Password = passwordEntry.Text;
		base.Navigation.InsertPageBefore(new MainPage(), this);
		await base.Navigation.PopAsync();
	}
	else
	{
		Toast.DisplayText("Unlock failed!", 2000);
		passwordEntry.Text = string.Empty;
	}
}
```

`IsPasswordCorrect()` returns true if the input matches `Util.Decode(TKData.Password)`. `TKData.Password` is statically set to a byte array and `Util.Decode()` simply XORs each byte with a key of `0x53`. We can use [CyberChef](https://gchq.github.io/CyberChef/) to extract the expected password of "mullethat"

![5.5.jpg](/assets/images/05TKApp/5.5.jpg)

## App.Step

![5.6.jpg](/assets/images/05TKApp/5.6.jpg)

Step is set in `PedDataUpdate()`. The following snippet of the function shows how it's set:
```csharp
if (e.get_StepCount() > 50 && string.IsNullOrEmpty(App.Step))
{
	App.Step = Application.get_Current().get_ApplicationInfo().get_Metadata()["its"];
}
```
After searching for a while, the metadata can be found in tizen-manifest.xml in the root of the TKApp directory. The value of the key of "its" is "magic"

![5.7.jpg](/assets/images/05TKApp/5.7.jpg)

## App.Note

![5.8.jpg](/assets/images/05TKApp/5.8.jpg)

ILSpy tells us that Note is set in `SetupList()`
```csharp
private void SetupList()
{
	List<Todo> list = new List<Todo>();
	if (!isHome)
	{
		list.Add(new Todo("go home", "and enable GPS", Done: false));
	}
	else
	{
		Todo[] collection = new Todo[5]
		{
			new Todo("hang out in tiger cage", "and survive", Done: true),
			new Todo("unload Walmart truck", "keep steaks for dinner", Done: false),
			new Todo("yell at staff", "maybe fire someone", Done: false),
			new Todo("say no to drugs", "unless it's a drinking day", Done: false),
			new Todo("listen to some tunes", "https://youtu.be/kTmZnQOfAF8", Done: true)
		};
		list.AddRange(collection);
	}
	List<Todo> list2 = new List<Todo>();
	foreach (Todo item in list)
	{
		if (!item.Done)
		{
			list2.Add(item);
		}
	}
	mylist.ItemsSource = list2;
	App.Note = list2[0].Note;
}
```

Reading through the code, Note ends up being set to the second string of the second Todo object in the list: "keep steaks for dinner"

## Wrapping it all up

Now that we've finished our side quests, we return to `GetImage()`. Using the strings we obtained in the last 4 sections, the `text` variable ends up being "the kind of challenges we are gonna make here", our `key` is the SHA256 hash of `text` (`248E9D7323A1A3C5D5B3283DCB2B40211A14415B6DCD2A86181721FD74B4BEFD`) and our `bytes` (IV) is `4e 6f 53 61 6c 74 4f 66 54 68 65 45 61 72 74 68` (or "NoSaltOfTheEarth"). These variables are passed to `GetString()`, which simply AES decrypts data with a key and an initialization vector - `key` is the key and `bytes` is the IV. The ciphertext is obtained from Runtime.Runtime_dll. After searching for a bit in ILSpy, I found Runtime.Runtime_dll file here:

![5.9.jpg](/assets/images/05TKApp/5.9.jpg)

We can right click --> save code on this item in ILSpy, upload it to CyberChef's input and use CyberChef's AES decrypt routine, along with the key and IV we found previously, CyberChef gives us a suggestion to use FromBase64 and RenderImage on the result which gives us the flag:

![5.10.jpg](/assets/images/05TKApp/5.10.jpg)

Flag: `n3ver_go1ng_to_recov3r@flare-on.com`

## Side note
If you reverse The `Init()` function, the Latitude and Longitude are set to [34.6252, -97.2117](https://www.google.com/maps/place/34%C2%B037'30.7%22N+97%C2%B012'42.1%22W/@34.6252044,-97.2138887,17z/data=!3m1!4b1!4m5!3m4!1s0x0:0x0!8m2!3d34.6252!4d-97.2117) based off of the coordinates embedded in the metadata of res/gallery/04.jpg. I haven't seen Tiger King, but my guess is that this the location of the park owned by Joe Exotic in the show.

{% for post in site.posts -%}
 {% if post.title contains "Flare-On 2020 Challenges" %}
   [Click here]({{- post.url  -}}) to return to the Flare-On 2020 overview page.
 {% endif %}
{%- endfor %}
