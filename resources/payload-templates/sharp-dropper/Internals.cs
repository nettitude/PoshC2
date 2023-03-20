using System;
using System.Runtime.InteropServices;

internal static class Internals
{
    internal const int PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    internal static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetConsoleWindow();

    [DllImport("shell32.dll")]
    internal static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

    [DllImport("user32.dll")]
    internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void CallBack(
        [MarshalAs(UnmanagedType.LPWStr)] string appDomainName,
        [MarshalAs(UnmanagedType.LPArray)] byte[] data,
        int len,
        [MarshalAs(UnmanagedType.LPArray)] byte[] echoAssembly,
        int echoAssemblyLength,
        [MarshalAs(UnmanagedType.LPWStr)] string className,
        [MarshalAs(UnmanagedType.LPWStr)] string entryPoint,
        int argsLength,
        [MarshalAs(UnmanagedType.LPWStr)] string argsString,
        out int output,
        out IntPtr outputStringIntPtr);
}