$psloadedrunas = $null
function Invoke-Runas {
<#
.SYNOPSIS
    Overview:
    
    if running as Standard user - Args MAX Length is 1024 characters
    using Advapi32::CreateProcessWithLogonW

    if running as SYSTEM user - Args MAX Length is 32k characters
    Advapi32::LogonUser, Advapi32::DuplicateTokenEx, CreateProcessAsUser 
        
    Parameters:

     -User              Specifiy username.
  
     -Password          Specify password.
     
     -Domain            Specify domain. Defaults to localhost if not specified.
     
     -Command           Full path of the module to be executed.

     -Args              Args to be executed, must start with a space, e.g. " /c calc.exe" Size can vary depending on the user

    # https://www.pinvoke.net/default.aspx/advapi32.logonuser

    LogonType Background Information:

    This logon type is intended for users who will be interactively using the computer, such as a user being logged on by a terminal server, remote shell, or similar process. This logon type has the additional expense of caching logon information for disconnected operations therefore, it is inappropriate for some client/server applications, such as a mail server.

    - LOGON32_LOGON_INTERACTIVE = 2

    This logon type is intended for high performance servers to authenticate plaintext passwords. The LogonUser function does not cache credentials for this logon type.

    - LOGON32_LOGON_NETWORK = 3

    This logon type is intended for batch servers, where processes may be executing on behalf of a user without their direct intervention. This type is also for higher performance servers that process many plaintext authentication attempts at a time, such as mail or Web servers. The LogonUser function does not cache credentials for this logon type.

    - LOGON32_LOGON_BATCH = 4

    Indicates a service-type logon. The account provided must have the service privilege enabled.
    
    - LOGON32_LOGON_SERVICE = 5

    This logon type is for GINA DLLs that log on users who will be interactively using the computer. This logon type can generate a unique audit record that shows when the workstation was unlocked.
    
    - LOGON32_LOGON_UNLOCK = 7

    This logon type preserves the name and password in the authentication package, which allows the server to make connections to other network servers while impersonating the client. A server can accept plaintext credentials from a client, call LogonUser, verify that the user can access the system across the network, and still communicate with other servers. NOTE: Windows NT:  This value is not supported.

    - LOGON32_LOGON_NETWORK_CLEARTEXT = 8

    This logon type allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identifier but uses different credentials for other network connections. NOTE: This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider. NOTE: Windows NT:  This value is not supported.
    
    - LOGON32_LOGON_NEW_CREDENTIALS = 9
    
    LogonProvider Background Information
    
    Use the standard logon provider for the system. The default security provider is negotiate, unless you pass NULL for the domain name and the user name is not in UPN format. In this case, the default provider is NTLM. NOTE: Windows 2000/NT:   The default security provider is NTLM.

    - LOGON32_PROVIDER_DEFAULT = 0

    - LOGON32_PROVIDER_WINNT35 = 1

    - LOGON32_PROVIDER_WINNT40 = 2
    
    - LOGON32_PROVIDER_WINNT50 = 3

.EXAMPLE
    Invoke-Runas -User Ted -Password Password1 -Domain MYDOMAIN -Command C:\Temp\Runme.exe                   

.EXAMPLE
    Invoke-Runas -User Ted -Password Password1 -Domain MYDOMAIN -Command C:\Windows\system32\WindowsPowershell\v1.0\powershell.exe -Args " -exec bypass -e Tjsksdsadsa"    

.DESCRIPTION
    Author: Ben Turner (@benpturner)
    License: BSD 3-Clause
#>

    param (
        [Parameter(Mandatory = $True)]
        [string]$User,
        [Parameter(Mandatory = $True)]
        [string]$Password,
        [Parameter(Mandatory = $False)]
        [string]$Domain=".",
        [Parameter(Mandatory = $True)]
        [string]$Command,
        [Parameter(Mandatory = $False)]
        [string]$Args,
        [Parameter(Mandatory=$False)]
        [switch]$AddType
    )

if ($AddType.IsPresent) {

echo "[+] Loading Assembly using AddType"
echo ""

        Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Security.Principal;

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
        
    public enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public class AdjPriv
    {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }
  
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            if(disable)
            {
                tp.Attr = SE_PRIVILEGE_DISABLED;
            }
            else
            {
                tp.Attr = SE_PRIVILEGE_ENABLED;
            }
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }

    public static class Advapi32
    {

        [DllImport("advapi32.dll", CharSet=CharSet.Auto)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            int ImpersonationLevel,
            int TokenType,
            ref IntPtr phNewToken);
            
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(
            string pszUsername, 
            string pszDomain, 
            string pszPassword,
            int dwLogonType, 
            int dwLogonProvider, 
            ref IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken, 
            string lpApplicationName,
            string lpCommandLine, 
            ref SECURITY_ATTRIBUTES lpProcessAttributes, 
            ref SECURITY_ATTRIBUTES lpThreadAttributes, 
            bool bInheritHandle, 
            Int32 dwCreationFlags, 
            IntPtr lpEnvrionment,
            string lpCurrentDirectory, 
            ref STARTUPINFO lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation);


        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            int logonFlags,
            String applicationName,
            String commandLine,
            int creationFlags,
            int environment,
            String currentDirectory,
            ref  STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);
    }
    
    public static class Kernel32
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();
    }
"@  

} else {
    if ($psloadedrunas -ne "TRUE") {
       $script:psloadedrunas = "TRUE"
        echo "[+] Loading Assembly using System.Reflection"
        echo ""
       $ps = "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CwB5BAkAIgUBABEAIgUGABkAIgUKACkAIgUQADEAIgUQADkAIgUQAEEAIgUQAEkAIgUQAFEAIgUQAFkAIgUQAGEAIgUVAGkAIgUQAHEAIgUQAJEAIgUgAJEAzgQlAIkAIgUGAAgAFAAxAAgAGAA2AAgAHAA7AAgAIABAAAgAfAA7AAgAgAAxAAgAhABFAAgAiABKAC4ACwDOAC4AEwDXAC4AGwD2AC4AIwD/AC4AKwAMAS4AMwAMAS4AOwAMAS4AQwD/AC4ASwASAS4AUwAMAS4AWwAMAS4AYwAqAS4AawBUAQEAAAAAAAkAGgC+A8sDQQEDAKoFAQBBAQUABwQBAEABBwByAwEABgENANEGAQBAAQ8A7QQBAEIDEQD3BAEARAETAMgAAQAAARUAFQUCAASAAAABAAAAAAAAAAAAAAAAAL0GAAACAAAAAAAAAAAAAAAoAP8AAAAAAAkABgAAAABBZHZhcGkzMgBLZXJuZWwzMgBjYlJlc2VydmVkMgBscFJlc2VydmVkMgA8TW9kdWxlPgBTRV9QUklWSUxFR0VfRU5BQkxFRABTRV9QUklWSUxFR0VfRElTQUJMRUQAU0VDVVJJVFlfSU1QRVJTT05BVElPTl9MRVZFTABQUk9DRVNTX0lORk9STUFUSU9OAFNUQVJUVVBJTkZPAFRPS0VOX0FESlVTVF9QUklWSUxFR0VTAFNFQ1VSSVRZX0FUVFJJQlVURVMAQ3JlYXRlUHJvY2Vzc1dpdGhMb2dvblcAZHdYAFRPS0VOX1FVRVJZAGR3WQB2YWx1ZV9fAGNiAG1zY29ybGliAGFjYwBkd1RocmVhZElkAGR3UHJvY2Vzc0lkAGhUaHJlYWQAbHBSZXNlcnZlZABUb2tQcml2MUx1aWQAcGx1aWQAcHN6UGFzc3dvcmQAcGFzc3dvcmQARW5hYmxlUHJpdmlsZWdlAHByaXZpbGVnZQBkaXNhYmxlAHByb2Nlc3NIYW5kbGUAYkluaGVyaXRIYW5kbGUAbHBUaXRsZQBscEFwcGxpY2F0aW9uTmFtZQBhcHBsaWNhdGlvbk5hbWUAdXNlck5hbWUAcHN6VXNlcm5hbWUAbHBDb21tYW5kTGluZQBjb21tYW5kTGluZQBWYWx1ZVR5cGUAVG9rZW5UeXBlAGR3TG9nb25UeXBlAEd1aWRBdHRyaWJ1dGUARGVidWdnYWJsZUF0dHJpYnV0ZQBDb21WaXNpYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAZHdGaWxsQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAExvb2t1cFByaXZpbGVnZVZhbHVlAGR3WFNpemUAZHdZU2l6ZQBMZW5ndGgAcGh0b2sASW1wZXJzb25hdGlvbkxldmVsAGRpc2FsbABhZHZhcGkzMi5kbGwAa2VybmVsMzIuZGxsAEFkalByaXYuZGxsAFN5c3RlbQBFbnVtAGhFeGlzdGluZ1Rva2VuAHBoVG9rZW4AT3BlblByb2Nlc3NUb2tlbgBwaE5ld1Rva2VuAHJlbGVuAHBzekRvbWFpbgBkb21haW4AU2VjdXJpdHlJZGVudGlmaWNhdGlvbgBTZWN1cml0eURlbGVnYXRpb24AbHBQcm9jZXNzSW5mb3JtYXRpb24AcHJvY2Vzc0luZm9ybWF0aW9uAFNlY3VyaXR5SW1wZXJzb25hdGlvbgBTeXN0ZW0uUmVmbGVjdGlvbgBscFN0YXJ0dXBJbmZvAHN0YXJ0dXBJbmZvAFplcm8AbHBEZXNrdG9wAGR3TG9nb25Qcm92aWRlcgBMb2dvblVzZXIAQ3JlYXRlUHJvY2Vzc0FzVXNlcgBoU3RkRXJyb3IAR2V0TGFzdEVycm9yAC5jdG9yAGxwU2VjdXJpdHlEZXNjcmlwdG9yAEludFB0cgBBdHRyAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBBZGp1c3RUb2tlblByaXZpbGVnZXMAbHBUaHJlYWRBdHRyaWJ1dGVzAGxwVG9rZW5BdHRyaWJ1dGVzAGxwUHJvY2Vzc0F0dHJpYnV0ZXMAbG9nb25GbGFncwBkd0NyZWF0aW9uRmxhZ3MAY3JlYXRpb25GbGFncwBkd0ZsYWdzAGR3WENvdW50Q2hhcnMAZHdZQ291bnRDaGFycwBkd0Rlc2lyZWRBY2Nlc3MAaFByb2Nlc3MAU2VjdXJpdHlBbm9ueW1vdXMAT2JqZWN0AGxwRW52cmlvbm1lbnQAZW52aXJvbm1lbnQAQ291bnQAaG9zdABuZXdzdABoU3RkSW5wdXQAaFN0ZE91dHB1dABwcmV2AEFkalByaXYAd1Nob3dXaW5kb3cARHVwbGljYXRlVG9rZW5FeABscEN1cnJlbnREaXJlY3RvcnkAY3VycmVudERpcmVjdG9yeQAAAAAAAACWZGjNb64yTZfnFNQeWEO1AAQgAQEIAyAAAQUgAQEREQQgAQEOBCABAQIFBwIRJBgEIAEBCgIGGAi3elxWGTTgiQQAAAAABAEAAAAEAgAAAAQDAAAABAgAAAAEIAAAAAIGCAIGAgMGEQwCBgkCBg4CBgYCBgoLAAYCGAIQESQIGBgHAAMCGAgQGAcAAwIODhAKBgADAgoOAgwABgIYCRARCAgIEBgKAAYCDg4OCAgQGBYACwIYDg4QEQgQEQgCCBgOEBEUEBEQEgALAg4ODggODggIDhARFBAREAMAAAkIAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEAAgAAAAAADAEAB0FkalByaXYAAAUBAAAAABcBABJDb3B5cmlnaHQgwqkgIDIwMTgAACkBACRkMmYwMzc0OS0wODNiLTQ1NDctODM1MC0zOTcxZmRkMGVjNzMAAAwBAAcxLjAuMC4wAAAAAAAAAAAAX8VgWgAAAAACAAAAHAEAAAQvAAAEEQAAUlNEU50IyNt/egRPrTqvLNKC4xcBAAAAQzpcVXNlcnNcYWRtaW5cc291cmNlXHJlcG9zXEFkalByaXZcQWRqUHJpdlxvYmpcUmVsZWFzZVxBZGpQcml2LnBkYgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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"    
       $dllbytes  = [System.Convert]::FromBase64String($ps)
       $assembly = [System.Reflection.Assembly]::Load($dllbytes)
    }
}
    if (($env:username -eq "$($env:computername)$")) {
        echo "User is `"NT Authority\SYSTEM`" so running LogonUser -> DuplicateTokenEx -> CreateProcessAsUser"
        # EnablePrivs from http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        $processHandle = (Get-Process -id $pid).Handle
        echo "`n[>] Enable SeAssignPrimaryTokenPrivilege Privilege:"
        $privs = [AdjPriv]::EnablePrivilege($processHandle, "SeAssignPrimaryTokenPrivilege", $Disable) 
        echo "==> $($privs)"
        
        $LogonTokenHandle = [IntPtr]::Zero

        echo "`n[>] Calling Advapi32::LogonUser with LOGON type 0x2"
        $CallResult1 = [Advapi32]::LogonUser($User, $Domain, $Password, 2, 0, [ref] $LogonTokenHandle)
        echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)"

        if (!$CallResult1) {
            echo "[!] Failed, Advapi32::LogonUser with LOGON type 0x2"
            echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)"
            echo "`n[>] Calling Advapi32::LogonUser with LOGON type 0x9 (netonly)"
            $CallResult1 = [Advapi32]::LogonUser($User, $Domain, $Password, 9, 3, [ref] $LogonTokenHandle)
            if (!$CallResult1) {
                echo "[!] Failed, Advapi32::LogonUser with LOGON type 0x9 (netonly)"
                echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)"
            } else {
                echo "`n[+] Success, LogonTokenHandle: "
                echo "==> $($LogonTokenHandle)"
            }            
        } else {
            echo "`n[+] Success, LogonTokenHandle: "
            echo "==> $($LogonTokenHandle)"
        }

        $SecImpersonation = New-Object SECURITY_IMPERSONATION_LEVEL
        $SECURITY_ATTRIBUTES = New-Object SECURITY_ATTRIBUTES
        $PrivLogonTokenHandle = [IntPtr]::Zero

        echo "`n[>] Calling Advapi32::DuplicateTokenEx"
        $CallResult2 = [Advapi32]::DuplicateTokenEx($LogonTokenHandle, 0x2000000, [ref] $SECURITY_ATTRIBUTES, 2, 1, [ref] $PrivLogonTokenHandle)
        echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)"

        if (!$CallResult2) {
            echo "[!] Failed, Advapi32::DuplicateTokenEx! GetLastError returned:"
            echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
        } else {
            echo "`n[+] Success, Duplicated LogonTokenHandle:"
            echo "==> $($PrivLogonTokenHandle)"
        }

        # StartupInfo Struct
        $StartupInfo = New-Object STARTUPINFO
        $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)    
        $StartupInfo.dwFlags = 0x00000001
        $StartupInfo.wShowWindow = 0x0001       

        # ProcessInfo Struct
        $ProcessInfo = New-Object PROCESS_INFORMATION
    
        $SecAttributes1 = New-Object SECURITY_ATTRIBUTES
        $SecAttributes2 = New-Object SECURITY_ATTRIBUTES
        $lpEnvrionment = [IntPtr]::Zero
        $CurrentDirectory = $Env:SystemRoot

        echo "`n[>] Calling Advapi32::CreateProcessAsUser"
        $CallResult3 = [Advapi32]::CreateProcessAsUser($PrivLogonTokenHandle, $command, $args, [ref] $SecAttributes1, [ref] $SecAttributes2, $false, 0, $lpEnvrionment, $CurrentDirectory, [ref]$StartupInfo, [ref]$ProcessInfo)
        echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)"
        
        if (!$CallResult3) {
            echo "[!] Failed, Advapi32::CreateProcessAsUser! GetLastError returned:"
            echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
        } else {
            echo "`n[+] Success, process details:"
            Get-Process -Id $ProcessInfo.dwProcessId
            echo "`n[+] Please note, this process will have a primary token assigned but the user displayed may be SYSTEM"
            echo "`n[+] Run Invoke-TokenManipulation to see the Token loaded"
        }
    } else {
        cd $Env:SystemRoot
        echo "User is `"$env:username`" so running CreateProcessWithLogonW"
        # Inspired from: https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-Runas.ps1
        # StartupInfo Struct
        $StartupInfo = New-Object STARTUPINFO
        $StartupInfo.dwFlags = 0x00000001
        $StartupInfo.wShowWindow = 0x0001
        $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
    
        # ProcessInfo Struct
        $ProcessInfo = New-Object PROCESS_INFORMATION
    
        # CreateProcessWithLogonW --> lpCurrentDirectory
        $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
    
        echo "`n[>] Calling Advapi32::CreateProcessWithLogonW"
        $CallResult = [Advapi32]::CreateProcessWithLogonW(
            $User, $Domain, $Password, 0x1, $Command,
            $Args, 0x04000000, $null, $GetCurrentPath,
            [ref]$StartupInfo, [ref]$ProcessInfo)
    
        if (!$CallResult) {
            echo "[!] Failed, Advapi32::CreateProcessWithLogonW! GetLastError returned:"
            echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
        } else {
            echo "`n[+] Success, process details:"
            Get-Process -Id $ProcessInfo.dwProcessId
        }
    } 
}
