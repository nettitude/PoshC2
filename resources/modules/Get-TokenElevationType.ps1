function Get-TokenElevationType {
<#
.SYNOPSYS
    This module uses a C# wrapper around a native API dll to determine the 
    token type of the current process, as well as the status of UAC.  
    Return values for the token type are:
        TokenElevationTypeDefault - Unprivileged token issued to standard 
            users, OR under certain conditions, to the default Administrator
            account when it is enabled and 'Admin approval mode for built-in 
            administrator account' is off.
        TokenElevationtypeLimited - Split token issued to a process from a 
            privileged user but running unprivileged.  
        TokenElevationTypeFull    - Usually indicates a split token with full 
            administrative rights.  

Function: Get-TokenElevationType  
Modifications: Jon Hickman (@0metasec)
Attributions: This code was adapted to purpose from code located at
  https://stackoverflow.com/questions/1220213/detect-if-running-as-administrator-with-or-without-elevated-privileges  
  contributed by https://stackoverflow.com/users/80566/steven
License: Modifications by Jon Hickman are MIT licensed  

.DESCRIPTION  

Running Get-TokenElevationType will return a value that exposes the 
TOKEN_ELEVATION_TYPE enum from the GetTokenInformation advapi32.dll call, 
as well as the status of UAC. If UAC is off, all tokens contain the full 
group membership and rights (no split tokens).  

#>


$assembly = @"
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class UacPoll
{
    private const string uacRegistryKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    private const string uacRegistryValue = "EnableLUA";

    private static uint STANDARD_RIGHTS_READ = 0x00020000;
    private static uint TOKEN_QUERY = 0x0008;
    private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
    }

    public enum TOKEN_ELEVATION_TYPE
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited
    }

    public static bool IsUacEnabled
    {
        get
        {
            RegistryKey uacKey = Registry.LocalMachine.OpenSubKey(uacRegistryKey, false);
            bool result = uacKey.GetValue(uacRegistryValue).Equals(1);
            return result;
        }
    }

    public static string IsProcessElevated()
    {
        if (IsUacEnabled)
            {
                IntPtr tokenHandle;
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_READ, out tokenHandle))
                {
                    throw new ApplicationException("Could not get process token.  Win32 Error Code: " + Marshal.GetLastWin32Error());
                }

                TOKEN_ELEVATION_TYPE elevationResult = TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault;

                int elevationResultSize = Marshal.SizeOf((int)elevationResult);
                uint returnedSize = 0;
                IntPtr elevationTypePtr = Marshal.AllocHGlobal(elevationResultSize);

                bool success = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevationType, elevationTypePtr, (uint)elevationResultSize, out returnedSize);
                if (success)
                {
                    elevationResult = (TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(elevationTypePtr);
                    string output = (elevationResult.ToString() + " and UAC is enabled");
                    return output;
                }
                else
                {
                    throw new ApplicationException("Unable to determine the current elevation.");
                    
                }
        }
        else { return "UAC IS OFF FIRE AWAY"; }
    }
}
"@
    if (-not [bool]([appdomain]::CurrentDomain.GetAssemblies() | ? { $_.gettypes() -match 'UacPoll' })) {
        Add-type -typedefinition $assembly -Language CSharp
    }
    [UacPoll]::IsProcessElevated()
    
}
