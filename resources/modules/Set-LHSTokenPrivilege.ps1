function Set-LHSTokenPrivilege
{
<#
.SYNOPSIS
    Enables or disables privileges in a specified access token.

.DESCRIPTION
    Enables or disables privileges in a specified access token.

.PARAMETER Privilege
    The privilege to adjust. This set is taken from
    http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx

.PARAMETER $ProcessId
    The process on which to adjust the privilege. Defaults to the current process.

.PARAMETER Disable
    Switch to disable the privilege, rather than enable it.

.EXAMPLE
    Set-LHSTokenPrivilege -Privilege SeRestorePrivilege

    To set the 'Restore Privilege' for the current Powershell Process.

.EXAMPLE
    Set-LHSTokenPrivilege -Privilege SeRestorePrivilege -Disable

    To disable 'Restore Privilege' for the current Powershell Process.

.EXAMPLE
    Set-LHSTokenPrivilege -Privilege SeShutdownPrivilege -ProcessId 4711
    
    To set the 'Shutdown Privilege' for the Process with Process ID 4711

.INPUTS
    None to the pipeline

.OUTPUTS
    System.Boolean, True if the privilege could be enabled

.NOTES
    to check privileges use whoami
    PS:\> whoami /priv

    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name                Description                          State
    ============================= ==================================== ========
    SeShutdownPrivilege           Shut down the system                 Disabled
    SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
    SeUndockPrivilege             Remove computer from docking station Disabled
    SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled


    AUTHOR: Pasquale Lantella 
    LASTEDIT: 
    KEYWORDS: Token Privilege

.LINK
    http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/

    The privilege to adjust. This set is taken from
    http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx

    pinvoke AdjustTokenPrivileges (advapi32)
    http://www.pinvoke.net/default.aspx/advapi32.AdjustTokenPrivileges

#Requires -Version 2.0
#>
   
[cmdletbinding(  
    ConfirmImpact = 'low',
    SupportsShouldProcess = $false
)]  

[OutputType('System.Boolean')]

Param(

    [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$False,HelpMessage='An Token Privilege.')]
    [ValidateSet(
        "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
    [String]$Privilege,

    [Parameter(Position=1)]
    $ProcessId = $pid,

    [Switch]$Disable
   )

BEGIN {

    Set-StrictMode -Version Latest
    ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name

## Taken from P/Invoke.NET with minor adjustments.

$definition = @'
 using System;
 using System.Runtime.InteropServices;
  
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
'@



} # end BEGIN

PROCESS {

    $processHandle = (Get-Process -id $ProcessId).Handle
    
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)

} # end PROCESS

END { Write-Verbose "Function ${CmdletName} finished." }

} # end Function Set-LHSTokenPrivilege                
 
$Privs =  "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",

        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",

        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",

        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",

        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",

        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",

        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",

        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",

        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",

        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",

        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege"

        foreach ($i in $Privs){
         Set-LHSTokenPrivilege -Privilege $i
        }
