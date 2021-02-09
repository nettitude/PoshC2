function Get-InjectedThread
{
    <# 
    
    .SYNOPSIS 
    
    Looks for threads that were created as a result of code injection.
    
    .DESCRIPTION
    
    Memory resident malware (fileless malware) often uses a form of memory injection to get code execution. Get-InjectedThread looks at each running thread to determine if it is the result of memory injection.
    
    Common memory injection techniques that *can* be caught using this method include:
    - Classic Injection (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    - Reflective DLL Injection
    - Memory Module

    NOTE: Nothing in security is a silver bullet. An attacker could modify their tactics to avoid detection using this methodology.
    
    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .EXAMPLE 
    
    PS > Get-InjectedThread 

    ProcessName               : ThreadStart.exe
    ProcessId                 : 7784
    Path                      : C:\Users\tester\Desktop\ThreadStart.exe
    KernelPath                : C:\Users\tester\Desktop\ThreadStart.exe
    CommandLine               : "C:\Users\tester\Desktop\ThreadStart.exe"
    PathMismatch              : False
    ThreadId                  : 14512
    AllocatedMemoryProtection : PAGE_EXECUTE_READWRITE
    MemoryProtection          : PAGE_EXECUTE_READWRITE
    MemoryState               : MEM_COMMIT
    MemoryType                : MEM_PRIVATE
    BasePriority              : 8
    IsUniqueThreadToken       : False
    Integrity                 : MEDIUM_MANDATORY_LEVEL
    Privilege                 : SeChangeNotifyPrivilege
    LogonId                   : 999
    SecurityIdentifier        : S-1-5-21-386661145-2656271985-3844047388-1001
    UserName                  : DESKTOP-HMTGQ0R\SYSTEM
    LogonSessionStartTime     : 3/15/2017 5:45:38 PM
    LogonType                 : System
    AuthenticationPackage     : NTLM
    BaseAddress               : 4390912
    Size                      : 4096
    Bytes                     : {144, 195, 0, 0...}
    
    #>

    [CmdletBinding()]
    param
    (

    )

    foreach($proc in (Get-Process))
    {
        if($proc.Id -ne 0 -and $proc.Id -ne 4)
        {
            Write-Verbose -Message "Checking $($proc.Name) [$($proc.Id)] for injection"
            foreach($thread in $proc.Threads)
            {
                Write-Verbose -Message "Thread Id: [$($thread.Id)]"
               
                $hThread = OpenThread -ThreadId $thread.Id -DesiredAccess THREAD_ALL_ACCESS
                if($hThread -ne 0)
                {
                    $BaseAddress = NtQueryInformationThread -ThreadHandle $hThread
                    $hProcess = OpenProcess -ProcessId $proc.Id -DesiredAccess PROCESS_ALL_ACCESS -InheritHandle $false

                    if($hProcess -ne 0)
                    {
                        $memory_basic_info = VirtualQueryEx -ProcessHandle $hProcess -BaseAddress $BaseAddress
                        $AllocatedMemoryProtection = $memory_basic_info.AllocationProtect -as $MemProtection
                        $MemoryProtection = $memory_basic_info.Protect -as $MemProtection
                        $MemoryState = $memory_basic_info.State -as $MemState
                        $MemoryType = $memory_basic_info.Type -as $MemType
                    
                        if($MemoryState -eq $MemState::MEM_COMMIT -and $MemoryType -ne $MemType::MEM_IMAGE)
                        {   
                            if($memory_basic_info.RegionSize.ToUInt64() -ge 0x400)
                            {
                                $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress $BaseAddress -Size 0x400
                            }
                            else
                            {
                                $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress $BaseAddress -Size $memory_basic_info.RegionSize
                            }
                            $proc = Get-WmiObject Win32_Process -Filter "ProcessId = '$($proc.Id)'"
                            $KernelPath = QueryFullProcessImageName -ProcessHandle $hProcess
                            $PathMismatch = $proc.Path.ToLower() -ne $KernelPath.ToLower()

                            # check if thread has unique token
                            try
                            {
                                $hThreadToken = OpenThreadToken -ThreadHandle $hThread -DesiredAccess TOKEN_QUERY
                                
                                if($hThreadToken -ne 0)
                                {
                                    $SID = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 1
                                    $Privs = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 3 
                                    $LogonSession = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 17 
                                    $Integrity = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 25 
                                    $IsUniqueThreadToken = $true
                                }
                            }
                            catch
                            {
                                $hProcessToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess TOKEN_QUERY
                                
                                if($hProcessToken -ne 0)
                                {
                                    $SID = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 1
                                    $Privs = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 3 
                                    $LogonSession = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 17 
                                    $Integrity = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 25
                                    $IsUniqueThreadToken = $false
                                }
                            }
                        
                            $ThreadDetail = New-Object PSObject
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessName -Value $proc.Name
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessId -Value $proc.ProcessId
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Path -Value $proc.Path
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name KernelPath -Value $KernelPath
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name CommandLine -Value $proc.CommandLine
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name PathMismatch -Value $PathMismatch
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadId -Value $thread.Id
                            $ThreadDetail | Add-Member -MemberType NoteProperty -Name ThreadStartTime -Value $thread.StartTime
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name AllocatedMemoryProtection -Value $AllocatedMemoryProtection
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryProtection -Value $MemoryProtection
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryState -Value $MemoryState
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryType -Value $MemoryType
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name BasePriority -Value $thread.BasePriority
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name IsUniqueThreadToken -Value $IsUniqueThreadToken
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Integrity -Value $Integrity
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Privilege -Value $Privs
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonId -Value $LogonSession.LogonId
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name SecurityIdentifier -Value $SID
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name UserName -Value "$($LogonSession.Domain)\$($LogonSession.UserName)"
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonSessionStartTime -Value $LogonSession.StartTime
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonType -Value $LogonSession.LogonType
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name AuthenticationPackage -Value $LogonSession.AuthenticationPackage
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name BaseAddress -Value $BaseAddress
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Size -Value $memory_basic_info.RegionSize
                            $ThreadDetail | Add-Member -MemberType Noteproperty -Name Bytes -Value $buf
                            Write-Output $ThreadDetail
                        }
                        CloseHandle($hProcess)
                    }
                }
                CloseHandle($hThread)
            }
        }
    }
}

function Get-LogonSession
{
    <#
    .NOTES

    Author: Lee Christensen (@tifkin_)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $LogonId
    )
    
    $LogonMap = @{}
    Get-WmiObject Win32_LoggedOnUser  | %{
    
        $Identity = $_.Antecedent | Select-String 'Domain="(.*)",Name="(.*)"'
        $LogonSession = $_.Dependent | Select-String 'LogonId="(\d+)"'

        $LogonMap[$LogonSession.Matches[0].Groups[1].Value] = New-Object PSObject -Property @{
            Domain = $Identity.Matches[0].Groups[1].Value
            UserName = $Identity.Matches[0].Groups[2].Value
        }
    }

    Get-WmiObject Win32_LogonSession -Filter "LogonId = `"$($LogonId)`"" | %{
        $LogonType = $Null
        switch($_.LogonType) {
            $null {$LogonType = 'None'}
            0 { $LogonType = 'System' }
            2 { $LogonType = 'Interactive' }
            3 { $LogonType = 'Network' }
            4 { $LogonType = 'Batch' }
            5 { $LogonType = 'Service' }
            6 { $LogonType = 'Proxy' }
            7 { $LogonType = 'Unlock' }
            8 { $LogonType = 'NetworkCleartext' }
            9 { $LogonType = 'NewCredentials' }
            10 { $LogonType = 'RemoteInteractive' }
            11 { $LogonType = 'CachedInteractive' }
            12 { $LogonType = 'CachedRemoteInteractive' }
            13 { $LogonType = 'CachedUnlock' }
            default { $LogonType = $_.LogonType}
        }

        New-Object PSObject -Property @{
            UserName = $LogonMap[$_.LogonId].UserName
            Domain = $LogonMap[$_.LogonId].Domain
            LogonId = $_.LogonId
            LogonType = $LogonType
            AuthenticationPackage = $_.AuthenticationPackage
            Caption = $_.Caption
            Description = $_.Description
            InstallDate = $_.InstallDate
            Name = $_.Name
            StartTime = $_.ConvertToDateTime($_.StartTime)
        }
    }
}

#region PSReflect

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

#endregion PSReflect

#region PSReflect Definitions (Thread)

$Module = New-InMemoryModule -ModuleName GetInjectedThread

#region Constants
$UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0"
$LOW_MANDATORY_LEVEL = "S-1-16-4096"
$MEDIUM_MANDATORY_LEVEL = "S-1-16-8192"
$MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448"
$HIGH_MANDATORY_LEVEL = "S-1-16-12288"
$SYSTEM_MANDATORY_LEVEL = "S-1-16-16384"
$PROTECTED_PROCESS_MANDATORY_LEVEL = "S-1-16-20480"
$SECURE_PROCESS_MANDATORY_LEVEL = "S-1-16-28672"
#endregion Constants

#region Enums
$LuidAttributes = psenum $Module LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield

$MemProtection = psenum $Module MemProtection UInt32 @{
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400
} -Bitfield

$MemState = psenum $Module MemState UInt32 @{
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000
}

$MemType = psenum $Module MemType UInt32 @{
    MEM_PRIVATE = 0x20000
    MEM_MAPPED = 0x40000
    MEM_IMAGE = 0x1000000
}

$PROCESS_ACCESS = psenum $Module PROCESS_ACCESS UInt32 @{
    PROCESS_TERMINATE                 = 0x00000001
    PROCESS_CREATE_THREAD             = 0x00000002
    PROCESS_VM_OPERATION              = 0x00000008
    PROCESS_VM_READ                   = 0x00000010
    PROCESS_VM_WRITE                  = 0x00000020
    PROCESS_DUP_HANDLE                = 0x00000040
    PROCESS_CREATE_PROCESS            = 0x00000080
    PROCESS_SET_QUOTA                 = 0x00000100
    PROCESS_SET_INFORMATION           = 0x00000200
    PROCESS_QUERY_INFORMATION         = 0x00000400
    PROCESS_SUSPEND_RESUME            = 0x00000800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    PROCESS_ALL_ACCESS                = 0x001f1ffb
} -Bitfield

$SecurityEntity = psenum $Module SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}

$SidNameUser = psenum $Module SID_NAME_USE UInt32 @{
  SidTypeUser                            = 1
  SidTypeGroup                           = 2
  SidTypeDomain                          = 3
  SidTypeAlias                           = 4
  SidTypeWellKnownGroup                  = 5
  SidTypeDeletedAccount                  = 6
  SidTypeInvalid                         = 7
  SidTypeUnknown                         = 8
  SidTypeComputer                        = 9
}

$THREAD_ACCESS = psenum $Module THREAD_ACCESS UInt32 @{
    THREAD_TERMINATE                 = 0x00000001
    THREAD_SUSPEND_RESUME            = 0x00000002
    THREAD_GET_CONTEXT               = 0x00000008
    THREAD_SET_CONTEXT               = 0x00000010
    THREAD_SET_INFORMATION           = 0x00000020
    THREAD_QUERY_INFORMATION         = 0x00000040
    THREAD_SET_THREAD_TOKEN          = 0x00000080
    THREAD_IMPERSONATE               = 0x00000100
    THREAD_DIRECT_IMPERSONATION      = 0x00000200
    THREAD_SET_LIMITED_INFORMATION   = 0x00000400
    THREAD_QUERY_LIMITED_INFORMATION = 0x00000800
    DELETE                           = 0x00010000
    READ_CONTROL                     = 0x00020000
    WRITE_DAC                        = 0x00040000
    WRITE_OWNER                      = 0x00080000
    SYNCHRONIZE                      = 0x00100000
    THREAD_ALL_ACCESS                = 0x001f0ffb
} -Bitfield

$TOKEN_ACCESS = psenum $Module TOKEN_ACCESS UInt32 @{
    TOKEN_DUPLICATE          = 0x00000002
    TOKEN_IMPERSONATE        = 0x00000004
    TOKEN_QUERY              = 0x00000008
    TOKEN_QUERY_SOURCE       = 0x00000010
    TOKEN_ADJUST_PRIVILEGES  = 0x00000020
    TOKEN_ADJUST_GROUPS      = 0x00000040
    TOKEN_ADJUST_DEFAULT     = 0x00000080
    TOKEN_ADJUST_SESSIONID   = 0x00000100
    DELETE                   = 0x00010000
    READ_CONTROL             = 0x00020000
    WRITE_DAC                = 0x00040000
    WRITE_OWNER              = 0x00080000
    SYNCHRONIZE              = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    TOKEN_ALL_ACCESS         = 0x001f01ff
} -Bitfield

$TokenInformationClass = psenum $Module TOKEN_INFORMATION_CLASS UInt16 @{ 
  TokenUser                             = 1
  TokenGroups                           = 2
  TokenPrivileges                       = 3
  TokenOwner                            = 4
  TokenPrimaryGroup                     = 5
  TokenDefaultDacl                      = 6
  TokenSource                           = 7
  TokenType                             = 8
  TokenImpersonationLevel               = 9
  TokenStatistics                       = 10
  TokenRestrictedSids                   = 11
  TokenSessionId                        = 12
  TokenGroupsAndPrivileges              = 13
  TokenSessionReference                 = 14
  TokenSandBoxInert                     = 15
  TokenAuditPolicy                      = 16
  TokenOrigin                           = 17
  TokenElevationType                    = 18
  TokenLinkedToken                      = 19
  TokenElevation                        = 20
  TokenHasRestrictions                  = 21
  TokenAccessInformation                = 22
  TokenVirtualizationAllowed            = 23
  TokenVirtualizationEnabled            = 24
  TokenIntegrityLevel                   = 25
  TokenUIAccess                         = 26
  TokenMandatoryPolicy                  = 27
  TokenLogonSid                         = 28
  TokenIsAppContainer                   = 29
  TokenCapabilities                     = 30
  TokenAppContainerSid                  = 31
  TokenAppContainerNumber               = 32
  TokenUserClaimAttributes              = 33
  TokenDeviceClaimAttributes            = 34
  TokenRestrictedUserClaimAttributes    = 35
  TokenRestrictedDeviceClaimAttributes  = 36
  TokenDeviceGroups                     = 37
  TokenRestrictedDeviceGroups           = 38
  TokenSecurityAttributes               = 39
  TokenIsRestricted                     = 40
  MaxTokenInfoClass                     = 41
}
#endregion Enums

#region Structs
$LUID = struct $Module Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module LuidAndAttributes @{
    Luid            =   field 0 $LUID
    Attributes      =   field 1 UInt32
}

$MEMORYBASICINFORMATION = struct $Module MEMORY_BASIC_INFORMATION @{
  BaseAddress       = field 0 UIntPtr
  AllocationBase    = field 1 UIntPtr
  AllocationProtect = field 2 UInt32
  RegionSize        = field 3 UIntPtr
  State             = field 4 UInt32
  Protect           = field 5 UInt32
  Type              = field 6 UInt32
}

$SID_AND_ATTRIBUTES = struct $Module SidAndAttributes @{
    Sid             =   field 0 IntPtr
    Attributes      =   field 1 UInt32
}

$TOKEN_MANDATORY_LABEL = struct $Module TokenMandatoryLabel @{
    Label           = field 0 $SID_AND_ATTRIBUTES;
}

$TOKEN_ORIGIN = struct $Module TokenOrigin @{
  OriginatingLogonSession = field 0 UInt64
}

$TOKEN_PRIVILEGES = struct $Module TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$TOKEN_USER = struct $Module TOKEN_USER @{
    User            = field 0 $SID_AND_ATTRIBUTES
}
#endregion Structs

#region Function Definitions
$FunctionDefinitions = @(
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError),
    
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError),
    
    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError),

    (func ntdll NtQueryInformationThread ([UInt32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    )),

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32],                                 #_In_ DWORD dwDesiredAccess,
        [bool],                                   #_In_ BOOL  bInheritHandle,
        [UInt32]                                  #_In_ DWORD dwProcessId
    ) -SetLastError),
    
    (func advapi32 OpenProcessToken ([bool]) @(
      [IntPtr],                                   #_In_  HANDLE  ProcessHandle
      [UInt32],                                   #_In_  DWORD   DesiredAccess
      [IntPtr].MakeByRefType()                    #_Out_ PHANDLE TokenHandle
    ) -SetLastError),

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32],                                  #_In_ DWORD dwDesiredAccess,
        [bool],                                    #_In_ BOOL  bInheritHandle,
        [UInt32]                                   #_In_ DWORD dwThreadId
    ) -SetLastError),
    
    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                                    #_In_  HANDLE  ThreadHandle
      [UInt32],                                    #_In_  DWORD   DesiredAccess
      [bool],                                      #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType()                     #_Out_ PHANDLE TokenHandle
    ) -SetLastError),
    
    (func kernel32 QueryFullProcessImageName ([bool]) @(
      [IntPtr]                                     #_In_    HANDLE hProcess
      [UInt32]                                     #_In_    DWORD  dwFlags,
      [System.Text.StringBuilder]                  #_Out_   LPTSTR lpExeName,
      [UInt32].MakeByRefType()                     #_Inout_ PDWORD lpdwSize
    ) -SetLastError),
    
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError),
    
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Win32SysInfo'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Advapi32 = $Types['advapi32']
#endregion Function Definitions

#endregion PSReflect Definitions (Thread)

#region Win32 API Abstractions

function CloseHandle
{
    <#
    .SYNOPSIS

    Closes an open object handle.

    .DESCRIPTION

    The CloseHandle function closes handles to the following objects:
    - Access token
    - Communications device
    - Console input
    - Console screen buffer
    - Event
    - File
    - File mapping
    - I/O completion port
    - Job
    - Mailslot
    - Memory resource notification
    - Mutex
    - Named pipe
    - Pipe
    - Process
    - Semaphore
    - Thread
    - Transaction
    - Waitable timer
    
    The documentation for the functions that create these objects indicates that CloseHandle should be used when you are finished with the object, and what happens to pending operations on the object after the handle is closed. In general, CloseHandle invalidates the specified object handle, decrements the object's handle count, and performs object retention checks. After the last handle to an object is closed, the object is removed from the system. 

    .PARAMETER Handle

    A valid handle to an open object.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Handle    
    )
    
    <#
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError)
    #>
    
    $Success = $Kernel32::CloseHandle($Handle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "Close Handle Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function ConvertSidToStringSid
{
    <#
    .SYNOPSIS

    The ConvertSidToStringSid function converts a security identifier (SID) to a string format suitable for display, storage, or transmission.

    .DESCRIPTION

    The ConvertSidToStringSid function uses the standard S-R-I-S-S format for SID strings.
    
    .PARAMETER SidPointer

    A pointer to the SID structure to be converted.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa376399(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SidPointer    
    )
    
    <#
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError)
    #>
    
    $StringPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSid($SidPointer, [ref]$StringPtr); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "ConvertSidToStringSid Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringPtr))
}

function GetTokenInformation
{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER TokenHandle

    .PARAMETER TokenInformationClass

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,
        
        [Parameter(Mandatory = $true)]
        $TokenInformationClass 
    )
    
    <# 
    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError)
    #>
    
    # initial query to determine the necessary buffer size
    $TokenPtrSize = 0
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, 0, $TokenPtrSize, [ref]$TokenPtrSize)
    [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)
    
    # retrieve the proper buffer value
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if($Success)
    {
        switch($TokenInformationClass)
        {
            1 # TokenUser
            {    
                $TokenUser = $TokenPtr -as $TOKEN_USER
                ConvertSidToStringSid -SidPointer $TokenUser.User.Sid
            }
            3 # TokenPrivilege
            {
                # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure
                $TokenPrivileges = $TokenPtr -as $TOKEN_PRIVILEGES
                
                $sb = New-Object System.Text.StringBuilder
                
                for($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) 
                {
                    if((($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes) -band $LuidAttributes::SE_PRIVILEGE_ENABLED) -eq $LuidAttributes::SE_PRIVILEGE_ENABLED)
                    {
                       $sb.Append(", $($TokenPrivileges.Privileges[$i].Luid.LowPart.ToString())") | Out-Null  
                    }
                }
                Write-Output $sb.ToString().TrimStart(', ')
            }
            17 # TokenOrigin
            {
                $TokenOrigin = $TokenPtr -as $LUID
                Write-Output (Get-LogonSession -LogonId $TokenOrigin.LowPart)
            }
            22 # TokenAccessInformation
            {
            
            }
            25 # TokenIntegrityLevel
            {
                $TokenIntegrity = $TokenPtr -as $TOKEN_MANDATORY_LABEL
                switch(ConvertSidToStringSid -SidPointer $TokenIntegrity.Label.Sid)
                {
                    $UNTRUSTED_MANDATORY_LEVEL
                    {
                        Write-Output "UNTRUSTED_MANDATORY_LEVEL"
                    }
                    $LOW_MANDATORY_LEVEL
                    {
                        Write-Output "LOW_MANDATORY_LEVEL"
                    }
                    $MEDIUM_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_MANDATORY_LEVEL"
                    }
                    $MEDIUM_PLUS_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_PLUS_MANDATORY_LEVEL"
                    }
                    $HIGH_MANDATORY_LEVEL
                    {
                        Write-Output "HIGH_MANDATORY_LEVEL"
                    }
                    $SYSTEM_MANDATORY_LEVEL
                    {
                        Write-Output "SYSTEM_MANDATORY_LEVEL"
                    }
                    $PROTECTED_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "PROTECTED_PROCESS_MANDATORY_LEVEL"
                    }
                    $SECURE_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "SECURE_PROCESS_MANDATORY_LEVEL"
                    }
                }
            }
        }
    }
    else
    {
        Write-Debug "GetTokenInformation Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }        
    try
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
    }
    catch
    {
    
    }
}

function NtQueryInformationThread
{
    <#
    .SYNOPSIS

    Retrieves information about the specified thread.

    .DESCRIPTION

    .PARAMETER ThreadHandle

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle  
    )
    
    <#
    (func ntdll NtQueryInformationThread ([Int32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    ))
    #>
    
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)

    $Success = $Ntdll::NtQueryInformationThread($ThreadHandle, 9, $buf, [IntPtr]::Size, [IntPtr]::Zero); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "NtQueryInformationThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output ([System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf))
}

function OpenProcess
{
    <#
    .SYNOPSIS

    Opens an existing local process object.

    .DESCRIPTION

    To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege.
    The handle returned by the OpenProcess function can be used in any function that requires a handle to a process, such as the wait functions, provided the appropriate access rights were requested.
    When you are finished with the handle, be sure to close it using the CloseHandle function.

    .PARAMETER ProcessId

    The identifier of the local process to be opened.
    If the specified process is the System Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER. If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.

    .PARAMETER DesiredAccess

    The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: PROCESS_ACCESS

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwProcessId
    ) -EntryPoint OpenProcess -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('PROCESS_TERMINATE','PROCESS_CREATE_THREAD','PROCESS_VM_OPERATION','PROCESS_VM_READ','PROCESS_VM_WRITE','PROCESS_DUP_HANDLE','PROCESS_CREATE_PROCESS','PROCESS_SET_QUOTA','PROCESS_SET_INFORMATION','PROCESS_QUERY_INFORMATION','PROCESS_SUSPEND_RESUME','PROCESS_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','PROCESS_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )

    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $PROCESS_ACCESS::$val
    }

    $hProcess = $Kernel32::OpenProcess($dwDesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hProcess -eq 0) 
    {
        #throw "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hProcess
}

function OpenProcessToken
{ 
    <#
    .SYNOPSIS

    The OpenProcessToken function opens the access token associated with a process.

    .PARAMETER ProcessHandle

    A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
    For a list of access rights for access tokens, see Access Rights for Access-Token Objects.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: TOKEN_ACCESS (Enumeration)

    (func advapi32 OpenProcessToken ([bool]) @(
        [IntPtr],                #_In_  HANDLE  ProcessHandle
        [UInt32],                #_In_  DWORD   DesiredAccess
        [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenProcessToken -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess  
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $dwDesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function OpenThread
{
    <#
    .SYNOPSIS

    Opens an existing thread object.

    .DESCRIPTION

    The handle returned by OpenThread can be used in any function that requires a handle to a thread, such as the wait functions, provided you requested the appropriate access rights. The handle is granted access to the thread object only to the extent it was specified in the dwDesiredAccess parameter.
    When you are finished with the handle, be sure to close it by using the CloseHandle function.

    .PARAMETER ThreadId

    The identifier of the thread to be opened.

    .PARAMETER DesiredAccess

    The access to the thread object. This access right is checked against the security descriptor for the thread. This parameter can be one or more of the thread access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    
    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: THREAD_ACCESS (Enumeration)

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32], #_In_ DWORD dwDesiredAccess
        [bool],   #_In_ BOOL  bInheritHandle
        [UInt32]  #_In_ DWORD dwThreadId
    ) -EntryPoint OpenThread -SetLastError)
        
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686769(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ThreadId,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('THREAD_TERMINATE','THREAD_SUSPEND_RESUME','THREAD_GET_CONTEXT','THREAD_SET_CONTEXT','THREAD_SET_INFORMATION','THREAD_QUERY_INFORMATION','THREAD_SET_THREAD_TOKEN','THREAD_IMPERSONATE','THREAD_DIRECT_IMPERSONATION','THREAD_SET_LIMITED_INFORMATION','THREAD_QUERY_LIMITED_INFORMATION','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','THREAD_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $InheritHandle = $false
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0
    
    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $THREAD_ACCESS::$val
    }

    $hThread = $Kernel32::OpenThread($dwDesiredAccess, $InheritHandle, $ThreadId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hThread -eq 0) 
    {
        #throw "OpenThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hThread
}

function OpenThreadToken
{
    <#
    .SYNOPSIS

    The OpenThreadToken function opens the access token associated with a thread

    .DESCRIPTION

    Tokens with the anonymous impersonation level cannot be opened.
    Close the access token handle returned through the Handle parameter by calling CloseHandle.

    .PARAMETER ThreadHandle

    A handle to the thread whose access token is opened.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are reconciled against the token's discretionary access control list (DACL) to determine which accesses are granted or denied.

    .PARAMETER OpenAsSelf

    TRUE if the access check is to be made against the process-level security context.
    FALSE if the access check is to be made against the current security context of the thread calling the OpenThreadToken function.
    The OpenAsSelf parameter allows the caller of this function to open the access token of a specified thread when the caller is impersonating a token at SecurityIdentification level. Without this parameter, the calling thread cannot open the access token on the specified thread because it is impossible to open executive-level objects by using the SecurityIdentification impersonation level.

    .NOTES
    
    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: $TOKEN_ACCESS (Enumeration)

    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                #_In_  HANDLE  ThreadHandle
      [UInt32],                #_In_  DWORD   DesiredAccess
      [bool],                  #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType() #_Out_ PHANDLE TokenHandle
    ) -EntryPoint OpenThreadToken -SetLastError)
        
    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379296(v=vs.85).aspx
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_IMPERSONATE','TOKEN_QUERY','TOKEN_QUERY_SOURCE','TOKEN_ADJUST_PRIVILEGES','TOKEN_ADJUST_GROUPS','TOKEN_ADJUST_DEFAULT','TOKEN_ADJUST_SESSIONID','DELETE','READ_CONTROL','WRITE_DAC','WRITE_OWNER','SYNCHRONIZE','STANDARD_RIGHTS_REQUIRED','TOKEN_ALL_ACCESS')]
        [string[]]
        $DesiredAccess,
        
        [Parameter()]
        [bool]
        $OpenAsSelf = $false   
    )
    
    # Calculate Desired Access Value
    $dwDesiredAccess = 0

    foreach($val in $DesiredAccess)
    {
        $dwDesiredAccess = $dwDesiredAccess -bor $TOKEN_ACCESS::$val
    }

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenThreadToken($ThreadHandle, $dwDesiredAccess, $OpenAsSelf, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        throw "OpenThreadToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $hToken
}

function QueryFullProcessImageName
{
    <#
    .SYNOPSIS

    Retrieves the full name of the executable image for the specified process.

    .PARAMETER ProcessHandle

    A handle to the process. This handle must be created with the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.

    .PARAMETER Flags

    This parameter can be one of the following values.
    0x00 - The name should use the Win32 path format.
    0x01 - The name should use the native system path format.

    .NOTES
    
    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684919(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter()]
        [UInt32]
        $Flags = 0
    )
    
    $capacity = 2048
    $sb = New-Object -TypeName System.Text.StringBuilder($capacity)

    $Success = $Kernel32::QueryFullProcessImageName($ProcessHandle, $Flags, $sb, [ref]$capacity); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "QueryFullProcessImageName Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $sb.ToString()
}

function ReadProcessMemory
{
    <#
    .SYNOPSIS

    Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.

    .DESCRIPTION

    ReadProcessMemory copies the data in the specified address range from the address space of the specified process into the specified buffer of the current process. Any process that has a handle with PROCESS_VM_READ access can call the function.

    The entire area to be read must be accessible, and if it is not accessible, the function fails.

    .PARAMETER ProcessHandle

    A handle to the process with memory that is being read. The handle must have PROCESS_VM_READ access to the process.

    .PARAMETER BaseAddress

    The base address in the specified process from which to read. Before any data transfer occurs, the system verifies that all data in the base address and memory of the specified size is accessible for read access, and if it is not accessible the function fails.

    .PARAMETER Size

    The number of bytes to be read from the specified process.

    .NOTES
    
    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
    
    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress,
        
        [Parameter(Mandatory = $true)]
        [Int]
        $Size    
    )
    
    <#
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError) # MSDN states to call GetLastError if the return value is false. 
    #>
    
    $buf = New-Object byte[]($Size)
    [Int32]$NumberOfBytesRead = 0
    
    $Success = $Kernel32::ReadProcessMemory($ProcessHandle, $BaseAddress, $buf, $buf.Length, [ref]$NumberOfBytesRead); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "ReadProcessMemory Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $buf
}

function VirtualQueryEx
{
    <#
    .SYNOPSIS

    Retrieves information about a range of pages within the virtual address space of a specified process.

    .PARAMETER ProcessHandle

    A handle to the process whose memory information is queried. The handle must have been opened with the PROCESS_QUERY_INFORMATION access right, which enables using the handle to read information from the process object.

    .PARAMETER BaseAddress

    The base address of the region of pages to be queried. This value is rounded down to the next page boundary.
    
    .NOTES
    
    Author - Jared Atkinson (@jaredcatkinson)
    
    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366907(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress
    )
    
    <#  
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError)
    #>
    
    $memory_basic_info = [Activator]::CreateInstance($MEMORYBASICINFORMATION)
    $Success = $Kernel32::VirtualQueryEx($ProcessHandle, $BaseAddress, [Ref]$memory_basic_info, $MEMORYBASICINFORMATION::GetSize()); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success) 
    {
        Write-Debug "VirtualQueryEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    
    Write-Output $memory_basic_info
}

#endregion Win32 API Abstractions
