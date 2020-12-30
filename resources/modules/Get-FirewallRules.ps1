<#
.Synopsis
    Returns all firewall rules
.DESCRIPTION
	Returns all firewall rules
.EXAMPLE
    PS C:\> Get-FirewallRule -Enabled $true | sort direction,applicationName,name
.EXAMPLE
	PS C:\> Get-firewallRule -enabled $true | sort direction,applicationName,name | format-table -wrap -autosize -property Name, @{Label="Action"; expression={$Fwaction[$_.action]}},@{label="Direction";expression={ $fwdirection[$_.direction]}},@{Label="Protocol"; expression={$FwProtocols[$_.protocol]}}, localPorts,applicationname
#>
Function Get-FireWallRule
{
Param (
$Name, 
$Direction, 
$Enabled, 
$Protocol, 
$profile, 
$action, 
$grouping
)

$Rules = (New-object -comObject HNetCfg.FwPolicy2).rules
If ($name) { $rules= $rules | where-object {$_.name -like $name}}
If ($direction) {$rules= $rules | where-object {$_.direction -eq $direction}}
If ($Enabled) {$rules= $rules | where-object {$_.Enabled -eq $Enabled}}
If ($protocol) {$rules= $rules | where-object {$_.protocol -eq  $protocol}}
If ($profile) {$rules= $rules | where-object {$_.Profiles -bAND $profile}}
If ($Action) {$rules= $rules | where-object {$_.Action -eq $Action}}
If ($Grouping) {$rules= $rules | where-object {$_.Grouping -Like $Grouping}}

$rules

}


Function Get-FireWallRulesAll
{

Netsh.exe Advfirewall show allprofiles

$spaces1 = " " * 71
$spaces2 = " " * 64
Get-FireWallRule -Enabled $true | sort name | `
format-table -property `
@{label="Name" + $spaces1             ; expression={$_.name}                    ; width=75}, `
@{label="Action"                      ; expression={$Fwaction[$_.action]}       ; width=6 }, `
@{label="Direction"                   ; expression={$fwdirection[$_.direction]} ; width=9 }, `
@{label="Protocol"                    ; expression={$FwProtocols[$_.protocol]}  ; width=8 }, `
@{label="Local Ports"                 ; expression={$_.localPorts}              ; width=11}, `
@{label="Application Name" + $spaces2 ; expression={$_.applicationname}         ; width=80} 

}
