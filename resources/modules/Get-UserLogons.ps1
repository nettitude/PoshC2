<#
.Synopsis
    Gets User Logon Events

    Author: @m0rv4i

.DESCRIPTION

    Lists User Logon Events from an event log and lists them with timestamps and from which hostname.

    Events where the hostname is '-' and machine logon events are excluded.

.PARAMETER Newest

    Check the newest X events. Defaults to 200.

.PARAMETER ComputerName

    Computername to run against using PSRemoting. Defaults to local host.

.PARAMETER ExclusionList

    Account names to exclude. Defaults to "SYSTEM", "NETWORK SERVICE", "DWM-1", "LOCAL SERVICE", "UMFD-0", "UMFD-1".

.PARAMETER ServiceAccounts

    Whether to logic service accounts or not. Defaults to false.
    Service accounts are accounts starting with SVC_, SVC-, svc_ or svc-.

.EXAMPLE

    PS C:\> Get-UserLogons

    2020-08-17 10:52:40 : BEEROCLOCK\bob -> BEEROCLOCK
    2020-08-17 10:52:40 : BEEROCLOCK\bob -> BEEROCLOCK
    2020-08-14 19:00:48 : BEEROCLOCK\bob -> BEEROCLOCK
    2020-08-14 19:00:48 : BEEROCLOCK\bob -> BEEROCLOCK
    2020-08-12 21:00:05 : BEEROCLOCK\bob -> BEEROCLOCK
    2020-08-12 21:00:05 : BEEROCLOCK\bob -> BEEROCLOCK

.EXAMPLE

    PS C:\> Get-UserLogons -Newest 20000 -ServiceAccounts -ComputerName DC01.DOMAIN.LOCAL

.EXAMPLE

    PS C:\> $exclusions = $("SYSTEM", "NETWORK SERVICE", "DWM-1", "LOCAL SERVICE", "UMFD-0", "UMFD-1", "ACCOUNT1", "ACCOUNT2")
    PS C:\> Get-UserLogons -ServiceAccounts -ComputerName DC01.DOMAIN.LOCAL -ExclusionList $exclusions

#>
function Get-UserLogons()
{
    [CmdletBinding()]
    Param
    (
            [string[]]$ExclusionList = $("SYSTEM", "NETWORK SERVICE", "DWM-1", "LOCAL SERVICE", "UMFD-0", "UMFD-1"),
            [int]$Newest = 200,
            [switch]$ServiceAccounts = $false,
            [string]$ComputerName = ""
    )

    Write-Output ""

    if($ComputerName)
    {
        $LogonEvents = Get-EventLog -newest $Newest -logname security -instanceid 4624 -ComputerName $ComputerName
    }
    else
    {
        $LogonEvents = Get-EventLog -newest $Newest -logname security -instanceid 4624
    }

    foreach($Events in $LogonEvents)
    {

        $LogonUsername = $Events.ReplacementStrings[5]
        $LogonHostname = $Events.ReplacementStrings[11]
        $LogonDomain = $Events.ReplacementStrings[6]

        if($ExclusionList -contains $LogonUsername)
        {
            continue
        }

        if($LogonHostname -eq "-")
        {
            continue
        }

        if($LogonUsername.Trim("`$") -eq $LogonHostname)
        {
            continue
        }

        if(!$ServiceAccounts)
        {
            if($LogonUsername.ToLower().StartsWith("svc_") -or $LogonUsername.ToLower().StartsWith("svc-"))
            {
                continue
            }
        }

        Write-Output "$($Events.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss")) : $LogonDomain\$LogonUsername -> $LogonHostname"

    }
}
