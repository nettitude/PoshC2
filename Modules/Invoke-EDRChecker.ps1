$edr_list = @('activeconsole',
              'authtap',
              'avast',
              'avecto',
              'canary',
              'carbon',
              'cb.exe',
              'ciscoamp',
              'cisco amp',
              'countertack',
              'cramtray',
              'crssvc',
              'crowd',
              'csagent',
              'csfalcon',
              'csshell',
              'cybereason',
              'cyclorama',
              'cylance',
              'cyoptics',
              'cyupdate',
              'cyvera',
              'cyserver',
              'cytray',
              'defendpoint',
              'defender',
              'eectrl',
              'endgame',
              'fireeye',
              'groundling',
              'inspector',
              'kaspersky',
              'lacuna',
              'logrhythm',
              'mandiant',
              'mcafee',
              'morphisec',
              'msascuil',
              'msmpeng',
              'nissrv',
              'osquery',
              'Palo Alto Networks',
              'pgeposervice',
              'pgsystemtray',
              'privilegeguard',
              'procwall',
              'protectorservice'
              'qradar',
              'redcloak',
              'secureworks',
              'securityhealthservice',
              'semlaunchsvc'
              'sentinel',
              'sepliveupdate'
              'sisidsservice',
              'sisipsservice',
              'sisipsutil',
              'smc.exe',
              'smcgui',
              'snac64',
              'sophos',
              'splunk',
              'srtsp',
              'symantec',
              'symcorpui'
              'symefasi',
              'sysinternal',
              'sysmon',
              'tanium',
              'tda.exe',
              'tdawork',
              'tpython',
              'wincollect',
              'windowssensor',
              'wireshark'
             )

<#
.SYNOPSIS
Enumerates the host and checks it for defensive products.

Author: Ross Bingham (@PwnDexter)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION
Enumerates the target host by querying processes, process metadata, dlls loaded into your current process and each dlls metadata, known install paths, installed services, the registry and running drivers then checks the output against a list of known defensive products such as AV's, EDR's and logging tools.

.PARAMETER Force
Forces registry checks when not running as admin.

.PARAMETER Remote
Specifies the computername to perform the remote checks against.

.PARAMETER Ignore
Forces the remote checks against the target regardless of connectivity and name resolution.

.EXAMPLE
PS C:\> Invoke-EDRChecker
PS C:\> Invoke-EDRChecker -Force
PS C:\> Invoke-EDRChecker -Remote <hostname>
PS C:\> Invoke-EDRChecker -Remote <hostname> -Ignore
#>

function Invoke-EDRChecker
{

    [CmdletBinding(DefaultParameterSetName='Registry')]
    param(
          [Parameter(ParameterSetName='Registry', Mandatory=$false)][switch] $Force,
          [Parameter(ParameterSetName='Remote', Mandatory=$false)][switch] $Remote,
          [Parameter(ParameterSetName='Remote', Mandatory=$false)][switch] $Ignore,
          [Parameter(ParameterSetName='Remote', Mandatory=$false, position=0)][string] $ComputerName
         )

    $edr = $edr_list
        
    if ($Remote -eq $false)
    {
        Write-Output ""
        Write-Output "[!] Performing EDR Checks"
        Write-Output "[!] Checking current user integrity"
        $user = [Security.Principal.WindowsIdentity]::GetCurrent();
        $isadm = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        if ($isadm | Select-String -Pattern "True") {Write-Output "[+] Running as admin, all checks will be performed"}
        elseif (($isadm | Select-String -Pattern "False") -and ($Force -eq $false))
        {Write-Output "[-] Not running as admin, process metadata, registry and drivers will not be checked"; Write-Output "[-] Use the -Force flag to force registry checks when not running as admin"}
        elseif (($isadm | Select-String -Pattern "False") -or ($Force -eq $true))
        {Write-Output "[-] Not running as admin, process metadata and drivers will not be checked"; Write-Output "[+] The -Force flag has been passed for best efforts registry checks"}

        Write-Output ""
        Write-Output "[!] Checking running processes"
        if ($proc = Get-Process | Select-Object ProcessName,Name,Path,Company,Product,Description | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $proc -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] No suspicious processes found"}

        Write-Output ""
        Write-Output "[!] Checking loaded DLLs in your current process"
        $procdll = Get-Process -Id $pid -Module
        if ($metadll = (Get-Item $procdll.FileName).VersionInfo | Select-Object CompanyName,FileDescription,FileName,InternalName,LegalCopyright,OriginalFileName,ProductName | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $metadll -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] No suspicious DLLs loaded"}

        Write-Output ""
        Write-Output "[!] Checking Program Files"
        if ($prog = Get-ChildItem -Path 'C:\Program Files\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $prog -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] Nothing found in Program Files"}
    
        Write-Output ""
        Write-Output "[!] Checking Program Files x86"
        if ($prog86 = Get-ChildItem -Path 'C:\Program Files (x86)\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $prog86 -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] Nothing found in Program Files x86"}

        Write-Output ""
        Write-Output "[!] Checking Program Data"
        if ($progd = Get-ChildItem -Path 'C:\ProgramData\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $progd -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] Nothing found in Program Data"}

        Write-Output ""
        Write-Output "[!] Checking installed services"
        if ($serv = Get-Service | Select-Object Name,DisplayName,ServiceName | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $serv -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] No suspicious services found"}

        if (($isadm | Select-String -Pattern "True") -or ($Force -eq $true))
        {
            Write-Output ""
            Write-Output "[!] Checking the registry"
            if ($reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*' | Select-Object PSChildName,PSPath,DisplayName,ImagePath,Description | Select-String -Pattern $edr -AllMatches) 
            {ForEach ($p in $reg -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
            else {Write-Output "[+] Nothing found in Registry"}
        }

        if ($isadm | Select-String -Pattern "True")
        {
            Write-Output ""
            Write-Output "[!] Checking the drivers"
            if ($drv = fltmc instances | Select-String -Pattern $edr -AllMatches) 
            {ForEach ($p in $drv -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
            else {Write-Output "[+] No suspicious drivers found"}
        }
    }
    
    if ($Remote -eq $true)
    {
        if ([string]::IsNullOrEmpty($ComputerName))
        {Throw "[-] ComputerName not set, please provide the hostname of the target"}

        if ($Ignore -ne $true)
        {
            Write-Output "" 
            Write-Output "[!] Checking connectivity to $ComputerName"
            $con = Test-Connection -ComputerName $ComputerName -Count 2 -Delay 2 -Quiet
            if ($con | Select-String -Pattern "False")
            {Throw "[-] Connectivity to $ComputerName failed, use the -Ignore flag to attempt the checks anyway"}
            else {Write-Output "[+] Connectivity to $ComputerName confirmed"}

            Write-Output ""
            Write-Output "[!] Resolving $ComputerName to it's FQDN"
            $fqdn = [System.Net.DNS]::GetHostEntry($ComputerName).hostname
            if ([string]::IsNullOrEmpty($fqdn))
            {Throw "[-] Unable to resolve $ComputerName to a FQDN, use the -Ignore flag to attempt the checks anyway"}
            else {Write-Output "[+] Successfully resolved $Computername to $fqdn"}
            $targ = $fqdn
        }
        elseif ($ignore -eq $true)
        {
            Write-Output "" 
            Write-Output "[!] Ignoring connectivity and FQDN checks to $ComputerName, this may result in errors"
            $targ = $ComputerName
        }

        $targ = $targ
        Write-Output ""
        Write-Output "[!] Performing EDR Checks against $targ, remote checks are limited to process listing, common install directories and installed services"

        Write-Output ""
        Write-Output "[!] Checking running processes of $targ"
        if ($proc = Get-Process -ComputerName $targ | Select-Object ProcessName,Name,Path,Company,Product,Description | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $proc -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] No suspicious processes found"}

        Write-Output ""
        Write-Output "[!] Checking running services of $targ"
        if ($serv = Get-Service -ComputerName $targ | Select-Object Name,DisplayName,ServiceName | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $serv -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] No suspicious services found"}

        Write-Output ""
        Write-Output "[!] Checking Program Files on $targ"
        if ($prog = Get-ChildItem -Path "\\$targ\c$\Program Files\*" | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $prog -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] Nothing found in Program Files"}
    
        Write-Output ""
        Write-Output "[!] Checking Program Files x86 on $targ"
        if ($prog86 = Get-ChildItem -Path "\\$targ\c$\Program Files (x86)\*" | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $prog86 -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] Nothing found in Program Files x86"}

        Write-Output ""
        Write-Output "[!] Checking Program Data on $targ"
        if ($progd = Get-ChildItem -Path "\\$targ\c$\ProgramData\*" | Select-Object Name | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $progd -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] Nothing found in Program Data"}
    
        Write-Output ""
        Write-Output "[!] Checking installed services on $targ"
        if ($serv = Get-Service -ComputerName $targ | Select-Object Name,DisplayName,ServiceName | Select-String -Pattern $edr -AllMatches)
        {ForEach ($p in $serv -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] No suspicious services found"}

        Write-Output ""
        Write-Output "[!] EDR Checks Complete"
        Write-Output ""
    }
}
