<#
.Synopsis
    Generates a list of IPv4 IP Addresses given a Start and End IP - All credit to @darkoperator
.DESCRIPTION
    Generates a list of IPv4 IP Addresses given a Start and End IP.
.EXAMPLE
    Generating a list of IPs from CIDR

    Get-IPRange 192.168.1.0/24
    
.EXAMPLE
    Generating a list of IPs from Range

    Get-IPRange -Range 192.168.1.1-192.168.1.50
#>
function New-IPv4Range
{
  param(
    [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
           $StartIP,
           
    [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
           $EndIP      
  )
  
    # created by Dr. Tobias Weltner, MVP PowerShell
    $ip1 = ([System.Net.IPAddress]$StartIP).GetAddressBytes()
    [Array]::Reverse($ip1)
    $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

    $ip2 = ([System.Net.IPAddress]$EndIP).GetAddressBytes()
    [Array]::Reverse($ip2)
    $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

    for ($x=$ip1; $x -le $ip2; $x++) {
        $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
        [Array]::Reverse($ip)
        $ip -join '.'
    }
}
<#
.Synopsis
    Generates a IP Address Objects for IPv4 and IPv6 Ranges - All credit to @darkoperator
.DESCRIPTION
    Generates a IP Address Objects for IPv4 and IPv6 Ranges given a ranges in CIDR or
    range <StartIP>-<EndIP> format.
.EXAMPLE
    PS C:\> New-IPvRange -Range 192.168.1.1-192.168.1.5

    Generate a collection of IPv4 Object collection for the specified range.

.EXAMPLE
   New-IPRange -Range 192.168.1.1-192.168.1.50 | select -ExpandProperty ipaddresstostring

   Get a list of IPv4 Addresses in a given range as a list for use in another tool.
#>
function New-IPRange
{
    [CmdletBinding(DefaultParameterSetName='CIDR')]
    Param(
        [parameter(Mandatory=$true,
        ParameterSetName = 'CIDR',
        Position=0)]
        [string]$CIDR,

        [parameter(Mandatory=$true,
        ParameterSetName = 'Range',
        Position=0)]
        [string]$Range   
    )
    if($CIDR)
    {
        $IPPart,$MaskPart = $CIDR.Split('/')
        $AddressFamily = ([System.Net.IPAddress]::Parse($IPPart)).AddressFamily

        # Get the family type for the IP (IPv4 or IPv6)
        $subnetMaskObj = [IPHelper.IP.Subnetmask]::Parse($MaskPart, $AddressFamily)
        
        # Get the Network and Brodcast Addressed
        $StartIP = [IPHelper.IP.IPAddressAnalysis]::GetClasslessNetworkAddress($IPPart, $subnetMaskObj)
        $EndIP = [IPHelper.IP.IPAddressAnalysis]::GetClasslessBroadcastAddress($IPPart,$subnetMaskObj)
        
        # Ensure we do not list the Network and Brodcast Address
        $StartIP = [IPHelper.IP.IPAddressAnalysis]::Increase($StartIP)
        $EndIP = [IPHelper.IP.IPAddressAnalysis]::Decrease($EndIP)
        [IPHelper.IP.IPAddressAnalysis]::GetIPRange($StartIP, $EndIP)
    }
    elseif ($Range)
    {
        $StartIP, $EndIP = $range.split('-')
        [IPHelper.IP.IPAddressAnalysis]::GetIPRange($StartIP, $EndIP)
    }
}

<#
.Synopsis
    Generates a list of IPv4 IP Addresses given a CIDR - All credit to @darkoperator
.DESCRIPTION
    Generates a list of IPv4 IP Addresses given a CIDR.
.EXAMPLE
    Generating a list of IPs
    PS C:\> New-IPv4RangeFromCIDR -Network 192.168.1.0/29
    192.168.1.1
    192.168.1.2
    192.168.1.3
    192.168.1.4
    192.168.1.5
    192.168.1.6
    192.168.1.7
#>
function New-IPv4RangeFromCIDR 
{
    param(
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
				   $Network
    )
    # Extract the portions of the CIDR that will be needed
    $StrNetworkAddress = ($Network.split('/'))[0]
    [int]$NetworkLength = ($Network.split('/'))[1]
    $NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
    $IPLength = 32-$NetworkLength
    [Array]::Reverse($NetworkIP)
    $NumberOfIPs = ([System.Math]::Pow(2, $IPLength)) -1
    $NetworkIP = ([System.Net.IPAddress]($NetworkIP -join '.')).Address
    $StartIP = $NetworkIP +1
    $EndIP = $NetworkIP + $NumberOfIPs
    # We make sure they are of type Double before conversion
    If ($EndIP -isnot [double])
    {
        $EndIP = $EndIP -as [double]
    }
    If ($StartIP -isnot [double])
    {
        $StartIP = $StartIP -as [double]
    }
    # We turn the start IP and end IP in to strings so they can be used.
    $StartIP = ([System.Net.IPAddress]$StartIP).IPAddressToString
    $EndIP = ([System.Net.IPAddress]$EndIP).IPAddressToString
    New-IPv4Range $StartIP $EndIP
}

$runme =
{
     param
     (
         [Object]
         $IPAddress,
         [Object]
         $Creds,
         [Bool]
         $Allshares,
         [Object]
         $Command
     )

    $getcreds = $Creds
    $Port = 135
    $Socket = New-Object Net.Sockets.TcpClient
    $Socket.client.ReceiveTimeout = 2000
    $ErrorActionPreference = 'SilentlyContinue'
    $Socket.Connect($IPAddress, $Port)
    $ErrorActionPreference = 'Continue'
    
    if ($Socket.Connected) {
        #Object to store result    
        $endpointResult = New-Object PSObject | Select-Object Host, PortOpen, LoggedOnUsers, LocalAdministrators, Members, SharesTested, FilesFound
        $endpointResult.PortOpen = 'Open'
        $endpointResult.Host = $IPAddress
        $Socket.Close()        
    } else {
        $portclosed = 'True'
    }
        
    $Socket = $null
   
    if ($endpointResult.PortOpen -eq 'Open')
    {
        if ($command) {
        # run a command of my choice
        Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $IPAddress -Credential $getcreds -ArgumentList $Command
        }
        # Get logged in users from remote machine
        $proc = Get-WmiObject -ComputerName $IPAddress -Credential $getcreds -query "SELECT * from win32_process WHERE Name = 'explorer.exe'"

        # Go through collection of processes and check for local admin rights
        ForEach ($p in $proc) {
            $temp = '' | Select-Object Computer, Domain, User
            $user = ($p.GetOwner()).User
            $domain = ($p.GetOwner()).Domain
            if($user){
            $username = "$domain\$user"
            $endpointResult.LoggedOnUsers += "'$username' " 
            }

            
            # Get local admin users  
            $arr = @()   
            $ComputerName = (Get-WmiObject -ComputerName $IPAddress -Credential $getcreds -Class Win32_ComputerSystem).Name 
            $wmi = Get-WmiObject -ComputerName $ComputerName -Credential $getcreds -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$ComputerName',Name='Administrators'`""  
  
            # Parse out the username from each result and append it to the array.  
            if ($wmi -ne $null)  
            {  
                foreach ($item in $wmi)  
                {  
                    $data = $item.PartComponent -split '\,' 
                    $domain = ($data[0] -split '=')[1] 
                    $name = ($data[1] -split '=')[1] 
                    $arr += ("$domain\$name").Replace('"','')
                    $currentuser = ("$domain\$name").Replace('"','')
                    [Array]::Sort($arr) 
                    if ($currentuser)
                    {
                    $endpointResult.Members += "'$currentuser' "
                    }
                    if ($currentuser -contains $username)
                    {
                    $endpointResult.LocalAdministrators += "'$currentuser' "
                    }
                }  
            }  
        }

        if (!$Allshares) {
            # Test for the default ADMIN$ share 
            $wmiquery = 'Select * from Win32_Share'
            $availableShares = Get-WmiObject -Query $wmiquery -ComputerName $IPAddress -Credential($getcreds) 
            foreach ($share in $availableShares){
                if ($share.Name -eq 'ADMIN$'){
                    $sharename = $share.Name                   
                    $endpointResult.SharesTested += "'$sharename' "
                    $drive = ($share.Path).Substring(0,1)
                    $path = (($share.Path).Substring(2)).Replace('\','\\')
                    $path = $path+'\\'
                    $path = $path.Replace('\\\\\\\\','\\')
                    $path = $path.Replace('\\\\\\','\\')
                    $path = $path.Replace('\\\\','\\')
                    $datesearch = (Get-Date).AddMonths(-1).ToString('MM/dd/yyyy')
                    $wmiquery = "SELECT * FROM CIM_DataFile WHERE Drive='"+$drive+":' AND Path='"+$path+"' AND Extension='exe' AND CreationDate > '"+$datesearch+"' "
                    Get-WmiObject -Query $wmiquery -ComputerName $IPAddress -Credential($getcreds) | foreach{ $filename = $_.Name; $endpointResult.FilesFound += "'$filename' "} 
                 }
            }
        } else {
            # Test against all available all shares
            $wmiquery = 'Select * from Win32_Share'
            $availableShares = Get-WmiObject -Query $wmiquery -ComputerName $IPAddress -Credential($getcreds) 
            foreach ($share in $availableShares){
                if ($share.Name -ne 'IPC$'){
                    $sharename = $share.Name
                    $endpointResult.SharesTested += "'$sharename' "
                    $drive = ($share.Path).Substring(0,1)
                    $path = (($share.Path).Substring(2)).Replace('\','\\')
                    $path = $path+'\\'
                    $path = $path.Replace('\\\\\\\\','\\')
                    $path = $path.Replace('\\\\\\','\\')
                    $path = $path.Replace('\\\\','\\')
                    $datesearch = (Get-Date).AddMonths(-1).ToString('MM/dd/yyyy')
                    $wmiquery = "SELECT * FROM CIM_DataFile WHERE Drive='"+$drive+":' AND Path='"+$path+"' AND Extension='exe' AND CreationDate > '"+$datesearch+"' "
                    Get-WmiObject -Query $wmiquery -ComputerName $IPAddress -Credential($getcreds) | foreach{ $filename = $_.Name; $endpointResult.FilesFound += "'$filename' "} 
                 }
            }
        }
    }   
    return $endpointResult
}
<#
.Synopsis
   WMI Checker over Windows RPC Ports (TCP 135) - @benpturner
.DESCRIPTION
   WMI Tool written to search for files younger than a month on network shares. This also searches is the current logged in user is part of the Local Administrators group. All communications is done over Windows RPC Ports (TCP 135)
.EXAMPLE
   Invoke-WMIChecker -IPAddress 172.16.0.205
.EXAMPLE
   Invoke-WMIChecker -IPRangeCIDR 172.16.0.0/22 -Threads 100 -Allshares 1
.EXAMPLE
   Invoke-WMIChecker -IPList C:\Temp\Hostlist.txt -Threads 30 -Allshares 0
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Invoke-WMIChecker
{
     param
     (
         [Object]
         $IPAddress,
         [Object]
         $IPRangeCIDR,
         [Object]
         $IPList,
         [Object]
         $Threads,
         [Bool]
         $Allshares,
         [Object]
         $Command,
         [Object]
         $username,
         [Object]
         $password
     )
    
    if ($username) { 
        $PSS = ConvertTo-SecureString $password -AsPlainText -Force
        $getcreds = new-object system.management.automation.PSCredential $username,$PSS
    } else {
        $getcreds = Get-Credential
    }

    if ($IPList) {$iprangefull = Get-Content $IPList}
    if ($IPRangeCIDR) {$iprangefull = New-IPv4RangeFromCIDR $IPRangeCIDR}
    if ($IPAddress) {$iprangefull = $IPAddress}
    Write-Output ''
    Write-Output $iprangefull.count Total hosts read from file
     
    $jobs = @()
    $start = get-date
    Write-Output `n"Begin Scanning at $start" -ForegroundColor Red

    #Multithreading setup
    # create a pool of maxThread runspaces
    if (!$Threads){$Threads = 64}   
    $pool = [runspacefactory]::CreateRunspacePool(1, $Threads)   
    $pool.Open()
    $endpointResults = @()
    $jobs = @()   
    $ps = @()   
    $wait = @()

    $i = 0
    #Loop through the endpoints starting a background job for each endpoint
    foreach ($endpoint in $iprangefull)
    {
        while ($($pool.GetAvailableRunspaces()) -le 0) {
            Start-Sleep -milliseconds 500
        }
    
        # create a "powershell pipeline runner"   
        $ps += [powershell]::create()

        # assign our pool of 3 runspaces to use   
        $ps[$i].runspacepool = $pool

        # command to run
        [void]$ps[$i].AddScript($runme)
        [void]$ps[$i].AddParameter('IPAddress', $endpoint)
        [void]$ps[$i].AddParameter('Creds', $getcreds) 
        [void]$ps[$i].AddParameter('Allshares', $Allshares) 
        [void]$ps[$i].AddParameter('Command', $Command)   
        # start job
        $jobs += $ps[$i].BeginInvoke();
     
        # store wait handles for WaitForAll call   
        $wait += $jobs[$i].AsyncWaitHandle
    
        $i++
    }
     
    Write-Output 'Waiting for scanning threads to finish...' -ForegroundColor Cyan

    $waitTimeout = get-date

    while ($($jobs | Where-Object {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) {
            Start-Sleep -milliseconds 500
        } 
  
    # end async call   
    for ($y = 0; $y -lt $i; $y++) {     
  
        try {   
            # complete async job   
            $endpointResults += $ps[$y].EndInvoke($jobs[$y])   
  
        } catch {   
       
            # oops-ee!   
            write-warning "error: $_"  
        }
    
        finally {
            $ps[$y].Dispose()
        }     
    }

    $pool.Dispose()
    
    #Statistics
    $end = get-date
    $totaltime = $end - $start

    Write-Output "We scanned $($iprangefull.count) endpoints in $($totaltime.totalseconds) seconds" -ForegroundColor green
    $endpointResults
}
