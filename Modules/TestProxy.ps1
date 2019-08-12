function TestProxy ($url,$proxy_url,$username,$password) {
    $wc = New-Object System.Net.WebClient;
    $wp = New-Object System.Net.WebProxy($proxy_url,$true)
    $wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko")
    #$wc.Headers.Add("Referer","")
    $wc.Proxy=$wp;
    if ($username) {
        $PSS = ConvertTo-SecureString $password -AsPlainText -Force; 
        $getcreds = new-object system.management.automation.PSCredential $username,$PSS; 
        $wp.Credentials = $getcreds;
    }
    $wc.downloadstring($url)
}
