function Invoke-URLCheck {
    Param (
        [Parameter(Mandatory = $true)]
        [array]$urls,
        [Parameter(Mandatory = $true)]
        [array]$domainfront,
        [Parameter(Mandatory = $true)]
        [string]$uri,
        [Parameter(Mandatory = $false)]
        [string]$proxyurl,
        [Parameter(Mandatory = $false)]
        [string]$username,
        [Parameter(Mandatory = $false)]
        [string]$password
        )
    
    function Test-Webclient() {

        $username = ""
        $password = ""
        $proxyurl = ""

        $wc = New-Object System.Net.WebClient;

        if ($script:hostheader -and (($psversiontable.CLRVersion.Major -gt 2))) 
        {
            $wc.Headers.Add("Host",$script:hostheader)
        }
        elseif($script:hostheader)
        {
            $script:srv="https://$($script:hostheader)$uri";$script:sconnect="https://$($script:hostheader)"
        }

        $wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko")
        $wc.Headers.Add("Referer",$script:sconnect)
        
        if ($proxyurl) 
        {
            $wp = New-Object System.Net.WebProxy($proxyurl,$true);
            if ($username -and $password) 
            {
                $PSS = ConvertTo-SecureString $password -AsPlainText -Force;
                $getcreds = new-object system.management.automation.PSCredential $username,$PSS;
                $wp.Credentials = $getcreds;
            } 
            else 
            { 
                $wc.UseDefaultCredentials = $true; 
            }
            $wc.Proxy = $wp; 
        } 
        else 
        {
            $wc.UseDefaultCredentials = $true;
            $wc.Proxy.Credentials = $wc.Credentials;
        }
        $wc 

    }

    function startprimer($url,$uri,$domainfront) 
    {
        $script:srv=$url+$uri
        $script:sconnect=$url
        $script:hostheader=$domainfront
        (Test-Webclient).downloadstring($script:srv)    
    }
    
    $uri = $uri+"?lang=1c400cee-081e-4898-977e-c984dcc1a8ba"

    foreach($url in $urls)
    {
        $index = [array]::IndexOf($urls, $url)
        try 
        {
            startprimer $url $uri $domainfront[$index]
        } 
        catch 
        {
            write-output $error[0]
        }
    }

}
