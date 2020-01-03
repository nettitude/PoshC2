function SSLInspectionCheck($url, $proxyurl, $proxyuser, $proxypass){

    $expiration = $null
    $certName = $null
    $certPublicKeyString = $null
    $certSerialNumber = $null
    $certThumbprint = $null
    $certEffectiveDate = $null
    $certIssuer = $null
    
    write-output "Checking $($url)"
    $req = [Net.HttpWebRequest]::Create($url)
    $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
    if ($proxyurl) {
        $wp = New-Object System.Net.WebProxy($proxyurl,$true)
        $req.Proxy=$wp;
    }
    if ($proxyuser) {
        $PSS = ConvertTo-SecureString $proxypass -AsPlainText -Force; 
        $getcreds = new-object system.management.automation.PSCredential $proxyuser,$PSS; 
        $wp.Credentials = $getcreds;
    }
    
    $req.timeout = 10000
    
    try {
        $req.GetResponse() |Out-Null
    } catch {
        write-output "Exception while checking URL $($url)`: $($_)"
    }
    
    $expiration = $req.ServicePoint.Certificate.GetExpirationDateString()
    $certName = $req.ServicePoint.Certificate.GetName()
    $certPublicKeyString = $req.ServicePoint.Certificate.GetPublicKeyString()
    $certSerialNumber = $req.ServicePoint.Certificate.GetSerialNumberString()
    $certThumbprint = $req.ServicePoint.Certificate.GetCertHashString()
    $certEffectiveDate = $req.ServicePoint.Certificate.GetEffectiveDateString()
    $certIssuer = $req.ServicePoint.Certificate.GetIssuerName()
    write-output "Cert for site $($url). Check details:`n`nCert name: $($certName)`nCert public key: $($certPublicKeyString)`nCert serial number: $($certSerialNumber)`nCert thumbprint: $($certThumbprint)`nCert effective date: $($certEffectiveDate)`nCert Expiry: $($expiration)`nCert issuer: $($certIssuer)"
    rv req
    
}
