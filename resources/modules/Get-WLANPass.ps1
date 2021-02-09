function Get-WLANPass
{
<#
.Synopsis
    Retrives password from stored wlan profiles
.DESCRIPTION
	Retrives password from stored wlan profiles
.EXAMPLE
    PS C:\> Get-WLANPass
    Output stored WLAN Profile passwords
#>
$netsh = (netsh wlan show profiles)
$netsh | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize
}
