<#
.Synopsis
    Retrives the default active directory password policy
.DESCRIPTION
	Retrives the default active directory password policy
.EXAMPLE
    PS C:\> Pass-Pol
    Output the default domain password policy
#>
function Get-PassPol
{
	$domain = [ADSI]"WinNT://$env:userdomain"
	$Name = @{Name='DomainName';Expression={$_.Name}}
	$MinPassLen = @{Name='Minimum Password Length (Chars)';Expression={$_.MinPasswordLength}}
	$MinPassAge = @{Name='Minimum Password Age (Days)';Expression={$_.MinPasswordAge.value/86400}}
	$MaxPassAge = @{Name='Maximum Password Age (Days)';Expression={$_.MaxPasswordAge.value/86400}}
	$PassHistory = @{Name='Enforce Password History (Passwords remembered)';Expression={$_.PasswordHistoryLength}}
	$AcctLockoutThreshold = @{Name='Account Lockout Threshold (Invalid logon attempts)';Expression={$_.MaxBadPasswordsAllowed}}
	$AcctLockoutDuration =  @{Name='Account Lockout Duration (Minutes)';Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
	$ResetAcctLockoutCounter = @{Name='Reset Account Lockout Counter After (Minutes)';Expression={$_.LockoutObservationInterval.value/60}}
	$domain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter
}
$PassPol = Get-PassPol
Write-Output 'Domain Password Policy: '
Write-Output $PassPol
