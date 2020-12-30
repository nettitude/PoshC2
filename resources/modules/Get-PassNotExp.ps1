<#
.Synopsis
    Identify accounts with passwords set not to expire
.DESCRIPTION
	Searches Active Directory for user accounts the have the flag set to allow the password never to expire
.EXAMPLE
    PS C:\> Pass-NotExp
#>
function Get-PassNotExp
{
$strFilter = '(&(objectCategory=User)(userAccountControl:1.2.840.113556.1.4.803:=65536))'
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.PageSize = 1000
$objSearcher.Filter = $strFilter
$colProplist = 'name'
Write-Output 'Users with Password set NOT to Expire'
Write-Output '====================================='
foreach ($i in $colPropList){$objSearcher.PropertiesToLoad.Add($i)} 
$colResults = $objSearcher.FindAll()
foreach ($objResult in $colResults) 
    {$objItem = $objResult.Properties; $objItem.name}
}
