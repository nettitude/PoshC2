function Get-MSHotFixes
{
<#
.Synopsis
Cmdlet to retrive the install Microsoft hotfixes
.Description
The cmdlet retrives all installled Microsoft hotfixes using WMI, specifically Win32_QuickFixEngineering class
Previously this was achieved by executing 'wmic qfe list' via Invoke-Expression, however this produced a pop-up window and Invoke-Expression could trigger various warnings or alerts.

Version 1.0

.Example
Get-MSHotfixes

Description     HotfixID  caption                                    InstalledOn        
-----------     --------  -------                                    -----------        
Security Update KB3200970 http://support.microsoft.com/?kbid=3200970 18/11/2016 00:00:00
Security Update KB3202790 http://support.microsoft.com/?kbid=3202790 17/11/2016 00:00:00
Update          KB3199986 http://support.microsoft.com/?kbid=3199986 03/11/2016 00:00:00
Update          KB2693643                                            02/11/2016 00:00:00
Update          KB3199209 http://support.microsoft.com/?kbid=3199209 18/10/2016 00:00:00
Update          KB3176936 http://support.microsoft.com/?kbid=3176936 24/08/2016 00:00:00

Retrive all installed hotfixes

.Example
Get-MSHotFixes | Where-Object -Property hotfixid -EQ KB3176936

Description HotfixID  caption                                    InstalledOn        
----------- --------  -------                                    -----------        
Update      KB3176936 http://support.microsoft.com/?kbid=3176936 24/08/2016 00:00:00

Determine if a specific patch is installed for later versions of Powershell

.Example
Get-MSHotFixes | Where-Object {$_.hotfixid -eq "KB2852386"}
Description                            HotfixID                              Caption                               InstalledOn                          
-----------                            --------                              -------                               -----------                          
Update                                 KB2852386                             http://support.microsoft.com/?kbid... 14/11/2016 00:00:00    

This is for PowerShell v2.0 installed on Windows 7


#>

$hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering
$hotfixes | Select-Object -Property Description, HotfixID, Caption,@{l="InstalledOn";e={[DateTime]::Parse($_.psbase.properties["installedon"].value,$([System.Globalization.CultureInfo]::GetCultureInfo("en-US")))}} | Sort-Object -Descending InstalledOn
}
