# https://gallery.technet.microsoft.com/scriptcenter/IPConfig-all-cfe08dc0

function Get-Ipconfig {

$array= @()
  
$wmi=Get-WmiObject win32_ComputerSystem
  
$obj=New-Object PSObject
  
$obj |Add-Member -MemberType NoteProperty -Name "ComputerName" $wmi.Name
 
# Finding the Network Adapter and MAC Address, DHCP Server
  
$wmi=Get-WmiObject win32_networkadapterconfiguration | where {$_.Ipenabled -Match "True"}
$obj |Add-Member -MemberType NoteProperty -Name "IPAddress" $wmi.IPAddress
$obj |Add-Member -MemberType NoteProperty -Name "NetworkAdapter" $wmi.description
$obj |Add-Member -MemberType NoteProperty -Name "MACAddress" $wmi.macaddress
$obj |Add-Member -MemberType NoteProperty -Name "DefaultGateway" $wmi.DefaultIPGateway
$obj |Add-Member -MemberType NoteProperty -Name "DHCPServer" $wmi.DHCPServer
$obj |Add-Member -MemberType NoteProperty -Name "DHCPEnabled" $wmi.DHCPEnabled
$obj |Add-Member -MemberType NoteProperty -Name "SubnetMask" $wmi.IPSubnet
$obj |Add-Member -MemberType NoteProperty -Name "DNSServer" $wmi.DnsServerSearchOrder
$obj |Add-Member -MemberType NoteProperty -Name "WinsPrimaryServer" $wmi.WinsPrimaryServer
$obj |Add-Member -MemberType NoteProperty -Name "WinsSecondaryServer" $wmi.WinsSecondaryServer
$array +=$obj

echo "[+] IPConfig "
echo $array

}
