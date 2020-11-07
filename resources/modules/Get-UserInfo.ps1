function Get-UserInfo
{
  Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
  $arr = @()
  $Users = Get-WmiObject -Query "Select * from Win32_UserAccount Where LocalAccount = True"
  echo ""
  echo "======================"
  echo "Local Users"
  echo "======================"
  foreach ($usr in $Users) {
    $usr.Name
  }
  $GroupNames = Get-WmiObject -Query "SELECT * FROM Win32_Group Where LocalAccount = True"
  echo ""
  echo "======================"
  echo "Local Groups"
  echo "======================"
  foreach ($grp in $GroupNames) {
    $grp.Name
  }

  $hostname = (Get-WmiObject -Class Win32_ComputerSystem).Name
  echo ""
  echo "======================"
  echo "Members of Local Groups"
  echo "======================"

  foreach ($Group in $GroupNames) {
    $GroupName = $Group.Name
    $wmi = Get-WmiObject -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$Hostname',Name='$GroupName'`""

    if ($wmi -ne $null)
    {
      foreach ($item in $wmi)
      {
          $data = $item.PartComponent -split "\,"
          $domain = ($data[0] -split "=")[1]
          $name = ($data[1] -split "=")[1]
          $arr += ("$domain\$name").Replace("""","")
          [Array]::Sort($arr)
      }
    }
    if ($arr.Count -gt 0) {
        echo ""
        echo $GroupName
        echo "======================"
        echo $arr
    }
    $arr = @()
  }
}
