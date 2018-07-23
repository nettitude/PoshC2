<#
        .Synopsis
        Returns members of the Local Admins group
        .DESCRIPTION
        Retrieves all computers from Active Direcrory and searches and returns the members of the Local Admins group
        .EXAMPLE
        PS C:\> Get-LocAdm
    
#>
Function Get-LocAdm
{
    $DirSearcher = New-Object -TypeName DirectoryServices.DirectorySearcher -ArgumentList ([ADSI]'')
    $DirSearcher.Filter = '(objectClass=computer)'
    $Computers = $DirSearcher.Findall()
    Foreach ($Computer in $Computers)
    {
        $Path = $Computer.Path
        $Name = ([ADSI]"$Path").Name
        Write-Output  -InputObject $Name
        Write-Output -InputObject 'Members of the Local Admins group'
        Write-Output -InputObject '================================='
        $members = [ADSI]"WinNT://$Name/Administrators"
        $members = @($members.psbase.Invoke('Members'))
        $members | ForEach-Object -Process {
            $_.GetType().InvokeMember('Name', 'GetProperty',
            $null, $_, $null)
        }
        Write-Output -InputObject `n
    }
}
