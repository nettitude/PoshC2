Function Get-RecentFiles {
    $obj = New-Object -ComObject WScript.Shell
    $Path = [System.Environment]::GetFolderPath('Recent')
    $files = Get-ChildItem -Path $Path | Sort-Object LastAccessTime | Select-Object -Last 50
    echo "" 
    echo "[+] Get-RecentFiles"
    echo ""
    foreach ($file in $files)
    {
        $extn = [IO.Path]::GetExtension($file)
        if ($extn -eq ".lnk" )
        {
          try {
            $lnk = $file.versioninfo.filename
            $lnkfile = $obj.CreateShortcut($lnk).TargetPath
            if ($lnkfile) {
                echo $lnkfile
            }
          } catch {}
        }
    }
}
