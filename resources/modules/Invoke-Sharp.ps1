<#
.Synopsis
    Execute Sharp Assembly in PowerhShell
.DESCRIPTION
    Execute Sharp Assembly in PowerhShell
.EXAMPLE
    PS C:\> Invoke-Sharp -asmName "ASMNAME" -asmArgs @("--listAll", "local", "\")
.EXAMPLE    
    PS C:\> Invoke-Sharp -asmName "ASMNAME" -asmArgs @("--addTask", "local", "09:30", "\", "TaskName", "Task Description", "C:\Windows\system32\cmd.exe", "/c calc.exe")
#>
function Invoke-Sharp {
    param (
        [string]$asmName,
        [string[]]$asmArgs
    )
    $sw = New-Object System.IO.StringWriter
    $originalOut = [Console]::Out
    try {
        [Console]::SetOut($sw)
        $asm = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq $asmName }
        if ($asm -and $asm.EntryPoint) {
            echo "[+] Found Assembly"
            $asm.EntryPoint.Invoke($null, @(, $asmArgs))
        } else {
            echo "[-] Assembly Not Found"
        }
    } finally {
    	$sw.Flush()
        [Console]::SetOut($originalOut)
    }
    $output = $sw.ToString()
    $sw.Close()
    return $output
}
function List-Assemblies {
    [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.FullName }
}