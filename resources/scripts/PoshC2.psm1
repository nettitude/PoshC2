<#
.SYNOPSIS

Builds the PoshC2 Docker image from the PoshC2 installation at the provided path.

Author: @m0rv4i
License: BSD 3-Clause
Required Dependencies: Docker Install
Optional Dependencies: None

.DESCRIPTION

A simple wrapper around the docker build command which specifies the tag name.

.PARAMETER PoshC2Dir

Specifies the path to the PoshC2 installation which will be built.

.PARAMETER NoCache

A switch which specifices that the image should be built without using any cached layers in Docker. 

.EXAMPLE

Build-PoshC2DockerImage -PoshC2Path C:\PoshC2 -NoCache
#>
Function Build-PoshC2DockerImage 
{

    [CmdletBinding()]
    params(
        [Parameter(Mandatory=$true)]
        [string] PoshC2Dir,
        [switch] NoCache
    )

    if($NoCache)
    {
        docker build -t nettitude/poshc2 $PoshC2Dir --no-cache
    } else {
        docker build -t nettitude/poshc2 $PoshC2Dir
    }
}

<#
.SYNOPSIS

Cleans the Docker cache to free space.

Author: @m0rv4i
License: BSD 3-Clause
Required Dependencies: Docker Install
Optional Dependencies: None

.DESCRIPTION

A simple wrapper around the Docker system prune command which prints a message and prompts for
confirmation before cleaning all images & containers in the Docker cache - including none PoshC2 items.

The Force flag can be added to skip the check.

.PARAMETER Force

A switch which skips the confirmation prompt.

.EXAMPLE

Clean-PoshC2DockerState 
#>
Function Clean-PoshC2DockerState 
{

    [CmdletBinding()]
    params(
        [switch] Force
    )

    if($Force){
        docker system prune -f
        return
    }

    Write-Output "Do a full docker system prune, cleaning up all unused images & containers?"
    Write-Output "*** This includes anything none-PoshC2 related. ***"

    $confirmation = Read-Host "Would you like to do a clean? y/N"

    if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
        docker system prune -f 
    }
}

<#
.SYNOPSIS

Runs the PoshC2 C2 Server in Docker.

Author: @m0rv4i
License: BSD 3-Clause
Required Dependencies: Docker Install
Optional Dependencies: None

.DESCRIPTION

Runs the PoshC2 C2 Server in Docker.

.PARAMETER PoshC2Dir

Specifies the path to the PoshC2 installation which will be built.

.PARAMETER PoshC2ProjectDir

The path that is/will be used as the Project Directory for PoshC2.

.PARAMETER PoshC2Port

The Port that the PoshC2 server binds to, defaults to 443.

.EXAMPLE

Invoke-PoshC2DockerServer -PoshC2Path C:\PoshC2 -PoshC2ProjectDir C:\PoshC2_Project
#>
Function Invoke-PoshC2DockerServer {

    [CmdletBinding()]
    params(
        [Parameter(Mandatory=$true)]
        [string] PoshC2Dir,
        [Parameter(Mandatory=$true)]
        [string] PoshC2ProjectDir,
        [int] PoshC2Port = 443
        
    )

    docker run -ti --rm -p "$PoshC2Port:$PoshC2Port" -v "$PoshC2ProjectDir:$PoshC2ProjectDir" -v "$PoshC2Dir:/opt/PoshC2" nettitude/poshc2 /usr/bin/posh-server
}

<#
.SYNOPSIS

Runs the PoshC2 ImplantHandler in Docker.

Author: @m0rv4i
License: BSD 3-Clause
Required Dependencies: Docker Install
Optional Dependencies: None

.DESCRIPTION

Runs the PoshC2 ImplantHandler in Docker.

.PARAMETER PoshC2Dir

Specifies the path to the PoshC2 installation which will be built.

.PARAMETER PoshC2ProjectDir

The path that is/will be used as the Project Directory for PoshC2.

.PARAMETER User

The user to login as in the ImplantHandler.x

.EXAMPLE

Invoke-PoshC2DockerHandler -PoshC2Path C:\PoshC2 -PoshC2ProjectDir C:\PoshC2_Project -User CrashOverride
#>
Function Invoke-PoshC2DockerHandler {

    [CmdletBinding()]
    params(
        [Parameter(Mandatory=$true)]
        [string] PoshC2Dir,
        [Parameter(Mandatory=$true)]
        [string] PoshC2ProjectDir,
        [string] User = ""
    )

    docker run -ti --rm -v "$PoshC2ProjectDir:$PoshC2ProjectDir" -v "$PoshC2Dir:/opt/PoshC2" nettitude/poshc2 /usr/bin/posh -u "$User"
}

<#
.SYNOPSIS

Updates the PoshC2 installation.

Author: @m0rv4i
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Updates the PoshC2 installation.

.PARAMETER PoshC2Dir

Specifies the path to the PoshC2 installation which will be built.

.EXAMPLE

Update-PoshC2 -PoshC2Dir C:\PoshC2
#>
Function Update-PoshC2 {

    [CmdletBinding()]
    params(
        [Parameter(Mandatory=$true)]
        [string] PoshC2Dir
    )
    
    
    Write-Output  """
       __________            .__.     _________  ________
       \_______  \____  _____|  |__   \_   ___ \ \_____  \\
        |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/
        |    |  (  <_> )___ \|   Y  \ \     \____/       \\
        |____|   \____/____  >___|  /  \______  /\_______ \\
                           \/     \/          \/         \/
        ================= www.PoshC2.co.uk ================"""

    Write-Output ""
    Write-Output "[+] Updating PoshC2"
    Write-Output ""

    Push-Location "$PoshC2Dir"

    Write-Output ""
    Write-Output "[+] Saving changes to Config.py"
    Write-Output ""
    git diff Config.py >> $env:Temp\PoshC2_Config_Diff.git

    Write-Output ""
    Write-Output "[+] Updating Posh Installation to latest master"
    git fetch
    git reset --hard origin/master

    Write-Output ""
    Write-Output "[+] Creating docker image"
    posh-docker-build

    Write-Output ""
    Write-Output "[+] Re-applying Config file changes"
    git apply $env:Temp\PoshC2_Config_Diff.git

    if($?)
    {
        Remote-Item $env:Temp\PoshC2_Config_Diff.git
    } 
    else
    {
        Write-Output "[-] Re-applying Config file changes failed, please merge manually from /tmp/PoshC2_Config_Diff.git"
    } 

    Pop-Location

    Write-Output ""
    Write-Output "[+] Update complete"
    Write-Output ""
}

Export-ModuleMember -Function Build-PoshC2DockerImage -Alias posh-docker-build,
Export-ModuleMember -Function Clean-PoshC2DockerState -Alias posh-docker-clean
Export-ModuleMember -Function Invoke-PoshC2DockerServer -Alias posh-docker-server
Export-ModuleMember -Function Invoke-PoshC2DockerHandler -Alias posh-docker
Export-ModuleMember -Function Update-PoshC2  -Alias posh-update
