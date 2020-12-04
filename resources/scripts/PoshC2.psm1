
$PoshC2DockerImage="m0rv4i/poshc2"

Function Build-PoshC2DockerImage {
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

    Build-PoshC2DockerImage -PoshC2Dir C:\PoshC2 -NoCache
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$PoshC2Dir,
        [switch]$NoCache
    )

    Write-Verbose "[+] Ensure .sh files use LF instead of CRLF"
    Get-ChildItem -Path $PoshC2Dir -File -Recurse | Where-Object {$_.Extension -eq '.sh'} | ForEach-Object {
        $Content = Get-Content -Raw -Path $_.FullName
        $Content -Replace "`r`n","`n" | Set-Content -Path $_.FullName -NoNewline -Force
    }

    If($NoCache) {
        docker build -t $PoshC2DockerImage $PoshC2Dir --no-cache
    } Else {
        docker build -t $PoshC2DockerImage $PoshC2Dir
    }
}; Set-Alias posh-docker-build Build-PoshC2DockerImage

Function Clean-PoshC2DockerState {
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
    [CmdletBinding()]
    Param(
        [switch]$Force
    )

    If($Force){
        docker system prune -f
        Return
    }

    Write-Output "Do a full docker system prune, cleaning up all unused images & containers?"
    Write-Output "*** This includes anything none-PoshC2 related. ***"

    $confirmation = Read-Host "Would you like to do a clean? y/N"

    if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
        docker system prune -f
    }
}; Set-Alias posh-docker-clean Clean-PoshC2DockerState

Function Start-PoshC2DockerServer {
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

    .PARAMETER LocalPoshC2ProjectDir

    The local path that is/will be used as the Project Directory for PoshC2.

    .PARAMETER PoshC2Port

    The Port that the PoshC2 server binds to, defaults to 443.

    .PARAMETER DockerTag

    The tag of the Docker container to use, defaults to 'latest' (master)

    .EXAMPLE

    Start-PoshC2DockerServer -PoshC2Dir "C:\PoshC2" -LocalPoshC2ProjectDir "C:\PoshC2_Project"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$PoshC2Dir,
        [Parameter(Mandatory=$true)]
        [string]$LocalPoshC2ProjectDir,
        [int]$PoshC2Port = 443,
        [string]$DockerTag = "latest"

    )

    docker run --rm -p "$("$($PoshC2Port):$($PoshC2Port)")" -v "$("$($LocalPoshC2ProjectDir):/var/poshc2")" "$($PoshC2DockerImage):$($DockerTag)" /usr/local/bin/posh-server
}; Set-Alias posh-server Start-PoshC2DockerServer

Function Start-PoshC2DockerHandler {
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

    .PARAMETER LocalPoshC2ProjectDir

    The local path that is/will be used as the Project Directory for PoshC2.

    .PARAMETER User

    The user to login as in the ImplantHandler.

    .PARAMETER DockerTag

    The tag of the Docker container to use, defaults to 'latest' (master)
    
    .EXAMPLE

    Start-PoshC2DockerHandler -PoshC2Dir "C:\PoshC2" -PoshC2ProjectDir "C:\PoshC2_Project" -User CrashOverride
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$PoshC2Dir,
        [Parameter(Mandatory=$true)]
        [string]$LocalPoshC2ProjectDir,
        [string]$User = "",
        [string]$DockerTag = "latest"
    )

    docker run -ti --rm -v "$("$($LocalPoshC2ProjectDir):/var/poshc2")" "$($PoshC2DockerImage):$($DockerTag)" /usr/local/bin/posh -u "$User"

}; Set-Alias posh Start-PoshC2DockerHandler


Function Start-PoshC2DockerProject {
    <#
    .SYNOPSIS

    Runs the PoshC2 Project Script in Docker.

    Author: @m0rv4i
    License: BSD 3-Clause
    Required Dependencies: Docker Install
    Optional Dependencies: None

    .DESCRIPTION

    Runs the PoshC2 Project Script in Docker.

    .PARAMETER PoshC2Dir

    Specifies the path to the PoshC2 installation which will be built.

    .PARAMETER LocalPoshC2ProjectDir

    The local path that is/will be used as the Project Directory for PoshC2.

    .PARAMETER DockerTag

    The tag of the Docker container to use, defaults to 'latest' (master)
    
    .EXAMPLE

    Start-PoshC2DockerProject -PoshC2Dir "C:\PoshC2" -PoshC2ProjectDir "C:\PoshC2_Project" -Arg1 "-n" -Arg2 "newproject"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$PoshC2Dir,
        [Parameter(Mandatory=$true)]
        [string]$LocalPoshC2ProjectDir,
        [string]$DockerTag = "latest",
        [Parameter(Mandatory=$true)]
        [string]$Arg1 = "",
        [string]$Arg2 = ""
    )

    docker run -ti --rm -v "$("$($LocalPoshC2ProjectDir):/var/poshc2")" "$($PoshC2DockerImage):$($DockerTag)" /usr/local/bin/posh-project $($Arg1) $($Arg2)

}; Set-Alias posh-project Start-PoshC2DockerProject


Function Start-PoshC2DockerConfig {
    <#
    .SYNOPSIS

    Runs the PoshC2 Project Config in Docker.

    Author: @m0rv4i
    License: BSD 3-Clause
    Required Dependencies: Docker Install
    Optional Dependencies: None

    .DESCRIPTION

    Runs the PoshC2 Project Config in Docker.

    .PARAMETER PoshC2Dir

    Specifies the path to the PoshC2 installation which will be built.

    .PARAMETER LocalPoshC2ProjectDir

    The local path that is/will be used as the Project Directory for PoshC2.

    .PARAMETER DockerTag

    The tag of the Docker container to use, defaults to 'latest' (master)
    
    .EXAMPLE

    Start-PoshC2DockerConfig -PoshC2Dir "C:\PoshC2" -PoshC2ProjectDir "C:\PoshC2_Project"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$PoshC2Dir,
        [Parameter(Mandatory=$true)]
        [string]$LocalPoshC2ProjectDir,
        [string]$DockerTag = "latest"
    )

    docker run -ti --rm -v "$("$($LocalPoshC2ProjectDir):/var/poshc2")" "$($PoshC2DockerImage):$($DockerTag)" /usr/local/bin/posh-config

}; Set-Alias posh-config Start-PoshC2DockerConfig