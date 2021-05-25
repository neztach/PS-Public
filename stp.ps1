#Requires -Version 5.1

<#
        .SYNOPSIS
        Installation script for PowerShell managing solution hosted at https://github.com/ztrhgf/Powershell_CICD_repository
        Contains same steps as described at https://github.com/ztrhgf/Powershell_CICD_repository/blob/master/1.%20HOW%20TO%20INSTALL.md
        .DESCRIPTION
        Installation script for PowerShell managing solution hosted at https://github.com/ztrhgf/Powershell_CICD_repository
        Contains same steps as described at https://github.com/ztrhgf/Powershell_CICD_repository/blob/master/1.%20HOW%20TO%20INSTALL.md
        .PARAMETER noEnvModification
        Switch to omit changes of your environment i.e. just customization of cloned folders content 'repo_content_set_up' will be made.
        .PARAMETER iniFile
        Path to text ini file that this script uses as storage for values the user entered during this scripts run.
        So next time, they can be used to speed up whole installation process.
        Default is "Powershell_CICD_repository.ini" in root of user profile, so it can't be replaced when user reset cloned repository etc.
        .NOTES
        Author: Ondřej Šebela - ztrhgf@seznam.cz
#>

[CmdletBinding()]
Param (
    [switch]$noEnvModification,
    [string]$iniFile = (Join-Path -Path $env:USERPROFILE -ChildPath 'Powershell_CICD_repository.ini')
)

Begin {
    #region Variables
    $isserver = $notadmin = $notadadmin = $noadmodule = $nogpomodule = $skipad = $skipgpo = $mgmserver = $accessdenied = $repositoryhostsession = $mgmserversession = 0
    $Host.UI.RawUI.Windowtitle = 'Installer of PowerShell CI/CD solution'

    $transcript             = Join-Path -Path $env:USERPROFILE -ChildPath ((Split-Path -Path $PSCommandPath -Leaf) + '.log')
    Start-Transcript -Path $transcript -Force

    $ErrorActionPreference  = 'Stop'

    # char that is between name of variable and its value in ini file
    $divider                = '='

    # list of variables needed for installation, will be saved to iniFile 
    $setupVariable          = @{}

    # name of GPO that will be used for connecting computers to this solution
    $GPOname                = 'PS_env_set_up'

    # hardcoded PATHs for TEST installation
    $repositoryShare        = "\\$env:COMPUTERNAME\repositoryShare"
    $repositoryShareLocPath = Join-Path -Path $env:SystemDrive -ChildPath 'repositoryShare'
    $remoteRepository       = Join-Path -Path $env:SystemDrive -ChildPath 'myCompanyRepository_remote'
    $userRepository         = Join-Path -Path $env:SystemDrive -ChildPath 'myCompanyRepository'
    #endregion Variables

    ### Detect if Server
    If ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -in (2, 3)) {$isServer++}

    #region helper functions
    Function Step-pressKeyToContinue {
        Write-Host "`nPress any key to continue" -NoNewline
        $null = [Console]::ReadKey('?')
    }

    Function Step-continue {
        [CmdletBinding()]
        Param ([string]$text, [switch]$passthru)

        $t = 'Continue? (Y|N)'
        If ($text) {$t = "$text. $t"}

        $choice = ''
        While ($choice -notmatch '^[Y|N]$') {$choice = Read-Host -Prompt $t}
        If ($choice -eq 'N') {
            If ($passthru) {Return $choice} else {break}
        }
        if ($passthru) {Return $choice}
    }

    Function Step-skip {
        [CmdletBinding()]
        Param ([string]$text)

        $t = 'Skip? (Y|N)'
        If ($text) {$t = "$text. $t"}
        $t = "`n$t"

        $choice = ''
        While ($choice -notmatch '^[Y|N]$') {$choice = Read-Host -Prompt $t}
        If ($choice -eq 'N') {Return $false} else {Return $true}
    }

    Function Step-getComputerMembership {
        # Pull the gpresult for the current server
        $Lines   = & "$env:windir\system32\gpresult.exe" /s $env:COMPUTERNAME /v /SCOPE COMPUTER

        # Initialize arrays
        $cgroups = @()

        # Out equals false by default
        $Out     = $False

        # Define start and end lines for the section we want
        $start   = 'The computer is a part of the following security groups'
        $end     = 'Resultant Set Of Policies for Computer'

        # Loop through the gpresult output looking for the computer security group section
        ForEach ($Line In $Lines) {
            If ($Line -match $start) {$Out      = $True}
            If ($Out -eq $True)      {$cgroups += $Line}
            If ($Line -match $end)   {Break}
        }
        $cgroups | ForEach-Object { $_.trim() }
    }

    Function Step-startProcess {
        [CmdletBinding()]
        param (
            [string]$filePath         = '',
            [string]$argumentList     = '',
            [string]$workingDirectory = (Get-Location),
            [switch]$dontWait,
            # lot of git commands output verbose output to error stream
            [switch]$outputErr2Std
        )

        $p = New-Object -TypeName System.Diagnostics.Process
        $p.StartInfo.UseShellExecute        = $false
        $p.StartInfo.RedirectStandardOutput = $true
        $p.StartInfo.RedirectStandardError  = $true
        $p.StartInfo.WorkingDirectory       = $workingDirectory
        $p.StartInfo.FileName               = $filePath
        $p.StartInfo.Arguments              = $argumentList
        [void]$p.Start()
        If (!$dontWait) {$p.WaitForExit()}
        $p.StandardOutput.ReadToEnd()
        If ($outputErr2Std) {
            $p.StandardError.ReadToEnd()
        } Else {
            If ($err = $p.StandardError.ReadToEnd()) {Write-Error -Message $err}
        }
    }

    Function Step-SetVariable {
        # function defines variable and fills it with value find in ini file or entered by user
        [CmdletBinding()]
        Param ([string]$variable,[string]$readHost,[switch]$optional,[switch]$passThru)

        $value = $setupVariable.GetEnumerator() | Where-Object {$_.name -eq $variable -and $_.value} | Select-Object -ExpandProperty value
        If (!$value) {
            If ($optional) {
                $value = Read-Host -Prompt "    - (OPTIONAL) Enter $readHost"
            } Else {
                While (!$value) {
                    $value = Read-Host -Prompt "    - Enter $readHost"
                }
            }
        } Else {
            '' # Write-Host "   - variable '$variable' will be: $value" -ForegroundColor Gray
        }
        If ($value) {
            # replace whitespaces so as quotes
            $value = $value -replace '^\s*|\s*$' -replace "^[`"']*|[`"']*$"
            $setupVariable.$variable = $value
            New-Variable -Name $variable -Value $value -Scope script -Force -Confirm:$false
        } Else {
            If (!$optional) {Throw "Variable $variable is mandatory!"}
        }

        If ($passThru) {Return $value}
    }

    Function Step-saveInput {
        # call after each successfuly ended section, so just correct inputs will be stored
        If (Test-Path -Path $iniFile -ErrorAction SilentlyContinue) {Remove-Item -Path $iniFile -Force -Confirm:$false}
        $setupVariable.GetEnumerator() | 
        ForEach-Object {
            If ($_.name -and $_.value) {
                $_.name + '=' + $_.value | Out-File -FilePath $iniFile -Append -Encoding utf8
            }
        }
    }

    Function Step-setPermissions {
        [cmdletbinding()]
        Param (
            [Parameter(Mandatory = $true,HelpMessage='Provide Path')][string]$path,
            $readUser,
            $writeUser,
            [switch]$resetACL
        )

        If (!(Test-Path -Path $path)) {Throw "Path isn't accessible"}
        $permissions = @()
        If (Test-Path -Path $path -PathType Container) {
            # it is folder
            $acl = New-Object -TypeName System.Security.AccessControl.DirectorySecurity
            If ($resetACL) {
                # reset ACL, i.e. remove explicit ACL and enable inheritance
                $acl.SetAccessRuleProtection($false, $false)
            } Else {
                # disable inheritance and remove inherited ACL
                $acl.SetAccessRuleProtection($true, $false)

                If ($readUser) {
                    $readUser  | ForEach-Object {
                        $permissions += @(, ("$_", 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
                    }
                }
                If ($writeUser) {
                    $writeUser | ForEach-Object {
                        $permissions += @(, ("$_", 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
                    }
                }
            }
        } Else {
            # it is file
            $acl = New-Object -TypeName System.Security.AccessControl.FileSecurity
            If ($resetACL) {
                # reset ACL, ie remove explicit ACL and enable inheritance
                $acl.SetAccessRuleProtection($false, $false)
            } Else {
                # disable inheritance and remove inherited ACL
                $acl.SetAccessRuleProtection($true, $false)

                If ($readUser) {
                    $readUser  | ForEach-Object {
                        $permissions += @(, ("$_", 'ReadAndExecute', 'Allow'))
                    }
                }
                If ($writeUser) {
                    $writeUser | ForEach-Object {
                        $permissions += @(, ("$_", 'FullControl', 'Allow'))
                    }
                }
            }
        }
        $permissions | ForEach-Object {
            $ace = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $_
            $acl.AddAccessRule($ace)
        }

        Try {
            # Set-Acl cannot be used because of bug https://stackoverflow.com/questions/31611103/setting-permissions-on-a-windows-fileshare
            (Get-Item -Path $path).SetAccessControl($acl)
        } Catch {
            Throw "There was an error when setting NTFS rights: $_"
        }
    }

    Function Step-copyFolder {
        [cmdletbinding()]
        Param (
            [string]$source,
            [string]$destination,
            [string]$excludeFolder = '',
            [switch]$mirror
        )

        Begin {
            [Void][System.IO.Directory]::CreateDirectory($destination)
        }
        Process {
            If ($mirror) {
                $result = & "$env:windir\system32\robocopy.exe" "$source" "$destination" /MIR /E /NFL /NDL /NJH /R:4 /W:5 /XD "$excludeFolder"
            } Else {
                $result = & "$env:windir\system32\robocopy.exe" "$source" "$destination" /E /NFL /NDL /NJH /R:4 /W:5 /XD "$excludeFolder"
            }

            $copied   = 0
            $failures = 0
            $duration = ''
            $deleted  = @()
            $errMsg   = @()

            $result | ForEach-Object {
                If ($_ -match '\s+Dirs\s+:') {
                    $lineAsArray = (($_.Split(':')[1]).trim()) -split '\s+'
                    $copied     += $lineAsArray[1]
                    $failures   += $lineAsArray[4]
                }
                If ($_ -match '\s+Files\s+:') {
                    $lineAsArray = ($_.Split(':')[1]).trim() -split '\s+'
                    $copied     += $lineAsArray[1]
                    $failures   += $lineAsArray[4]
                }
                If ($_ -match '\s+Times\s+:') {
                    $lineAsArray = ($_.Split(':', 2)[1]).trim() -split '\s+'
                    $duration    = $lineAsArray[0]
                }
                If ($_ -match '\*EXTRA \w+') {
                    $deleted    += @($_ | ForEach-Object { ($_ -split '\s+')[-1] })
                }
                If ($_ -match '^ERROR: ') {
                    $errMsg     += ($_ -replace '^ERROR:\s+')
                }
                # captures errors like: 2020/04/27 09:01:27 ERROR 2 (0x00000002) Accessing Source Directory C:\temp
                If ($match = ([regex]'^[0-9 /]+ [0-9:]+ ERROR \d+ \([0-9x]+\) (.+)').Match($_).captures.groups) {
                    $errMsg     += $match[1].value
                }
            }

            Return [PSCustomObject]@{
                'Copied'   = $copied
                'Failures' = $failures
                'Duration' = $duration
                'Deleted'  = $deleted
                'ErrMsg'   = $errMsg
            }
        }
    }

    Function Step-ChooseFile {
        Param ([string]$Title)
        Add-Type -AssemblyName system.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
        $FileBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop') 
        $FileBrowser.Filter           = 'Application (*.exe)|*.exe'
        $FileBrowser.Title            = $Title
        $FileChoice = $FileBrowser.ShowDialog()
 
        If ($FileChoice -eq [System.Windows.Forms.DialogResult]::OK) {
            $EXEPath = $FileBrowser.FileName
        } else {
            $EXEPath = 'NA'
        }
 
        Return $EXEPath#.FileName #$BackupLocation
    }

    Function Step-installGIT {
        $iPath1 = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        $iPath2 = 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        $installedGITVersion = ((Get-ItemProperty -Path $iPath1) + (Get-ItemProperty -Path $iPath2) | Where-Object {$_.DisplayName -and $_.Displayname.Contains('Git version')}) | 
                               Select-Object -ExpandProperty DisplayVersion

        If (!$installedGITVersion -or $installedGITVersion -as [version] -lt '2.27.0') {
            # Get latest download url for git-for-windows 64-bit exe
            $url          = 'https://api.github.com/repos/git-for-windows/git/releases/latest'
            $install_args = '/SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS'
            If ($asset = Invoke-RestMethod -Method Get -Uri $url | ForEach-Object {$_.assets} | Where-Object {$_.name -like '*64-bit.exe'}) {
                ### Download Git Installer File
                Write-Host '      - downloading'
                $installer          = "$env:temp\$($asset.name)"
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $installer 
                $ProgressPreference = 'Continue'
            
                ### Install Git
                Write-Host '      - installing'
                Start-Process -FilePath $installer -ArgumentList $install_args -Wait
                Start-Sleep -Seconds 3

                # update PATH
                $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')
            } Else {
                $Choice = Read-Host -Prompt 'Unable to fetch.  If you previously downloaded, would you like to browse to the installer? [Y/N]'
                If ($Choice -match '[Yy]'){
                    $installer = Step-ChooseFile -Title 'Git-Installer'
                    Start-Process -FilePath $installer -ArgumentList $install_args -Wait
                    Start-Sleep -Seconds 3
                    # update PATH
                    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')
                } Else {
                    Write-Warning -Message "Skipped!`nURL $url isn't accessible, install GIT manually"
                    Step-continue
                }
            }
        } Else {
            Write-Host '      - already installed'
        }
    }

    Function Step-installGITCredManager {
        $ErrorActionPreference = 'Stop'
        $url   = 'https://github.com/Microsoft/Git-Credential-Manager-for-Windows/releases/latest'
        $asset = Invoke-WebRequest -Uri $url -UseBasicParsing
        Try {
            $durl = (($asset.RawContent -split "`n" | Where-Object { $_ -match '<a href="/.+\.exe"' }) -split '"')[1]
        } Catch {
            ''
        }
        If ($durl) {
            ### Downloading Git Credential Manager
            $url       = 'github.com' + $durl
            $installer = "$env:temp\gitcredmanager.exe"
            Write-Host '      - downloading'
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $url -OutFile $installer 
            $ProgressPreference = 'Continue'

            ### Installing Git Credential Manager
            Write-Host '      - installing'
            $install_args = '/VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS'
            Start-Process -FilePath $installer -ArgumentList $install_args -Wait
        } Else {
            Write-Warning -Message "Skipped!`nURL $url isn't accessible, install GIT Credential Manager for Windows manually"
            Step-continue
        }
    }

    Function Step-installVSC {
        ### Test if Microsoft VS Code is already installed
        $codeCmdPath = "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd"
        $codeExePath = "$env:ProgramFiles\Microsoft VS Code\Code.exe"
        If (Test-Path -Path $codeExePath) {
            Write-Host '      - already installed'
            Return
        }

        ### Downloading Microsoft VS Code
        $vscInstaller       = "$env:TEMP\vscode-stable.exe"
        Remove-Item -Force -Path $vscInstaller -ErrorAction SilentlyContinue
        Write-Host '      - downloading'
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri 'https://update.code.visualstudio.com/latest/win32-x64/stable' -OutFile $vscInstaller 
        $ProgressPreference = 'Continue'

        ### Installing Microsoft VS Code
        Write-Host '      - installing'
        $loadInf = '@
            [Setup]
            Lang=english
            Dir=C:\Program Files\Microsoft VS Code
            Group=Visual Studio Code
            NoIcons=0
            Tasks=desktopicon,addcontextmenufiles,addcontextmenufolders,addtopath
        @'
        $infPath = Join-Path -Path $env:TEMP -ChildPath load.inf
        $loadInf | Out-File -FilePath $infPath
        Start-Process -FilePath $vscInstaller -ArgumentList "/VERYSILENT /LOADINF=${infPath} /mergetasks=!runcode" -Wait
    }

    Function Step-createSchedTask {
        [CmdletBinding()]
        Param ($xmlDefinition, $taskName)
        $result = & "$env:windir\system32\schtasks.exe" /CREATE /XML "$xmlDefinition" /TN "$taskName" /F
        If (!$?) {Throw "Unable to create scheduled task $taskName"}
    }

    Function Step-startSchedTask {
        [CmdletBinding()]
        Param ($taskName)
        $result = & "$env:windir\system32\schtasks.exe" /RUN /I /TN "$taskName"
        If (!$?) {Throw "Task $taskName finished with error. Check '$env:SystemRoot\temp\repo_sync.ps1.log'"}
    }

    Function Step-exportCred {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true,HelpMessage='Provide Credentials')][System.Management.Automation.Credential()][System.Management.Automation.PSCredential]$credential,
            [string]$xmlPath = "$env:SystemDrive\temp\login.xml",
            [Parameter(Mandatory = $true,HelpMessage='Credentials to Run As')][string]$runAs
        )

        Begin {
            # transform relative path to absolute
            Try {
                $null    = Split-Path -Path $xmlPath -Qualifier -ErrorAction Stop
            } Catch {
                $xmlPath = Join-Path -Path (Get-Location) -ChildPath $xmlPath
            }

            # remove existing xml
            Remove-Item -Path $xmlPath -ErrorAction SilentlyContinue -Force

            # create destination folder
            [Void][System.IO.Directory]::CreateDirectory((Split-Path -Path $xmlPath -Parent))
        }
        Process {
            $login = $credential.UserName
            $pswd  = $credential.GetNetworkCredential().password

            $command = @"
# just in case auto-load of modules would be broken
Import-Module `$env:windir\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security -ErrorAction Stop
`$pswd       = ConvertTo-SecureString `'$pswd`' -AsPlainText -Force
`$credential = New-Object System.Management.Automation.PSCredential $login, `$pswd
Export-Clixml -inputObject `$credential -Path $xmlPath -Encoding UTF8 -Force -ErrorAction Stop
"@

            # encode as base64
            $bytes         = [System.Text.Encoding]::Unicode.GetBytes($command)
            $encodedString = [Convert]::ToBase64String($bytes)

            #TODO idealne pomoci schtasks aby bylo univerzalnejsi
            $A        = New-ScheduledTaskAction -Argument "-ExecutionPolicy Bypass -NoProfile -EncodedCommand $encodedString" -Execute "$PSHome\powershell.exe"
            If ($runAs -match '\$') {
                # under gMSA account
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType Password
            } Else {
                # under SYSTEM account
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType ServiceAccount
            }
            $S        = New-ScheduledTaskSettingsSet
            $taskName = 'cred_export'
            Try {
                $null = New-ScheduledTask -Action $A -Principal $P -Settings $S -ErrorAction Stop | Register-ScheduledTask -Force -TaskName $taskName -ErrorAction Stop
            } Catch {
                If ($_ -match 'No mapping between account names and security IDs was done') {
                    Throw "Account $runAs doesn't exist or cannot be used on $env:COMPUTERNAME"
                } Else {
                    Throw "Unable to create scheduled task for exporting credentials.`nError was:`n$_"
                }
            }
            Start-Sleep -Seconds 1
            Start-ScheduledTask -TaskName $taskName
            Start-Sleep -Seconds 5
            $result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
            Try {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            } Catch {
                Throw "Unable to remove scheduled task $taskName. Remove it manually, it contains the credentials!"
            }
            If ($result -ne 0) {Throw 'Export of the credentials end with error'}
            If ((Get-Item -Path $xmlPath).Length -lt 500) {
                # sometimes sched. task doesn't end with error, but xml contained gibberish
                Throw 'Exported credentials are not valid'
            }
        }
    }

    Function Test-Administrator {
        <#
                .SYNOPSIS
                Checks if you are running as Administrator.
                .DESCRIPTION
                Tests if you are currently running powershell as administrator.
                .EXAMPLE
                Test-Administrator
                If yes, returns true, if not, returns false
        #>

        If ($PSVersionTable.PSVersion.Major -le 5) {
            $currentUser = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
            Return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }

    #endregion helper functions

    # store function definitions so I can recreate them in scriptblock
    $allFunctionDefs = "Function Step-continue { ${function:Step-continue} };`
        Function Step-pressKeyToContinue { ${function:Step-pressKeyToContinue} };`
        Function Step-skip { ${function:Step-skip} };`
        Function Step-installGIT { ${function:Step-installGIT} };`
        Function Step-installGITCredManager { ${function:Step-installGITCredManager} };`
        Function Step-createSchedTask { ${function:Step-createSchedTask} };`
        Function Step-exportCred { ${function:Step-exportCred} };`
        Function Step-startSchedTask { ${function:Step-startSchedTask} };`
        Function Step-setPermissions { ${function:Step-setPermissions} };`
        Function Step-getComputerMembership { ${function:Step-getComputerMembership} };`
        Function Step-startProcess { ${function:Step-startProcess} }"
}
Process {
    #region initial
    Function Step-OnScreenMSG {
        Param ([int]$z)
        Switch ($z) {
            1 {
                Write-Host "####################################`n#   INSTALL OPTIONS`n####################################" -ForegroundColor Magenta
                Write-Host '1)' -NoNewline -ForegroundColor Yellow;Write-Host ' TEST installation' -ForegroundColor Cyan
                Write-Host '    - PURPOSE : ' -NoNewLine -ForegroundColor Yellow;Write-Host 'Fast and safe test of the features, this solution offers.'
                Write-Host '        - Run this installer on a test computer (preferably VM [Windows Sandbox, Virtualbox, Hyper-V, etc.])'
                Write-Host "        - No prerequisities needed like '" -NoNewLine;Write-Host 'Active Directory' -NoNewLine -ForegroundColor Cyan;Write-Host "' or a '" -NoNewLine;Write-Host 'Cloud Repository' -NoNewLine -ForegroundColor Cyan;Write-Host "'."
                Write-Host '    - GOAL    : ' -NoNewLine -ForegroundColor Yellow;Write-Host 'To have this as simple as possible - Installer automatically:'
                Write-Host '        - Installs VSC, GIT.'
                Write-Host '        - Creates GIT repository in ' -NoNewLine;Write-Host $remoteRepository -NoNewLine -ForegroundColor Cyan;Write-Host '. (and clone it to ' -NoNewLine;Write-Host $userRepository -NoNewLine -ForegroundColor Cyan;Write-Host '.)'
                Write-Host '        - Creates folder ' -NoNewLine;Write-Host $repositoryShareLocPath -NoNewLine -ForegroundColor Cyan;Write-Host ' and shares it as ' -NoNewLine;Write-Host $repositoryShare -NoNewLine -ForegroundColor Cyan;Write-Host '.'
                Write-Host '        - Creates security group repo_reader, repo_writer.'
                Write-Host '        - Creates required scheduled tasks.'
                Write-Host '        - Creates and sets global PowerShell profile.'
                Write-Host "        - Starts VSC editor with your new repository, so you can start your testing immediately. :)`n"
                Write-Host '2)' -NoNewline -ForegroundColor Yellow;Write-Host ' Standard installation (Active Directory needed)' -ForegroundColor Cyan
                Write-Host '    - This script will set up your own GIT repository and your environment by:'
                Write-Host '        - Creating repo_reader, repo_writer AD groups.'
                Write-Host '        - Creates shared folder for serving repository data to clients.'
                Write-Host '        - Customizes generic data from repo_content_set_up folder to match your environment.'
                Write-Host '        - Copies customized data to your repository.'
                Write-Host '        - Sets up your repository: (Activate custom git hooks / Set git user name and email).'
                Write-Host '        - Commit & Push new content of your repository.'
                Write-Host '        - Sets up MGM server: (Copies the Repo_sync folder / Creates Repo_sync scheduled task / Exports repo_puller credentials).'
                Write-Host '        - Copies exported credentials from MGM to local repository, Commmit and Push it.'
                Write-Host "        - Creates a GPO '" -NoNewLine;Write-Host $GPOname -NoNewLine -ForegroundColor Cyan;Write-Host "' that will be used for connecting clients to this solution:"
                Write-Host '            - NOTE: Linking GPO has to be done manually.' -ForegroundColor Yellow
                Write-Host '    - NOTE: Every step has to be explicitly confirmed.' -ForegroundColor Red
                Write-Host '3)' -NoNewline -ForegroundColor Yellow;Write-Host ' Update of existing installation' -ForegroundColor Cyan
                Write-Host '    - NO MODIFICATION OF YOUR ENVIRONMENT WILL BE MADE.' -ForegroundColor Yellow
                Write-Host '        - Just customization of generic data in repo_content_set_up folder to match your environment.'
                Write-Host '            - Merging with your own repository etc has to be done manually.'
            }
            2 {
                Write-Host "####################################`n#   BEFORE YOU CONTINUE`n####################################" -ForegroundColor Magenta
                Write-Host '- Create cloud or locally hosted GIT !private! repository (tested with Azure DevOps but probably will work also with GitHub etc).'
                Write-Host '   - Create READ only account in that repository (repo_puller).'
                Write-Host '       - Create credentials for this account, that can be used in unnatended way (i.e. alternate credentials in Azure DevOps).'
                Write-Host "   - Install the newest version of 'Git' and 'Git Credential Manager for Windows' and clone your repository locally."
                Write-Host "        - Using 'git clone' command under account, that has write permission to the repository i.e. yours."
                Write-Host '   - NOTE:' -ForegroundColor Yellow
                Write-Host "        - It is highly recommended to use 'Visual Studio Code (VSC)' editor to work with the repository content because it provides:"
                Write-Host '            - Uunified admin experience through repository VSC workspace settings.'
                Write-Host '            - Integration & control of GIT.'
                Write-Host '            - Auto-Formatting of the code, etc..'
                Write-Host '        - More details can be found at https://github.com/ztrhgf/Powershell_CICD_repository/blob/master/1.%20HOW%20TO%20INSTALL.md'
            }
            3 {
                Write-Host "############################`n!!! ANYONE WHO CONTROL THIS SOLUTION IS THE DE FACTO ADMINISTRATOR ON EVERY COMPUTER CONNECTED TO IT !!!`n" -ForegroundColor Red
                Write-Host 'So:'
                Write-Host '    - Only *Approved Users* should have write access to GIT repository.' -ForegroundColor Yellow
                Write-Host '    - For accessing cloud GIT repository, use MFA if possible' -ForegroundColor Yellow
                Write-Host '    - MGM server (processes repository data and uploads them to share) has to be protected same as the server that hosts that repository share.' -ForegroundColor Yellow
                Write-Host '############################' -ForegroundColor Red
            }
            4 {
                Write-Host '############################' -ForegroundColor Yellow
                Write-Host "Your input will be stored to '" -NoNewLine -ForegroundColor Yellow;Write-Host $iniFile -NoNewLine;Write-Host "'. So next time you start this script, its content will be automatically used." -ForegroundColor Yellow
                Write-Host '############################' -ForegroundColor Yellow
            }
            5 {
                Write-Host "   - copy Repo_sync folder to " -NoNewLine;Write-Host $MGMRepoSync -NoNewLine -ForegroundColor Magenta;Write-Host "'"
                Write-Host "   - install newest version of 'GIT'"
                Write-Host "   - create scheduled task '" -NoNewLine;Write-Host 'Repo_sync' -NoNewLine -ForegroundColor Magenta;Write-Host "' from '" -NoNewLine;Write-Host 'Repo_sync.xml' -NoNewLine -ForegroundColor Magenta;Write-Host "'"
                Write-Host "   - export '" -NoNewLine;Write-Host 'repo_puller' -NoNewLine -ForegroundColor Magenta;Write-Host "' account alternate credentials to '" -NoNewLine;Write-Host "$MGMRepoSync\login.xml" -NoNewLine -ForegroundColor Magenta;Write-Host "' (only SYSTEM account on " -NoNewLine;Write-Host $MGMServer -NoNewLine -ForegroundColor Magenta;Write-Host " will be able to read them!)"
                Write-Host "   - copy exported credentials from " -NoNewLine;Write-Host $MGMServer -NoNewLine -ForegroundColor Magenta;Write-Host " to " -NoNewLine;Write-Host $userRepoSync -ForegroundColor Magenta
                Write-Host "   - commit&push exported credentials (so they won't be automatically deleted from " -NoNewLine;Write-Host $MGMServer -NoNewLine -ForegroundColor Magenta;Write-Host ', after this solution starts working)'
            }
            6 {
                Write-Host '    - For ASAP test that synchronization is working:'
                Write-Host "        - Run on client command '" -NoNewLine;Write-Host 'gpupdate /force' -NoNewLine -ForegroundColor Cyan;Write-Host "' to create scheduled task " -NoNewLine;Write-Host $GPOname -NoNewLine -ForegroundColor Magenta;Write-Host '.'
                Write-Host '        - Run that sched. task and check the result in ' -NoNewLine;Write-Host "C:\Windows\Temp\$GPOname.ps1.log" -NoNewLine -ForegroundColor Cyan;Write-Host '.'
            }
            7 {
                Write-Host "SUMMARY INFORMATION ABOUT THIS !TEST! INSTALLATION:"
                Write-Host " - Central Repository share is at " -NoNewLine;Write-Host $repositoryShareLocPath -NoNewLine -ForegroundColor Magenta;Write-Host " (locally at " -NoNewLine;Write-Host $repositoryShareLocPath -NoNewLine -ForegroundColor Magenta;Write-Host ').'
                Write-Host "    - It is used by clients to synchronize their repository data."
                Write-Host " - (Cloud) Repository is hosted locally at " -NoNewLine;Write-Host $remoteRepository -ForegroundColor Magenta
                Write-Host "    - Simulates for example GitHub private repository."
                Write-Host " - (Cloud) Repository is locally cloned to " -NoNewLine;Write-Host $userRepository -ForegroundColor Magenta
                Write-Host "    - Here you make changes (creates new functions, modules, ...) and commit them to (Cloud) Repository."
                Write-Host " - Scheduled Tasks:"
                Write-Host "    - Repo_sync - Pulls data from (Cloud) GIT repository, Process them, and Synchronize result to " -NoNewLine;Write-Host $repositoryShare -ForegroundColor Magenta
                Write-Host "        - Processing is done in C:\Windows\Scripts\Repo_sync"
                Write-Host "        - Log file in C:\Windows\Temp\Repo_sync.ps1.log"
                Write-Host "    - PS_env_set_up - Synchronizes local content from " -NoNewLine;Write-Host $repositoryShare -NoNewLine -ForegroundColor Magenta;Write-Host " (i.e. it is used to get repository data to clients)."
                Write-Host "        - Log file in C:\Windows\Temp\PS_env_set_up.ps1.log"
            }
            8 {
                Write-Host '- Do NOT place your GIT repository inside Dropbox, Onedrive or other similar synchronization tool, it would cause problems!'
                Write-Host "- To understand, what is purpose of this repository content check https://github.com/ztrhgf/Powershell_CICD_repository/blob/master/3.%20SIMPLIFIED%20EXPLANATION%20OF%20HOW%20IT%20WORKS.md"
                Write-Host "- For immediate refresh of clients data (and console itself) use function Refresh-Console"
                Write-Host "    - NOTE: Available only on computers defined in Variables module in variable `$computerWithProfile"
                Write-Host "- For examples check https://github.com/ztrhgf/Powershell_CICD_repository/blob/master/2.%20HOW%20TO%20USE%20-%20EXAMPLES.md"
                Write-Host "- For brief video introduction check https://youtu.be/-xSJXbmOgyk and other videos at https://youtube.com/playlist?list=PLcNLAABGhY_GqrWfOZGjpgFv3fiaL0ciM"
                Write-Host "- For master Modules deployment check \modules\modulesConfig.ps1"
                Write-Host "- For master Custom section features check \custom\customConfig.ps1"
                Write-Host "- To see what is happening in the background check logs"
                Write-Host "    - In VSC Output terminal (CTRL + SHIFT + U, there switch output to GIT) (pre-commit.ps1 checks)"
                Write-Host "    - C:\Windows\Temp\Repo_sync.ps1.log on MGM server (synchronization from GIT repository to share)"
                Write-Host "    - C:\Windows\Temp\PS_env_set_up.ps1.log on client (synchronization from share to client)"
                Write-Host "ENJOY :)"
            }
        }
    }

    If (!$noEnvModification) {
        Clear-Host
        Step-OnScreenMSG 1
        $choice = ''
        While ($choice -notmatch '^[1|2|3]$') {$choice = Read-Host -Prompt 'Choose install option (1|2|3)'}
        If ($choice -eq 1) {
            $testInstallation = 1
            If (Test-Administrator -eq $false) {
                # not running "as Administrator" - so relaunch as administrator
                # get command line arguments and reuse them
                $arguments = $myInvocation.line -replace [regex]::Escape($myInvocation.InvocationName), ''
                Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList ('-noprofile -file "{0}" {1}' -f ($myinvocation.MyCommand.Definition), $arguments) # -noexit nebo -WindowStyle Hidden
                # exit from the current, unelevated, process
                Exit
            }
        }
        If ($choice -in 1, 2) {
            $noEnvModification = $false
        } Else {
            $noEnvModification = $true
        }
    }

    Clear-Host
    If (!$noEnvModification -and !$testInstallation) {
        Step-OnScreenMSG 2
        Step-pressKeyToContinue
    } ElseIf ($testInstallation) {
        Write-Host "   - installing 'GIT'"
        Step-installGIT

        Write-Host "   - installing 'VSC'"
        Step-installVSC

        Install-PackageProvider -Name nuget -Force -ForceBootstrap -Scope allusers | Out-Null
    
        <#
            If (!(Get-Module -ListAvailable PSScriptAnalyzer)) {
                "   - installing 'PSScriptAnalyzer' PS module"
                Install-Module PSScriptAnalyzer -SkipPublisherCheck -Force
            }
        #>

        Write-Host "   - updating 'PackageManagement' PS module"
        # solves issue https://github.com/PowerShell/vscode-powershell/issues/2824
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-Module -Name PackageManagement -Force -ErrorActionPreference SilentlyContinue

        Write-Host '   - enabling running of PS scripts'
        # because of PS global profile loading
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
    }

    # TODO nekam napsat ze je potreba psremoting

    If (!$testInstallation) {Clear-Host} Else {''}
    If (!$noEnvModification -and !$testInstallation) {
        Step-OnScreenMSG 3
        Step-pressKeyToContinue
        Clear-Host
        Step-OnScreenMSG 4
    }

    If (!$testInstallation) {
        Step-pressKeyToContinue
        Clear-Host
    }
    #endregion initial

    Try {
        #region import variables
        # import variables from ini file
        # '#' can be used for comments, so skip such lines
        If (Test-Path -Path $iniFile) {
            Write-host "- Importing variables from $iniFile" -ForegroundColor Green
            Get-Content -Path $iniFile -ErrorAction SilentlyContinue | Where-Object {$_ -and $_ -notmatch '^\s*#'} | ForEach-Object {
                $line = $_
                If (($line -split $divider).count -ge 2) {
                    $position = $line.IndexOf($divider)
                    $name     = $line.Substring(0, $position) -replace '^\s*|\s*$'
                    $value    = $line.Substring($position + 1) -replace '^\s*|\s*$'
                    Write-Host "   - variable $name` will have value: $value"

                    # fill hash so I can later export (updated) variables back to file
                    $setupVariable.$name = $value
                }
            }
            Step-pressKeyToContinue
        }
        #endregion import variables

        If (!$testInstallation) {Clear-Host}

        #region checks
        Write-host '- Checking permissions etc' -ForegroundColor Green

        <# computer isn't in domain
            If (!$noEnvModification -and !(Get-WmiObject -Class win32_computersystem).partOfDomain) {
                Write-Warning 'This PC isn't joined to domain. AD related steps will have to be done manually.'
                ++$skipAD
                Step-continue
            }
        #>

        # is local administrator
        If (Test-Administrator -eq $false) {
            Write-Warning -Message "Not running as administrator. Symlink for using repository PowerShell snippets file in VSC won't be created"
            $notAdmin++
            Step-pressKeyToContinue
        }

        If (!$testInstallation) {
            # is domain admin
            If (!$noEnvModification -and !((& "$env:windir\system32\whoami.exe" /all) -match 'Domain Admins|Enterprise Admins')) {
                Write-Warning -Message 'You are not member of Domain nor Enterprise Admin group. AD related steps will have to be done manually.'
                $notADAdmin++
                Step-continue
            }

            # ActiveDirectory PS module is available
            $ADAvailable = Get-Module -Name ActiveDirectory -ListAvailable
            If (!$noEnvModification -and !$ADAvailable) {
                Write-Warning -Message "ActiveDirectory PowerShell module isn't installed (part of RSAT)."
                If (!$notAdmin -and ((Step-continue -text 'Proceed with installation' -passthru) -eq 'Y')) {
                    If ($isServer) {
                        $null = Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeManagementTools
                    } Else {
                        Try {
                            $null = Get-WindowsCapability -Name '*activedirectory*' -Online -ErrorAction Stop | Add-WindowsCapability -Online -ErrorAction Stop 
                        } Catch {
                            Write-Warning -Message "Unable to install RSAT AD tools.`nAD related steps will be skipped, so make them manually."
                            $noADmodule++
                            Step-pressKeyToContinue
                        }
                    }
                } Else {
                    Write-Warning -Message 'AD related steps will be skipped, so make them manually.'
                    $noADmodule++
                    Step-pressKeyToContinue
                }
            }

            # GroupPolicy PS module is available
            $GPOAvailable = Get-Module -Name GroupPolicy -ListAvailable
            If (!$noEnvModification -and !$GPOAvailable) {
                Write-Warning -Message "GroupPolicy PowerShell module isn't installed (part of RSAT)."
                If (!$notAdmin -and ((Step-continue -text 'Proceed with installation' -passthru) -eq 'Y')) {
                    If ($isServer) {
                        $null = Install-WindowsFeature -Name GPMC -IncludeManagementTools
                    } Else {
                        Try {
                            $null = Get-WindowsCapability -Name '*grouppolicy*' -Online -ErrorAction Stop | Add-WindowsCapability -Online -ErrorAction Stop 
                        } Catch {
                            Write-Warning -Message "Unable to install RSAT GroupPolicy tools.`nGPO related steps will be skipped, so make them manually."
                            $noGPOmodule++
                            Step-pressKeyToContinue
                        }
                    }
                } Else {
                    Write-Warning -Message 'GPO related steps will be skipped, so make them manually.'
                    $noGPOmodule++
                    Step-pressKeyToContinue
                }
            }
            If ($notADAdmin -or $noADmodule)  {$skipAD++}
            If ($notADAdmin -or $noGPOmodule) {$skipGPO++}
        }

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }
        #endregion checks


        If (!$testInstallation) {
            Step-SetVariable -variable MGMServer -readHost 'the name of the MGM server (will be used for pulling, processing and distributing of repository data to repository share).'
            If ($MGMServer -like '*.*') {
                $MGMServer = ($MGMServer -split '\.')[0]
                Write-Warning -Message "$MGMServer was in FQDN format. Just hostname was used"
            }
            If (!$noADmodule -and !(Get-ADComputer -Filter "name -eq '$MGMServer'")) {
                Throw "$MGMServer doesn't exist in AD"
            }
        } Else {
            # test installation
            $MGMServer = $env:COMPUTERNAME
            Write-Host '   - For testing purposes, this computer will host MGM server role too'
        }

        If (!$testInstallation) {
            Step-saveInput
            Clear-Host
        }

        #region create repo_reader, repo_writer
        If (!$testInstallation) {
            Write-Host '- Creating repo_reader, repo_writer AD security groups' -ForegroundColor Green
            If (!$noEnvModification -and !$skipAD -and !(Step-skip)) {
                'repo_reader', 'repo_writer' | ForEach-Object {
                    If (Get-ADGroup -filter "samaccountname -eq '$_'") {
                        Write-Host "   - $_ already exists"
                    } Else {
                        If ($_ -match 'repo_reader') {
                            $right = 'read'
                        } Else {
                            $right = 'modify'
                        }
                        New-ADGroup -Name $_ -GroupCategory Security -GroupScope Universal -Description "Members have $right permission to repository share content."
                        Write-Host " - created $_"
                    }
                }
            } Else {
                Write-Warning -Message "Skipped!`n`nCreate them manually"
            }
        } Else {
            Write-Host '- Creating repo_reader, repo_writer security groups' -ForegroundColor Green
            'repo_reader', 'repo_writer' | ForEach-Object {
                If (Get-LocalGroup -Name $_ -ErrorAction SilentlyContinue) {
                    Write-Host "$_ group already exists."
                } Else {
                    If ($_ -match 'repo_reader') {
                        $right = 'read'
                    } Else {
                        $right = 'modify'
                    }
                    $null = New-LocalGroup -Name $_ -Description "Members have $right right to repository share." # max 48 chars!
                }
            }
        }
        #endregion create repo_reader, repo_writer

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }

        #region adding members to repo_reader, repo_writer
        If (!$testInstallation) {
            Write-Host '- Adding members to repo_reader, repo_writer AD groups' -ForegroundColor Green
            Write-Host "   - add 'Domain Computers' to repo_reader group"
            Write-Host "   - add 'Domain Admins' and $MGMServer to repo_writer group"
            If (!$noEnvModification -and !$skipAD -and !(Step-skip)) {
                Write-Host "   - adding 'Domain Computers' to repo_reader group (DCs are not members of this group!)"
                Add-ADGroupMember -Identity 'repo_reader' -Members 'Domain Computers'
                Write-Host "   - adding 'Domain Admins' and $MGMServer to repo_writer group"
                Add-ADGroupMember -Identity 'repo_writer' -Members 'Domain Admins', "$MGMServer$"
            } Else {
                Write-Warning -Message "Skipped! Fill them manually.`n`n - repo_reader should contains computers which you want to join to this solution i.e. 'Domain Computers' (if you choose just subset of computers, use repo_reader and repo_writer for security filtering on lately created GPO $GPOname)`n - repo_writer should contains 'Domain Admins' and $MGMServer server"
            }
            Write-Warning -Message "`nRESTART $MGMServer (and rest of the computers) to apply new membership NOW!"
        } Else {
            Write-Host '- Adding members to repo_reader, repo_writer groups' -ForegroundColor Green
            #Write-Host "   - adding SYSTEM to repo_reader group"
            #Add-LocalGroupMember -Name 'repo_reader' -Member "SYSTEM"
            Write-Host '   - adding Administrators and SYSTEM to repo_writer group'
            'Administrators', 'SYSTEM' | ForEach-Object {
                If ($_ -notin (Get-LocalGroupMember -Name 'repo_writer' | Select-Object -Property @{n='Name';e={($_.Name -split '\\')[-1]}} | Select-Object -ExpandProperty Name)) {
                    Add-LocalGroupMember -Name 'repo_writer' -Member $_
                }
            } 
        }
        #endregion adding members to repo_reader, repo_writer
    
        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }

        #region set up shared folder for repository data
        Write-Host '- Creating shared folder for hosting repository data' -ForegroundColor Green
        If (!$testInstallation) {
            Step-SetVariable -variable repositoryShare -readHost 'UNC path to folder, where the repository data should be stored (i.e. \\mydomain\dfs\repository)'
        } Else {
            Write-Host "   - For testing purposes $repositoryShare will be used"
        }
        If ($repositoryShare -notmatch '^\\\\[^\\]+\\[^\\]+') {Throw "$repositoryShare isn't valid UNC path"}

        $permissions = "`n`t`t- SHARE`n`t`t`t- Everyone - FULL CONTROL`n`t`t- NTFS`n`t`t`t- SYSTEM, repo_writer - FULL CONTROL`n`t`t`t- repo_reader - READ"

        If ($testInstallation -or (!$noEnvModification -and !(Step-skip))) {
            Write-Host "   - Testing, whether '$repositoryShare' already exists"
            Try {
                $repositoryShareExists = Test-Path -Path $repositoryShare
            } Catch {
                # in case this script already created that share but this user isn't yet in repo_writer, he will receive access denied error when accessing it
                If ($_ -match 'access denied') {$accessDenied++}
            }
            If ($repositoryShareExists -or $accessDenied) {
                If (!$testInstallation) {
                    Write-Warning -Message "Share '$repositoryShare' already exists.`n`tMake sure, that ONLY following permissions are set:$permissions`n`nNOTE: it's content will be replaced by repository data eventually!"
                }
            } Else {
                # share or some part of its path doesn't exist
                $isDFS = ''
                If (!$testInstallation) {
                    # for testing installation I will use common UNC share
                    While ($isDFS -notmatch '^[Y|N]$') {$isDFS = Read-Host -Prompt "`n   - Is '$repositoryShare' DFS share? (Y|N)"}
                }
                If ($isDFS -eq 'Y') {
                    #TODO pridat podporu pro tvorbu DFS share
                    Write-Warning -Message "Skipped! Currently this installer doesn't support creation of DFS share.`nMake share manually with ONLY following permissions:$permissions"
                } Else {
                    # creation of non-DFS shared folder
                    $repositoryHost = ($repositoryShare -split '\\')[2]
                    If (!$testInstallation -and !$noADmodule -and !(Get-ADComputer -Filter "name -eq '$repositoryHost'")) {Throw "$repositoryHost doesn't exist in AD"}
                    $parentPath = '\\' + [string]::join('\', $repositoryShare.Split('\')[2..3])
                    If (($parentPath -eq $repositoryShare) -or ($parentPath -ne $repositoryShare -and !(Test-Path -Path $parentPath -ErrorAction SilentlyContinue))) {
                        # shared folder doesn't exist, can't deduce local path from it, so get it from the user
                        If (!$testInstallation) {
                            Write-Host ''
                            Step-SetVariable -variable repositoryShareLocPath -readHost "local path to folder, which will be than shared as '$parentPath' (on $repositoryHost)"
                        } Else {
                            Write-Host "   - For testing purposes, repository share will be stored locally in '$repositoryShareLocPath'"
                        }
                    } Else {
                        Write-Host "`n   - Share $parentPath already exists. Folder for repository data will be created (if necessary) and JUST NTFS permissions will be set."
                        Write-Warning -Message 'So make sure, that SHARE permissions are set to: Everyone - FULL CONTROL!'
                        Step-pressKeyToContinue
                    }
                    $invokeParam = @{}
                    If (!$testInstallation) {
                        If ($notADAdmin) {
                            While (!$repositoryHostSession) {
                                $repositoryHostSession = New-PSSession -ComputerName $repositoryHost -Credential (Get-Credential -Message "Enter admin credentials for connecting to $repositoryHost through psremoting") -ErrorAction SilentlyContinue
                            }
                        } Else {
                            $repositoryHostSession = New-PSSession -ComputerName $repositoryHost
                        }
                        $invokeParam.Session = $repositoryHostSession
                    } Else {
                        Write-Host 'Testing installation i.e. locally'
                    }
                    $invokeParam.argumentList = $repositoryShareLocPath, $repositoryShare, $allFunctionDefs
                    $invokeParam.ScriptBlock  = {
                        [CmdletBinding()]
                        Param ($repositoryShareLocPath, $repositoryShare, $allFunctionDefs)
                        # recreate function from it's definition
                        Foreach ($functionDef in $allFunctionDefs) {([ScriptBlock]::Create($functionDef))}
                        $shareName = ($repositoryShare -split '\\')[3]
                        If ($repositoryShareLocPath) {
                            # share doesn't exist yet
                            # create folder (and subfolders) and share it
                            If (Test-Path -Path $repositoryShareLocPath) {
                                Write-Warning -Message "$repositoryShareLocPath already exists on $env:COMPUTERNAME!"
                                Step-continue -text 'Content will be eventually overwritten'
                            } Else {
                                [Void][System.IO.Directory]::CreateDirectory($repositoryShareLocPath)
                                # create subfolder structure if UNC path contains them as well
                                $subfolder = [string]::join('\', $repositoryShare.split('\')[4..1000])
                                $subfolder = Join-Path -Path $repositoryShareLocPath -ChildPath $subfolder 
                                [Void][System.IO.Directory]::CreateDirectory($subfolder)
                                # share the folder
                                Write-Host "       - share $repositoryShareLocPath as $shareName"
                                $null = Remove-SmbShare -Name $shareName -Force -Confirm:$false -ErrorAction SilentlyContinue
                                $null = New-SmbShare -Name $shareName -Path $repositoryShareLocPath -FullAccess Everyone
                                # set NTFS permission
                                Write-Host "       - setting NTFS permissions on $repositoryShareLocPath"
                                Step-setPermissions -path $repositoryShareLocPath -writeUser SYSTEM, repo_writer -readUser repo_reader
                            }
                        } Else {
                            # share already exists
                            # create folder for storing repository, set NTFS permissions and check SHARE permissions 
                            $share = Get-SmbShare -Name $shareName
                            $repositoryShareLocPath = $share.path
                            # create subfolder structure if UNC path contains them as well
                            $subfolder = [string]::join('\', $repositoryShare.split('\')[4..1000])
                            $subfolder = Join-Path -Path $repositoryShareLocPath -ChildPath $subfolder
                            [Void][System.IO.Directory]::CreateDirectory($subfolder)
                            # set NTFS permission
                            "`n   - setting NTFS permissions on $repositoryShareLocPath"
                            Step-setPermissions -path $repositoryShareLocPath -writeUser SYSTEM, repo_writer -readUser repo_reader
                            # check/set SHARE permission
                            $sharePermission = Get-SmbShareAccess -Name $shareName
                            If (!($sharePermission | Where-Object {$_.accountName -eq 'Everyone' -and $_.AccessControlType -eq 'Allow' -and $_.AccessRight -eq 'Full'})) {
                                Write-Host "      - share $shareName doesn't contain valid SHARE permissions, EVERYONE should have FULL CONTROL access (access to repository data is driven by NTFS permissions)."
                                Step-pressKeyToContinue "Current share $repositoryShare will be un-shared and re-shared with correct SHARE permissions"
                                Remove-SmbShare -Name $shareName -Force -Confirm:$false            
                                New-SmbShare -Name $shareName -Path $repositoryShareLocPath -FullAccess EVERYONE
                            } Else {
                                Write-Host "      - share $shareName already has correct SHARE permission, no action needed"
                            }
                        }
                    }
                    Invoke-Command @invokeParam
                    If ($repositoryHostSession) {
                        Remove-PSSession -Id $repositoryHostSession -ErrorAction SilentlyContinue
                    }
                }
            }
        } Else {
            Write-Warning -Message "Skipped!`n`n - Create shared folder '$repositoryShare' manually and set there following permissions:$permissions"
        }
        #endregion set up shared folder for repository data

        If (!$testInstallation) {
            Step-saveInput
            Step-pressKeyToContinue
            Clear-Host
        }

        #region customize cloned data
        $repo_content_set_up = Join-Path -Path $PSScriptRoot -ChildPath 'repo_content_set_up'
        $_other              = Join-Path -Path $PSScriptRoot -ChildPath '_other'
        Write-Host "- Customizing generic data to match your environment by replacing '__REPLACEME__<number>' in content of '$repo_content_set_up' and '$_other'" -ForegroundColor Green
        If (!(Test-Path -Path $repo_content_set_up -ErrorAction SilentlyContinue)) {Throw "Unable to find '$repo_content_set_up'. Clone repository https://github.com/ztrhgf/Powershell_CICD_repository again"}
        If (!(Test-Path -Path $_other -ErrorAction SilentlyContinue)) {Throw "Unable to find '$_other'. Clone repository https://github.com/ztrhgf/Powershell_CICD_repository again"}
        If (!$testInstallation) {
            Write-Host "`n   - Gathering values for replacing __REPLACEME__<number> string:" -ForegroundColor DarkGreen
            Write-Host "       - in case, you will need to update some of these values in future, clone again this repository, edit content of $iniFile and run this wizard again`n"
            $replacemeVariable = @{
                1 = $repositoryShare
                2 = Step-SetVariable -variable repositoryURL -readHost 'Cloning URL of your own GIT repository. Will be used on MGM server' -passThru
                3 = $MGMServer
                4 = Step-SetVariable -variable computerWithProfile -readHost "name of computer(s) (without ending $, divided by comma) that should get:`n       - global Powershell profile (shows number of commits this console is behind in Title etc)`n       - adminFunctions module (Refresh-Console function etc)`n" -passThru
                5 = Step-SetVariable -variable smtpServer -readHost 'IP or hostname of your SMTP server. Will be used for sending error notifications (recipient will be specified later)' -optional -passThru
                6 = Step-SetVariable -variable adminEmail -readHost 'recipient(s) email address (divided by comma), that should receive error notifications. Use format it@contoso.com' -optional -passThru
                7 = Step-SetVariable -variable 'from' -readHost 'sender email address, that should be used for sending error notifications. Use format robot@contoso.com' -optional -passThru
            }
        } Else {
            # there will be created GIT repository for test installation
            $repositoryURL = $remoteRepository
            $computerWithProfile = $env:COMPUTERNAME
            Write-Warning -Message "So this computer will get:`n - global Powershell profile (shows number of commits this console is behind in Title etc)`n - adminFunctions module (Refresh-Console function etc)`n"
            $replacemeVariable = @{
                1 = $repositoryShare
                2 = $repositoryURL
                3 = $MGMServer
                4 = $computerWithProfile
            }
        }
        # replace __REPLACEME__<number> for entered values in cloned files
        $replacemeVariable.GetEnumerator() | ForEach-Object {
            # in files, __REPLACEME__<number> format is used where user input should be placed
            $name  = '__REPLACEME__' + $_.name
            $value = $_.value

            # variables that support array convert to "a", "b", "c" format
            If ($_.name -in (4, 6) -and $value -match ',') {
                $value = $value -split ',' -replace '\s*$|^\s*'
                $value = $value | ForEach-Object { "`"$_`"" }
                $value = $value -join ', '
            }

            # variable is repository URL, convert it to correct format
            If ($_.name -eq 2) {
                # remove leading http(s):// because it is already mentioned in repo_sync.ps1
                $value = $value -replace '^http(s)?://'
                # remove login i.e. part before @
                $value = $value.Split('@')[-1]
            }

            # remove quotation, replace string is already quoted in files
            $value = $value -replace "^\s*[`"']" -replace "[`"']\s*$"

            If (!$testInstallation) {
                Write-Host "   - replacing: $name for: $value"
            } Else {
                Write-Verbose -Message "   - replacing: $name for: $value"
            }

            Get-ChildItem -Path $repo_content_set_up, $_other -Include *.ps1, *.psm1, *.xml -Recurse | ForEach-Object {
                (Get-Content -Path $_.fullname) -replace $name, $value | Set-Content -Path $_.fullname
            }

            #TODO zkontrolovat/upozornit na soubory kde jsou replaceme (exclude takovych kde nezadal uzivatel zadnou hodnotu)
        }
        #endregion customize cloned data

        If (!$testInstallation) {
            Step-saveInput
            Step-pressKeyToContinue
            Clear-Host
        }

        #region warn about __CHECKME__
        Write-Host "- Searching for __CHECKME__ in $repo_content_set_up" -ForegroundColor Green
        $fileWithCheckMe = Get-ChildItem -Path $repo_content_set_up -Recurse | ForEach-Object {
                               If ((Get-Content -Path $_.fullname -ErrorAction SilentlyContinue -Raw) -match '__CHECKME__') {$_.fullname}
                           }
        # remove this script from the list
        $fileWithCheckMe = $fileWithCheckMe | Where-Object { $_ -ne $PSCommandPath }
        If ($fileWithCheckMe) {
            Write-Warning -Message '(OPTIONAL CUSTOMIZATIONS) Search for __CHECKME__ string in the following files and decide what to do according to information that follows there (save any changes before continue):'
            $fileWithCheckMe | ForEach-Object { "   - $_" }
        }
        #endregion warn about __CHECKME__

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }

        #region copy customized repository data to user own repository
        If (!$testInstallation) {
            Step-SetVariable -variable userRepository -readHost "path to ROOT of your locally cloned company repository '$repositoryURL'"
        } Else {
            Write-Host " - Creating new GIT repository '$remoteRepository'. It will be used instead of your own cloud repository like GitHub or Azure DevOps. DON'T MAKE ANY CHANGES HERE." -ForegroundColor Green
            [Void][System.IO.Directory]::CreateDirectory($remoteRepository)
            Set-Location -Path $remoteRepository
            $result = Step-startProcess -filePath git -argumentList init
            #FIXME https://stackoverflow.com/questions/3221859/cannot-push-into-git-repository
            $result = Step-startProcess -filePath git -argumentList 'config receive.denyCurrentBranch updateInstead'
            Write-Host "`n - Cloning '$remoteRepository' to '$userRepository'. So in '$userRepository' MAKE YOUR CHANGES." -ForegroundColor Green
            Set-Location -Path (Split-Path -Path $userRepository -Parent)
            $result = Step-startProcess -filePath git -argumentList "clone --local $remoteRepository $(Split-Path -Path $userRepository -Leaf)" -outputErr2Std
        }

        If ($testInstallation -or (!$noEnvModification -and !(Step-skip))) {
            If (!(Test-Path -Path (Join-Path -Path $userRepository -ChildPath '.git') -ErrorAction SilentlyContinue)) {Throw "$userRepository isn't cloned GIT repository (.git folder is missing)"}
            Write-Host "- Copying customized repository data ($repo_content_set_up) to your own company repository ($userRepository)" -ForegroundColor Green
            $result = Step-copyFolder -source $repo_content_set_up -destination $userRepository
            If ($err = $result.errMsg) {Throw "Copy failed:`n$err"}
        } Else {
            Write-Warning -Message "Skipped!`n`n - Copy CONTENT of $repo_content_set_up to ROOT of your locally cloned company repository. Review the changes to prevent loss of any of your customization (preferably merge content of customConfig.ps1 and Variables.psm1 instead of replacing them completely) and COMMIT them"
        }
        #endregion copy customized repository data to user own repository

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Step-saveInput
            Clear-Host
        }

        #region configure user repository
        If ($env:USERDNSDOMAIN) {
            $userDomain = $env:USERDNSDOMAIN
        } Else {
            $userDomain = "$env:COMPUTERNAME.com"
        }
        Write-Host "- Configuring repository '$userRepository'" -ForegroundColor Green

        If ($testInstallation -or (!$noEnvModification -and !(Step-skip))) {
            $currPath = Get-Location
            Set-Location -Path $userRepository

            # just in case user installed GIT after launch of this console, update PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')
        
            Write-Host "   - setting GIT user name to '$env:USERNAME'"
            git config user.name $env:USERNAME

            Write-Host "   - setting GIT user email to '$env:USERNAME@$userDomain'"
            git config user.email "$env:USERNAME@$userDomain"

            $VSCprofile          = Join-Path -Path $env:APPDATA -ChildPath 'Code\User'
            $profileSnippets     = Join-Path -Path $VSCprofile -ChildPath 'snippets'
            [Void][System.IO.Directory]::CreateDirectory($profileSnippets)
            $profilePSsnippet    = Join-Path -Path $profileSnippets -ChildPath 'powershell.json'
            $repositoryPSsnippet = Join-Path -Path $userRepository -ChildPath 'powershell.json'
            Write-Host "   - creating symlink '$profilePSsnippet' for '$repositoryPSsnippet', so VSC can offer these PowerShell snippets"
            If (!$notAdmin -and (Test-Path -Path $VSCprofile -ErrorAction SilentlyContinue) -and !(Test-Path -Path $profilePSsnippet -ErrorAction SilentlyContinue)) {
                [Void][System.IO.Directory]::CreateDirectory($profileSnippets)
                $null = New-Item -itemtype symboliclink -path $profileSnippets -name 'powershell.json' -value $repositoryPSsnippet
            } Else {
                Write-Warning -Message "Skipped.`n`nYou are not running this script with admin privileges or VSC isn't installed or '$profilePSsnippet' already exists"
            }

            # to avoid message 'warning: LF will be replaced by CRLF'
            $null = Step-startProcess -filePath git -argumentList 'config core.autocrlf false' -outputErr2Std -dontWait
        
            # commit without using hooks, to avoid possible problem with checks (because of wrong encoding, missing PSScriptAnalyzer etc), that could stop it 
            Write-Host "   - commiting & pushing changes to repository $repositoryURL"
            $null = git add .
            $null = Step-startProcess -filePath git -argumentList 'commit --no-verify -m initial' -outputErr2Std -dontWait
            $null = Step-startProcess -filePath git -argumentList 'push --no-verify' -outputErr2Std

            Write-Host '   - activating GIT hooks for automation of checks, git push etc'
            $null = Step-startProcess -filePath git -argumentList 'config core.hooksPath ".\.githooks"'

            # to set default value again
            $null = Step-startProcess -filePath git -argumentList 'config core.autocrlf true' -outputErr2Std -dontWait

            Set-Location -Path $currPath
        } Else {
            Write-Warning -Message "Skipped!`n`nFollow instructions in $(Join-Path -Path $repo_content_set_up -ChildPath '!!!README!!!.txt') file"
        }
        #endregion configure user repository

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }

        #region preparation of MGM server
        $MGMRepoSync = "\\$MGMServer\C$\Windows\Scripts\Repo_sync"
        $userRepoSync = Join-Path -Path $userRepository -ChildPath 'custom\Repo_sync'
        Write-Host "- Setting MGM server ($MGMServer)" -ForegroundColor Green
        if (!$testInstallation) {
            Step-OnScreenMSG 5
        }

        If ($testInstallation -or (!$noEnvModification -and !(Step-skip))) {
            Write-Host "   - copying Repo_sync folder to '$MGMRepoSync'"
            If (!$testInstallation) {
                If ($notADAdmin) {
                    While (!$MGMServerSession) {
                        $MGMServerSession = New-PSSession -ComputerName $MGMServer -Credential (Get-Credential -Message "Enter admin credentials for connecting to $MGMServer through psremoting") -ErrorAction SilentlyContinue
                    }
                } Else {
                    $MGMServerSession = New-PSSession -ComputerName $MGMServer
                }

                If ($notADAdmin) {
                    $destination = "$env:windir\Scripts\Repo_sync"

                    # remove existing folder, otherwise Copy-Item creates eponymous subfolder and copies the content to it
                    Invoke-Command -Session $MGMServerSession -ScriptBlock {
                        [CmdletBinding()]
                        Param ($destination)
                        If (Test-Path -Path $destination -ErrorAction SilentlyContinue) {
                            Remove-Item -Path $destination -Recurse -Force
                        }
                    } -ArgumentList $destination
                    Copy-Item -ToSession $MGMServerSession -Path $userRepoSync -Destination $destination -Force -Recurse
                } Else {
                    # copy using admin share
                    $result = Step-copyFolder -source $userRepoSync -destination $MGMRepoSync 
                    If ($err = $result.errMsg) {
                        Throw "Copy failed:`n$err"
                    }
                }
            } Else {
                # local copy
                $destination = "$env:windir\Scripts\Repo_sync"
                $result = Step-copyFolder -source $userRepoSync -destination $destination
                If ($err = $result.errMsg) {
                    Throw "Copy failed:`n$err"
                }
            }

            $invokeParam = @{ArgumentList = $repositoryShare, $allFunctionDefs, $testInstallation}
            if ($MGMServerSession) {$invokeParam.session = $MGMServerSession}
            $invokeParam.ScriptBlock = {
                [CmdletBinding()]
                param ($repositoryShare, $allFunctionDefs, $testInstallation)
                # recreate function from it's definition
                Foreach ($functionDef in $allFunctionDefs) {
                    . ([ScriptBlock]::Create($functionDef))
                }

                $MGMRepoSync = "$env:windir\Scripts\Repo_sync"
                $taskName    = 'Repo_sync'

                If (!$testInstallation) {
                    Write-Host "   - checking that $env:COMPUTERNAME is in AD group repo_writer"
                    If (!(Step-getComputerMembership -match 'repo_writer')) {
                        Throw "Check failed. Make sure, that $env:COMPUTERNAME is in repo_writer group and restart it to apply new membership. Than run this script again"
                    }
                }

                Write-Host "   - installing newest 'GIT'"
                Step-installGIT

                #Write-Host "   - downloading & installing 'GIT Credential Manager'"
                #Step-installGITCredManager

                $Repo_syncXML = "$MGMRepoSync\Repo_sync.xml"
                Write-Host "   - creating scheduled task '$taskName' from $Repo_syncXML"
                Step-createSchedTask -xmlDefinition $Repo_syncXML -taskName $taskName

                If (!$testInstallation) {
                    Write-Host "   - exporting repo_puller account alternate credentials to '$MGMRepoSync\login.xml' (only SYSTEM account on $env:COMPUTERNAME will be able to read them!)"
                    Step-exportCred -credential (Get-Credential -Message 'Enter credentials (that can be used in unattended way) for GIT "repo_puller" account, you created earlier') -RunAs 'NT AUTHORITY\SYSTEM' -xmlPath "$MGMRepoSync\login.xml"
                }

                Write-Host "   - starting scheduled task '$taskName' to fill $repositoryShare immediately"
                Step-startSchedTask -taskName $taskName

                Write-Host '      - checking, that the task ends up succesfully'
                While (($result = ((& "$env:windir\system32\schtasks.exe" /query /tn "$taskName" /v /fo csv /nh) -split ',')[6]) -eq '"267009"') {
                    # task is running
                    Start-Sleep -Seconds 1
                }
                If ($result -ne '"0"') {
                    Throw "Task '$taskName' ends up with error ($($result -replace '"')). Check C:\Windows\Temp\Repo_sync.ps1.log on $env:COMPUTERNAME for more information"
                }
            }
            Invoke-Command @invokeParam

            If (!$testInstallation) {
                Write-Host "   - copying exported credentials from $MGMServer to $userRepoSync"
                If ($notADAdmin) {
                    Copy-Item -FromSession $MGMServerSession -Path "$env:windir\Scripts\Repo_sync\login.xml" -Destination "$userRepoSync\login.xml" -Force
                } Else {
                    # copy using admin share
                    Copy-Item -Path "$MGMRepoSync\login.xml" -Destination "$userRepoSync\login.xml" -Force
                }

                If ($MGMServerSession) {
                    Remove-PSSession -Id $MGMServerSession -ErrorAction SilentlyContinue
                }

                Write-Host "   - committing exported credentials (so they won't be automatically deleted from MGM server, after this solution starts)"
                $currPath = Get-Location
                Set-Location -Path $userRepository
                $null = git add .
                $null = Step-startProcess -filePath git -argumentList 'commit --no-verify -m "repo_puller creds for $MGMServer"' -outputErr2Std -dontWait
                $null = Step-startProcess -filePath git -argumentList 'push --no-verify' -outputErr2Std
                # git push # push should be done automatically thanks to git hooks
                Set-Location -Path $currPath
            }
        } Else {
            Write-Warning -Message "Skipped!`n`nFollow instruction in configuring MGM server section https://github.com/ztrhgf/Powershell_CICD_repository/blob/master/1.%20HOW%20TO%20INSTALL.md#on-server-which-will-be-used-for-cloning-and-processing-cloud-repository-data-and-copying-result-to-dfs-ie-mgm-server"
        }
        #endregion preparation of MGM server

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }

        #region create GPO (PS_env_set_up scheduled task)
        If (!$testInstallation) {
            $GPObackup = Join-Path -Path $_other -ChildPath 'PS_env_set_up GPO'
            Write-Host "- Creating GPO $GPOname for creating sched. task, that will synchronize repository data from share to clients" -ForegroundColor Green
            If (!$noEnvModification -and !$skipGPO -and !(Step-skip)) {
                If (Get-GPO -Guid $GPOname -ErrorAction SilentlyContinue) {
                    $choice = ''
                    While ($choice -notmatch '^[Y|N]$') {
                        $choice = Read-Host -Prompt "GPO $GPOname already exists. Replace it? (Y|N)"
                    }
                    If ($choice -eq 'Y') {
                        $null = Import-GPO -BackupGpoName $GPOname -Path $GPObackup -TargetName $GPOname 
                    } Else {
                        Write-Warning -Message "Skipped creation of $GPOname"
                    }
                } Else {
                    $null = Import-GPO -BackupGpoName $GPOname -Path $GPObackup -TargetName $GPOname -CreateIfNeeded 
                }
            } Else {
                Write-Warning -Message "Skipped!`n`nCreate GPO by following https://github.com/ztrhgf/Powershell_CICD_repository/blob/master/1.%20HOW%20TO%20INSTALL.md#in-active-directory-1 or using 'Import settings...' wizard in GPMC. GPO backup is stored in '$GPObackup'"
            }
        } Else {
            # testing installation i.e. sched. task has to be created manually (instead of GPO)
            Write-Host '- Creating PS_env_set_up scheduled task, that will synchronize repository data from share to this client' -ForegroundColor Green

            $PS_env_set_up_schedTaskDefinition = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
    <Author>CONTOSO\adminek</Author>
    <URI>\PS_env_set_up</URI>
    </RegistrationInfo>
    <Triggers>
    <TimeTrigger>
        <Repetition>
        <Interval>PT10M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
        </Repetition>
        <StartBoundary>2019-04-10T14:31:23</StartBoundary>
        <Enabled>true</Enabled>
    </TimeTrigger>
    </Triggers>
    <Principals>
    <Principal id="Author">
        <UserId>S-1-5-18</UserId>
        <RunLevel>HighestAvailable</RunLevel>
    </Principal>
    </Principals>
    <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
        <Duration>PT5M</Duration>
        <WaitTimeout>PT1H</WaitTimeout>
        <StopOnIdleEnd>false</StopOnIdleEnd>
        <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
        <Interval>PT1M</Interval>
        <Count>3</Count>
    </RestartOnFailure>
    </Settings>
    <Actions Context="Author">
    <Exec>
        <Command>powershell.exe</Command>
        <Arguments>-ExecutionPolicy ByPass -NoProfile `"$repositoryShare\PS_env_set_up.ps1`"</Arguments>
    </Exec>
    </Actions>
</Task>
"@
            $PS_env_set_up_schedTaskDefinitionFile = "$env:TEMP\432432432.xml"
            $PS_env_set_up_schedTaskDefinition | Out-File -FilePath $PS_env_set_up_schedTaskDefinitionFile -Encoding ascii -Force
            Step-createSchedTask -xmlDefinition $PS_env_set_up_schedTaskDefinitionFile -taskName 'PS_env_set_up'
            Write-Host "   - starting scheduled task 'PS_env_set_up' to synchronize repository data from share to this client"
            Step-startSchedTask -taskName 'PS_env_set_up'
        }
        #endregion create GPO (PS_env_set_up scheduled task)

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }

        #region finalize installation
        Write-Host 'FINALIZING INSTALLATION' -ForegroundColor Green
        If (!$noEnvModification -and !$skipAD -and !$skipGPO -and !$notAdmin) {
            Write-Host 'enough rights to process all steps'
        } Else {
            Write-Host '- DO NOT FORGET TO DO ALL SKIPPED TASKS MANUALLY'
        }
        If (!$testInstallation) {
            Write-Warning -Message "- Link GPO $GPOname to OU(s) with computers, that should be driven by this tool.`n    - don't forget, that also $MGMServer server has to be in such OU!"
            Step-OnScreenMSG 6
        } Else {
            Write-Host '- check this console output, to get better idea what was done'
        }
        #endregion finalize installation

        If (!$testInstallation) {
            Step-pressKeyToContinue
            Clear-Host
        }

        If ($testInstallation) {
            Step-OnScreenMSG 7
            Step-pressKeyToContinue
            Clear-Host
        }

        Write-Host 'GOOD TO KNOW' -ForegroundColor Green
        Step-OnScreenMSG 8

        # Start VSC and open there GIT repository
        $codeCmdPath = "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd"
        If (Test-Path -Path $codeCmdPath) {
            Start-Sleep -Seconds 10
            Write-Host '- Opening your repository in VSC'
            & $codeCmdPath "$userRepository"
        }
    } Catch {
        $e    = $_.Exception
        $line = $_.InvocationInfo.ScriptLineNumber
        Write-Host "$e (file: $PSCommandPath line: $line)" -ForegroundColor Red
        break
    } Finally {
        Stop-Transcript -ErrorAction SilentlyContinue
        Try {
            Remove-PSSession -Session $repositoryHostSession
            Remove-PSSession -Session $MGMServerSession
        } catch {
            ''
        }
    }
}
