#region Functions
Function Test-Admin             {
    <#
        .SYNOPSIS
        Check if running with elevated privileges
    #>
    $currentUser = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList (
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

Function Get-AppUninstallInfo   {
    <#
        .SYNOPSIS
        Retrieves detailed uninstall information for installed applications from a local or remote Windows machine.

        .DESCRIPTION
        Get-AppUninstallInfo scans the standard "Uninstall" registry keys for both machine-wide and per-user installs.
        It queries:
        - HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
        - HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        - HKU:\<SID or temp mount>\Software\Microsoft\Windows\CurrentVersion\Uninstall  (per-user)

        Per-user hives are discovered via HKLM:\...\ProfileList (SID → profile path) and, when not already mounted,
        are temporarily loaded under HKU:\TEMP_<guid> and unloaded when finished.

        By default, entries with SystemComponent = 1 are hidden. Use -IncludeSystemComponents to include them.

        Two parameter sets are supported:
        - ByName: filter by one or more application names (partial, case-insensitive by default).
        - All:    list all entries (subject to SystemComponent filtering).

        When -ComputerName targets a remote host, the discovery runs in a remote session and returns objects locally.

        .PARAMETER AppName
        [String[]]  (ByName set, Mandatory)
        Display names (or fragments) to match against the DisplayName registry value.
        Matching is case-insensitive and partial unless -ExactMatchOnly is specified.
        Accepts pipeline input of strings.

        .PARAMETER ExactMatchOnly
        [Switch]  (ByName set)
        When specified, only returns items whose DisplayName equals one of the names in -AppName (case-insensitive).

        .PARAMETER ListAll
        [Switch]  (All set, Mandatory)
        Returns all uninstall entries (subject to SystemComponent filtering). Do not supply -AppName with this switch.

        .PARAMETER ComputerName
        [String]  (Shared)
        Target computer. Defaults to the local computer. When remote, PowerShell Remoting must be enabled and
        you must have appropriate permissions.

        .PARAMETER IncludeSystemComponents
        [Switch]  (Shared)
        Include entries where SystemComponent = 1. By default, such entries are excluded.

        .INPUTS
        System.String
        You can pipe one or more application name strings to -AppName (ByName set).

        .OUTPUTS
        PSCustomObject[]
        Each object represents one uninstall entry and includes:
        - Name                      (DisplayName)
        - Version                   (DisplayVersion)
        - InstallLocation
        - RegKeyPath                (raw registry key name)
        - RegKeyFullPath            (provider path)
        - UninstallString           (original uninstall string with MSI /I normalized to /X when applicable)
        - UninstallStringNormalized (canonical one-liner suitable to execute; for MSI: "msiexec.exe <args>")
        - UninstallerPath           (parsed executable path or "msiexec.exe" for MSI)
        - UninstallerArguments      (parsed arguments; MSI arguments if MSI)
        - MSIarguments              (msiexec arguments such as "/X {GUID} /qn /norestart", if MSI)
        - IsMSI                     (True when detected as an MSI)
        - QuietUninstallString      (when available)

        .EXAMPLE
        # Partial, case-insensitive match for "Java" on the local computer
        Get-AppUninstallInfo -AppName 'Java'

        .EXAMPLE
        # Exact match for two display names
        Get-AppUninstallInfo -AppName 'Notepad++','Google Chrome' -ExactMatchOnly

        .EXAMPLE
        # List all non-system-component apps on a remote computer
        Get-AppUninstallInfo -ListAll -ComputerName 'PC-42'

        .EXAMPLE
        # Include system components while listing all on the local machine
        Get-AppUninstallInfo -ListAll -IncludeSystemComponents

        .NOTES
        - Requires administrative privileges to load per-user hives (HKU) for profiles not currently mounted.
        - Per-user uninstall keys do not have separate WOW6432Node views; HKU paths are scanned as-is.
        - Entries without an UninstallString are skipped.
        - MSI uninstall strings are normalized from install (/I) to uninstall (/X) and canonicalized via MSIarguments.
        - PowerShell Remoting is used for remote queries; you may be prompted for credentials if required.

        .LINK
        Start-Process
        Invoke-Command
    #>
    [CmdletBinding(DefaultParameterSetName='ByName',SupportsShouldProcess,SupportsVerbose,ConfirmImpact='None')]
    Param (
        ### ByName set
        [Parameter(ParameterSetName='ByName',Mandatory,ValueFromPipeline,HelpMessage='Application Display Name')]
        [string[]]$AppName,

        [Parameter(ParameterSetName='ByName')]
        [switch]$ExactMatchOnly,

        ### All set
        [Parameter(ParameterSetName='All',HelpMessage='List all software',Mandatory)]
        [switch]$ListAll,

        ### Shared
        [Parameter(ParameterSetName='ByName')]
        [Parameter(ParameterSetName='All')]
        [string]$ComputerName = $env:COMPUTERNAME,

        ### Hide system components unless requested
        [Parameter(ParameterSetName='ByName')]
        [Parameter(ParameterSetName='All')]
        [switch]$IncludeSystemComponents
    )

    Begin {
        $scriptBlock = {
            Param (
                [string[]]$AppName, 
                [switch]$ExactMatchOnly, 
                [switch]$ListAll,
                [switch]$IncludeSystemComponents
            )

            $Output = @()

            ### Registry paths for system-wide installed software
            $RegUninstallPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )

            ### Already-loaded user SIDs under HKEY_USERS
            $LoadedUserSIDs = Get-ChildItem -Path Registry::HKEY_USERS | Where-Object {
                $_.PSChildName -match '^S-\d-\d+-(\d+-){1,14}\d+$'
            } | Select-Object -ExpandProperty PSChildName

            ### Map SIDs to profile paths from ProfileList
            $ProfileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
            $UserProfiles    = Get-ChildItem -Path $ProfileListPath -ErrorAction SilentlyContinue | Where-Object {
                $_.PSChildName -match '^S-\d-\d+-(\d+-){1,14}\d+$'
            } | ForEach-Object {
                [pscustomobject]@{
                    SID   = $_.PSChildName
                    Path  = (Get-ItemProperty -Path $_.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
                }
            } | Where-Object {
                $_.Path -and (Test-Path -LiteralPath (Join-Path -Path $_.Path -ChildPath 'NTUSER.DAT'))
            }

            $TempHivesToUnload = @()

            ForEach ($p in $UserProfiles) {
                If ($LoadedUserSIDs -contains $p.SID) {
                    $RegUninstallPaths += ('Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Uninstall' -f $p.SID)
                    continue
                }

                $tempHiveName = "TEMP_$([guid]::NewGuid().ToString('N'))"
                Try {
                    reg load "HKU\$tempHiveName" (Join-Path -Path $p.Path -ChildPath 'NTUSER.DAT') | Out-Null
                    $RegUninstallPaths += ('Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Uninstall' -f $tempHiveName)
                    $TempHivesToUnload += $tempHiveName
                } Catch {
                    Write-Warning -Message ("Could not load hive for SID '{0}': {1}" -f $p.SID, $_)
                }
            }

            ### Define filter predicate for registry keys
            $searchNames = $AppName  # avoid directly referencing $AppName later

            #region Helpers
            Function Test-MatchDisplayName {
                <#
                    .SYNOPSIS
                    Named Filter function
                #>
                [CmdletBinding()]
                Param (
                    [Parameter(Mandatory,HelpMessage='App Names')]
                    [string[]]$Names,
                    [string]$DisplayName,
                    [switch]$Exact, 
                    [switch]$All
                )

                If ($All) { return $true }
                If ([string]::IsNullOrEmpty($DisplayName)) { return $false }

                If ($Exact) {
                    return (($Names | Where-Object {$_}) | Where-Object {$DisplayName -ieq $_}).Count -gt 0
                }

                ### Build regex: "Java|Chrome|Firefox"
                $regex = ($Names | Where-Object {$_} | ForEach-Object {[regex]::Escape($_)}) -join '|'
                If (-not $regex) { return $false }
                return $DisplayName -imatch $regex
            }

            Function Get-UninstallFields   {
                <#
                    .SYNOPSIS
                    Populate uninstall fields
                #>
                Param (
                    [Parameter(Mandatory,HelpMessage='Uninstall String')]
                    [string]$UninstallString,
                    [Parameter(Mandatory,HelpMessage='Quiet Uninstall String')]
                    [string]$QuietUninstallString
                )

                $result = [ordered]@{
                    UninstallerPath      = $null
                    UninstallerArguments = $null
                    MSIarguments         = $null
                    IsMSI                = $false
                }

                ### Prefer quiet string if present
                $raw = If ($QuietUninstallString) { $QuietUninstallString } Else { $UninstallString }
                If (-not $raw) { return $result }

                ### Normalize msiexec detection (case-insensitive, with/without .exe)
                If ($raw -imatch 'msiexec(\.exe)?\s+') {
                    $result.IsMSI = $true
                    $result.UninstallerPath = 'msiexec.exe'

                    ### Ensure uninstall (not install)
                    $normalized = $raw -ireplace 'msiexec(\.exe)?\s+/I','msiexec.exe /X'

                    ### Extract GUID in either /X{GUID} or /X {GUID}
                    $guidMatch = [regex]::Match($normalized, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')
                    $guid      = $guidMatch.Value

                    If ($guid) {
                        $result.MSIarguments = "/X $guid /qn /norestart"
                        $result.UninstallerArguments = $result.MSIarguments
                    } Else {
                        ### Fallback: strip path & keep remaining args
                        $argsOnly = ($normalized -ireplace '^.*?msiexec(\.exe)?\s+', '').Trim()
                        If ($argsOnly -notmatch '/X') { $argsOnly = "/X $argsOnly" }
                        $result.MSIarguments         = ($argsOnly + ' /qn /norestart').Trim()
                        $result.UninstallerArguments = $result.MSIarguments
                    }

                    return $result
                }

                ### EXE-style: split path from args but DO NOT split args into tokens
                $m    = [regex]::Match($raw, '^(?:"([^"]+)"|([^\s]+))\s*(.*)$')
                $exe  = If ($m.Groups[1].Success) { $m.Groups[1].Value.Trim() } Else { $m.Groups[2].Value.Trim() }
                $args = $m.Groups[3].Value.Trim()

                $result.UninstallerPath      = $exe
                $result.UninstallerArguments = $args
                return $result
            }
            #endregion Helpers

            ForEach ($Path in $RegUninstallPaths) {
                If (-not (Test-Path -Path $Path)) { continue }

                Get-ChildItem -Path $Path | Where-Object {
                    ### Hide system components unless explicitly included
                    If (-not $IncludeSystemComponents) {
                        $sys = $_.GetValue('SystemComponent')
                        If ($sys -ne $null -and [int]$sys -eq 1) { return $false }
                    }

                    $displayName = $_.GetValue('DisplayName')
                    If ($null -ne $displayName) {
                        Test-MatchDisplayName -Names $searchNames -DisplayName $displayName -Exact:$ExactMatchOnly -All:$ListAll
                    }
                } | ForEach-Object {
                    ### Skip if no uninstall string
                    If (-not $_.GetValue('UninstallString')) { continue }
                    $QuietUninstallString = $_.GetValue('QuietUninstallString')
                    $uninstallString      = $_.GetValue('UninstallString') -ireplace 'MsiExec.exe /I', 'MsiExec.exe /X'
                    $parsed = Get-UninstallFields -UninstallString $_.GetValue('UninstallString') -QuietUninstallString $QuietUninstallString

                    $rawUninstall = $_.GetValue('UninstallString')
                    $uninstallStringNormalized = If ($parsed.IsMSI) {
                        "msiexec.exe $($parsed.MSIarguments)"
                    } Else {
                        $parsed.UninstallerPath + ($(if ($parsed.UninstallerArguments) { ' ' + $parsed.UninstallerArguments } else { '' }))
                    }

                    $obj = [pscustomobject]@{
                        Name                      = $_.GetValue('DisplayName')
                        Version                   = $_.GetValue('DisplayVersion')
                        UninstallString           = $uninstallString
                        UninstallStringNormalized = $uninstallStringNormalized
                        InstallLocation           = $_.GetValue('InstallLocation')
                        RegKeyPath                = $_.Name
                        RegKeyFullPath            = $_.PSPath
                        UninstallerPath           = $parsed.UninstallerPath
                        UninstallerArguments      = $parsed.UninstallerArguments
                        MSIarguments              = $parsed.MSIarguments
                        IsMSI                     = $parsed.IsMSI
                    }

                    If ($QuietUninstallString) {
                        $obj | Add-Member -NotePropertyName QuietUninstallString -NotePropertyValue $QuietUninstallString
                    }

                    $Output += $obj
                }
            }

            ### Unload loaded temp hives
            ForEach ($hive in $TempHivesToUnload) {
                Try {
                    reg unload "HKU\$hive" | Out-Null
                } Catch {
                    Write-Warning -Message ('Failed to unload registry hive: {0}' -f $hive)
                }
            }

            return $Output
        }
    }
    Process {
        If ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME) {
            ### Remote execution with elevation
            $ICMSplat = @{
                ComputerName   = $ComputerName
                ScriptBlock    = $scriptBlock
                ArgumentList   = @($AppName, $ExactMatchOnly, $ListAll, $IncludeSystemComponents)
                Authentication = 'Default'
                ErrorAction    = 'Stop'
            }
            Try {
                $Output = Invoke-Command @ICMSplat
            } Catch {
                $ICMSplat.Credential = (Get-Credential)
                $Output = Invoke-Command @ICMSplat
            }
        } Else {
            $Output = & $scriptBlock -AppName $AppName -ExactMatchOnly:$ExactMatchOnly -ListAll:$ListAll -IncludeSystemComponents:$IncludeSystemComponents
        }

        Write-Output -InputObject $Output
    }
}

Function Uninstall-Applications {
    <#
        .SYNOPSIS
        Silently uninstalls one or more applications locally or on a remote computer, with progress, retries, and timeouts.

        .DESCRIPTION
        Uninstall-Applications executes the uninstall commands provided in a list of application objects. It supports:
        - Local and remote execution (remote via PowerShell Remoting with background jobs).
        - MSI-aware success codes (0, 3010, 1641) treated as successful uninstalls.
        - Fallback argument strategies when silent flags are unknown.
        - Per-attempt confirmation via -WhatIf/-Confirm (SupportsShouldProcess).
        - A visible progress bar and a summary of failures.

        For each app, the function:
        1) Resolves the uninstaller path **locally** only when uninstalling locally (remote paths are resolved on the remote host).
        2) Attempts uninstall with the following argument order:
           - MSIarguments (if present)
           - UninstallerArguments (from registry)
           - Generic silent flags: /S, /silent, /quiet, /qn, /verysilent
        3) Waits up to 300 seconds per attempt (configurable in helper) and treats 0, 3010, 1641 as success.

        .PARAMETER AppsToUninstall
        [array]  (Mandatory)
        Collection of application objects to uninstall. Each object should include:
        - Name                  : String (display name; used for logging/confirmation)
        - IsMSI                 : Boolean
        - UninstallerPath       : String (path to exe or "msiexec.exe" for MSI)
        - UninstallerArguments  : String (arguments parsed from registry, may be empty)
        - MSIarguments          : String (e.g., "/X {GUID} /qn /norestart"), when MSI

        Typically produced by Get-AppUninstallInfo.

        .PARAMETER ComputerName
        [string]
        Target computer name. Defaults to the local computer. When a remote name is provided,
        the uninstall runs **on the remote host** using Invoke-Command -AsJob. PowerShell remoting
        must be enabled and your account must have appropriate permissions.

        .INPUTS
        PSCustomObject[]
        App objects (as described above). Usually the output of Get-AppUninstallInfo.

        .OUTPUTS
        PSCustomObject[]
        Returns an array of the app objects that **failed** to uninstall. If all uninstalls succeed,
        an empty array is returned.

        .EXAMPLE
        # Uninstall anything with "Java" in the name on the local machine
        $apps = Get-AppUninstallInfo -AppName 'Java'
        Uninstall-Applications -AppsToUninstall $apps -Verbose

        .EXAMPLE
        # Uninstall a specific set remotely
        $apps = Get-AppUninstallInfo -AppName 'Notepad++','Google Chrome' -ExactMatchOnly -ComputerName 'PC-42'
        Uninstall-Applications -AppsToUninstall $apps -ComputerName 'PC-42' -WhatIf

        .EXAMPLE
        # List all non-system apps on a remote host and remove them
        $apps = Get-AppUninstallInfo -ListAll -ComputerName 'LAB-10'
        Uninstall-Applications -AppsToUninstall $apps -ComputerName 'LAB-10' -Confirm

        .NOTES
        - Requires administrative privileges for best results; some uninstallers require elevation.
        - Uninstallers without silent flags may prompt interactively; fallback flags are best-effort.
        - Remote path resolution is performed on the remote machine; local validation is not used for remote targets.
        - Success codes 0, 3010 (reboot required), and 1641 (reboot initiated) are treated as successful.
        - Respects -WhatIf and -Confirm due to SupportsShouldProcess.
        - Default per-attempt timeout is 300 seconds; adjust inside Uninstall-WithTimeout if needed.

        .LINK
        Get-AppUninstallInfo
        Start-Process
        Invoke-Command
        Wait-Job
    #>
    [CmdletBinding(SupportsShouldProcess,SupportsVerbose,ConfirmImpact='None')]
    Param (
        [Parameter(Mandatory,HelpMessage='Apps to Uninstall')]
        [array]$AppsToUninstall,
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $failedUninstalls = @()
    $total            = $AppsToUninstall.Count
    $current          = 0

    #region Helpers
    Function Uninstall-WithTimeout  {
        <#
            .SYNOPSIS
            Runs an uninstaller (EXE or msiexec) locally or on a remote computer, enforces a 
            per-attempt timeout, and returns $true on success (exit codes 0, 3010, 1641) or $false otherwise.
        #>
        Param (
            [Parameter(Mandatory,HelpMessage='EXE path')]
            [string]$ExePath,
            [Parameter(Mandatory,HelpMessage='App Name')]
            [string]$AppName,
            [Parameter()]
            [string]$Arguments,
            [int]$TimeoutSeconds = 300,
            [string]$ComputerName = $env:COMPUTERNAME
        )

        $EASilent = 'SilentlyContinue'

        If ($ComputerName -and ($ComputerName -ne $env:COMPUTERNAME)) {
            ### Remote: run Start-Process on the target via a background job
            $sb = {
                Param($exe,$args)
                $proc = Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -Wait -PassThru
                $proc.ExitCode
            }
            $job = Invoke-Command -ComputerName $ComputerName -ScriptBlock $sb -ArgumentList @($ExePath,$Arguments) -AsJob
            $completed = $job | Wait-Job -Timeout $TimeoutSeconds
            If (-not $completed) {
                Write-Warning -Message ('Uninstall of {0} on {1} timed out after {2} seconds.' -f $AppName,$ComputerName,$TimeoutSeconds)
                Stop-Job $job -ErrorAction $EASilent | Out-Null
                Remove-Job $job -ErrorAction $EASilent | Out-Null
                return $false
            }
            $exitCode = Receive-Job $job
            Remove-Job $job -ErrorAction $EASilent | Out-Null
        } Else {
            ### Local: same as before
            $job = Start-Job -ScriptBlock {
                Param($exe, $args)
                $proc = Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -Wait -PassThru
                $proc.ExitCode
            } -ArgumentList $ExePath, $Arguments

            $completed = $job | Wait-Job -Timeout $TimeoutSeconds
            If (-not $completed) {
                Write-Warning -Message ('Uninstall of {0} timed out after {1} seconds.' -f $AppName, $TimeoutSeconds)
                Stop-Job $job -ErrorAction $EASilent | Out-Null
                Remove-Job $job -ErrorAction $EASilent | Out-Null
                return $false
            }
            $exitCode = Receive-Job $job
            Remove-Job $job -ErrorAction $EASilent | Out-Null
        }

        $successCodes = 0,3010,1641
        If ($successCodes -contains ([int]$exitCode)) { return $true }
        Write-Warning -Message ('{0} uninstall exited with code {1}.' -f $AppName, $exitCode)
        return $false
    }

    Function Uninstall-WithFallback {
        <#
            .SYNOPSIS
            Tries an uninstaller with a sequence of fallback argument strings (MSI/EXE), locally or 
            remotely, honoring -WhatIf/-Confirm; returns $true on first success (0/3010/1641), otherwise $false.
        #>
        Param (
            [Parameter(Mandatory,HelpMessage='EXE Path')]
            [string]$ExePath,
            [Parameter(Mandatory,HelpMessage='App Name')]
            [string]$AppName,
            [Parameter(Mandatory,HelpMessage='Fallback Arguments')]
            [string[]]$FallbackArgs,
            [string]$ComputerName = $env:COMPUTERNAME
        )

        ### Force Confirm OFF in this scope (but keep -WhatIf behavior)
        $prevConfirm       = $ConfirmPreference
        $ConfirmPreference = 'None'
        Try {
            ForEach ($arg in $FallbackArgs) {
                Try {
                    If ($PSCmdlet.ShouldProcess($AppName, "Uninstall via $ExePath $arg")) {
                        Write-Verbose -Message ("Attempting uninstall of '{0}' with: {1} {2}" -f $AppName, $ExePath, $arg)
                        $ok = Uninstall-WithTimeout -ExePath $ExePath -AppName $AppName -Arguments $arg -ComputerName $ComputerName
                        If ($ok) { return $true }
                        Write-Warning -Message ("'{0}' uninstall with '{1}' failed." -f $AppName, $arg)
                    }
                } Catch {
                    Write-Warning -Message ("Failed uninstall attempt for '{0}' with '{1}': {2}" -f $AppName, $arg, $_)
                }
            }
            return $false
        } Finally {
            $ConfirmPreference = $prevConfirm
        }
    }
    #endregion Helpers

    ForEach ($app in $AppsToUninstall) {
        $current++
        Write-Progress -Activity 'Uninstalling Applications' -Status ('Removing {0}' -f $app.Name) -PercentComplete (($current / $total) * 100)

        If (-not $app.UninstallerPath) {
            Write-Warning -Message ('No uninstaller path found for {0}. Skipping.' -f $app.Name)
            $failedUninstalls += $app
            continue
        }

        ### Resolve exe path if not MSI
        $exePath = $app.UninstallerPath -replace '^"(.*)"$','$1'  ### Strip enclosing quotes if present

        If ($ComputerName -eq $env:COMPUTERNAME) {
            If (-not $app.IsMSI) {
                If (-not (Test-Path -LiteralPath $exePath)) {
                    $cmd = Get-Command -Name $exePath -ErrorAction SilentlyContinue
                    If ($cmd -and $cmd.Source) {
                        $exePath = $cmd.Source
                    } Else {
                        Write-Warning -Message ("Uninstaller not found for '{0}': {1}. Skipping." -f $app.Name, $app.UninstallerPath)
                        $failedUninstalls += $app
                        continue
                    }
                }
            }
        } #Else { ### Remote: trust the remote machine to resolve the path via Start-Process }

        ### Prefer MSI args, then registry args, then generic
        $fallbackArgs = @()
        If ($app.MSIarguments)         { $fallbackArgs += $app.MSIarguments }
        If ($app.UninstallerArguments) { $fallbackArgs += $app.UninstallerArguments }
        $fallbackArgs += '/S','/silent','/quiet','/qn','/verysilent'
        $fallbackArgs  = $fallbackArgs | Where-Object { $_ } | Select-Object -Unique

        $success = Uninstall-WithFallback -ExePath $exePath -AppName $app.Name -FallbackArgs $fallbackArgs -ComputerName $ComputerName
        If (-not $success) { $failedUninstalls += $app }
    }

    Write-Progress -Activity 'Uninstalling Applications' -Completed

    If ($failedUninstalls.Count -gt 0) {
        Write-Warning -Message 'The following applications could NOT be uninstalled:'
        $failedUninstalls | ForEach-Object { Write-Warning -Message $_.Name }
    } Else {
        Write-Host 'All applications uninstalled successfully.' -ForegroundColor Green
    }

    return $failedUninstalls
}
#endregion Functions

#region Main script logic
$MSG = @{
  'Admin'   = 'This script is not running with administrative privileges. Please run it as Administrator for best results.'
  'PromptC' = 'Enter computer name (leave blank for local machine)'
  'PromptA' = 'Enter one or more application names (comma-separated, e.g. Chrome,Java,Notepad++)'
  'ERR1'    = 'No valid application names provided. Exiting.'
  'Search'  = "Searching for applications matching '{0}' on '{1}'..."
  'NoMatch' = "No applications found matching '{0}'"
  'ERR2'    = "No matching applications found on '{0}'. Exiting."
  'Prompt3' = "`nDo you want to uninstall ALL of these applications? (Y/N)"
  'Fail'    = "`nThe following applications failed to uninstall:"
  'Success' = "`nAll applications uninstalled successfully."
}

If (-not (Test-Admin)) { Write-Warning -Message $MSG.Admin }

### Prompt for computer name to allow remote targeting
$targetComputer = Read-Host -Prompt $MSG.PromptC
If ([string]::IsNullOrWhiteSpace($targetComputer)) { $targetComputer = $env:COMPUTERNAME }

#region App input
### Prompt for app name(s) - comma separated
$appNameInput = Read-Host -Prompt $MSG.PromptA

### Split into an array, trimming extra whitespace
$appNames = ($appNameInput -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_}

### Validate
$useListAll = -not $appNames
If (-not $useListAll -and -not $appNames) {
    Write-Warning -Message $MSG.ERR1
    return
}
#endregion App input

### Initialize output array
$appList = @()

### Get the list of applications
$searchLabel = If ($useListAll) { 'ALL' } Else { ($appNames -join ', ') }
Write-Host ($MSG.Search -f $searchLabel, $targetComputer)

If ($useListAll) {
    $results = Get-AppUninstallInfo -ListAll -ComputerName $targetComputer -IncludeSystemComponents:$false
} Else {
    $results = Get-AppUninstallInfo -AppName $appNames -ComputerName $targetComputer -ExactMatchOnly:$false -IncludeSystemComponents:$false
}

If ($results) { $appList += $results } Else { Write-Warning -Message ($MSG.NoMatch -f $appNames) }

If ($appList.Count -eq 0) {
    Write-Warning -Message ($MSG.Err2 -f $targetComputer)
    return
}

### Display found applications
Write-Host "`nApplications found:"
$appList | ForEach-Object { Write-Host (" - {0}`tVersion: {1}" -f $_.Name, $_.Version) }

### Confirm uninstall
$response = Read-Host -Prompt $MSG.Prompt3
If ($response -notmatch '[Yy]') {
    Write-Host 'Uninstall cancelled by user.'
    return
}

### Run uninstall
$failed = Uninstall-Applications -AppsToUninstall $appList -ComputerName $targetComputer
If ($failed.Count -gt 0) {
    Write-Warning -Message $MSG.Fail
    $failed | ForEach-Object { Write-Warning -Message $_.Name }
} Else {
    Write-Host $MSG.Success -ForegroundColor Green
}
#endregion Main script logic
