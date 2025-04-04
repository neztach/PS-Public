Function Show-ColoredLogoWithSystemInfo {
    ### Environment Detection
    $isOhMyPosh = $env:POSH_THEME -or $env:POSH_SESSION
    If ($isOhMyPosh) { return }

    Function Write-Color {
        <#
            .SYNOPSIS
            Color Writing helper
        #>
        [CmdletBinding()]
        Param (
            [String[]]$Text,
            [ConsoleColor[]]$Color = [ConsoleColor]::White,
            [switch]$NoNewLine
        )
        $segments = @()
        For ($i = 0; $i -lt $Text.Length; $i++) {
            $fg = If ($i -lt $Color.Count) { $Color[$i] } Else { $Color[0] }
            $segments += @{ Text = $Text[$i]; Color = $fg }
        }

        ForEach ($segment in $segments) {
            Write-Host -NoNewline:$true -ForegroundColor $segment.Color -Object $segment.Text
        }

        If (-not $NoNewLine) {
            Write-Host
        }
    }

    Function Get-SystemInfoLines {
        <#
            .SYNOPSIS
            Get System Infos
        #>
        $os       = Get-CimInstance -ClassName Win32_OperatingSystem
        $comp     = Get-CimInstance -ClassName Win32_ComputerSystem
        $uptime   = (Get-Date) - $os.LastBootUpTime
        $cpu      = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $gpu      = Get-CimInstance -ClassName Win32_VideoController | Select-Object -First 1
        $memTotal = [math]::Round($comp.TotalPhysicalMemory / 1GB, 2)
        $sysDrive = Get-PSDrive -Name C
        $used     = [math]::Round($sysDrive.Used / 1GB, 1)
        $total    = $used + [math]::Round($sysDrive.Free / 1GB, 1)

        Try {
            $geo = Invoke-RestMethod -Uri 'http://ip-api.com/json/'
            $ip  = $geo.query
            $loc = "$($geo.city), $($geo.regionName)"
            $isp = $geo.isp
        } Catch {
            $ip  = 'Unavailable'
            $loc = 'Unknown'
            $isp = 'Unavailable'
        }

        return @(
            [PSCustomObject]@{Label = 'OS       '; Value = "$($os.Caption) $($os.OSArchitecture)" }
            [PSCustomObject]@{Label = 'Hostname '; Value = $env:COMPUTERNAME }
            [PSCustomObject]@{Label = 'User     '; Value = $env:USERNAME }
            [PSCustomObject]@{Label = 'Uptime   '; Value = "$([int]$uptime.TotalDays)d $($uptime.Hours)h $($uptime.Minutes)m" }
            [PSCustomObject]@{Label = 'CPU      '; Value = $cpu.Name.Trim() }
            [PSCustomObject]@{Label = 'GPU      '; Value = $gpu.Name }
            [PSCustomObject]@{Label = 'Memory   '; Value = "$memTotal GB" }
            [PSCustomObject]@{Label = 'Disk (C:)'; Value = "$used GB used / $total GB total" }
            [PSCustomObject]@{Label = 'Shell    '; Value = "PowerShell $($PSVersionTable.PSVersion)" }
            [PSCustomObject]@{Label = 'IP Addr  '; Value = $ip }
            [PSCustomObject]@{Label = 'Location '; Value = $loc }
            [PSCustomObject]@{Label = 'ISP      '; Value = $isp }
        )
    }

    $script:info = Get-SystemInfoLines
    Set-Variable -Name infoIndex -Value 0 -Scope script

    Function PrintInfo {
        If ($script:infoIndex -lt $script:info.Count) {
            $item       = $script:info[$script:infoIndex]
            $labelColor = 'Magenta'
            $valueColor = If ($script:infoIndex % 2 -eq 0) { 'White' } else { 'Gray' }

            $padding    = ' ' * 4
            Write-Host "$padding$($item.Label)" -ForegroundColor $labelColor -NoNewline
            Write-Host " : $($item.Value)" -ForegroundColor $valueColor
            $script:infoIndex++
        } Else {
            Write-Host ''
        }
    }

    Clear-Host

    #region Logo + Info
    Write-Color -Text '                            .?7'                   -Color Cyan
    Write-Color -Text '                        .~?P@@Y'                   -Color Cyan -NoNewLine; PrintInfo
    Write-Color -Text '                 .o!7?','YPB#@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '             .!YBBY7^:','7@@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '           ^Y#@@J.','    ^@@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '         .Y@@@&^','      ^@@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '        .G@@@@J','       ^@@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '        ?@@@@@J','       ^@@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '        J@@@@@&!','      ^@@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '        ^@@@@@@@5^','    ^@@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '         ?@@@@@@@@P!.',' :&@@@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '          !#@@@@@@@@#Y^:','7G@@@@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '           .J#@@@@@@@@@G7:','^Y#@Y'                -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '             .?B@@@@@@@@@&5&~','^!'             -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '                ~5&@@@@@@@@@B?',':'             -Color Yellow, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '                  .?G@@@@@@@@@@P!'              -Color Yellow -NoNewLine; PrintInfo
    Write-Color -Text '           :^!777~.  ^Y#@@@@@@@@@B?.'              -Color Yellow -NoNewLine; PrintInfo
    Write-Color -Text '       .75#@@&P?~:.','   ^:','!G@@@@@@@@@#?'       -Color Yellow, DarkCyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '     .Y&@@@#7.','        ^B?:','^Y&@@@@@@@@B^'     -Color Yellow, DarkCyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '    ~#@@@@P.','          ','^@@&5^',':?#@@@@@@@@!' -Color Yellow, Cyan, DarkCyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '   ^&@@@@&:','           ^@@','@@G!.','?#@@@@@@@^' -Color Yellow, Cyan, DarkCyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '   Y@@@@@B','            ^@@@@','@@@J',' .J@@@@@@G' -Color Yellow, Cyan, DarkCyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '   P@@@@@#.','           ^@@@@@@','@Y','   ~&@@@@&:'-Color Yellow, Cyan, DarkCyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '   7@@@@@@J','           ^@@@@@@@','Y','    !@@@@@^'  -Color Yellow, Cyan, DarkCyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '    Y@@@@@@J','          ^@@@@@@@J','    .#@@@&.'  -Color Yellow, Cyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '     ?&@@@@@G~','        ^@@@@@@@?','    ^@@@@?'   -Color Yellow, Cyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '      .J#@@@@@B?^','     ^@@@@@@@!','   ^B@@@?'    -Color Yellow, Cyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '         ~YB&@@@@#P','J!^','7@@@@@@&^','^7P@@#5^' -Color Yellow, DarkYellow, Cyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '     ~?JY?:',' ',':!J5G#&','@@@','@@@@@@@&','###GJ!.' -Color DarkCyan, Cyan, Yellow, DarkYellow, Cyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '   !B@@@','#5b','      ..', ':^^','B@@@@@&~',':.'     -Color Cyan, DarkCyan, Yellow, DarkYellow, Cyan, Yellow -NoNewLine; PrintInfo
    Write-Color -Text '  ~@@@@5','  7.','         ~@@@@@@7'                     -Color Cyan, DarkCyan, Cyan -NoNewLine; PrintInfo
    Write-Color -Text '  ?@@@@!            .B@@@@&7'                      -Color Cyan -NoNewLine; PrintInfo
    Write-Color -Text '  ^&@@@P           :B@@@@P^'                       -Color Cyan -NoNewLine; PrintInfo
    Write-Color -Text '   ~B@@@G~       .?&@@&P~'                         -Color Cyan -NoNewLine; PrintInfo
    Write-Color -Text '    .7P#@@#5J??YG&@B57:'                           -Color Cyan -NoNewLine; PrintInfo
    Write-Color -Text '       .~7J5P55Y?~:'                               -Color Cyan -NoNewLine; PrintInfo
    #endregion Logo + Info
}
Show-ColoredLogoWithSystemInfo
