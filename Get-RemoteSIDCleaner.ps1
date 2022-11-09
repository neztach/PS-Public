### script to remotely check a workstation's Windows profiles, then resolve them back to a SID to see if the user still exists in Active Directory. If not, delete the profile.
### https://old.reddit.com/r/PowerShell/comments/yj6tsf/what_have_you_done_with_powershell_this_month/iutey0b/?context=3
Function Get-SidToUser      {
    <#
        .SYNOPSIS
        Lookup SID in AD.
    #>
    Param ([Parameter(Mandatory,HelpMessage='SID')][String]$SID)
    $ad       = [adsi]"LDAP://<SID=$SID>"
    $UserID   = $ad.sAMAccountName
    $UserName = $ad.Name
    If ($UserID) {
        $obj = [PSCustomObject]@{
            UserID = $UserID
            Name   = $UserName
        }
        return $obj
    } Else {
        throw 'Invalid SID.'
    }
}
 
Function Write-ArrayToTable {
    <#
            .SYNOPSIS
            Write array to table.
    #>
    Param (
        [Parameter(Mandatory,HelpMessage='Names')][String[]]$Names, 
        [Parameter(Mandatory,HelpMessage='Data')][Object[][]]$Data
    )

    $myProps = For ($i=0; ;++$i) {
        $Props = [Ordered]@{}
        For ($j=0;$j -lt $Data.Length; ++$j){
            If ($i -lt $Data[$j].Length) {
                $Props.Add($Names[$j], $Data[$j][$i])
            }
        }
        If (!$Props.get_Count()) {break}
        [PSCustomObject]$Props
    }
    $myProps | Format-Table
}
 
Function Read-YesNo         {
    <#
        .SYNOPSIS
        Read a Yes/No Prompt.
    #>
    [CmdletBinding()]
    Param ([String]$Title = 'Confirmation needed.', [String]$Message = 'Are you sure?')
    $choiceYes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Answer Yes.'
    $choiceNo  = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Answer No.'
    $options   = [Management.Automation.Host.ChoiceDescription[]]($choiceYes, $choiceNo)
    $result    = $host.ui.PromptForChoice($title, $message, $options, 1)
    Switch ($result) {
        0 {return $true}
        1 {return $false}
    }
}

Function Get-Exiter         {
    <#
            .SYNOPSIS
            Exit the script.
    #>
    [CmdletBinding()]
    Param (
        [string]$input, 
        [switch]$good, 
        [switch]$bad
    )
    $Ye = @{ForegroundColor = 'Yellow'}
    $Re = @{ForegroundColor = 'Red'}

    $PE = 'Press enter to exit'
    If ($input) {
        If ($input -match 'ERROR') {
            Write-Host $input @Re
        } Else {
            Write-Host $input @Ye
        }
    }

    Read-Host -Prompt $PE
    If ($good) {
        exit 0
    } ElseIf ($bad) {
        exit 1
    }
}

$IgnoredAccounts = @($env:UserName, 'Public', 'default', 'administrator', 'technology', 'tech', 'tech2', 'cnb')
$Computer        = Read-Host -Prompt "`nEnter the computer name"
If (Test-Connection -ComputerName $Computer -Quiet) {
    [Collections.ArrayList]$BadProfiles     = @()
    [Collections.ArrayList]$RemovedProfiles = @()
    [Collections.ArrayList]$LockedProfiles  = @()
    [Collections.ArrayList]$objBadProfiles  = @()
    [Collections.ArrayList]$tmp             = @()
    $Profiles = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $Computer -ErrorAction SilentlyContinue | 
                Where-Object {-not ($_.Special)} | Where-Object {$_.LocalPath.split('\')[-1] -notin $IgnoredAccounts}

    ForEach ($profile in $Profiles) {
        Try {
            $objSID  = $profile.SID
            $objUser = Get-SidToUser -SID $objSID
        } Catch { # SID not found in AD. Add to BadProfiles array.
            $err     = $_.Exception
            $null    = $BadProfiles.Add($profile.LocalPath)

            # If profile is locked, add to LockedProfiles array.
            If ($profile.Loaded -eq $true) {
                $null = $LockedProfiles.Add($profile.LocalPath)
            } Else {
                $null = $objBadProfiles.Add($profile)
            }
        }
    }

    # Print results
    $PE = 'Press enter to exit'
    $NP = "`nNo profiles removed.`n"

    If ($BadProfiles.Count -gt 0) {
        Write-ArrayToTable -Names 'Bad Profiles', 'Locked Profiles' -Data $BadProfiles, $LockedProfiles | Format-Table
    } Else {
        Get-Exiter -input "`nNo bad profiles found on $($Computer.ToUpper()).`n" -good
    }

    $result = Read-YesNo -Title '' -Message 'Remove all unlocked bad profiles?'
    If ($result -eq $true) {
        ForEach ($profile in $objBadProfiles) {
            Write-Host "`nRemoving profile:"
            Write-Host $profile.LocalPath
            $profile | Remove-CimInstance
            $null = $RemovedProfiles.Add($profile.LocalPath)
        }
        If ($RemovedProfiles.Count -gt 0) {
            Write-ArrayToTable -Names 'Removed Profiles','tmp' -Data $RemovedProfiles,$tmp
        } Else {
            Write-Host $NP -ForegroundColor Yellow
        }
        Get-Exiter
    } Else {
        Get-Exiter -input $NP -good
    }
} Else {
    Get-Exiter -Input "`nERROR: $Computer is not accessible." -bad
} 
