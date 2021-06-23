Function Find-Lockouts {
    <#
            .SYNOPSIS
            Find all users that are locked out
            .DESCRIPTION
            Finds all users that are locked out
            .PARAMETER Unlock
            Unlock all those locked out
            .EXAMPLE
            Find-Lockouts -Unlock

            Unlocks all locked users
            .EXAMPLE
            Unlocker

            menu to unlock users
    #>
    [CmdletBinding()][Alias('Unlocker')]Param([switch]$Unlock)
    $GRN = 'Green'
    Add-Type -AssemblyName PresentationFramework
    $LockedOutUsers = Search-ADAccount -LockedOut
    If ($Unlock -OR ($MyInvocation.InvocationName -eq 'Unlocker')){
        If ($LockedOutUsers){
            ### Function to test for a specific account lockout (verify)
            Function Get-UserLockedOut {
                <#
                        .SYNOPSIS
                        Find lockout status of a specific user
                        .DESCRIPTION
                        Finds current lockout status of a specific user by samaccountname
                        .PARAMETER CheckUser
                        The user to check if locked out.
                        .EXAMPLE
                        Get-UserLockedOut testuser
                #>
                Param ([Parameter(Mandatory=$true,HelpMessage='Username required')]$CheckUser)
                $lockstatus = Get-ADUser -Identity $CheckUser -Properties LockedOut | Select-Object -Property Name,@{n='Username';e={$_.SamAccountName}},LockedOut
                $lockstatus = $lockstatus | Select-Object -Property Username,Name,LockedOut
                Return $lockstatus
            }

            ### 1. Get list of lockouts
            $StepOne = Search-ADAccount -LockedOut | Select-Object -Property Name,@{n='Username';e={$_.SamAccountName}} | Sort-Object -Property Name

            ### 2. Put up menu (gridview) of locked accounts or tell user none were found
            $StepTwo = If ($StepOne){
                #SINGLE $StepOne | Select-Object -Property Username,Name | Out-GridView -Title "User unlocker $(Get-Date)" -OutputMode Single
                $StepOne | Select-Object -Property Username,Name | Out-GridView -Title "User unlocker $(Get-Date)" -Passthru
            } else {
                [Windows.MessageBox]::Show('No locked out users found')
            }

            ### 3. Check if a username was selected, and if-so unlock
            If ($StepTwo.Username){
                ### MULTIPLE
                ForEach ($lockedUser in $StepTwo){
                    #If ($lockedUser.Username){
                    #SINGLE $lockeduser = $StepTwo.Username
                    $lockedusername = $lockedUser.Username
                    $unlocks       += $lockedusername
                    #SINGLE Get-ADUser $lockeduser | Unlock-ADAccount
                    Get-ADUser -Identity $lockedusername | Unlock-ADAccount
                }
            } else {
                Write-Host 'No user selected' -ForegroundColor Yellow
            }

            ### 4. Verify account was unlocked
            ### MULTIPLE
            ForEach ($verification in $unlocks){
                #SINGLE If ($StepTwo.Username){
                $v = Get-UserLockedOut -Checkuser $verification
                if ($v.Lockedout -eq $false){
                    #SINGLE Write-Host "Unlocked: $($lockeduser.name)" -ForegroundColor Green
                    Write-Host ('Unlocked: {0}' -f $v.name) -ForegroundColor $GRN
                    Return
                } else {
                    #SINGLE Write-Host "Unable to unlock $($lockeduser.name)" -ForegroundColor Red
                    Write-Host ('Unable to unlock {0}' -f $v.name) -ForegroundColor Red
                    #SINGLE $lockedUser.DistinguishedName
                    $v.DistinguishedName
                    Return
                }
            }
            $LockedOutUsers | Select-object -Property SamAccountName,Name
        } else {
            Write-Host 'Checked for user lockouts - none found.' -ForegroundColor $GRN
        }
    } else {
        If ($LockedOutUsers){
            $LockedOutUsers | Select-Object -Property SamAccountName,Name
        } else {
            Write-Host 'No locked out users to report' -ForegroundColor $GRN
        }
    }
} ### DOMAIN - USER
New-Alias -Name WhosLocked -Value Find-Lockouts
