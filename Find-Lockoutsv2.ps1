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
    [CmdletBinding()]
    [Alias('Unlocker')]
    [Alias('UnlockAll')]
    [Alias('zx')]
    Param (
        [Switch]$Unlock
    )
    
    #region Variables
    Add-Type -AssemblyName PresentationFramework
    
    ### Colors
    $Y      = 'Yellow'
    $R      = 'Red'
    $G      = 'Green'
    $Ye     = @{ForegroundColor = $Y}
    $Re     = @{ForegroundColor = $R}
    $Gr     = @{ForegroundColor = $G}
    
    ### Strings
    $msg1   = 'Checked for user lockouts - none found.'
    $msg2   = 'No user selected'
    $msg3   = "User unlocker $(Get-Date)"
    
    ### Selections
    $Sel1   = 'Name', @{n='Username';e={$_.SamAccountName}}
    $Sel2   = 'Username', 'Name'
    $Sel3   = 'SamAccountName', 'Name'
    
    ### Functions
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
        Param (
            [Parameter(
                    Mandatory = $true, 
                    HelpMessage = 'Username required'
            )]
            [String]$CheckUser
        )
        $lockADSplat  = @{
            Identity   = $CheckUser
            Properties = 'LockedOut'
        }
        $SelSplat     = @{
            Property = @{
                n = 'Username'
                e = {$_.SamAccountName}
            }, 
            'Name', 
            'LockedOut'
        }
                
        $lockstatus = Get-ADUser @lockADSplat | Select-Object @SelSplat
        Return $lockstatus
    }
    #endregion Variables

    $LockedOutUsers = Search-ADAccount -LockedOut
    If ($Unlock -OR ($MyInvocation.InvocationName -eq 'Unlocker')) {
        If ($LockedOutUsers) {
            ### 1. Get list of lockouts
            $StepOne = Search-ADAccount -LockedOut | Select-Object -Property $script:Sel1 | Sort-Object -Property Name

            ### 2. Put up menu (gridview) of locked accounts or tell user none were found
            $StepTwo = If ($StepOne) {
                $StepOne | Select-Object -Property $Sel2 | Out-GridView -Title $msg3 -Passthru
            } Else {
                [Windows.MessageBox]::Show('No locked out users found')
            }

            ### 3. Check if a username was selected, and if-so unlock
            If ($StepTwo.Username) {
                ForEach ($lockedUser in $StepTwo){
                    $lockedusername = $lockedUser.'Username'
                    $unlocks       += $lockedusername

                    Get-ADUser -Identity $lockedusername | Unlock-ADAccount
                }
            } Else {
                Write-Host $msg2 @Ye
            }

            ### 4. Verify account was unlocked
            ForEach ($verification in $unlocks){
                $v = Get-UserLockedOut -Checkuser $verification
                If ($v.Lockedout -eq $false) {
                    Write-Host ('Unlocked: {0}' -f $v.name) @Gr
                    Return
                } Else {
                    Write-Host ('Unable to unlock {0}' -f $v.name) @Re
                    $v.DistinguishedName
                    Return
                }
            }
            $LockedOutUsers | Select-object -Property $Sel3
        } Else {
            Write-Host $msg1 @Gr
        }
    } ElseIf (($MyInvocation.InvocationName -eq 'UnlockAll') -OR ($MyInvocation.InvocationName -eq 'zx')) {
        ### If called with UnlockAll or zx - Get all locked accounts and unlock
        If ($LockedOutUsers) {
            Search-ADAccount -LockedOut | Unlock-ADAccount
            Write-Host (Get-Date)
            $LockedOutUsers | Select-Object -Property $Sel3
        } Else {
            Write-Host $msg1 @Gr
        }
    } Else {
        ### If not called with any specifics, just report lockouts
        If ($LockedOutUsers) {
            $LockedOutUsers | Select-Object -Property $Sel3
        } Else {
            Write-Host $msg1 @Gr
        }
    }
}
