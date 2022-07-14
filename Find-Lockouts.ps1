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

        Gridview type of Menu to unlock users
        .EXAMPLE
        WhosLocked

        Output a list of accounts that are locked out and stop.
    #>
    [CmdletBinding()] 
    [Alias('Unlocker')]
    [Alias('WhosLocked')]
    Param([switch]$Unlock)
    
    Begin {
        Add-Type -AssemblyName PresentationFramework

        ### Domain PDC Emulator
        $PDC = Get-AdDomainController -Filter {OperationMasterRoles -like '*PDCEmulator*'} | Select-Object -ExpandProperty HostName

        ### Get current Locked Out users (optional: add -Server $PDC to send the query to your PDC)
        $LockedOutUsers = Search-ADAccount -LockedOut

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
            Param (
                [Parameter(Mandatory=$true,HelpMessage='Username required')]$CheckUser
            )
            $SelParam   = @{Property = 'SamAccountName', 'Name', 'LockedOut'}
            $lockstatus = Get-ADUser -Identity $CheckUser -Properties LockedOut | Select-Object @SelParam
            $lockstatus = $lockstatus | Select-Object @SelParam
            Return $lockstatus
        }
    }
    Process {
        ### If the function is called by the alias 'Unlocker' we assume you want to not only check
        ### but also intend to unlock one or more users.
        If ($Unlock -OR ($MyInvocation.InvocationName -eq 'Unlocker')){
            If ($LockedOutUsers){
                ### 1. Get list of lockouts (Optional: add the $PDC as the server target)
                $StepOne = Search-ADAccount -LockedOut | Select-Object -Property Name, SamAccountName | Sort-Object -Property Name

                ### 2. Put up menu (gridview) of locked accounts or tell user none were found
                $StepTwo = If ($StepOne){
                               $StepOne | Select-Object -Property Username, Name | Out-GridView -Title "User unlocker $(Get-Date)" -Passthru
                           } Else {
                               [Windows.MessageBox]::Show('No locked out users found')
                           }

                ### 3. Check if a username was selected, and if-so unlock
                If ($StepTwo.Username){
                    ForEach ($lockedUser in $StepTwo){
                        $lockedusername = $lockedUser.Username
                        $unlocks       += $lockedusername
                        Get-ADUser -Identity $lockedusername -Server $PDC | Unlock-ADAccount
                    }
                } Else {
                    Write-Warning -Message 'No user selected'
                }

                ### 4. Verify account was unlocked
                ForEach ($verification in $unlocks){
                    $v = Get-UserLockedOut -Checkuser $verification -Server $PDC
                    If ($v.Lockedout -eq $false){
                        Write-Output -InputObject ('Unlocked: {0}' -f $v.name)
                        Return
                    } Else {
                        Write-Error -Exception ('Unable to unlock {0}' -f $v.name)
                        $v.DistinguishedName
                        Return
                    }
                }
                $LockedOutUsers | Select-Object -Property SamAccountName, Name
            } Else {
                Write-Output -InputObject 'Checked for user lockouts - none found.'
            }
        } Else {
            If ($LockedOutUsers){
                $LockedOutUsers | Select-Object -Property SamAccountName, Name
            } Else {
                Write-Output -InputObject 'No locked out users to report'
            }
        }
    }
}
