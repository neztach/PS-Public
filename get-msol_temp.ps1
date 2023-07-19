#region Check for MSOnline module
$Modules = Get-Module -Name MSOnline -ListAvailable
If ($Modules.count -eq 0){
    Write-Output -InputObject 'Please install MSOnline module (as Administrator): '
    Write-Output -InputObject 'Install-Module -Name MSOnline'
    Exit
} Else {
    Connect-MsolService
}
#endregion

Function Get-MFAStatus {
    <#
            .SYNOPSIS
            Get users and details from O365
            .DESCRIPTION
            Get users and details from O365 based on flags used
            .PARAMETER
            Choose which parameter to run the script with or it willdefault to the first option

            all-en-nocontacts - Get all Enabled users that are users and not contacts
            all-en            - Get all Enabled users (even if they are only contacts)
            all-nocontacts    - Get all users (whether they are Enabled or Disabled) that are users and not contacts
            all               - Get all users (whether they are Enabled or Disabled) including users that are only contacts
            nolicense         - Get all users wwithout a license
            disabled          - Get all Disabled users
    #>
    [CmdletBinding(DefaultParametersetName='None')]
    Param (
        [Nullable[boolean]]$SignInAllowed = $null,
        [Parameter(
                Position    = 0,
                HelpMessage = 'Which users are we targeting',
                Mandatory   = $true
        )]
        [ValidateSet(
                'all-en-nocontacts', 
                'all-en', 
                'all-nocontacts', 
                'all', 
                'nolicense', 
                'disabled', 
                'nopasschange'
        )]
        [ValidateNotNullOrEmpty()]
        [string]$RunType,
        [Parameter(
                ParameterSetName = 'FileOutput',
                Mandatory = $false
        )]
        [switch]$SaveFile,
        [Parameter(
                ParameterSetName = 'FileOutput',
                HelpMessage = 'Path for file output',
                Mandatory = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$OutPath,
        [switch]$Grid
    )

    #region Variables
    $FinalResult = @()
    $PrintedUser = 0
    $DateFormat  = (Get-Date -Format yyyy-MMM-dd-ddd_hh-mm_tt).ToString()
    $xlsx        = '.csv'

    ### Progress Meter - Initialization
    $pi       = 0
    $Progress = @{
        Activity         = 'Working through users . . .'
        CurrentOperation = 'Loading'
        PercentComplete  = 0
    }

    #endregion #variables

    #region Decide which query to run
    If (-not $RunType) {$RunType = 'all-en-nocontacts'}

    Switch ($RunType)  {
        'all-en-nocontacts' {
            $torun     = {Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object ImmutableID -ne $NULL}
            $GridTitle = 'All Enabled Users (excluding entries that are only contacts)'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_All-Enabled-NoContacts_' + $DateFormat + $xlsx}
        }
        'all-en'            {
            $torun     = {Get-MsolUser -EnabledFilter EnabledOnly -All}
            $GridTitle = 'All Enabled users (including users that are only contacts)'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_All-Enabled_' + $DateFormat + $xlsx}
        }
        'all-nocontacts'    {
            $torun     = {Get-MsolUser -All | Where-Object ImmutableID -ne $NULL}
            $GridTitle = 'All Users, enabled or not (excluding entries that are only contacts)'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_All-NoContacts_' + $DateFormat + $xlsx}
        }
        'all'               {
            $torun     = {Get-MsolUser -All}
            $GridTitle = 'All Users, enabled or not (including entries that are only contacts)'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_All_' + $DateFormat + $xlsx}
        }
        'nolicense'         {
            $torun     = {Get-MsolUser -UnlicensedUsersOnly}
            $GridTitle = 'Unlicensed Users'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_UnlicensedUsersOnly_' + $DateFormat + $xlsx}
        }
        'disabled'          {
            $torun     = {Get-MsolUser -EnabledFilter DisabledOnly -ALL}
            $GridTitle = 'All Disabled Users'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_All-Disabled-Users_' + $DateFormat + $xlsx}
        }
        'nopasschange'      {
            $torun     = {Get-MsolUser -All | Where-Object {$_.LastPasswordChangeTimestamp -lt (Get-Date).AddDays(-90)}}
            $GridTitle = 'Users without a password change in the last 90 days'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_NoPassChange_' + $DateFormat + $xlsx}
        }
        default {
            $torun     = {Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object ImmutableID -ne $NULL}
            $GridTitle = 'All Enabled Users (excluding entries that are only contacts)'
            If ($OutPath) {$ExportCSV = $OutPath + '\MSOL-Output_All-Enabled-NoContacts_' + $DateFormat + $xlsx}
        }
    }
    <########### More queries ############
            # No password change in the last 90 days
            #   Get-MsolUser -All | Where-Object {$_.LastPasswordChangeTimestamp -lt (Get-Date).AddDays(-90)} | Select-Object DisplayName,UserPrincipalName,LastPasswordChangeTimestamp,Licenses,PasswordNeverExpires
            # Deleted accounts
            #   Get-MsolUser -ReturnDeletedUsers | FL UserPrincipalName,ObjectID
            #
            ### Useful fields: UserPrincipalName, DisplayName, PhoneNumber, Department, UsageLocation, whenCreated
    #>
    #endregion Query decision

    ### Based on query decision -- Loop through each user
    #$Total = (Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object ImmutableID -ne $NULL).Count
    $Total = (& $torun).Count
    #Get-MsolUser -EnabledFilter EnabledOnly -All | Where-Object ImmutableID -ne $NULL | 
    & $torun | Foreach-Object {
        $pi++

        #region base user variables
        $DisplayName   = $_.DisplayName
        $Upn           = $_.UserPrincipalName
        $MFAStatus     = $_.StrongAuthenticationRequirements.State
        $MethodTypes   = $_.StrongAuthenticationMethods
        $RolesAssigned = ''
        
        $Department    = $_.Department
        If ($Department -eq $Null) {$Department = '-'}
        
        If ($RunType -eq 'nopasschange') {
            $LastPasswordChangeTimestamp = $_.LastPasswordChangeTimestamp 
            $Licenses                    = $_.Licenses
            $PasswordNeverExpires        = $_.PasswordNeverExpires
        }
        #endregion base user variables

        #region Progress Meter - Update and Display
        [int]$percentage           = ($pi / $Total) * 100
        $Progress.CurrentOperation = "$pi of $Total - $DisplayName"
        $Progress.PercentComplete  = $percentage
        Write-Progress @Progress
        #endregion Progress Meter

        #region Can this user sign in
        If ($_.BlockCredential -eq $true) {$SignInStat = 'Denied'} Else {$SignInStat = 'Allowed'}
        #endregion

        #region License status
        If ($_.IsLicensed -eq $true) {$LicenseStat = 'Licensed'} Else {$LicenseStat = 'Unlicensed'}
        #endregion

        #region Check for user admin role
        $Roles = (Get-MsolUserRole -UserPrincipalName $upn).Name
        If ($Roles.count -eq 0) {
            $RolesAssigned = 'No roles'
            $IsAdmin       = 'False'
        } Else {
            $IsAdmin = 'True'
            ForEach ($Role in $Roles) {
                $RolesAssigned = $RolesAssigned + $Role
                If ($Roles.indexof($role) -lt (($Roles.count)-1)) {$RolesAssigned = $RolesAssigned + ','}
            }
        }
        #endregion

        #region Establish MFA Enabled/Disabled and add to $FinalResult
        If (($MethodTypes -ne $Null) -or ($MFAStatus -ne $Null)) {
            ### Check for Conditional Access
            If ($MFAStatus -eq $null){$MFAStatus = 'Enabled via Conditional Access'}

            $Methods          = ''
            $MethodTypes      = ''

            $MethodTypes      = $_.StrongAuthenticationMethods.MethodType
            $DefaultMFAMethod = ($_.StrongAuthenticationMethods | Where-Object {$_.IsDefault -eq 'True'}).MethodType
            $MFAPhone         = $_.StrongAuthenticationUserDetails.PhoneNumber
            $MFAEmail         = $_.StrongAuthenticationUserDetails.Email

            If ($MFAPhone -eq $Null) {$MFAPhone = '-'}
            If ($MFAEmail -eq $Null) {$MFAEmail = '-'}

            If ($MethodTypes -ne $Null) {
                $ActivationStatus = 'Yes'
                ForEach ($MethodType in $MethodTypes) {
                    If ($Methods -ne '') {$Methods = $Methods + ','}
                    $Methods = $Methods + $MethodType
                }
            } Else {
                $ActivationStatus = 'No'
                $Methods          = '-'
                $DefaultMFAMethod = '-'
                $MFAPhone         = '-'
                $MFAEmail         = '-'
            }

            #region Add results of Enabled MFA users to $FinalResult
            $PrintedUser++
            If ($RunType -eq 'nopasschange') {
                $FinalResult += New-Object -TypeName PSObject -Property ([ordered]@{
                        'DisplayName'                 = $DisplayName
                        'UserPrincipalName'           = $upn
                        'Department'                  = $Department
                        'MFAStatus'                   = $MFAStatus
                        'ActivationStatus'            = $ActivationStatus
                        'DefaultMFAMethod'            = $DefaultMFAMethod
                        'AllMFAMethods'               = $Methods
                        'MFAPhone'                    = $MFAPhone
                        'MFAEmail'                    = $MFAEmail
                        'LicenseStatus'               = $LicenseStat
                        'IsAdmin'                     = $IsAdmin
                        'AdminRoles'                  = $RolesAssigned
                        'SignInStatus'                = $SigninStat
                        'LastPasswordChangeTimestamp' = $LastPasswordChangeTimestamp
                        'Licenses'                    = $Licenses
                        'PasswordNeverExpires'        = $PasswordNeverExpires
                })
            } Else {
                $FinalResult += New-Object -TypeName PSObject -Property ([ordered]@{
                        'DisplayName'       = $DisplayName
                        'UserPrincipalName' = $upn
                        'Department'        = $Department
                        'MFAStatus'         = $MFAStatus
                        'ActivationStatus'  = $ActivationStatus
                        'DefaultMFAMethod'  = $DefaultMFAMethod
                        'AllMFAMethods'     = $Methods
                        'MFAPhone'          = $MFAPhone
                        'MFAEmail'          = $MFAEmail
                        'LicenseStatus'     = $LicenseStat
                        'IsAdmin'           = $IsAdmin
                        'AdminRoles'        = $RolesAssigned
                        'SignInStatus'      = $SigninStat
                })
            }
            #endregion
        } ElseIf (($MFAStatus -eq $Null) -and ($_.StrongAuthenticationMethods.MethodType -eq $Null)) {
            $MFAStatus  = 'Disabled'

            #region Add results of Disabled MFA users to $FinalResult
            $PrintedUser++
            If ($RunType -eq 'nopasschange') {
                $FinalResult += New-Object -TypeName PSObject -Property ([ordered]@{
                        'DisplayName'                 = $DisplayName
                        'UserPrincipalName'           = $upn
                        'Department'                  = $Department
                        'MFAStatus'                   = $MFAStatus
                        'ActivationStatus'            = $ActivationStatus
                        'DefaultMFAMethod'            = $DefaultMFAMethod
                        'AllMFAMethods'               = $Methods
                        'MFAPhone'                    = $MFAPhone
                        'MFAEmail'                    = $MFAEmail
                        'LicenseStatus'               = $LicenseStat
                        'IsAdmin'                     = $IsAdmin
                        'AdminRoles'                  = $RolesAssigned
                        'SignInStatus'                = $SigninStat
                        'LastPasswordChangeTimestamp' = $LastPasswordChangeTimestamp
                        'Licenses'                    = $Licenses
                        'PasswordNeverExpires'        = $PasswordNeverExpires
                })
            } Else {
                $FinalResult += New-Object -TypeName PSObject -Property ([ordered]@{
                        'DisplayName'       = $DisplayName
                        'UserPrincipalName' = $upn
                        'Department'        = $Department
                        'MFAStatus'         = $MFAStatus
                        'ActivationStatus'  = '-'
                        'DefaultMFAMethod'  = '-'
                        'AllMFAMethods'     = '-'
                        'MFAPhone'          = '-'
                        'MFAEmail'          = '-'
                        'LicenseStatus'     = $LicenseStat
                        'IsAdmin'           = $IsAdmin
                        'AdminRoles'        = $RolesAssigned
                        'SignInStatus'      = $SigninStat
                })
            }
            #endregion
        }
        #endregion MFA Enabled/Disabled and add to $FinalResult
    }

    ### Export our findings $FinalResult
    #$FinalResult | Export-Csv -Path "C:\down\MSOL-Output_$((Get-Date -format yyyy-MMM-dd-ddd_hh-mm_tt).ToString()).csv" -NotypeInformation

    #region Open output file after execution
    Write-Output -InputObject "`r`nUser gathering successful"

    If ((-not $SaveFile) -and (-not $Grid)){
        $option = Read-Host -Prompt 'Savefile or grid'
        Switch ($option){
            'SaveFile' {
                $SaveFile = $true
                $OutPath  = Read-Host -Prompt 'Output Path'
            }
            'Grid'     {
                $Grid     = $true
            }
        }
    }
    ### If output exported...
    If ($SaveFile) {
        #ConvertTo-Excel -DataTable $FinalResult -FilePath $ExportCSV -ExcelWorksheetName $GridTitle -AutoFilter -AutoFit -FreezeTopRow
        $FinalResult | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8 -Delimiter ','
        Write-Output -InputObject "MFA Disabled user report available in: $OutPath"
        
        ### Prompt to open output file with default application for .CSV files (Excel)
        $Prompt    = New-Object -ComObject wscript.shell
        $UserInput = $Prompt.popup('Do you want to open output file?',0,'Open Output File',4)
        If ($UserInput -eq 6) {
            Invoke-Item -Path "$ExportCSV"
        }
        Write-Output -InputObject "Exported report has $($PrintedUser) users"
    } Elseif ($grid) {
        ### Chose not to output file. Check if GridView was chosen.
        $FinalResult | Out-GridView -Title "$GridTitle - $DateFormat"
    }
    #endregion

    #Clean up session
    Get-PSSession | Remove-PSSession
}

Get-MFAStatus -runtype 'all-en-nocontacts' -savefile -Verbose
