Function Search-ADUser {
    <#
            .SYNOPSIS
            Find any/all users that match.
            .DESCRIPTION
            Finds any/all users that even resemble your search criteria
            .PARAMETER <name or part of name>
            Define the target to look for
            .EXAMPLE
            Search-ADUser jess
            .EXAMPLE
            findu jess
    #>
    [cmdletbinding()]
    [alias('findu')]
    Param (
        [Parameter(
                Mandatory,
                HelpMessage = 'Partial Name / Username'
        )]
        [ValidateNotNullorEmpty()]
        [String]$SearchString
    )
    Begin {
        Function Convert-StandardPhone {
            <#
                    .SYNOPSIS
                    Convert value to proper Phone format.
                    .DESCRIPTION
                    Determine how many digits are in input and format to proper telephone syntax.
                    .PARAMETER NumtoConv
                    Number to convert.
                    .EXAMPLE
                    Convert-StandardPhone -NumtoConv 1234567
                    123-4567
                    .EXAMPLE
                    Convert-StandardPhone -NumtoConv 1234567890
                    (123) 456-7890
            #>
            [cmdletbinding()]
            [alias('conph')]
            Param (
                [Parameter(
                        Mandatory,
                        HelpMessage = 'Phone Number required'
                )]
                [string]$NumtoConv
            )
            If ($NumtoConv -like '*'){
                $pnum       = $NumtoConv -replace '[^0-9]',''
                $pnum       = $pnum -replace '^0' -replace '^1' -replace '\s' -as [LONG]
                $pnumlength = ($pnum | Measure-Object -Character).Characters

                If ($pnumlength -eq 7) {
                    $newPhoneNumber = '{0:###-####}' -f ([long]$pnum)
                } ElseIf ($pnumlength -eq '11') {
                    $pnum           = $pnum.Substring(1)
                    $newPhoneNumber = '{0:(###) ###-####}' -f ([long]$pnum)
                } ElseIf ($pnumlength -eq 10) {
                    $newPhoneNumber = '{0:(###) ###-####}' -f ([long]$pnum)
                } Else {
                    $newPhoneNumber = $NumtoConv
                }
            } Else {
                $newPhoneNumber = $null
            }
            Return $newPhoneNumber
        }
        
        ### Get the local PDC        
        $PDC     = (Get-AdDomainController -Filter {OperationMasterRoles -like '*PDCEmulator*'}).HostName

        ### Get-ADUser Parameters
        $AdParam = @{
            Filter     = "samaccountname -like '*$($SearchString)*' -or 
                          name -like '*$($SearchString)*' -or 
                          givenname -like '*$($SearchString)*' -or 
                          surname -like '*$($SearchString)*' -or 
                          userprincipalname -like '*$($SearchString)*'"
            Properties = 'Company', 
                         'CanonicalName', 
                         'Department', 
                         'Description', 
                         'EmployeeID', 
                         'Enabled', 
                         'GivenName', 
                         'Manager', 
                         'Surname', 
                         'Title', 
                         'LockedOut', 
                         'Fax', 
                         'mobile', 
                         'OfficePhone', 
                         'otherTelephone', 
                         'PasswordLastSet', 
                         'whenCreated', 
                         'whenChanged'
            Server     = $PDC
        }

        ### Select User Paramters
        $mSel    = @{
            Property   = 'DistinguishedName', 
                         'SamAccountname', 
                         'Name', 
                         'Enabled', 
                         'EmployeeID', 
                         'LockedOut', 
                         #'GivenName', 
                         #'Surname', 
                         'Company', 
                         'Title', 
                         'Description', 
                         'Department', 
                         @{
                             n = 'Manager'
                             e = {Try {(Get-ADUser -Identity $_.Manager -ErrorAction Stop).Name} Catch {''}}
                         }, 
                         @{
                             n = 'Container'
                             e = {$_.CanonicalName -ireplace '\/[^\/]+$',''}
                         }, 
                         'UserPrincipalName',
                         @{
                             n = 'MobilePhone'
                             e = {conph $_.mobile}
                         }, 
                         @{
                             n = 'OfficePhone'
                             e = {conph $_.OfficePhone}
                         }, 
                         @{
                             n = 'otherTelephone'
                             e = {(@($_.otherTelephone | ForEach-Object {conph $_}) -join ', ').TrimEnd(', ')}
                         },
                         @{
                             n = 'Fax'
                             e = {conph $_.Fax}
                         }, 
                         'PasswordLastSet', 
                         'whenCreated', 
                         'whenChanged'
        }
        
        ### Make sure $Match is $null before query
        $Match = $null
    }
    Process {
        ### Find Matches
        $Match = Get-ADUser @AdParam | Select-Object @mSel
        
        ### Return matches found or state none found.
        $Ye = @{ForegroundColor = 'Yellow'}
        If ($Match -eq $null){
            Write-Host 'No matching accounts were found.' @Ye
        } Else {
            return $Match
        }
    }
}
