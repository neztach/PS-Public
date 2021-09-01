<#
        This script automatically disables user accounts that have not logged in in more than 12 months
        It then moves the accounts to the DisabledUsers OU
        All accounts that are processed are sent in an email to SystemNotices@example.edu
        In order to get real user activity, accounts are pulled from an O365 User Report, and stored in a hashtable
        if they've logged in within the last 12 months. 
 
        Then all accounts are pulled from AD that have a LastLogonDate >= 12 months ago
 
        Any accounts reported inactive in AD but *ACTIVE* in Office 365 are *not* disabled. All others are disabled.
 
        O365 is queried using a custom app and the GRAPH REST API.
        -------
#>
Begin {
    #region Variables
    $s            = 's'
    $F            = 'F'
    $DDash        = '======='

    #reference to the mail server
    $mailServer   = 'mail.example.edu'

    #the base OU that users will be found in and the OU accounts will be moved to after being disabled
    $SearchBase   = 'OU=UserOU,DC=example,DC=edu' #Replace this out with the DistinguishedName of your User OU
    $disabledOU   = 'OU=DisabledUsers,DC=example,DC=edu' #Replace this out with the DisginguishedName of your Disabled OU

    #App used to run the Office 365 Reports
    $ClientID     = 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX' #The AppID of an App Registration that has Microsoft Graph Reports.Read.All permissions
    $ClientSecret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' # The Client Secret associated with the App ID above
    $TenantName   = 'exampleedu.onmicrosoft.com' # Your tenant name.
    $GraphUrl     = "https://graph.microsoft.com/v1.0/reports/getOffice365ActiveUserDetail(period='D7')" # The Graph URL to retrieve data.

    #How many months the user has to be considered valid
    $ValidMonths  = -12

    ### Arrays of users successfully deleted and users with errors
    $successUsers = @()
    $errorUsers   = @()

    #endregion Variables

    #region Functions
    Function Write-ScriptLog         {
        <#
                .SYNOPSIS
                This simple function writes a log entry
        #>
        Param (
            [Parameter(Mandatory=$true)][string]$LogFile,
            [Parameter(Mandatory=$true)][object[]]$Content
        )
        Try {
            Add-Content -Path $LogFile -Value $Content
        } Catch {
            Write-Error -Message "Could not write data to $LogFile"
        }
    }

    Function Get-GraphToken          {
        <#
                .SYNOPSIS
                This function gets an access token from Microsoft Graph
                .OUTPUTS
                Returns one of 2 possible outputs:
                * The token
                * a pscustomobject that represents the error that occurred
        #>
        Param (
            [Parameter(Mandatory = $true)] [string]$ClientID,
            [Parameter(Mandatory = $true)] [string]$ClientSecret,
            [Parameter(Mandatory = $true)] [string]$TenantName,
            [string]$LoginUrl    = 'https://login.microsoft.com',
            [string]$ResourceUrl = 'https://graph.microsoft.com/.default'
        )
        Try {
            ### Compose REST request.
            $Body  = @{
                grant_type    = 'client_credentials'
                scope         = $ResourceUrl
                client_id     = $ClientID
                client_secret = $ClientSecret
            }
            $token = Invoke-RestMethod -Method Post -Uri "$LoginUrl/$TenantName/oauth2/v2.0/token" -Body $Body
            If ($null -eq $token.access_token) {$fatalError = $true}
        } Catch {
            $fatalError = $true
            $err        = [PSCustomobject]@{Error = $true;ErrorMessage = $_.Exception.Message}
        } Finally {
            If (-not $fatalError) {
                $token
            } Else {
                $err
            }
        }
    }

    Function Get-Office365Report     {
        <#
                .SYNOPSIS
                This Function gets a report from Microsoft Graph
                .OUTPUTS
                Returns one of 2 possible outputs:
                * $false - Something went wrong and the report couldn't be retrieved
                * The report as a PSCUSTOMOBJECT, generated from the CSV retrieved from Graph
                .Parameter ClientID
                The AppID of your Enterprise App Registration that have Graph API Access
                .Parameter ClientSecret
                The Client Secret associated with the App Registration
                .Parameter TenantName
                Your Office 365 tenant name
                .Parameter Url
                The URL of the Graph report you'd like to run
        #>
        Param (
            [Parameter(Mandatory=$true)]$ClientID,
            [Parameter(Mandatory=$true)]$ClientSecret,
            [Parameter(Mandatory=$true)]$TenantName,
            [Parameter(Mandatory=$true)]$Url
        )
        $Dash = '---'
        Try {
            Write-ScriptLog -LogFile $scriptLog -Content $Dash,'Beginning Get-Office365Report function. Inside try{} block',$Dash
            ### Graph API URLs.
            $LoginUrl    = 'https://login.microsoft.com'
            $ResourceUrl = 'https://graph.microsoft.com/.default'

            Write-ScriptLog -LogFile $scriptLog -Content 'Attempting to generate OAuth access token'
            ### Compose REST request.
            $token = Get-GraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantName $TenantName -LoginUrl $LoginUrl -ResourceUrl $ResourceUrl
            If ($token.Error) {Throw $token}
            ### Check if authentication is successful.
            If ($token.access_token -eq $null) {
                Write-Error -Message 'No Access Token'
                #Write-Host "Error getting token"
                Write-ScriptLog -LogFile $scriptLog -Content '    ERROR: Could not retrieve OAuth access token'
            } Else {
                Write-ScriptLog -LogFile $scriptLog -Content 'Successfully retrieved OAuth access token:',$OAuth
                ### Perform REST call.
                $HeaderParams = @{ 'Authorization' = "$($OAuth.token_type) $($OAuth.access_token)" }
                Write-ScriptLog -LogFile $scriptLog -Content 'Attempting to retrieve Office 365 User Report'
                $Result = (Invoke-RestMethod -Method Get -Headers $HeaderParams -Uri $Url)
                If ($Result -eq $null) {
                    Write-ScriptLog -LogFile $scriptLog -Content '    ERROR: Could not retrieve Office 365 User Report'
                    $false
                } Else {
                    Write-ScriptLog -LogFile $scriptLog -Content 'Successfully retrieved Office 365 User Report'
                    ### Return result.
                    $Result | ConvertFrom-CSV
                }
            }
        } Catch {
            Write-ScriptLog -LogFile $scriptLog -Content '    ERROR: Get-Office365Report try block failed',$_.Exception
            $false
        }
        Write-ScriptLog -LogFile $scriptLog -Content $Dash,'Ending Get-Office365Report function',$Dash
    }

    Function Get-ActiveUserHashTable {
        <#
                .SYNOPSIS
                Converts a [pscustomobject] to a Hashtable
                .DESCRIPTION
                This function returns a hash table of ACTIVE users, meaning users who have used Exchange Online within the specified number of months. Inactive users are excluded.
                .OUTPUTS
                A HashTable with the following format
                key   = UserPrincipalName
                value = Last Activity Date in Exchange
                .Parameter ReportResults
                The report object retrieved from the Graph call
                .Parameter Months
                The number of months for a user to be considered active. Should be a negative number.
                ie: -12 would mean the user must have been active in the last 12 months
        #>
        Param (
            [Parameter(Mandatory = $true)]$ReportResults,
            [int]$Months=-12
        )
        ### Ensures that the value of Months is negative
        $Dash = '---'
        If ($Months -gt 0){$Months *=-1}
        Try {
            Write-ScriptLog -LogFile $scriptLog -Content $Dash,'Beginning Get-ActiveUserHashTable function. Inside try{} block',$Dash
            $HashTable = @{}
            <#
                    This filters the report results based on:
                    - User is has a Last Activity date in Exchange (ie, they've used Exchange)
                    - Exchange Last Activity Date is >= however many months back were specified (default is 12 months)
            #>
            $FilteredResults = ($ReportResults | 
                               Where-Object {
                                   $_.'Exchange Last Activity Date' -ne '' -and 
                                   $_.'Exchange Last Activity Date' -ne $null -and 
                                   [datetime]($_.'Exchange Last Activity Date') -ge (Get-Date).AddMonths(-12)
                               })
            $FilteredResults | ForEach-Object {
                $HashTable.Add($_.'User Principal Name',$_.'Exchange Last Activity Date')
            }
            $HashTable
        } Catch {
            Write-ScriptLog -LogFile $scriptLog -Content '    ERROR: Get-ActiveUserHashTable try block failed.',$_.Exception
        }
        Write-ScriptLog -LogFile $scriptLog -Content $Dash,'Ending Get-ActiveUserHashTable function',$Dash
    }
    #endregion Functions
}
Process {
    #-------SCRIPT STARTS HERE---------
    #----you can change variable values around here

    #---Code here does the work---
 
    ### Check and Set TLS 1.2 to avoid errors
    If ([enum]::GetNames([Net.SecurityProtocolType]) -notcontains 'Tls12'){
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    ### The cutoff date for active accounts. Any accounts that haven't logged in since before this date will be disabled.
    If ($ValidMonths -gt 1) {
        $ValidMonths *= -1
    }
    $oldDate           = (Get-Date).AddMonths($ValidMonths)

    ### Today's date, formatted
    $today             = (Get-Date).ToString('yyyy-MM-dd')

    ### Set up log file names
    $scriptName        = (Split-Path -Path $PSCommandPath -Leaf).Split('.')[0]            ### Get the file name of the script without the .ps1 
    $scriptFolderName  = Split-Path -Path (Split-Path -Path $PSCommandPath -Parent) -Leaf ### Get the name of the folder the script is in
    $logPath           = "C:\Scripts\Logs\$($scriptFolderName)\"                          ### Set the base path for the log files
    $allUsersLogFile   = "$($logPath)$($scriptName)-$($today).txt"                        ### Set the full path for the log file of all users to be touched
    $errorusersLogFile = "$($logPath)$($scriptName)-errors-$($today).txt"                 ### Set the full path for the error log
    $scriptLog         = "$($logPath)$($scriptName)-$($today).txt"                        ### The log of this script run

    ### Ensure that the path to the log files exists. If it doesn't, create it
    If (-not (Test-Path -Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory
    }

    ### Begin Logfile
    Write-ScriptLog -LogFile $scriptLog -Content $DDash,"Beginning script run: $((Get-Date).ToString($F))",$DDash
    Write-ScriptLog -LogFile $scriptLog -Content 'About to get Office 365 User Report'
    $ReportResults     = Get-Office365Report -ClientID $ClientID -ClientSecret $ClientSecret -TenantName $TenantName -Url $GraphUrl

    ### If the report results were invalid exit the script
    If (($ReportResults -eq $false) -or ($ReportResults -eq $null)) {
        Write-ScriptLog -LogFile $scriptLog -Content '    ERROR: Office 365 report was invalid. Aborting script!'
        Return
    } Else {
        ### Build hashtable of active users
        $O365ActiveUserHash = Get-ActiveUserHashTable -ReportResults $ReportResults -Months $ValidMonths

        ### Only proceed if the Active User Hash is valid
        If ($O365ActiveUserHash -is [hashtable]) {
            ### Variable that will contain the body of the email text, if it will go out
            $emailBody = '<html>'

            Write-ScriptLog -LogFile $scriptLog -Content 'Getting potentially invalid users from Active Directory'
            ### Grab all users from AD that haven't logged in in recently - Note, this may be inaccurate and needs to be compared to Office 365
            ### Parameters: Users at least 12 months old who haven't logged in in at least a year OR who have never logged in
            $users =  @(
                Get-ADUser -Filter {(WhenCreated -lt $oldDate) -and ((LastLogonDate -lt $oldDate) -or (LastLogonDate -notlike '*'))} `
                           -SearchBase  $SearchBase `
                           -SearchScope Subtree `
                           -Properties  SamAccountName, 
                                        UserPrincipalName, 
                                        LastLogonDate, 
                                        employeeID, 
                                        Enabled, 
                                        Description
            )

            ### Write the list of all potential users out to a log
            Write-ScriptLog -LogFile $scriptLog -Content 'Potentially invalid users:',($users).SamAccountName

            ### Iterate through all users and attempt to disable them, stop protecting them from accidental deletion, and move them to the disabled OU
            ForEach ($user in $users) {
                ### If the user isn't in the Office 365 active user hash
                If ($O365ActiveUserHash.ContainsKey($user.UserPrincipalName) -eq $false) {
                    #$user
                    ### Flag indicating no error has occured
                    $errorOccured = $false
                    #Write-Host $user
                    Try {
                        Write-ScriptLog -LogFile $scriptLog -Content "User $($user.SamAccountName) is inactive. Attempting to disable and move."
                        Set-ADUser    -Identity $user.DistinguishedName -Enabled:$false
                        Set-ADUser    -Identity $user.SamAccountName    -Description "Inactive Account, Disabled on $(Get-Date -Format 'yyyy-MM-dd hh:mm:ss tt')$(If ($user.Description.Length -gt 0){" - $($user.Description)"} Else {''})"
                        Set-ADObject  -Identity $user.DistinguishedName -ProtectedFromAccidentalDeletion:$false
                        Move-ADObject -Identity $user.DistinguishedName -TargetPath $disabledOU -Confirm:$false
                    } Catch {
                        ### If an error occured, store the user in a new PSobject and add the object to the error user list
                        $errorUser    = [pscustomobject]@{
                            SamAccountName    = $user.SamAccountName
                            UserPrincipalName = $user.UserPrincipalName
                            LastLogonDate     = $user.LastLogonDate
                            employeeID        = $user.employeeID
                            Enabled           = $user.Enabled
                            ErrorCode         = $_.Exception.ErrorCode
                            ErrorMsg          = $_.Exception.Message
                        }
                        $errorUsers  += $errorUser
                        #Write-Host "Inside error catch"
                        $errorOccured = $true
                        Write-ScriptLog -LogFile $scriptLog -Content "`tError: $($_.Exception.Message)"
                    }

                    #if no error occured, add the user to the successful list
                    If ($errorOccured -eq $false) {
                        $successUsers += $user
                        Write-ScriptLog -LogFile $scriptLog -Content 'Success!'
                    }
                }
            }

            ### If there were either successes *or* failures, send an email
            ### NOTE: I'm checking this way, because if $users only contains a single user, it's stored as some type of AD Collection that doesn't have a .Count property
            If ($successUsers.Count -gt 0 -or $errorUsers.Count -gt 0) {
                $DateShort = (Get-Date).ToShortDateString()
                $Header = @"
    <style>
      TABLE {border-collapse: collapse;}
      TD, TH {text-align: left; padding: 3px; border-width: 1px; border-color: #000000; border-style: dotted;}
      TR:nth-child(even) {background-color: #f2f2f2;}
    </style>
"@
                ### Generate some of the body text for the email
                # Write-Host "Inside email if"
                $emailBody  = "  <head>$($Header)</head>`n  <body>"
                $emailBody += "    <p><strong>Disabled User Account Information for $($DateShort):</strong></p>"
                $emailBody += "    <p>Total User Accounts to disable: <strong>$($successUsers.Count + $errorUsers.Count)</strong> - Criteria: LastLogonDate <em>Before</em> <strong>$($oldDate.ToString())</strong></p>"
                $emailBody += "    <p>SearchBase:</br> $($SearchBase)</p>"
                #Write-Host $emailBody

                ### If there were users with errors, write the users to a log file and add the users to the email
                If ($errorUsers.Count -gt 0) {
                    $errorUsers | Select-Object -Property SamAccountName, LastLogonDate, ErrorCode, ErrorMsg | Export-CSV -Path $errorusersLogFile -Delimiter `t -NoTypeInformation
                    $emailBody     += "    <p><strong><font color=""red"">$($errorUsers.Count) User Account$(If ($errorUsers.Count -gt 1){$s}) with problems:</font></strong></br>"
                    $errorUsersText = $errorUsers | Sort-Object -Property SamAccountName | ConvertTo-Html -Property SamAccountName, UserPrincipalName, LastLogonDate, ErrorCode, ErrorMsg -As Table -Fragment
                    $emailBody     += $errorUsersText + '</p>'
                }

                ### If there were users that were successes add the users to the email
                If ($successUsers.Count -gt 0) {
                    $emailBody += "    <p><strong>$($successUsers.Count) User Account$(If($successUsers.Count -gt 1){$s}) Successfully Disabled:</strong></br>"
                    $emailBody += $successUsers | Sort-Object -Property SamAccountName | ConvertTo-Html -Property SamAccountName, UserPrincipalName, LastLogonDate -As Table -Fragment
                }

                ### Finish the body text and send the email
                $emailBody += "  </body>`n</html>"
                #Write-Host "attempting to email"
                Try {
                    Write-ScriptLog  -LogFile $scriptLog -Content 'Attempting to send an email'

                    Send-MailMessage -SmtpServer $mailServer `
                                     -Subject    "Disabled User Accounts - $((Get-Date).ToShortDateString())" `
                                     -From       'scriptcenter@example.edu' `
                                     -To         'SystemNotices@example.edu' `
                                     -Cc         'cherylnardone@example.edu' `
                                     -Body       $emailBody `
                                     -BodyAsHtml:$true

                    Write-ScriptLog  -LogFile $scriptLog -Content 'Email sent without errors'
                    Write-ScriptLog  -LogFile $scriptLog -Content $emailBody
                } Catch {
                    Write-ScriptLog  -LogFile $scriptLog -Content '    ERROR: Problem sending an email.',$_.Exception.Message
                }
            } Else {
                Write-ScriptLog -LogFile $scriptLog -Content 'No users to email about. Exiting script gracefully.'
            }
        }
    }

    Write-ScriptLog -LogFile $scriptLog -Content $DDash,"Ending script run: $((Get-Date).ToString($F))",$DDash
}


