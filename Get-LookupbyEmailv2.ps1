#Requires -Module ActiveDirectory

Function Get-LookupbyEmail {
    <#
        .SYNOPSIS
        Find any/all users that match an email address.
        .DESCRIPTION
        Finds any/all users that match emails provided one way or another.
        .PARAMETER UsersIn
        Define the copy/paste variable from Excel or point to a CSV file

        Copy/Paste - Example
        $users = @"
        <pasted from excel>
        "@
        .PARAMETER output
        Define the path where you want to save the output csv.
        If you don't define a path, script run directory will be default.
        .PARAMETER quiet
        Don't output results to screen
        .EXAMPLE
        Get-LookupbyEmail -UsersIn C:\path\to\file.csv -output 'C:\temp\file.csv'
        .EXAMPLE
        $emailUsers = @"
        someone@contoso.com
        someoneelse@contoso.com
        nobody@contoso.com
        anybody@contoso.com
        "@

        Get-LookupbyEmail -UsersIn $emailUsers | Convertto-CSV -NoTypeInformation -Delimiter ',' | Set-Clipboard
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,HelpMessage='String of emails')][string]$UsersIn,
        [Parameter(Mandatory=$false,HelpMessage='Output path and Filename')][string]$output,
        [switch]$quiet
    )
    Begin {
        ### ErrorAction Preference
        $ErrorActionPreference = 'SilentlyContinue'
        
        ### Strings
        $SAM = 'SamAccountName'
        $NF  = 'Not Found'
        $A   = '@'
        $E   = 'Email'
        
        #region Colors (out to screen - non-quiet)
        $Y         = 'Yellow'
        $nC        = @{
            NoNewLine       = $true
            ForegroundColor = 'Cyan'
        }
        $nY        = @{
            NoNewLine       = $true
            ForegroundColor = $Y
        }
        $Ye        = @{ForegroundColor = $Y}
        $Gr        = @{ForegroundColor = 'Green'}
        #endregion Colors

        #region New Array
        If ($UsersIn.GetType().Name -eq 'String') {
            If (Test-Path -Path $UsersIn) {
                $content = Import-Csv -Path $UsersIn
                $headers = ($content | Get-Member -MemberType NoteProperty).Name
                If ($headers.count -eq 1) {
                    If ($headers -match $A) {
                        $Imported = Import-Csv -Path $UsersIn #-Header 'Email'
                    } Else {
                        $Imported = Import-Csv -Path $UsersIn | Select-Object -Skip 1
                    }
                    $NewArray = @()
                    $Imported | ForEach-Object {
                        $NewArray += [PsCustomObject]@{
                            Email = $_.toLower().trim()
                        }
                    }
                } Else {
                    $msg = 'More than one column in CSV'
                    Write-Error -Message $msg
                }
            } Else {
                $msg = 'Invalid CSV path'
                Write-Error -Message $msg
            }
        } Else {
            $NewArray = @()
            $UsersIn -split "`n" | ForEach-Object {
                $NewArray += [PsCustomObject]@{
                    Email = $_.toLower().trim()
                }
            }
        }
        #endregion NewArray

        #region Get all initial AD users
        $PDC = (Get-AdDomainController -Filter {OperationMasterRoles -like '*PDCEmulator*'}).HostName

        ### String Shorthand
        $NAM = 'Name'
        $ENE = 'Enabled'
        $EMA = 'EmailAddress'
        $UPN = 'UserPrincipalName'
        $EXA = 'extensionAttribute7'
        $PRX = 'proxyAddresses'
        $CPY = 'Company'

        $adParams = @{
            Filter     = '*'
            Properties = $SAM, $NAM, $ENE, $EMA, $UPN, $EXA, $PRX, $CPY
            Server     = $PDC
        }
        $adSel    = @{
            Property = $SAM, $NAM, $ENE, $EMA, $UPN, $EXA, $CPY, 
                       @{
                           n = $PRX
                           e = {
                               $S1 = 'smtp:*'
                               $S2 = 'SMTP:'
                               $S3 = 'smtp:'
                               $C  = ', '
                               $N  = ''
                               ((($_.proxyAddresses -like $S1) -join $C).replace($S2,$N)).replace($S3,$N)
                           }
                       }
        }
        $ADUsers  = Get-ADUser @adParams | Select-Object @adSel
        #endregion Get all initial AD Users

        #region Progress Meter
        $pi       = 0
        $progAct  = 'Finding targeted users . . .'
        $Progress = @{
            Activity         = $progAct
            CurrentOperation = 'Loading'
            PercentComplete  = 0
        }
        #endregion Progress Meter

        #region Functions
        Function Search-ADUser {
            <#
                .SYNOPSIS
                Find any/all users that match.
                .DESCRIPTION
                Finds any/all users that even resemble your search criteria
                .PARAMETER <name or part of name>
                Define the target to look for
                .PARAMETER toarray
                All matches are returned as an array, however, if no results were found, an array is still 
                returned - Without this switch if no match was found a simple "no match" string is returned.
                .EXAMPLE
                Search-ADUser jess
            #>
            [alias('fuser')]
            Param(
                [Parameter(Mandatory,HelpMessage='Part of the users name/username')][String]$SearchString,
                [switch]$toarray
            )
            #region Variables (Static)
            $Match  = $null
            $RMatch = $null
            $NF     = 'NotFound'
            #endregion Variables (Static)

            #region Search AD
            $PDC = (Get-AdDomainController -Filter {OperationMasterRoles -like '*PDCEmulator*'}).HostName

            ### String Shorthand
            $ENA = 'Enabled'
            $CPY = 'Company'
            $TLE = 'Title'
            $DPT = 'Department'
            $DES = 'Description'
            $MGR = 'Manager'
            $EID = 'EmployeeID'
            $DIS = 'DisplayName'
            $EMA = 'EmailAddress'
            $UPN = 'UserPrincipalName'
            $SAM = 'SamAccountname'
            $CNT = 'Container'
            $NAM = 'Name'
            
            $adParams = @{
                Filter     = "EmailAddress -like '*$($SearchString)*' -or 
                             UserPrincipalName -like '*$($SearchString)*' -or 
                             proxyAddresses -like '*$($SearchString)*'"
                Properties = $ENA, $CPY, $TLE, $DPT, $DES, 'CanonicalName', $MGR, $EID, $DIS, $EMA, $UPN
                Server     = $PDC
            }
            $SelProps = @{
                Property = $SAM, $DIS, $ENA, $CPY, $TLE, $DES, $DPT, $UPN, $NAM, $EID, $EMA, 
                           @{
                               n = $MGR
                               e = {(Get-ADUser -Identity $_.Manager).Name}
                           }, 
                           @{
                               n = $CNT
                               e = {$_.CanonicalName -ireplace '\/[^\/]+$',''}
                           }
            }
            $Match       = Get-ADUser @adParams | Select-Object @SelProps
            #endregion Search AD

            If ($Match -eq $null){
                If ($toarray) {
                    $RMatch = [pscustomobject]@{
                        $SAM = $NF
                        $DIS = $NF
                        $ENA = $NF
                        $CPY = $NF
                        $TLE = $NF
                        $DES = $NF
                        $DPT = $NF
                        $MGR = $NF
                        $CNT = $NF
                        $UPN = $NF
                        $NAM = $NF
                        $EID = $NF
                        $EMA = $NF
                    }
                } Else {
                    $RMatch = 'No matching accounts were found.'
                }
            } Else {
                $RMatch = $Match
            }
            Return $RMatch
        }

        Function Save-Output {
            <#
                .SYNOPSIS
                Saves output to CSV file.
                .DESCRIPTION
                Takes an array and oututs to CSV file of your choosing.
                .PARAMETER input
                Array to send to CSV.
                .PARAMETER Path
                Path to save CSV file.
                .PARAMETER Name
                Name of the CSV file.
                .EXAMPLE
                Save-Output -input $ADLookup -Path 'C:\path\to\save\file' -Name 'output.csv'
                .NOTES
                If no path is specified file will output to script run dir can be called results.csv.
                .INPUTS
                [Array]
                .OUTPUTS
                None
            #>
            Param (
                [Parameter(Mandatory,HelpMessage='Array Object')][array]$input, 
                [String]$Path = $null, 
                [String]$Name = 'results.csv'
            )
            ### Strings
            $L = '\'

            If (-not $Path)    {
                If ($psISE) {
                    $ScriptRoot = Get-ChildItem -Path $psISE.CurrentFile.FullPath
                    $Path       = $ScriptRoot.DirectoryName + $L
                    $promptText = "Default path:   Script Path`n       Filename:  results.csv?"
                } Else {
                    $ScriptRoot = Get-ChildItem -Path $PSScriptRoot
                    $Path       = $ScriptRoot.DirectoryName + $L
                }
            } Else {
                $Path       = $(Split-Path -Path $Path -Parent) + $L
                $Name       = Split-Path -Path $Path -Leaf
                $promptText = "Default path:   $Path`n       Filename:  $Name ?"
            }
        
            Function Save-File {
                <#
                    .SYNOPSIS
                    Graphical form to confirm file output.
                #>
                Param ([Parameter(Mandatory,HelpMessage='Starting Point')][string]$initialDirectory)
                $SaveInitialPath = $Path
                $SaveFileName    = $Name
                $null            = Add-Type -AssemblyName System.Windows.Forms
                $OpenFileDialog  = New-Object -TypeName System.Windows.Forms.SaveFileDialog
                $OpenFileDialog.InitialDirectory = $SaveInitialPath
                $OpenFileDialog.Filter           = 'CSV (*.csv)| *.csv'
                $OpenFileDialog.FileName         = $SaveFileName
                $null            = $OpenFileDialog.ShowDialog()
                Return $OpenFileDialog.filename
            }

            $results          = $input
            $defaultpath      = ("$path" + "$Name")

            $PromptDefPath    = New-Object -ComObject WScript.Shell
            $DefPathUserInput = $PromptDefPath.PopUp($promptText,0,'Save Output File',4)
            If ($DefPathUserInput -eq 6) { ### 6 = Yes
                $SaveMyFile = $defaultpath
            } Else {                       ### 7 = No
                $SaveMyFile = Save-File -initialDirectory $Path
            }

            $eCSVParams       = @{
                Path              = $SaveMyFile
                NoTypeInformation = $true
                Encoding          = 'UTF8'
                Delimiter         = ','
            }
            Try {
                $results | Export-CSV @eCSVParams 
            } Catch {
                $msg = 'Could not save to default path. Please select a different path.'
                Write-Error -Message $msg
                $SaveMyFile = Save-File -initialDirectory $Path
                $results | Export-CSV @eCSVParams
            }
        }
        #endregion Functions
    }
    Process {
        ### Look our users up from the AD fetch above and fill out a new array with results
        $ADLookup = @()
        Foreach ($e in $NewArray){
            #region Progress Meter
            $pi++
            [int]$percentage = ($pi / $NewArray.Count) * 100
            $Progress.CurrentOperation = "$pi of $($NewArray.Count) - $($e.Email)"
            $Progress.PercentComplete  = $percentage
            Write-Progress @Progress
            #endregion Progress Meter

            #region find a match or don't
            $found   = $null
            $eTarget = $e.Email
            $fTarget = $e.Email.split($A)[0] ### Attempt by username (Last resort)
            If ($ADUsers.EmailAddress -contains $eTarget) {
                $found = $ADUsers | Where-Object {$_.EmailAddress -eq $eTarget}
            } ElseIf ($ADUsers.UserPrincipalName -contains $eTarget) {
                $found = $ADUsers | Where-Object {$_.UserPrincipalName -eq $eTarget}
            } ElseIf ($ADUsers.proxyAddresses -like "*$($eTarget)*") {
                $found = $ADUsers | Where-Object {$_.proxyAddresses -like "*$eTarget*"}
            } ElseIf ($ADUsers.SamAccountName -eq $fTarget) {
                $found = $ADUsers | Where-Object {$_.SamAccountName -eq $fTarget}
            }
            #endregion find a match or don't

            ### If a match was found
            If ($found){
                ### If there is more than 1 match
                If ($found.Count -gt 1) {
                    $found | ForEach-Object {
                        $e = $_.EmailAddress
                        $u = $_.UserPrincipalName
                        $p = $_.proxyAddresses
                        $ADLookup += [PsCustomObject]@{
                            Query               = $UsersIn | Where-Object {($_ -match $e) -or ($_ -match $u) -or ($_ -in $p)}
                            SamAccountName      = $_.SamAccountName
                            Company             = $_.Company
                            Name                = $_.Name
                            Enabled             = $_.Enabled
                            EmailAddress        = $_.EmailAddress
                            UserPrincipalName   = $_.UserPrincipalName
                            extensionAttribute7 = $_.extensionAttribute7
                            proxyAddresses      = $_.proxyAddresses.replace('smtp:','')
                        }
                    }
                } Else {
                    ### If a user was found with a single match, add to array with info
                    $ADLookup += [PsCustomObject]@{
                        SamAccountName      = $found.SamAccountName
                        Company             = $found.Company
                        Name                = $found.Name
                        Enabled             = $found.Enabled
                        EmailAddress        = $found.EmailAddress
                        UserPrincipalName   = $found.UserPrincipalName
                        extensionAttribute7 = $found.extensionAttribute7
                        proxyAddresses      = $found.proxyAddresses.replace('smtp:','')
                    }
                }
            } Else {
                ### If no match was found, add to array with 'Not Found'
                $ADLookup += [PsCustomObject]@{
                    SamAccountName      = $NF
                    Company             = $NF
                    Name                = $NF
                    Enabled             = $NF
                    EmailAddress        = $eTarget
                    UserPrincipalName   = $NF
                    extensionAttribute7 = $NF
                    proxyAddresses      = $NF
                }
            }
        }
        
        ### Clear (terminate) progress meter
        Write-Progress -Activity $progAct -Status 'Ready' -Completed
    }
    End {
        #region Output to screen - Informative
        If (-not $quiet) {
            $badusers  = @()
            $GoodUsers = @()
            $ADLookup | ForEach-Object {
                If (($_.SamAccountName -eq $NF) -or ($_.Enabled -eq $false)) {
                    $badUsers += $_
                } Else {
                    $GoodUsers += $_
                }
            }

            Write-Host 'Original count: ' @nC
            ### How many users were in our batch to lookup
            Write-Host $NewArray.Count @nY

            Write-Host ' - Users fetched from AD: ' @nC
            ### How many users we looked up against AD
            Write-Host $ADLookup.Count @Ye

            Write-Host 'Users Not Found: ' @nC
            ### Count of users who were not found or were Disabled
            Write-Host $badUsers.Count @Ye

            Write-Host 'Users Found Count: ' @nC
            ### Count of users who were found and enabled
            Write-Host $GoodUsers.Count @Gr
        }
        #endregion Output to screen - Informative
    
        #region Save File - or not
        If ($output) {
            Save-Output -input $ADLookup -Path $output
        } Else {
            return $ADLookup
        }
        #endregion Save File - or not
    }
}

### Example 1: 
### Copy/Paste from Excel column
$emailUsers = @'
someone@contoso.com
someoneelse@contoso.com
nobody@contoso.com
anybody@contoso.com
'@
$emailUsers.Count

### Look all users up | Format for excel | Send to clipboard == Ready to paste back into excel.
Get-LookupbyEmail -UsersIn $emailUsers | Convertto-CSV -NoTypeInformation -Delimiter ',' | Set-Clipboard

### Example 2: pull in CSV file directly and save output file
#Get-LookupbyEmail -UsersIn C:\path\to\file.csv -output 'C:\path\to\output\file.csv'