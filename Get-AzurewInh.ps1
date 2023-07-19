Function Get-UserLicenseTypeDetails {
    <#
        .Synopsis
        Cmdlet to find out whether user has a license assigned by direct or inherited path.
        .DESCRIPTION
        Cmdlet accepts the user UPN or output of 'Get-MSOLUser'cmdlet and returns information about whether user has any O365 license assigned.
        If license is assigned, output also shows the path of the license assignment(Direct/Inherited).
        If the license is inherited, cmdlet output shows the group name from which user has received the license.
        .EXAMPLE
        Get-UserLicenseTypeDetails -UserEmail xxxx@abc.onmicrosoft.com 
        # This example will provide license information for a particular user
        .EXAMPLE
        Get-Content Users.csv | Get-UserLicenseTypeDetails | Export-csv Licenseinfo.csv
        # In this example, you import a list of users from a csv file which has no headers, just a list of user email addresses. 
        # Output is then exported to another csv file
        .EXAMPLE
        Get-MSOLUser -All | Get-UserLicenseTypeDetails 
        # This example will pull a list of all users in Azure Active Directory and then get license information for each of them
        .EXAMPLE
        Get-MSOLUser -All | Where isLicensed -eq $true | Get-UserLicenseTypeDetails 
        # This example will pull a list of all users in Azure Active Directory, filter out unlicensed users and then get license information for each of them
        .INPUTS
        User Principal Name of users  -or
        Object of class [Microsoft.Online.Administration.User]
        .OUTPUTS
        Object with License information details
        .NOTES
        version 1.2.2 - 29/10/2019
        All rights reserved (c) 2019 Rajiv Pasalkar
        .COMPONENT
        This cmdlet belongs to Office 365 administration module
    #>

    Param (
        # List of users (provide UserPrincipalName)
        [Parameter(
            Mandatory = $true, 
            ParameterSetName = 'WithEmailAddress', 
            Position = 0, 
            ValueFromPipeline = $true
        )]
        [String]$UserEmail,
        # List of users (accepts output of Get-MSOLUser cmdlet)
        [Parameter(
            Mandatory = $true, 
            ParameterSetName = 'WithMSOLUser', 
            Position = 0, 
            ValueFromPipeline = $true
        )]
        [Microsoft.Online.Administration.User]$MSOLUser
    )
    Begin   {
        #region Functions
        Function Convert-HTMLTableToArray        {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU / Service plans info (GUID, String ID, Product Name).
                .DESCRIPTION
                Get last Microsoft Office 365 SKU / Service plans info (GUID, String ID, Product Name).
                Resolve SKU and Service Plans from GUID, String ID, Name.
                Get all SKUs that include a Service Plan.
                Cache last catalog from Microsoft locally.
                .EXAMPLE
                Get-O365SKUCatalog
                Get last Microsoft Office 365 SKU / Service Plans catalog from Microsoft website and return an array of custom psobjects
                .EXAMPLE
                Get-O365SKUinfo
                Get SKU info using a GUID, String ID or Product Name
                .EXAMPLE
                Get-O365SKUInfoFromPlan
                Get all SKU and related info including a Service Plan (using GUID, String ID or Plan Name)
                .EXAMPLE
                Get-O365Planinfo
                Get Service Plan info using a GUID, String ID or Plan Name
            #>
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory = $true
                )]
                $HTMLObject,
                [Parameter(
                    Mandatory = $true
                )]
                [Int]$TableNumber
            )
            Process {
                $tables = @($HTMLObject.getElementsByTagName('TABLE'))
                $table  = $tables[$TableNumber]
                $titles = @()
                $rows   = @($table.Rows)
                ForEach ($row in $rows) {
                    $cells = @($row.Cells)
                    If ($cells[0].tagName -eq 'TH') {
                        $titles = @(
                            $cells | ForEach-Object {
                                ('' + $_.InnerText).Trim()
                            }
                        )
                        continue
                    }
                    If (-not ($titles)) {
                        $titles = @(
                            1..($cells.Count + 2) | ForEach-Object {
                                "P$_"
                            }
                        )
                    }
                    $resultObject = [Ordered]@{}
                    For ($counter = 0; $counter -lt $cells.Count; $counter++) {
                        $title = $titles[$counter]
                        If (-not ($title)) {
                            continue
                        }
                        $resultObject[$title] = ('' + $cells[$counter].InnerText).Trim()
                    }
                    [PSCustomObject]$resultObject
                }
            }
        }

        Function Get-O365SKUCatalog              {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU / Service Plans information from Microsoft Website
                .DESCRIPTION
                Get last Microsoft Office 365 SKU / Service Plans information from Microsoft Website
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                .PARAMETER ServicePlansInfoAsStrings
                -ServicePlansInfoAsStrings [switch]
                add a new property 'Service plans included as strings' so the object could be easily exported to an external file like a CSV file.
                .PARAMETER AsGlobalVariable
                -AsGlobalVariable [switch]
                save objets into global variable O365SKUsInfos
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365SKUCatalog
                Get all MS O365 SKUs / Service Plans info
                .EXAMPLE
                Get-O365SKUCatalog -AsGlobalVariable
                Get all MS O365 SKUs / Service Plans info and save psobjets to $global:O365SKUsInfos
            #>
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory = $false
                )]
                [Switch]$ServicePlansInfoAsStrings,
                [Parameter(
                    Mandatory = $false
                )]
                [Switch]$AsGlobalVariable
            )
            Process {
                #$script:URICatalog = "https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference"
                $script:URICatalog = 'https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-service-plan-reference.md'
                $script:tempfile   = [IO.Path]::GetTempFileName()
                Write-Verbose -Message "Microsoft O365 SKU catalog URL : $($script:URICatalog)"
                Write-Verbose -Message "Temporary html file : $($script:tempfile)"
                Try {
                    $request = Invoke-WebRequest -Uri $script:URICatalog -OutFile $script:tempfile -UseBasicParsing
                } Catch {
                    throw "Microsoft O365 SKU online catalog $($script:URICatalog) is not available. Please check your network / internet connection."
                }
                If (-not (Test-Path -Path $script:tempfile)) {
                    throw "not able to dowload licensing-service-plan-reference HTML content to $($script:tempfile)"
                } Else {
                    Write-Verbose -Message "Temporary html file $($script:tempfile) created successfully"
                }
                $htmlcontent = Get-Content -Raw -Path $script:tempfile
                Try {
                    $htmlobj = New-Object -ComObject 'HTMLFile'
                } Catch {
                    throw 'not able to create HTMLFile com object'
                }
                Try {
                    If ($host.Version.Major -gt 5) {
                        $encodedhtmlcontent = [Text.Encoding]::Unicode.GetBytes($htmlcontent)
                        $htmlobj.write($encodedhtmlcontent)
                    } Else {
                        $htmlobj.IHTMLDocument2_write($htmlcontent)
                    }
                } Catch {
                    throw "not able to create Com HTML object from temporary file $($script:tempfile)"
                }
                If ($htmlobj) {
                    $skuinfo = Convert-HTMLTableToArray -HTMLObject $htmlobj -TableNumber 1
                }
                $skuinfo
                ForEach ($sku in $skuinfo) {
                    If ($sku.'Service plans included') {
                        $tmpserviceplan     = $sku.'Service plans included'.split("`n")
                        $tmpserviceplanname = $sku.'Service plans included (friendly names)'.split("`n")
                        $resultserviceplan  = @()
                        For ($i=0;$i -le ($tmpserviceplan.count -1);$i++) {
                            $tmpstringid        = ($tmpserviceplan[$i]).substring(0,$tmpserviceplan[$i].length - 39)
                            $tmpguid            = ($tmpserviceplan[$i]).substring($tmpstringid.length,$tmpserviceplan[$i].length - $tmpstringid.length)
                            $tmpplanname        = ($tmpserviceplanname[$i]).substring(0,$tmpserviceplanname[$i].length - 39)
                            $resultserviceplan += [PSCustomObject]@{
                                'String ID' = $tmpstringid.replace(' ','')
                                'GUID'      = ((($tmpguid.replace('(','')).replace(')','')).replace(' ','')).replace("`r",'')
                                'Plan Name' = If (($tmpplanname.substring($tmpplanname.length - 1,1)) -eq ' ') {
                                    $tmpplanname.substring(0, $tmpplanname.length - 1)
                                } Else {
                                    $tmpplanname
                                }
                            }
                        }
                        If ($ServicePlansInfoAsStrings.IsPresent) {
                            $sku | Add-Member -NotePropertyName 'Service plans included as strings' -NotePropertyValue $sku.'Service plans included'
                        }
                        $sku.'Service plans included' = $resultserviceplan
                        $sku.PSObject.Properties.Remove('Service plans included (friendly names)')
                    }
                }
                If ($AsGlobalVariable.IsPresent) {
                    $script:O365SKUsInfos = $skuinfo
                    Write-Verbose -message 'Global Variable O365SKUsInfos set with SKUs Infos'
                }
                return $skuinfo
            }
        }
        $script:O365SKUsInfos = Get-O365SKUCatalog
        #$script:O365SKUsInfos | Select -First 2 | Format-table

        Function Get-O365SKUinfo                 {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU information from Microsoft Website.
                .DESCRIPTION
                Get last Microsoft Office 365 SKU information from Microsoft Website.
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                You can search the SKU info based on its GUID, String ID or Product Name
                .PARAMETER GUID
                -GUID [GUID]
                search a SKU using its GUID
                .PARAMETER StringID
                -StringID [string]
                search a SKU using its StringID
                .PARAMETER ProductName
                -ProductName [string]
                search a SKU using its Product Name
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365SKUinfo -GUID 8f0c5670-4e56-4892-b06d-91c085d7004f
                Get SKU info based on GUID 8f0c5670-4e56-4892-b06d-91c085d7004f
                .EXAMPLE
                Get-O365SKUinfo -ProductName "Microsoft 365 F1"
                Get SKU info of "Microsoft 365 F1"
            #>
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory = $false
                )]
                [guid]$GUID,
                [Parameter(
                    Mandatory = $false
                )]
                [ValidateNotNullOrEmpty()]
                [String]$StringID,
                [Parameter(
                    Mandatory = $false
                )]
                [ValidateNotNullOrEmpty()]
                [String]$ProductName
            )
            Process {
                If (-not $script:O365SKUsInfos) {
                    Get-O365SKUCatalog -AsGlobalVariable | 
                    out-null
                }
                If ($GUID) {
                    $script:O365SKUsInfos | 
                    Where-Object {$_.GUID -eq $GUID}
                } ElseIf ($StringID) {
                    $script:O365SKUsInfos | 
                    Where-Object {$_.'String ID' -eq $StringID}
                } ElseIf ($ProductName) {
                    $script:O365SKUsInfos | 
                    Where-Object {$_.'Product Name' -eq $ProductName}
                } Else {
                    throw 'please use GUID or StringID or ProductName parameters'
                }
            }
        }

        Function Get-O365SKUInfoFromPlan         {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU information that included a specific Service Plan.
                .DESCRIPTION
                Get last Microsoft Office 365 SKU information that included a specific Service Plan.
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                You can search the Service Plan info based on its GUID, String ID or Plan Name
                .PARAMETER GUID
                -GUID [GUID]
                search a SP using its GUID
                .PARAMETER StringID
                -StringID [string]
                search a SP using its StringID
                .PARAMETER PlanName
                -PlanName [string]
                search a SP using its Plan Name
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365SKUInfoFromPlan -GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                Get all SKU including Service Plan GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                .EXAMPLE
                Get-O365SKUInfoFromPlan -PlanName "AZURE ACTIVE DIRECTORY PREMIUM P1"
                Get all SKU including Service Plan "AZURE ACTIVE DIRECTORY PREMIUM P1"
            #>
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory = $false
                )]
                [guid]$GUID,
                [Parameter(
                    Mandatory = $false
                )]
                [ValidateNotNullOrEmpty()]
                [String]$StringID,
                [Parameter(
                    Mandatory = $false
                )]
                [ValidateNotNullOrEmpty()]
                [String]$PlanName
            )
            Process {
                If (-not $script:O365SKUsInfos) {
                    Get-O365SKUCatalog -AsGlobalVariable | 
                    out-null
                }
                If ($GUID) {
                    $script:O365SKUsInfos | 
                    Where-Object {$_.'Service plans included'.GUID -contains $GUID}
                } ElseIf ($StringID) {
                    $script:O365SKUsInfos | 
                    Where-Object {$_.'Service plans included'.'String ID' -contains $StringID}
                } ElseIf ($PlanName) {
                    $script:O365SKUsInfos | 
                    Where-Object {$_.'Service plans included'.'Plan Name' -contains $PlanName}
                } Else {
                    throw 'please use GUID or StringID or PlanName parameters'
                }
            }
        }

        Function Get-O365Planinfo                {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 Service Plan information from Microsoft Website.
                .DESCRIPTION
                Get last Microsoft Office 365 Service Plan information from Microsoft Website.
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                You can search the Service Plan info based on its GUID, String ID or Plan Name
                .PARAMETER GUID
                -GUID [GUID]
                search a SP using its GUID
                .PARAMETER StringID
                -StringID [string]
                search a SP using its StringID
                .PARAMETER PlanName
                -PlanName [string]
                search a SP using its Plan Name
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365Planinfo -GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                Get Service Plan info based on GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                .EXAMPLE
                Get-O365Planinfo -PlanName "AZURE ACTIVE DIRECTORY PREMIUM P1"
                Get Service Plan info of "AZURE ACTIVE DIRECTORY PREMIUM P1"
            #>
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory = $false
                )]
                [guid]$GUID,
                [Parameter(
                    Mandatory = $false
                )]
                [ValidateNotNullOrEmpty()]
                [String]$StringID,
                [Parameter(
                    Mandatory = $false
                )]
                [ValidateNotNullOrEmpty()]
                [String]$PlanName
            )
            Process {
                If (-not $script:O365SKUsInfos) {
                    Get-O365SKUCatalog -AsGlobalVariable | out-null
                }
                If ($GUID) {
                    (
                        $script:O365SKUsInfos | Where-Object {$_.'Service plans included'.GUID -contains $GUID}
                    )[0].'Service plans included' | 
                    Where-Object {$_.GUID -eq $GUID}
                } ElseIf ($StringID) {
                    (
                        $script:O365SKUsInfos | Where-Object {$_.'Service plans included'.'String ID' -contains $StringID}
                    )[0].'Service plans included' | 
                    Where-Object {$_.'String ID' -eq $StringID}
                } ElseIf ($PlanName) {
                    (
                        $script:O365SKUsInfos | Where-Object {$_.'Service plans included'.'Plan Name' -contains $PlanName}
                    )[0].'Service plans included' | 
                    Where-Object {$_.'Plan Name' -eq $PlanName}
                } Else {
                    throw 'please use GUID or StringID or PlanName parameters'
                }
            }
        }
        #endregion Functions

        $script:AllADUsers = Get-ADUser -Filter * -Properties EmailAddress, proxyAddresses, Department, Title | 
        Select-Object -Property SamAccountName, EmailAddress, @{n='proxyAddresses';e={((($_.proxyAddresses -like 'smtp:*') -join ', ').replace('SMTP:','')).replace('smtp:','')}}, Department, Title

        <#region Progress Meter
        $Act      = 'Enumerating Users'
        $Progress = @{
            ID               = 1
            Activity         = 'Enumerating Users'
            CurrentOperation = 'Loading'
            PercentComplete  = 0
        }
        #endregion Progress Meter#>

        $UserLicenseDetail = @()
    }
    Process {
        If ($UserEmail) {
            $UserInfo = Get-MsolUser -UserPrincipalName $UserEmail
        } Else {
            $UserInfo = $MSOLUser
        }
        If ($UserInfo.Licenses.count -gt 0) {
            ### Process further if user has any license assigned
            ForEach ($license in $UserInfo.Licenses) {
                <#region Progress Meter
                $Progress.PercentComplete  = ([array]::IndexOf($UserInfo,$license)/$UserInfo.Count*100)
                $Progress.CurrentOperation = "$($UserInfo.indexof($license)) of $($UserInfo.count) - $($UserInfo.DisplayName)"
                #Write-Progress -Id 1 -Activity 'Enumerating User Licenses . . . ' -PercentComplete ([array]::IndexOf($UserInfo,$license) / $UserInfo.Count * 100) -Status "$($UserInfo.indexof($license)) of $($UserInfo.count)"
                Write-Progress @Progress
                #endregion Progress Meter#>

                ### Gather details about each individual license
                $LicenseName = $license.AccountSkuId
                If ($license.GroupsAssigningLicense.Count -eq 0) {
                    ### If the license is not inherited from any group
                    $AssignmentPath = "Direct"
                } Else {
                    #When license is inherited
                    ForEach ($groupid in $license.GroupsAssigningLicense) {
                        ### Checking each object id, if the id is same as user's object id, there 
                        ### is duplication of license assignment, else capture all the group names
                        $AssignmentPath = "Inherited"
                        If ($groupid -ieq $UserInfo.ObjectId) {
                            If ($license.GroupsAssigningLicense.Count -eq 1) {
                                $AssignmentPath = "Direct"
                            } Else {
                                $AssignmentPath += " + Direct"
                            }
                            break
                        }
                        #Capture group names
                        $GroupNames += Get-MsolGroup -ObjectId $groupid | Select-Object -ExpandProperty DisplayName
                    }
                }

                #region On-prem user
                $NF = 'Not Found'
                If ($script:AllADUsers.UserPrincipalName -contains $UserInfo.UserPrincipalName) {
                    $OnPremUser = $script:AllADUsers | Where-Object {$_.UserPrincipalName -eq $UserInfo.UserPrincipalName}
                } ElseIf ($script:AllADUsers.EmailAddress -contains $UserInfo.UserPrincipalName) {
                    $OnPremUser = $script:AllADUsers | Where-Object {$_.EmailAddress -eq $UserInfo.UserPrincipalName}
                } ElseIf ($script:AllADUsers.proxyAddresses -like "*$($UserInfo.UserPrincipalName)*") {
                    $OnPremUser = $script:AllADUsers | Where-Object {$_.proxyAddresses -like "*$($UserInfo.UserPrincipalName)*"}
                } Else {
                    $OnPremUser = [PSCustomObject]@{
                        SamAccountName = $NF
                        EmailAddress   = $NF
                        proxyAddresses = $NF
                        Department     = $NF
                        Title          = $NF
                    }
                }
                #endregion On-prem user


                $UserLicenseDetail += [PSCustomObject]@{
                    'DisplayName'       = $UserInfo.DisplayName
                    'UserPrincipalName' = $UserInfo.UserPrincipalName
                    'isLicensed'        = $UserInfo.isLicensed
                    'SignInStatus'      = If ($UserInfo.BlockCredential -eq $true) {'Denied'} Else {'Allowed'}
                    'LicenseCount'      = $UserInfo.Licenses.count
                    'LicenseName'       = $LicenseName
                    'FriendlyLicense'   = (Get-O365SKUinfo -StringID $($LicenseName.split(':')[-1]) | Select-Object -Property 'Product name' -Unique).'Product name'
                    'AssignmentPath'    = $AssignmentPath
                    'LicensedGroups'    = $GroupNames
                }
                $GroupNames = ""
            }
            #Write-Progress -Activity $Act -Status 'Ready' -Completed
        }
    }
    End     {
        return $UserLicenseDetail
    }
}


Connect-MsolService


#Get-MSOLUser -All | Get-UserLicenseTypeDetails | Export-CSV -Path "C:\down\MSOL_Lic_Details_$((Get-Date -Format 'MMddyy').ToString()).csv" -NoTypeInformation -Encoding UTF8 -Delimiter ','
Get-MSOLUser -All | Get-UserLicenseTypeDetails | ConvertTo-Excel -Path "C:\down\MSOL_Lic_Details_$((Get-Date -Format 'MMddyy').ToString()).xlsx" -AutoSize -FreezeTopRow -ExcelWorkSheetName 'Inherited vs Direct' -TableStyle Medium20 -Verbose
#Get-UserLicenseTypeDetails -UserEmail bnorris@shermco.com | Format-Table -AutoSize
