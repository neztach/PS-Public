Function Join-UriQuery     { 
    <#
        .SYNOPSIS
        Provides ability to join two Url paths together including advanced querying
        .DESCRIPTION
        Provides ability to join two Url paths together including advanced querying which is useful for RestAPI/GraphApi calls
        .PARAMETER BaseUri
        Primary Url to merge
        .PARAMETER RelativeOrAbsoluteUri
        Additional path to merge with primary url (optional)
        .PARAMETER QueryParameter
        Parameters and their values in form of hashtable
        .EXAMPLE
        Join-UriQuery -BaseUri 'https://evotec.xyz/' -RelativeOrAbsoluteUri '/wp-json/wp/v2/posts' -QueryParameter @{
            page = 1
            per_page = 20
            search = 'SearchString'
        }
        .EXAMPLE
        Join-UriQuery -BaseUri 'https://evotec.xyz/wp-json/wp/v2/posts' -QueryParameter @{
            page = 1
            per_page = 20
            search = 'SearchString'
        }
        .EXAMPLE
        Join-UriQuery -BaseUri 'https://evotec.xyz' -RelativeOrAbsoluteUri '/wp-json/wp/v2/posts'
        .NOTES
        General notes
    #>
    [Alias('Join-UrlQuery')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [uri]$BaseUri,
        [Parameter(Mandatory = $false)]
        [uri]$RelativeOrAbsoluteUri,
        [Parameter()]
        [System.Collections.IDictionary]$QueryParameter
    )
    If ($BaseUri -and $RelativeOrAbsoluteUri) {
        $Url = Join-Uri -BaseUri $BaseUri -RelativeOrAbsoluteUri $RelativeOrAbsoluteUri
    } Else {
        $Url = $BaseUri
    }
    If ($QueryParameter) {
        $Collection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        ForEach ($key in $QueryParameter.Keys) {
            $Collection.Add($key, $QueryParameter.$key)
        }
    }
    $uriRequest = [System.UriBuilder] $Url
    If ($Collection) {
        $uriRequest.Query = $Collection.ToString()
    }
    return $uriRequest.Uri.AbsoluteUri
}

Function Remove-EmptyValue {
    <#
    .SYNOPSIS
    Removes empty, null, or uninitialized values from a hashtable.
    .DESCRIPTION
    This function iteratively checks each key-value pair in the provided hashtable and removes entries based on specified conditions. It can operate recursively on nested hashtables and can be rerun multiple times to ensure deep cleaning.
    .PARAMETER Hashtable
    The hashtable from which empty or null values are to be removed.
    .PARAMETER ExcludeParameter
    An array of keys to exclude from removal operations.
    .PARAMETER Recursive
    A switch to enable recursive removal within nested hashtables.
    .PARAMETER Rerun
    Specifies the number of additional times the removal process should be rerun on the hashtable.
    .PARAMETER DoNotRemoveNull
    If set, the function will not remove keys with null values.
    .PARAMETER DoNotRemoveEmpty
    If set, the function will not remove keys with empty string values.
    .PARAMETER DoNotRemoveEmptyArray
    If set, the function will not remove keys with empty arrays.
    .PARAMETER DoNotRemoveEmptyDictionary
    If set, the function will not remove keys with empty dictionaries or hashtables.
    .EXAMPLE
    $myHashtable = @{
        Name = 'John Doe'
        Age = $null
        Attributes = @{}
    }
    Remove-EmptyValue -Hashtable $myHashtable -Recursive

    This example will remove the 'Age' key because it is null and 'Attributes' key because it is an empty hashtable.
    .NOTES
    Use the Recursive switch with caution on deeply nested hashtables to avoid extensive processing times.
    #>
    [alias('Remove-EmptyValues')]
    [CmdletBinding()]
    Param (
        [alias('Splat', 'IDictionary')]
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Hashtable,
        [string[]]$ExcludeParameter,
        [switch]$Recursive,
        [int]$Rerun,
        [switch]$DoNotRemoveNull,
        [switch]$DoNotRemoveEmpty,
        [switch]$DoNotRemoveEmptyArray,
        [switch]$DoNotRemoveEmptyDictionary
    )
    ForEach ($Key in [string[]]$Hashtable.Keys) {
        If ($Key -notin $ExcludeParameter) {
            If ($Recursive) {
                If ($Hashtable[$Key] -is [System.Collections.IDictionary]) {
                    If ($Hashtable[$Key].Count -eq 0) {
                        If (-not $DoNotRemoveEmptyDictionary) {
                            $Hashtable.Remove($Key)
                        }
                    } Else {
                        Remove-EmptyValue -Hashtable $Hashtable[$Key] -Recursive:$Recursive
                    }
                } Else {
                    If (-not $DoNotRemoveNull -and $null -eq $Hashtable[$Key]) {
                        $Hashtable.Remove($Key)
                    } ElseIf (-not $DoNotRemoveEmpty -and $Hashtable[$Key] -is [string] -and $Hashtable[$Key] -eq '') {
                        $Hashtable.Remove($Key)
                    } ElseIf (-not $DoNotRemoveEmptyArray -and $Hashtable[$Key] -is [System.Collections.IList] -and $Hashtable[$Key].Count -eq 0) {
                        $Hashtable.Remove($Key)
                    }
                }
            } Else {
                If (-not $DoNotRemoveNull -and $null -eq $Hashtable[$Key]) {
                    $Hashtable.Remove($Key)
                } ElseIf (-not $DoNotRemoveEmpty -and $Hashtable[$Key] -is [string] -and $Hashtable[$Key] -eq '') {
                    $Hashtable.Remove($Key)
                } ElseIf (-not $DoNotRemoveEmptyArray -and $Hashtable[$Key] -is [System.Collections.IList] -and $Hashtable[$Key].Count -eq 0) {
                    $Hashtable.Remove($Key)
                }
            }
        }
    }
    If ($Rerun) {
        For ($i = 0; $i -lt $Rerun; $i++) {
            Remove-EmptyValue -Hashtable $Hashtable -Recursive:$Recursive
        }
    }
} ###

Function Select-Properties { 
    <#
        .SYNOPSIS
        Allows for easy selecting property names from one or multiple objects
        .DESCRIPTION
        Allows for easy selecting property names from one or multiple objects. This is especially useful with using AllProperties parameter where we want to make sure to get all properties from all objects.
        .PARAMETER Objects
        One or more objects
        .PARAMETER Property
        Properties to include
        .PARAMETER ExcludeProperty
        Properties to exclude
        .PARAMETER AllProperties
        All unique properties from all objects
        .PARAMETER PropertyNameReplacement
        Default property name when object has no properties
        .EXAMPLE
        $Object1 = [PSCustomobject] @{
            Name1 = '1'
            Name2 = '3'
            Name3 = '5'
        }
        $Object2 = [PSCustomobject] @{
            Name4 = '2'
            Name5 = '6'
            Name6 = '7'
        }
 
        Select-Properties -Objects $Object1, $Object2 -AllProperties
 
        #OR:
 
        $Object1, $Object2 | Select-Properties -AllProperties -ExcludeProperty Name6 -Property Name3
        .EXAMPLE
        $Object3 = [Ordered] @{
            Name1 = '1'
            Name2 = '3'
            Name3 = '5'
        }
        $Object4 = [Ordered] @{
            Name4 = '2'
            Name5 = '6'
            Name6 = '7'
        }
 
        Select-Properties -Objects $Object3, $Object4 -AllProperties
 
        $Object3, $Object4 | Select-Properties -AllProperties
        .NOTES
        General notes
    #>
    [CmdLetBinding()]
    Param (
        [Parameter(
            Position = 0,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Array]$Objects,
        [string[]]$Property,
        [string[]]$ExcludeProperty,
        [switch]$AllProperties,
        [string]$PropertyNameReplacement = '*'
    )
    Begin   {
        Function Select-Unique {
            [CmdLetBinding()]
            Param (
                [System.Collections.IList]$Object
            )
            $New      = $Object.ToLower() | Select-Object -Unique
            $Selected = ForEach ($_ in $New) {
                $Index = $Object.ToLower().IndexOf($_)
                If ($Index -ne -1) {$Object[$Index]}
            }
            $Selected
        }
        $ObjectsList = [System.Collections.Generic.List[Object]]::new()
    }
    Process {
        ForEach ($Object in $Objects) {
            $ObjectsList.Add($Object)
        }
    }
    End     {
        If ($ObjectsList.Count -eq 0) {
            Write-Warning 'Select-Properties - Unable to process. Objects count equals 0.'
            return
        }
        If ($ObjectsList[0] -is [System.Collections.IDictionary]) {
            If ($AllProperties) {
                [Array]$All            = ForEach ($_ in $ObjectsList) {$_.Keys}
                $FirstObjectProperties = Select-Unique -Object $All
            } Else {
                $FirstObjectProperties = $ObjectsList[0].Keys
            }
            If ($Property.Count -gt 0 -and $ExcludeProperty.Count -gt 0) {
                $FirstObjectProperties = ForEach ($_ in $FirstObjectProperties) {
                    If ($Property -contains $_ -and $ExcludeProperty -notcontains $_) {
                        $_
                        continue
                    }
                }
            } ElseIf ($Property.Count -gt 0) {
                $FirstObjectProperties = ForEach ($_ in $FirstObjectProperties) {
                    If ($Property -contains $_) {
                        $_
                        continue
                    }
                }
            } ElseIf ($ExcludeProperty.Count -gt 0) {
                $FirstObjectProperties = ForEach ($_ in $FirstObjectProperties) {
                    If ($ExcludeProperty -notcontains $_) {
                        $_
                        continue
                    }
                }
            }
        } ElseIf ($ObjectsList[0].GetType().Name -match 'bool|byte|char|datetime|decimal|double|ExcelHyperLink|float|int|long|sbyte|short|string|timespan|uint|ulong|URI|ushort') {
            $FirstObjectProperties = $PropertyNameReplacement
        } Else {
            If ($Property.Count -gt 0 -and $ExcludeProperty.Count -gt 0) {
                $ObjectsList = $ObjectsList | Select-Object -Property $Property -ExcludeProperty $ExcludeProperty
            } ElseIf ($Property.Count -gt 0) {
                $ObjectsList = $ObjectsList | Select-Object -Property $Property
            } ElseIf ($ExcludeProperty.Count -gt 0) {
                $ObjectsList = $ObjectsList | Select-Object -Property '*' -ExcludeProperty $ExcludeProperty
            }
            If ($AllProperties) {
                [Array]$All = ForEach ($_ in $ObjectsList) {
                    $_.PSObject.Properties.Name
                }
                $FirstObjectProperties = Select-Unique -Object $All
            } Else {
                $FirstObjectProperties = $ObjectsList[0].PSObject.Properties.Name
            }
        }
        $FirstObjectProperties
    }
}

Function Join-Uri          { 
    <#
        .SYNOPSIS
        Provides ability to join two Url paths together
        .DESCRIPTION
        Provides ability to join two Url paths together
        .PARAMETER BaseUri
        Primary Url to merge
        .PARAMETER RelativeOrAbsoluteUri
        Additional path to merge with primary url
        .EXAMPLE
        Join-Uri 'https://evotec.xyz/' '/wp-json/wp/v2/posts'
        .EXAMPLE
        Join-Uri 'https://evotec.xyz/' 'wp-json/wp/v2/posts'
        .EXAMPLE
        Join-Uri -BaseUri 'https://evotec.xyz/' -RelativeOrAbsoluteUri '/wp-json/wp/v2/posts'
        .EXAMPLE
        Join-Uri -BaseUri 'https://evotec.xyz/test/' -RelativeOrAbsoluteUri '/wp-json/wp/v2/posts'
        .NOTES
        General notes
    #>
    [Alias('Join-Url')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [uri]$BaseUri,
        [Parameter(Mandatory)]
        [uri]$RelativeOrAbsoluteUri
    )
    return ($BaseUri.OriginalString.TrimEnd('/') + "/" + $RelativeOrAbsoluteUri.OriginalString.TrimStart('/'))
}

Function Convert-AzureEnterpriseAppsUserConsent {
    <#
        .SYNOPSIS
        Converts Azure Enterprise Apps user consent policies between internal and external representations.
        .DESCRIPTION
        This function translates Azure Enterprise Apps user consent policies from their internal representation to a more user-friendly format and vice versa. 
        It can be used to convert policies for display or for processing by other functions.
        .PARAMETER PermissionsGrantPoliciesAssigned
        An array of policies assigned to the user. The function processes the first element of this array.
        .PARAMETER Reverse
        A switch parameter. If specified, the function performs the reverse translation, converting user-friendly policy names back to their internal representations.
        .EXAMPLE
        Convert-AzureEnterpriseAppsUserConsent -PermissionsGrantPoliciesAssigned @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
        This example converts the internal policy 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy' to 'AllowUserConsentForApps'.
        .EXAMPLE
        Convert-AzureEnterpriseAppsUserConsent -PermissionsGrantPoliciesAssigned @('AllowUserConsentForApps') -Reverse
        This example converts the user-friendly policy 'AllowUserConsentForApps' back to its internal representation 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'.
        .NOTES
        This function only processes the first element of the PermissionsGrantPoliciesAssigned array.
    #>
    [CmdletBinding()]
    Param (
        [Array]$PermissionsGrantPoliciesAssigned,
        [switch]$Reverse
    )
    $StringToProcess = $PermissionsGrantPoliciesAssigned[0]

    If (-not $Reverse) {
        $TranslatePermissions = @{
            'ManagePermissionGrantsForSelf.microsoft-user-default-legacy' = 'AllowUserConsentForApps'
            'ManagePermissionGrantsForSelf.microsoft-user-default-low'    = 'AllowUserConsentForSelectedPermissions'
        }
        If ($StringToProcess -and $TranslatePermissions[$StringToProcess]) {
            $TranslatePermissions[$StringToProcess]
        } Else {
            'DoNotAllowUserConsent'
        }
    } Else {
        $TranslatePermissions = @{
            'AllowUserConsentForApps'                = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
            'AllowUserConsentForSelectedPermissions' = 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
            'DoNotAllowUserConsent'                  = ''
        }
        $TranslatePermissions[$StringToProcess]
    }
} ###

Function Convert-AzureRole {
    <#
        .SYNOPSIS
        Converts Azure role IDs to their corresponding role names.
        .DESCRIPTION
        This function takes one or more Azure role IDs and converts them to their human-readable role names. If the -All switch is used, it returns all available role names.
        .PARAMETER RoleID
        An array of Azure role IDs to be converted to role names.
        .PARAMETER All
        A switch parameter. If specified, the function returns all role names available in the system.
        .EXAMPLE
        Convert-AzureRole -RoleID '62e90394-69f5-4237-9190-012177145e10'
        Returns 'Global Administrator'.
        .EXAMPLE
        Convert-AzureRole -All
        Returns all role names available in the system.
        .NOTES
        This function is useful for mapping role IDs to their descriptive names in scripts and reports.
    #>
    [CmdletBinding()]
    Param (
        [string[]]$RoleID,
        [switch]$All
    )
    $Roles = [ordered] @{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Guest User'
        '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted Guest User'
        '95e79109-95c0-4d8e-aee3-d01accf2d47b' = 'Guest Inviter'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
        'f023fd81-a637-4b56-95fd-791ac0226033' = 'Service Support Administrator'
        'b0f54661-2d74-4c50-afa3-1ec803f12efe' = 'Billing Administrator'
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'User'
        '4ba39ca4-527c-499a-b93d-d9b492c50246' = 'Partner Tier1 Support'
        'e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8' = 'Partner Tier2 Support'
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b' = 'Directory Readers'
        '9360feb5-f418-4baa-8175-e2a00bac4301' = 'Directory Writers'
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
        '75941009-915a-4869-abe7-691bff18279e' = 'Skype for Business Administrator'
        'd405c6df-0af8-4e3b-95e4-4d06e542189e' = 'Device Users'
        '9f06204d-73c1-4d4c-880a-6edb90606fd8' = 'Azure AD Joined Device Local Administrator'
        '9c094953-4995-41c8-84c8-3ebb9b32c93f' = 'Device Join'
        'c34f683f-4d5a-4403-affd-6615e00e3a7f' = 'Workplace Device Join'
        '17315797-102d-40b4-93e0-432062caca18' = 'Compliance Administrator'
        'd29b2b05-8046-44ba-8758-1e26182fcf32' = 'Directory Synchronization Accounts'
        '2b499bcd-da44-4968-8aec-78e1674fa64d' = 'Device Managers'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        'cf1c38e5-3621-4004-a7cb-879624dced7c' = 'Application Developer'
        '5d6b6bb7-de71-4623-b4af-96380a352509' = 'Security Reader'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
        '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
        '5c4f9dcd-47dc-4cf7-8c9a-9e4207cbfc91' = 'Customer LockBox Access Approver'
        '44367163-eba1-44c3-98af-f5787879f96a' = 'Dynamics 365 Administrator'
        'a9ea8996-122f-4c74-9520-8edcd192826c' = 'Power BI Administrator'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
        '4a5d8f65-41da-4de4-8968-e035b65339cf' = 'Reports Reader'
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b' = 'Message Center Reader'
        '7495fdc4-34c4-4d15-a289-98788ce399fd' = 'Azure Information Protection Administrator'
        '38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4' = 'Desktop Analytics Administrator'
        '4d6ac14f-3453-41d0-bef9-a3e0c569773a' = 'License Administrator'
        '7698a772-787b-4ac8-901f-60d6b08affd2' = 'Cloud Device Administrator'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
        'baf37b3a-610e-45da-9e62-d9d1e5e8914b' = 'Teams Communications Administrator'
        'f70938a0-fc10-4177-9e90-2178f8765737' = 'Teams Communications Support Engineer'
        'fcf91098-03e3-41a9-b5ba-6f0ec8188a12' = 'Teams Communications Support Specialist'
        '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
        'eb1f4a8d-243a-41f0-9fbd-c7cdf6c5ef7c' = 'Insights Administrator'
        'ac16e43d-7b2d-40e0-ac05-243ff356ab5b' = 'Message Center Privacy Reader'
        '6e591065-9bad-43ed-90f3-e9424366d2f0' = 'External ID User Flow Administrator'
        '0f971eea-41eb-4569-a71e-57bb8a3eff1e' = 'External ID User Flow Attribute Administrator'
        'aaf43236-0c0d-4d5f-883a-6955382ac081' = 'B2C IEF Keyset Administrator'
        '3edaf663-341e-4475-9f94-5c398ef6c070' = 'B2C IEF Policy Administrator'
        'be2f45a1-457d-42af-a067-6ec1fa63bc45' = 'External Identity Provider Administrator'
        'e6d1a23a-da11-4be4-9570-befc86d067a7' = 'Compliance Data Administrator'
        '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f' = 'Security Operator'
        '74ef975b-6605-40af-a5d2-b9539d836353' = 'Kaizala Administrator'
        'f2ef992c-3afb-46b9-b7cf-a126ee74c451' = 'Global Reader'
        '0964bb5e-9bdb-4d7b-ac29-58e794862a40' = 'Search Administrator'
        '8835291a-918c-4fd7-a9ce-faa49f0cf7d9' = 'Search Editor'
        '966707d0-3269-4727-9be2-8c3a10f19b9d' = 'Password Administrator'
        '644ef478-e28f-4e28-b9dc-3fdde9aa0b1f' = 'Printer Administrator'
        'e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477' = 'Printer Technician'
        '0526716b-113d-4c15-b2c8-68e3c22b9f80' = 'Authentication Policy Administrator'
        'fdd7a751-b60b-444a-984c-02652fe8fa1c' = 'Groups Administrator'
        '11648597-926c-4cf3-9c36-bcebb0ba8dcc' = 'Power Platform Administrator'
        'e3973bdf-4987-49ae-837a-ba8e231c7286' = 'Azure DevOps Administrator'
        '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
        '2b745bdf-0803-4d80-aa65-822c4493daac' = 'Office Apps Administrator'
        'd37c8bed-0711-4417-ba38-b4abe66ce4c2' = 'Network Administrator'
        '31e939ad-9672-4796-9c2e-873181342d2d' = 'Insights Business Leader'
        '3d762c5a-1b6c-493f-843e-55a3b42923d4' = 'Teams Devices Administrator'
        'c430b396-e693-46cc-96f3-db01bf8bb62a' = 'Attack Simulation Administrator'
        '9c6df0f2-1e7c-4dc3-b195-66dfbd24aa8f' = 'Attack Payload Author'
        '75934031-6c7e-415a-99d7-48dbd49e875e' = 'Usage Summary Reports Reader'
        'b5a8dcf3-09d5-43a9-a639-8e29ef291470' = 'Knowledge Administrator'
        '744ec460-397e-42ad-a462-8b3f9747a02c' = 'Knowledge Manager'
        '8329153b-31d0-4727-b945-745eb3bc5f31' = 'Domain Name Administrator'
        '31392ffb-586c-42d1-9346-e59415a2cc4e' = 'Exchange Recipient Administrator'
        '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e' = 'Identity Governance Administrator'
        '892c5842-a9a6-463a-8041-72aa08ca3cf6' = 'Cloud App Security Administrator'
        '32696413-001a-46ae-978c-ce0f6b3620d2' = 'Windows Update Deployment Administrator'
    }
    If ($All) {
        $Roles.Values
    } Else {
        ForEach ($Role in $RoleID) {
            $RoleName = $Roles[$Role]
            If ($RoleName) {$RoleName} Else {$Role}
        }
    }
} ###

Function Convert-CompanyType {
    <#
        .SYNOPSIS
        Converts company type codes to their descriptive names.
        .DESCRIPTION
        This function takes an array of company type codes and converts each code to its corresponding descriptive name. 
        If a code does not have a corresponding name, the code itself is returned.
        .PARAMETER CompanyType
        An array of company type codes that need to be converted to descriptive names.
        .EXAMPLE
        Convert-CompanyType -CompanyType '5', '4'
        # Returns 'Indirect reseller', 'Reseller'
        .EXAMPLE
        Convert-CompanyType -CompanyType '5', '1'
        # Returns 'Indirect reseller', '1'
        # Note: '1' is returned as is because it does not have a corresponding name in the mapping.
        .NOTES
        Current mappings include:
        '5' for 'Indirect reseller'
        '4' for 'Reseller'
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string[]]$CompanyType
    )

    $CompanyTypeInformation = [ordered] @{
        '5' = 'Indirect reseller'
        '4' = 'Reseller'
    }

    ForEach ($Company in $CompanyType) {
        $CompanyName = $CompanyTypeInformation[$Company]
        If ($CompanyName) {
            $CompanyName
        } Else {
            $Company
        }
    }
} ###

Function Convert-ContractType {
    <#
        .SYNOPSIS
        Converts contract type codes to their descriptive names.
        .DESCRIPTION
        This function takes an array of contract type codes and converts each code to its corresponding descriptive name.
        If a code does not have a corresponding name, the code itself is returned.
        .PARAMETER ContractType
        An array of contract type codes that need to be converted to descriptive names.
        .EXAMPLE
        Convert-ContractType -ContractType '3', '1'
        # Returns 'Reseller', '1'
        # Note: '1' is returned as is because it does not have a corresponding name in the mapping.
        .NOTES
        Current mappings include:
        '3' for 'Reseller'
    #>
    [CmdletBinding()]
    Param (
        [String[]]$ContractType
    )
    $ContractTypeInformation = [ordered]@{
        '3' = 'Reseller'
    }
    ForEach ($Contract in $ContractType) {
        $ContractName = $ContractTypeInformation[$Contract]
        If ($ContractName) {
            $ContractName
        } Else {
            $Contract
        }
    }
} ###

Function Convert-SKUToLicense {
    <#
        .SYNOPSIS
        Converts a SKU to its corresponding license details.
        .DESCRIPTION
        This function takes a SKU (Stock Keeping Unit) identifier and retrieves the associated service plans and license details.
        .PARAMETER SKU
        The SKU identifier for which the license details need to be retrieved.
        .EXAMPLE
        Convert-SKUToLicense -SKU "ENTERPRISEPACK"
        # Returns the service plans and license details for the specified SKU.
        .NOTES
        This function relies on the Get-O365AzureLicenses cmdlet to fetch the license details.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]$SKU
    )
    $ServicePlans = Get-O365AzureLicenses -LicenseSKUID $SKU -ServicePlans -IncludeLicenseDetails
    If ($ServicePlans) {
        $ServicePlans
    }
} ###

Function Find-EnabledServicePlan {
    <#
        .SYNOPSIS
        Identifies enabled and disabled service plans from a given list.
        .DESCRIPTION
        This function takes two arrays: one containing all service plans and another containing disabled service plans. 
        It returns an ordered dictionary with two keys: 'Enabled' and 'Disabled'. The 'Enabled' key contains an array of service plans that are not in the disabled list, 
        and the 'Disabled' key contains an array of service plans that are in the disabled list.
        .PARAMETER ServicePlans
        An array of all available service plans.
        .PARAMETER DisabledServicePlans
        An array of service plans that are disabled.
        .EXAMPLE
        $allPlans = @('PlanA', 'PlanB', 'PlanC')
        $disabledPlans = @('PlanB')
        $result = Find-EnabledServicePlan -ServicePlans $allPlans -DisabledServicePlans $disabledPlans
        # $result.Enabled will contain 'PlanA' and 'PlanC'
        # $result.Disabled will contain 'PlanB'
        .NOTES
        This function is useful for categorizing service plans into enabled and disabled groups.
    #>
    [CmdletBinding()]
    Param (
        [Array]$ServicePlans,
        [Array]$DisabledServicePlans
    )
    $CachePlan = @{}
    ForEach ($Plan in $ServicePlans) {
        $CachePlan[$Plan.serviceName] = $Plan
    }

    $Plans = [ordered]@{
        Enabled  = $null
        Disabled = $null
    }

    If ($DisabledServicePlans.Count -gt 0) {
        [Array]$Plans['Enabled'] = ForEach ($Plan in $ServicePlans) {
            If ($Plan.serviceName -notin $DisabledServicePlans) {
                $Plan
            }
        }
    } Else {
        [Array]$Plans['Enabled'] = $ServicePlans
    }
    [Array]$Plans['Disabled'] = ForEach ($Plan in $DisabledServicePlans) {
        $CachePlan[$Plan]
    }
    $Plans
} ###

Function Get-O365PrivateUserOrSPN {
    <#
        .SYNOPSIS
        Retrieves an Office 365 user or service principal by their principal ID.
        .DESCRIPTION
        This function attempts to retrieve an Office 365 user or service principal using the provided principal ID. 
        It first tries to find a user with the given ID. If no user is found, it then tries to find a service principal with the same ID.
        If neither a user nor a service principal is found, it outputs any warnings encountered during the process.
        .PARAMETER PrincipalID
        The ID of the principal (user or service principal) to retrieve.
        .EXAMPLE
        $principal = Get-O365PrivateUserOrSPN -PrincipalID "user@example.com"
        This example retrieves the Office 365 user or service principal with the ID "user@example.com".
        .NOTES
        This function is useful for identifying whether a given principal ID corresponds to a user or a service principal in Office 365.
    #>
    [cmdletBinding()]
    Param (
        [string]$PrincipalID
    )
    $OutputUser = Get-O365User -Id $PrincipalID -WarningAction SilentlyContinue -WarningVariable varWarning
    If ($OutputUser) {
        $OutputUser
    } Else {
        $OutputService = Get-O365ServicePrincipal -Id $PrincipalID -WarningAction SilentlyContinue -WarningVariable +varWarning
        If ($OutputService) {
            $OutputService
        }
    }
    If (-not $OutputService -and -not $OutputUser) {
        ForEach ($Warning in $VarWarning) {
            Write-Warning -Message $Warning
        }
    }
} ###

Function Connect-O365Admin {
    <#
        .SYNOPSIS
        Connects to Office 365 as an administrator.
        .DESCRIPTION
        This function establishes a connection to Office 365 using provided credentials or cached authorization tokens. 
        It supports multiple authentication methods and handles token refreshes as needed.
        .PARAMETER Credential
        The PSCredential object containing the username and password for authentication.
        .PARAMETER Headers
        A dictionary containing authorization headers, including tokens and expiration information.
        .PARAMETER ExpiresIn
        The duration in seconds for which the token is valid. Default is 3600 seconds.
        .PARAMETER ExpiresTimeout
        The timeout in seconds before the token expires to initiate a refresh. Default is 30 seconds.
        .PARAMETER ForceRefresh
        A switch to force the refresh of the authorization token, even if it is not expired.
        .PARAMETER Tenant
        The tenant ID for the Office 365 subscription.
        .PARAMETER DomainName
        The domain name associated with the Office 365 tenant.
        .PARAMETER Subscription
        The subscription ID for the Office 365 service.
        .EXAMPLE
        Connect-O365Admin -Credential (Get-Credential) -Tenant "your-tenant-id"
        This example connects to Office 365 using the provided credentials and tenant ID.
        .EXAMPLE
        Connect-O365Admin -Headers $headers -ForceRefresh
        This example connects to Office 365 using the provided headers and forces a token refresh.
        .NOTES
        This function is useful for administrators who need to manage Office 365 services and require a reliable way to authenticate and maintain session tokens.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param (
        [Parameter(ParameterSetName = 'Credential')]
        [PSCredential]$Credential,
        [Parameter(
            ParameterSetName = 'Headers',
            DontShow
        )]
        [alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [int]$ExpiresIn = 3600,
        [int]$ExpiresTimeout = 30,
        [switch]$ForceRefresh,
        [Alias('TenantID')]
        [string]$Tenant,
        [string]$DomainName,
        [string]$Subscription
    )

    If ($Headers) {
        If ($Headers.ExpiresOnUTC -gt [datetime]::UtcNow -and -not $ForceRefresh) {
            Write-Verbose -Message "Connect-O365Admin - Using cache for connection $($Headers.UserName)"
            return $Headers
        } Else {
            # if header is expired, we need to use it's values to try and push it for refresh
            $Credential   = $Headers.Credential
            $Tenant       = $Headers.Tenant
            $Subscription = $Headers.Subscription
        }
    } ElseIf ($Script:AuthorizationO365Cache) {
        If ($Script:AuthorizationO365Cache.ExpiresOnUTC -gt [datetime]::UtcNow -and -not $ForceRefresh) {
            Write-Verbose -Message "Connect-O365Admin - Using cache for connection $($Script:AuthorizationO365Cache.UserName)"
            return $Script:AuthorizationO365Cache
        } Else {
            $Credential   = $Script:AuthorizationO365Cache.Credential
            $Tenant       = $Script:AuthorizationO365Cache.Tenant
            $Subscription = $Script:AuthorizationO365Cache.Subscription
        }
    }

    If ($DomainName) {
        Write-Verbose -Message "Connect-O365Admin - Querying tenant to get domain name"
        $Tenant = Get-O365TenantID -DomainName $DomainName
    }

    Try {
        $connectAzAccountSplat = @{
            Credential   = $Credential
            ErrorAction  = 'Stop'
            TenantId     = $Tenant
            Subscription = $Subscription
        }
        Remove-EmptyValue -Hashtable $connectAzAccountSplat
        If ($Credential) {
            Write-Verbose -Message "Connect-O365Admin - Connecting to Office 365 using Connect-AzAccount ($($Credential.UserName))"
        } Else {
            Write-Verbose -Message "Connect-O365Admin - Connecting to Office 365 using Connect-AzAccount"
        }
        $AzConnect = (Connect-AzAccount @connectAzAccountSplat -WarningVariable warningAzAccount -WarningAction SilentlyContinue )
    } Catch {
        If ($_.CategoryInfo.Reason -eq 'AzPSAuthenticationFailedException') {
            If ($Credential) {
                Write-Warning -Message "Connect-O365Admin - Tenant most likely requires MFA. Please drop credential parameter, and just let the Connect-O365Admin prompt you for them."
            } Else {
                Write-Warning -Message "Connect-O365Admin - Please provide DomainName or TenantID parameter."
            }
        } Else {
            Write-Warning -Message "Connect-O365Admin - Error: $($_.Exception.Message)"
        }
        return
    }

    $Context = $AzConnect.Context

    Try {
        Write-Verbose -Message "Connect-O365Admin - Establishing tokens for O365"
        $AuthenticationO365 = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $Context.Account,
            $Context.Environment,
            $Context.Tenant.Id.ToString(),
            $null,
            [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Auto,
            $null,
            'https://admin.microsoft.com'
        )
    } Catch {
        Write-Warning -Message "Connect-O365Admin - Authentication failure. Error: $($_.Exception.Message)"
        return
    }

    Try {
        Write-Verbose -Message "Connect-O365Admin - Establishing tokens for Azure"
        $AuthenticationAzure = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $Context.Account,
            $Context.Environment,
            $Context.Tenant.Id.ToString(),
            $null,
            [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Auto,
            $null,
            "74658136-14ec-4630-ad9b-26e160ff0fc6"
        )
    } Catch {
        Write-Warning -Message "Connect-O365Admin - Authentication failure. Error: $($_.Exception.Message)"
        return
    }

    Try {
        Write-Verbose -Message "Connect-O365Admin - Establishing tokens for Graph"
        $AuthenticationGraph = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $Context.Account,
            $Context.Environment,
            $Context.Tenant.Id.ToString(),
            $null,
            [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Auto,
            $null,
            "https://graph.microsoft.com"
        )
    } Catch {
        Write-Warning -Message "Connect-O365Admin - Authentication failure. Error: $($_.Exception.Message)"
        return
    }

    Write-Verbose -Message "Connect-O365Admin - Disconnecting from O365 using Disconnect-AzAccount"
    $null = Disconnect-AzAccount -AzureContext $Context

    $Script:AuthorizationO365Cache = [ordered] @{
        'Credential'          = $Credential
        'UserName'            = $Context.Account
        'Environment'         = $Context.Environment
        'Subscription'        = $Subscription
        'Tenant'              = $Context.Tenant.Id
        'ExpiresOnUTC'        = ([datetime]::UtcNow).AddSeconds($ExpiresIn - $ExpiresTimeout)
        # This authorization is used for admin.microsoft.com
        'AuthenticationO365'  = $AuthenticationO365
        'AccessTokenO365'     = $AuthenticationO365.AccessToken
        'HeadersO365'         = [ordered] @{
            "Content-Type"           = "application/json; charset=UTF-8"
            "Authorization"          = "Bearer $($AuthenticationO365.AccessToken)"
            'X-Requested-With'       = 'XMLHttpRequest'
            'x-ms-client-request-id' = [guid]::NewGuid()
            'x-ms-correlation-id'    = [guid]::NewGuid()
        }
        # This authorization is used for azure stuff
        'AuthenticationAzure' = $AuthenticationAzure
        'AccessTokenAzure'    = $AuthenticationAzure.AccessToken
        'HeadersAzure'        = [ordered] @{
            "Content-Type"           = "application/json; charset=UTF-8"
            "Authorization"          = "Bearer $($AuthenticationAzure.AccessToken)"
            'X-Requested-With'       = 'XMLHttpRequest'
            'x-ms-client-request-id' = [guid]::NewGuid()
            'x-ms-correlation-id'    = [guid]::NewGuid()
        }
        'AuthenticationGraph' = $AuthenticationGraph
        'AccessTokenGraph'    = $AuthenticationGraph.AccessToken
        'HeadersGraph'        = [ordered] @{
            "Content-Type"           = "application/json; charset=UTF-8" ; 
            "Authorization"          = "Bearer $($AuthenticationGraph.AccessToken)"
            'X-Requested-With'       = 'XMLHttpRequest'
            'x-ms-client-request-id' = [guid]::NewGuid()
            'x-ms-correlation-id'    = [guid]::NewGuid()
        }
    }
    $Script:AuthorizationO365Cache
} ###

Function ConvertFrom-JSONWebToken {
    <#
        .SYNOPSIS
        Converts JWT token to PowerShell object allowing for easier analysis.
        .DESCRIPTION
        Converts JWT token to PowerShell object allowing for easier analysis.
        .PARAMETER Token
        Provide Token to convert to PowerShell object
        .PARAMETER IncludeHeader
        Include header as part of ordered dictionary
        .EXAMPLE
        ConvertFrom-JSONWebToken -Token .....
        .NOTES
        Based on https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
 
        Basically does what: https://jwt.ms/ and https://jwt.io/ do for you online
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$Token,
        [switch]$IncludeHeader
    )

    # Validate as per https://tools.ietf.org/html/rfc7519
    # Access and ID tokens are fine, Refresh tokens will not work
    If (!$Token.Contains(".") -or !$Token.StartsWith("eyJ")) {
        Write-Warning -Message "ConvertFrom-JSONWebToken - Wrong token. Skipping."
        return
    }

    # Extract header and payload
    $tokenheader, $tokenPayload = $Token.Split(".").Replace('-', '+').Replace('_', '/')[0..1]

    # Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    While ($tokenheader.Length % 4) {
        $tokenheader += "="
    }

    # Invalid length for a Base-64 char array or string, adding =
    While ($tokenPayload.Length % 4) {
        $tokenPayload += "="
    }

    # Convert header from Base64 encoded string to PSObject all at once
    $header = [System.Text.Encoding]::UTF8.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json

    # Convert payload to string array
    $tokenArray = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($tokenPayload))

    # Convert from JSON to PSObject
    $TokenObject = $tokenArray | ConvertFrom-Json

    # Signature
    ForEach ($i in 0..2) {
        $Signature = $Token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        Switch ($Signature.Length % 4) {
            0 { break }
            2 { $Signature += '==' }
            3 { $Signature += '=' }
        }
    }
    $TokenObject | Add-Member -Type NoteProperty -Name "signature" -Value $Signature

    # Convert Expire time to PowerShell DateTime
    $DateZero  = (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $TimeZone  = Get-TimeZone
    $UTC       = $DateZero.AddSeconds($TokenObject.exp)
    $Offset    = $TimeZone.GetUtcOffset($(Get-Date)).TotalMinutes
    $LocalTime = $UTC.AddMinutes($Offset)
    Add-Member -Type NoteProperty -Name "expires" -Value $LocalTime -InputObject $TokenObject

    # Time to Expire
    $TimeToExpire = ($LocalTime - (Get-Date))
    Add-Member -Type NoteProperty -Name "timeToExpire" -Value $TimeToExpire -InputObject $TokenObject

    If ($IncludeHeader) {
        [ordered] @{
            Header = $header
            Token  = $TokenObject
        }
    } Else {
        $TokenObject
    }
}

Function Get-O365AzureADConnect {
    <#
        .SYNOPSIS
        Retrieves the status of Azure AD Connect for Office 365.
        .DESCRIPTION
        This function calls the Azure AD API to get the status of password synchronization and AD Connect status.
        It returns a custom PowerShell object containing various synchronization and configuration details.
        .PARAMETER Headers
        A dictionary containing the headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365AzureADConnect -Verbose
        .NOTES
        https://portal.azure.com/#blade/Microsoft_AAD_IAM/PassThroughAuthenticationConnectorsBlade
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    $Uri     = "https://main.iam.ad.ext.azure.com/api/Directories/GetPasswordSyncStatus"
    $Output3 = Invoke-O365Admin -Uri $Uri -Headers $Headers
    #$Output3 | Format-Table

    $Uri     = "https://main.iam.ad.ext.azure.com/api/Directories/ADConnectStatus"
    $Output4 = Invoke-O365Admin -Uri $Uri -Headers $Headers

    [PSCustomObject]@{
        passwordSyncStatus               = $Output3
        verifiedDomainCount              = $Output4.verifiedDomainCount              #: 3
        verifiedCustomDomainCount        = $Output4.verifiedCustomDomainCount        #: 2
        federatedDomainCount             = $Output4.federatedDomainCount             #: 0
        numberOfHoursFromLastSync        = $Output4.numberOfHoursFromLastSync        #: 0
        dirSyncEnabled                   = $Output4.dirSyncEnabled                   #: True
        dirSyncConfigured                = $Output4.dirSyncConfigured                #: True
        passThroughAuthenticationEnabled = $Output4.passThroughAuthenticationEnabled #: True
        seamlessSingleSignOnEnabled      = $Output4.seamlessSingleSignOnEnabled      #: True
    }
} ###

Function Get-O365AzureADConnectPTA {
    <#
        .SYNOPSIS
        Retrieves the status of Pass-Through Authentication (PTA) connectors for Office 365.
        .DESCRIPTION
        This function calls the Azure AD API to get the status of Pass-Through Authentication (PTA) connectors.
        It returns the details of the PTA connector groups.
        .PARAMETER Headers
        A dictionary containing the headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365AzureADConnectPTA -Headers $headers
        .NOTES
        https://portal.azure.com/#blade/Microsoft_AAD_IAM/PassThroughAuthenticationConnectorsBlade
    #>
    [CmdletBinding()]
    Param (
        [alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    $Uri     = "https://main.iam.ad.ext.azure.com/api/Directories/PassThroughAuthConnectorGroups"
    $Output1 = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output1
} ###

Function Get-O365AzureADConnectSSO {
    <#
        .SYNOPSIS
        Retrieves information about Azure AD Connect with Pass-Through Authentication (PTA).
        .DESCRIPTION
        This function retrieves detailed information about Azure AD Connect with Pass-Through Authentication (PTA) connectors.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365AzureADConnect -Verbose
        .NOTES
        For more information, visit: https://portal.azure.com/#blade/Microsoft_AAD_IAM/PassThroughAuthenticationConnectorsBlade
    #>
    [CmdletBinding()]
    Param (
        [alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    $Uri     = "https://main.iam.ad.ext.azure.com/api/Directories/GetSeamlessSingleSignOnDomains"
    $Output2 = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output2
} ###

Function Get-O365AzureADRoles {
    <#
        .SYNOPSIS
        Retrieves Azure AD roles from Microsoft Graph API.
        .DESCRIPTION
        This function retrieves Azure AD roles from the Microsoft Graph API based on the provided URI.
        It returns a list of Azure AD roles.
    #>
    [CmdletBinding()]
    Param ( )

    #https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments&$filter=roleDefinitionId eq '<object-id-or-template-id-of-role-definition>'


    #$Uri = 'https://main.iam.ad.ext.azure.com/api/Roles/User/e6a8f1cf-0874-4323-a12f-2bf51bb6dfdd/RoleAssignments?scope=undefined'
    $Uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'
    <#
    $QueryParameter = @{
        '$Select' = $Property -join ','
        '$filter' = $Filter
        '$orderby' = $OrderBy
    }
    #>
    <#
    GET https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$filter=DisplayName eq 'Conditional Access Administrator'&$select=rolePermissions
    #>
    Write-Verbose -Message "Get-O365AzureADRoles - Getting all Azure AD Roles"
    $Script:AzureADRolesList        = [ordered]@{}
    $Script:AzureADRolesListReverse = [ordered]@{}
    $RolesList = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter -Method GET
    $Script:AzureADRoles = $RolesList
    ForEach ($Role in $RolesList) {
        $Script:AzureADRolesList[$Role.id]                 = $Role
        $Script:AzureADRolesListReverse[$Role.displayName] = $Role
    }

    $RolesList
}

<#
Invoke-WebRequest -Uri "https://main.iam.ad.ext.azure.com/api/Roles/User/e6a8f1cf-0874-4323-a12f-2bf51bb6dfdd/RoleAssignments?scope=undefined" `
-Method "OPTIONS" `
-Headers @{
"Accept"="*/*"
  "Access-Control-Request-Method"="GET"
  "Access-Control-Request-Headers"="authorization,content-type,x-ms-client-request-id,x-ms-client-session-id,x-ms-effective-locale"
  "Origin"="https://portal.azure.com"
  "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84"
  "Sec-Fetch-Mode"="cors"
  "Sec-Fetch-Site"="same-site"
  "Sec-Fetch-Dest"="empty"
  "Accept-Encoding"="gzip, deflate, br"
  "Accept-Language"="en-US,en;q=0.9,pl;q=0.8"
}
#>


<#
 
GET https://admin.exchange.microsoft.com/beta/RoleGroup? HTTP/1.1
Host: admin.exchange.microsoft.com
Connection: keep-alive
sec-ch-ua: "Chromium";v="92", " Not A;Brand";v="99", "Microsoft Edge";v="92"
x-ms-mac-hostingapp: M365AdminPortal
AjaxSessionKey: x5eAwqzbVehBOP7QHfrjpwr9eYtLiHJt7TZFj0uhUMUPQ2T7yNdA7rEgOulejHDHYM1ZyCT0pgXo96EwrfVpMA==
x-adminapp-request: /rbac/exchange
sec-ch-ua-mobile: ?0
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyIsImtpZCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyJ9.eyJhdWQiOiI0OTdlZmZlOS1kZjcxLTQwNDMtYThiYi0xNGNmNzhjNGI2M2IiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jZWIzNzFmNi04NzQ1LTQ4NzYtYTA0MC02OWYyZDEwYTlkMWEvIiwiaWF0IjoxNjMwMjYwMjMxLCJuYmYiOjE2MzAyNjAyMzEsImV4cCI6MTYzMDI2NDEzMSwiYWNyIjoiMSIsImFpbyI6IkFWUUFxLzhUQUFBQXBtQ1F1b2lIR3lpYTd0dFB0czFZOEpIWUpleTB1Zndzb2oycUFvSEJKWjhQclowWlJONmhQSW5BblZHRld2cXp1R0xtbXNyS1Vaak12ZVBwNDJsQXhHY0d1bk5ZNTNNMmdWbE9uSXRhcHBrPSIsImFtciI6WyJyc2EiLCJtZmEiXSwiYXBwaWQiOiIwMDAwMDAwNi0wMDAwLTBmZjEtY2UwMC0wMDAwMDAwMDAwMDAiLCJhcHBpZGFjciI6IjIiLCJkZXZpY2VpZCI6IjNhZTIyNzI2LWRmZDktNGFkNy1hODY1LWFhMmI1MWM2ZTBmZiIsImZhbWlseV9uYW1lIjoiS8WCeXMiLCJnaXZlbl9uYW1lIjoiUHJ6ZW15c8WCYXciLCJpcGFkZHIiOiI4OS43Ny4xMDIuMTciLCJuYW1lIjoiUHJ6ZW15c8WCYXcgS8WCeXMiLCJvaWQiOiJlNmE4ZjFjZi0wODc0LTQzMjMtYTEyZi0yYmY1MWJiNmRmZGQiLCJvbnByZW1fc2lkIjoiUy0xLTUtMjEtODUzNjE1OTg1LTI4NzA0NDUzMzktMzE2MzU5ODY1OS0xMTA1IiwicHVpZCI6IjEwMDMwMDAwOTQ0REI4NEQiLCJyaCI6IjAuQVM4QTluR3p6a1dIZGtpZ1FHbnkwUXFkR2dZQUFBQUFBUEVQemdBQUFBQUFBQUF2QUM4LiIsInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInNpZCI6ImJkYjU3MmNiLTNkMzgtNGZlZi1iNjg2LTlmODhjNWRkNWQyNSIsInN1YiI6ImRranZjSlpIWjdjWkZPbnlSZkxZaDVLeHBUalVWdEVBLTVNSl81aF9GLWMiLCJ0aWQiOiJjZWIzNzFmNi04NzQ1LTQ4NzYtYTA0MC02OWYyZDEwYTlkMWEiLCJ1bmlxdWVfbmFtZSI6InByemVteXNsYXcua2x5c0Bldm90ZWMucGwiLCJ1cG4iOiJwcnplbXlzbGF3LmtseXNAZXZvdGVjLnBsIiwidXRpIjoiekxXUTdvUmc4ay0yVmlJV1dQNG1BQSIsInZlciI6IjEuMCIsIndpZHMiOlsiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwiYjc5ZmJmNGQtM2VmOS00Njg5LTgxNDMtNzZiMTk0ZTg1NTA5Il19.nzALEBEAAQBJddeeyt7Gn5sgy7y1Z1z_jfpLdjsPjgNSEOlHLPHqeyOx9QuHaEywK6es2pobYfhFtUvx1d09nz0qBI0b1wIRMX2W2-XaQOmg0FRTDQvTcC9d4Kum_hXmpTt8WgIpjKLKE0wmW8ZtsHbmh-JH3m9Y8j-9zktiRFtNbEyEa1uCTD7Wph9Ow_PAc6M9mWrERCb_XzaYDuwZWbfA_Ls2Bv8MGQsfkQh9RBsa-TgeuU1hhhGgcSaHPFAytJVQBq6QuMdqnO1pCevECf_OI2K54CcpISAUAPXW_gZXcj1waXzRRQfm85vCCh14oXvEj-Q94RsSq_5c_8cEFA
client-request-id: 64d0ca10-08f4-11ec-ad6e-f9fb25a685f4
Accept: application/json, text/plain, */*
x-ms-mac-version: host-mac_2021.8.19.4
x-portal-routekey: weu
x-ms-mac-appid: 86d5ab1a-7f52-418c-b62d-a33841f2c949
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84
x-ms-mac-target-app: EAC
Origin: https://admin.microsoft.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://admin.microsoft.com/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,pl;q=0.8
 
 
 
GET https://admin.microsoft.com/admin/api/rbac/deviceManagement/roles HTTP/1.1
Host: admin.microsoft.com
Connection: keep-alive
sec-ch-ua: "Chromium";v="92", " Not A;Brand";v="99", "Microsoft Edge";v="92"
x-ms-mac-hostingapp: M365AdminPortal
AjaxSessionKey: x5eAwqzbVehBOP7QHfrjpwr9eYtLiHJt7TZFj0uhUMUPQ2T7yNdA7rEgOulejHDHYM1ZyCT0pgXo96EwrfVpMA==
x-adminapp-request: /rbac/deviceManagement
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84
Accept: application/json, text/plain, */*
x-ms-mac-version: host-mac_2021.8.19.4
x-portal-routekey: weu
x-ms-mac-appid: 86d5ab1a-7f52-418c-b62d-a33841f2c949
x-ms-mac-target-app: MAC
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://admin.microsoft.com/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,pl;q=0.8
Cookie: MC1=GUID=480c128a5ba04faea7df151a53bdfa9a&HASH=480c&LV=202107&V=4&LU=1627670649689; x-portal-routekey=weu; p.BDId=00ab552e-0bd2-44f6-afb9-cbec94cb4051; s.AjaxSessionKey=x5eAwqzbVehBOP7QHfrjpwr9eYtLiHJt7TZFj0uhUMUPQ2T7yNdA7rEgOulejHDHYM1ZyCT0pgXo96EwrfVpMA%3D%3D; s.cachemap=22; s.BrowserIDe6a8f1cf-0874-4323-a12f-2bf51bb6dfdd=00ab552e-0bd2-44f6-afb9-cbec94cb4051; s.classic=False; s.CURedir=True; s.DisplayCulture=en-US; s.MFG=True; p.UtcOffset=-120; market=US; mslocale={'u':'pl-pl'}; LPVID=JjZDkxOGFjNzI3ZTFlZmY5; s.Cart={"BaseOffers":null,"Frequency":0,"IWPurchaseUserId":null,"PromotionCodes":null,"IsOfferTransition":false}; s.InNewAdmin=True; at_check=true; p.FirstLoginDateTimeUtc=id=-172832015&value=Oct_14_2015; s.ImpressionId=9c5222af-0f0a-4464-886a-ebc7eee1b188; p.FirstBillingYear=id=-172832015&value=2015; s.DefaultBillingMonth=08/20/2021 20:04:06; s.DCLoc=weuprod; p.TenantCulture=ceb371f6-8745-4876-a040-69f2d10a9d1a::pl-PL; mbox=PC#7383f384d21f43ef9a0d9d5c273578ed.37_0#1664248950|session#020faa6548144c6486e3597fd3298e30#1630064111; LPSID-60270350=HKOY_Iw3QjSJ9ijUKJt52Q; s.SessID=8798a6f9-b245-4f5e-99ed-1b78809d75a1; RootAuthToken=AwAAABoxMS8yNi8yMDIxIDE5OjA1OjU2ICswMDowMOoLMC5BUzhBOW5HenprV0hka2lnUUdueTBRcWRHZ1lBQUFBQUFQRVB6Z0FBQUFBQUFBQXZBQzguQWdBQkFBQUFBQUQtLURMQTNWTzdRcmRkZ0pnN1dldnJBZ0RzX3dRQTlQOHJfczBGMDYxZ053MTBrZllsVmtYOHZnYVZIbWFUWUVDbXltT2dzMWlGTFRsQXZ4VS1lYjdScjg2U2QwYXZSY05tNGpIcWhlMDBrYmJuWUh3NEtURnVHalN4cklQRTZjamlUUXJKYmRMMXNzcVpBVTZpUE94eVM1aHQzNEN0M1p0bWV1Y1BXaWNsZFdUNmlwVDJtT3JNS2RDaVZLUS1iRGctSHRjUjc3R094eU1hM2pIclBWOXZkOVFqdEdBY1g0azNqalZtRHJhODVFWFRKRjk3TFFEVUxGcWw1SUhyTy1ROHVfQ1RneUFjeHdjVml0anNBRllyUVFwTTFZM3hJRTFxcF9BXzZzeUZuRUFQVm9kUDIzSkUwLWtHaWNvYUowOXhRSlpvMEdTM2IwSzJtUWdFMTYybUUzRGdDQ3lna01qRjlBNko2b0otY09pZ25JOFVLNGg0MnAzVDlSeEdEbVZrTEM4LVJUbHVBUkVNS1JmTElsbFNXZVota1JHU1pZVExLY3IxUG5NN2pVSjBGZDZUODl5LTE1cFVSaWdFdHZKLTJtUms0S2s0ejUwTUtEUzIwejQzMHV3b19Ra1N6el81QnpyeFU5dnY1aGZGai1aOU5TSC16eEtKWHpaUUxua2toMElMd2NVc0xQVmdDVndPa3ZYTlRLazdNWmNUdHcyLVBOVFV2bTJha0p0ZjNQM3hIZExNX3RzdFlZUmxjVUlSOVBWWGFOeXpRTWlvX0kxU1lCanh6bUtpM2tfdVBvdXd1bzYycDltZlFOeUlrOWotX2ctQ2RlSVA4WVBsOHRnekhNMXJWTGlBWjdLUVlDZHpBNXRBMll5LVFFZEYyYi1VcDZqblFmeExoRnJBM3ZleWpRck1MUmJCdVVGVUxscUVMODZSRE16eld1eENoSGh1eEdzSTZaYnFPek9BdUJBSHpjRGxuNHN1MEpEQ3hmc3hidWhocTk4RHNHdWQ4MnhJNU1zYWtEZlZfYUN4ZXV0NzRPR1A2SnkyVGtaLVRJNWcyc2xpM2hEOW14VWRVNmVNdG1HQTVXeWs4dG9JaG1oMXVtMWNNVTBsblpFOUhOZDJKMzJHbk1LaU5Mejg4dktfeW5Va1llY2NwOEcwNUR4aUtpSGkzVUZqNm01eXFBSnVneFRTYTZ6SHBGWHF0SVFfNXZjTHJjM2JhR1paMm4xWjdBTEhZd3hxN3NSSmFNUTROZnFpRnNlT2pqR1JaNjI1VU5kdWxFTGJaLUp1aFpiS05uTG1wQlB5UkNSMEp2czlpekdRRU1ReXhhMzJKWHEzaGduQi1TcGd5N1lLS1dmYXN2MmVhV0hibUctR1hxQ2N4THZKbUV4WHM5VXVBd2NzLU1pc19wUmNzNTdlWmxHZ0xPTlpNUGxvNGQ5Vmh1b0tLanQ4dHdlRDA1VXZ5VGIzaFhjSjFBVG41aVhQampwaEFVaEhPNS01ZXg0cDkyakVmcy13SUhRV2ZURE1aZy1Ca0diVU85LUQtd0NSVExqVm1QV0k2TUFpM0h3cWxvZXZ2M3doWE80bm9NQmVMQlRsNHRiT2QyZXZocXlPaTNudHpNTzVBMFoxbzFDZ1NCMkozVkxRbFpDR2ZocHdHd1kwT3JGb25kVExIcG5LUnBLOE1YdkRLdldSd0tqUl9CSEVPU0IxNlVQOHg2SERZV1BUaGRWRDJFamVtbWpZWmgxaVF0cnZobjBFYTJiRE1yekVHcjFNTlFROGlPVENnLXlVWk1YeVVobXJYMklra05rVExZWWYzRU1ndHBGRUhDWHRTZWpueVphZ1JvcGh0M05yUTJ2MWFXOFE4Q1pfR21XcGs5dkE2MXR4MUhKZHExY3FldE1GM3FpbFAxSTJjd09RZFdNZy1OT2cA; s.LoginUserTenantId=kyHaNehhz9jpR+09ZPKS4DynUHwzw7PquEHQY+SZE6vRWhg+ZenTYDg29pApIbkUamgN9MVhZ/VbADv3Wr2Xnn3vQCRp3hHGvLU4EDcKBxLdi/J1UCSJ5YS6JobJ+hPsanTiHrdOwR5fSMI4rt1cJg==; UserIndex=H4sIAAAAAAAEAGNkYGBgBGI2IGYCsfWBBINkQVFVam5lcU5iuV52TmWxQ2pZfklqsl5BDjNQVtjIwMhQ18BC18gyxNDCysDUytSCBaSNFYTdEnOKU0HGqSSlJJmaGyUn6RqnGFvomqSlpukmmVmY6VqmWVgkm6akmKYYmYK0AQDFS8PlhAAAAA%3D%3D; OIDCAuthCookie=%2BSKNwKbOp3tUWr2%2BSTWrgME8BQoKkh7P55ishMUl3EwwalLmRnorz031%2FWXRh2gszg0uE20Nfdak8qB1vtHFOz%2FF24zwiQa0THjlt6pnBbz9vyhA4iuJNzvwt3XjSmId3Da9X8P4nQ%2FUJE%2BssHTASvNOEnPrMWvrBm1z0222f3GgiWQ2v9ArrbeXOxWvV8Me%2BUPnQ%2FEDui%2B940hO6htSDcG3h46GZJBbFSysbtE5dgQgPhixil29dQE7npcsCycLBgv%2FwypJXh%2BKq5mD%2BpfJwtNbDmvuxz9eQYZUBPWvriBHva6on%2FRXp19xAX8K%2BMwukPVYtCbqeaLP5LCK%2B1pQAFFa4GtKOY1OxVmIUcTSg88Jf0DGWYkR8CzFINgWxNhsVXRV%2BIWjz2OF6irsv%2F3L18zNFxluVlL41uzho5gqlI%2BTmgwtO%2FtWwMDqfZkdVYaufr%2B6DF6alJHFTGEb67sTmlMGeBI1w%2BeHc9Z3alFqLqcBVxg8XB88pUxzF6Dj7CGySByFC2lg%2FZaZeNgFx4BYYUa4o2rYpWhjVhYcXxixSOmFaqZhEEOCdrgB5qoTdoGMPCpoj22C9g6yow1l51GANTK9ujTRGS5LYLFA7R%2BSIcQNM50zDU1wAgoAl%2BnWQUjzK5D9XlBMhSovq7Dd4hXFW%2BnsQp2xKJL1AcE89FVKhlC3LKiwNHKSmDz2mlvYHyVRasm1jbel1BY0dKd%2F1ZMd5aKg94GEXeMdwpyyyg573HuFbCnPBd4TYdeMPg6siaMj%2Bwt%2BcZfZGbm6A9xfaq82vzUP3AU0lmz%2BYxaPT3e4fqmQVNxw0FvfPoIjy3SHaQryqseAP0LVwC6GXFOH4yEGtC63Y%2F%2FVOaE0LXbhhN10ejkQbwZGDtpUiO3%2FBihlUTVAEvYlWEnNd1Mjnr1uRl0JPknEUsbFe4gQNi7UIZo4T7vjDeNGom53bp%2BFryaNb9jCQi3jp1f9CU2xli%2B6pH%2B%2BuFvnODrDE5tJUHE3v13LljzGCbLXO%2B91K17KzIfiAoKAYnZPWNsFvgp2iUPbNRqax%2FBBtF7Zv%2ByofRex3OxXAR1kQCUcmxzItYeLBMNkTKY4B6L8w84U8Cmem%2Fnets2xdzNcYnu30qJkwHIckG7M5A4bpObrscZQ34XOiZ3%2FaLb3nAt8GhOgRe51XbzqVX86NeE9iDBhis%2FBG0JY2Ux3LZO%2B1FwKMjLO2a60OnJIRgORbjSaJV3aJiCkBlbpQ4PX5zXji41h4wSlVzYNsy2QlGJVpDfqbfqWl2DAH5JQKobBmlcp7bn3l6GGXR0XUcJJ6Qi4ZmXzofMLlc6zRhKe15cBp0zmzAlTd4%2BH6kbcduITep6h3NdjDmwFoTz96XY%2BzCE3HxgL1zrVW8qr6WYqSGbaaSqVMNKoM6Z33CRB%2BFUoVpZjHRl2kAxVdvRc3zLSI10M23PELrDur56TDDpgfi2ERY1DjNnS8BaucCs5Rqh35QQPLGmumMRprtrURFitfRlLgl7ZSyOW62ScyxxclityxBeY8NA%2Fi8IPFGrWSSrSVjAtTsJVjRUX5GHIANuZL9YImsVnrShvbyrbxMmSxfJ45pAo8mqX%2FGwnOg7V8TabzvYWuWZvUwpM%2BFktbNaQ960iRoR00UYI0IhC4hnoAAnlKeguUGq8aHuEUywllI%2FwYyjlRCXkx7znLCMj%2FuG7x7acGAStDg%2F97Q8ImojZWT9y9oD6QIPQLI7%2B4vqxBht2ZHxZMxr2WsoAUn1cB7WvPtIyJA43T36AL%2F64X0rg8Kj0nMsC3eQzoJGaWB9XSJzogLtCZAQ1W5%2BLPCIpsWL3IsL9J2gjivl%2BKNH8kDxckxpTFB69Rkau0%2BgjXXiyHEQEd6%2FDtOeRMI3MOWg%2FGzjVbVNxMJock%2B%2FpoAf%2FPgtkV8w%3D; s.DmnHQT=08/29/2021 18:06:00; s.DmnRQT=08/29/2021 18:06:07; s.DmnSOQT=08/29/2021 18:06:07; p.LastLoginDateTimeUtc=Aug_29_2021_18_06_00; MicrosoftApplicationsTelemetryDeviceId=f7e3a469-8044-4a21-ad55-69ce7f6b4086; MicrosoftApplicationsTelemetryFirstLaunchTime=2021-08-29T18:10:03.226Z
 
 
#>
Function Get-O365AzureADRolesMember {
    <#
    .SYNOPSIS
    Retrieves Azure AD roles members based on specified role names or filters.
    .DESCRIPTION
    This function retrieves Azure AD roles members based on specified role names or filters. It allows querying for one or more roles at the same time and provides the flexibility to filter the results based on specific criteria.
    .PARAMETER RoleName
    Specifies the name of the role(s) to retrieve members for.
    .PARAMETER Filter
    Specifies the filter criteria to apply when retrieving role members.
    .PARAMETER Property
    Specifies the properties to include in the results.
    .PARAMETER OrderBy
    Specifies the order in which the results should be sorted.
    .PARAMETER All
    Indicates whether all roles should be retrieved.
    .EXAMPLE
    Get-O365AzureADRolesMember -RoleName "Role1", "Role2" -Property "Property1", "Property2" -OrderBy "Property1" -All
    Retrieves members for specified roles with specific properties and sorting order.
    .EXAMPLE
    Get-O365AzureADRolesMember -Filter "FilterCriteria"
    Retrieves members based on the specified filter criteria.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Role')]
    Param (
        [Parameter(Mandatory, ParameterSetName = 'Role')]
        [Array]$RoleName,

        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [Parameter(ParameterSetName = 'Role')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'All')]
        [string[]]$Property,

        [Parameter(ParameterSetName = 'Role')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'All')]
        [string]$OrderBy,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All
    )
    $Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
    $QueryParameter = @{
        '$Select'  = $Property -join ','
        '$orderby' = $OrderBy
    }

    $RolesList = [ordered] @{}
    If ($RoleName -or $All) {
        # in case user wanted all roles, we get it to him
        If ($All) {
            # we either use cache, or we ask for it
            If (-not $Script:AzureADRoles) {
                $RoleName = (Get-O365AzureADRoles).displayName
            } Else {
                $RoleName = $Script:AzureADRoles.displayName
            }
        }
        # We want to get one or more roles at the same time
        ForEach ($Role in $RoleName) {
            $RoleID = $null
            # We find the ID based on the cache or we ask Graph API to provide the list the first time
            If ($Script:AzureADRolesListReverse) {
                $TranslatedRole = $Script:AzureADRolesListReverse[$Role]
            } Else {
                $null = Get-O365AzureADRoles
                $TranslatedRole = $Script:AzureADRolesListReverse[$Role]
            }
            If ($TranslatedRole) {
                # Once we have ID we query graph API
                $RoleID = $TranslatedRole.id
                $QueryParameter['$filter'] = "roleDefinitionId eq '$RoleID'"
            } Else {
                Write-Warning -Message "Get-O365AzureADRolesMember - Couldn't gather roles because the ID translation didn't work for $Role"
                continue
            }
            Remove-EmptyValue -Hashtable $QueryParameter
            # We query graph API
            Write-Verbose -Message "Get-O365AzureADRolesMember - requesting role $Role ($RoleID)"
            $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter -Method GET
            # if we asked for just one role we return the results directly
            If ($RoleName.Count -eq 1) {
                Write-Verbose -Message "Get-O365AzureADRolesMember - requesting users for $Role ($RoleID)"
                ForEach ($User in $Output) {
                    Get-O365PrivateUserOrSPN -PrincipalID $User.principalId
                }
            } Else {
                # if we asked for more than one role we add the results to the list
                Write-Verbose -Message "Get-O365AzureADRolesMember - requesting users for $Role ($RoleID)"
                $RolesList[$Role] = ForEach ($User in $Output) {
                    Get-O365PrivateUserOrSPN -PrincipalID $User.principalId
                }
            }
        }
        If ($RoleName.Count -gt 1) {
            # if we asked for more than one role we return the list
            $RolesList
        }
    } ElseIf ($Filter) {
        $QueryParameter['$filter'] = $Filter
        Remove-EmptyValue -Hashtable $QueryParameter
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter -Method GET
        ForEach ($User in $Output) {
            Get-O365PrivateUserOrSPN -PrincipalID $User.principalId
        }
    }
} ###

$Script:AzureRolesScriptBlock = {
    Param ($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    #Convert-AzureRole -All | Where-Object { $_ -like "*$wordToComplete*" }
    If (-not $Script:AzureADRoles) {
        $AzureRoles = Get-O365AzureADRoles
    } Else {
        $AzureRoles = $Script:AzureADRoles
    }
    ($AzureRoles | Where-Object { $_.displayName -like "*$wordToComplete*" }).displayName
}

Register-ArgumentCompleter -CommandName Get-O365AzureADRolesMember -ParameterName RoleName -ScriptBlock $Script:AzureRolesScriptBlock

<#
    https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments&$filter=roleDefinitionId eq '<object-id-or-template-id-of-role-definition>'
#>

#https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments&$filter=roleDefinitionId eq '<object-id-or-template-id-of-role-definition>'


#$Uri = 'https://main.iam.ad.ext.azure.com/api/Roles/User/e6a8f1cf-0874-4323-a12f-2bf51bb6dfdd/RoleAssignments?scope=undefined'

<#
GET https://graph.microsoft.com/beta/rolemanagement/directory/roleAssignments?$filter=principalId eq '55c07278-7109-4a46-ae60-4b644bc83a31'
 
 
GET https://graph.microsoft.com/beta/groups?$filter=displayName+eq+'Contoso_Helpdesk_Administrator'
 
GET https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter=principalId eq
#>

<#
Invoke-WebRequest -Uri "https://api.azrbac.mspim.azure.com/api/v2/privilegedAccess/aadroles/roleAssignments?`$expand=linkedEligibleRoleAssignment,subject,scopedResource,roleDefinition(`$expand=resource)&`$count=true&`$filter=(roleDefinition/resource/id%20eq%20%27ceb371f6-8745-4876-a040-69f2d10a9d1a%27)+and+(roleDefinition/id%20eq%20%275d6b6bb7-de71-4623-b4af-96380a352509%27)+and+(assignmentState%20eq%20%27Eligible%27)&`$orderby=roleDefinition/displayName&`$skip=0&`$top=10" -Headers @{
"x-ms-client-session-id"="3049c4c42d944f68bb7423154f7a1da5"
  "Accept-Language"="en"
  "Authorization"="Bearer ."
  "x-ms-effective-locale"="en.en-us"
  "Accept"="application/json, text/javascript, */*; q=0.01"
  #"Referer"=""
  "x-ms-client-request-id"="b0a543fc-ca4c-4ac6-aef6-5ceb09ad9003"
  "User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84"
}
#>
Function Get-O365AzureEnterpriseAppsGroupConsent {
    <#
        .SYNOPSIS
        Retrieves the group consent settings for Azure Enterprise Apps.
        .DESCRIPTION
        This function retrieves the group consent settings for Azure Enterprise Apps from the Microsoft Graph API.
        It returns the specific consent settings for the group.
        .PARAMETER Headers
        A dictionary containing the headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        Specifies whether to return the consent settings without translation.
        .EXAMPLE
        Get-O365AzureEnterpriseAppsGroupConsent -Headers $headers
        .NOTES
        For more information, visit: https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )
    $Uri    = 'https://graph.microsoft.com/beta/settings'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        If ($NoTranslation) {
            ($Output | Where-Object { $_.displayName -eq 'Consent Policy Settings' }).values
        } Else {
            $ConsentPolicy = $Output | Where-Object { $_.displayName -eq 'Consent Policy Settings' }
            If ($ConsentPolicy) {
                $Object = [PSCustomObject] @{
                    EnableGroupSpecificConsent                      = ($ConsentPolicy.values | Where-Object { $_.name -eq 'EnableGroupSpecificConsent' } | Select-Object -ExpandProperty value)
                    BlockUserConsentForRiskyApps                    = $ConsentPolicy.values | Where-Object { $_.name -eq 'BlockUserConsentForRiskyApps' } | Select-Object -ExpandProperty value
                    EnableAdminConsentRequests                      = $ConsentPolicy.values | Where-Object { $_.name -eq 'EnableAdminConsentRequests' } | Select-Object -ExpandProperty value
                    ConstrainGroupSpecificConsentToMembersOfGroupId = $ConsentPolicy.values | Where-Object { $_.name -eq 'ConstrainGroupSpecificConsentToMembersOfGroupId' } | Select-Object -ExpandProperty value
                }
                If ($Object.EnableGroupSpecificConsent -eq 'true') {
                    $Object.EnableGroupSpecificConsent = $true
                } Else {
                    $Object.EnableGroupSpecificConsent = $false
                }

                If ($Object.BlockUserConsentForRiskyApps -eq 'true') {
                    $Object.BlockUserConsentForRiskyApps = $true
                } Else {
                    $Object.BlockUserConsentForRiskyApps = $false
                }
                If ($Object.EnableAdminConsentRequests -eq 'true') {
                    $Object.EnableAdminConsentRequests = $true
                } Else {
                    $Object.EnableAdminConsentRequests = $false
                }
                $Object
            }
        }
    }
} ###

Function Get-O365AzureEnterpriseAppsUserConsent {
    <#
        .SYNOPSIS
        Retrieves user consent settings for Azure Enterprise Apps.
        .DESCRIPTION
        This function retrieves user consent settings for Azure Enterprise Apps based on the provided headers.
        It returns information about permissions and policies assigned to users.
        .PARAMETER Headers
        A dictionary containing the headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        Specifies whether to return the consent settings without translation.
        .EXAMPLE
        Get-O365AzureEnterpriseAppsUserConsent -Headers $headers
        .NOTES
        For more information, visit: https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
    #>
    # https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
    # https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/UserSettings
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )

    $Uri    = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy?$select=defaultUserRolePermissions'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        If ($NoTranslation) {
            $Output
        } Else {
            [PSCustomObject] @{
                allowedToCreateApps             = $Output.defaultUserRolePermissions.allowedToCreateApps
                allowedToCreateSecurityGroups   = $Output.defaultUserRolePermissions.allowedToCreateSecurityGroups
                allowedToReadOtherUsers         = $Output.defaultUserRolePermissions.allowedToReadOtherUsers
                permissionGrantPoliciesAssigned = Convert-AzureEnterpriseAppsUserConsent -PermissionsGrantPoliciesAssigned $Output.defaultUserRolePermissions.permissionGrantPoliciesAssigned
            }
        }
    }
} ###

Function Get-O365AzureEnterpriseAppsUserSettings {
    <#
        .SYNOPSIS
        Retrieves user settings for Azure Enterprise Apps.
        .DESCRIPTION
        This function retrieves user settings for Azure Enterprise Apps based on the provided headers.
        It returns information about user consent settings for accessing data, adding gallery apps, and visibility of Office 365 apps in the portal.
        .PARAMETER Headers
        A dictionary containing the headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        Specifies whether to return the user settings without translation.
        .EXAMPLE
        Get-O365AzureEnterpriseAppsUserSettings -Headers $headers
        .NOTES
        For more information, visit: https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )
    $Uri    = 'https://main.iam.ad.ext.azure.com/api/EnterpriseApplications/UserSettings'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        If ($NoTranslation) {
            $Output
        } Else {
            [PSCustomObject]@{
                UsersCanConsentAppsAccessingData = $Output.usersCanAllowAppsToAccessData
                UsersCanAddGalleryAppsToMyApp    = $Output.usersCanAddGalleryApps
                UsersCanOnlySeeO365AppsInPortal  = $Output.hideOffice365Apps
            }
        }
    }
} ###

Function Get-O365AzureEnterpriseAppsUserSettingsAdmin {
    <#
        .SYNOPSIS
        Retrieves user settings for Azure Enterprise Apps with admin consent flow.
        .DESCRIPTION
        This function retrieves user settings for Azure Enterprise Apps with admin consent flow based on the provided headers.
        It returns information about request expiration days, notifications, reminders, approvers, and approversV2.
        .PARAMETER Headers
        A dictionary containing the headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        Specifies whether to return the user settings without translation.
        .EXAMPLE
        Get-O365AzureEnterpriseAppsUserSettingsAdmin -Headers $headers
        .NOTES
        For more information, visit: https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )
    # https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
    # https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/UserSettings
    # https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/UserSettings/menuId/
    $Uri    = 'https://main.iam.ad.ext.azure.com/api/RequestApprovals/V2/PolicyTemplates?type=AdminConsentFlow'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        If ($NoTranslation) {
            $Output
        } Else {
            [PSCustomObject]@{
                requestExpiresInDays = $Output.requestExpiresInDays
                notificationsEnabled = $Output.notificationsEnabled
                remindersEnabled     = $Output.remindersEnabled
                approvers            = $Output.approvers
                approversV2          = $Output.approversV2
            }
        }
    }
} ###

Function Get-O365AzureEnterpriseAppsUserSettingsPromoted {
    <#
        .SYNOPSIS
        Retrieves user settings for promoted Azure Enterprise Apps.
        .DESCRIPTION
        This function retrieves user settings for promoted Azure Enterprise Apps based on the provided headers.
        .PARAMETER Headers
        A dictionary containing the headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365AzureEnterpriseAppsUserSettingsPromoted -Headers $headers
        .NOTES
        For more information, visit: 
        - https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
        - https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/UserSettings
        - https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/UserSettings/menuId/
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    # https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?tabs=azure-portal
    # https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/UserSettings
    # https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/UserSettings/menuId/
    $Uri    = 'https://main.iam.ad.ext.azure.com/api/workspaces/promotedapps'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365AzureExternalCollaborationFlows {
    <#
        .SYNOPSIS
        Provides information about Azure external collaboration flows.
        .DESCRIPTION
        This function retrieves details about Azure external collaboration flows based on the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365AzureExternalCollaborationFlows -Headers $headers
        .NOTES
        WARNING: Invoke-O365Admin - Error JSON: Response status code does not indicate success:
        403 (Forbidden). The application does not have any of the required delegated permissions
        (Policy.Read.All, Policy.ReadWrite.AuthenticationFlows) to access the resource.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    $Uri    = 'https://graph.microsoft.com/v1.0/policies/authenticationFlowsPolicy'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365AzureExternalCollaborationSettings {
    <#
        .SYNOPSIS
        Retrieves Azure external collaboration settings based on the provided headers.
        .DESCRIPTION
        This function retrieves Azure external collaboration settings from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $ReverseGuestRole = @{
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'User'
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'GuestUser'
        '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'RestrictedUser'
    }

    $Uri    = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        [PSCustomObject]@{
            #id = $Output.id # : authorizationPolicy
            allowInvitesFrom                          = $Output.allowInvitesFrom                          # : adminsAndGuestInviters
            allowedToSignUpEmailBasedSubscriptions    = $Output.allowedToSignUpEmailBasedSubscriptions    # : True
            allowedToUseSSPR                          = $Output.allowedToUseSSPR                          # : True
            allowEmailVerifiedUsersToJoinOrganization = $Output.allowEmailVerifiedUsersToJoinOrganization # : False
            blockMsolPowerShell                       = $Output.blockMsolPowerShell                       # : False
            displayName                               = $Output.displayName                               # : Authorization Policy
            description                               = $Output.description                               # : Used to manage authorization related settings across the company.
            guestUserRoleId                           = $ReverseGuestRole[$Output.guestUserRoleId]                           # : a0b1b346-4d3e-4e8b-98f8-753987be4970
            defaultUserRolePermissions                = $Output.defaultUserRolePermissions                # :
        }
    }
} ###

<#
$o = Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/policies/authenticationFlowsPolicy" -Headers @{
    "x-ms-client-session-id" = "a2f6c5f9b1b8450dbb0116f95ffbe9b2"
    "Accept-Language" = "en"
    "Authorization" = "Bearer .
    "x-ms-effective-locale" = "en.en-us"
    "Accept" = "*/*"
    #"Referer"=""
    "x-ms-client-request-id" = "d4bc027d-339c-46c2-ba96-c07f53fc5002"
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84"
}
$o.content
 
$p = Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy" -Headers @{
    "x-ms-client-session-id" = "a2f6c5f9b1b8450dbb0116f95ffbe9b2"
    "Accept-Language" = "en"
    "Authorization" = "Bearer ..
    "x-ms-effective-locale" = "en.en-us"
    "Accept" = "*/*"
    #"Referer" = ""
    "x-ms-client-request-id" = "d4bc027d-339c-46c2-ba96-c07f53fc5001"
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84"
}
$p.COntent
 
$g = Invoke-WebRequest -Uri "https://main.iam.ad.ext.azure.com/api/B2B/b2bPolicy" `
    -Headers @{
    "x-ms-client-session-id" = "02ca6867073543de9a89b767ad581135"
    "Accept-Language" = "en"
    "Authorization" = "Bearer "
    "x-ms-effective-locale" = "en.en-us"
    "Accept" = "*/*"
    #"Referer" = ""
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84"
    "x-ms-client-request-id" = "cf957d13-fc12-415d-a86a-1d74507d9003"
} `
    -ContentType "application/json"
$g.content
#>
Function Get-O365AzureExternalIdentitiesEmail {
    <#
        .SYNOPSIS
        Provides functionality to retrieve email authentication method configurations for external identities in Office 365.
        .DESCRIPTION
        This function retrieves email authentication method configurations for external identities in Office 365 from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        A switch parameter to indicate whether to skip translation of the output.
        .EXAMPLE
        Get-O365AzureExternalIdentitiesEmail -Headers $headers -NoTranslation
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )
    # https://portal.azure.com/#blade/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/IdentityProviders
    $Uri    = 'https://graph.microsoft.com/beta/policies/authenticationmethodspolicy/authenticationMethodConfigurations/email'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        If ($NoTranslation) {
            $Output
        } Else {
            $Output
        }
    }
} ###

<# Requires
scp : AccessReview.ReadWrite.All AuditLog.Read.All Directory.AccessAsUser.All Directory.Read.All Directory.ReadWrite.All email EntitlementManagement.Read.All Group.ReadWrite.All IdentityProvider.ReadWrite.All IdentityRiskEvent.ReadWri
                      te.All IdentityUserFlow.Read.All openid Policy.Read.All Policy.ReadWrite.AuthenticationFlows Policy.ReadWrite.AuthenticationMethod Policy.ReadWrite.ConditionalAccess profile Reports.Read.All RoleManagement.ReadWrite.Directory Se
                      curityEvents.ReadWrite.All TrustFrameworkKeySet.Read.All User.Export.All User.ReadWrite.All UserAuthenticationMethod.ReadWrite.All
 
#>
Function Get-O365AzureExternalIdentitiesPolicies {
    <#
        .SYNOPSIS
        Retrieves Azure external identities policies from the specified endpoint.
        .DESCRIPTION
        This function retrieves Azure external identities policies from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        A switch parameter to indicate whether to skip translation of the output.
        .EXAMPLE
        Get-O365AzureExternalIdentitiesPolicies -Headers $headers -NoTranslation
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )
    # https://portal.azure.com/#blade/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/IdentityProviders
    $Uri    = 'https://main.iam.ad.ext.azure.com/api/B2B/b2bPolicy'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        If ($NoTranslation) {
            $Output
        } Else {
            $Output
        }
    }
} ###

Function Get-O365AzureGroupExpiration {
    <#
        .SYNOPSIS
        Retrieves Azure group expiration information from the specified endpoint.
        .DESCRIPTION
        This function retrieves Azure group expiration information from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        A switch parameter to indicate whether to skip translation of the output.
        .EXAMPLE
        Get-O365AzureGroupExpiration -Headers $headers -NoTranslation
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )
    $Uri    = 'https://main.iam.ad.ext.azure.com/api/Directories/LcmSettings'
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method Get
    If ($Output) {
        If ($NoTranslation) {
            $Output
        } Else {
            If ($Output.expiresAfterInDays -eq 0) {
                $GroupLifeTime = '180'
            } ElseIf ($Output.expiresAfterInDays -eq 1) {
                $GroupLifeTime = '365'
            } ElseIf ($Output.expiresAfterInDays -eq 2) {
                $GroupLifeTime = $Output.groupLifetimeCustomValueInDays
            }

            If ($Output.managedGroupTypes -eq 2) {
                $ExpirationEnabled = 'None'
            } ElseIf ($Output.managedGroupTypes -eq 1) {
                $ExpirationEnabled = 'Selected'
            } ElseIf ($Output.managedGroupTypes -eq 0) {
                $ExpirationEnabled = 'All'
            } Else {
                $ExpirationEnabled = 'Unknown'
            }
            <#
            expiresAfterInDays : 2
            groupLifetimeCustomValueInDays : 185
            managedGroupTypesEnum : 0
            managedGroupTypes : 0
            adminNotificationEmails : przemyslaw.klys@evotec.pl
            groupIdsToMonitorExpirations : {}
            policyIdentifier : 6f843b54-8fa0-4837-a8e7-b01d00d25892
            #>
            [PSCustomObject]@{
                GroupLifeTime           = $GroupLifeTime
                AdminNotificationEmails = $Output.adminNotificationEmails
                ExpirationEnabled       = $ExpirationEnabled
                ExpirationGroups        = $Output.groupIdsToMonitorExpirations
            }
        }
    }
} ###

Function Get-O365AzureLicenses {
    <#
        .SYNOPSIS
        Retrieves Azure licensing information based on provided parameters.
        .DESCRIPTION
        This function retrieves Azure licensing information based on the provided parameters such as LicenseName, LicenseSKUID, ServicePlans, and ServicePlansComplete.
        .PARAMETER Headers
        Specifies the headers required for the API request.
        .PARAMETER LicenseName
        Specifies the name of the license to retrieve information for.
        .PARAMETER ServicePlans
        Switch parameter to indicate whether to retrieve detailed service plans information.
        .PARAMETER ServicePlansComplete
        Switch parameter to indicate whether to retrieve complete service plans information.
        .PARAMETER LicenseSKUID
        Specifies the SKU ID of the license to retrieve information for.
        .PARAMETER IncludeLicenseDetails
        Switch parameter to include detailed license information along with service plans.
        .EXAMPLE
        $Licenses = Get-O365AzureLicenses
        $Licenses | Format-Table
        .EXAMPLE
        $ServicePlans = Get-O365AzureLicenses -ServicePlans -LicenseName 'Enterprise Mobility + Security E5' -Verbose
        $ServicePlans | Format-Table
        .EXAMPLE
        $ServicePlans = Get-O365AzureLicenses -ServicePlans -LicenseSKUID 'EMSPREMIUM' -Verbose
        $ServicePlans | Format-Table
        .EXAMPLE
        $ServicePlans = Get-O365AzureLicenses -ServicePlans -LicenseSKUID 'evotecpoland:EMSPREMIUM' -Verbose
        $ServicePlans | Format-Table
        .EXAMPLE
        $ServicePlans = Get-O365AzureLicenses -ServicePlans -LicenseSKUID 'evotecpoland:EMSPREMIUM' -IncludeLicenseDetails -Verbose
        $ServicePlans | Format-Table
        .NOTES
        Detailed information about the Get-O365AzureLicenses function and its usage scenarios.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [string]$LicenseName,
        [switch]$ServicePlans,
        [switch]$ServicePlansComplete,
        [string]$LicenseSKUID,
        [switch]$IncludeLicenseDetails
    )

    # Maybe change it to https://docs.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0&tabs=http
    # Or maybe not because it doesn't contain exactly same data missing displayName from service plans
    # $Uri = "https://graph.microsoft.com/v1.0/subscribedSkus"

    $Uri = "https://main.iam.ad.ext.azure.com/api/AccountSkus"

    $QueryParameter = @{
        backfillTenants = $false
    }

    If (-not $Script:AzureLicensesList) {
        Write-Verbose -Message "Get-O365AzureLicenses - Querying for Licenses SKU"
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
        # We build a list of all the licenses, for caching purposes
        If ($Output) {
            $Script:AzureLicensesList = $Output
        }
    } Else {
        Write-Verbose -Message "Get-O365AzureLicenses - Reusing cache for Licenses SKU"
        $Output = $Script:AzureLicensesList
    }

    # If license name or license id is provided we filter thjings out
    If ($LicenseName) {
        $Output = $Output | Where-Object { $_.Name -eq $LicenseName }
    } ElseIf ($LicenseSKUID) {
        $Output = $Output | Where-Object {
            $TempSplit = $_.AccountSkuId -split ':'
            $TempSplit[1] -eq $LicenseSKUID -or $_.AccountSkuId -eq $LicenseSKUID
        }
    }

    # we then based on ServicePlans request only display service plans
    If ($ServicePlans) {
        ForEach ($O in $Output) {
            If ($IncludeLicenseDetails) {
                ForEach ($Plan in $O.serviceStatuses.servicePlan) {
                    [PSCustomObject]@{
                        LicenseName        = $O.Name
                        LicenseSKUID       = $O.AccountSkuId
                        ServiceDisplayName = $Plan.displayName
                        ServiceName        = $Plan.serviceName
                        ServicePlanId      = $Plan.servicePlanId
                        ServiceType        = $Plan.serviceType
                    }
                }
            } Else {
                $O.serviceStatuses.servicePlan
            }
        }
    } ElseIf ($ServicePlansComplete) {
        # or display everything
        ForEach ($O in $Output) {
            [PSCustomObject]@{
                Name           = $O.Name
                AccountSkuID   = $O.AccountSkuId
                ServicePlan    = $O.serviceStatuses.servicePlan
                AvailableUnits = $o.availableUnits
                TotalUnits     = $O.totalUnits
                ConsumedUnits  = $O.consumedUnits
                WarningUnits   = $O.warningUnits
            }
        }
    } Else {
        $Output
    }
} ###

# https://main.iam.ad.ext.azure.com/api/AccountSkus/UserAssignments?accountSkuID=evotecpoland%3AEMSPREMIUM&nextLink=&searchText=&columnName=&sortOrder=undefined
# https://main.iam.ad.ext.azure.com/api/AccountSkus/UserAssignments?accountSkuID=evotecpoland%3AEMSPREMIUM&nextLink=&searchText=&columnName=&sortOrder=undefined
# https://main.iam.ad.ext.azure.com/api/AccountSkus/GroupAssignments?accountSkuID=evotecpoland%3AEMSPREMIUM&nextLink=&searchText=&sortOrder=undefined

Function Get-O365AzureMultiFactorAuthentication {
    <#
        .SYNOPSIS
        Retrieves the Multi-Factor Authentication settings for the specified tenant.
        .DESCRIPTION
        This function retrieves the Multi-Factor Authentication settings for the specified tenant using the provided headers.
        .PARAMETER Headers
        Specifies the headers required for the API request.
        .EXAMPLE
        Get-O365AzureMultiFactorAuthentication -Headers $Headers
        An example of how to retrieve Multi-Factor Authentication settings for a tenant.
        .NOTES
        Based on: https://portal.azure.com/#blade/Microsoft_AAD_IAM/MultifactorAuthenticationMenuBlade/GettingStarted/fromProviders/
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    #$Uri = "https://main.iam.ad.ext.azure.com/api/MultiFactorAuthentication/GetOrCreateExpandedTenantModel?tenantName=Evotec"
    $Uri    = "https://main.iam.ad.ext.azure.com/api/MultiFactorAuthentication/GetOrCreateExpandedTenantModel"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365AzureUserSettings {
    <#
        .SYNOPSIS
        Retrieves Azure user settings from the specified URI.
        .DESCRIPTION
        This function retrieves Azure user settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Specifies the headers required for the API request.
        .EXAMPLE
        Get-O365AzureUserSettings -Headers $Headers
        An example of how to retrieve Azure user settings using specified headers.
        .NOTES
        Based on: https://main.iam.ad.ext.azure.com/api/Directories/Properties
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://main.iam.ad.ext.azure.com/api/Directories/Properties"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method GET
    If ($Output) {
        [PSCustomObject]@{
            objectId                                  = $Output.objectId                                  #: ceb371f6 - 8745 - 4876-a040 - 69f2d10a9d1a
            displayName                               = $Output.displayName                               #: Evotec
            usersCanRegisterApps                      = $Output.usersCanRegisterApps                      #: True
            isAnyAccessPanelPreviewFeaturesAvailable  = $Output.isAnyAccessPanelPreviewFeaturesAvailable  #: False
            showMyGroupsFeature                       = $Output.showMyGroupsFeature                       #: False
            myGroupsFeatureValue                      = $Output.myGroupsFeatureValue                      #:
            myGroupsGroupId                           = $Output.myGroupsGroupId                           #:
            myGroupsGroupName                         = $Output.myGroupsGroupName                         #:
            showMyAppsFeature                         = $Output.showMyAppsFeature                         #: False
            myAppsFeatureValue                        = $Output.myAppsFeatureValue                        #:
            myAppsGroupId                             = $Output.myAppsGroupId                             #:
            myAppsGroupName                           = $Output.myAppsGroupName                           #:
            showUserActivityReportsFeature            = $Output.showUserActivityReportsFeature            #: False
            userActivityReportsFeatureValue           = $Output.userActivityReportsFeatureValue           #:
            userActivityReportsGroupId                = $Output.userActivityReportsGroupId                #:
            userActivityReportsGroupName              = $Output.userActivityReportsGroupName              #:
            showRegisteredAuthMethodFeature           = $Output.showRegisteredAuthMethodFeature           #: False
            registeredAuthMethodFeatureValue          = $Output.registeredAuthMethodFeatureValue          #:
            registeredAuthMethodGroupId               = $Output.registeredAuthMethodGroupId               #:
            registeredAuthMethodGroupName             = $Output.registeredAuthMethodGroupName             #:
            usersCanAddExternalUsers                  = $Output.usersCanAddExternalUsers                  #: False
            limitedAccessCanAddExternalUsers          = $Output.limitedAccessCanAddExternalUsers          #: False
            restrictDirectoryAccess                   = $Output.restrictDirectoryAccess                   #: False
            groupsInAccessPanelEnabled                = $Output.groupsInAccessPanelEnabled                #: False
            selfServiceGroupManagementEnabled         = $Output.selfServiceGroupManagementEnabled         #: True
            securityGroupsEnabled                     = $Output.securityGroupsEnabled                     #: False
            usersCanManageSecurityGroups              = $Output.usersCanManageSecurityGroups              #:
            office365GroupsEnabled                    = $Output.office365GroupsEnabled                    #: False
            usersCanManageOfficeGroups                = $Output.usersCanManageOfficeGroups                #:
            allUsersGroupEnabled                      = $Output.allUsersGroupEnabled                      #: False
            scopingGroupIdForManagingSecurityGroups   = $Output.scopingGroupIdForManagingSecurityGroups   #:
            scopingGroupIdForManagingOfficeGroups     = $Output.scopingGroupIdForManagingOfficeGroups     #:
            scopingGroupNameForManagingSecurityGroups = $Output.scopingGroupNameForManagingSecurityGroups #:
            scopingGroupNameForManagingOfficeGroups   = $Output.scopingGroupNameForManagingOfficeGroups   #:
            objectIdForAllUserGroup                   = $Output.objectIdForAllUserGroup                   #:
            allowInvitations                          = $Output.allowInvitations                          #: False
            isB2CTenant                               = $Output.isB2CTenant                               #: False
            restrictNonAdminUsers                     = $Output.restrictNonAdminUsers                     #: False
            toEnableLinkedInUsers                     = $Output.toEnableLinkedInUsers                     #: {}
            toDisableLinkedInUsers                    = $Output.toDisableLinkedInUsers                    #: {}
            # We try to make it the same as shown in Set-O365UserSettings
            linkedInAccountConnection                 = If ($Output.enableLinkedInAppFamily -eq 4) { $true } ElseIf ($Output.enableLinkedInAppFamily -eq 0) { $true } Else { $false }
            linkedInSelectedGroupObjectId             = $Output.linkedInSelectedGroupObjectId             #: b6cdb9c3-d660 - 4558-bcfd - 82c14a986b56
            linkedInSelectedGroupDisplayName          = $Output.linkedInSelectedGroupDisplayName          #: All Users
        }
    }
} ###

Function Get-O365BillingAccounts {
    <#
        .SYNOPSIS
        Retrieves billing accounts information from Office 365.
        .DESCRIPTION
        This function retrieves billing accounts information from Office 365 using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365BillingAccounts -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/fd/commerceMgmt/moderncommerce/accountGraph?api-version=3.0"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365BillingInvoices {
    <#
        .SYNOPSIS
        Gets all invoices from Office 365. If no StartDate and EndDate are specified last 6 months are used.
        .DESCRIPTION
        Gets all invoices from Office 365. If no StartDate and EndDate are specified last 6 months are used.
        .PARAMETER Headers
        Parameter description
        .PARAMETER StartDate
        Provide StartDate for the invoices to be retrieved. If not specified, StartDate is set to 6 months ago.
        .PARAMETER EndDate
        Provide EndDate for the invoices to be retrieved. If not specified, EndDate is set to current date.
        .EXAMPLE
        Get-O365BillingInvoices -Headers $headers -StartDate (Get-Date).AddMonths(-6) -EndDate (Get-Date)
        .NOTES
        This function retrieves invoices from Office 365. If no specific StartDate and EndDate are provided, the function defaults to retrieving invoices from the last 6 months.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [DateTime]$StartDate,
        [DateTime]$EndDate
    )
    If (-not $StartDate) {
        $StartDate = (Get-Date).AddMonths(-6)
    }
    If (-not $EndDate) {
        $EndDate = Get-Date
    }
    $StartDateText = $StartDate.ToString("yyyy-MM-dd")
    $EndDateText   = $EndDate.ToString("yyyy-MM-dd")
    $Uri           = "https://admin.microsoft.com/fd/commerceapi/my-org/legacyInvoices(startDate=$StartDateText,endDate=$EndDateText)"
    $Output        = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365BillingLicenseAutoClaim {
    <#
        .SYNOPSIS
        Retrieves information about licensed devices assets for a specific Office 365 tenant.
        .DESCRIPTION
        This function retrieves information about licensed devices assets for a specific Office 365 tenant using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365BillingLicenseAutoClaim -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    If ($Headers) {
        $TenantID = $Headers.Tenant
    } Else {
        $TenantID = $Script:AuthorizationO365Cache.Tenant
    }
    $Uri    = "https://admin.microsoft.com/fd/m365licensing/v1/tenants/$TenantID/licenseddevicesassets"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output.items
} ###

Function Get-O365BillingLicenseRequests {
    <#
        .SYNOPSIS
        Retrieves self-service license requests for a specific Office 365 tenant.
        .DESCRIPTION
        This function retrieves self-service license requests for a specific Office 365 tenant using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365BillingLicenseRequests -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    If ($Headers) {
        $TenantID = $Headers.Tenant
    } Else {
        $TenantID = $Script:AuthorizationO365Cache.Tenant
    }
    $Uri    = "https://admin.microsoft.com/fd/m365licensing/v1/tenants/$TenantID/self-service-requests"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output.items
} ###

Function Get-O365BillingNotifications {
    <#
        .SYNOPSIS
        Retrieves invoice preference settings for billing notifications in Office 365.
        .DESCRIPTION
        This function retrieves invoice preference settings for billing notifications in Office 365 from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365BillingNotifications -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/fd/commerceMgmt/mgmtsettings/invoicePreference?api-version=1.0 "
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365BillingNotificationsList {
    <#
        .SYNOPSIS
        Retrieves a list of billing notification users in Office 365.
        .DESCRIPTION
        This function retrieves a list of billing notification users in Office 365 from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365BillingNotificationsList -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/fd/commerceMgmt/mgmtsettings/billingNotificationUsers?api-version=1.0"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
}

<# Not working
function Get-O365BillingNotificationsList {
    [cmdletbinding()]
    param(
        [alias('Authorization')][System.Collections.IDictionary] $Headers
    )
 
    $Uri = "https://admin.microsoft.com/admin/api/Users/ListBillingNotificationsUsers"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST
    $Output
}
 
Get-O365BillingNotificationsList
#>

Function Get-O365BillingPaymentMethods {
    <#
        .SYNOPSIS
        Retrieves unsettled charges for payment instruments in the specified organization.
        .DESCRIPTION
        This function retrieves unsettled charges for payment instruments in the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365BillingPaymentMethods -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/fd/commerceapi/my-org/paymentInstruments('ObnETQAAAAABAACA')/unsettledCharges"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365BillingProfile {
    <#
        .SYNOPSIS
        Retrieves billing profile information for a specific billing group in Office 365.
        .DESCRIPTION
        This function retrieves billing profile information for a specified billing group in Office 365 from the designated API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365BillingProfile -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri = "https://admin.microsoft.com/fd/commerceMgmt/moderncommerce/checkaccess/bulk?api-version=3.0&accountId=91e58......."

    $Body = @{
        "permissionId"       = "40000000-aaaa-bbbb-ccc............"
        "organizationId"     = "19419c1b-1bf1-41...."
        "commerceObjectType" = "BillingGroup"
        "commerceObjectId"   = "6YPQ-QFKZ....."
    }

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Get-O365BillingSubscriptions {
    <#
        .SYNOPSIS
        Retrieves billing subscriptions for a specific organization in Office 365.
        .DESCRIPTION
        This function retrieves billing subscriptions for a specified organization in Office 365 from the designated API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER Property
        An array of properties to include in the query response.
        .PARAMETER OrderBy
        The property to order the query results by.
        .EXAMPLE
        Get-O365BillingSubscriptions -Headers $headers -Property @('displayName', 'status') -OrderBy 'displayName'
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [string[]]$Property,
        [string]$OrderBy
    )

    #$Uri = "https://admin.microsoft.com/fd/commerceapi/my-org/subscriptions?`$filter=parentId%20eq%20null&`$expand=subscribedsku&optional=cspsubscriptions,price,actions,transitiondetails,quickstarttag"
    $Uri = "https://admin.microsoft.com/fd/commerceapi/my-org/subscriptions"

    $QueryParameter = @{
        '$Select'  = $Property -join ','
        '$filter'  = 'parentId eq null'
        '$orderby' = $OrderBy
        'expand'   = 'subscribedsku'
        'optional' = "cspsubscriptions,price,actions,transitiondetails,quickstarttag"
    }
    Remove-EmptyValue -Hashtable $QueryParameter

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
    $Output
} ###

Function Get-O365ConsiergeAll {
    <#
        .SYNOPSIS
        Retrieves configuration information for the Concierge service in Office 365.
        .DESCRIPTION
        This function retrieves configuration information for the Concierge service in Office 365 from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365ConsiergeAll -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/api/concierge/GetConciergeConfigAll"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365DirectorySync {
    <#
        .SYNOPSIS
        Retrieves directory synchronization settings from Office 365.
        .DESCRIPTION
        This function retrieves directory synchronization settings from Office 365 using the specified API endpoint and headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/dirsync"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365DirectorySyncErrors {
    <#
        .SYNOPSIS
        Retrieves directory synchronization errors from Office 365.
        .DESCRIPTION
        This function retrieves directory synchronization errors from Office 365 using the specified API endpoint and headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365DirectorySyncErrors -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/dirsyncerrors/listdirsyncerrors"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST
    If ($Output.ObjectsWithErrorsList) {
        $Output.ObjectsWithErrorsList
    }
} ###

Function Get-O365DirectorySyncManagement {
    <#
        .SYNOPSIS
        Retrieves directory synchronization management details from Office 365.
        .DESCRIPTION
        This function retrieves directory synchronization management details from Office 365 using the specified API endpoint and headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/DirsyncManagement/manage"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365Domain {
    <#
        .SYNOPSIS
        Retrieves domain information from Office 365.
        .DESCRIPTION
        This function retrieves domain information from Office 365 using the specified API endpoint and headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365Domain -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    #$Uri = "https://admin.microsoft.com/admin/api/Domains/List?filter=&searchText=&computeDomainRegistrationData=true"
    $Uri    = "https://admin.microsoft.com/admin/api/Domains/List"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365DomainDependencies {
    <#
        .SYNOPSIS
        Provides functionality to retrieve domain dependencies in Office 365.
        .DESCRIPTION
        This function allows you to query and retrieve dependencies related to a specific domain in Office 365 using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER DomainName
        The name of the domain for which to retrieve dependencies.
        .PARAMETER Type
        Specifies the type of dependencies to retrieve. Valid values are 'All', 'Users', 'TeamsAndGroups', and 'Apps'. Default is 'All'.
        .EXAMPLE
        Get-O365DomainDependencies -Headers $headers -DomainName 'example.com' -Type 'Users'
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [string]$DomainName,
        [ValidateSet('All', 'Users', 'TeamsAndGroups', 'Apps')]
        [string]$Type = 'All'
    )
    $Uri = "https://admin.microsoft.com/admin/api/Domains/Dependencies"

    $Types = @{
        'All'    = 0
        'Users'  = 1
        'Groups' = 2
        'Apps'   = 4
    }

    $QueryParameter = @{
        'domainName' = $DomainName
        'kind'       = $Types[$Type]
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter -Method POST
    If ($Output.Succeeded) {
        $Output.Data.Dependencies
    } Else {
        [PSCustomObject]@{
            DomainName = $DomainName
            Status     = $false
            Message    = $Output.Message
        }
    }
} ###

Function Get-O365DomainHealth {
    <#
        .SYNOPSIS
        Provides functionality to check the DNS health of a specified domain in Office 365.
        .DESCRIPTION
        This function allows you to query and check the DNS health of a specific domain in Office 365 using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER DomainName
        The name of the domain for which to check DNS health.
        .EXAMPLE
        Get-O365DomainHealth -Headers $headers -DomainName 'example.com'
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [string]$DomainName
    )
    $Uri = "https://admin.microsoft.com/admin/api/Domains/CheckDnsHealth"

    $QueryParameter = @{
        'domainName'             = $DomainName
        'overrideSkip'           = $true
        'canRefreshCache'        = $true
        'dnsHealthCheckScenario' = 2
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
    If ($Output.Succeeded) {
        $Output.Data
    } Else {
        $Output
    }
} ###

<#
function Get-O365DomainRegistrarsInformation {
    [cmdletbinding()]
    param(
        [alias('Authorization')][System.Collections.IDictionary] $Headers #,
       # [parameter(Mandatory)][string] $DomainName
    )
    $Uri = "https://admin.microsoft.com/admin/api/Domains/GetRegistrarsHelpInfo"
 
    $QueryParameter = @{
        #'domainName' = $DomainName
        #'overrideSkip' = $true
        #'canRefreshCache' = $true
        #'dnsHealthCheckScenario' = 2
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
    $Output
}
#>

Function Get-O365DomainRecords {
    <#
        .SYNOPSIS
        Provides functionality to retrieve domain records for a specified domain in Office 365.
        .DESCRIPTION
        This function allows you to query and retrieve domain records for a specific domain in Office 365 using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER DomainName
        The name of the domain for which to retrieve records.
        .EXAMPLE
        Get-O365DomainRecords -Headers $headers -DomainName 'example.com'
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [string]$DomainName
    )
    $Uri = "https://admin.microsoft.com/admin/api/Domains/Records"

    $QueryParameter = @{
        'domainName' = $DomainName
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
    $Output
} ###

Function Get-O365DomainTroubleshooting {
    <#
        .SYNOPSIS
        Provides troubleshooting information for a specified domain in Office 365.
        .DESCRIPTION
        This function allows you to check if troubleshooting is allowed for a specific domain in Office 365 using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER DomainName
        The name of the domain to check troubleshooting for.
        .EXAMPLE
        Get-O365DomainTroubleshooting -Headers $headers -DomainName 'example.com'
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [string]$DomainName
    )
    $Uri = "https://admin.microsoft.com/admin/api/Domains/CheckIsTroubleshootingAllowed"

    $QueryParameter = @{
        'domainName'      = $DomainName
        #'overrideSkip' = $true
        'canRefreshCache' = $true
        #'dnsHealthCheckScenario' = 2
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
    $Output
} ###

Function Get-O365Group {
    <#
        .SYNOPSIS
        Provides functionality to retrieve Office 365 group information based on various parameters.
        .DESCRIPTION
        This function allows you to query and retrieve group information from Office 365 based on different criteria such as ID, display name, email address, and more.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER Id
        The ID of the group to query.
        .PARAMETER DisplayName
        The display name of the group to query.
        .PARAMETER EmailAddress
        The email address of the group to query.
        .PARAMETER Property
        An array of properties to include in the query response.
        .PARAMETER Filter
        The filter to apply to the query.
        .PARAMETER OrderBy
        The property to order the query results by.
        .EXAMPLE
        Get-O365Group -Headers $headers -DisplayName 'MyGroup' -Property @('displayName', 'mail')
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(ParameterSetName = 'UnifiedGroupsOnly')]
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'EmailAddress')]
        [Parameter(ParameterSetName = 'DisplayName')]
        [Parameter(ParameterSetName = 'Id')]
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,

        [Parameter(ParameterSetName = 'Id')]
        [string]$Id,

        [Parameter(ParameterSetName = 'DisplayName')]
        [string]$DisplayName,

        [Alias('Mail')]
        [Parameter(ParameterSetName = 'EmailAddress')]
        [string]$EmailAddress,

        [Parameter(ParameterSetName = 'UnifiedGroupsOnly')]
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'EmailAddress')]
        [Parameter(ParameterSetName = 'DisplayName')]
        [Parameter(ParameterSetName = 'Id')]
        [string[]]$Property,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [Parameter(ParameterSetName = 'UnifiedGroupsOnly')]
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [string]$OrderBy,

        [Parameter(ParameterSetName = 'UnifiedGroupsOnly')]
        [switch]$UnifiedGroupsOnly
    )
    If ($DisplayName) {
        $Uri = 'https://graph.microsoft.com/v1.0/groups'
        $QueryParameter = @{
            '$Select' = $Property -join ','
            '$filter' = "displayName eq '$DisplayName'"
        }
    } ElseIf ($EmailAddress) {
        $Uri = 'https://graph.microsoft.com/v1.0/groups'
        $QueryParameter = @{
            '$Select' = $Property -join ','
            '$filter' = "mail eq '$EmailAddress'"
        }
    } ElseIf ($ID) {
        # Query a single group
        $Uri = "https://graph.microsoft.com/v1.0/groups/$ID"
        $QueryParameter = @{
            '$Select' = $Property -join ','
        }
    } ElseIf ($UnifiedGroupsOnly) {
        $Uri = "https://graph.microsoft.com/v1.0/groups"
        $QueryParameter = @{
            '$Select'  = $Property -join ','
            '$filter'  = "groupTypes/any(c: c eq 'Unified')"
            '$orderby' = $OrderBy
        }
    } Else {
        # Query multiple groups
        $Uri = 'https://graph.microsoft.com/v1.0/groups'
        $QueryParameter = @{
            '$Select'  = $Property -join ','
            '$filter'  = $Filter
            '$orderby' = $OrderBy
        }
    }
    Remove-EmptyValue -Hashtable $QueryParameter
    Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
} ###

Function Get-O365GroupAdministrativeUnit {
    <#
        .SYNOPSIS
        Retrieves the administrative unit of an Office 365 group.
        .DESCRIPTION
        This function retrieves the administrative unit of an Office 365 group based on the provided GroupID or GroupDisplayName.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER GroupID
        The ID of the group to query. Default value is '75233998-a950-41de-97d0-6c259d0580a7'.
        .PARAMETER GroupDisplayName
        The display name of the group to query.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()]
        [string]$GroupID = '75233998-a950-41de-97d0-6c259d0580a7',
        [Parameter()]
        [string]$GroupDisplayName
    )

    If ($GroupID) {
        $Group = $GroupID
    } ElseIf ($GroupDisplayName) {
        $Group = $GroupDisplayName
    }
    #$Uri    = "https://graph.microsoft.com/beta/groups/$Group/memberOf/microsoft.graph.administrativeUnit"
    $Uri    = "https://graph.microsoft.com/v1.0/groups/$Group/memberOf/microsoft.graph.administrativeUnit"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365GroupLicenses {
    <#
        .SYNOPSIS
        Retrieves the licenses information for a specified Office 365 group.
        .DESCRIPTION
        This function retrieves the licenses information for an Office 365 group based on the provided GroupID or GroupDisplayName. It can also include detailed service plans information if specified.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER GroupID
        The ID of the group to query.
        .PARAMETER GroupDisplayName
        The display name of the group to query.
        .PARAMETER ServicePlans
        Switch parameter to indicate whether to retrieve detailed service plans information.
        .PARAMETER NoTranslation
        Switch parameter to skip translation of the output.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()]
        [string]$GroupID,
        [Parameter()]
        [Alias('GroupName')]
        [string]$GroupDisplayName,
        [switch]$ServicePlans,
        [switch]$NoTranslation
    )

    If ($GroupID) {
        $Group = $GroupID
    } ElseIf ($GroupDisplayName) {
        $GroupSearch = Get-O365Group -DisplayName $GroupDisplayName
        If ($GroupSearch.id) {
            $Group = $GroupSearch.id
        }
    }
    If ($Group) {
        $Uri    = "https://main.iam.ad.ext.azure.com/api/AccountSkus/Group/$Group"
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
        If ($Output) {
            If ($NoTranslation) {
                $Output
            } Else {
                ForEach ($License in $Output.licenses) {
                    $SP = Convert-SKUToLicense -SKU $License.accountSkuID
                    If ($SP) {
                        $ServicePlansPrepared = Find-EnabledServicePlan -ServicePlans $SP -DisabledServicePlans $License.disabledServicePlans
                        [PSCustomObject]@{
                            License      = $SP[0].LicenseName
                            LicenseSKUID = $SP[0].LicenseSKUID
                            Enabled      = $ServicePlansPrepared.Enabled.ServiceDisplayName
                            Disabled     = $ServicePlansPrepared.Disabled.ServiceDisplayName
                            EnabledPlan  = $ServicePlansPrepared.Enabled
                            DisabledPlan = $ServicePlansPrepared.Disabled
                        }
                    }
                }
            }
        }
    }
} ###

Function Get-O365GroupMember {
    <#
        .SYNOPSIS
        Retrieves members of an Office 365 group based on the provided group ID.
        .DESCRIPTION
        This function queries the Microsoft Graph API to retrieve members of an Office 365 group using the specified group ID.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER Id
        The ID of the Office 365 group for which members are to be retrieved.
        .PARAMETER Search
        A search query to filter the members of the group.
        .PARAMETER Property
        An array of properties to include in the query results.
        .EXAMPLE
        Get-O365GroupMember -Headers $headers -Id 'groupID' -Search 'searchQuery' -Property @('property1', 'property2')
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [string]$Id,
        [string]$Search,
        [string[]]$Property
    )
    If ($ID) {
        # Query a single group
        $Uri = "https://graph.microsoft.com/v1.0/groups/$ID/members"
        $QueryParameter = @{
            '$Select' = $Property -join ','
            '$Search' = $Search
        }
        If ($QueryParameter.'$Search') {
            # This is required for search to work
            # https://developer.microsoft.com/en-us/identity/blogs/build-advanced-queries-with-count-filter-search-and-orderby/
            $Headers['ConsistencyLevel'] = 'eventual'
        }

        Remove-EmptyValue -Hashtable $QueryParameter
        Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
    }
} ###

Function Get-O365OrgAzureSpeechServices {
    <#
        .SYNOPSIS
        Retrieves the status of Azure Speech Services for the organization.
        .DESCRIPTION
        This function queries the Microsoft Graph API to retrieve the status of Azure Speech Services for the organization.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgAzureSpeechServices -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    $Uri    = "https://admin.microsoft.com/admin/api/services/apps/azurespeechservices"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers

    [PSCustomobject]@{
        AllowTheOrganizationWideLanguageModel = $Output.IsTenantEnabled
    }
} ###

Function Get-O365OrgBingDataCollection {
    <#
        .SYNOPSIS
        Retrieves the Bing Data Collection settings for the organization.
        .DESCRIPTION
        This function queries the Microsoft Graph API to retrieve the Bing Data Collection settings for the organization.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgBingDataCollection -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/security/bingdatacollection"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgBookings {
    <#
        .SYNOPSIS
        Retrieves the Bookings settings for the organization.
        .DESCRIPTION
        This function queries the Microsoft Graph API to retrieve the Bookings settings for the organization.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgBookings -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/bookings"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgBriefingEmail {
    <#
        .SYNOPSIS
        Retrieves the status of Briefing emails for the organization.
        .DESCRIPTION
        This function queries the Microsoft Graph API to retrieve the status of Briefing emails for the organization.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgBriefingEmail -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/services/apps/briefingemail"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        [PSCustomObject]@{
            IsMailEnabled         = $Output.IsMailEnabled
            IsSubscribedByDefault = $Output.IsSubscribedByDefault
        }
    }
} ###

Function Get-O365OrgCalendarSharing {
    <#
    .SYNOPSIS
    Let your users share their calendars with people outside of your organization who have Office 365 or Exchange
    .DESCRIPTION
    Let your users share their calendars with people outside of your organization who have Office 365 or Exchange
    .PARAMETER Headers
    Authentication Token along with additional information that is created with Connect-O365Admin. If heaaders are not provided it will use the default token.
    .EXAMPLE
    Get-O365CalendarSharing
    .NOTES
    General notes
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    $Uri = 'https://admin.microsoft.com/admin/api/settings/apps/calendarsharing'

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
}

Function Get-O365OrgCommunicationToUsers {
    <#
        .SYNOPSIS
        Retrieves information about end user communications settings.
        .DESCRIPTION
        This function retrieves information about end user communications settings from the specified URI.
        .PARAMETER Headers
        Specifies the headers containing the authorization information.
        .EXAMPLE
        Get-O365OrgCommunicationToUsers -Headers $Headers
        .NOTES
        General notes
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/EndUserCommunications"

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgCompanyInformation {
    <#
        .SYNOPSIS
        Retrieves company profile information from the specified URI.
        .DESCRIPTION
        This function retrieves company profile information from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Specifies the headers containing the authorization information.
        .EXAMPLE
        Get-O365OrgCompanyInformation -Headers $Headers
        An example of how to retrieve company profile information.
        .NOTES
        General notes
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/company/profile"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
}

Function Get-O365OrgCortana {
    <#
        .SYNOPSIS
        Retrieves Cortana app information for the organization.
        .DESCRIPTION
        This function retrieves Cortana app information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Specifies the headers containing the authorization information.
        .EXAMPLE
        Get-O365OrgCortana -Headers $Headers
        An example of how to retrieve Cortana app information.
        .NOTES
        General notes
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/services/apps/cortana"

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgCustomerLockbox {
    <#
        .SYNOPSIS
        Retrieves customer lockbox information for the organization.
        .DESCRIPTION
        This function retrieves customer lockbox information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Specifies the headers containing the authorization information.
        .EXAMPLE
        Get-O365OrgCustomerLockbox -Headers $Headers
        An example of how to retrieve customer lockbox information.
        .NOTES
        General notes
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/security/dataaccess"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgCustomThemes {
    <#
        .SYNOPSIS
        Retrieves custom themes information for the organization.
        .DESCRIPTION
        This function retrieves custom themes information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Specifies the headers containing the authorization information.
        .EXAMPLE
        Get-O365OrgCustomThemes -Headers $Headers
        An example of how to retrieve custom themes information.
        .NOTES
        General notes
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/company/theme/v2"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output.ThemeData
} ###

Function Get-O365OrgDataLocation {
    <#
        .SYNOPSIS
        Retrieves the data location information for the organization.
        .DESCRIPTION
        This function retrieves the data location information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgDataLocation -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/tenant/datalocation"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgDynamics365ConnectionGraph {
    <#
        .SYNOPSIS
        Retrieves Dynamics 365 Connection Graph information for the organization.
        .DESCRIPTION
        This function retrieves Dynamics 365 Connection Graph information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgDynamics365ConnectionGraph -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/dcg"

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgDynamics365CustomerVoice {
    <#
        .SYNOPSIS
        Retrieves Dynamics 365 Customer Voice information for the organization.
        .DESCRIPTION
        This function retrieves Dynamics 365 Customer Voice information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgDynamics365CustomerVoice -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/officeformspro"

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgDynamics365SalesInsights {
    <#
        .SYNOPSIS
        Retrieves Dynamics 365 Sales Insights information for the organization.
        .DESCRIPTION
        This function retrieves Dynamics 365 Sales Insights information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgDynamics365SalesInsights -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/dci"

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgForms {
    <#
        .SYNOPSIS
        Retrieves information about Office Forms for the organization.
        .DESCRIPTION
        This function retrieves information about Office Forms for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgForms -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/officeforms/"

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgGraphDataConnect {
    <#
        .SYNOPSIS
        Retrieves Graph Data Connect information for the organization.
        .DESCRIPTION
        This function retrieves Graph Data Connect information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgGraphDataConnect -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/o365dataplan"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgHelpdeskInformation {
    <#
        .SYNOPSIS
        Retrieves helpdesk information for the organization.
        .DESCRIPTION
        This function retrieves helpdesk information for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgHelpdeskInformation -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/company/helpdesk"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgInstallationOptions {
    <#
        .SYNOPSIS
        Retrieves installation options for Microsoft 365 software.
        .DESCRIPTION
        This function retrieves installation options for Microsoft 365 software from the specified API endpoint using the provided headers. It provides details on Windows and Mac installation settings.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER NoTranslation
        Indicates whether to include translation for the installation options.
        .EXAMPLE
        Get-O365OrgInstallationOptions -Headers $headers -NoTranslation
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch] $NoTranslation
    )
    $Branches = @{
        "0" = 'Not applicable'
        "1" = "CurrentChannel"
        "3" = 'MonthlyEnterpriseChannel'
        "2" = 'SemiAnnualEnterpriseChannel'
    }

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/usersoftware"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($NoTranslation) {
        $Output.UserSoftwareSettings
    } else {
        If ($Output.UserSoftwareSettings) {
            [PSCustomObject]@{
                WindowsBranch           = $Branches[$($Output.UserSoftwareSettings[0].Branch.ToString())]
                WindowsClient           = $Output.UserSoftwareSettings[0].ClientVersion
                WindowsLastUpdate       = $Output.UserSoftwareSettings[0].BranchLastUpdateTime
                WindowsOffice           = $Output.UserSoftwareSettings[0].ServiceStatusMap.'Office (includes Skype for Business),MicrosoftOffice_ClientDownload'
                WindowsSkypeForBusiness = $Output.UserSoftwareSettings[0].ServiceStatusMap.'Skype for Business (Standalone),MicrosoftCommunicationsOnline';
                MacBranch               = $Branches[$($Output.UserSoftwareSettings[1].Branch.ToString())]
                MacClient               = $Output.UserSoftwareSettings[1].ClientVersion
                MacLastUpdate           = $Output.UserSoftwareSettings[1].BranchLastUpdateTime
                MacOffice               = $Output.UserSoftwareSettings[1].ServiceStatusMap.'Office,MicrosoftOffice_ClientDownload'
                MacSkypeForBusiness     = $Output.UserSoftwareSettings[1].LegacyServiceStatusMap.'Skype for Business (X EI Capitan 10.11 or higher),MicrosoftCommunicationsOnline'
            }
        }
    }
} ###

Function Get-O365OrgLicensesAutoClaim {
    <#
        .SYNOPSIS
        Provides functionality to retrieve auto claim policies for Microsoft 365 licenses.
        .DESCRIPTION
        This function retrieves auto claim policies for Microsoft 365 licenses from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgLicensesAutoClaim -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/fd/m365licensing/v1/policies/autoclaim"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgM365Groups {
    <#
        .SYNOPSIS
        Provides information on how guests from outside the organization can collaborate with users in Microsoft 365 Groups.
        .DESCRIPTION
        This function retrieves settings related to guest access in Microsoft 365 Groups.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgM365Groups -Headers $headers
        .NOTES
        This function provides details on guest access settings in Microsoft 365 Groups.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )
    #$Uri = "https://admin.microsoft.com/admin/api/settings/security/guestUserPolicy"
    #$Output1 = Invoke-O365Admin -Uri $Uri -Headers $Headers

    $Uri    = "https://admin.microsoft.com/admin/api/settings/security/o365guestuser"
    $Output2 = Invoke-O365Admin -Uri $Uri -Headers $Headers

    [PSCustomObject]@{
        #AllowGuestAccess = $Output1.AllowGuestAccess
        #AllowGuestInvitations = $Output1.AllowGuestInvitations
        #SitesSharingEnabled = $Output1.SitesSharingEnabled
        AllowGuestsAsMembers = $Output2.AllowGuestsAsMembers
        AllowGuestAccess     = $Output2.AllowGuestAccess
    }
} ###

Function Get-O365OrgMicrosoftSearch {
    <#
        .SYNOPSIS
        Provides functionality to retrieve Microsoft search configurations for the organization.
        .DESCRIPTION
        This function retrieves Microsoft search configurations for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgMicrosoftSearch -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/searchadminapi/configurations"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgMicrosoftTeams {
    <#
        .SYNOPSIS
        Retrieves Microsoft Teams settings for the organization.
        .DESCRIPTION
        This function retrieves Microsoft Teams settings for the organization from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgMicrosoftTeams -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/skypeteams"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
    <#
    IsSkypeTeamsLicensed : True
    TenantCategorySettings : {@{TenantSkuCategory=BusinessEnterprise; IsSkypeTeamsEnabled=; Meetups=; FunControl=; Messaging=}, @{TenantSkuCategory=Guest; IsSkypeTeamsEnabled=; Meetups=; FunControl=; Messaging=}}
    Bots : @{IsBotsEnabled=; IsSideLoadedBotsEnabled=; BotSettings=System.Object[]; IsExternalAppsEnabledByDefault=}
    Miscellaneous : @{IsOrganizationTabEnabled=; IsSkypeBusinessInteropEnabled=; IsTBotProactiveMessagingEnabled=}
    Email : @{IsEmailIntoChannelsEnabled=; RestrictedSenderList=System.Object[]}
    CloudStorage : @{Box=; Dropbox=; GoogleDrive=; ShareFile=}
    TeamsOwnedApps : @{TeamsOwnedAppSettings=System.Object[]}
    TenantOwnedApps : @{TenantOwnedAppSettings=System.Object[]}
    MigrationStates : @{EnableAppsMigration=; EnableClientSettingsMigration=; EnableMeetupsMigration=; EnableMessagingMigration=}
    #>
} ###

Function Get-O365OrgModernAuthentication {
    <#
        .SYNOPSIS
        Provides information about modern authentication for Office 365.
        .DESCRIPTION
        This function retrieves details about modern authentication for Office 365 from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgModernAuthentication -Verbose
        .NOTES
        For more information, visit: https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/ModernAuthentication
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/services/apps/modernAuth"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgMyAnalytics {
    <#
        .SYNOPSIS
        Retrieves MyAnalytics settings for Office 365.
        .DESCRIPTION
        This function retrieves MyAnalytics settings for Office 365 from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .EXAMPLE
        Get-O365OrgMyAnalytics -Headers $headers
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/services/apps/myanalytics"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        [PSCustomObject]@{
            EnableInsightsDashboard    = -not $Output.IsDashboardOptedOut
            EnableWeeklyDigest         = -not $Output.IsEmailOptedOut
            EnableInsightsOutlookAddIn = -not $Output.IsAddInOptedOut
            # IsNudgesOptedOut : False
            # IsWindowsSignalOptedOut : False
            # MeetingEffectivenessSurvey : Unavailable
        }
    }
} ###

Function Get-O365OrgNews {
    <#
        .SYNOPSIS
        Retrieves news options for Bing in the organization.
        .DESCRIPTION
        This function retrieves news options for Bing in the organization. It can return the content enabled on a new tab and whether company information and industry are enabled.
        .PARAMETER Headers
        Authentication token and additional information created with Connect-O365Admin.
        .PARAMETER NoTranslation
        Indicates whether to skip translation of news options.
        .EXAMPLE
        Get-O365OrgNews -Headers $headers -NoTranslation
        .NOTES
        This function retrieves news options for Bing from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch] $NoTranslation
    )

    $Uri    = "https://admin.microsoft.com/admin/api/searchadminapi/news/options/Bing"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($NoTranslation) {
        $Output
    } Else {
        If ($Output) {
            [PSCustomObject]@{
                ContentOnNewTabEnabled               = $Output.NewsOptions.EdgeNTPOptions.IsOfficeContentEnabled
                CompanyInformationAndIndustryEnabled = $Output.NewsOptions.EdgeNTPOptions.IsShowCompanyAndIndustry
            }
        }
    }
} ###

Function Get-O365OrgOfficeOnTheWeb {
    <#
        .SYNOPSIS
        Retrieves settings for Office Online apps in the organization.
        .DESCRIPTION
        This function retrieves settings for Office Online apps in the organization from the specified URI.
        .PARAMETER Headers
        Authentication token and additional information created with Connect-O365Admin.
        .EXAMPLE
        Get-O365OrgOfficeOnTheWeb -Headers $headers
        .NOTES
        This function retrieves settings for Office Online apps from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/officeonline"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgOfficeProductivity {
    <#
        .SYNOPSIS
        Retrieves productivity score information for the organization.
        .DESCRIPTION
        This function retrieves productivity score information for the organization from the specified URIs.
        .PARAMETER Headers
        Authentication token and additional information created with Connect-O365Admin.
        .EXAMPLE
        Get-O365OrgOfficeProductivity -Headers $headers
        .NOTES
        This function retrieves productivity score information from the specified URIs.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri     = "https://admin.microsoft.com/admin/api/reports/productivityScoreCustomerOption"
    $Output1 = Invoke-O365Admin -Uri $Uri -Headers $Headers

    $Uri     = "https://admin.microsoft.com/admin/api/reports/productivityScoreConfig/GetProductivityScoreConfig"
    $Output2 = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output2Json = $Output2.Output | ConvertFrom-Json
    $Output1Json = $Output1.Output | ConvertFrom-Json
    $Output = [PSCustomObject] @{
        TenantId                  = $Output2Json.TenantId
        ProductivityScoreSignedup = $Output2Json.ProductivityScoreSignedup
        SignupUserPuid            = $Output2Json.SignupUserPuid
        SignupTime                = $Output2Json.SignupTime
        ReadyTime                 = $Output2Json.ReadyTime
        ProductivityScoreOptedIn  = $Output1Json.ProductivityScoreOptedIn
        OperationUserPuid         = $Output1Json.OperationUserPuid
        OperationTime             = $Output1Json.OperationTime
    }
    $Output
} ###

Function Get-O365OrgOrganizationInformation {
    <#
        .SYNOPSIS
        Retrieves organization information from the specified URI.
        .DESCRIPTION
        This function retrieves organization information from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .PARAMETER NoTranslation
        Specifies whether to skip translation.
        .EXAMPLE
        Get-O365OrgOrganizationInformation -Headers $headers -NoTranslation
        .NOTES
        This function retrieves organization information from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/company/profile"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($NoTranslation) {
        $Output
    } Else {
        $Output
    }
} ###

Function Get-O365OrgPasswordExpirationPolicy {
    <#
        .SYNOPSIS
        Retrieves password expiration policy information from the specified URI.
        .DESCRIPTION
        This function retrieves password expiration policy information from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .PARAMETER NoTranslation
        Specifies whether to skip translation.
        .EXAMPLE
        Get-O365OrgPasswordExpirationPolicy -Headers $headers -NoTranslation
        .NOTES
        This function retrieves password expiration policy information from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch] $NoTranslation
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/security/passwordpolicy"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($NoTranslation) {
        $Output
    } Else {
        [PSCustomObject]@{
            PasswordNeverExpires      = $Output.NeverExpire
            DaysBeforePasswordExpires = $Output.ValidityPeriod
            DaysBeforeUserNotified    = $Output.NotificationDays
            # not shown in the GUI
            # MinimumValidityPeriod : 14
            # MinimumNotificationDays : 1
            # MaximumValidityPeriod : 730
            # MaximumNotificationDays : 30
        }
    }
} ###

Function Get-O365OrgPlanner {
    <#
        .SYNOPSIS
        Retrieves information about Planner settings from the specified URI.
        .DESCRIPTION
        This function retrieves information about Planner settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .EXAMPLE
        Get-O365OrgPlanner -Headers $headers
        .NOTES
        This function retrieves information about Planner settings from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/services/apps/planner"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        [PSCustomObject]@{
            # Thos are always the same
            #id = $Output.id # : 1
            #isPlannerAllowed = $Output.isPlannerAllowed # : True
            allowCalendarSharing = $Output.allowCalendarSharing # : True
            # Those are always the same
            # GUI doesn't show that
            # allowTenantMoveWithDataLoss = $Output.allowTenantMoveWithDataLoss # : False
            # allowRosterCreation = $Output.allowRosterCreation # : True
            # allowPlannerMobilePushNotifications = $Output.allowPlannerMobilePushNotifications # : True
        }
    }
} ###

Function Get-O365OrgPrivacyProfile {
    <#
        .SYNOPSIS
        Retrieves information about the organization's privacy policy.
        .DESCRIPTION
        This function retrieves information about the organization's privacy policy from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .EXAMPLE
        Get-O365OrgPrivacyProfile -Headers $headers
        .NOTES
        This function retrieves information about the organization's privacy policy from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/security/privacypolicy"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgPrivilegedAccess {
    <#
        .SYNOPSIS
        Retrieves information about privileged access settings for the organization.
        .DESCRIPTION
        This function retrieves information about privileged access settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .EXAMPLE
        Get-O365OrgPrivilegedAccess -Headers $headers
        .NOTES
        This function retrieves information about privileged access settings from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/security/tenantLockbox"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgProject {
    <#
        .SYNOPSIS
        Retrieves information about the organization's Project settings.
        .DESCRIPTION
        This function retrieves information about the organization's Project settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .PARAMETER NoTranslation
        Switch to indicate whether to skip translation of output.
        .EXAMPLE
        Get-O365OrgProject -Headers $headers -NoTranslation
        .NOTES
        This function retrieves information about the organization's Project settings from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch] $NoTranslation
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/projectonline"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($NoTranslation) {
        $Output
    } Else {
        If ($Output) {
            [PSCustomObject]@{
                RoadmapEnabled          = $Output.IsRoadmapEnabled
                ProjectForTheWebEnabled = $Output.IsModProjEnabled
            }
        }
    }
} ###

Function Get-O365OrgReports {
    <#
        .SYNOPSIS
        Retrieves organization reports configuration.
        .DESCRIPTION
        This function retrieves the organization's reports configuration from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .EXAMPLE
        Get-O365OrgReports -Headers $headers
        .NOTES
        This function retrieves organization reports configuration from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/reports/config/GetTenantConfiguration"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $OutputFromJson = $Output.Output | ConvertFrom-Json
    $OutputFromJson
} ###

Function Get-O365OrgScripts {
    <#
        .SYNOPSIS
        Retrieves organization scripts configuration.
        .DESCRIPTION
        This function retrieves the organization's scripts configuration from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .EXAMPLE
        Get-O365OrgScripts -Headers $headers
        .NOTES
        This function retrieves organization scripts configuration from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Status = @{
        '0' = 'Disabled'
        '1' = 'Everyone'
        '2' = 'SpecificGroup'
    }

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/officescripts"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        [PSCustomObject]@{
            # we don't show those options as they have no values
            # we also don't show them as there is no option in GUI
            #OfficeScriptsEnabled = $Output.OfficeScriptsEnabled # :
            #OfficeScriptsPreviewEnabled = $Output.OfficeScriptsPreviewEnabled # :
            EnabledOption         = $Status[$($Output.EnabledOption).ToString()]               # : 1
            EnabledGroup          = $Output.EnabledGroup                # :
            EnabledGroupDetail    = $Output.EnabledGroupDetail          # :
            ShareOption           = $Status[$($Output.ShareOption).ToString()]                 # : 1
            ShareGroup            = $Output.ShareGroup                  # :
            ShareGroupDetail      = $Output.ShareGroupDetail            # :
            UnattendedOption      = $Status[$($Output.UnattendedOption).ToString()]            # : 0
            UnattendedGroup       = $Output.UnattendedGroup             # :
            UnattendedGroupDetail = $Output.UnattendedGroupDetail       # :
            #TenantId = $Output.TenantId # :
        }
    }
} ###

Function Get-O365OrgSharePoint {
    <#
        .SYNOPSIS
        Retrieves SharePoint organization settings.
        .DESCRIPTION
        This function retrieves SharePoint organization settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .EXAMPLE
        Get-O365OrgSharePoint -Headers $headers
        .NOTES
        This function retrieves SharePoint organization settings from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $TranslateCollaboration = @{
        '2'  = 'NewAndExistingGuestsOnly'
        '16' = 'Anyone'
        '32' = 'ExistingGuestsOnly'
        '1'  = 'OnlyPeopleInYourOrganization'
    }

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/sitessharing"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        [PSCustomObject]@{
            AllowSharing                      = $Output.AllowSharing
            SiteUrl                           = $Output.SiteUrl
            AdminUrl                          = $Output.AdminUrl
            RequireAnonymousLinksExpireInDays = $Output.RequireAnonymousLinksExpireInDays
            CollaborationType                 = $TranslateCollaboration[$Output.CollaborationType.ToString()]
        }
    }
} ###

Function Get-O365OrgSharing {
    <#
        .SYNOPSIS
        Retrieves organization sharing settings.
        .DESCRIPTION
        This function retrieves organization sharing settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .PARAMETER NoTranslation
        Switch to bypass translation.
        .EXAMPLE
        Get-O365OrgSharing -Headers $headers
        .NOTES
        This function retrieves organization sharing settings from the specified URI.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch] $NoTranslation
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/security/guestUserPolicy"
    $Output1 = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($NoTranslation) {
        $Output1
    } Else {
        # In fiddler we could see additional queries, but in edge/chrome not so much
        #$Uri = "https://admin.microsoft.com/admin/api/settings/apps/sitessharing"
        #$Output2 = Invoke-O365Admin -Uri $Uri -Headers $Headers
        #$Output2 | Format-Table

        # $Uri = "https://admin.microsoft.co//admin/api/settings/security/o365guestuser"
        # $Output3 = Invoke-O365Admin -Uri $Uri -Headers $Headers
        # $Output3 | Format-Table
        If ($Output1) {
            [PSCustomObject]@{
                # GUI doesn't show them, so maybe let's not show them either
                #AllowGuestAccess = $Output1.AllowGuestAccess
                LetUsersAddNewGuests = $Output1.AllowGuestInvitations
                #SitesSharingEnabled = $Output1.SitesSharingEnabled
                #AllowSharing = $Output2.AllowSharing
                #SiteUrl = $Output2.SiteUrl
                #AdminUri = $Output2.AdminUri
                #RequireAnonymousLinksExpireInDays = $Output2.RequireAnonymousLinksExpireInDays
                #CollaborationType = $Output2.CollaborationType
            }
        }
    }
} ###

Function Get-O365OrgSway {
    <#
        .SYNOPSIS
        Retrieves organization Sway settings.
        .DESCRIPTION
        This function retrieves organization Sway settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/Sway"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgToDo {
    <#
        .SYNOPSIS
        Retrieves organization To-Do app settings.
        .DESCRIPTION
        This function retrieves organization To-Do app settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/services/apps/todo"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365OrgUserConsentApps {
    <#
        .SYNOPSIS
        Retrieves organization user consent apps settings.
        .DESCRIPTION
        This function retrieves organization user consent apps settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/IntegratedApps"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($null -ne $Output) {
        [PSCustomObject]@{
            UserConsentToAppsEnabled = $Output
        }
    }
} ###

Function Get-O365OrgUserOwnedApps {
    <#
        .SYNOPSIS
        Retrieves organization user owned apps settings.
        .DESCRIPTION
        This function retrieves organization user owned apps settings from the specified URIs using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri1    = "https://admin.microsoft.com/admin/api/settings/apps/store"
    $Output1 = Invoke-O365Admin -Uri $Uri1 -Headers $Headers

    $Uri2    = "https://admin.microsoft.com/admin/api/storesettings/iwpurchaseallowed"
    $Output2 = Invoke-O365Admin -Uri $Uri2 -Headers $Headers

    $Uri3    = 'https://admin.microsoft.com/fd/m365licensing/v1/policies/autoclaim'
    $Output3 = Invoke-O365Admin -Uri $Uri3 -Headers $Headers

    [PSCustomObject]@{
        LetUsersAccessOfficeStore = $Output1
        LetUsersStartTrials       = $Output2
        LetUsersAutoClaimLicenses = If ($Output3.tenantPolicyValue -eq 'Disabled') { $false } ElseIf ($Output3.tenantPolicyValue -eq 'Enabled') { $true } Else { $null }
        <#
        {
        "policyId": "Autoclaim",
        "tenantPolicyValue": "Enabled",
        "tenantId": "ceb371f6-"
        }
        #>

    }
} ###

Function Get-O365OrgWhiteboard {
    <#
        .SYNOPSIS
        Retrieves organization whiteboard settings.
        .DESCRIPTION
        This function retrieves organization whiteboard settings from the specified URI using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .PARAMETER NoTranslation
        Switch to disable translation of telemetry data.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [switch]$NoTranslation
    )

    $TranslateTelemetry = @{
        '0' = 'Neither'
        '1' = 'Required'
        '2' = 'Optional'
    }
    $Uri = 'https://admin.microsoft.com/admin/api/settings/apps/whiteboard'

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($NoTranslation) {
        $Output
    } Else {
        If ($Output) {
            [PSCustomObject]@{
                WhiteboardEnabled            = $Output.IsEnabled
                DiagnosticData               = $TranslateTelemetry[$Output.TelemetryPolicy.ToString()]
                OptionalConnectedExperiences = $Output.AreConnectedServicesEnabled
                BoardSharingEnabled          = $Output.IsClaimEnabled
                OneDriveStorageEnabled       = $Output.IsSharePointDefault
                # Not sure what this does
                NonTenantAccess              = $Output.NonTenantAccess
                #LearnMoreUrl = $Output.LearnMoreUrl
                #ProductUrl = $Output.ProductUrl
                #TermsOfUseUrl = $Output.TermsOfUseUrl
            }
        }
    }
} ###

Function Get-O365PartnerRelationship {
    <#
        .SYNOPSIS
        Retrieves partner relationship information based on the specified tenant ID.
        .DESCRIPTION
        This function retrieves partner relationship details for the provided tenant ID from the partner management API.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .PARAMETER TenantID
        The ID of the tenant for which partner relationships are to be retrieved.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [string]$TenantID
    )
    If (-not $TenantID) {
        If ($Headers.Tenant) {
            $TenantID = $Headers.Tenant
        } ElseIf ($Script:AuthorizationO365Cache.Tenant) {
            $TenantID = $Script:AuthorizationO365Cache.Tenant
        }
    }
    If ($TenantID) {
        $Uri    = "https://admin.microsoft.com/fd/commerceMgmt/partnermanage/partners?customerTenantId=$TenantID&api-version=2.1"
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers

        If ($Output.partners) {
            ForEach ($Partner in $Output.partners) {
                [PSCustomObject]@{
                    id            = $Partner.id  #: c2248f0a
                    name          = $Partner.name  #:
                    aadRoles      = Convert-AzureRole -RoleID $Partner.aadRoles
                    # i am not 100% sure on the conversion types on different numbers so i'll disable them for now
                    companyType   = $Partner.companyType #Convert-CompanyType -CompanyType $Partner.companyType #: 4
                    canRemoveDap  = $Partner.canRemoveDap  #: True
                    contractTypes = $Partner.contractTypes # Convert-ContractType -ContractType $Partner.contractTypes #: {3}
                    partnerType   = $Partner.partnerType  #: 1
                }
            }
        }
    } Else {
        Write-Warning -Message "Get-O365PartnerRelationship - TenantID was not found in headers. Skipping."
    }
} ###

Function Get-O365PasswordReset {
    <#
        .SYNOPSIS
        Retrieves password reset policies from the specified endpoint.
        .DESCRIPTION
        This function retrieves password reset policies from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365PasswordResetIntegration {
    <#
        .SYNOPSIS
        Retrieves password reset integration details from the specified endpoint.
        .DESCRIPTION
        This function retrieves password reset integration details from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    #$Uri = "https://main.iam.ad.ext.azure.com/api/PasswordReset/IsOnPremisesPasswordResetAvailable"
    $Uri    = "https://main.iam.ad.ext.azure.com/api/PasswordReset/OnPremisesPasswordResetPolicies"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    If ($Output) {
        [PSCustomObject]@{
            PasswordWritebackSupported = $Output.passwordWritebackSupported
            # This one doesn't change and stays enabled all the time
            #AccountUnlockSupported = $Output.accountUnlockSupported
            AccountUnlockEnabled       = $Output.accountUnlockEnabled
        }
    }
} ###

Function Get-O365OrgReleasePreferences {
    <#
        .SYNOPSIS
        Retrieves organization release preferences from the specified endpoint.
        .DESCRIPTION
        This function retrieves organization release preferences from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
        .NOTES
        Invoke-O365Admin function is used to make administrative calls to the Office 365 API. It handles requests for various administrative tasks.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/Settings/company/releasetrack"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365SearchIntelligenceBingConfigurations {
    <#
        .SYNOPSIS
        Retrieves Bing configurations for Office 365 search intelligence.
        .DESCRIPTION
        This function retrieves Bing configurations for Office 365 search intelligence from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/admin/api/searchadminapi/configurations"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365SearchIntelligenceItemInsights {
    <#
        .SYNOPSIS
        Retrieves item insights for Office 365 search intelligence.
        .DESCRIPTION
        This function retrieves item insights for Office 365 search intelligence from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/fd/configgraphprivacy/ceb371f6-8745-4876-a040-69f2d10a9d1a/settings/ItemInsights"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365SearchIntelligenceMeetingInsights {
    <#
        .SYNOPSIS
        Retrieves meeting insights for Office 365 search intelligence.
        .DESCRIPTION
        This function retrieves meeting insights for Office 365 search intelligence from the specified API endpoint using the provided headers.
        .PARAMETER Headers
        Authentication token and additional information for the API request.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers
    )

    $Uri    = "https://admin.microsoft.com/fd/ssms/api/v1.0/'3srecs'/Collection('meetinginsights')/Settings(Path=':',LogicalId='MeetingInsightsToggle')"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers
    $Output
} ###

Function Get-O365ServicePrincipal {
    <#
        .SYNOPSIS
        Retrieves information about Office 365 service principals based on various parameters.
        .DESCRIPTION
        This function allows you to query and retrieve service principal information from Office 365 based on different criteria such as ID, display name, service principal type, and more.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER Id
        The ID of the service principal to query.
        .PARAMETER DisplayName
        The display name of the service principal to query.
        .PARAMETER ServicePrincipalType
        The type of service principal to query. Valid values are 'Application', 'Legacy', 'SocialIdp'.
        .PARAMETER Property
        An array of properties to include in the query response.
        .PARAMETER Filter
        The filter to apply to the query.
        .PARAMETER GuestsOnly
        Switch parameter to query only guest service principals.
        .PARAMETER OrderBy
        The property to order the query results by.
        .EXAMPLE
        Get-O365ServicePrincipal -Headers $headers -DisplayName 'MyApp' -Property @('displayName', 'appId')
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    Param (
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'GuestsOnly')]
        [Parameter(ParameterSetName = 'ServicePrincipalType')]
        [Parameter(ParameterSetName = 'DisplayName')]
        [Parameter(ParameterSetName = 'Id')]
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,

        [Parameter(ParameterSetName = 'Id')]
        [string]$Id,

        [Parameter(ParameterSetName = 'DisplayName')]
        [string]$DisplayName,

        [Parameter(ParameterSetName = 'ServicePrincipalType')]
        [ValidateSet('Application', 'Legacy', 'SocialIdp')]
        [string]$ServicePrincipalType,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'GuestsOnly')]
        [Parameter(ParameterSetName = 'ServicePrincipalType')]
        [Parameter(ParameterSetName = 'DisplayName')]
        [Parameter(ParameterSetName = 'Id')]
        [string[]]$Property,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [Parameter(ParameterSetName = 'GuestsOnly')]
        [switch]$GuestsOnly,

        [Parameter(ParameterSetName = 'GuestsOnly')]
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [string]$OrderBy
    )
    If ($GuestsOnly) {
        $Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals'
        $QueryParameter = @{
            '$Select'  = $Property -join ','
            '$filter'  = "userType eq 'Guest'"
            '$orderby' = $OrderBy
        }
    } ElseIf ($DisplayName) {
        $Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals'
        $QueryParameter = @{
            '$Select' = $Property -join ','
            '$filter' = "displayName eq '$DisplayName'"
        }
    } ElseIf ($ServicePrincipalType) {
        $Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals'
        $QueryParameter = @{
            '$Select' = $Property -join ','
            '$filter' = "servicePrincipalType eq '$ServicePrincipalType'"
        }
    } ElseIf ($ID) {
        # Query a single service principal
        $Uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ID"
        $QueryParameter = @{
            '$Select' = $Property -join ','
        }
    } Else {
        # Query multiple service principals
        $Uri = 'https://graph.microsoft.com/v1.0/servicePrincipals'
        $QueryParameter = @{
            '$Select'  = $Property -join ','
            # https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter
            '$filter'  = $Filter
            '$orderby' = $OrderBy
        }
    }
    Remove-EmptyValue -Hashtable $QueryParameter
    Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
} ###

Function Get-O365TenantID {
    <#
        .SYNOPSIS
        Provides the tenant ID for a given domain.
        .DESCRIPTION
        This function retrieves the tenant ID associated with a specific domain by querying the OpenID configuration endpoint.
        .PARAMETER Domain
        Specifies the domain for which to retrieve the tenant ID.
        .EXAMPLE
        Get-O365TenantID -Domain 'evotec.pl'
        .NOTES
        For more information, refer to the OpenID Connect Discovery documentation.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [Alias('DomainName')]
        [string]$Domain
    )
    $Invoke = Invoke-RestMethod "https://login.windows.net/$Domain/.well-known/openid-configuration" -Method GET -Verbose:$false
    If ($Invoke) {
        $Invoke.userinfo_endpoint.Split("/")[3]
    }
} ###

Function Get-O365User {
    <#
        .SYNOPSIS
        Provides functionality to retrieve Office 365 user information based on various parameters.
        .DESCRIPTION
        This function allows you to query and retrieve user information from Office 365 based on different criteria such as UserPrincipalName, EmailAddress, and ID.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER Id
        The ID of the user to query.
        .PARAMETER UserPrincipalName
        The UserPrincipalName of the user to query.
        .PARAMETER EmailAddress
        The email address of the user to query.
        .PARAMETER Property
        An array of properties to include in the query response.
        .PARAMETER Filter
        The filter to apply to the query.
        .PARAMETER GuestsOnly
        Switch parameter to query only guest users.
        .PARAMETER OrderBy
        The property to order the query results by.
        .EXAMPLE
        Get-O365User -Headers $headers -UserPrincipalName 'john.doe@example.com' -Property @('displayName', 'jobTitle')
        .NOTES
        For more information, visit: https://docs.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    Param (
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'GuestsOnly')]
        [Parameter(ParameterSetName = 'EmailAddress')]
        [Parameter(ParameterSetName = 'UserPrincipalName')]
        [Parameter(ParameterSetName = 'Id')]
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,

        [Parameter(ParameterSetName = 'Id')]
        [string]$Id,

        [Parameter(ParameterSetName = 'UserPrincipalName')]
        [string]$UserPrincipalName,

        [Parameter(ParameterSetName = 'EmailAddress')]
        [Alias('Mail')]
        [string]$EmailAddress,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [Parameter(ParameterSetName = 'GuestsOnly')]
        [Parameter(ParameterSetName = 'EmailAddress')]
        [Parameter(ParameterSetName = 'UserPrincipalName')]
        [Parameter(ParameterSetName = 'Id')]
        [string[]]$Property,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [string]$Filter,

        [Parameter(ParameterSetName = 'GuestsOnly')]
        [switch]$GuestsOnly,

        [Parameter(ParameterSetName = 'GuestsOnly')]
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Filter')]
        [string]$OrderBy
    )
    If ($GuestsOnly) {
        $Uri = 'https://graph.microsoft.com/v1.0/users'
        $QueryParameter = @{
            '$Select'  = $Property -join ','
            '$filter'  = "userType eq 'Guest'"
            '$orderby' = $OrderBy
        }
    } ElseIf ($UserPrincipalName) {
        $Uri = 'https://graph.microsoft.com/v1.0/users'
        $QueryParameter = @{
            '$Select' = $Property -join ','
            '$filter' = "userPrincipalName eq '$UserPrincipalName'"
        }
    } ElseIf ($EmailAddress) {
        $Uri = 'https://graph.microsoft.com/v1.0/users'
        $QueryParameter = @{
            '$Select' = $Property -join ','
            '$filter' = "mail eq '$EmailAddress'"
        }
    } ElseIf ($ID) {
        # Query a single group
        $Uri = "https://graph.microsoft.com/v1.0/users/$ID"
        $QueryParameter = @{
            '$Select' = $Property -join ','
        }
    } Else {
        # Query multiple groups
        $Uri = 'https://graph.microsoft.com/v1.0/users'
        $QueryParameter = @{
            '$Select'  = $Property -join ','
            # https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter
            '$filter'  = $Filter
            '$orderby' = $OrderBy
        }
    }
    Remove-EmptyValue -Hashtable $QueryParameter
    Invoke-O365Admin -Uri $Uri -Headers $Headers -QueryParameter $QueryParameter
} ###

Function Invoke-O365Admin {
    <#
        .SYNOPSIS
        This function is used to make administrative calls to the Office 365 API.
        .DESCRIPTION
        This function is responsible for sending requests to the Office 365 API for administrative tasks.
        .PARAMETER Uri
        The URI endpoint for the API request.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER Method
        The HTTP method to be used for the request (GET, DELETE, POST, PATCH, PUT).
        .PARAMETER ContentType
        The content type of the request body.
        .PARAMETER Body
        The body of the request, if applicable.
        .PARAMETER QueryParameter
        The query parameters for the request.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [uri]$Uri,
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [ValidateSet('GET', 'DELETE', 'POST', 'PATCH', 'PUT')]
        [string]$Method = 'GET',
        [string]$ContentType = "application/json; charset=UTF-8",
        [System.Collections.IDictionary]$Body,
        [System.Collections.IDictionary]$QueryParameter
    )
    If (-not $Headers -and $Script:AuthorizationO365Cache) {
        # This forces a reconnect of session in case it's about to time out. If it's not timeouting a cache value is used
        $Headers = Connect-O365Admin -Headers $Headers
    } Else {
        Write-Warning "Invoke-O365Admin - Not connected. Please connect using Connect-O365Admin."
        return
    }
    If (-not $Headers) {
        Write-Warning "Invoke-O365Admin - Authorization error. Skipping."
        return
    }
    $RestSplat = @{
        Method      = $Method
        ContentType = $ContentType
    }
    If ($Uri -like '*admin.microsoft.com*') {
        $RestSplat['Headers'] = $Headers.HeadersO365
    } ElseIf ($Uri -like '*graph.microsoft.com*') {
        $RestSplat['Headers'] = $Headers.HeadersGraph
    } Else {
        $RestSplat['Headers'] = $Headers.HeadersAzure
    }

    If ($PSVersionTable.PSVersion.Major -eq 5) {
        $CookieContainer = [System.Net.CookieContainer]::new()
        $CookieContainer.MaxCookieSize = 1048576

        $Session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $Session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36 Edg/93.0.961.38"
        $Session.Cookies = $CookieContainer
        $RestSplat['WebSession'] = $Session
    }

    #$RestSplat.Headers."x-ms-mac-hosting-app" = 'M365AdminPortal'
    #$RestSplat.Headers."x-ms-mac-version" = 'host-mac_2021.8.16.1'
    #$RestSplat.Headers."sec-ch-ua" = '"Chromium";v="92", " Not A;Brand";v="99", "Microsoft Edge";v="92"'
    #$RestSplat.Headers."x-portal-routekey" = 'weu'
    #$RestSplat.Headers."x-ms-mac-appid" = 'feda2aab-4737-4646-a86c-98a7742c70e6'
    #$RestSplat.Headers."x-adminapp-request" = '/Settings/Services/:/Settings/L1/Whiteboard'
    #$RestSplat.Headers."x-ms-mac-target-app" = 'MAC'
    #$RestSplat.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 Edg/92.0.902.73'
    #$RestSplat.Headers.Cookie = 'MC1=GUID=480c128a5ba04faea7df151a53bdfa9a&HASH=480c&LV=202107&V=4&LU=1627670649689'

    #$RestSplat.Headers."x-ms-mac-hosting-app" = 'M365AdminPortal'
    #$RestSplat.Headers."x-adminapp-request" = '/Settings/Services/:/Settings/L1/EndUserCommunications'
    #$RestSplat.Headers."Referer" = 'https://admin.microsoft.com/'
    #$RestSplat.Headers."AjaxSessionKey" = 'x5eAwqzbVehBOP7QHfrjpwr9eYtLiHJt7TZFj0uhUMUPQ2T7yNdA7rEgOulejHDHYM1ZyCT0pgXo96EwrfVpMA=='
    #$RestSplat.Headers."etag" = '1629993527.826253_3ce8143d'

    If ($Body) {
        $RestSplat['Body'] = $Body | ConvertTo-Json -Depth 5
    }
    $RestSplat.Uri = Join-UriQuery -BaseUri $Uri -QueryParameter $QueryParameter
    If ($RestSplat['Body']) {
        $WhatIfInformation = "Invoking [$Method] " + [System.Environment]::NewLine + $RestSplat['Body'] + [System.Environment]::NewLine
    } Else {
        $WhatIfInformation = "Invoking [$Method] "
    }
    Try {
        Write-Verbose "Invoke-O365Admin - $($WhatIfInformation)over URI $($RestSplat.Uri)"
        If ($Method -eq 'GET') {
            # We use separate check because WHATIF would sometimes trigger when GET was used inside a SET
            $OutputQuery = Invoke-RestMethod @RestSplat -Verbose:$false
            If ($null -ne $OutputQuery) {
                If ($OutputQuery -is [bool]) {
                    $OutputQuery
                } ElseIf ($OutputQuery -is [array]) {
                    $Properties = $OutputQuery | Select-Properties -ExcludeProperty '@odata.context', '@odata.id', '@odata.type', 'Length' -WarningAction SilentlyContinue -WarningVariable varWarning
                    If (-not $varWarning) {
                        $OutputQuery | Select-Object -Property $Properties
                    }
                } ElseIf ($OutputQuery -is [string]) {
                    If ($OutputQuery) {
                        $Properties = $OutputQuery | Select-Properties -ExcludeProperty '@odata.context', '@odata.id', '@odata.type', 'Length' -WarningAction SilentlyContinue -WarningVariable varWarning
                        If (-not $varWarning) {
                            $OutputQuery | Select-Object -Property $Properties
                        }
                    }
                } ElseIf ($OutputQuery -is [PSCustomObject]) {
                    If ($OutputQuery.PSObject.Properties.Name -contains 'value') {
                        $Properties = $OutputQuery.value | Select-Properties -ExcludeProperty '@odata.context', '@odata.id', '@odata.type', 'Length' -WarningAction SilentlyContinue -WarningVariable varWarning
                        If (-not $varWarning) {
                            $OutputQuery.value | Select-Object -Property $Properties
                        }
                    } Else {
                        $Properties = $OutputQuery | Select-Properties -ExcludeProperty '@odata.context', '@odata.id', '@odata.type', 'Length' -WarningAction SilentlyContinue -WarningVariable varWarning
                        If (-not $varWarning) {
                            $OutputQuery | Select-Object -Property $Properties
                        }
                    }
                } Else {
                    Write-Warning -Message "Invoke-O365Admin - Type $($OutputQuery.GetType().Name) potentially unsupported."
                    $OutputQuery
                }
            }
            If ($OutputQuery -isnot [array]) {
                If ($OutputQuery.'@odata.nextLink') {
                    $RestSplat.Uri = $OutputQuery.'@odata.nextLink'
                    If ($RestSplat.Uri) {
                        $MoreData = Invoke-O365Admin @RestSplat
                        If ($null -ne $MoreData) {
                            $MoreData
                        }
                    }
                }
            }
        } Else {
            If ($PSCmdlet.ShouldProcess($($RestSplat.Uri), $WhatIfInformation)) {
                #$CookieContainer = [System.Net.CookieContainer]::new()
                #$CookieContainer.MaxCookieSize = 8096
                $OutputQuery = Invoke-RestMethod @RestSplat -Verbose:$false
                If ($Method -in 'POST', 'PUT') {
                    If ($null -ne $OutputQuery) {
                        $OutputQuery
                    }
                } Else {
                    return $true
                }
            }
        }
    } Catch {
        $RestError = $_.ErrorDetails.Message
        If ($RestError) {
            Try {
                $ErrorMessage = ConvertFrom-Json -InputObject $RestError -ErrorAction Stop
                # Write-Warning -Message "Invoke-Graph - [$($ErrorMessage.error.code)] $($ErrorMessage.error.message), exception: $($_.Exception.Message)"
                Write-Warning -Message "Invoke-O365Admin - Error JSON: $($_.Exception.Message) $($ErrorMessage.error.message)"
            } Catch {
                Write-Warning -Message "Invoke-O365Admin - Error: $($RestError.Trim())"
            }
        } Else {
            Write-Warning -Message "Invoke-O365Admin - $($_.Exception.Message)"
        }
        If ($_.ErrorDetails.RecommendedAction) {
            Write-Warning -Message "Invoke-O365Admin - Recommended action: $RecommendedAction"
        }
        If ($Method -notin 'GET', 'POST') {
            return $false
        }
    }
} ###

Function New-O365License {
    <#
        .SYNOPSIS
        Helper cmdlet to create a new O365 license that is used in Set-O365AzureGroupLicenses cmdlet.
        .DESCRIPTION
        Helper cmdlet to create a new O365 license that is used in Set-O365AzureGroupLicenses cmdlet.
        .PARAMETER LicenseName
        LicenseName to assign. Can be used instead of LicenseSKUID
        .PARAMETER LicenseSKUID
        LicenseSKUID to assign. Can be used instead of LicenseName
        .PARAMETER EnabledServicesDisplayName
        Specifies the display names of services to enable.
        .PARAMETER EnabledServicesName
        Specifies the names of services to enable.
        .PARAMETER DisabledServicesDisplayName
        Specifies the display names of services to disable.
        .PARAMETER DisabledServicesName
        Specifies the names of services to disable.
        .EXAMPLE
        Set-O365GroupLicenses -GroupDisplayName 'Test-Group-TestEVOTECPL' -Licenses @(
            New-O365License -LicenseName 'Office 365 E3' -Verbose
            New-O365License -LicenseName 'Enterprise Mobility + Security E5' -Verbose
        ) -Verbose -WhatIf
        .EXAMPLE
        Set-O365GroupLicenses -GroupDisplayName 'Test-Group-TestEVOTECPL' -Licenses @(
            New-O365License -LicenseName 'Office 365 E3' -Verbose -DisabledServicesDisplayName 'Microsoft Kaizala Pro', 'Whiteboard (Plan 2)'
            New-O365License -LicenseName 'Enterprise Mobility + Security E5' -Verbose -EnabledServicesDisplayName 'Azure Information Protection Premium P2', 'Microsoft Defender for Identity'
        ) -Verbose -WhatIf
        .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName = 'ServiceDisplayNameEnable')]
    Param (
        [string]$LicenseName,
        [string]$LicenseSKUID,
        [Parameter(ParameterSetName = 'ServiceDisplayNameEnable')]
        [string[]]$EnabledServicesDisplayName,
        [Parameter(ParameterSetName = 'ServiceNameEnable')]
        [string[]]$EnabledServicesName,
        [Parameter(ParameterSetName = 'ServiceDisplayNameDisable')]
        [string[]]$DisabledServicesDisplayName,
        [Parameter(ParameterSetName = 'ServiceNameDisable')]
        [string[]]$DisabledServicesName
    )

    If ($LicenseName) {
        $ServicePlans = Get-O365AzureLicenses -ServicePlans -IncludeLicenseDetails -LicenseName $LicenseName
    } ElseIf ($LicenseSKUID) {
        $ServicePlans = Get-O365AzureLicenses -ServicePlans -IncludeLicenseDetails -LicenseSKUID $LicenseSKUID
    } Else {
        Return
    }
    If ($ServicePlans) {
        If ($EnabledServicesDisplayName -or $EnabledServicesName -or $DisabledServicesDisplayName -or $DisabledServicesName) {
            [Array]$DisabledServicePlans = ForEach ($Plan in $ServicePlans) {
                If ($EnabledServicesDisplayName) {
                    If ($Plan.ServiceDisplayName -notin $EnabledServicesDisplayName) {
                        $Plan.serviceName
                    }
                } ElseIf ($EnabledServicesName) {
                    If ($Plan.ServiceName -notin $EnabledServicesName) {
                        $Plan.serviceName
                    }
                } ElseIf ($DisabledServicesDisplayName) {
                    If ($Plan.ServiceDisplayName -in $DisabledServicesDisplayName) {
                        $Plan.serviceName
                    }
                } ElseIf ($DisabledServicesName) {
                    If ($Plan.ServiceName -in $DisabledServicesName) {
                        $Plan.serviceName
                    }
                }
            }
        } Else {
            $DisabledServicePlans = @()
        }
        If ($ServicePlans[0].LicenseSKUID) {
            [ordered]@{
                accountSkuId         = $ServicePlans[0].LicenseSKUID
                disabledServicePlans = if ($DisabledServicePlans.Count -eq 0) { , @() } else { $DisabledServicePlans }
            }
        } Else {
            Write-Warning "New-O365License - No LicenseSKUID found. Skipping"
        }
    }
} ###

Function Set-O365AzureEnterpriseAppsGroupConsent {
    <#
        .SYNOPSIS
        Provides functionality to set group-specific consent for enterprise apps in Azure Active Directory.
        .DESCRIPTION
        This function allows administrators to configure group-specific consent for enterprise apps in Azure Active Directory.
        .PARAMETER Headers
        Specifies the headers for the API request, typically including authorization tokens.
        .PARAMETER EnableGroupSpecificConsent
        Specifies whether to enable group-specific consent.
        .PARAMETER GroupId
        The ID of the group for which to set consent.
        .PARAMETER GroupName
        The display name of the group for which to set consent.
        .PARAMETER BlockUserConsentForRiskyApps
        Specifies whether to block user consent for risky apps.
        .PARAMETER EnableAdminConsentRequests
        Specifies whether to enable admin consent requests.
        .EXAMPLE
        An example of how to use this function:
        Set-O365AzureEnterpriseAppsGroupConsent -Headers $headers -EnableGroupSpecificConsent $true -GroupId "12345" -BlockUserConsentForRiskyApps $true -EnableAdminConsentRequests $false
        .NOTES
        Please ensure that:
            - Group-specific consent can be set using either GroupId or GroupName parameter.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()]
        [bool]$EnableGroupSpecificConsent,
        [Parameter()]
        [string]$GroupId,
        [Parameter()]
        [string]$GroupName,
        # Other options
        [Parameter()]
        [bool]$BlockUserConsentForRiskyApps,
        [Parameter()]
        [bool]$EnableAdminConsentRequests
    )

    $Uri = 'https://graph.microsoft.com/beta/settings/e0953218-a490-4c92-a975-ab724a6cfb07'
    $CurrentSettings = Get-O365AzureEnterpriseAppsGroupConsent -Headers $Headers
    If ($CurrentSettings) {
        [string]$EnableSpecific = If ($PSBoundParameters.ContainsKey('EnableGroupSpecificConsent')) {
            $EnableGroupSpecificConsent.ToString().ToLower()
        } Else {
            $CurrentSettings.EnableGroupSpecificConsent.ToString().ToLower()
        }
        If ($PSBoundParameters.ContainsKey('EnableGroupSpecificConsent')) {
            # We only set group if EnableGroupSpecificConsent is used
            If ($GroupId) {
                $Group = $GroupId
            } ElseIf ($GroupName) {
                $AskForGroup = Get-O365Group -DisplayName $GroupName -Headers $Headers
                If ($AskForGroup.Id) {
                    $Group = $AskForGroup.Id
                    If ($Group -isnot [string]) {
                        Write-Warning -Message "Set-O365AzureEnterpriseAppsGroupConsent - GroupName couldn't be translated to single ID. "
                        ForEach ($G in $AskForGroup) {
                            Write-Warning -Message "Group DisplayName: $($G.DisplayName) | Group ID: $($G.ID)"
                        }
                        return
                    }
                } Else {
                    Write-Warning -Message "Set-O365AzureEnterpriseAppsGroupConsent - GroupName couldn't be translated to ID. Skipping."
                    Return
                }
            } Else {
                $Group = ''
            }
        } Else {
            # We read the current group
            $Group = $CurrentSettings.ConstrainGroupSpecificConsentToMembersOfGroupId
        }
        [string]$BlockUserConsent = If ($PSBoundParameters.ContainsKey('BlockUserConsentForRiskyApps')) {
            $BlockUserConsentForRiskyApps.ToString().ToLower()
        } Else {
            $CurrentSettings.BlockUserConsentForRiskyApps.ToString().ToLower()
        }
        [string] $AdminConsent = If ($PSBoundParameters.ContainsKey('EnableAdminConsentRequests')) {
            $EnableAdminConsentRequests.ToString().ToLower()
        } Else {
            $CurrentSettings.EnableAdminConsentRequests.ToString().ToLower()
        }
        $Body = @{
            values = @(
                [ordered]@{
                    "name"  = "EnableGroupSpecificConsent"
                    "value" = $EnableSpecific
                }
                [ordered]@{
                    "name"  = "BlockUserConsentForRiskyApps"
                    "value" = $BlockUserConsent
                }
                [ordered]@{
                    "name"  = "EnableAdminConsentRequests"
                    "value" = $AdminConsent
                }
                [ordered]@{
                    "name" = "ConstrainGroupSpecificConsentToMembersOfGroupId"
                    value  = $Group
                }
            )
        }
        $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PATCH -Body $Body
    }
} ###

Function Set-O365AzureEnterpriseAppsUserConsent {
    <#
        .SYNOPSIS
        Configures user consent settings for Azure enterprise applications.
        .DESCRIPTION
        This function allows administrators to configure user consent settings for Azure enterprise applications.
        .PARAMETER Headers
        Specifies the headers for the API request, typically including authorization tokens.
        .PARAMETER PermissionGrantPoliciesAssigned
        Specifies the permission grant policies assigned for user consent.
        .EXAMPLE
        An example of how to use this function:
        Set-O365AzureEnterpriseAppsUserConsent -Headers $headers -PermissionGrantPoliciesAssigned 'AllowUserConsentForApps'
        .NOTES
        For more information, visit: https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/UserSettings
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [string]
        [ValidateSet('AllowUserConsentForApps', 'AllowUserConsentForSelectedPermissions', 'DoNotAllowUserConsent')]
        $PermissionGrantPoliciesAssigned
    )

    $Uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'

    $Convert = Convert-AzureEnterpriseAppsUserConsent -PermissionsGrantPoliciesAssigned $PermissionGrantPoliciesAssigned -Reverse

    $Body = @{
        defaultUserRolePermissions = [ordered]@{
            permissionGrantPoliciesAssigned = If ($Convert) { , @($Convert) } Else { , @() }
        }
    }
    If ($Body) {
        $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PATCH -Body $Body
    }
} ###

Function Set-O365AzureEnterpriseAppsUserSettings {
    <#
        .SYNOPSIS
        Configures user settings for Azure enterprise applications.
        .DESCRIPTION
        This function allows administrators to configure user settings for Azure enterprise applications.
        .PARAMETER Headers
        Specifies the headers for the API request, typically including authorization tokens.
        .PARAMETER UsersCanConsentAppsAccessingData
        Specifies whether users can consent to apps accessing company data.
        .PARAMETER UsersCanAddGalleryAppsToMyApp
        Specifies whether users can add gallery apps to their applications.
        .PARAMETER UsersCanOnlySeeO365AppsInPortal
        Specifies whether users can only see Office 365 apps in the portal.
        .EXAMPLE
        An example of how to use this function:
        Set-O365AzureEnterpriseAppsUserSettings -Headers $headers -UsersCanConsentAppsAccessingData $true -UsersCanAddGalleryAppsToMyApp $false -UsersCanOnlySeeO365AppsInPortal $true
        .NOTES
        Please keep in mind that:
            - Users can consent to apps accessing company data for the groups they own -> can be set using Set-O3465AzureEnterpriseAppsGroupConsent
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$UsersCanConsentAppsAccessingData,
        [System.Nullable[bool]]$UsersCanAddGalleryAppsToMyApp,
        [System.Nullable[bool]]$UsersCanOnlySeeO365AppsInPortal
    )

    $Uri = 'https://main.iam.ad.ext.azure.com/api/EnterpriseApplications/UserSettings'

    # Contrary to most of the cmdlets, if you provide null as values not filled in, nothing is changed.
    # Body "{`"usersCanAllowAppsToAccessData`":false,`"usersCanAddGalleryApps`":null,`"hideOffice365Apps`":null}"
    $Body = @{
        usersCanAllowAppsToAccessData = $UsersCanConsentAppsAccessingData
        usersCanAddGalleryApps        = $UsersCanAddGalleryAppsToMyApp
        hideOffice365Apps             = $UsersCanOnlySeeO365AppsInPortal
    }
    # However, we're going to remove those empty entries anyways.
    Remove-EmptyValue -Hashtable $Body
    If ($Body.Keys.Count -gt 0) {
        $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PATCH -Body $Body
    }
} ###

<#Function Set-O365AzureEnterpriseAppsUserSettingsAdmin {
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$UserConsentToAppsEnabled
    )
    $Uri = "https://main.iam.ad.ext.azure.com/api/RequestApprovals/V2/PolicyTemplates"
    #-Body "{`"id`":null,`"requestExpiresInDays`":30,`"notificationsEnabled`":true,`
    #"remindersEnabled`":true,`"approversV2`":{`"user`":[`"e6a8f1cf-0874-4323-a12f-2bf51bb6dfdd`"],`"group`":[],`"role`":[]}}"
    #$Body = @{
    # Enabled = $UserConsentToAppsEnabled
    #}
    #$null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
}#>

Function Set-O365AzureExternalCollaborationSettings {
    <#
        .SYNOPSIS
        Configures external collaboration settings for Office 365 Azure.
        .DESCRIPTION
        This function allows administrators to configure various settings related to external collaboration in Office 365 Azure. It includes options for managing invitations, subscription sign-ups, self-service password reset (SSPR), and more.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER AllowInvitesFrom
        Specifies who can send invitations to external users. Valid values are 'none', 'adminsAndGuestInviters', 'adminsGuestInvitersAndAllMembers', 'everyone'.
        .PARAMETER AllowedToSignUpEmailBasedSubscriptions
        Indicates whether users are allowed to sign up for email-based subscriptions.
        .PARAMETER AllowedToUseSSPR
        Indicates whether users are allowed to use Self-Service Password Reset.
        .PARAMETER AllowEmailVerifiedUsersToJoinOrganization
        Indicates whether email verified users are allowed to join the organization.
        .PARAMETER BlockMsolPowerShell
        Indicates whether to block the use of MSOnline PowerShell module.
        .PARAMETER DisplayName
        The display name for the settings.
        .PARAMETER Description
        A description of the settings.
        .PARAMETER GuestUserRole
        Specifies the role of a guest user. Valid values are 'User', 'GuestUser', 'RestrictedUser'.
        .PARAMETER AllowedToCreateApps
        Indicates whether users are allowed to create applications.
        .PARAMETER AllowedToCreateSecurityGroups
        Indicates whether users are allowed to create security groups.
        .PARAMETER AllowedToReadOtherUsers
        Indicates whether users are allowed to read other users' profiles.
        .PARAMETER PermissionGrantPoliciesAssigned
        Specifies the permission grant policies assigned to the user.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365AzureExternalCollaborationSettings -Headers $headers -AllowInvitesFrom "everyone" -AllowedToSignUpEmailBasedSubscriptions $true -AllowedToUseSSPR $true -AllowEmailVerifiedUsersToJoinOrganization $false -BlockMsolPowerShell $false -DisplayName "External Collaboration Policy" -Description "Policy for managing external collaboration." -GuestUserRole "GuestUser" -AllowedToCreateApps $true -AllowedToCreateSecurityGroups $true -AllowedToReadOtherUsers $false -PermissionGrantPoliciesAssigned @("Policy1", "Policy2")
        .NOTES
        Ensure that you have the necessary permissions to invoke this command.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [ValidateSet('none', 'adminsAndGuestInviters', 'adminsGuestInvitersAndAllMembers', 'everyone')]
        [string]$AllowInvitesFrom,
        [System.Nullable[bool]]$AllowedToSignUpEmailBasedSubscriptions,
        [System.Nullable[bool]]$AllowedToUseSSPR,
        [System.Nullable[bool]]$AllowEmailVerifiedUsersToJoinOrganization,
        [System.Nullable[bool]]$BlockMsolPowerShell,
        [string]$DisplayName,
        [string]$Description,
        [ValidateSet('User', 'GuestUser', 'RestrictedUser')]
        [string]$GuestUserRole,
        [System.Nullable[bool]]$AllowedToCreateApps,
        [System.Nullable[bool]]$AllowedToCreateSecurityGroups,
        [System.Nullable[bool]]$AllowedToReadOtherUsers,
        [Array]$PermissionGrantPoliciesAssigned
    )

    $GuestUserRoleIDs = @{
        'User'           = 'a0b1b346-4d3e-4e8b-98f8-753987be4970'
        'GuestUser'      = '10dae51f-b6af-4016-8d66-8c2a99b929b3'
        'RestrictedUser' = '2af84b1e-32c8-42b7-82bc-daa82404023b'
    }
    If ($GuestUserRole) {
        $GuestUserRoleID = $GuestUserRoleIDs[$GuestUserRole]
    }

    If ($AllowInvitesFrom) {
        # This translation is to make sure the casing is correct as it may be given by user in different way
        If ($AllowInvitesFrom -eq 'none') {
            $AllowInvitesFrom = 'none'
        } ElseIf ($AllowInvitesFrom -eq 'adminsAndGuestInviters') {
            $AllowInvitesFrom = 'adminsAndGuestInviters'
        } ElseIf ($AllowInvitesFrom -eq 'adminsGuestInvitersAndAllMembers') {
            $AllowInvitesFrom = 'adminsGuestInvitersAndAllMembers'
        } ElseIf ($AllowInvitesFrom -eq 'everyone') {
            $AllowInvitesFrom = 'everyone'
        }
    }

    $Uri = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'

    $Body = @{
        allowInvitesFrom                          = $AllowInvitesFrom                          # : adminsAndGuestInviters
        allowedToSignUpEmailBasedSubscriptions    = $AllowedToSignUpEmailBasedSubscriptions    # : True
        allowedToUseSSPR                          = $AllowedToUseSSPR                          # : True
        allowEmailVerifiedUsersToJoinOrganization = $AllowEmailVerifiedUsersToJoinOrganization # : False
        blockMsolPowerShell                       = $BlockMsolPowerShell                       # : False
        displayName                               = $DisplayName                               # : Authorization Policy
        description                               = $Description                               # : Used to manage authorization related settings across the company.
        guestUserRoleId                           = $GuestUserRoleId                           # : a0b1b346-4d3e-4e8b-98f8-753987be4970
        defaultUserRolePermissions                = [ordered]@{
            allowedToCreateApps             = $AllowedToCreateApps
            allowedToCreateSecurityGroups   = $AllowedToCreateSecurityGroups
            allowedToReadOtherUsers         = $AllowedToReadOtherUsers
            permissionGrantPoliciesAssigned = $PermissionGrantPoliciesAssigned
        }
    }
    Remove-EmptyValue -Hashtable $Body -Recursive -Rerun 2
    If ($Body) {
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PATCH -Body $Body
        #$Output
    }
} ###

Function Set-O365AzureGroupExpiration {
    <#
        .SYNOPSIS
        Sets the expiration settings for Office 365 Azure groups.
        .DESCRIPTION
        This function configures the lifecycle management settings for Office 365 Azure groups, including setting the group lifetime, specifying which groups are managed, and configuring admin notification emails.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER GroupLifeTime
        Specifies the lifetime of the group in days. Accepts 180 or 365 days, or a custom value.
        .PARAMETER ExpirationEnabled
        Determines the scope of groups for which expiration is enabled. Valid values are 'None', 'Selected', 'All'.
        .PARAMETER AdminNotificationEmails
        Specifies the email addresses for sending notifications about group expiration events.
        .PARAMETER ExpirationGroups
        Specifies the display names of groups for which expiration settings are to be applied. This parameter is used when ExpirationEnabled is set to 'Selected'.
        .PARAMETER ExpirationGroupsID
        Specifies the IDs of groups for which expiration settings are to be applied. This parameter is used when ExpirationEnabled is set to 'Selected'.
        .EXAMPLE
        $Headers = @{Authorization = "Bearer your_token"}
        Set-O365AzureGroupExpiration -Headers $Headers -GroupLifeTime 365 -ExpirationEnabled 'Selected' -AdminNotificationEmails 'admin@example.com' -ExpirationGroups @('Group1', 'Group2')

        This example sets the group expiration for 'Group1' and 'Group2' with a lifetime of 365 days, where only selected groups are managed, and notifications are sent to 'admin@example.com'.
        .LINK
        https://main.iam.ad.ext.azure.com/api/Directories/LcmSettings
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[int]]$GroupLifeTime,
        [ValidateSet('None', 'Selected', 'All')]
        [string]$ExpirationEnabled,
        [string]$AdminNotificationEmails,
        [Array]$ExpirationGroups,
        [Array]$ExpirationGroupsID
    )

    $Uri = 'https://main.iam.ad.ext.azure.com/api/Directories/LcmSettings'

    $CurrentSettings = Get-O365AzureGroupExpiration -Headers $Headers -NoTranslation

    If ($null -ne $GroupLifeTime) {
        # if group lifetime is defined we need to build 2 values
        If ($GroupLifeTime -eq 180) {
            $expiresAfterInDays = 0
            $groupLifetimeCustomValueInDays = 0
        } ElseIf ($GroupLifeTime -eq 365) {
            $expiresAfterInDays = 1
            $groupLifetimeCustomValueInDays = 0
        } Else {
            $expiresAfterInDays = 2
            $groupLifetimeCustomValueInDays = $GroupLifeTime
        }
    } Else {
        # if it's not defined we need to get current values
        $expiresAfterInDays = $CurrentSettings.expiresAfterInDays
        $groupLifetimeCustomValueInDays = $CurrentSettings.groupLifetimeCustomValueInDays
    }
    If ($ExpirationEnabled -eq 'None') {
        $ManagedGroupTypes = 2
    } ElseIf ($ExpirationEnabled -eq 'Selected') {
        $ManagedGroupTypes = 1
    } ElseIf ($ExpirationEnabled -eq 'All') {
        $ManagedGroupTypes = 0
    } Else {
        $ManagedGroupTypes = $CurrentSettings.managedGroupTypes
    }
    If (-not $AdminNotificationEmails) {
        $AdminNotificationEmails = $CurrentSettings.adminNotificationEmails
    }

    If ($ExpirationGroups) {
        [Array] $GroupsID = ForEach ($Ex in $ExpirationGroups) {
            $GroupFound = Get-O365Group -DisplayName $Ex -Headers $Headers
            If ($GroupFound.Id) {
                $GroupFound.Id
            }
        }
        If ($GroupsID.Count -gt 0) {
            $groupIdsToMonitorExpirations = If ($GroupsID.Count -in 0, 1) {
                , @($GroupsID)
            } Else {
                $GroupsID
            }
        } Else {
            Write-Warning -Message "Set-O365AzureGroupExpiration - Couldn't find any groups provided in ExpirationGroups. Skipping"
            return
        }
    } ElseIf ($ExpirationGroupsID) {
        $groupIdsToMonitorExpirations = If ($ExpirationGroupsID.Count -in 0, 1) {
            , @($ExpirationGroupsID)
        } Else {
            $ExpirationGroupsID
        }

    } Else {
        $groupIdsToMonitorExpirations = If ($CurrentSettings.groupIdsToMonitorExpirations.count -in 0, 1) {
            , @($CurrentSettings.groupIdsToMonitorExpirations)
        } Else {
            $CurrentSettings.groupIdsToMonitorExpirations
        }
    }

    $Body = [ordered]@{
        expiresAfterInDays             = $expiresAfterInDays
        groupLifetimeCustomValueInDays = $groupLifetimeCustomValueInDays
        managedGroupTypesEnum          = $CurrentSettings.managedGroupTypesEnum
        managedGroupTypes              = $ManagedGroupTypes
        adminNotificationEmails        = $AdminNotificationEmails
        groupIdsToMonitorExpirations   = $groupIdsToMonitorExpirations
        policyIdentifier               = $CurrentSettings.policyIdentifier
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body
} ###

Function Set-O365AzureMultiFactorAuthentication {
    <#
        .SYNOPSIS
        Configures Multi-Factor Authentication (MFA) settings for an Office 365 tenant.
        .DESCRIPTION
        This function allows administrators to modify various settings related to Multi-Factor Authentication (MFA) for their Office 365 tenant. It includes options such as account lockout policies, fraud alert configurations, and bypass settings.
        .PARAMETER Headers
        Specifies the headers for the API request, typically including authorization details.
        .PARAMETER AccountLockoutDurationMinutes
        Specifies the duration in minutes that an account remains locked after reaching the threshold of failed MFA attempts.
        .PARAMETER AccountLockoutResetMinutes
        Defines the time period in minutes after which the count of failed MFA attempts is reset.
        .PARAMETER AccountLockoutThreshold
        Number of MFA denials to trigger account lockout
        .PARAMETER AllowPhoneMenu
        Parameter description
        .PARAMETER BlockForFraud
        Automatically block users who report fraud
        .PARAMETER CallerId
        MFA caller ID number (US phone number only)
        .PARAMETER DefaultBypassTimespan
        Default one-time bypass seconds
        .PARAMETER EnableFraudAlert
        Allow users to submit fraud alerts
        .PARAMETER FraudCode
        Code to report fraud during initial greeting
        .PARAMETER FraudNotificationEmailAddresses
        Recipient's Email Address
        .PARAMETER OneTimeBypassEmailAddresses
        Recipient's One-Time Email Addresses for Bypass
        .PARAMETER PinAttempts
        Number of PIN attempts allowed per call
        .PARAMETER SayExtensionDigits
        Parameter description
        .PARAMETER SmsTimeoutSeconds
        Two-way text message timeout seconds
        .PARAMETER Caches
        Parameter description
        .PARAMETER Notifications
        Parameter description
        .PARAMETER NotificationEmailAddresses
        Parameter description
        .PARAMETER Greetings
        Parameter description
        .PARAMETER BlockedUsers
        Parameter description
        .PARAMETER BypassedUsers
        Parameter description
        .EXAMPLE
        An example
        .NOTES
        Based on: https://portal.azure.com/#blade/Microsoft_AAD_IAM/MultifactorAuthenticationMenuBlade/GettingStarted/fromProviders/
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[int]]$AccountLockoutDurationMinutes,
        [System.Nullable[int]]$AccountLockoutResetMinutes,
        [System.Nullable[int]]$AccountLockoutThreshold,
        #$AllowPhoneMenu,
        [System.Nullable[bool]]$BlockForFraud,
        #$CallerId,
        #$DefaultBypassTimespan,
        [System.Nullable[bool]]$EnableFraudAlert,
        [System.Nullable[int]]$FraudCode
        #$FraudNotificationEmailAddresses,
        #$OneTimeBypassEmailAddresses,
        #$PinAttempts,
        #$SayExtensionDigits,
        #$SmsTimeoutSeconds,
        #$Caches,
        #$Notifications,
        #$NotificationEmailAddresses
        #$Greetings ,
        #$BlockedUsers ,
        #$BypassedUsers
    )
    #$Uri = "https://main.iam.ad.ext.azure.com/api/MultiFactorAuthentication/GetOrCreateExpandedTenantModel?tenantName=Evotec"
    # $Uri = "https://main.iam.ad.ext.azure.com/api/MultiFactorAuthentication/GetOrCreateExpandedTenantModel"

    # Whatever I do, doesn't work!

    $Uri  = "https://main.iam.ad.ext.azure.com/api/MultiFactorAuthentication/TenantModel"
    $Body = [ordered]@{
        #tenantId = $CurrentSettings #: ceb371f6
        #licenseKey = $CurrentSettings #:
        #customerId = $CurrentSettings #:
        AccountLockoutDurationMinutes   = $accountLockoutDurationMinutes #:
        AccountLockoutResetMinutes      = $accountLockoutResetMinutes #:
        AccountLockoutThreshold         = $accountLockoutThreshold #:
        AllowPhoneMenu                  = $allowPhoneMenu #: False
        BlockForFraud                   = $BlockForFraud #: False
        CallerId                        = $callerId #: 8553308653
        DefaultBypassTimespan           = $defaultBypassTimespan #: 300
        EnableFraudAlert                = $EnableFraudAlert #: True
        FraudCode                       = $fraudCode #: 0
        FraudNotificationEmailAddresses = $fraudNotificationEmailAddresses #:
        OneTimeBypassEmailAddresses     = $oneTimeBypassEmailAddresses #:
        PinAttempts                     = $pinAttempts #:
        SayExtensionDigits              = $sayExtensionDigits #: False
        SmsTimeoutSeconds               = $smsTimeoutSeconds #: 60
        #caches = $caches #: {}
        Notifications                   = $notifications #:
        NotificationEmailAddresses      = $notificationEmailAddresses #: {}
        #greetings = $greetings #: {}
        #blockedUsers = $blockedUsers #: {}
        #bypassedUsers = $bypassedUsers #: {}
        #groups = $groups
        #etag = $etag
    }

    Remove-EmptyValue -Hashtable $Body
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PATCH -Body $Body
    $Output
} ###

<#
/api/MultiFactorAuthentication/TenantModel?licenseKey=
 
PATCH https://main.iam.ad.ext.azure.com/api/MultiFactorAuthentication/TenantModel?licenseKey= HTTP/1.1
Host: main.iam.ad.ext.azure.com
Connection: keep-alive
Content-Length: 67
x-ms-client-session-id: 9fb6b21894f14f5786814508d7462a51
Accept-Language: en
etag: 1629994960.340884_c0565cb3
Authorization: Bearer .
x-ms-effective-locale: en.en-us
Content-Type: application/json
Accept: */*
x-ms-client-request-id: 983affdb-0b06-4095-b652-048e18d8d010
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.78
Origin: https://portal.azure.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
 
{"AccountLockoutResetMinutes":5,"AccountLockoutDurationMinutes":20}
#>
Function Set-O365AzureUserSettings {
    <#
        .SYNOPSIS
        Configures user settings for Azure AD.
        .DESCRIPTION
        This function allows you to set various user settings for Azure AD.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER UsersCanRegisterApps
        Specifies whether users can register apps.
        .PARAMETER RestrictNonAdminUsers
        Specifies whether to restrict non-admin users.
        .PARAMETER LinkedInAccountConnection
        Specifies whether to enable LinkedIn account connection.
        .PARAMETER LinkedInSelectedGroupObjectId
        The object ID of the selected LinkedIn group.
        .PARAMETER LinkedInSelectedGroupDisplayName
        The display name of the selected LinkedIn group.
        .EXAMPLE
        Set-O365UserSettings -RestrictNonAdminUsers $true -LinkedInAccountConnection $true -LinkedInSelectedGroupObjectId 'b6cdb9c3-d660-4558-bcfd-82c14a986b56'
        .EXAMPLE
        Set-O365UserSettings -RestrictNonAdminUsers $true -LinkedInAccountConnection $true -LinkedInSelectedGroupDisplayName 'All Users'
        .EXAMPLE
        Set-O365UserSettings -RestrictNonAdminUsers $true -LinkedInAccountConnection $false
        .EXAMPLE
        Set-O365UserSettings -RestrictNonAdminUsers $true
        .NOTES
        For more information, visit: https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/UserSettings
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$UsersCanRegisterApps,
        [System.Nullable[bool]]$RestrictNonAdminUsers,
        [System.Nullable[bool]]$LinkedInAccountConnection,
        [string]$LinkedInSelectedGroupObjectId,
        [string]$LinkedInSelectedGroupDisplayName
    )
    $Uri  = "https://main.iam.ad.ext.azure.com/api/Directories/PropertiesV2"

    $Body = @{
        usersCanRegisterApps  = $UsersCanRegisterApps
        restrictNonAdminUsers = $RestrictNonAdminUsers
    }
    Remove-EmptyValue -Hashtable $Body

    If ($null -ne $LinkedInAccountConnection) {
        If ($LinkedInAccountConnection -eq $true -and $linkedInSelectedGroupObjectId) {
            $Body.enableLinkedInAppFamily = 4
            $Body.linkedInSelectedGroupObjectId = $linkedInSelectedGroupObjectId
        } ElseIf ($LinkedInAccountConnection -eq $true -and $LinkedInSelectedGroupDisplayName) {
            $Body.enableLinkedInAppFamily = 4
            $Body.linkedInSelectedGroupDisplayName = $LinkedInSelectedGroupDisplayName
        } ElseIf ($LinkedInAccountConnection -eq $true) {
            $Body.enableLinkedInAppFamily = 0
            $Body.linkedInSelectedGroupObjectId = $null
        } ElseIf ($LinkedInAccountConnection -eq $false) {
            $Body.enableLinkedInAppFamily = 1
            $Body.linkedInSelectedGroupObjectId = $null
        }
    }
    If ($Body.Keys.Count -gt 0) {
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body
        # $Output
    }
} ###

Function Set-O365BillingNotifications {
    <#
        .SYNOPSIS
        Sets settings for Billing notifications, allowing control over Invoice PDF delivery.
        .DESCRIPTION
        This function configures the settings for Billing notifications, enabling the user to specify whether to receive Invoice PDFs.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER SendInvoiceEmails
        Specifies whether to send Invoice emails. This parameter is mandatory.
        .EXAMPLE
        Set-O365BillingNotifications -Headers $headers -SendInvoiceEmails $true
        .NOTES
        For more information on Billing notifications settings, visit: https://admin.microsoft.com/#/BillingNotifications
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$SendInvoiceEmails
    )
    $Uri = "https://admin.microsoft.com/fd/commerceMgmt/mgmtsettings/invoicePreference?api-version=1.0"

    $Body = @{
        sendInvoiceEmails = $SendInvoiceEmails
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    if ($Output.setInvoicePreferenceSuccessful -eq $true) {

    }
} ###

Function Set-O365GroupLicenses {
    <#
        .SYNOPSIS
        Sets Office 365 group licenses based on provided parameters.
        .DESCRIPTION
        This function assigns or removes licenses for an Office 365 group based on the provided parameters.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER GroupID
        The ID of the Office 365 group to assign licenses to.
        .PARAMETER GroupDisplayName
        The display name of the Office 365 group to assign licenses to.
        .PARAMETER Licenses
        An array of licenses to assign to the group.
        .EXAMPLE
        Set-O365GroupLicenses -Headers $headers -GroupID "12345" -Licenses @($License1, $License2)
        .NOTES
        For more information, visit: https://docs.microsoft.com/en-us/office365/enterprise/office-365-service-descriptions
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()]
        [string]$GroupID,
        [Parameter()]
        [Alias('GroupName')]
        [string]$GroupDisplayName,
        [Array]$Licenses
    )
    $Uri = "https://main.iam.ad.ext.azure.com/api/AccountSkus/assignUpdateRemove"

    If ($GroupID) {
        $Group = $GroupID
        #$GroupSearch = Get-O365Group -Id $GroupID
        #if ($GroupSearch.id) {
        # $GroupName = $GroupSearch.displayName
        #}
    } ElseIf ($GroupDisplayName) {
        $GroupSearch = Get-O365Group -DisplayName $GroupDisplayName
        If ($GroupSearch.id) {
            $Group = $GroupSearch.id
            #$GroupName = $GroupSearch.displayName
        }
    }
    If ($Group) {
        $CurrentLicenses = Get-O365GroupLicenses -GroupID $Group -NoTranslation
        If ($CurrentLicenses.objectid) {
            # we cache it for better use of search
            $CacheLicenses = [ordered]@{}
            ForEach ($License in $CurrentLicenses.licenses) {
                $CacheLicenses[$License.accountSkuId] = $License
            }

            <#
            accountSkuId disabledServicePlans hasErrors errorCount
            ------------ -------------------- --------- ----------
            evotecpoland:FLOW_FREE {} 0
            evotecpoland:POWER_BI_STANDARD {} 0
            evotecpoland:POWER_BI_PRO {} 0
            evotecpoland:ENTERPRISEPACK {POWER_VIRTUAL_AGENTS_O365_P2, PROJECT_O365_P2} 0
            #>
            $AddLicenses    = [System.Collections.Generic.List[System.Collections.IDictionary]]::new()
            $RemoveLicenses = [System.Collections.Generic.List[string]]::new()
            $UpdateLicenses = [System.Collections.Generic.List[System.Collections.IDictionary]]::new()

            ForEach ($License in $Licenses) {
                If ($CacheLicenses[$License.accountSkuId]) {
                    If (-not (Compare-Object -ReferenceObject $License.disabledServicePlans -DifferenceObject $CacheLicenses[$License.accountSkuId].disabledServicePlans)) {
                        # We do nothing, because the licenses have the same disabled service plans are the same
                    } Else {
                        $UpdateLicenses.Add($License)
                    }
                } Else {
                    $AddLicenses.Add($License)
                }
            }
            ForEach ($License in $CurrentLicenses.licenses) {
                If ($License.accountSkuId -notin $Licenses.accountSkuId) {
                    #$PrepareForRemoval = New-O365License -DisabledServicesName $License.disabledServicePlans -LicenseSKUID $License.accountSkuId
                    #if ($PrepareForRemoval) {
                    $RemoveLicenses.Add($License.accountSkuId)
                    #}
                }
            }

            $Body = [ordered]@{
                assignments = @(
                    [ordered]@{
                        objectId       = $Group
                        #displayName = $GroupName
                        isUser         = $false
                        addLicenses    = $AddLicenses
                        removeLicenses = $RemoveLicenses
                        updateLicenses = $UpdateLicenses
                    }
                )
            }
            $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
            $Output

        } Else {
            Write-Warning -Message "Set-O365GroupLicenses - Querying for current group licenses failed. Skipping."
        }
    } Else {
        Write-Error -Message "Set-O365GroupLicenses - Couldn't find group. Skipping."
    }
} ###

Function Set-O365OrgAzureSpeechServices {
    <#
        .SYNOPSIS
        Provides functionality to enable or disable the organization-wide language model for Azure Speech Services.
        .DESCRIPTION
        This function allows enabling or disabling the organization-wide language model for Azure Speech Services.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER AllowTheOrganizationWideLanguageModel
        Specifies whether to enable or disable the organization-wide language model.
        .EXAMPLE
        Set-O365OrgAzureSpeechServices -Headers $headers -AllowTheOrganizationWideLanguageModel $true
        .NOTES
        For more information, visit: https://admin.microsoft.com/admin/api/services/apps/azurespeechservices
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [bool]$AllowTheOrganizationWideLanguageModel
    )
    $Uri = "https://admin.microsoft.com/admin/api/services/apps/azurespeechservices"

    $Body = @{
        isTenantEnabled = $AllowTheOrganizationWideLanguageModel
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgBingDataCollection {
    <#
        .SYNOPSIS
        Provides functionality to set consent for Bing data collection in the organization.
        .DESCRIPTION
        This function allows setting consent for Bing data collection in the organization.
        .PARAMETER Headers
        A dictionary containing the necessary headers for the API request, typically including authorization information.
        .PARAMETER IsBingDataCollectionConsented
        Specifies whether Bing data collection is consented or not.
        .EXAMPLE
        Set-O365OrgBingDataCollection -Headers $headers -IsBingDataCollectionConsented $true
        .NOTES
        For more information, visit: https://admin.microsoft.com/admin/api/settings/security/bingdatacollection
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$IsBingDataCollectionConsented
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/security/bingdatacollection"

    $Body = [ordered] @{
        IsBingDataCollectionConsented = $IsBingDataCollectionConsented
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgBookings {
    <#
        .SYNOPSIS
        Set various settings for the Bookings app in the organization.
        .DESCRIPTION
        This function allows setting various configurations for the Bookings app in the organization.
        .PARAMETER Headers
        Authentication token and additional information created with Connect-O365Admin.
        .PARAMETER Enabled
        Enables or disables the Bookings app.
        .PARAMETER ShowPaymentsToggle
        Shows or hides the payments toggle in the Bookings app.
        .PARAMETER PaymentsEnabled
        Enables or disables payments in the Bookings app.
        .PARAMETER ShowSocialSharingToggle
        Shows or hides the social sharing toggle in the Bookings app.
        .PARAMETER SocialSharingRestricted
        Restricts social sharing in the Bookings app.
        .PARAMETER ShowBookingsAddressEntryRestrictedToggle
        Shows or hides the address entry restriction toggle in the Bookings app.
        .PARAMETER BookingsAddressEntryRestricted
        Restricts address entry in the Bookings app.
        .PARAMETER ShowBookingsAuthEnabledToggle
        Shows or hides the authentication enabled toggle in the Bookings app.
        .PARAMETER BookingsAuthEnabled
        Enables or disables authentication in the Bookings app.
        .PARAMETER ShowBookingsCreationOfCustomQuestionsRestrictedToggle
        Shows or hides the custom questions creation restriction toggle in the Bookings app.
        .PARAMETER BookingsCreationOfCustomQuestionsRestricted
        Restricts custom questions creation in the Bookings app.
        .PARAMETER ShowBookingsExposureOfStaffDetailsRestrictedToggle
        Shows or hides the staff details exposure restriction toggle in the Bookings app.
        .PARAMETER BookingsExposureOfStaffDetailsRestricted
        Restricts staff details exposure in the Bookings app.
        .PARAMETER ShowBookingsNotesEntryRestrictedToggle
        Shows or hides the notes entry restriction toggle in the Bookings app.
        .PARAMETER BookingsNotesEntryRestricted
        Restricts notes entry in the Bookings app.
        .PARAMETER ShowBookingsPhoneNumberEntryRestrictedToggle
        Shows or hides the phone number entry restriction toggle in the Bookings app.
        .PARAMETER BookingsPhoneNumberEntryRestricted
        Restricts phone number entry in the Bookings app.
        .PARAMETER ShowStaffApprovalsToggle
        Shows or hides the staff approvals toggle in the Bookings app.
        .PARAMETER StaffMembershipApprovalRequired
        Requires staff membership approval in the Bookings app.
        .EXAMPLE
        Set-O365OrgBookings -Headers $headers -Enabled $true -ShowPaymentsToggle $false -PaymentsEnabled $false
        .NOTES
        This function allows granular control over various settings in the Bookings app.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$Enabled,
        [System.Nullable[bool]]$ShowPaymentsToggle,
        [System.Nullable[bool]]$PaymentsEnabled,
        [System.Nullable[bool]]$ShowSocialSharingToggle,
        [System.Nullable[bool]]$SocialSharingRestricted,
        [System.Nullable[bool]]$ShowBookingsAddressEntryRestrictedToggle,
        [System.Nullable[bool]]$BookingsAddressEntryRestricted,
        [System.Nullable[bool]]$ShowBookingsAuthEnabledToggle,
        [System.Nullable[bool]]$BookingsAuthEnabled,
        [System.Nullable[bool]]$ShowBookingsCreationOfCustomQuestionsRestrictedToggle,
        [System.Nullable[bool]]$BookingsCreationOfCustomQuestionsRestricted,
        [System.Nullable[bool]]$ShowBookingsExposureOfStaffDetailsRestrictedToggle,
        [System.Nullable[bool]]$BookingsExposureOfStaffDetailsRestricted,
        [System.Nullable[bool]]$ShowBookingsNotesEntryRestrictedToggle,
        [System.Nullable[bool]]$BookingsNotesEntryRestricted,
        [System.Nullable[bool]]$ShowBookingsPhoneNumberEntryRestrictedToggle,
        [System.Nullable[bool]]$BookingsPhoneNumberEntryRestricted,
        [System.Nullable[bool]]$ShowStaffApprovalsToggle,
        [System.Nullable[bool]]$StaffMembershipApprovalRequired
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/bookings"

    $CurrentSettings = Get-O365OrgBookings -Headers $Headers
    If ($CurrentSettings) {
        $Body = @{
            Enabled                                               = $CurrentSettings.Enabled                                               #: True
            ShowPaymentsToggle                                    = $CurrentSettings.ShowPaymentsToggle                                    #: False
            PaymentsEnabled                                       = $CurrentSettings.PaymentsEnabled                                       #: False
            ShowSocialSharingToggle                               = $CurrentSettings.ShowSocialSharingToggle                               #: True
            SocialSharingRestricted                               = $CurrentSettings.SocialSharingRestricted                               #: False
            ShowBookingsAddressEntryRestrictedToggle              = $CurrentSettings.ShowBookingsAddressEntryRestrictedToggle              #: False
            BookingsAddressEntryRestricted                        = $CurrentSettings.BookingsAddressEntryRestricted                        #: False
            ShowBookingsAuthEnabledToggle                         = $CurrentSettings.ShowBookingsAuthEnabledToggle                         #: False
            BookingsAuthEnabled                                   = $CurrentSettings.BookingsAuthEnabled                                   #: False
            ShowBookingsCreationOfCustomQuestionsRestrictedToggle = $CurrentSettings.ShowBookingsCreationOfCustomQuestionsRestrictedToggle #: False
            BookingsCreationOfCustomQuestionsRestricted           = $CurrentSettings.BookingsCreationOfCustomQuestionsRestricted           #: False
            ShowBookingsExposureOfStaffDetailsRestrictedToggle    = $CurrentSettings.ShowBookingsExposureOfStaffDetailsRestrictedToggle    #: False
            BookingsExposureOfStaffDetailsRestricted              = $CurrentSettings.BookingsExposureOfStaffDetailsRestricted              #: False
            ShowBookingsNotesEntryRestrictedToggle                = $CurrentSettings.ShowBookingsNotesEntryRestrictedToggle                #: False
            BookingsNotesEntryRestricted                          = $CurrentSettings.BookingsNotesEntryRestricted                          #: False
            ShowBookingsPhoneNumberEntryRestrictedToggle          = $CurrentSettings.ShowBookingsPhoneNumberEntryRestrictedToggle          #: False
            BookingsPhoneNumberEntryRestricted                    = $CurrentSettings.BookingsPhoneNumberEntryRestricted                    #: False
            ShowStaffApprovalsToggle                              = $CurrentSettings.ShowStaffApprovalsToggle                              #: True
            StaffMembershipApprovalRequired                       = $CurrentSettings.StaffMembershipApprovalRequired                       #: False
        }

        If ($null -ne $Enabled) {
            $Body.Enabled = $Enabled
        }
        If ($null -ne $ShowPaymentsToggle) {
            $Body.ShowPaymentsToggle = $ShowPaymentsToggle
        }
        If ($null -ne $PaymentsEnabled) {
            $Body.PaymentsEnabled = $PaymentsEnabled
        }
        If ($null -ne $ShowSocialSharingToggle) {
            $Body.ShowSocialSharingToggle = $ShowSocialSharingToggle
        }
        If ($null -ne $SocialSharingRestricted) {
            $Body.SocialSharingRestricted = $SocialSharingRestricted
        }
        If ($null -ne $ShowBookingsAddressEntryRestrictedToggle) {
            $Body.ShowBookingsAddressEntryRestrictedToggle = $ShowBookingsAddressEntryRestrictedToggle
        }
        If ($null -ne $BookingsAddressEntryRestricted) {
            $Body.BookingsAddressEntryRestricted = $BookingsAddressEntryRestricted
        }
        If ($null -ne $ShowBookingsAuthEnabledToggle) {
            $Body.ShowBookingsAuthEnabledToggle = $ShowBookingsAuthEnabledToggle
        }
        If ($null -ne $BookingsAuthEnabled) {
            $Body.BookingsAuthEnabled = $BookingsAuthEnabled
        }
        If ($null -ne $ShowBookingsCreationOfCustomQuestionsRestrictedToggle) {
            $Body.ShowBookingsCreationOfCustomQuestionsRestrictedToggle = $ShowBookingsCreationOfCustomQuestionsRestrictedToggle
        }
        If ($null -ne $BookingsCreationOfCustomQuestionsRestricted) {
            $Body.BookingsCreationOfCustomQuestionsRestricted = $BookingsCreationOfCustomQuestionsRestricted
        }
        If ($null -ne $ShowBookingsExposureOfStaffDetailsRestrictedToggle) {
            $Body.ShowBookingsExposureOfStaffDetailsRestrictedToggle = $ShowBookingsExposureOfStaffDetailsRestrictedToggle
        }
        If ($null -ne $BookingsExposureOfStaffDetailsRestricted) {
            $Body.BookingsExposureOfStaffDetailsRestricted = $BookingsExposureOfStaffDetailsRestricted
        }
        If ($null -ne $ShowBookingsNotesEntryRestrictedToggle) {
            $Body.ShowBookingsNotesEntryRestrictedToggle = $ShowBookingsNotesEntryRestrictedToggle
        }
        If ($null -ne $BookingsNotesEntryRestricted) {
            $Body.BookingsNotesEntryRestricted = $BookingsNotesEntryRestricted
        }
        If ($null -ne $ShowBookingsPhoneNumberEntryRestrictedToggle) {
            $Body.ShowBookingsPhoneNumberEntryRestrictedToggle = $ShowBookingsPhoneNumberEntryRestrictedToggle
        }
        If ($null -ne $BookingsPhoneNumberEntryRestricted) {
            $Body.BookingsPhoneNumberEntryRestricted = $BookingsPhoneNumberEntryRestricted
        }
        If ($null -ne $ShowStaffApprovalsToggle) {
            $Body.ShowStaffApprovalsToggle = $ShowStaffApprovalsToggle
        }
        If ($null -ne $StaffMembershipApprovalRequired) {
            $Body.StaffMembershipApprovalRequired = $StaffMembershipApprovalRequired
        }
        Remove-EmptyValue -Hashtable $Body
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
        $Output
    }
} ###

Function Set-O365OrgBriefingEmail {
    <#
        .SYNOPSIS
        Let people in your organization receive Briefing Email
        .DESCRIPTION
        Let people in your organization receive Briefing Email
        .PARAMETER Headers
        Parameter description
        .PARAMETER SubscribeByDefault
        Subscribes or unsubscribes people in your organization to receive Briefing Email
        .EXAMPLE
        An example
        .NOTES
        Users will receive Briefing email by default, but can unsubscribe at any time from their Briefing email or Briefing settings page. Email is only sent to users if their Office 365 language is English or Spanish.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        #[bool]$MailEnable,
        [bool]$SubscribeByDefault
    )
    $Uri  = "https://admin.microsoft.com/admin/api/services/apps/briefingemail"

    $Body = @{
        value = @{
            IsSubscribedByDefault = $SubscribeByDefault
        }
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
}

Function Set-O365OrgCalendarSharing {
    <#
        .SYNOPSIS
        Let your users share their calendars with people outside of your organization who have Office 365 or Exchange
        .DESCRIPTION
        Let your users share their calendars with people outside of your organization who have Office 365 or Exchange
        .PARAMETER Headers
        Authentication Token along with additional information that is created with Connect-O365Admin. If heaaders are not provided it will use the default token.
        .PARAMETER EnableAnonymousCalendarSharing
        Enables or Disables anonymous calendar sharing
        .PARAMETER EnableCalendarSharing
        Enables or Disables calendar sharing
        .PARAMETER SharingOption
        Decide on how to share the calendar
            - Show calendar free/busy information with time only (CalendarSharingFreeBusySimple)
            - Show calendar free/busy information with time, subject and location (CalendarSharingFreeBusyDetail)
            - Show all calendar appointment information (CalendarSharingFreeBusyReviewer)
        .EXAMPLE
        Set-O365CalendarSharing -EnableCalendarSharing $false
        .NOTES
        General notes
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$EnableAnonymousCalendarSharing,
        [System.Nullable[bool]]$EnableCalendarSharing,
        [ValidateSet('CalendarSharingFreeBusyDetail', 'CalendarSharingFreeBusySimple', 'CalendarSharingFreeBusyReviewer')]
        [string]$SharingOption
    )
    # We need to get current settings because it always requires all parameters
    # If we would just provide one parameter it would reset everything else
    $CurrentSettings = Get-O365OrgCalendarSharing -Headers $Headers
    $Body = [ordered]@{
        ContractIdentity               = $CurrentSettings.ContractIdentity
        EnableAnonymousCalendarSharing = $CurrentSettings.EnableAnonymousCalendarSharing
        EnableCalendarSharing          = $CurrentSettings.EnableCalendarSharing
        SharingOption                  = $CurrentSettings.SharingOption
    }
    If ($null -ne $EnableAnonymousCalendarSharing) {
        $Body.EnableAnonymousCalendarSharing = $EnableAnonymousCalendarSharing
    }
    If ($null -ne $EnableCalendarSharing) {
        $Body.EnableCalendarSharing = $EnableCalendarSharing
    }
    If ($SharingOption) {
        $Body.SharingOption = $SharingOption
    }
    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/calendarsharing"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgCommunicationToUsers {
    <#
        .SYNOPSIS
        Configures the communication settings for end users in an Office 365 organization.
        .DESCRIPTION
        This function allows you to enable or disable communication services for end users in your Office 365 organization.
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER ServiceEnabled
        Specifies whether the communication service should be enabled for end users.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgCommunicationToUsers -Headers $headers -ServiceEnabled $true

        This example enables the communication service for end users in the Office 365 organization.
        .NOTES
        This function sends a POST request to the Office 365 admin API with the specified settings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$ServiceEnabled
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/apps/EndUserCommunications"

    $Body = @{
        ServiceEnabled = $ServiceEnabled
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body #-WhatIf:$WhatIfPreference.IsPresent
    $Output
} ###

Function Set-O365OrgCortana {
    <#
        .SYNOPSIS
        Configures the Cortana settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to enable or disable the Cortana service for your Office 365 organization.
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER Enabled
        Specifies whether the Cortana service should be enabled.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgCortana -Headers $headers -Enabled $true

        This example enables the Cortana service for the Office 365 organization.
        .NOTES
        This function sends a POST request to the Office 365 admin API with the specified settings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$Enabled
    )
    $Uri  = "https://admin.microsoft.com/admin/api/services/apps/cortana"

    $Body = @{
        Enabled = $Enabled
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgCustomerLockbox {
    <#
        .SYNOPSIS
        Configures the Customer Lockbox settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to enable or disable the Customer Lockbox feature for your Office 365 organization.
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER RequireApproval
        Specifies whether Customer Lockbox should require approval.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgCustomerLockbox -Headers $headers -RequireApproval $true

        This example enables the Customer Lockbox feature for the Office 365 organization.
        .NOTES
        This function sends a POST request to the Office 365 admin API with the specified settings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$RequireApproval
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/security/dataaccess"
    $Body = @{
        RequireApproval = $RequireApproval
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgDynamics365ConnectionGraph {
    <#
        .SYNOPSIS
        Configures the Dynamics 365 Connection Graph settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to enable or disable the Dynamics 365 Connection Graph service for your Office 365 organization.
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER ServiceEnabled
        Specifies whether the Dynamics 365 Connection Graph service should be enabled.
        .PARAMETER ConnectionGraphUsersExclusionGroup
        Specifies the group of users to be excluded from the Connection Graph.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgDynamics365ConnectionGraph -Headers $headers -ServiceEnabled $true -ConnectionGraphUsersExclusionGroup "GroupID"

        This example enables the Dynamics 365 Connection Graph service for the Office 365 organization and excludes the specified group of users.
        .NOTES
        This function sends a POST request to the Office 365 admin API with the specified settings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$ServiceEnabled,
        [string]$ConnectionGraphUsersExclusionGroup
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/apps/dcg"

    $Body = @{
        ServiceEnabled                     = $ServiceEnabled
        ConnectionGraphUsersExclusionGroup = $ConnectionGraphUsersExclusionGroup
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgDynamics365SalesInsights {
    <#
        .SYNOPSIS
        Configures the Dynamics 365 Sales Insights settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to enable or disable the Dynamics 365 Sales Insights service for your Office 365 organization. 
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER ServiceEnabled
        Specifies whether the Dynamics 365 Sales Insights service should be enabled.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgDynamics365SalesInsights -Headers $headers -ServiceEnabled $true

        This example enables the Dynamics 365 Sales Insights service for the Office 365 organization.
        .NOTES
        This function sends a POST request to the Office 365 admin API with the specified settings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$ServiceEnabled
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/apps/dci"

    $Body = @{
        ServiceEnabled = $ServiceEnabled
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgForms {
    <#
        .SYNOPSIS
        Configures the settings for Office 365 Forms.
        .DESCRIPTION
        This function allows you to configure various settings for Office 365 Forms. It retrieves the current settings, updates them based on the provided parameters, and then sends the updated settings back to the Office 365 admin API.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER BingImageSearchEnabled
        Specifies whether Bing Image Search should be enabled in Office 365 Forms.
        .PARAMETER ExternalCollaborationEnabled
        Specifies whether external collaboration should be enabled in Office 365 Forms.
        .PARAMETER ExternalSendFormEnabled
        Specifies whether sending forms externally should be enabled in Office 365 Forms.
        .PARAMETER ExternalShareCollaborationEnabled
        Specifies whether external share collaboration should be enabled in Office 365 Forms.
        .PARAMETER ExternalShareTemplateEnabled
        Specifies whether external share template should be enabled in Office 365 Forms.
        .PARAMETER ExternalShareResultEnabled
        Specifies whether external share result should be enabled in Office 365 Forms.
        .PARAMETER InOrgFormsPhishingScanEnabled
        Specifies whether phishing scan for in-organization forms should be enabled in Office 365 Forms.
        .PARAMETER InOrgSurveyIncentiveEnabled
        Specifies whether survey incentive for in-organization forms should be enabled in Office 365 Forms.
        .PARAMETER RecordIdentityByDefaultEnabled
        Specifies whether recording identity by default should be enabled in Office 365 Forms.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgForms -Headers $headers -BingImageSearchEnabled $true -ExternalCollaborationEnabled $false

        This example enables Bing Image Search and disables external collaboration in Office 365 Forms.
        .NOTES
        This function sends a POST request to the Office 365 admin API with the specified settings. It retrieves the current settings, updates them based on the provided parameters, and then sends the updated settings back to the API.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$BingImageSearchEnabled,
        [System.Nullable[bool]]$ExternalCollaborationEnabled,
        [System.Nullable[bool]]$ExternalSendFormEnabled,
        [System.Nullable[bool]]$ExternalShareCollaborationEnabled,
        [System.Nullable[bool]]$ExternalShareTemplateEnabled,
        [System.Nullable[bool]]$ExternalShareResultEnabled,
        [System.Nullable[bool]]$InOrgFormsPhishingScanEnabled,
        [System.Nullable[bool]]$InOrgSurveyIncentiveEnabled,
        [System.Nullable[bool]]$RecordIdentityByDefaultEnabled
    )
    # We need to get current settings because it always requires all parameters
    # If we would just provide one parameter it would reset everything else
    $CurrentSettings = Get-O365OrgForms -Headers $Headers
    $Body = [ordered]@{
        BingImageSearchEnabled            = $CurrentSettings.BingImageSearchEnabled
        ExternalCollaborationEnabled      = $CurrentSettings.ExternalCollaborationEnabled
        ExternalSendFormEnabled           = $CurrentSettings.ExternalSendFormEnabled
        ExternalShareCollaborationEnabled = $CurrentSettings.ExternalShareCollaborationEnabled
        ExternalShareTemplateEnabled      = $CurrentSettings.ExternalShareTemplateEnabled
        ExternalShareResultEnabled        = $CurrentSettings.ExternalShareResultEnabled
        InOrgFormsPhishingScanEnabled     = $CurrentSettings.InOrgFormsPhishingScanEnabled
        InOrgSurveyIncentiveEnabled       = $CurrentSettings.InOrgSurveyIncentiveEnabled
        RecordIdentityByDefaultEnabled    = $CurrentSettings.RecordIdentityByDefaultEnabled
    }
    If ($null -ne $BingImageSearchEnabled) {
        $Body.BingImageSearchEnabled = $BingImageSearchEnabled
    }
    If ($null -ne $ExternalCollaborationEnabled) {
        $Body.ExternalCollaborationEnabled = $ExternalCollaborationEnabled
    }
    If ($null -ne $ExternalSendFormEnabled) {
        $Body.ExternalSendFormEnabled = $ExternalSendFormEnabled
    }
    If ($null -ne $ExternalShareCollaborationEnabled) {
        $Body.ExternalShareCollaborationEnabled = $ExternalShareCollaborationEnabled
    }
    If ($null -ne $ExternalShareTemplateEnabled) {
        $Body.ExternalShareTemplateEnabled = $ExternalShareTemplateEnabled
    }
    If ($null -ne $ExternalShareResultEnabled) {
        $Body.ExternalShareResultEnabled = $ExternalShareResultEnabled
    }
    If ($null -ne $InOrgFormsPhishingScanEnabled) {
        $Body.InOrgFormsPhishingScanEnabled = $InOrgFormsPhishingScanEnabled
    }
    If ($null -ne $InOrgSurveyIncentiveEnabled) {
        $Body.InOrgSurveyIncentiveEnabled = $InOrgSurveyIncentiveEnabled
    }
    If ($null -ne $RecordIdentityByDefaultEnabled) {
        $Body.RecordIdentityByDefaultEnabled = $RecordIdentityByDefaultEnabled
    }

    $Uri    = "https://admin.microsoft.com/admin/api/settings/apps/officeforms"
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgGraphDataConnect {
    <#
    .SYNOPSIS
    Configures the settings for Office 365 Organizational Graph Data Connect.
    .DESCRIPTION
    This function allows you to configure the settings for Office 365 Organizational Graph Data Connect. 
    It sends a POST request to the Office 365 admin API with the specified settings.
    .PARAMETER Headers
    Specifies the headers for the API request. Typically includes authorization tokens.
    .PARAMETER ServiceEnabled
    Specifies whether the Organizational Graph Data Connect service should be enabled or disabled.
    .PARAMETER TenantLockBoxApproverGroup
    Specifies the email address of the group that will act as the Tenant LockBox approver. The email address must exist; otherwise, the API will break the cmdlet.
    .PARAMETER Force
    Forces the operation to run, ignoring current settings. Useful to overwrite settings after breaking tenant.
    .EXAMPLE
    $headers = @{Authorization = "Bearer your_token"}
    Set-O365OrgGraphDataConnect -Headers $headers -ServiceEnabled $true -TenantLockBoxApproverGroup "approver@example.com" -Force

    This example enables the Organizational Graph Data Connect service, sets the Tenant LockBox approver group to "approver@example.com", and forces the operation to run.
    .NOTES
    Ensure that the TenantLockBoxApproverGroup email address is valid and exists in your organization to avoid errors.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$ServiceEnabled,
        [string]$TenantLockBoxApproverGroup,
        [switch]$Force
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/o365dataplan"

    If ($TenantLockBoxApproverGroup -and $TenantLockBoxApproverGroup -notlike "*@*") {
        Write-Warning -Message "Set-O365OrgGraphDataConnect - TenantLockBoxApproverGroup must be given in email format, and it must exists."
        return
    }

    If (-not $Force) {
        $CurrentSettings = Get-O365OrgGraphDataConnect -Headers $Headers
        If ($CurrentSettings) {
            $Body = @{
                "ServiceEnabled"             = $CurrentSettings.ServiceEnabled
                "TenantLockBoxApproverGroup" = $CurrentSettings.TenantLockBoxApproverGroup
            }

            If ($null -ne $ServiceEnabled) {
                $Body.ServiceEnabled = $ServiceEnabled
            }
            If ($TenantLockBoxApproverGroup) {
                $Body.TenantLockBoxApproverGroup = $TenantLockBoxApproverGroup
            }
        }
    } Else {
        $Body = @{
            "ServiceEnabled"             = $ServiceEnabled
            "TenantLockBoxApproverGroup" = $TenantLockBoxApproverGroup
        }
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgInstallationOptions {
    <#
        .SYNOPSIS
        Configures the installation options for Microsoft Office 365 applications on user devices.
        .DESCRIPTION
        This function allows you to configure how often users receive feature updates and which Microsoft applications they can install on their devices. 
        You can specify the update channel for Windows, and enable or disable the installation of Office and Skype for Business on both Windows and Mac devices.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER WindowsBranch
        Specifies the update channel for Windows. Valid values are 'CurrentChannel', 'MonthlyEnterpriseChannel', and 'SemiAnnualEnterpriseChannel'.
        .PARAMETER WindowsOffice
        Specifies whether the Office suite should be enabled or disabled for Windows devices.
        .PARAMETER WindowsSkypeForBusiness
        Specifies whether Skype for Business should be enabled or disabled for Windows devices.
        .PARAMETER MacOffice
        Specifies whether the Office suite should be enabled or disabled for Mac devices.
        .PARAMETER MacSkypeForBusiness
        Specifies whether Skype for Business should be enabled or disabled for Mac devices.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgInstallationOptions -Headers $headers -WindowsBranch 'CurrentChannel' -WindowsOffice $true -WindowsSkypeForBusiness $false -MacOffice $true -MacSkypeForBusiness $false

        This example sets the update channel for Windows to 'CurrentChannel', enables Office for both Windows and Mac devices, disables Skype for Business for both Windows and Mac devices.
        .NOTES
        It takes a while for GUI to report these changes. Be patient.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [ValidateSet('CurrentChannel', 'MonthlyEnterpriseChannel', 'SemiAnnualEnterpriseChannel')]
        [string]$WindowsBranch,
        [System.Nullable[bool]]$WindowsOffice,
        [System.Nullable[bool]]$WindowsSkypeForBusiness,
        [System.Nullable[bool]]$MacOffice,
        [System.Nullable[bool]]$MacSkypeForBusiness
    )
    $ReverseBranches = @{
        "CurrentChannel"              = 1
        "MonthlyEnterpriseChannel"    = 3
        "SemiAnnualEnterpriseChannel" = 2
    }

    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/usersoftware"

    $CurrentSettings = Get-O365OrgInstallationOptions -NoTranslation -Headers $Headers
    If ($CurrentSettings) {
        $Body = @{
            UserSoftwareSettings = $CurrentSettings
        }

        If ($WindowsBranch) {
            $Body.UserSoftwareSettings[0].Branch = $ReverseBranches[$WindowsBranch]
            # we probably should update "BranchLastUpdateTime": "2021-09-02T21:54:02.953Z",
            # but I am not sure if it matters
        }
        If ($null -ne $WindowsOffice) {
            $Body.UserSoftwareSettings[0].ServiceStatusMap.'Office (includes Skype for Business),MicrosoftOffice_ClientDownload' = $WindowsOffice
        }
        If ($null -ne $WindowsSkypeForBusiness) {
            $Body.UserSoftwareSettings[0].ServiceStatusMap.'Skype for Business (Standalone),MicrosoftCommunicationsOnline' = $WindowsSkypeForBusiness
        }
        If ($null -ne $MacOffice) {
            $Body.UserSoftwareSettings[1].ServiceStatusMap.'Office,MicrosoftOffice_ClientDownload' = $MacOffice
        }
        If ($null -ne $MacSkypeForBusiness) {
            $Body.UserSoftwareSettings[1].LegacyServiceStatusMap.'Skype for Business (X EI Capitan 10.11 or higher),MicrosoftCommunicationsOnline' = $MacSkypeForBusiness
        }
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
        $Output
    }
} ###

Function Set-O365OrgM365Groups {
    <#
        .SYNOPSIS
        Choose how guests from outside your organization can collaborate with your users in Microsoft 365 Groups. Learn more about guest access to Microsoft 365 Groups.
        .DESCRIPTION
        This function allows you to configure how guests from outside your organization can collaborate with your users in Microsoft 365 Groups. You can specify whether to allow guest access and whether to allow guests as members.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER AllowGuestAccess
        Specifies whether to let group owners add people outside your organization to Microsoft 365 Groups as guests.
        .PARAMETER AllowGuestsAsMembers
        Specifies whether to let guest group members access group content.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgM365Groups -Headers $headers -AllowGuestAccess $true -AllowGuestsAsMembers $false

        This example allows group owners to add guests to Microsoft 365 Groups but does not allow guest members to access group content.
        .NOTES
        This function sends a POST request to the Office 365 admin API with the specified settings. It retrieves the current settings, updates them based on the provided parameters, and then sends the updated settings back to the API.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$AllowGuestAccess,
        [System.Nullable[bool]]$AllowGuestsAsMembers
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/security/o365guestuser"

    $CurrentSettings = Get-O365OrgM365Groups -Headers $Headers
    $Body = [ordered] @{
        AllowGuestAccess     = $CurrentSettings.AllowGuestAccess
        AllowGuestsAsMembers = $CurrentSettings.AllowGuestsAsMembers
    }
    If ($null -ne $AllowGuestAccess) {
        $Body.AllowGuestAccess = $AllowGuestAccess
    }
    If ($null -ne $AllowGuestsAsMembers) {
        $Body.AllowGuestsAsMembers = $AllowGuestsAsMembers
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgMicrosoftTeams {
    <#
        .SYNOPSIS
        Configures Microsoft Teams settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to configure the Microsoft Teams settings for your Office 365 organization. 
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER AllowCalendarSharing
        Specifies whether calendar sharing should be allowed in Microsoft Teams.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgMicrosoftTeams -Headers $headers -AllowCalendarSharing $true

        This example enables calendar sharing in Microsoft Teams for the Office 365 organization.
        .NOTES
        https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/SkypeTeams
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$AllowCalendarSharing
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/apps/skypeteams"

    $Body = Get-O365OrgMicrosoftTeams -Headers $Headers

    # It seems every time you check https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/SkypeTeams
    # and you enable just 1 or two settings you need to reapply everything! so i'll
    # leave it for now - as it needs more investigation
    # $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    # $Output
} ###

Function Set-O365OrgModernAuthentication {
    <#
        .SYNOPSIS
        Configures Modern Authentication settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to configure the Modern Authentication settings for your Office 365 organization. 
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER EnableModernAuth
        Specifies whether Modern Authentication should be enabled.
        .PARAMETER SecureDefaults
        Specifies whether Secure Defaults should be enabled.
        .PARAMETER DisableModernAuth
        Specifies whether Modern Authentication should be disabled.
        .PARAMETER AllowBasicAuthActiveSync
        Specifies whether Basic Authentication for ActiveSync should be allowed.
        .PARAMETER AllowBasicAuthImap
        Specifies whether Basic Authentication for IMAP should be allowed.
        .PARAMETER AllowBasicAuthPop
        Specifies whether Basic Authentication for POP should be allowed.
        .PARAMETER AllowBasicAuthWebServices
        Specifies whether Basic Authentication for Web Services should be allowed.
        .PARAMETER AllowBasicAuthPowershell
        Specifies whether Basic Authentication for PowerShell should be allowed.
        .PARAMETER AllowBasicAuthAutodiscover
        Specifies whether Basic Authentication for Autodiscover should be allowed.
        .PARAMETER AllowBasicAuthMapi
        Specifies whether Basic Authentication for MAPI should be allowed.
        .PARAMETER AllowBasicAuthOfflineAddressBook
        Specifies whether Basic Authentication for Offline Address Book should be allowed.
        .PARAMETER AllowBasicAuthRpc
        Specifies whether Basic Authentication for RPC should be allowed.
        .PARAMETER AllowBasicAuthSmtp
        Specifies whether Basic Authentication for SMTP should be allowed.
        .PARAMETER AllowOutlookClient
        Specifies whether Basic Authentication for Outlook Client should be allowed.
        .EXAMPLE
        Set-O365OrgModernAuthentication -AllowBasicAuthImap $true -AllowBasicAuthPop $true -WhatIf

        This example enables Basic Authentication for IMAP and POP, and uses the WhatIf parameter to show what would happen if the command runs.
        .EXAMPLE
        Set-O365OrgModernAuthentication -AllowBasicAuthImap $false -AllowBasicAuthPop $false -Verbose -WhatIf

        This example disables Basic Authentication for IMAP and POP, and uses the Verbose and WhatIf parameters to show detailed information about what would happen if the command runs.
        .NOTES
        https://admin.microsoft.com/#/Settings/Services/:/Settings/L1/ModernAuthentication
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$EnableModernAuth, #: True
        [System.Nullable[bool]]$SecureDefaults, #: False
        [System.Nullable[bool]]$DisableModernAuth, #: False
        [System.Nullable[bool]]$AllowBasicAuthActiveSync, #: True
        [System.Nullable[bool]]$AllowBasicAuthImap, #: True
        [System.Nullable[bool]]$AllowBasicAuthPop, #: True
        [System.Nullable[bool]]$AllowBasicAuthWebServices, #: True
        [System.Nullable[bool]]$AllowBasicAuthPowershell, #: True
        [System.Nullable[bool]]$AllowBasicAuthAutodiscover, #: True
        [System.Nullable[bool]]$AllowBasicAuthMapi, #: True
        [System.Nullable[bool]]$AllowBasicAuthOfflineAddressBook , #: True
        [System.Nullable[bool]]$AllowBasicAuthRpc, #: True
        [System.Nullable[bool]]$AllowBasicAuthSmtp, #: True
        [System.Nullable[bool]]$AllowOutlookClient #:
    )
    $Uri = "https://admin.microsoft.com/admin/api/services/apps/modernAuth"
    $CurrentSettings = Get-O365OrgModernAuthentication -Headers $Headers
    If (-not $CurrentSettings) {
        Write-Warning -Message "Set-O365ModernAuthentication - Couldn't gather current settings. Skipping setting anything."
        return
    }
    $Body = [ordered]@{
        EnableModernAuth                 = $CurrentSettings.EnableModernAuth                 #: True
        SecureDefaults                   = $CurrentSettings.SecureDefaults                   #: False
        DisableModernAuth                = $CurrentSettings.DisableModernAuth                #: False
        AllowBasicAuthActiveSync         = $CurrentSettings.AllowBasicAuthActiveSync         #: True
        AllowBasicAuthImap               = $CurrentSettings.AllowBasicAuthImap               #: False
        AllowBasicAuthPop                = $CurrentSettings.AllowBasicAuthPop                #: False
        AllowBasicAuthWebServices        = $CurrentSettings.AllowBasicAuthWebServices        #: True
        AllowBasicAuthPowershell         = $CurrentSettings.AllowBasicAuthPowershell         #: True
        AllowBasicAuthAutodiscover       = $CurrentSettings.AllowBasicAuthAutodiscover       #: True
        AllowBasicAuthMapi               = $CurrentSettings.AllowBasicAuthMapi               #: True
        AllowBasicAuthOfflineAddressBook = $CurrentSettings.AllowBasicAuthOfflineAddressBook #: True
        AllowBasicAuthRpc                = $CurrentSettings.AllowBasicAuthRpc                #: True
        AllowBasicAuthSmtp               = $CurrentSettings.AllowBasicAuthSmtp               #: True
        AllowOutlookClient               = $CurrentSettings.AllowOutlookClient               #: True
    }
    If ($null -ne $SecureDefaults) {
        $Body.SecureDefaults = $SecureDefaults
    }
    If ($null -ne $EnableModernAuth) {
        $Body.EnableModernAuth = $EnableModernAuth
    }
    If ($null -ne $DisableModernAuth) {
        $Body.DisableModernAuth = $DisableModernAuth
    }
    If ($null -ne $AllowBasicAuthActiveSync) {
        $Body.AllowBasicAuthActiveSync = $AllowBasicAuthActiveSync
    }
    If ($null -ne $AllowBasicAuthImap) {
        $Body.AllowBasicAuthImap = $AllowBasicAuthImap
    }
    If ($null -ne $AllowBasicAuthPop) {
        $Body.AllowBasicAuthPop = $AllowBasicAuthPop
    }
    If ($null -ne $AllowBasicAuthWebServices) {
        $Body.AllowBasicAuthWebServices = $AllowBasicAuthWebServices
    }
    If ($null -ne $AllowBasicAuthPowershell) {
        $Body.AllowBasicAuthPowershell = $AllowBasicAuthPowershell
    }
    If ($null -ne $AllowBasicAuthAutodiscover) {
        $Body.AllowBasicAuthAutodiscover = $AllowBasicAuthAutodiscover
    }
    If ($null -ne $AllowBasicAuthMapi) {
        $Body.AllowBasicAuthMapi = $AllowBasicAuthMapi
    }
    If ($null -ne $AllowBasicAuthOfflineAddressBook) {
        $Body.AllowBasicAuthOfflineAddressBook = $AllowBasicAuthOfflineAddressBook
    }
    If ($null -ne $AllowBasicAuthRpc) {
        $Body.AllowBasicAuthRpc = $AllowBasicAuthRpc
    }
    If ($null -ne $AllowBasicAuthSmtp) {
        $Body.AllowBasicAuthSmtp = $AllowBasicAuthSmtp
    }
    If ($null -ne $AllowOutlookClient) {
        $Body.AllowOutlookClient = $AllowOutlookClient
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgMyAnalytics {
    <#
        .SYNOPSIS
        Configures MyAnalytics settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to configure the MyAnalytics settings for your Office 365 organization. 
        It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER EnableInsightsDashboard
        Specifies whether the Insights Dashboard should be enabled or disabled.
        .PARAMETER EnableWeeklyDigest
        Specifies whether the Weekly Digest emails should be enabled or disabled.
        .PARAMETER EnableInsightsOutlookAddIn
        Specifies whether the Insights Outlook Add-In should be enabled or disabled.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgMyAnalytics -Headers $headers -EnableInsightsDashboard $true -EnableWeeklyDigest $false -EnableInsightsOutlookAddIn $true

        This example enables the Insights Dashboard and the Insights Outlook Add-In, and disables the Weekly Digest emails for the Office 365 organization.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$EnableInsightsDashboard,
        [System.Nullable[bool]]$EnableWeeklyDigest,
        [System.Nullable[bool]]$EnableInsightsOutlookAddIn
    )
    $Uri = "https://admin.microsoft.com/admin/api/services/apps/myanalytics"

    $CurrentSettings = Get-O365OrgMyAnalytics -Headers $Headers
    If ($CurrentSettings) {
        $Body = @{
            value = @{
                IsDashboardOptedOut = $CurrentSettings.EnableInsightsDashboard
                IsEmailOptedOut     = $CurrentSettings.EnableWeeklyDigest
                IsAddInOptedOut     = $CurrentSettings.EnableInsightsOutlookAddIn
            }
        }
        If ($null -ne $EnableInsightsDashboard) {
            $Body.value.IsDashboardOptedOut = -not $EnableInsightsDashboard
        }
        If ($null -ne $EnableWeeklyDigest) {
            $Body.value.IsEmailOptedOut = -not $EnableWeeklyDigest
        }
        If ($null -ne $EnableInsightsOutlookAddIn) {
            $Body.value.IsAddInOptedOut = -not $EnableInsightsOutlookAddIn
        }
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
        $Output
    }
} ###

Function Set-O365OrgNews {
    <#
        .SYNOPSIS
        Configures the news settings for an Office 365 organization.
        .DESCRIPTION
        This function allows you to configure the news settings for your Office 365 organization. It sends a PUT request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER ContentOnNewTabEnabled
        Specifies whether content on the new tab should be enabled or disabled.
        .PARAMETER CompanyInformationAndIndustryEnabled
        Specifies whether company information and industry news should be shown.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgNews -Headers $headers -ContentOnNewTabEnabled $true -CompanyInformationAndIndustryEnabled $false

        This example enables content on the new tab and disables company information and industry news for the Office 365 organization.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$ContentOnNewTabEnabled,
        [System.Nullable[bool]]$CompanyInformationAndIndustryEnabled
    )
    $Uri = "https://admin.microsoft.com/admin/api/searchadminapi/news/options"

    $CurrentSettings = Get-O365OrgNews -Headers $Headers -NoTranslation
    If ($CurrentSettings) {
        $Body = [ordered]@{
            ServiceType = 'Bing'
            NewsOptions = $CurrentSettings.NewsOptions
        }
        If ($null -ne $ContentOnNewTabEnabled) {
            $Body.NewsOptions.EdgeNTPOptions.IsOfficeContentEnabled = $ContentOnNewTabEnabled
        }
        If ($null -ne $CompanyInformationAndIndustryEnabled) {
            $Body.NewsOptions.EdgeNTPOptions.IsShowCompanyAndIndustry = $CompanyInformationAndIndustryEnabled
        }
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body
        $Output
    }
} ###

Function Set-O365OrgOfficeOnTheWeb {
    <#
        .SYNOPSIS
        Enables or disables Office on the web for an Office 365 tenant.
        .DESCRIPTION
        This function allows you to enable or disable the Office on the web feature for your Office 365 organization. It sends a POST request to the Office 365 admin API with the specified settings.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER Enabled
        Specifies whether Office on the web should be enabled or disabled. This parameter is mandatory.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgOfficeOnTheWeb -Headers $headers -Enabled $true

        This example enables Office on the web for the Office 365 organization.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgOfficeOnTheWeb -Headers $headers -Enabled $false

        This example disables Office on the web for the Office 365 organization.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)][bool]$Enabled
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/officeonline"

    $Body = @{
        Enabled = $Enabled
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgOrganizationInformation {
    <#
        .SYNOPSIS
        Updates the organization information for an Office 365 tenant.
        .DESCRIPTION
        This function allows you to update various details about your Office 365 organization, such as the name, address, city, state, postal code, phone number, and technical contact email. It retrieves the current settings and updates only the specified parameters.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER Name
        Specifies the name of the organization.
        .PARAMETER StreetAddress
        Specifies the street address of the organization.
        .PARAMETER ApartmentOrSuite
        Specifies the apartment or suite number of the organization.
        .PARAMETER City
        Specifies the city where the organization is located.
        .PARAMETER State
        Specifies the state where the organization is located.
        .PARAMETER PostalCode
        Specifies the postal code of the organization.
        .PARAMETER PhoneNumber
        Specifies the phone number of the organization.
        .PARAMETER TechnicalContactEmail
        Specifies the technical contact email for the organization.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgOrganizationInformation -Headers $headers -Name "Contoso Ltd." -StreetAddress "123 Main St" -City "Redmond" -State "WA" -PostalCode "98052" -PhoneNumber "123-456-7890" -TechnicalContactEmail "admin@contoso.com"

        This example updates the organization information for Contoso Ltd. with the specified address, city, state, postal code, phone number, and technical contact email.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [string]$Name,
        [string]$StreetAddress,
        [string]$ApartmentOrSuite,
        [string]$City,
        [string]$State,
        [string]$PostalCode,
        #[string]$Country,
        #[string]$CountryCode,
        #[string]$PossibleStatesOrProvinces,
        [string]$PhoneNumber,
        [string]$TechnicalContactEmail
    )
    $Uri = "https://admin.microsoft.com/admin/api/Settings/company/profile"

    $CurrentSettings = Get-O365OrgOrganizationInformation -Headers $Headers
    If ($CurrentSettings) {
        $Body = @{
            Name                  = $CurrentSettings.Name                      ## : Evotec
            Address1              = $CurrentSettings.Address1                  ## :
            Address2              = $CurrentSettings.Address2                  ## :
            #Address3 = $CurrentSettings.Address3 ## :
            #Address4 = $CurrentSettings.Address4 ## :
            City                  = $CurrentSettings.City                      ## : KATOWICE
            State                 = $CurrentSettings.State                     ## : Śląskie
            PostalCode            = $CurrentSettings.PostalCode                ## : 40-
            Country               = $CurrentSettings.Country                   ## : Poland
            #CountryCode = $CurrentSettings.CountryCode ## : PL
            #PossibleStatesOrProvinces = $CurrentSettings.PossibleStatesOrProvinces ## :
            PhoneNumber           = $CurrentSettings.PhoneNumber               ## : +4
            TechnicalContactEmail = $CurrentSettings.TechnicalContactEmail     ## : p
            #DefaultDomain = $CurrentSettings.DefaultDomain ## :
            Language              = $CurrentSettings.Language                  ## : en
            #MSPPID = $CurrentSettings.MSPPID ## :
            #SupportUrl = $CurrentSettings.SupportUrl ## :
            #SupportEmail = $CurrentSettings.SupportEmail ## :
            #SupportPhone = $CurrentSettings.SupportPhone ## :
            SupportedLanguages    = $CurrentSettings.SupportedLanguages        ## : {@{ID=en; Name=English; Default=True; DefaultCulture=en-US; PluralFormRules=IsOne}, @{ID=pl; Name=polski; Default=False; DefaultCulture=pl-PL; PluralFormRules=IsOne,EndsInTwoThruFourNotTweleveThruFourteen}}
        }
        If ($PSBoundParameters.ContainsKey('Name')) {
            $Body.Name = $Name
        }
        If ($PSBoundParameters.ContainsKey('StreetAddress')) {
            $Body.Address1 = $StreetAddress
        }
        If ($PSBoundParameters.ContainsKey('ApartmentOrSuite')) {
            $Body.Address2 = $ApartmentOrSuite
        }
        If ($PSBoundParameters.ContainsKey('City')) {
            $Body.City = $City
        }
        If ($PSBoundParameters.ContainsKey('State')) {
            $Body.State = $State
        }
        If ($PSBoundParameters.ContainsKey('PostalCode')) {
            $Body.PostalCode = $PostalCode
        }
        #if ($PSBoundParameters.ContainsKey('Country')) {
        # $Body.Country = $Country
        #}
        #if ($PSBoundParameters.ContainsKey('CountryCode')) {
        # $Body.CountryCode = $CountryCode
        #}
        If ($PSBoundParameters.ContainsKey('PhoneNumber')) {
            $Body.PhoneNumber = $PhoneNumber
        }
        If ($PSBoundParameters.ContainsKey('TechnicalContactEmail')) {
            $Body.TechnicalContactEmail = $TechnicalContactEmail
        }

        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
        $Output
    }
} ###

Function Set-O365OrgPasswordExpirationPolicy {
    <#
        .SYNOPSIS
        Configures the password expiration policy for an Office 365 organization.
        .DESCRIPTION
        This function updates the password expiration policy settings for an Office 365 organization. It allows specifying whether passwords never expire, the number of days before passwords expire, and the number of days before users are notified of password expiration.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER PasswordNeverExpires
        Specifies whether passwords should never expire. Accepts a nullable boolean value.
        .PARAMETER DaysBeforePasswordExpires
        Specifies the number of days before passwords expire. Accepts a nullable integer value.
        .PARAMETER DaysBeforeUserNotified
        Specifies the number of days before users are notified of password expiration. Accepts a nullable integer value.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgPasswordExpirationPolicy -Headers $headers -PasswordNeverExpires $true -DaysBeforePasswordExpires 90 -DaysBeforeUserNotified 14

        This example sets the password expiration policy to never expire passwords, with a notification period of 14 days before expiration.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()]
        [nullable[bool]]$PasswordNeverExpires,
        [Parameter()]
        [nullable[int]]$DaysBeforePasswordExpires,
        [Parameter()]
        [nullable[int]]$DaysBeforeUserNotified
    )
    $Uri = "https://admin.microsoft.com/admin/api/Settings/security/passwordpolicy"

    $CurrentSettings = Get-O365OrgPasswordExpirationPolicy -Headers $Headers -NoTranslation
    If ($CurrentSettings) {
        $Body = @{
            ValidityPeriod   = $CurrentSettings.ValidityPeriod   #: 90
            NotificationDays = $CurrentSettings.NotificationDays #: 14
            NeverExpire      = $CurrentSettings.NeverExpire      #: True
        }
        If ($null -ne $DaysBeforeUserNotified) {
            $Body.NotificationDays = $DaysBeforeUserNotified
        }
        If ($null -ne $DaysBeforePasswordExpires) {
            $Body.ValidityPeriod = $DaysBeforePasswordExpires
        }
        If ($null -ne $PasswordNeverExpires) {
            $Body.NeverExpire = $PasswordNeverExpires
        }
        $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    }
} ###

Function Set-O365OrgPlanner {
    <#
        .SYNOPSIS
        Configures the Planner settings for an Office 365 organization.
        .DESCRIPTION
        This function updates the Planner settings for an Office 365 organization. It allows enabling or disabling calendar sharing within Planner.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER AllowCalendarSharing
        Specifies whether calendar sharing should be allowed in Planner. Accepts a boolean value.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgPlanner -Headers $headers -AllowCalendarSharing $true

        This example enables calendar sharing in Planner.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$AllowCalendarSharing
    )
    $Uri = "https://admin.microsoft.com/admin/api/services/apps/planner"

    $Body = @{
        allowCalendarSharing = $AllowCalendarSharing
        id                   = "1"
        isPlannerAllowed     = $true
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgPrivacyProfile {
    <#
        .SYNOPSIS
        Configures the privacy profile settings for an Office 365 organization.
        .DESCRIPTION
        This function updates the privacy profile settings for an Office 365 organization. It allows specifying the privacy statement URL and the privacy contact information.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER PrivacyUrl
        Specifies the URL of the privacy statement. Accepts a URI value.
        .PARAMETER PrivacyContact
        Specifies the contact information for privacy-related inquiries. Accepts a string value.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgPrivacyProfile -Headers $headers -PrivacyUrl "https://example.com/privacy" -PrivacyContact "privacy@example.com"

        This example sets the privacy statement URL to "https://example.com/privacy" and the privacy contact to "privacy@example.com".
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()][uri]$PrivacyUrl,
        [Parameter()][string]$PrivacyContact
    )
    $Uri  = "https://admin.microsoft.com/admin/api/Settings/security/privacypolicy"
    $Body = @{
        PrivacyStatement = $PrivacyUrl
        PrivacyContact   = $PrivacyContact
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgPrivilegedAccess {
    <#
        .SYNOPSIS
        Configures the privileged access settings for an Office 365 organization.
        .DESCRIPTION
        This function updates the privileged access settings for an Office 365 organization. It allows enabling or disabling the Tenant Lockbox feature and specifying an admin group.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER TenantLockBoxEnabled
        Specifies whether the Tenant Lockbox feature should be enabled or disabled. Accepts a nullable boolean value.
        .PARAMETER AdminGroup
        Specifies the admin group for privileged access.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgPrivilegedAccess -Headers $headers -TenantLockBoxEnabled $true -AdminGroup "AdminGroupName"

        This example enables the Tenant Lockbox feature and sets the admin group to "AdminGroupName".
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$TenantLockBoxEnabled,
        [string]$AdminGroup
    )
    $Uri  = "https://admin.microsoft.com/admin/api/Settings/security/tenantLockbox"

    $Body = @{
        EnabledTenantLockbox = $TenantLockBoxEnabled
        AdminGroup           = $AdminGroup
        Identity             = $null
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgProject {
    <#
        .SYNOPSIS
        Configures the project settings for an Office 365 organization.
        .DESCRIPTION
        This function updates the project settings for an Office 365 organization. It allows enabling or disabling Roadmap and Project for the Web features.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER RoadmapEnabled
        Specifies whether the Roadmap feature should be enabled or disabled. Accepts a nullable boolean value.
        .PARAMETER ProjectForTheWebEnabled
        Specifies whether the Project for the Web feature should be enabled or disabled. Accepts a nullable boolean value.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgProject -Headers $headers -RoadmapEnabled $true -ProjectForTheWebEnabled $false

        This example enables the Roadmap feature and disables the Project for the Web feature.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$RoadmapEnabled,
        [System.Nullable[bool]]$ProjectForTheWebEnabled
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/projectonline"

    $CurrentSettings = Get-O365OrgProject -Headers $Headers -NoTranslation
    If ($CurrentSettings) {
        $Body = @{
            IsRoadmapEnabled          = $CurrentSettings.IsRoadmapEnabled          #: True
            IsModProjEnabled          = $CurrentSettings.IsModProjEnabled          #: True
            RoadmapAvailabilityError  = $CurrentSettings.RoadmapAvailabilityError  #: 0
            ModProjAvailabilityStatus = $CurrentSettings.ModProjAvailabilityStatus #: 0
        }
        If ($null -ne $RoadmapEnabled) {
            $Body.IsRoadmapEnabled = $RoadmapEnabled
        }
        If ($null -ne $ProjectForTheWebEnabled) {
            $Body.IsModProjEnabled = $ProjectForTheWebEnabled
        }
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
        $Output
    }
} ###

Function Set-O365OrgReleasePreferences {
    <#
        .SYNOPSIS
        Configures the release preferences for an Office 365 organization.
        .DESCRIPTION
        This function updates the release preferences for an Office 365 organization. It allows setting the release track to one of the following options:
            - FirstRelease
            - StagedRollout
            - None
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER ReleaseTrack
        Specifies the release track for the organization. Must be one of the following values:
            - FirstRelease
            - StagedRollout
            - None
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgReleasePreferences -Headers $headers -ReleaseTrack 'FirstRelease'

        This example sets the release track to 'FirstRelease'.
    #>
    [CmdletBinding()]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [ValidateSet('FirstRelease', 'StagedRollout', 'None')]
        $ReleaseTrack
    )

    $Uri  = 'https://admin.microsoft.com/admin/api/Settings/company/releasetrack'

    $Body = [ordered] @{
        ReleaseTrack = $ReleaseTrack
        ShowCompass  = $false
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgReports {
    <#
        .SYNOPSIS
        Configures the reporting settings for an Office 365 organization.
        .DESCRIPTION
        This function updates the reporting settings for an Office 365 organization. It allows enabling or disabling privacy settings and Power BI integration for reports.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER PrivacyEnabled
        Specifies whether privacy settings are enabled for reports. Accepts a boolean value.
        .PARAMETER PowerBiEnabled
        Specifies whether Power BI integration is enabled for reports. Accepts a boolean value.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgReports -Headers $headers -PrivacyEnabled $true -PowerBiEnabled $false

        This example sets the reporting settings to enable privacy settings and disable Power BI integration.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()]
        [System.Nullable[bool]]$PrivacyEnabled,
        [Parameter()]
        [System.Nullable[bool]]$PowerBiEnabled
    )
    $Uri  = "https://admin.microsoft.com/admin/api/reports/config/SetTenantConfiguration"

    $Body = @{
        PrivacyEnabled = $PrivacyEnabled
        PowerBiEnabled = $PowerBiEnabled
    }
    Remove-EmptyValue -Hashtable $Body
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgScripts {
    <#
        .SYNOPSIS
        Configures the Office Scripts settings for an Office 365 organization.
        .DESCRIPTION
        This function updates the settings for Office Scripts in an Office 365 organization. It allows setting the permissions for users to automate their tasks, share their scripts, and run scripts in Power Automate.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER LetUsersAutomateTheirTasks
        Specifies whether users are allowed to automate their tasks. Must be one of the following values:
            - Disabled
            - Everyone
            - SpecificGroup
        .PARAMETER LetUsersAutomateTheirTasksGroup
        Specifies the name of the group allowed to automate their tasks. This parameter is used if LetUsersAutomateTheirTasks is set to 'SpecificGroup'.
        .PARAMETER LetUsersAutomateTheirTasksGroupID
        Specifies the ID of the group allowed to automate their tasks. This parameter is used if LetUsersAutomateTheirTasks is set to 'SpecificGroup'.
        .PARAMETER LetUsersShareTheirScripts
        Specifies whether users are allowed to share their scripts. Must be one of the following values:
            - Disabled
            - Everyone
            - SpecificGroup
        .PARAMETER LetUsersShareTheirScriptsGroup
        Specifies the name of the group allowed to share their scripts. This parameter is used if LetUsersShareTheirScripts is set to 'SpecificGroup'.
        .PARAMETER LetUsersShareTheirScriptsGroupID
        Specifies the ID of the group allowed to share their scripts. This parameter is used if LetUsersShareTheirScripts is set to 'SpecificGroup'.
        .PARAMETER LetUsersRunScriptPowerAutomate
        Specifies whether users are allowed to run scripts in Power Automate. Must be one of the following values:
            - Disabled
            - Everyone
            - SpecificGroup
        .PARAMETER LetUsersRunScriptPowerAutomateGroup
        Specifies the name of the group allowed to run scripts in Power Automate. This parameter is used if LetUsersRunScriptPowerAutomate is set to 'SpecificGroup'.
        .PARAMETER LetUsersRunScriptPowerAutomateGroupID
        Specifies the ID of the group allowed to run scripts in Power Automate. This parameter is used if LetUsersRunScriptPowerAutomate is set to 'SpecificGroup'.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgScripts -Headers $headers -LetUsersAutomateTheirTasks 'Everyone' -LetUsersShareTheirScripts 'SpecificGroup' -LetUsersShareTheirScriptsGroup 'GroupName' -LetUsersRunScriptPowerAutomate 'Disabled'

        This example sets the Office Scripts settings to allow everyone to automate their tasks, a specific group to share their scripts, and disables running scripts in Power Automate.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter()]
        [ValidateSet('Disabled', 'Everyone', 'SpecificGroup')]
        [string]$LetUsersAutomateTheirTasks,
        [Parameter()]
        [string]$LetUsersAutomateTheirTasksGroup,
        [Parameter()]
        [string]$LetUsersAutomateTheirTasksGroupID,
        [Parameter()]
        [ValidateSet('Disabled', 'Everyone', 'SpecificGroup')]
        [string]$LetUsersShareTheirScripts,
        [Parameter()]
        [string]$LetUsersShareTheirScriptsGroup,
        [Parameter()]
        [string]$LetUsersShareTheirScriptsGroupID,
        [Parameter()]
        [ValidateSet('Disabled', 'Everyone', 'SpecificGroup')]
        [string]$LetUsersRunScriptPowerAutomate,
        [Parameter()]
        [string]$LetUsersRunScriptPowerAutomateGroup,
        [Parameter()]
        [string]$LetUsersRunScriptPowerAutomateGroupID
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/apps/officescripts"

    $Body = [ordered] @{}
    If ($LetUsersAutomateTheirTasks -eq 'Disabled') {
        # if the user wants to disable the LetUsersAutomateTheirTasks, then we need to disable all other options as well
        $Body.EnabledOption = 0
        $Body.ShareOption = 0
        $Body.UnattendedOption = 0
    } Else {
        If ($LetUsersAutomateTheirTasks -or $LetUsersAutomateTheirTasksGroup -or $LetUsersAutomateTheirTasksGroupID) {
            # We check for the presence of option, but also if the user just provided a group name or ID we then assume the user wants specific group
            If ($LetUsersAutomateTheirTasks -eq 'SpecificGroup' -or $LetUsersAutomateTheirTasksGroup -or $LetUsersAutomateTheirTasksGroupID) {
                If ($LetUsersAutomateTheirTasksGroup) {
                    # we find the id of the group from the name
                    $Group = Get-O365Group -DisplayName $LetUsersAutomateTheirTasksGroup -Headers $Headers
                    If ($Group.Id) {
                        $Body.EnabledOption = 2
                        $Body.EnabledGroup = $Group.Id
                    } Else {
                        Write-Warning -Message "Set-O365Scripts - LetUsersAutomateTheirTasksGroup couldn't be translated to ID. Skipping."
                        return
                    }
                } ElseIf ($LetUsersAutomateTheirTasksGroupID) {
                    # we use direct ID
                    $Body.EnabledOption = 2
                    $Body.EnabledGroup = $LetUsersAutomateTheirTasksGroupID
                } Else {
                    Write-Warning -Message "Set-O365Scripts - LetUsersAutomateTheirTasksGroup/LetUsersAutomateTheirTasksGroupID not provided. Please provide group."
                    return
                }
            } ElseIf ($LetUsersAutomateTheirTasks -eq 'Everyone') {
                $Body.EnabledOption = 1
            } ElseIf ($LetUsersAutomateTheirTasks -eq 'Disabled') {
                $Body.EnabledOption = 0
            }
        }
        If ($LetUsersShareTheirScripts -or $LetUsersShareTheirScriptsGroup -or $LetUsersShareTheirScriptsGroupID) {
            # We check for the presence of option, but also if the user just provided a group name or ID we then assume the user wants specific group
            If ($LetUsersShareTheirScripts -eq 'SpecificGroup' -or $LetUsersShareTheirScriptsGroup -or $LetUsersShareTheirScriptsGroupID) {
                If ($LetUsersShareTheirScriptsGroup) {
                    # we find the id of the group from the name
                    $Group = Get-O365Group -DisplayName $LetUsersShareTheirScriptsGroup -Headers $Headers
                    If ($Group.Id) {
                        $Body.ShareOption = 2
                        $Body.ShareGroup = $Group.Id
                    } Else {
                        Write-Warning -Message "Set-O365Scripts - LetUsersAutomateTheirTasksGroup couldn't be translated to ID. Skipping."
                        return
                    }
                } ElseIf ($LetUsersShareTheirScriptsGroupID) {
                    # we use direct ID
                    $Body.ShareOption = 2
                    $Body.ShareGroup = $LetUsersShareTheirScriptsGroupID
                } Else {
                    Write-Warning -Message "Set-O365Scripts - LetUsersShareTheirScriptsGroup/LetUsersShareTheirScriptsGroupID not provided. Please provide group."
                    return
                }
            } ElseIf ($LetUsersShareTheirScripts -eq 'Everyone') {
                $Body.ShareOption = 1
            } ElseIf ($LetUsersShareTheirScripts -eq 'Disabled') {
                $Body.ShareOption = 0
            }
        }
        If ($LetUsersRunScriptPowerAutomate -or $LetUsersRunScriptPowerAutomateGroup -or $LetUsersRunScriptPowerAutomateGroupID) {
            # We check for the presence of option, but also if the user just provided a group name or ID we then assume the user wants specific group
            If ($LetUsersRunScriptPowerAutomate -eq 'SpecificGroup' -or $LetUsersRunScriptPowerAutomateGroup -or $LetUsersRunScriptPowerAutomateGroupID) {
                If ($LetUsersRunScriptPowerAutomateGroup) {
                    # we find the id of the group from the name
                    $Group = Get-O365Group -DisplayName $LetUsersRunScriptPowerAutomateGroup -Headers $Headers
                    If ($Group.Id) {
                        $Body.UnattendedOption = 2
                        $Body.UnattendedGroup = $Group.Id
                    } Else {
                        Write-Warning -Message "Set-O365Scripts - LetUsersRunScriptPowerAutomateGroup couldn't be translated to ID. Skipping."
                        return
                    }
                } ElseIf ($LetUsersRunScriptPowerAutomateGroupID) {
                    # we use direct ID
                    $Body.UnattendedOption = 2
                    $Body.UnattendedGroup = $LetUsersRunScriptPowerAutomateGroupID
                } Else {
                    Write-Warning -Message "Set-O365Scripts - LetUsersShareTheirScriptsGroup/LetUsersRunScriptPowerAutomateGroupID not provided. Please provide group."
                    return
                }
            } ElseIf ($LetUsersRunScriptPowerAutomateGroup -eq 'Everyone') {
                $Body.UnattendedOption = 1
            } ElseIf ($LetUsersRunScriptPowerAutomateGroup -eq 'Disabled') {
                $Body.UnattendedOption = 0
            }
        }
    }
    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    $Output
} ###

Function Set-O365OrgSharePoint {
    <#
        .SYNOPSIS
        Configures the sharing settings for SharePoint in an Office 365 organization.
        .DESCRIPTION
        This function updates the sharing settings for SharePoint in an Office 365 organization. It allows setting the collaboration type to one of the following options:
        - OnlyPeopleInYourOrganization
        - ExistingGuestsOnly
        - NewAndExistingGuestsOnly
        - Anyone
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER CollaborationType
        Specifies the type of collaboration allowed. Must be one of the following values:
        - OnlyPeopleInYourOrganization
        - ExistingGuestsOnly
        - NewAndExistingGuestsOnly
        - Anyone
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgSharePoint -Headers $headers -CollaborationType 'Anyone'

        This example sets the SharePoint collaboration type to allow sharing with anyone.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [ValidateSet('OnlyPeopleInYourOrganization', 'ExistingGuestsOnly', 'NewAndExistingGuestsOnly', 'Anyone')]
        [string]$CollaborationType
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/sitessharing"

    $ReverseTranslateCollaboration = @{
        'NewAndExistingGuestsOnly'     = 2
        'Anyone'                       = 16
        'ExistingGuestsOnly'           = 32
        'OnlyPeopleInYourOrganization' = 1
    }

    $Body = @{
        AllowSharing      = if ($CollaborationType -eq 'OnlyPeopleInYourOrganization') { $false } else { $true }
        CollaborationType = $ReverseTranslateCollaboration[$CollaborationType]
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgSharing {
    <#
        .SYNOPSIS
        Configures the guest user policy for an Office 365 organization.
        .DESCRIPTION
        This function updates the guest user policy settings for an Office 365 organization. It allows enabling or disabling the ability for users to add new guests.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER LetUsersAddNewGuests
        Specifies whether users are allowed to add new guests. Set to $true to allow, $false to disallow.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgSharing -Headers $headers -LetUsersAddNewGuests $true

        This example allows users to add new guests in the Office 365 organization.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$LetUsersAddNewGuests
    )
    $Uri  = "https://admin.microsoft.com/admin/api/settings/security/guestUserPolicy"
    $Body = @{
        AllowGuestInvitations = $LetUsersAddNewGuests
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgSway {
    <#
        .SYNOPSIS
        Configures settings for Microsoft Sway in Office 365.
        .DESCRIPTION
        This function updates the configuration settings for Microsoft Sway in Office 365. It allows enabling or disabling external sharing, people picker search, Flickr, Pickit, Wikipedia, and YouTube.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER ExternalSharingEnabled
        Specifies whether external sharing is enabled or disabled.
        .PARAMETER PeoplePickerSearchEnabled
        Specifies whether people picker search is enabled or disabled.
        .PARAMETER FlickrEnabled
        Specifies whether Flickr integration is enabled or disabled.
        .PARAMETER PickitEnabled
        Specifies whether Pickit integration is enabled or disabled.
        .PARAMETER WikipediaEnabled
        Specifies whether Wikipedia integration is enabled or disabled.
        .PARAMETER YouTubeEnabled
        Specifies whether YouTube integration is enabled or disabled.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgSway -Headers $headers -ExternalSharingEnabled $true -PeoplePickerSearchEnabled $false -FlickrEnabled $true -PickitEnabled $false -WikipediaEnabled $true -YouTubeEnabled $false

        This example enables external sharing, disables people picker search, enables Flickr, disables Pickit, enables Wikipedia, and disables YouTube for Microsoft Sway.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$ExternalSharingEnabled,
        [System.Nullable[bool]]$PeoplePickerSearchEnabled,
        [System.Nullable[bool]]$FlickrEnabled,
        [System.Nullable[bool]]$PickitEnabled,
        [System.Nullable[bool]]$WikipediaEnabled,
        [System.Nullable[bool]]$YouTubeEnabled
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/Sway"

    $CurrentSettings = Get-O365OrgSway -Headers $Headers
    If ($CurrentSettings) {
        $Body = [ordered]@{
            ExternalSharingEnabled    = $CurrentSettings.ExternalSharingEnabled    # : True
            PeoplePickerSearchEnabled = $CurrentSettings.PeoplePickerSearchEnabled # : True
            FlickrEnabled             = $CurrentSettings.FlickrEnabled             # : True
            PickitEnabled             = $CurrentSettings.PickitEnabled             # : True
            WikipediaEnabled          = $CurrentSettings.WikipediaEnabled          # : True
            YouTubeEnabled            = $CurrentSettings.YouTubeEnabled            # : True
        }

        If ($null -ne $ExternalSharingEnabled) {
            $Body.ExternalSharingEnabled = $ExternalSharingEnabled
        }
        If ($null -ne $FlickrEnabled) {
            $Body.FlickrEnabled = $FlickrEnabled
        }
        If ($null -ne $PickitEnabled) {
            $Body.PickitEnabled = $PickitEnabled
        }
        If ($null -ne $WikipediaEnabled) {
            $Body.WikipediaEnabled = $WikipediaEnabled
        }
        If ($null -ne $YouTubeEnabled) {
            $Body.YouTubeEnabled = $YouTubeEnabled
        }
        If ($null -ne $PeoplePickerSearchEnabled) {
            $Body.PeoplePickerSearchEnabled = $PeoplePickerSearchEnabled
        }

        $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    }
} ###

Function Set-O365OrgTodo {
    <#
        .SYNOPSIS
        Configures settings for Microsoft To-Do in Office 365.
        .DESCRIPTION
        This function updates the configuration settings for Microsoft To-Do in Office 365. It allows enabling or disabling external join, push notifications, and external sharing.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER ExternalJoinEnabled
        Specifies whether external join is enabled or disabled.
        .PARAMETER PushNotificationEnabled
        Specifies whether push notifications are enabled or disabled.
        .PARAMETER ExternalShareEnabled
        Specifies whether external sharing is enabled or disabled.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgTodo -Headers $headers -ExternalJoinEnabled $true -PushNotificationEnabled $false -ExternalShareEnabled $true

        This example enables external join, disables push notifications, and enables external sharing for Microsoft To-Do.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$ExternalJoinEnabled,
        [System.Nullable[bool]]$PushNotificationEnabled,
        [System.Nullable[bool]]$ExternalShareEnabled
    )
    $Uri = "https://admin.microsoft.com/admin/api/services/apps/todo"

    $CurrentSettings = Get-O365OrgToDo -Headers $Headers
    If ($CurrentSettings) {
        $Body = @{
            IsExternalJoinEnabled     = $CurrentSettings.IsExternalJoinEnabled
            IsPushNotificationEnabled = $CurrentSettings.IsPushNotificationEnabled
            IsExternalShareEnabled    = $CurrentSettings.IsExternalShareEnabled
        }
        If ($null -ne $ExternalJoinEnabled) {
            $Body.IsExternalJoinEnabled = $ExternalJoinEnabled
        }
        If ($null -ne $PushNotificationEnabled) {
            $Body.IsPushNotificationEnabled = $PushNotificationEnabled
        }
        If ($null -ne $ExternalShareEnabled) {
            $Body.IsExternalShareEnabled = $ExternalShareEnabled
        }
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
        $Output
    }
} ###

Function Set-O365OrgUserConsentApps {
    <#
        .SYNOPSIS
        Configures user consent settings for integrated apps in Office 365.
        .DESCRIPTION
        This function updates the configuration settings for user consent to integrated apps in Office 365. It allows enabling or disabling user consent to apps.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER UserConsentToAppsEnabled
        Specifies whether user consent to apps is enabled or disabled. This parameter is mandatory.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgUserConsentApps -Headers $headers -UserConsentToAppsEnabled $true

        This example enables user consent to integrated apps.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [Parameter(Mandatory)]
        [bool]$UserConsentToAppsEnabled
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/IntegratedApps"

    $Body = @{
        Enabled = $UserConsentToAppsEnabled
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365OrgUserOwnedApps {
    <#
        .SYNOPSIS
        Configures settings for user-owned apps in Office 365.
        .DESCRIPTION
        This function updates the configuration settings for user-owned apps in Office 365. It allows enabling or disabling user access to the Office Store, starting trials, and auto-claiming licenses.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER LetUsersAccessOfficeStore
        Specifies whether users are allowed to access the Office Store.
        .PARAMETER LetUsersStartTrials
        Specifies whether users are allowed to start trials.
        .PARAMETER LetUsersAutoClaimLicenses
        Specifies whether users are allowed to auto-claim licenses.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgUserOwnedApps -Headers $headers -LetUsersAccessOfficeStore $true -LetUsersStartTrials $false -LetUsersAutoClaimLicenses $true

        This example enables user access to the Office Store, disables starting trials, and enables auto-claiming licenses.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$LetUsersAccessOfficeStore,
        [System.Nullable[bool]]$LetUsersStartTrials,
        [System.Nullable[bool]]$LetUsersAutoClaimLicenses
    )

    If ($null -ne $LetUsersAccessOfficeStore) {
        $Uri  = "https://admin.microsoft.com/admin/api/settings/apps/store"
        $Body = @{
            Enabled = $LetUsersAccessOfficeStore
        }
        $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    }
    If ($null -ne $LetUsersStartTrials) {
        $TrialState = $LetUsersStartTrials.ToString().ToLower()
        $Uri        = "https://admin.microsoft.com/admin/api/storesettings/iwpurchase/$TrialState"
        $null       = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT #-Body $Body
    }
    If ($null -ne $LetUsersAutoClaimLicenses) {
        $Uri  = "https://admin.microsoft.com/fd/m365licensing/v1/policies/autoclaim"
        $Body = @{
            policyValue = if ($LetUsersAutoClaimLicenses -eq $true) { 'Enabled' } else { 'Disabled' }
        }
        $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
    }
} ###

Function Set-O365OrgWhiteboard {
    <#
        .SYNOPSIS
        Configures settings for the Office 365 Whiteboard application.
        .DESCRIPTION
        This function updates the configuration settings for the Office 365 Whiteboard application. It allows enabling or disabling the Whiteboard, setting diagnostic data sharing preferences, and configuring related features like connected experiences, board sharing, and OneDrive storage.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER WhiteboardEnabled
        Specifies whether the Whiteboard is enabled or disabled.
        .PARAMETER DiagnosticData
        Specifies the level of diagnostic data allowed. Valid values are 'Neither', 'Required', 'Optional'.
        .PARAMETER OptionalConnectedExperiences
        Specifies whether optional connected experiences are enabled.
        .PARAMETER BoardSharingEnabled
        Specifies whether board sharing is enabled.
        .PARAMETER OneDriveStorageEnabled
        Specifies whether OneDrive storage is enabled for Whiteboard.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365OrgWhiteboard -Headers $headers -WhiteboardEnabled $true -DiagnosticData 'Optional' -OptionalConnectedExperiences $true -BoardSharingEnabled $true -OneDriveStorageEnabled $true

        This example enables the Whiteboard with optional diagnostic data, connected experiences, board sharing, and OneDrive storage.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$WhiteboardEnabled,
        [ValidateSet('Neither', 'Required', 'Optional')]
        $DiagnosticData,
        [System.Nullable[bool]]$OptionalConnectedExperiences,
        [System.Nullable[bool]]$BoardSharingEnabled,
        [System.Nullable[bool]]$OneDriveStorageEnabled
    )
    $Uri = "https://admin.microsoft.com/admin/api/settings/apps/whiteboard"

    $CurrentSettings = Get-O365OrgWhiteboard -Headers $Headers -NoTranslation

    $Body = [ordered]@{
        IsEnabled                   = $CurrentSettings.IsEnabled                   # : True
        IsClaimEnabled              = $CurrentSettings.IsClaimEnabled              #: True
        IsSharePointDefault         = $CurrentSettings.IsSharePointDefault         #: False
        # This always seems to be 0, but i'll let it read it from Get-O365OrgWhiteboard
        NonTenantAccess             = $CurrentSettings.NonTenantAccess             #: 0
        TelemetryPolicy             = $CurrentSettings.TelemetryPolicy             #: 2
        AreConnectedServicesEnabled = $CurrentSettings.AreConnectedServicesEnabled #: True
    }
    If ($null -ne $WhiteboardEnabled) {
        $Body.IsEnabled = $WhiteboardEnabled
    }
    If ($DiagnosticData) {
        $ReverseTranslateTelemetry = @{
            'Neither'  = 0
            'Required' = 1
            'Optional' = 2
        }
        $Body.TelemetryPolicy = $ReverseTranslateTelemetry[$DiagnosticData]
    }
    If ($null -ne $OptionalConnectedExperiences) {
        $Body.AreConnectedServicesEnabled = $OptionalConnectedExperiences
    }
    If ($null -ne $BoardSharingEnabled) {
        $Body.IsClaimEnabled = $BoardSharingEnabled
    }
    If ($null -ne $OneDriveStorageEnabled) {
        $Body.IsSharePointDefault = $OneDriveStorageEnabled
    }
    $null = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method POST -Body $Body
} ###

Function Set-O365PasswordReset {
    <#
        .SYNOPSIS
        Configures password reset settings for Office 365.
        .DESCRIPTION
        This function updates the settings for password reset policies in Office 365. It allows configuring various options such as authentication methods, notification settings, and security questions.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER EnablementType
        Specifies the type of enablement for the password reset policy.
        .PARAMETER NumberOfAuthenticationMethodsRequired
        Specifies the number of authentication methods required for password reset.
        .PARAMETER EmailOptionEnabled
        Indicates whether the email option is enabled for password reset.
        .PARAMETER MobilePhoneOptionEnabled
        Indicates whether the mobile phone option is enabled for password reset.
        .PARAMETER OfficePhoneOptionEnabled
        Indicates whether the office phone option is enabled for password reset.
        .PARAMETER SecurityQuestionsOptionEnabled
        Indicates whether the security questions option is enabled for password reset.
        .PARAMETER MobileAppNotificationEnabled
        Indicates whether the mobile app notification option is enabled for password reset.
        .PARAMETER MobileAppCodeEnabled
        Indicates whether the mobile app code option is enabled for password reset.
        .PARAMETER NumberOfQuestionsToRegister
        Specifies the number of security questions required to register for password reset.
        .PARAMETER NumberOfQuestionsToReset
        Specifies the number of security questions required to reset the password.
        .PARAMETER RegistrationRequiredOnSignIn
        Indicates whether registration is required on sign-in.
        .PARAMETER RegistrationReconfirmIntevalInDays
        Specifies the interval in days for reconfirming registration.
        .PARAMETER SkipRegistrationAllowed
        Indicates whether skipping registration is allowed.
        .PARAMETER SkipRegistrationMaxAllowedDays
        Specifies the maximum number of days allowed for skipping registration.
        .PARAMETER CustomizeHelpdeskLink
        Indicates whether the helpdesk link is customized.
        .PARAMETER CustomHelpdeskEmailOrUrl
        Specifies the custom helpdesk email or URL.
        .PARAMETER NotifyUsersOnPasswordReset
        Indicates whether users are notified on password reset.
        .PARAMETER NotifyOnAdminPasswordReset
        Indicates whether administrators are notified on password reset.
        .PARAMETER PasswordResetEnabledGroupIds
        Specifies the group IDs for which password reset is enabled.
        .PARAMETER PasswordResetEnabledGroupName
        Specifies the group name for which password reset is enabled.
        .PARAMETER EmailOptionAllowed
        Indicates whether the email option is allowed for password reset.
        .PARAMETER MobilePhoneOptionAllowed
        Indicates whether the mobile phone option is allowed for password reset.
        .PARAMETER OfficePhoneOptionAllowed
        Indicates whether the office phone option is allowed for password reset.
        .PARAMETER SecurityQuestionsOptionAllowed
        Indicates whether the security questions option is allowed for password reset.
        .PARAMETER MobileAppNotificationOptionAllowed
        Indicates whether the mobile app notification option is allowed for password reset.
        .PARAMETER MobileAppCodeOptionAllowed
        Indicates whether the mobile app code option is allowed for password reset.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365PasswordReset -Headers $headers -EnablementType 1 -NumberOfAuthenticationMethodsRequired 2 -EmailOptionEnabled $true
    
        This example configures the password reset policy with the specified settings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[int]]$EnablementType                       , # = $CurrentSettings.enablementType #: 1
        [System.Nullable[int]]$NumberOfAuthenticationMethodsRequired, # = $CurrentSettings.numberOfAuthenticationMethodsRequired #: 1
        [System.Nullable[bool]]$EmailOptionEnabled                   , # = $CurrentSettings.emailOptionEnabled #: True
        [System.Nullable[bool]]$MobilePhoneOptionEnabled             , # = $CurrentSettings.mobilePhoneOptionEnabled #: True
        [System.Nullable[bool]]$OfficePhoneOptionEnabled             , # = $CurrentSettings.officePhoneOptionEnabled #: False
        [System.Nullable[bool]]$SecurityQuestionsOptionEnabled       , # = $CurrentSettings.securityQuestionsOptionEnabled #: False
        [System.Nullable[bool]]$MobileAppNotificationEnabled         , # = $CurrentSettings.mobileAppNotificationEnabled #: False
        [System.Nullable[bool]]$MobileAppCodeEnabled                 , # = $CurrentSettings.mobileAppCodeEnabled #: True
        [System.Nullable[int]]$NumberOfQuestionsToRegister          , # = $CurrentSettings.numberOfQuestionsToRegister #: 5
        [System.Nullable[int]]$NumberOfQuestionsToReset             , # = $CurrentSettings.numberOfQuestionsToReset #: 3
        [System.Nullable[bool]]$RegistrationRequiredOnSignIn         , # = $CurrentSettings.registrationRequiredOnSignIn #: True
        [System.Nullable[int]]$RegistrationReconfirmIntevalInDays   , # = $CurrentSettings.registrationReconfirmIntevalInDays #: 180
        [System.Nullable[bool]]$SkipRegistrationAllowed              , # = $CurrentSettings.skipRegistrationAllowed #: True
        [System.Nullable[int]]$SkipRegistrationMaxAllowedDays       , # = $CurrentSettings.skipRegistrationMaxAllowedDays #: 7
        [System.Nullable[bool]]$CustomizeHelpdeskLink                , # = $CurrentSettings.customizeHelpdeskLink #: False
        [string]$CustomHelpdeskEmailOrUrl             , # = $CurrentSettings.customHelpdeskEmailOrUrl #:
        [System.Nullable[bool]]$NotifyUsersOnPasswordReset           , # = $CurrentSettings.notifyUsersOnPasswordReset #: True
        [System.Nullable[bool]]$NotifyOnAdminPasswordReset           , # = $CurrentSettings.notifyOnAdminPasswordReset #: True
        [string]$PasswordResetEnabledGroupIds         , # = $CurrentSettings.passwordResetEnabledGroupIds #: {b6cdb9c3-d660-4558-bcfd-82c14a986b56}
        [string]$PasswordResetEnabledGroupName        , # = $CurrentSettings.passwordResetEnabledGroupName #:
        # don't have details about those. needs investigations
        # $securityQuestions , # = $CurrentSettings.securityQuestions #: {}
        #$registrationConditionalAccessPolicies, # = $CurrentSettings.registrationConditionalAccessPolicies #: {}
        [System.Nullable[bool]]$EmailOptionAllowed                   , # = $CurrentSettings.emailOptionAllowed #: True
        [System.Nullable[bool]]$MobilePhoneOptionAllowed             , # = $CurrentSettings.mobilePhoneOptionAllowed #: True
        [System.Nullable[bool]]$OfficePhoneOptionAllowed             , # = $CurrentSettings.officePhoneOptionAllowed #: True
        [System.Nullable[bool]]$SecurityQuestionsOptionAllowed       , # = $CurrentSettings.securityQuestionsOptionAllowed #: True
        [System.Nullable[bool]]$MobileAppNotificationOptionAllowed   , # = $CurrentSettings.mobileAppNotificationOptionAllowed #: True
        [System.Nullable[bool]]$MobileAppCodeOptionAllowed            # = $CurrentSettings.mobileAppCodeOptionAllowed #: True
    )
    $Uri             = "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies"

    $CurrentSettings = Get-O365PasswordReset -Headers $Headers

    If ($CurrentSettings.objectId -ne 'default') {
        Write-Warning -Message "Set-O365PasswordReset - Getting current settings failed. Skipping changes."
        return
    }

    $Body = [ordered]@{
        objectId                              = $CurrentSettings.objectId #: default
        enablementType                        = $CurrentSettings.enablementType #: 1
        numberOfAuthenticationMethodsRequired = $CurrentSettings.numberOfAuthenticationMethodsRequired #: 1
        emailOptionEnabled                    = $CurrentSettings.emailOptionEnabled #: True
        mobilePhoneOptionEnabled              = $CurrentSettings.mobilePhoneOptionEnabled #: True
        officePhoneOptionEnabled              = $CurrentSettings.officePhoneOptionEnabled #: False
        securityQuestionsOptionEnabled        = $CurrentSettings.securityQuestionsOptionEnabled #: False
        mobileAppNotificationEnabled          = $CurrentSettings.mobileAppNotificationEnabled #: False
        mobileAppCodeEnabled                  = $CurrentSettings.mobileAppCodeEnabled #: True
        numberOfQuestionsToRegister           = $CurrentSettings.numberOfQuestionsToRegister #: 5
        numberOfQuestionsToReset              = $CurrentSettings.numberOfQuestionsToReset #: 3
        registrationRequiredOnSignIn          = $CurrentSettings.registrationRequiredOnSignIn #: True
        registrationReconfirmIntevalInDays    = $CurrentSettings.registrationReconfirmIntevalInDays #: 180
        skipRegistrationAllowed               = $CurrentSettings.skipRegistrationAllowed #: True
        skipRegistrationMaxAllowedDays        = $CurrentSettings.skipRegistrationMaxAllowedDays #: 7
        customizeHelpdeskLink                 = $CurrentSettings.customizeHelpdeskLink #: False
        customHelpdeskEmailOrUrl              = $CurrentSettings.customHelpdeskEmailOrUrl #:
        notifyUsersOnPasswordReset            = $CurrentSettings.notifyUsersOnPasswordReset #: True
        notifyOnAdminPasswordReset            = $CurrentSettings.notifyOnAdminPasswordReset #: True
        passwordResetEnabledGroupIds          = $CurrentSettings.passwordResetEnabledGroupIds #: {b6cdb9c3-d660-4558-bcfd-82c14a986b56}
        passwordResetEnabledGroupName         = $CurrentSettings.passwordResetEnabledGroupName #:
        securityQuestions                     = $CurrentSettings.securityQuestions #: {}
        registrationConditionalAccessPolicies = $CurrentSettings.registrationConditionalAccessPolicies #: {}
        emailOptionAllowed                    = $CurrentSettings.emailOptionAllowed #: True
        mobilePhoneOptionAllowed              = $CurrentSettings.mobilePhoneOptionAllowed #: True
        officePhoneOptionAllowed              = $CurrentSettings.officePhoneOptionAllowed #: True
        securityQuestionsOptionAllowed        = $CurrentSettings.securityQuestionsOptionAllowed #: True
        mobileAppNotificationOptionAllowed    = $CurrentSettings.mobileAppNotificationOptionAllowed #: True
        mobileAppCodeOptionAllowed            = $CurrentSettings.mobileAppCodeOptionAllowed #: True
    }

    If ($null -ne $EnablementType) {
        $Body.enablementType = $EnablementType
    }
    If ($null -ne $NumberOfAuthenticationMethodsRequired) {
        $Body.numberOfAuthenticationMethodsRequired = $NumberOfAuthenticationMethodsRequired
    }
    If ($null -ne $EmailOptionEnabled) {
        $Body.emailOptionEnabled = $EmailOptionEnabled
    }
    If ($null -ne $MobilePhoneOptionEnabled) {
        $Body.mobilePhoneOptionEnabled = $MobilePhoneOptionEnabled
    }
    If ($null -ne $OfficePhoneOptionEnabled) {
        $Body.officePhoneOptionEnabled = $OfficePhoneOptionEnabled
    }
    If ($null -ne $SecurityQuestionsOptionEnabled) {
        $Body.securityQuestionsOptionEnabled = $SecurityQuestionsOptionEnabled
    }
    If ($null -ne $MobileAppNotificationEnabled) {
        $Body.mobileAppNotificationEnabled = $MobileAppNotificationEnabled
    }
    If ($null -ne $MobileAppCodeEnabled) {
        $Body.mobileAppCodeEnabled = $MobileAppCodeEnabled
    }
    If ($null -ne $NumberOfQuestionsToRegister) {
        $Body.numberOfQuestionsToRegister = $NumberOfQuestionsToRegister
    }
    If ($null -ne $NumberOfQuestionsToReset) {
        $Body.numberOfQuestionsToReset = $NumberOfQuestionsToReset
    }
    If ($null -ne $RegistrationRequiredOnSignIn) {
        $Body.registrationRequiredOnSignIn = $RegistrationRequiredOnSignIn
    }
    If ($null -ne $RegistrationReconfirmIntevalInDays) {
        $Body.registrationReconfirmIntevalInDays = $RegistrationReconfirmIntevalInDays
    }
    If ($null -ne $SkipRegistrationAllowed) {
        $Body.skipRegistrationAllowed = $SkipRegistrationAllowed
    }
    If ($null -ne $SkipRegistrationMaxAllowedDays) {
        $Body.skipRegistrationMaxAllowedDays = $SkipRegistrationMaxAllowedDays
    }
    If ($CustomizeHelpdeskLink) {
        $Body.customizeHelpdeskLink = $CustomizeHelpdeskLink
    }
    If ($null -ne $CustomHelpdeskEmailOrUrl) {
        $Body.customHelpdeskEmailOrUrl = $CustomHelpdeskEmailOrUrl
    }
    If ($null -ne $NotifyUsersOnPasswordReset) {
        $Body.notifyUsersOnPasswordReset = $NotifyUsersOnPasswordReset
    }
    If ($null -ne $NotifyOnAdminPasswordReset) {
        $Body.notifyOnAdminPasswordReset = $NotifyOnAdminPasswordReset
    }
    If ($PasswordResetEnabledGroupName) {
        # We should find an easy way to find ID of a group and set it here
        # Not implemented yet
        $Body.passwordResetEnabledGroupIds = @(
            # Query for group id from group name $PasswordResetEnabledGroupName
        )
        throw 'PasswordResetEnabledGroupName is not implemented yet'
    } ElseIf ($PasswordResetEnabledGroupIds) {
        $Body.passwordResetEnabledGroupIds = @($PasswordResetEnabledGroupIds)
        # This seems like an empty value - always
        $Body.passwordResetEnabledGroupName = ''
    }
    If ($null -ne $SecurityQuestions) {
        $Body.securityQuestions = $SecurityQuestions
    }
    If ($null -ne $RegistrationConditionalAccessPolicies) {
        $Body.registrationConditionalAccessPolicies = $RegistrationConditionalAccessPolicies
    }
    If ($null -ne $EmailOptionAllowed) {
        $Body.emailOptionAllowed = $EmailOptionAllowed
    }
    If ($null -ne $MobilePhoneOptionAllowed) {
        $Body.mobilePhoneOptionAllowed = $MobilePhoneOptionAllowed
    }
    If ($null -ne $OfficePhoneOptionAllowed) {
        $Body.officePhoneOptionAllowed = $OfficePhoneOptionAllowed
    }
    If ($null -ne $SecurityQuestionsOptionAllowed) {
        $Body.securityQuestionsOptionAllowed = $SecurityQuestionsOptionAllowed
    }
    If ($null -ne $mobileAppNotificationOptionAllowed) {
        $Body.mobileAppNotificationOptionAllowed = $mobileAppNotificationOptionAllowed
    }
    If ($null -ne $mobileAppCodeOptionAllowed) {
        $Body.mobileAppCodeOptionAllowed = $mobileAppCodeOptionAllowed
    }

    $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body
} ###

Function Set-O365PasswordResetIntegration {
    <#
        .SYNOPSIS
        Configures password reset integration settings for Office 365.
        .DESCRIPTION
        This function updates the settings for password writeback and account unlock features in Office 365. 
        It allows enabling or disabling the password writeback and account unlock capabilities.
        .PARAMETER Headers
        Specifies the headers for the API request. Typically includes authorization tokens.
        .PARAMETER PasswordWritebackSupported
        Indicates whether password writeback is supported. Accepts $true or $false.
        .PARAMETER AccountUnlockEnabled
        Indicates whether account unlock is enabled. Accepts $true or $false.
        .EXAMPLE
        $headers = @{Authorization = "Bearer your_token"}
        Set-O365PasswordResetIntegration -Headers $headers -PasswordWritebackSupported $true -AccountUnlockEnabled $true
    
        This example enables both password writeback and account unlock features.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    Param (
        [Alias('Authorization')]
        [System.Collections.IDictionary]$Headers,
        [System.Nullable[bool]]$PasswordWritebackSupported,
        [System.Nullable[bool]]$AccountUnlockEnabled
    )
    $Uri = "https://main.iam.ad.ext.azure.com/api/PasswordReset/OnPremisesPasswordResetPolicies"

    <#
        $Body = @{
            passwordWriteBackSupported = $passwordWriteBackSupported
            accountUnlockEnabled       = $AccountUnlockEnabled
            #accountUnlockSupported    = $accountUnlockSupported - doesn't seem to be used/work, always enabled
        }
        Remove-EmptyValue -Hashtable $Body
        If ($Body.Keys.Count -gt 0) {$Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body}
    #>

    # It seems you need to set this separatly for AccountUnlockEnabled to be picked up properly.
    # So we do it..
    <#
        $Body   = @{passwordWriteBackSupported = $passwordWriteBackSupported}
        passwordWriteBackSupported = $passwordWriteBackSupported
        accountUnlockEnabled       = $AccountUnlockEnabled
        #accountUnlockSupported    = $accountUnlockSupported - doesn't seem to be used/work, always enabled
        }
        Remove-EmptyValue -Hashtable $Body
        If ($Body.Keys.Count -gt 0) {$Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body}
    #>

    # It seems you need to set this separatly for AccountUnlockEnabled to be picked up properly.
    # So we do it..
    <#
        $Body = @{
            passwordWriteBackSupported = $passwordWriteBackSupported
            accountUnlockEnabled       = $AccountUnlockEnabled
            #accountUnlockSupported    = $accountUnlockSupported - doesn't seem to be used/work, always enabled
        }
        Remove-EmptyValue -Hashtable $Body
        If ($Body.Keys.Count -gt 0) {$Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body}
    #>

    # It seems you need to set this separatly for AccountUnlockEnabled to be picked up properly.
    # So we do it..
    <#
        $Body = @{
            passwordWriteBackSupported = $passwordWriteBackSupported
            accountUnlockEnabled       = $AccountUnlockEnabled
            #accountUnlockSupported    = $accountUnlockSupported - doesn't seem to be used/work, always enabled
        }
        Remove-EmptyValue -Hashtable $Body
        If ($Body.Keys.Count -gt 0) {$Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body}
    #>

    # It seems you need to set this separatly for AccountUnlockEnabled to be picked up properly.
    # So we do it..
    <#
        $Body = @{
            passwordWriteBackSupported = $passwordWriteBackSupported
            accountUnlockEnabled       = $AccountUnlockEnabled
            #accountUnlockSupported    = $accountUnlockSupported - doesn't seem to be used/work, always enabled
        }
        Remove-EmptyValue -Hashtable $Body
        If ($Body.Keys.Count -gt 0) {$Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body}
    #>

    # It seems you need to set this separatly for AccountUnlockEnabled to be picked up properly.
    # So we do it..
    <#
        $Body = @{
            passwordWriteBackSupported = $passwordWriteBackSupported
            accountUnlockEnabled       = $AccountUnlockEnabled
            #accountUnlockSupported    = $accountUnlockSupported - doesn't seem to be used/work, always enabled
        }
        Remove-EmptyValue -Hashtable $Body
        If ($Body.Keys.Count -gt 0) {$Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body}
    #>

    # It seems you need to set this separatly for AccountUnlockEnabled to be picked up properly.
    # So we do it..
    <#
        $Body = @{
            passwordWriteBackSupported = $passwordWriteBackSupported
            accountUnlockEnabled       = $AccountUnlockEnabled
            #accountUnlockSupported    = $accountUnlockSupported - doesn't seem to be used/work, always enabled
        }
        Remove-EmptyValue -Hashtable $Body
        If ($Body.Keys.Count -gt 0) {$Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body}
    #>

    # It seems you need to set this separatly for AccountUnlockEnabled to be picked up properly.
    # So we do it..
    If ($null -ne $PasswordWritebackSupported) {
        $Body   = @{passwordWriteBackSupported = $PasswordWritebackSupported}
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body
    }
    If ($null -ne $AccountUnlockEnabled) {
        $Body   = @{accountUnlockEnabled = $AccountUnlockEnabled}
        $Output = Invoke-O365Admin -Uri $Uri -Headers $Headers -Method PUT -Body $Body
    }
} ###
