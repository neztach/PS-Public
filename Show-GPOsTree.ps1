Function Show-GPOsTree {
    <#
        .SYNOPSIS
        Displays a hierarchical tree of Organizational Units (OUs) within a domain, showing GPO inheritance status, including whether inheritance is blocked.

        .DESCRIPTION
        The `Show-GPOsTree` function generates a tree-like structure of Organizational Units (OUs) in an Active Directory domain.
        It recursively lists all OUs in the domain, and for each OU, it shows its GPO inheritance status. OUs with GPO inheritance blocking can be highlighted in red.
        The function allows filtering to display only those OUs where GPO inheritance is blocked when the `-ShowBlockedOnly` switch is used.

        .PARAMETER ParentDistinguishedName
        The Distinguished Name (DN) of the parent Organizational Unit (OU). The default is the root domain's DN if not specified. This parameter is used to start the recursive search of OUs under the given parent.
    
        .PARAMETER ShowBlockedOnly
        A switch that, when specified, filters the tree to display only those OUs where GPO inheritance is blocked. If not specified, all OUs will be shown regardless of their GPO inheritance status.

        .EXAMPLE
        Show-GPOsTree
        Displays the entire tree of OUs in the domain, showing all OUs and their GPO inheritance status.

        .EXAMPLE
        Show-GPOsTree -ShowBlockedOnly
        Displays the tree of OUs in the domain, but only those where GPO inheritance is blocked will be shown.

        .EXAMPLE
        Show-GPOsTree -ParentDistinguishedName 'DC=example,DC=com'
        Displays the tree of OUs starting from the specified parent OU 'example.com' (the Distinguished Name provided) and includes all child OUs.

        .NOTES
        This function relies on the `Get-GPInheritance` cmdlet to retrieve Group Policy inheritance information for each OU. Ensure you have appropriate permissions to query Group Policy inheritance details.
    #>
    [CmdletBinding()]
    Param (
        [string]$ParentDistinguishedName = (Get-ADDomain).DistinguishedName,
        [switch]$ShowBlockedOnly
    )

    ### Internal hashtable to track processed OUs to avoid infinite recursion
    $ProcessedOUs = @{}

    ### Internal function to handle recursion and display the OUs
    Function Show-ChildOUs {
        [CmdletBinding()]
        Param (
            [string]$ParentDistinguishedName,
            [string]$Indentation = '',
            [bool]$IsLastChild = $true
        )

        ### Get all OUs in the domain
        $AllOUs = Get-ADOrganizationalUnit -Filter * 

        ### Filter the OUs for the current parent
        $childOUs = $AllOUs | Where-Object { $_.DistinguishedName -like "*$ParentDistinguishedName*" -and $_.DistinguishedName -ne $ParentDistinguishedName }

        ### If there are child OUs, iterate through each
        $childOUs | ForEach-Object {
            $ou = $_

            ### Skip if this OU has already been processed
            If ($ProcessedOUs.ContainsKey($ou.DistinguishedName)) {
                return
            }

            ### Mark this OU as processed
            $ProcessedOUs[$ou.DistinguishedName] = $true

            ### Get GPO inheritance information for the OU
            $gpoInheritance = Get-GPInheritance -Target $ou.DistinguishedName

            ### Check if GPO blocking is enabled for this OU (either through BlockInheritance or a GPO link)
            $gpoBlockStatus = $gpoInheritance.GpoInheritanceBlocked

            ### Determine the block status message
            $blockStatusMessage = If ($gpoBlockStatus -eq 'Yes') {' [GPO Blocked]'} Else {' [No GPO Blocking]'}

            ### If ShowBlockedOnly is true, skip OUs that are not blocking inheritance
            If ($ShowBlockedOnly -and $gpoBlockStatus -ne 'Yes') {return}

            ### Determine the branch symbol (├── or └──)
            $branchSymbol = If ($IsLastChild) { '└──' } Else { '├──' }

            ### Only apply color if GPO inheritance is blocked
            If ($gpoBlockStatus -eq 'Yes') {
                Write-Host (('{0}{1} {2}{3}' -f $Indentation, $branchSymbol, $ou.Name, $blockStatusMessage)) -ForegroundColor Red
            } Else {
                Write-Host (('{0}{1} {2}{3}' -f $Indentation, $branchSymbol, $ou.Name, $blockStatusMessage))
            }

            ### Recursively check if there are child OUs
            Show-ChildOUs -ParentDistinguishedName $ou.DistinguishedName -Indentation ('{0}│   ' -f $Indentation) -IsLastChild $false
        }
    }

    ### Get the domain info and show the OUs tree
    $domain = Get-ADDomain
    Write-Host ('{0} [Root Domain]' -f $domain.Forest)
    
    ### Start recursive process to show child OUs
    Show-ChildOUs -ParentDistinguishedName $ParentDistinguishedName
}

### Run the function
Show-GPOsTree
