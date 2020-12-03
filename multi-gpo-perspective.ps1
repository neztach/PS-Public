$OutputPath    = "C:\down\GPO"
$script:AllGPOObjects = Get-GPO -All | Sort-Object DisplayName

Function Find-OrphanedOUs {
    $orphanOutput = @()
    $Orphans      = $script:AllGPOObjects | Where-Object {If ($_ | Get-GPOReport -ReportType XML | Select-String -NotMatch "<LinksTo>") {$_.DisplayName}}
    ForEach ($Orphan in $Orphans){
        $orphanOutput += [pscustomobject][ordered]@{
            DisplayName      = $Orphan.Displayname
            DomainName       = $Orphan.DomainName
            Owner            = $Orphan.Owner
            GpoStatus        = $Orphan.GpoStatus
            CreationTime     = $Orphan.CreationTime
            ModificationTime = $Orphan.ModificationTime
            UserVersion      = $Orphan.UserVersion
            ComputerVersion  = $Orphan.ComputerVersion
            WmiFilter        = $Orphan.WmiFilter
            Description      = $Orphan.Description
            Id               = $Orphan.Id
        }
    }
    Return $orphanOutput
}

Function Get-WmiFilters {
    $WMIFilters = @()

    $Domain        = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetDirectoryEntry() | Select-Object -ExpandProperty DistinguishedName
    $search        = new-object System.DirectoryServices.DirectorySearcher([adsi]("LDAP://CN=SOM,CN=WMIPolicy,CN=System,"+$Domain))
    $search.filter = '(objectclass=msWMI-Som)'
    $results       = $search.FindAll()

    $WMIFilters += ForEach ($result in $results) {
        $GUID         = $result.properties.'mswmi-id'
        $NAME         = $result.properties.'mswmi-name'
        $DESCRIPTION  = $result.properties.'mswmi-parm1'
        $AUTHOR       = $result.properties.'mswmi-author'
        $CHANGEDATE   = $result.properties.'mswmi-changedate'
        $CREATIONDATE = $result.properties.'mswmi-creationdate'
        $WQL          = $result.properties.'mswmi-parm2'

        [PSCustomObject]@{
            GUID         = $GUID
            Name         = $NAME
            Description  = $DESCRIPTION
            Author       = $AUTHOR
            ChangeDate   = $CHANGEDATE
            CreationDate = $CREATIONDATE
            WQL          = $WQL
        }
    }
    Return $WMIFilters
}

Function Find-GPOUnknownUsersorGroups {
    $gpoPerms = @()
    Foreach ($GPO in $script:AllGPOObjects){
        Foreach ($Perm in (Get-GPPermissions $GPO.DisplayName -All | Where {$_.Permission -eq "GpoApply"})) {
            $tGPO = $GPO.DisplayName
            $Trus = $Perm.Trustee.Name
            $Perm = $Perm.Permission
            $objC = If ($Trus -ne $null){
                        If ($Trus -eq "Authenticated Users"){"group"} else {(Get-ADObject -LDAPFilter "(SamAccountName=$Trus)").ObjectClass}
                    } else {
                        "NA"
                    }
            If ($Trus -ne 'Authenticated Users'){
                $gpoPerms += [pscustomobject][ordered]@{
                    GPO            = $tGPO
                    SecurityFilter = $Trus
                    ObjectClass    = $ObjC
                    Permission     = $Perm
                }
            }
        }
    }
    Return $gpoPerms
}

Function Find-EmptyGPOs {
    $emptyGpos = @()
    ForEach ($item in $script:AllGPOObjects) {
        If ($item.Computer.DSVersion -eq 0 -and $item.User.DSVersion -eq 0) {
            $emptyGPOs += [pscustomObject][ordered]@{
                DisplayName      = $item.DisplayName
                DomainName       = $item.DomainName
                Owner            = $item.Owner
                CreationTime     = $item.CreationTime
                ModificationTime = $item.ModificationTime
            }
        }
    }
    Return $emptyGpos
}

Function Get-CanName ([string[]]$DistName) {    
    ForEach ($dn in $DistName) {      
        $d = $dn.Split(',') 
        $arr = (@(($d | Where-Object { $_ -notmatch 'DC=' }) | ForEach-Object { $_.Substring(3) }))  ## get parts excluding the parts relevant to the FQDN and trim off the dn syntax 
        [array]::Reverse($arr)  ## Flip the order of the array. 
 
        ## Create and return the string representation in canonical name format of the supplied DN 
        "{0}/{1}" -f  (($d | Where-Object { $_ -match 'dc=' } | ForEach-Object { $_.Replace('DC=','') }) -join '.'), ($arr -join '/') 
    } 
}

Function Get-LinkedPath {
    $Domain        = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetDirectoryEntry() | Select-Object -ExpandProperty DistinguishedName
    $Searcher             = New-Object -TypeName System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot  = "LDAP://$($Domain)"
    $Searcher.SearchScope = "subtree"
    $Searcher.Filter      = "(objectClass=organizationalUnit)"
    $Searcher.PropertiesToLoad.Add('Distinguishedname') | Out-Null
    $LDAP_OUs             = $Searcher.FindAll()
    $OUs                  = $LDAP_OUs.properties.distinguishedname

    $LinkedPaths = @()

    #$LinksTemp = 
    $OUs | 
                 ForEach {(Get-GPInheritance -Target $_).GPOlinks} | 
                 Select-Object -Property Displayname,Target | 
                 Sort-Object -Property DisplayName | 
                 #Group-Object -Property GPOName | 
                 ForEach-Object {$LinkedPaths += [pscustomobject][ordered]@{GPOName = $_.DisplayName;Links = Get-CanName $_.Target}}

    #$LinksTemp | ForEach {$LinkedPaths += [pscustomobject][ordered]@{GPOName=$_.GPOName;Links=Get-CanName $_.Links}}
    $LinkedPaths = $LinkedPaths | Sort-Object -Property Links,GPOName
    Return $LinkedPaths
}
#Get-LinkedPath | OGV

Function Get-GPOTree {
    #https://adamtheautomator.com/get-gporeport-how-to-build-fancy-gpo-reports-with-powershell/
    #https://old.reddit.com/r/PowerShell/comments/b5yf06/parse_xml_from_getgporeport/
    $GpoLinks = @()
    ForEach ($g in $script:AllGPOObjects) {
        [xml]$Gpo = Get-GPOReport -ReportType Xml -Guid $g.Id
        $GPOEnabled = If ($Gpo.DocumentElement.Computer.Enabled -eq 'true' -or $Gpo.DocumentElement.User.Enabled -eq 'true'){"Enabled"} else {"Disabled"}
        If ($Gpo.GPO.LinksTo){
            ForEach ($i in $Gpo.GPO.LinksTo) {
                $GpoLinks += [PSCustomObject][ordered]@{
                    Name           = $Gpo.GPO.Name
                    Enabled        = $GPOEnabled
                    Link           = $i.SOMPath
                    "Link Enabled" = $i.Enabled
                }
            }
        } else {
            $GpoLinks += [PSCustomObject][ordered]@{
                Name           = $Gpo.GPO.Name
                Enabled        = $GPOEnabled
                Link           = 'Not Linked'
                "Link Enabled" = 'NA'
            }
        }
    }
    $GpoLinks = $GpoLinks | Sort-Object -Property Link,Name
    Return $GpoLinks
}

Function Run-Reports {
    Param([switch]$showall)
    If ($showall){
        Find-OrphanedOUs | Sort-Object -Property DisplayName | OGV -Title "Orphaned GPOs"
        Get-WmiFilters | Select-Object -Property Name,Description,Author,@{n='WQL';e={($_.WQL).split(';')[-2]}} | Format-Table -AutoSize
        Find-GPOUnknownUsersorGroups | Sort-Object GPO,SecurityFilter | Out-GridView -Title "GPOs with unknown Users or Groups"
        Find-EmptyGPOs | Sort-Object -Property DisplayName | Out-GridView -Title "GPOs with no settings"
        Get-GPOTree | Sort-Object -Property Link,Name | Out-GridView -Title "GPOs Enabled/Disabled with OU links Endabled/Disabled"
    } else {
        Find-OrphanedOUs | Sort-Object -Property DisplayName | Export-CSV -Path "$($OutputPath)\OrphanedGPOs.csv" -NoTypeInformation
        Find-GPOUnknownUsersorGroups | Sort-Object GPO,SecurityFilter | Export-CSV -Path "$($OutputPath)\GPOsWithUnknownTrustees.csv" -NoTypeInformation
        Find-EmptyGPOs | Sort-Object -Property DisplayName | Export-CSV -Path "$($OutputPath)\GPOsWithNoSettings.csv" -NoTypeInformation
        Get-GPOTree | Sort-Object -Property Link,Name | Export-CSV -Path "$($OutputPath)\GPOs-inTreeForm.csv" -NoTypeInformation
    }
}

Run-Reports
