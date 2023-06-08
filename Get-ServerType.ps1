#Requires -Module ActiveDirectory

Function Find-ADConnectServer {
    <#
        .SYNOPSIS
        Self explanatory.
    #>
    [alias('Find-ADSyncServer')]
    Param( )
    $Description = Get-ADUser -Filter {Name -like 'MSOL*'} -Properties Description | 
                   Select-Object -ExpandProperty Description

    ForEach ($Desc in $Description) {
        $PatternType           = '(?<=(Account created by ))(.*)(?=(with installation identifier))'
        $PatternServerName     = '(?<=(on computer ))(.*)(?=(configured))'
        $PatternTenantName     = '(?<=(to tenant ))(.*)(?=(. This))'
        $PatternInstallationID = '(?<=(installation identifier ))(.*)(?=( running on ))'
        if ($Desc -match $PatternServerName) {
            $ServerName = ($Matches[0]).Replace("'", '').Replace(' ', '')
            If ($Desc -match $PatternTenantName)     {
                $TenantName = ($Matches[0]).Replace("'", '').Replace(' ', '')
            } Else {
                $TenantName = ''
            }
            If ($Desc -match $PatternInstallationID) {
                $InstallationID = ($Matches[0]).Replace("'", '').Replace(' ', '')
            } Else {
                $InstallationID = ''
            }
            If ($Desc -match $PatternType)           {
                $Type = ($Matches[0]).Replace("'", '').Replace('by ', '').Replace('the ', '')
            } Else {
                $Type = ''
            }
            $Data = Get-ADComputer -Identity $ServerName
            [PSCustomObject] @{
                Name              = $Data.Name
                FQDN              = $Data.DNSHostName
                DistinguishedName = $Data.DistinguishedName
                Type              = $Type
                TenantName        = $TenantName
                InstallatioNID    = $InstallationID 
            }
        }
    }
}

Function Find-ServerTypes {
    <#
        .SYNOPSIS
        Find all server types.
        .DESCRIPTION
        Searches AD for servers that host AD Connect, DC, Exchange, Hyper-V, RDS, SQL, VMs, or All.
        .PARAMETER Type
        What kinds of servers are you looking for - the following are valid
          * ADConnect
          * DomainController
          * Exchange
          * Hyper-V
          * RDSLicense
          * SQL
          * VirtualMachine
          * All
        .EXAMPLE
        Find-ServerTypes -Type All
        Returns all servers in domain that can match one of the server types.
    #>
    [cmdletbinding()]
    Param(
        [ValidateSet(
            'All', 
            'ADConnect', 
            'DomainController', 
            'Exchange', 
            'Hyper-V', 
            'RDSLicense', 
            'SQL', 
            'VirtualMachine'
        )]
        [string[]]$Type = 'All'
    )
    $Forest = Get-ADForest
    ForEach ($Domain in $Forest.Domains) {
        Try {
            $DomainInformation = Get-ADDomain -Server $Domain -ErrorAction Stop
        } Catch {
            Write-Warning -Message ("Find-ServerTypes - Domain {0} couldn't be reached. Skipping" -f $Domain)
            Continue
        }
        Try {
            $SPParams = @{
                Filter      = 'ObjectClass -eq "serviceConnectionPoint"'
                Server      = $Domain
                ErrorAction = 'Stop'
            }
            $ServiceConnectionPoint = Get-ADObject @SPParams
            ForEach ($Point in $ServiceConnectionPoint) {  
                $Temporary         = $Point.DistinguishedName.split(',')            
                $DistinguishedName = $Temporary[1..$Temporary.Count] -join ','    
                $Point | Add-Member -MemberType 'NoteProperty' -Name 'DN' -Value $DistinguishedName -Force
            }
        } Catch {
            Write-Error -Message ('Find-ServerTypes - Get-ADObject command failed. Terminating. Error {0}' -f $_)
            Return
        }
        $ADConnect = Find-ADConnectServer
        $CompParms = @{
            Filter     = 'OperatingSystem -like "Windows Server*"'
            Properties = 'Name', 'DNSHostName', 'OperatingSystem', 'DistinguishedName', 'ServicePrincipalName'
            Server     = $Domain
        }
        $Computers = Get-ADComputer @CompParms
        $Servers   = ForEach ($Computer in $Computers) {
            $Services = ForEach ($Service in $Computer.servicePrincipalName) {
                ($Service -split '/')[0]
            }
            [PSCustomObject][ordered] @{
                Name              = $Computer.Name
                FQDN              = $Computer.DNSHostName
                OperatingSystem   = $Computer.OperatingSystem
                DistinguishedName = $Computer.DistinguishedName
                Enabled           = $Computer.Enabled
                IsExchange   = If ($Services -like '*ExchangeMDB*' -or $Services -like '*ExchangeRFR*') {
                    $true
                } Else {
                    $false
                }
                IsSQL        = If ($Services -like '*MSSql*') {
                    $true
                } Else {
                    $false
                }
                IsVM         = If (
                    $ServiceConnectionPoint.DN -eq $Computer.DistinguishedName -and 
                    $ServiceConnectionPoint.Name -eq 'Windows Virtual Machine'
                ) {
                    $true
                } Else {
                    $false
                }
                IsHyperV     = If ($Services -like '*Hyper-V Replica*') {
                    $true
                } Else {
                    $false
                }
                IsSPHyperV   = If (
                    $ServiceConnectionPoint.DN -eq $Computer.DistinguishedName -and 
                    $ServiceConnectionPoint.Name -eq 'Microsoft Hyper-V'
                ) {
                    $true
                } Else {
                    $false
                }
                IsRDSLicense = If (
                    $ServiceConnectionPoint.DN -eq $Computer.DistinguishedName -and 
                    $ServiceConnectionPoint.Name -eq 'TermServLicensing'
                ) {
                    $true
                } Else {
                    $false
                }
                #IsDC        = If (
                #    $Services -like '*ldap*' -and 
                #    $Services -like '*DNS*'
                #) {
                #    $true
                #} Else {
                #    $false
                #}
                IsDC         = If ($DomainInformation.ReplicaDirectoryServers -contains $Computer.DNSHostName) {
                    $true
                } Else {
                    $false
                }
                IsADConnect   = If ($ADConnect.FQDN -eq $Computer.DNSHostName) {
                    $true
                } Else {
                    $false
                }
                Forest                 = $Forest.Name
                Domain                 = $Domain
                ServicePrincipalName   = ($Services | Sort-Object -Unique) -Join ','
                ServiceConnectionPoint = (
                    $ServiceConnectionPoint | 
                    Where-Object { $_.DN -eq $Computer.DistinguishedName }
                ).Name -join ','
            }
        }
        If ($Type -eq 'All') {
            $Servers
        } Else {
            If ($Type -contains 'SQL')              {
            $Servers | Where-Object {$_.IsSQL -eq $true}
            }
            If ($Type -contains 'Exchange' )        {
                $Servers | Where-Object {$_.IsExchange -eq $true}
            }
            If ($Type -contains 'Hyper-V')          {
                $Servers | Where-Object {$_.IsHyperV -eq $true -or $_.IsSPHyperV -eq $true}
            }
            If ($Type -contains 'VirtualMachine')   {
                $Servers | Where-Object {$_.IsVM -eq $true}
            }
            If ($Type -contains 'RDSLicense')       {
                $Servers | Where-Object {$_.IsRDSLicense -eq $true}
            }
            If ($Type -contains 'DomainController') {
                $Servers | Where-Object {$_.IsDC -eq $true}
            }
            If ($Type -contains 'DomainController') {
                $Servers | Where-Object {$_.IsDC -eq $true}
            }
            If ($Type -contains 'ADConnect')        {
                $Servers | Where-Object {$_.IsADConnect -eq $true}
            }
        }
    }
}

$SQL = Find-ServerTypes -Type All
$SQL | Out-GridView -Title "$($SQL.Count) Results"
#$SQL | Export-CSV -Path "C:\down\ServerTypes_011123.csv" -Encoding UTF8 -Delimiter ','
