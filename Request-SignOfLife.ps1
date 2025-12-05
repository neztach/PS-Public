Function Request-SignOfLife {
    <#
        .SYNOPSIS
        Checks network/AD info for one or more computers or IPs.

        .DESCRIPTION
        Accepts:
        - Names/IPs (arrays or pipeline)
        - Active Directory computer objects from Get-ADComputer

        If both ComputerName and IPAddress are provided with the same length,
        they are paired by index. Otherwise, each provided name/IP is tested
        independently. If no IP can be resolved, continues with name-only.

        .PARAMETER ComputerName
        One or more hostnames/FQDNs/NetBIOS names or IPs.

        .PARAMETER IPAddress
        One or more IPv4 addresses (optional). Can be $null.

        .PARAMETER ADComputer
        One or more [ADComputer] objects, e.g.
        Get-ADComputer ... | Request-SignOfLife

        .PARAMETER Raw
        Emit raw PSCustomObjects to the pipeline instead of fdns-style
        colored/spacing host output. By default, pretty output is shown.

        .EXAMPLE
        Request-SignOfLife -ComputerName server01,server02

        .EXAMPLE
        'server01','10.0.0.5' | Request-SignOfLife

        .EXAMPLE
        Request-SignOfLife -ComputerName server01,server02 -IPAddress 10.0.0.10,10.0.0.11

        .EXAMPLE
        Get-ADComputer -Filter "OperatingSystem -like '*Windows Server*'" -Properties IPv4Address,OperatingSystem,DistinguishedName |
            Request-SignOfLife
        Get-ADComputer ... | Request-SignOfLife -Raw   # raw objects
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByNameOrIP')]
    [OutputType([pscustomobject])]
    [Alias('sol','alive?')]
    Param (
        ### Normal name/IP usage
        [Parameter(ParameterSetName='ByNameOrIP',Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias('DNSHostName','Name')]
        [string[]]$ComputerName,

        [Parameter(ParameterSetName='ByNameOrIP',Position=1,ValueFromPipelineByPropertyName)]
        [AllowNull()]
        [string[]]$IPAddress,

        ### ADComputer pipeline support
        [Parameter(ParameterSetName='ByADComputer',ValueFromPipeline)]
        [Microsoft.ActiveDirectory.Management.ADComputer[]]$ADComputer,

        ### Raw output instead of pretty
        [switch]$Raw
    )

    Begin {
        ### Basic IPv4 sanity regex
        $script:ipRegex = '^\d{1,3}(\.\d{1,3}){3}$'

        ### Check if RSAT Tools are installed
        $script:ADAvailable = $false
        Try {
            If (Get-Command -Name Get-ADComputer -ErrorAction Stop) { $script:ADAvailable = $true }
        } Catch {
            $script:ADAvailable = $false
        }

        ### Service ports to probe
        $script:servicePorts = @{
            21   = 'FTP'
            22   = 'SSH'
            23   = 'Telnet'
            53   = 'DNS'
            80   = 'HTTP'
            123  = 'NTP'
            135  = 'RPC'
            139  = 'NetBIOS-SSN'
            161  = 'SNMP'
            222  = 'RSH-SPX'
            389  = 'LDAP'
            443  = 'HTTPS'
            445  = 'SMB'
            502  = 'Modbus'
            554  = 'RTSP'
            1433 = 'SQL'
            2179 = 'VMConnect'
            3389 = 'RDP'
            5985 = 'WinRMHTTP'
            5986 = 'WinRMHTTPS'
            8000 = 'HTTPAlt'
            8080 = 'HTTP8080'
            8443 = 'HTTPSAlt'
            9100 = 'Printer'
        }

        #region Helper Functions
        Function Test-Port       {
            <#
                .SYNOPSIS
                Test if port is open or closed
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory,HelpMessage='Computer Target')]
                [string]$Target,
                [Parameter(Mandatory,HelpMessage='Port')]
                [int]$Port
            )

            Write-Verbose -Message ('Testing port {0} on {1}...' -f $Port, $Target)

            Try {
                $tcpClient   = New-Object -TypeName Net.Sockets.TcpClient
                $asyncResult = $tcpClient.BeginConnect($Target, $Port, $null, $null)

                If ($asyncResult.AsyncWaitHandle.WaitOne(500)) {
                    $tcpClient.EndConnect($asyncResult)
                    $tcpClient.Close()
                    return $true
                }
                $tcpClient.Close()
            } Catch {
                If ($tcpClient) {
                    $tcpClient.Close()
                }
                return $false
            }

            return $false
        }

        Function Get-NetworkProfileFromPorts {
            <#
                .SYNOPSIS
                Best-effort guess if this looks like a network device based on port response.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory,HelpMessage='Port Results')]
                [hashtable]$PortResults,

                [Parameter(Mandatory,HelpMessage='Service Ports')]
                [hashtable]$ServicePorts
            )

            $ssh   = [bool]$PortResults['SSH']
            $tel   = [bool]$PortResults['Telnet']
            $ftp   = [bool]$PortResults['FTP']
            $http  = [bool]$PortResults['HTTP']
            $https = [bool]$PortResults['HTTPS']
            $snmp  = [bool]$PortResults['SNMP']

            $smb   = [bool]$PortResults['SMB']
            $rpc   = [bool]$PortResults['RPC']
            $rdp   = [bool]$PortResults['RDP']

            ### Heuristic:
            ### - One or more of: SSH / Telnet / SNMP / HTTP / HTTPS / FTP open
            ### - None of the Windows-y ports open: SMB/RPC/RDP
            $mgmtOpen   = $ssh -or $tel -or $snmp -or $http -or $https -or $ftp
            $windowsish = $smb -or $rpc -or $rdp

            If (-not $mgmtOpen -or $windowsish) { return $null }

            ### Narrow ports we care about when probing a "Network" device
            $networkPorts = 21,22,23,80,443,161,8000,8080,8443
            $ports = $networkPorts | Where-Object { $ServicePorts.ContainsKey($_) } | Sort-Object

            return [pscustomobject]@{
                Profile           = 'Network'
                Ports             = $ports
                OperatingSystem   = $null
                DistinguishedName = $null
                OU                = $null
            }
        }

        Function Get-PortProfile {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory,HelpMessage='AD Computer Object')]
                [Microsoft.ActiveDirectory.Management.ADComputer]$ADComputerObject,

                [Parameter(Mandatory,HelpMessage='Service Ports')]
                [hashtable]$ServicePorts
            )

            If (-not $script:ADAvailable) {
                return [pscustomobject]@{
                    Profile           = 'Unknown'
                    Ports             = $ServicePorts.Keys
                    OperatingSystem   = $null
                    DistinguishedName = $null
                    OU                = $null
                }
            }

            $os   = $ADComputerObject.OperatingSystem
            $dn   = $ADComputerObject.DistinguishedName
            $name = $ADComputerObject.Name

            ### Default
            $role = 'Workstation'

            ### Role detection
            If ($dn -match 'OU=Domain Controllers') {
                $role = 'DC'
            } ElseIf ($name -match '(?i)SQL|DB|MSSQL') {
                $role = 'SQL'
            } ElseIf ($name -match '(?i)RDS|RD-|TERM|TS-') {
                $role = 'RDS'
            } ElseIf (
                ($name -match '(?i)HV-|HYPERV|HYPV|-core0|vhost') -or 
                ($os -match '(?i)hyper-?v')
            ) {
                $role = 'HyperV'
            } ElseIf ($name -match 'nsi') {
                $role = 'Nasuni'
            } ElseIf ($os -match '(?i)server') {
                $role = 'Server'
            } Else {
                $role = 'Workstation'
            }

            ### Port sets per profile (port numbers)
            $profilePortSets = @{
                'DC'          = 53,88,135,389,445,464,5722,9389,5985,5986
                'SQL'         = 135,1433,1434,445,80,443,5985,5986
                'RDS'         = 3389,135,445,80,443,5985,5986
                'HyperV'      = 135,445,3389,80,443,2179,5985,5986
                'Nasuni'      = 21,22,80,135,139,222,443,445,8443
                'Server'      = 135,445,80,443,3389,5985,5986
                'Workstation' = 135,445,80,443,5985,5986
            }

            $ports = $profilePortSets[$role]

            ### Fallback: if we don't have a defined set, use the full servicePorts
            If (-not $ports) {
                $role  = 'Custom'
                $ports = $ServicePorts.Keys
            }

            ### Keep only ports we actually know about and sort them
            $ports = $ports | Where-Object { $ServicePorts.ContainsKey($_) } | Sort-Object

            ### Extract OU from DN (everything after the CN= part)
            $ou = $null
            If ($dn) { $ou = ($dn -replace '^CN=[^,]+,','') }

            [pscustomobject]@{
                Profile           = $role
                Ports             = $ports
                OperatingSystem   = $os
                DistinguishedName = $dn
                OU                = $ou
            }
        }

        Function Test-OneTarget  {
            <#
                .SYNOPSIS
                Test name or IP
            #>
            [CmdletBinding()]
            Param(
                [AllowNull()]
                [string]$NameOrNull,

                [AllowNull()]
                [string]$IPOrNull,

                ### Optional: if we already have the AD object, don't look it up again
                [Microsoft.ActiveDirectory.Management.ADComputer]$ADComputerObject
            )

            If (-not $NameOrNull -and -not $IPOrNull) {
                throw 'Test-OneTarget: you must provide at least a NameOrNull or an IPOrNull.'
            }

            $ComputerNameLocal = $NameOrNull
            $IPAddressLocal    = $IPOrNull
            $ipResolved        = $false

            If (-not $IPAddressLocal -and $ComputerNameLocal) {
                #region If only a name was given, try to resolve A record; keep going if it fails
                If ($ComputerNameLocal -match $script:ipRegex) {
                    ### Name is actually an IP
                    $IPAddressLocal = $ComputerNameLocal
                    Try {
                        $ptr = Resolve-DnsName -Name $ComputerNameLocal -Type PTR -ErrorAction Stop
                        $ComputerNameLocal = $ptr.NameHost
                    } Catch {
                        $mesg = ('No PTR hostname found for IP {0}. Continuing with IP as the name.' -f $ComputerNameLocal)
                        Write-Verbose -Message $mesg
                    }
                    $ipResolved = $true
                } Else {
                    Try {
                        $a = Resolve-DnsName -Name $ComputerNameLocal -Type A -ErrorAction Stop

                        $ipRecord = $a | Where-Object { $_.PSObject.Properties['IPAddress'] -and $_.IPAddress } | Select-Object -First 1

                        If ($ipRecord) {
                            $IPAddressLocal = $ipRecord.IPAddress
                            Write-Verbose -Message ('Resolved IP Address: {0}' -f $IPAddressLocal)
                            $ipResolved = $true
                        } Else {
                            $mesg = ('Resolve-DnsName returned no A records with an IPAddress for {0}. Proceeding with name-only tests.' -f $ComputerNameLocal)
                            Write-Verbose -Message $mesg
                            $IPAddressLocal = $null
                            $ipResolved     = $false
                        }
                    } Catch {
                        $mesg = ('No IP address could be resolved for {0}. Proceeding with name-only tests.' -f $ComputerNameLocal)
                        Write-Verbose -Message $mesg
                        $IPAddressLocal = $null
                        $ipResolved     = $false
                    }
                }
                #endregion If only a name was given, try to resolve A record; keep going if it fails
            } Elseif ($IPAddressLocal) {
                $ipResolved = $true

                ### If only IP provided and no name, try PTR (best-effort)
                If (-not $ComputerNameLocal) {
                    Try {
                        $ptr = Resolve-DnsName -Name $IPAddressLocal -Type PTR -ErrorAction Stop
                        $ComputerNameLocal = $ptr.NameHost
                    } Catch {
                        $ComputerNameLocal = $IPAddressLocal
                    }
                }
            }

            #region AD lookup (reuse existing object if provided)
            ### Base name for AD lookup
            $BaseComputerName = If ($ComputerNameLocal -and $ComputerNameLocal -like '*.*') {
                $ComputerNameLocal.Split('.')[0]
            } Else {
                $ComputerNameLocal
            }

            $portProfile    = $null
            $adObjectExists = $false
            $adComputerIP   = $null

            If (-not $script:ADAvailable) {
                Write-Verbose -Message 'ActiveDirectory module unavailable; skipping AD lookup.'
            } ElseIf ($ADComputerObject) {
                $adObjectExists = $true

                ### Try to pull an IPv4Address from the object if present
                $ipv4Prop = $ADComputerObject.PSObject.Properties['IPv4Address']
                If ($ipv4Prop -and $ipv4Prop.Value) { $adComputerIP = $ipv4Prop.Value }

                ### Build port profile from the AD object we already have
                $portProfile = Get-PortProfile -ADComputerObject $ADComputerObject -ServicePorts $script:servicePorts
            } ElseIf ($BaseComputerName) {
                Try {
                    Write-Verbose -Message ('AD Lookup: {0}' -f $BaseComputerName)
                    $adComputerObject = Get-ADComputer -Identity $BaseComputerName -Properties IPv4Address, OperatingSystem, DistinguishedName -ErrorAction Stop
                    $adObjectExists   = $true
                    $adComputerIP     = $adComputerObject.IPv4Address

                    ### Build port profile from the looked-up object
                    $portProfile = Get-PortProfile -ADComputerObject $adComputerObject -ServicePorts $script:servicePorts
                } Catch {
                    $adObjectExists = $false
                    $adComputerIP   = $null
                    $portProfile    = $null
                }
            }
            #endregion AD lookup (reuse existing object if provided)

            #region Test Ping (name if no IP)
            $pingTarget = If ($IPAddressLocal -and $ComputerNameLocal -ne $IPAddressLocal) {
                $IPAddressLocal
            } Else {
                $ComputerNameLocal
            }

            ### Make sure we only ever test a single target
            If ($pingTarget -is [array]) {$pingTarget = $pingTarget[0]}

            Try {
                If ($pingTarget) {
                    $pingSuccess = Test-Connection -ComputerName $pingTarget -Count 2 -Quiet -ErrorAction Stop
                } Else {
                    $pingSuccess = $false
                }
            } Catch {
                $pingSuccess = $false
            }
            Write-Verbose -Message ('Ping result: {0}' -f $pingSuccess)
            #endregion Test Ping

            #region Port testing target (IP preferred; name ok)
            $connectionTarget = If ($IPAddressLocal) { $IPAddressLocal } Else { $ComputerNameLocal }

            $portTestResults = @{}

            ### Decide which ports to test
            $portsToTest = If ($portProfile -and $portProfile.Ports) {
                $portProfile.Ports
            } Else {
                $script:servicePorts.Keys
            }

            If ($connectionTarget) {
                ForEach ($port in $portsToTest) {
                    $label = $script:servicePorts[$port]
                    $portTestResults[$label] = Test-Port -Target $connectionTarget -Port $port
                }
            } Else {
                ForEach ($port in $portsToTest) {
                    $label = $script:servicePorts[$port]
                    $portTestResults[$label] = $false
                }
            }

            ### Ensure every service in $servicePorts exists as a property (untested => $false)
            ForEach ($kv in $script:servicePorts.GetEnumerator()) {
                $label = $kv.Value
                If (-not $portTestResults.ContainsKey($label)) {
                    $portTestResults[$label] = $false
                }
            }
            #endregion Port testing target (IP preferred; name ok)

            ### If we don't have an AD-derived profile, see if it smells like a network device
            If (-not $portProfile) {
                $netProfile = Get-NetworkProfileFromPorts -PortResults $portTestResults -ServicePorts $script:servicePorts
                If ($netProfile) { $portProfile = $netProfile }
            }

            ### Sign of life
            $signOfLife = If ($pingSuccess -or ($portTestResults.Values -contains $true)) { $true } Else { $false }

            #region Build result object
            $resultObject = [pscustomobject]@{
                Name        = $ComputerNameLocal
                IP          = $IPAddressLocal
                IPResolved  = [bool]$ipResolved
                SignOfLife  = $signOfLife
                ADObject    = $script:ADAvailable -and $adObjectExists
                ADIP        = $adComputerIP
                Ping        = $pingSuccess
                PortProfile = If ($portProfile) { $portProfile.Profile } Else { $null }
                ADOS        = If ($script:ADAvailable -and $portProfile) { $portProfile.OperatingSystem } Else { $null }
                ADOU        = If ($script:ADAvailable -and $portProfile) { $portProfile.OU } Else { $null }
            }

            ForEach ($entry in $portTestResults.GetEnumerator()) {
                $resultObject.PSObject.Properties.Add(
                    [psnoteproperty]::new($entry.Key, $entry.Value)
                )
            }
            #endregion Build result object

            return $resultObject
        }

        Function Out-Formatted   {
            <#
                .SYNOPSIS
                Helper for Write-Host
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory,HelpMessage='Message')]
                [string]$msg, 
                [switch]$n, 
                [switch]$c, 
                [switch]$g, 
                [switch]$r
            )
            $w = @{ Object = $msg }
            If ($n) { $w.NoNewLine = $true }
            If ($c) {
                $w.ForegroundColor = 'Cyan'
            } ElseIf ($g) {
                $w.ForegroundColor = 'Green'
            } ElseIf ($r) {
                $w.ForegroundColor = 'Red'
            }
            Write-Host @w
        }

        Function Show-Pretty     {
            <#
                .SYNOPSIS
                Helper for prettified output
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory,HelpMessage='Line')]
                [string]$line, 
                [Parameter(Mandatory=$true,HelpMessage='Boolean')]
                [bool]$v, 
                [switch]$n
            )
            Out-Formatted -msg ('{0}' -f $line) -n -c
            If ($n) {
                If ($v) { Out-Formatted -msg 'Yes' -g } Else { Out-Formatted -msg 'No ' -r }
            } Else {
                If ($v) { Out-Formatted -msg 'Yes' -n -g } Else { Out-Formatted -msg 'No ' -n -r }
            }
        }
        #endregion Helper Functions

        ### Accumulators (for Name/IP mode and for pretty output)
        $pipelineNames = New-Object -TypeName System.Collections.Generic.List[string]
        $pipelineIPs   = New-Object -TypeName System.Collections.Generic.List[object]
        $allResults    = New-Object -TypeName System.Collections.Generic.List[object]
        $adList        = New-Object -TypeName System.Collections.Generic.List[object]
    }
    Process {
        If ($PSCmdlet.ParameterSetName -eq 'ByADComputer') {
            ForEach ($ad in $ADComputer) {
                If (-not $ad) { continue }
                $null = $adList.Add($ad)
            }
        } Else {
            ### Original name/IP collection behavior
            If ($PSBoundParameters.ContainsKey('ComputerName') -and $ComputerName) {
                ForEach ($n in $ComputerName) {
                    If ($null -ne $n -and $n -ne '') {
                        $null = $pipelineNames.Add($n)
                    }
                }
            }
            If ($PSBoundParameters.ContainsKey('IPAddress')) {
                ForEach ($ip in $IPAddress) {
                    If ($null -ne $ip -and $ip -ne '') {
                        If ($ip -notmatch $script:ipRegex) {
                            throw ('Invalid IP address format: {0}' -f $ip)
                        }
                    }
                    $null = $pipelineIPs.Add($ip)
                }
            }
        }
    }
    End {
        If ($PSCmdlet.ParameterSetName -eq 'ByADComputer') {
            $total = $adList.Count
            $Act   = 'Request-SignOfLife (ADComputer)'
            If ($total -eq 0) { return }

            For ($i = 0; $i -lt $total; $i++) {
                $ad = $adList[$i]
                If (-not $ad) { continue }

                ### Prefer DNSHostName when available
                $name = If ($ad.DNSHostName) { $ad.DNSHostName } Else { $ad.Name }

                ### IPv4 if the property exists & has a value
                $ipv4Prop = $ad.PSObject.Properties['IPv4Address']
                $ip = If ($ipv4Prop -and $ipv4Prop.Value) { $ipv4Prop.Value } Else { $null }

                If ($total -gt 1) {
                    $pct = [int](($i + 1) / $total * 100)
                    $stat = ('{0}/{1}: {2}' -f ($i + 1), $total, $name)
                    Write-Progress -Activity $Act -Status $stat -PercentComplete $pct
                }

                $result = Test-OneTarget -NameOrNull $name -IPOrNull $ip -ADComputerObject $ad
                $null   = $allResults.Add($result)
                If ($Raw) { Write-Output -InputObject $result }
            }

            If ($total -gt 1) {
                Write-Progress -Activity $Act -Completed
            }
        } Else {
            $names     = $pipelineNames.ToArray()
            $ips       = $pipelineIPs.ToArray()

            $haveNames = $names.Count -gt 0
            $haveIPs   = $ips.Count   -gt 0

            If (-not $haveNames -and -not $haveIPs) {
                throw 'You must provide at least one ComputerName or IPAddress.'
            }

            ### Build unified target list for progress + processing
            $targets = New-Object -TypeName System.Collections.Generic.List[object]
        
            ### Case 1: both provided and same count -> pair by index
            If ($haveNames -and $haveIPs -and ($names.Count -eq $ips.Count)) {
                For ($i=0; $i -lt $names.Count; $i++) {
                    $null = $targets.Add(
                        [pscustomobject]@{
                            Name = $names[$i]
                            IP   = $ips[$i]
                        }
                    )
                }
            } Else {
                ### Case 2: names only (or names + mismatched IP count) -> process names independently
                If ($haveNames) {
                    ForEach ($n in $names) {
                        $null = $targets.Add(
                            [pscustomobject]@{
                                Name = $n
                                IP   = $null
                            }
                        )
                    }
                }
                ### Case 3: IPs only (or extra IPs when counts differ) -> process IPs independently
                If ($haveIPs -and (-not $haveNames -or $names.Count -ne $ips.Count)) {
                    ForEach ($ip in $ips) {
                        $null = $targets.Add(
                            [pscustomobject]@{
                                Name = $null
                                IP   = $ip
                            }
                        )
                    }
                }
            }

            $total = $targets.Count
            For ($i = 0; $i -lt $total; $i++) {
                $t = $targets[$i]

                If ($total -gt 1) {
                    $dispName = If ($t.Name) { $t.Name } ElseIf ($t.IP) { $t.IP } Else { '<null>' }
                    $pct   = [int](($i + 1) / $total * 100)
                    $stat  = ('{0}/{1}: {2}' -f ($i + 1), $total, $dispName)
                    Write-Progress -Activity 'Request-SignOfLife' -Status $stat -PercentComplete $pct
                }

                $result = Test-OneTarget -NameOrNull $t.Name -IPOrNull $t.IP
                $null   = $allResults.Add($result)
                If ($Raw) { Write-Output -InputObject $result }
            }

            If ($total -gt 1) {
                Write-Progress -Activity 'Request-SignOfLife' -Completed
            }
        }

        ### Pretty / Colored output (optional)
        If (-not $Raw -and $allResults.Count -gt 0) {
            #region De-duplicate results for display (NetBIOS + FQDN, etc.)
            $displayResults = New-Object -TypeName 'System.Collections.Generic.List[object]'
            $seen           = @{}

            ForEach ($r in $allResults) {
                $baseName = If ($r.Name) { ($r.Name.Split('.')[0]).ToUpperInvariant() } Else { '' }
                $ipKey    = If ($r.IP) { $r.IP } Else { '' }
                $key      = '{0}|{1}' -f $baseName, $ipKey
                If (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    [void]$displayResults.Add($r)
                }
            }

            If ($displayResults.Count -eq 0) { return }
            #endregion De-duplicate results for display

            ### Compute column widths
            $nameWidth = ($displayResults.Name | Measure-Object -Maximum -Property Length).Maximum
            If (-not $nameWidth) { $nameWidth = 4 }

            $ipWidth = ($displayResults.IP | Measure-Object -Maximum -Property Length).Maximum
            If (-not $ipWidth) { $ipWidth = 2 }

            $profileWidth = ($displayResults.PortProfile | Measure-Object -Maximum -Property Length).Maximum + 3
            If (-not $profileWidth) { $profileWidth = 8 }

            $fName    = ('{{0,-{0}}} : ' -f $nameWidth)
            $fIP      = ('{{0,-{0}}} | ' -f $ipWidth)
            $fProfile = ('[ {{0,-{0}}} ] ' -f $profileWidth)

            ForEach ($r in $displayResults) {
                $nameText    = If ($r.Name) { $r.Name } Else { '<no-name>' }
                $ipText      = If ($r.IP) { $r.IP } Else { '-' }
                $profileText = If ($r.PortProfile) { $r.PortProfile } Else { 'Unknown' }

                ### Which ports responded?
                $up = @()
                ForEach ($port in ($script:servicePorts.Keys | Sort-Object)) {
                    $label = $script:servicePorts[$port]
                    If ($r.PSObject.Properties[$label] -and $r.$label) { $up += $label }
                }
                $portsText = If ($up.Count -gt 0) { $up -join ', ' } Else { '<none>' }

                ### Base Fields
                Out-Formatted -msg ($fName    -f $nameText)    -n
                Out-Formatted -msg ($fIP      -f $ipText)      -n -c
                Out-Formatted -msg ($fProfile -f $profileText) -n

                ### AD + Ping + SoL
                Show-Pretty -line '| AD: ' -v ([bool]$r.ADObject)
                Show-Pretty -line ' -- Ping: ' -v ([bool]$r.Ping)
                Show-Pretty -line ' -- SignOfLife: ' -v ([bool]$r.SignOfLife)

                ### Ports summary
                Out-Formatted -msg (' -- Ports: (') -n -c
                Out-Formatted -msg ($portsText) -n
                Out-Formatted -msg (')') -c
            }
        }
    }
}
