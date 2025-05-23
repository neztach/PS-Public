Function Get-MassRename {
    <#
        .SYNOPSIS
        Performs a bulk DNS A and PTR record validation and correction across a list of server entries.

        .DESCRIPTION
        The Get-MassRename function automates the enforcement of DNS integrity across a list of server entries, where each line contains a hostname and an IP address.
        The input is provided as a raw multiline string, with each line containing two values separated by either tab(s), comma(s), or spaces.
        The function performs the following operations for each entry:

        - Parses each line into a [PSCustomObject] using Convert-ToServerList
        - Resolves candidate FQDNs for each hostname
        - Verifies and corrects A records using Update-ARecord
        - Verifies and corrects PTR records using Update-PTRRecord
        - Creates missing reverse zones using Get-ReverseZone if configured
        - Logs actions to the $script:Summary object and shows final DNS state using Confirm-FinalDnsState

        The function honors WhatIf mode and dynamically determines the PDC Emulator to target DNS changes consistently.

        .PARAMETER List
        A raw multiline string where each line contains a hostname and an IP address separated by tab(s), comma(s), or spaces.
        The function auto-detects which field is the IP using Get-IPValid. Fields are trimmed, and hostnames are converted to uppercase.

        .EXAMPLE
        $raw = @'
        SI-IT001	10.10.1.1
        10.10.1.2,SI-IT002
        si-it003     10.10.1.3
        bad entry here
        '@
        Get-MassRename -List $raw

        Parses the list, processes valid records, updates DNS as needed, and shows a summary.

        .OUTPUTS
        None directly. Writes formatted output to console and tracks actions in the global $script:Summary variable.

        .NOTES
        ROLE  : DNS normalization and conflict correction for Azure-migrated virtual machines

        PURPOSE
        -------
        This function was built specifically for use during **VM migration from vCenter to Microsoft Azure**.

        As VMs are replatformed from on-prem VMware infrastructure to Azure, they are assigned **new IP 
        addresses**. To maintain internal name resolution integrity, **on-premises DNS records must be 
        updated** to reflect these new Azure IPs. This script **automates and validates** the update of 
        both forward (A) and reverse (PTR) records for each machine.

        It operates by accepting a flexible list of machine names and new IP addresses, resolving potential 
        conflicts, enforcing DNS corrections, and logging every action for traceability.

        KEY CAPABILITIES
        ----------------
        • Bulk Input Parsing
          - Accepts a freeform multiline string of Name ↔ IP mappings
          - Handles input lines with inconsistent delimiters (spaces, tabs, commas)
          - Auto-detects which value is the IP using `Get-IPValid`
          - Trims, uppercases, and normalizes input for reliable downstream logic

        • DNS A Record Enforcement
          - Ensures each hostname resolves to the expected (Azure-assigned) IP
          - Detects and reports when IPs are **shared across multiple FQDNs**
          - Interactively resolves A record conflicts (continue, skip, or remove other records)
          - Replaces stale A records if the IP is wrong or multiple records exist

        • PTR Record Enforcement
          - Ensures each Azure IP has a correct reverse DNS (PTR) entry
          - Creates missing PTRs or replaces incorrect ones
          - Handles PTR record conflicts interactively (update, remove others, skip)
          - Automatically **creates reverse DNS zones** if missing (optional, controlled via `$script:CreateMissingZones`)

        • Preloading and Caching
          - Caches:
            - All A records across all forward zones (`$script:AllARecords`)
            - All manually-created reverse lookup zones (`$script:ReverseLookupZones`)
            - Forward DNS lookups (Resolve-DnsName results)
            - Reverse DNS lookups (PTR queries)
          - Reduces redundant DNS queries and accelerates batch processing

        • Conflict Detection and Logging
          - Detects:
            - Multiple FQDNs using the same IP (shared IP conflicts)
            - FQDNs resolving to multiple IPs (ambiguous FQDNs)
            - PTR records pointing to incorrect FQDNs
          - Logs each class of issue to `$script:Summary`, displayed and exported at the end
          - Generates CSVs for:
            - Shared IPs: `$env:TEMP\MassRename_SharedIPs.csv`
            - PTR conflicts: `$env:TEMP\MassRename_PTRConflicts.csv`

        • Final Verification and Reporting
          - Displays a **color-coded table** summarizing the DNS state for all processed entries:
            - [OK]           A and PTR records are correct
            - [!] Mismatch   A record or PTR is incorrect
            - [X] Missing    Record not found
          - Tracks created zones, updated records, skipped items, and duplicate mappings
          - Final pass uses cached and live resolution to validate outcome

        • WhatIf & TestMode Simulation
          - `$TestMode = $true` globally enables:
            - `$WhatIfPreference = $true` (simulation)
            - Zone creation suppression
          - `Show-WhatIfSummary` provides a full breakdown of what **would** have been changed
          - No records are updated unless TestMode is disabled

        • Utility Functions
          - `Split-FQDNIntoZoneAndHost` → cleanly extracts zone and host label from any FQDN
          - `Get-CandidateFqdnsFromEntry` → generates likely FQDNs for a given name
          - `Get-CachedARecordByFQDN` and `Get-CachedForwardLookup` → reduce lookup duplication
          - `Get-SharedIPConflicts` and `Get-FQDNReuseConflicts` → surface integrity problems
          - `Export-ConflictReports` → clean export of key findings for external analysis

        REQUIREMENTS
        ------------
        • PowerShell 5.1
        • Must be run with administrator privileges
        • ActiveDirectory and DnsServer modules installed and available
        • Intended for use in **on-prem environments** managing DNS for hybrid workloads
        • All DNS actions target the domain PDC Emulator by default, unless manually overridden

        LIMITATIONS
        -----------
        • IPv4 only (no IPv6 or AAAA support)
        • Does not manage TTL, SOA, NS, or other DNS record types
        • Conflict prompts are interactive - script is not designed for unattended execution (yet)
        • Assumes provided host ↔ IP mappings are authoritative and trusted
        • Does not natively interface with Azure DNS or validate against Azure metadata

        REAL-WORLD USE CASE
        -------------------
        Designed for teams migrating hundreds of servers from vCenter to Azure who must ensure that internal 
        applications, scripts, and AD services still resolve these VMs correctly using **new Azure IPs**. 
        Prevents stale DNS, broken reverse lookups, and split-brain resolution.

        EXAMPLE
        -------
        $raw = @'
        SI-APP01    10.50.101.11
        10.50.101.12,SI-APP02
        si-web03     10.50.101.13
        '@

        Get-MassRename -List $raw

        This will validate and update the A and PTR records for these three servers using their Azure IPs, ensuring DNS is accurate post-migration.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param (
        [Parameter(Mandatory=$true,HelpMessage='Array of Names and IPs')]
        [string]$List, 

        [Parameter(Mandatory=$false, HelpMessage='Target DNS server (optional)')]
        [string]$DnsServer
    )

    $script:stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Import-Module -Name DnsServer
    Import-Module -Name ActiveDirectory

    #region Runtime Variables
    #region Colors and Strings
    $Y = 'Yellow'
    $script:Gr = @{ForegroundColor = 'Green'     }
    $script:Ma = @{ForegroundColor = 'Magenta'   }
    $script:Gy = @{ForegroundColor = 'Gray'      }
    $script:Ye = @{ForegroundColor = $Y          }
    $script:Re = @{ForegroundColor = 'Red'       }
    $script:DY = @{ForegroundColor = 'DarkYellow'}
    $script:Cy = @{ForegroundColor = 'Cyan'      }
    $script:WI = @{
        ForegroundColor = 'Black'
        BackgroundColor = $Y
    }

    $script:EA0 = @{ErrorAction = 'Stop'}
    $script:EA1 = @{ErrorAction = 'SilentlyContinue'}

    $script:ForwardCache = @{}
    $script:ReverseCache = @{}
    #endregion Colors and Strings

    #region Enable WhatIf simulation mode globally if desired
    $TestMode                  = $false
    $WhatIfPreference          = $false
    $script:CreateMissingZones = $true
    If ($TestMode) {
        $WhatIfPreference          = $true
        $script:CreateMissingZones = $false
    }
    If ($WhatIfPreference) {
        Write-Host ('[i] Running in WHATIF mode (TestMode = {0})' -f $TestMode) @script:WI
    }
    #endregion Enable WhatIf simulation mode globally if desired

    ### Initialize summary tracking
    $script:Summary = [ordered]@{
        CreatedZones      = @()
        MissingZones      = @()
        UpdatedARecords   = @()
        UpdatedPTRRecords = @()
        SkippedPTR        = @()
        PTRConflicts      = @()
        SharedIPs         = @()
        FQDNConflicts     = @()
    }
    #endregion Runtime Variables

    ### Step 1: Discover the PDC Emulator and verify DNS services
    If (-not $DnsServer) {
        $DnsServer = (Get-ADDomainController -Filter {OperationMasterRoles -like 'PDCE*'}).HostName
        Write-Host ('[i] No DNS server specified. Using PDC Emulator: {0}' -f $DnsServer) @script:Gy
    } Else {
        Write-Host ('[i] Using specified DNS server: {0}' -f $DnsServer) @script:Gy
    }

    $script:DnsServer = $DnsServer

    #region Helper Functions
    Function Test-DnsAdminRights         {
        <#
            .SYNOPSIS
            Ensures current or prompted credentials have Domain Admin + DNS rights. Relaunches script if needed.

            .DESCRIPTION
            Checks if the current user is a Domain Admin and can access DNS. If not, prompts for credentials,
            validates them, and re-launches the script with the original arguments under the alternate identity.

            .PARAMETER DnsServer
            Optional. DNS server to validate against.

            .OUTPUTS
            System.Boolean (only on success under current identity).

            .NOTES
            PowerShell 5.1 only. Requires DnsServer and ActiveDirectory modules.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $false)]
            [string]$DnsServer = $script:DnsServer
        )

        Function Test-CredentialAccess {
            Param (
                [System.Management.Automation.PSCredential]$Credential,
                [string]$DnsServer
            )
            Try {
                $user     = Get-ADUser -Identity $Credential.UserName -Credential $Credential -Properties MemberOf
                $daGroup  = Get-ADGroup -Filter { Name -eq 'Domain Admins' } -Credential $Credential

                If ($user.MemberOf -notcontains $daGroup.DistinguishedName) {
                    Throw "[X] Supplied credentials are not a member of Domain Admins."
                }

                $null = Get-DnsServerZone -ComputerName $DnsServer -Credential $Credential -ErrorAction Stop
                return $true
            } Catch {
                Write-Host ('[!] Credential validation failed: {0}' -f $_.Exception.Message) @script:Re
                return $false
            }
        }

        Try {
            ### Check current user
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $adUser      = Get-ADUser -Identity $currentUser -Properties MemberOf
            $daGroup     = Get-ADGroup -Filter { Name -eq 'Domain Admins' }

            If ($adUser.MemberOf -contains $daGroup.DistinguishedName) {
                $null = Get-DnsServerZone -ComputerName $DnsServer @script:EA0
                Write-Host '[OK] Current user is a Domain Admin and has DNS access.' @script:Gr
                return $true
            } Else {
                Write-Host '[!] Current user is NOT a member of Domain Admins.' @script:Ye
                Write-Host '[>] Please enter alternate credentials...' @script:Cy

                $cred = Get-Credential -Message 'Enter credentials with Domain Admin and DNS permissions'

                If (Test-CredentialAccess -Credential $cred -DnsServer $DnsServer) {
                    ### Re-launch script with original args
                    $scriptPath = $MyInvocation.MyCommand.Path
                    If (-not $scriptPath) {
                        Write-Host '[!] Relaunch aborted. Script must be saved to a .ps1 file to support credential elevation.' @script:Ye
                        Exit 1
                    }

                    # Rebuild argument string safely
                    $argString = ''
                    ForEach ($arg in $MyInvocation.UnboundArguments) {
                        $argString += (' "{0}"' -f $arg.Replace('"', '\"'))
                    }

                    $fullCommand = '-ExecutionPolicy Bypass -NoProfile -File "{0}"{1}' -f $scriptPath, $argString
                    Write-Host "`n[i] Relaunching script under alternate credentials:" @script:Cy
                    Write-Host ('[>] powershell.exe {0}' -f $fullCommand) @script:Gy

                    Start-Process -FilePath 'powershell.exe' -ArgumentList $fullCommand -Credential $cred -WindowStyle Normal

                    Write-Host '[i] Relaunch initiated. Exiting current session.' @script:Ye
                    Exit
                } Else {
                    Throw '[X] Supplied credentials are invalid or lack required rights.'
                }
            }
        } Catch {
            Write-Host ('[X] Access check failed: {0}' -f $_.Exception.Message) @script:Re
            Exit 1
        }
    }

    Function Show-ServerInputDialog      {
        <#
            .SYNOPSIS
            Displays a WPF form for user-pasted server input or CSV file import.

            .DESCRIPTION
            Allows the user to paste server:IP entries or load a CSV/TSV file. The
            text is parsed by Convert-ToServerList and stored in $script:ServerList.

            .OUTPUTS
            None directly — sets $script:ServerList.

            .NOTES
            Requires Convert-ToServerList to exist in scope.
            PowerShell 5.1 compatible.
        #>
        [CmdletBinding()]
        Param ()

        Add-Type -AssemblyName PresentationFramework

        $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Enter Hostnames and IPs" Height="500" Width="700"
        WindowStartupLocation="CenterScreen" ResizeMode="CanResizeWithGrip">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <DockPanel Grid.Row="0" Margin="0,0,0,10">
            <Button Name="BrowseButton" Content="Browse CSV..." Width="100" DockPanel.Dock="Right" Margin="0,0,0,5"/>
        </DockPanel>
        <TextBox Name="InputBox" Grid.Row="0" AcceptsReturn="True" VerticalScrollBarVisibility="Auto"
                 FontFamily="Consolas" FontSize="12" TextWrapping="Wrap"/>
        <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button Name="OkButton" Content="OK" Width="80" Margin="5"/>
            <Button Name="CancelButton" Content="Cancel" Width="80" Margin="5"/>
        </StackPanel>
    </Grid>
</Window>
"@

        [xml]$xamlReader = $xaml
        $reader = (New-Object System.Xml.XmlNodeReader $xamlReader)
        $form   = [Windows.Markup.XamlReader]::Load($reader)

        $InputBox     = $form.FindName("InputBox")
        $OkButton     = $form.FindName("OkButton")
        $CancelButton = $form.FindName("CancelButton")
        $BrowseButton = $form.FindName("BrowseButton")

        $OkButton.Add_Click({
            Try {
                $rawText = $InputBox.Text
                If (-not $rawText.Trim()) {
                    [System.Windows.MessageBox]::Show("Please enter or import at least one server entry.", "Missing Input", "OK", "Warning")
                    return
                }

                $parsed = Convert-ToServerList -RawText $rawText
                If (-not $parsed -or $parsed.Count -eq 0) {
                    [System.Windows.MessageBox]::Show("No valid entries could be parsed from input.", "Parse Error", "OK", "Error")
                    return
                }

                $script:ServerList = $parsed
                $form.Close()
            } Catch {
                [System.Windows.MessageBox]::Show("An error occurred: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        })

        $CancelButton.Add_Click({
            Write-Host '[!] Server input cancelled by user.' @script:Ye
            $form.Close()
            Exit
        })

        $BrowseButton.Add_Click({
            Try {
                $ofd  = New-Object -ComObject Microsoft.Win32.OpenFileDialog
                $ofd.Filter = "CSV/TSV/Text Files (*.csv;*.txt)|*.csv;*.txt|All Files (*.*)|*.*"
                $null = $ofd.ShowDialog()

                If ($ofd.FileName) {
                    $fileText = Get-Content -Path $ofd.FileName -Raw
                    $InputBox.Text = $fileText
                }
            } Catch {
                [System.Windows.MessageBox]::Show("Could not open file: $($_.Exception.Message)", "File Load Error", "OK", "Error")
            }
        })

        $form.ShowDialog() | Out-Null
    }

    Function Get-IPValid                 {
        <#
            .SYNOPSIS
            Determines whether a string is a valid IPv4 address.

            .DESCRIPTION
            The Get-IPValid function checks if a given string is a syntactically valid IPv4 address using a regular expression.
            It trims the input, excludes invalid values like '0.0.0.0', and ensures the address is in dotted decimal format.
            Returns $true for valid IPs and $false otherwise.

            .PARAMETER testip
            The string to validate as an IPv4 address.

            .EXAMPLE
            Get-IPValid -testip '192.168.1.100'

            Returns:
            True

            .EXAMPLE
            Get-IPValid -testip 'invalid_ip'

            Returns:
            False

            .EXAMPLE
            '10.0.0.1', '256.1.1.1', '0.0.0.0' | ForEach-Object { Get-IPValid $_ }

            Checks a list of values for valid IP addresses.

            .OUTPUTS
            System.Boolean

            .NOTES
            - Excludes '0.0.0.0' by design.
            - Supports only IPv4 format.
            - Requires PowerShell 3.0 or higher.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,HelpMessage='Would-Be IP Address to test',Position=0)]
            [ValidateNotNullOrEmpty()]
            [string]$testip
        )

        $testip = $testip.Trim()

        If ($testip -eq '0.0.0.0') { return $false }

        $pattern = '^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.' +
                   '(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.' +
                   '(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.' +
                   '(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$'

        return ($testip -match $pattern)
    }

    Function Get-IPFoolery               {
        <#
            .SYNOPSIS
            Transforms an IPv4 address string for use in DNS reverse lookup logic.

            .DESCRIPTION
            Accepts an IPv4 address or `.in-addr.arpa`-style PTR string and returns a transformed version for reverse DNS use. 
            Mode options:
            - 'Trim' removes the last octet.
            - 'Rev' reverses the first 3 octets.
            - 'Zone' reverses all 4 octets (used for constructing full PTR zones).

            The function first strips `.in-addr.arpa` if present, validates the result as an IPv4 address, 
            and then applies the selected transformation. If the IP is invalid, `$null` is returned with a warning.

            .PARAMETER ip
            A string representing either a valid IPv4 address or a `.in-addr.arpa` reverse DNS query.

            .PARAMETER do
            A keyword indicating which transformation to perform:
            - 'Trim' → removes the final octet
            - 'Rev'  → reverses the first 3 octets
            - 'Zone' → reverses all 4 octets

            .EXAMPLE
            Get-IPFoolery -ip '10.20.30.40' -do 'Trim'
            Returns: 10.20.30

            .EXAMPLE
            Get-IPFoolery -ip '10.20.30.40' -do 'Rev'
            Returns: 30.20.10

            .EXAMPLE
            Get-IPFoolery -ip '10.20.30.40.in-addr.arpa' -do 'Zone'
            Returns: 40.30.20.10

            .OUTPUTS
            System.String. A transformed IP segment string for DNS reverse lookups.

            .NOTES
            - Requires `Get-IPValid` to validate input before proceeding.
            - Returns `$null` if input is not a valid IP after `.in-addr.arpa` is removed.
            - Used in reverse zone validation, creation, and PTR record logic.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,Position=0,HelpMessage='IPv4 address or PTR name')]
            [ValidateNotNullOrEmpty()]
            [string]$ip,

            [Parameter(Mandatory=$true,HelpMessage='Trim, Rev, or Zone',Position=1)]
            [ValidateSet('Trim', 'Rev', 'Zone')]
            [string]$do
        )

        ### Normalize and strip .in-addr.arpa if present
        $ip = $ip.Trim().ToLower()
        If ($ip -like '*.in-addr.arpa') {
            $ip = $ip -replace '\.in-addr\.arpa$', ''
        }

        ### Validate format (after potential trim)
        If (-not (Get-IPValid -testip $ip)) {
            Write-Warning -Message ('Invalid IP address: {0}' -f $ip)
            return $null
        }

        # Split once
        $octets = $ip.Split('.')

        Switch ($do) {
            'Trim' {
                return ($octets[0..2] -join '.')
            }
            'Rev' {
                $rev = $octets[0..2]
                [array]::Reverse($rev)
                return ($rev -join '.')
            }
            'Zone' {
                [array]::Reverse($octets)
                return ($octets -join '.')
            }
        }
    }

    Function New-ServerEntry             {
        <#
            .SYNOPSIS
            Constructs a normalized server entry object from a name and IP address.

            .DESCRIPTION
            This helper function creates a `[PSCustomObject]` representing a server entry, containing:
            - `Name`: The server hostname, converted to uppercase.
            - `IP`  : The IPv4 address, unmodified.

            It is used by parsing functions like `Convert-ToServerList` to encapsulate object creation logic, and
            makes unit testing and reuse easier.

            .PARAMETER Name
            The hostname of the server. This value will be trimmed and uppercased.

            .PARAMETER IP
            The IPv4 address of the server. This value is stored exactly as passed in.

            .OUTPUTS
            [PSCustomObject] with two properties:
                - Name [string]
                - IP   [string]

            .EXAMPLE
            New-ServerEntry -Name 'si-app01' -IP '10.50.1.100'

            Returns:
            @{
                Name = 'SI-APP01'
                IP   = '10.50.1.100'
            }

            .NOTES
            Author: YourName
            PowerShell 5.1 compatible.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true, HelpMessage='The hostname of the server')]
            [string]$Name,

            [Parameter(Mandatory=$true, HelpMessage='The IP address of the server')]
            [string]$IP
        )
        return [PSCustomObject]@{
            Name = $Name.Trim().ToUpper()
            IP   = $IP.Trim()
        }
    }

    Function Convert-ToServerList        {
        <#
            .SYNOPSIS
            Parses a flexible multiline string of server names and IPs into structured objects.

            .DESCRIPTION
            This function converts a block of raw server data into structured `[PSCustomObject]` items, handling:
            - Any mix of comma and tab delimiters
            - Switched order: Name,IP or IP,Name (in the same block)
            - Extra spaces, mixed casing, or malformed lines

            It uses `Get-IPValid` to detect the IP side and always outputs the name in uppercase.

            .PARAMETER RawText
            The multiline raw string to parse. Each line must contain at least one IP and one name.

            .EXAMPLE
            $testlist = @'
            SI-IT096	10.90.7.14
            10.90.7.15,SI-IT097
            10.90.7.16		SI-IT098
            si-it099, 10.90.7.17
            badlinehere
            '@
            $ServerList = Convert-ToServerList -RawText $testlist

            Returns:
            [ Name = 'SI-IT096'; IP = '10.90.7.14' ]
            [ Name = 'SI-IT097'; IP = '10.90.7.15' ]
            [ Name = 'SI-IT098'; IP = '10.90.7.16' ]
            [ Name = 'SI-IT099'; IP = '10.90.7.17' ]

            .OUTPUTS
            System.Object[] - PSCustomObject with properties: Name (uppercase), IP (validated)

            .NOTES
            Requires helper function: Get-IPValid
            Skips any line where a valid IP can't be detected.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,HelpMessage='Multiline string of hostname and IP entries')]
            [string]$RawText
        )

        $SvrList = @()

        $lines = $RawText -split "`n"
        ForEach ($line in $lines) {
            $line = $line.Trim()
            If (-not $line) { Continue }

            ### Normalize whitespace, then split on comma or tab or space
            $lineClean = $line -replace '\s+', ',' -replace '\t+', ','
            $parts     = $lineClean -split ',' | ForEach-Object { $_.Trim() }

            ### Find an IP address among the parts
            $ip        = $null
            $name      = $null

            ForEach ($part in $parts) {
                If ([string]::IsNullOrWhiteSpace($part)) { Continue }

                If (Get-IPValid -testip $part) { $ip = $part } Else { $name = $part }
            }

            If (-not [string]::IsNullOrWhiteSpace($ip) -and -not [string]::IsNullOrWhiteSpace($name)) {
                #$SvrList += [PSCustomObject]@{ Name = $name.ToUpper(); IP = $ip }
                $SvrList += New-ServerEntry -Name $name -IP $ip
            } Else {
                Write-Warning -Message ('Skipping line (could not detect valid IP and name): {0}' -f $line)
            }
        }

        return $SvrList
    }

    Function Get-PTRZones                {
        <#
            .SYNOPSIS
            Retrieves all non-autocreated IPv4 reverse lookup zones from the specified DNS server.

            .DESCRIPTION
            This function queries the given DNS server (defaults to `$script:DnsServer`) and returns all existing IPv4 reverse zones,
            excluding IPv6 and auto-created entries.

            .PARAMETER ComputerName
            The DNS server to query. Defaults to `$script:DnsServer`.

            .OUTPUTS
            System.String[] - Array of reverse lookup zone names (e.g., 7.90.10.in-addr.arpa).

            .NOTES
            Typically called once and cached into `$script:ReverseLookupZones` for reuse.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false)]
            [string]$ComputerName = $script:DnsServer
        )

        return (Get-DnsServerZone -ComputerName $script:DnsServer |
            Where-Object {
                $_.IsReverseLookupZone -and
                -not $_.IsAutoCreated   -and
                $_.ZoneName -notmatch 'ip6'
            }).ZoneName
    }

    Function Get-AllARecords             {
        <#
            .SYNOPSIS
            Retrieves all DNS A records and builds a reusable cache with zone, type, and subnet info.

            .DESCRIPTION
            Polls all non-reverse zones for A records, attaches subnet and static/dynamic flags, and returns a deduplicated list.

            .PARAMETER StaticOnly
            If specified, filters to static A records only.

            .OUTPUTS
            PSCustomObject[]
        #>
        [CmdletBinding()]
        Param (
            [switch]$StaticOnly, 

            [Parameter(Mandatory=$false)]
            [string]$ComputerName = $script:DnsServer
        )

        $allRecords = @()
        $recordSeen = @{}

        $zones = Get-DnsServerZone -ComputerName $ComputerName | Where-Object { -not $_.IsReverseLookupZone -and $_.ZoneName -notmatch 'msdcs|TrustAnchors|\.ca|\.com' }

        ForEach ($zone in $zones) {
            $zoneName = $zone.ZoneName
            $records  = Get-DnsServerResourceRecord -ZoneName $zoneName -ComputerName $ComputerName -RRType A |
                        Where-Object { $_.HostName -notmatch '@|DomainDnsZones|ForestDnsZones' }

            ForEach ($r in $records) {
                $ip = $r.RecordData.IPv4Address.IPAddressToString
                $key = "$($r.HostName).$zoneName|$ip"
                If ($recordSeen.ContainsKey($key)) { Continue }

                $recordSeen[$key] = $true

                $allRecords += [PSCustomObject]@{
                    Hostname    = $r.HostName
                    Zone        = $zoneName
                    FQDN        = "$($r.HostName).$zoneName"
                    IPv4Address = $ip
                    Type        = If ($r.Timestamp) { 'Dynamic' } Else { 'Static' }
                    Subnet      = Get-SubnetMask -ip $ip
                }
            }
        }

        If ($StaticOnly) {
            return $allRecords | Where-Object { $_.Type -eq 'Static' }
        }

        return $allRecords
    }

    Function Get-SharedIPConflicts       {
        <#
            .SYNOPSIS
            Identifies IP addresses assigned to more than one FQDN (shared A records).

            .DESCRIPTION
            Scans $script:AllARecords for any IPv4 address used by multiple distinct FQDNs,
            and returns a hashtable keyed by IP with the list of FQDNs using that IP.

            .OUTPUTS
            [Hashtable] of [string[]] keyed by shared IPs
        #>
        [CmdletBinding()]
        Param ()

        $shared = @{}

        $grouped = $script:AllARecords | Group-Object -Property IPv4Address

        ForEach ($g in $grouped) {
            If ($g.Count -gt 1) {
                $fqdnList = $g.Group | ForEach-Object { $_.FQDN }
                $shared[$g.Name] = $fqdnList | Sort-Object -Unique
            }
        }

        return $shared
    }

    Function Test-SharedIPConflict       {
        <#
            .SYNOPSIS
            Checks if the given IP is used by a different FQDN in the cached A record list.

            .DESCRIPTION
            Scans $script:AllARecords to determine if the given IP is associated with any
            other hostnames than the one being processed.

            .PARAMETER ExpectedIP
            The IP to check for sharing.

            .PARAMETER CurrentFQDN
            The hostname we're validating (to exclude from the comparison).

            .OUTPUTS
            [string[]] List of conflicting FQDNs (empty if none)
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory,HelpMessage='Expected IP Address')]
            [string]$ExpectedIP,

            [Parameter(Mandatory,HelpMessage='Fully Qualified Domain Name')]
            [string]$CurrentFQDN
        )

        $conflicts = $script:AllARecords |
            Where-Object { $_.IPv4Address -eq $ExpectedIP -and $_.FQDN -ne $CurrentFQDN } |
            Select-Object -ExpandProperty FQDN -Unique

        return $conflicts
    }

    Function Get-FQDNReuseConflicts      {
        <#
            .SYNOPSIS
            Identifies FQDNs that point to more than one IP in the cached A record list.

            .DESCRIPTION
            Scans $script:AllARecords for FQDNs with multiple associated IPv4 addresses,
            and returns a formatted string for each conflict.

            Each line is in the format:
                FQDN ⇨ IP1, IP2, ...

            .OUTPUTS
            System.String[] - List of FQDN conflict strings

            .EXAMPLE
            Get-FQDNReuseConflicts

            Returns:
                HOST01.DOMAIN.LOCAL ⇨ 10.0.1.1, 10.0.2.1

            .NOTES
            - Helps identify cases where a hostname may resolve inconsistently.
            - Useful for DNS integrity checks alongside shared IP analysis.
        #>
        [CmdletBinding()]
        Param ()

        $conflicts = $script:AllARecords |
            Group-Object -Property FQDN |
            Where-Object { $_.Count -gt 1 } |
            ForEach-Object {
                '{0} ⇨ {1}' -f $_.Name, ($_.Group.IPv4Address -join ', ')
            }

        return $conflicts
    }

    Function Get-AllPTRZones             {
        <#
            .SYNOPSIS
            Returns the full list of reverse DNS zones, optionally filtered by an IP or octet pattern.

            .DESCRIPTION
            This function fetches reverse lookup zones from the target PDC DNS server. It filters for IPv4 reverse zones only,
            excluding IPv6 and auto-created zones. When called with `-Find`, it matches zones based on reversed octet format.

            It is usually called once per run and stored in $script:ReverseLookupZones to avoid repeated remote queries.

            .PARAMETER Find
            Optional. A string (usually an IP address) used to narrow down the reverse zones based on pattern match.

            .PARAMETER ComputerName
            The DNS server to query. Defaults to `$script:DnsServer`.

            .OUTPUTS
            System.String[] - List of reverse zone names.

            .NOTES
            Should be called only once and cached in `$script:ReverseLookupZones`.
        #>
        Param (
            [Parameter(Position=0)]
            [string]$Find, 

            [Parameter(Mandatory=$false)]
            [string]$ComputerName = $script:DnsServer
        )

        If (-not $script:ReverseLookupZones) {
            Write-Warning -Message 'PTR zone cache not initialized. Querying live DNS...'
            $script:ReverseLookupZones = Get-PTRZones -ComputerName $DnsServer
        } Else {
            $AllZoneNames = $script:ReverseLookupZones
        }

        If (-not $AllZoneNames) {
            Throw 'PTR zone cache ($script:ReverseLookupZones) is not initialized. Ensure it is loaded before calling this function.'
        }

        If ($Find) {
            If (Get-IPValid -testip $Find) {
                $searchKey = Get-IPFoolery -ip $Find -do 'Rev'
                return ($AllZoneNames | Where-Object { $_ -like "*$searchKey*" })
            } ElseIf (($Find.ToCharArray() -eq '.').Count -ge 2) {
                return ($AllZoneNames | Where-Object { $_ -like "*$Find*" })
            } Else {
                return $null
            }
        }

        return $AllZoneNames
    }

    Function Get-ReverseZone             {
        <#
            .SYNOPSIS
            Finds or creates the reverse DNS (PTR) zone for a given IPv4 address.

            .DESCRIPTION
            This function locates the reverse DNS zone that matches a given IPv4 address using the cached `$script:ReverseLookupZones`.
            If no matching zone is found:
            - It computes a proposed reverse zone from the IP address
            - Logs the missing zone to `$script:Summary['MissingZones']`
            - If allowed, it creates the zone using `Add-DnsServerPrimaryZone` and logs to `$script:Summary['CreatedZones']`

            All actions honor `$script:CreateMissingZones` and `$WhatIfPreference`. The function depends on
            prior initialization of `$script:ReverseLookupZones` using `Get-PTRZones`.

            .PARAMETER ip
            The IPv4 address to evaluate (e.g., 10.90.7.14).

            .PARAMETER ComputerName
            The DNS server on which to query or create the reverse zone. Defaults to `$script:DnsServer`.

            .EXAMPLE
            Get-ReverseZone -ip '10.90.7.14'

            .OUTPUTS
            System.String
            The name of the existing or newly created reverse DNS zone.

            .NOTES
            - Requires `$script:ReverseLookupZones` to be preloaded (via `Get-PTRZones`)
            - Uses `Add-DnsServerPrimaryZone` for zone creation if enabled.
            - Uses `Get-AllPTRZones` and `Get-IPFoolery`
            - Updates the `$script:Summary` object
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'IPv4 address to evaluate')]
            [string]$ip, 

            [Parameter(Mandatory=$false)]
            [string]$ComputerName = $script:DnsServer
        )

        ### Attempt to find an existing zone
        $zone = Get-AllPTRZones -Find $ip -ComputerName $DnsServer

        If ($zone) {
            Write-Host ('[OK] PTR zone found for {0} : {1}' -f $ip, $zone) @script:Gr
            return $zone
        }

        ### Compute the proposed zone name
        $revSuffix    = Get-IPFoolery -ip $ip -do 'Rev'
        $proposedZone = '{0}.in-addr.arpa' -f $revSuffix

        Write-Warning -Message ('[!] PTR zone for {0} not found. Proposed zone: {1}' -f $ip, $proposedZone)

        ### Log missing zone
        $script:Summary['MissingZones'] += $proposedZone
        $script:Summary['MissingZones']  = $script:Summary['MissingZones'] | Select-Object -Unique

        ### Create it if allowed
        If ($script:CreateMissingZones) {
            If ($WhatIfPreference) {
                Write-Host ('[WhatIf] Reverse zone {0} would be created on {1}.' -f $proposedZone, $DnsServer) @script:Ma
                Throw ('[WhatIf] Zone {0} not created due to simulation mode.' -f $proposedZone)
            }

            Try {
                Add-DnsServerPrimaryZone -NetworkId $revSuffix -ReplicationScope 'Domain' -ComputerName $DnsServer @script:EA0
                $script:Summary['CreatedZones'] += $proposedZone
                Write-Host ('[+] Created reverse zone {0} on {1}' -f $proposedZone, $DnsServer) @script:Gr
                return $proposedZone
            } Catch {
                Throw ('[X] Failed to create reverse zone {0}: {1}' -f $proposedZone, $_.Exception.Message)
            }
        } Else {
            Throw ('[X] Zone {0} does not exist and automatic creation is disabled.' -f $proposedZone)
        }
    }

    Function Get-ReverseName             {
        <#
            .SYNOPSIS
            Extracts the final octet from a valid IPv4 address for use in PTR record creation.

            .DESCRIPTION
            This function takes a valid IPv4 address and returns its last octet as a string.
            This is typically used as the record name for PTR entries in reverse lookup zones.
            Input is validated using `Get-IPValid` to ensure correctness.

            .PARAMETER ip
            A valid IPv4 address (e.g., 10.90.7.14). The address is trimmed and validated before processing.

            .EXAMPLE
            Get-ReverseName -ip '192.168.1.10'
            Returns: '10'

            .EXAMPLE
            Get-ReverseName -ip '10.90.7.14'
            Returns: '14'

            .OUTPUTS
            System.String
            The final octet of the provided IP address.

            .NOTES
            - Uses `Get-IPValid` for input validation.
            - Returns `$null` if input is invalid.
            - Typically used with `Add-DnsServerResourceRecordPtr`.

            .LINK
            Get-IPFoolery
            Get-ReverseZone
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,HelpMessage='IPv4 address to extract final octet from')]
            [string]$ip
        )

        $ip = $ip.Trim()

        If (-not (Get-IPValid -testip $ip)) {
            Write-Warning -Message ("[!] Get-ReverseName: Invalid IP address '{0}'" -f $ip)
            return $null
        }

        return ($ip -split '\.')[-1]
    }

    Function Split-FQDNIntoZoneAndHost   {
        <#
            .SYNOPSIS
            Splits a Fully Qualified Domain Name into its host label and zone components.

            .DESCRIPTION
            This function accepts an FQDN string like `host01.ad.contoso.com` and returns a PSCustomObject with:
            - `Host`: the first label (e.g., 'host01')
            - `Zone`: the remainder as the zone (e.g., 'ad.contoso.com')

            This eliminates repeated splitting logic and safeguards against malformed or short FQDNs.

            .PARAMETER Fqdn
            The fully qualified domain name to split.

            .OUTPUTS
            PSCustomObject with `Host` and `Zone` properties.

            .EXAMPLE
            Split-FQDNIntoZoneAndHost -Fqdn 'host01.ad.contoso.com'
            Returns:
            @{ Host = 'host01'; Zone = 'ad.contoso.com' }

            .NOTES
            Use anywhere zone extraction from FQDNs is needed. Validates minimum dot-depth.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,HelpMessage='Fully Qualified Domain Name')]
            [string]$Fqdn
        )

        $parts = $Fqdn -split '\.'
        If ($parts.Count -lt 2) {
            Throw ("FQDN '{0}' is not valid - must include host and zone components." -f $Fqdn)
        }

        return [PSCustomObject]@{
            Host = $parts[0]
            Zone = ($parts[1..($parts.Count - 1)] -join '.')
        }
    }

    Function Get-CachedForwardLookup     {
        <#
            .SYNOPSIS
            Resolves A record for an FQDN with caching to avoid duplicate DNS queries.

            .DESCRIPTION
            Stores successful Resolve-DnsName results in a global hashtable keyed by FQDN.
            Reuses previous result if available. Uses $script:EA1 to avoid throwing on failure.

            .PARAMETER Fqdn
            The FQDN to resolve.

            .PARAMETER DnsServer
            DNS server to query.

            .OUTPUTS
            System.String[] or $null
            IP address array or null if resolution failed.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,HelpMessage='Fully Qualified Domain Name')]
            [string]$Fqdn,

            [Parameter(Mandatory=$true,HelpMessage='DNS Server')]
            [string]$DnsServer
        )

        If (-not $script:ForwardCache) { $script:ForwardCache = @{} }
        If (-not $script:Summary.ContainsKey('AliasesFound')) {
            $script:Summary['AliasesFound'] = @()
        }

        If ($script:ForwardCache.ContainsKey($Fqdn)) {
            return $script:ForwardCache[$Fqdn]
        }

        Try {
            $result = Resolve-DnsName -Name $Fqdn -Type A -Server $DnsServer @script:EA1

            ### After successful Resolve-DnsName, check for CNAME:
            $cnames = $result | Where-Object { $_.QueryType -eq 'CNAME' }
            If ($cnames) {
                $aliasInfo = '{0} → {1}' -f $Fqdn, $cnames[0].NameHost
                Write-Host ('[!] {0}' -f $aliasInfo) @script:DY
                $script:Summary['AliasesFound'] += $aliasInfo
            }

            $ips    = $result.IPAddress
        } Catch {
            $ips = $null
        }

        $script:ForwardCache[$Fqdn] = $ips
        return $ips
    }

    Function Get-CachedARecordByFQDN     {
        <#
            .SYNOPSIS
            Returns the cached A record IP(s) for a given FQDN from $script:AllARecords.

            .DESCRIPTION
            This function scans the $script:AllARecords cache and retrieves one or more IPv4 addresses
            associated with the specified FQDN. It avoids live DNS queries and reflects any in-memory 
            changes from earlier steps in the current run.

            .PARAMETER FQDN
            The Fully Qualified Domain Name to query in the A record cache.

            .OUTPUTS
            System.String[] - One or more matching IP addresses, or an empty array if none are found.

            .EXAMPLE
            Get-CachedARecordByFQDN -FQDN 'host01.domain.local'

            .NOTES
            - Used for forward resolution consistency checks.
            - Helps reduce dependency on Resolve-DnsName in post-checks.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true)]
            [string]$FQDN
        )

        return $script:AllARecords |
            Where-Object { $_.FQDN -ieq $FQDN } |
            Select-Object -ExpandProperty IPv4Address -Unique
    }

    Function Get-CachedReverseLookup     {
        <#
            .SYNOPSIS
            Returns cached reverse lookup result for a given IP, or performs PTR resolution.

            .DESCRIPTION
            Uses Resolve-DnsName against the provided DNS server. Caches PTR response by IP.
            Returns either a PTR target name or $null.

            .PARAMETER IP
            The IPv4 address to reverse-resolve.

            .PARAMETER DnsServer
            The DNS server to use for the PTR lookup. Defaults to `$script:DnsServer`.

            .PARAMETER DnsServer
            DNS server to query.

            .OUTPUTS
            System.String or $null
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,HelpMessage='IP Address')]
            [string]$IP,

            [Parameter(Mandatory=$false)]
            [string]$DnsServer = $script:DnsServer
        )

        If ($script:ReverseCache.ContainsKey($IP)) {
            return $script:ReverseCache[$IP]
        }

        Try {
            $ptrQuery = '{0}.in-addr.arpa' -f (Get-IPFoolery -ip $IP -do 'Zone')
            $ptr      = Resolve-DnsName -Name $ptrQuery -Type PTR -Server $DnsServer @script:EA1
            $target   = $ptr.NameHost.Trim()
        } Catch {
            $target = $null
        }

        $script:ReverseCache[$IP] = $target
        return $target
    }

    Function Update-ARecord              {
        <#
            .SYNOPSIS
            Verifies and updates a DNS A record to match the expected IPv4 address.

            .DESCRIPTION
            This function ensures that a DNS A record exists and points to the correct IP. If the IP is incorrect or missing,
            the record is replaced. If other A records are found pointing to the same IP (shared IP conflict), it prompts the user to decide:
            - Update target
            - Remove other A record(s)
            - Skip

            Logs results and respects WhatIf mode.

            .PARAMETER DnsServer
            DNS server to query and update.

            .PARAMETER HostFQDN
            Fully qualified domain name (FQDN) of the host.

            .PARAMETER ExpectedIP
            Target IP address for the A record.

            .EXAMPLE
            Update-ARecord -DnsServer 'dns01' -HostFQDN 'host01.domain.local' -ExpectedIP '192.168.1.10'

            .OUTPUTS
            None directly. Writes to console and appends HostFQDN to $script:Summary['UpdatedARecords'] if updated.
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        Param (
            [Parameter(Mandatory=$false,HelpMessage='DNS Server')]
            [string]$DnsServer = $script:DnsServer,

            [Parameter(Mandatory=$true,HelpMessage='Host Fully Qualified Domain Name')]
            [string]$HostFQDN,

            [Parameter(Mandatory=$true,HelpMessage='Expected IP')]
            [string]$ExpectedIP
        )

        If (-not (Get-IPValid -testip $ExpectedIP)) {
            Write-Warning -Message ('[!] Invalid expected IP: {0}' -f $ExpectedIP)
            return
        }

        Try {
            $fqdnParts = Split-FQDNIntoZoneAndHost -Fqdn $HostFQDN
            $short     = $fqdnParts.Host
            $zone      = $fqdnParts.Zone

            ### Confirm the zone is writable
            Try {
                $zoneMeta = Get-DnsServerZone -ComputerName $DnsServer -Name $zone @script:EA0
                If ($zoneMeta.IsReadOnly) {
                    Write-Host ('[!] Zone {0} is read-only. Skipping A record update.' -f $zone) @script:Re
                    return
                }
            } Catch {
                Write-Warning -Message ("[!] Could not verify write access to zone '{0}': {1}" -f $zone, $_.Exception.Message)
                return
            }
        } Catch {
            Write-Warning -Message $_.Exception.Message
            return
        }

        $WAdd = ('[WhatIf] Add-DnsServerResourceRecordA -ComputerName {0} -ZoneName {1} -Name {2} -IPv4Address {3}' -f $DnsServer, $zone, $short, $ExpectedIP)

        ### Check if this IP is shared by other FQDNs
        $ipConflicts = Test-SharedIPConflict -ExpectedIP $ExpectedIP -CurrentFQDN $HostFQDN

        If ($ipConflicts.Count -gt 0) {
            $conflictList  = $ipConflicts -join ', '
            $conflictEntry = '{0} ⇨ {1}' -f $ExpectedIP, $conflictList
            Write-Host ('[!] Shared IP conflict detected for {0}: {1}' -f $ExpectedIP, $conflictList) @script:Ye
            $script:Summary['SharedIPs'] += $conflictEntry

            If (-not $WhatIfPreference) {
                $decision = Read-Host -Prompt 'Shared IP in use. [C]ontinue / [S]kip / [L]ist again'

                Switch ($decision.ToUpper()) {
                    'S' {
                        Write-Host '[i] Skipping A record update due to shared IP.' @script:DY
                        return
                    }
                    'L' {
                        Write-Host ('[!] Shared by: {0}' -f $conflictList) @script:Ye
                        # falls through
                    }
                    Default { }
                }
            }
        }

        ### Step 1: Check for A records for this host
        $existing    = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $short @script:EA1 | 
                       Where-Object { $_.RecordType -eq 'A' }

        ### Step 2: Check for A records across all zones pointing to this same IP
        $allRecords  = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName * @script:EA1 |
                       Where-Object { $_.RecordType -eq 'A' -and $_.RecordData.IPv4Address.IPAddressToString -eq $ExpectedIP }

        $ipConflicts = $allRecords | Where-Object { ($_.HostName + '.' + $_.ZoneName) -ne $HostFQDN }

        If ($ipConflicts.Count -gt 0) {
            Write-Host ('[!] Conflict: IP {0} is already used by other host(s):' -f $ExpectedIP) @script:DY
            $ipConflicts | ForEach-Object {
                Write-Host (' - {0}.{1}' -f $_.HostName, $_.ZoneName) @script:DY
            }

            $script:Summary['SharedIPs'] += ('{0} used by: {1}' -f $ExpectedIP, ($ipConflicts | ForEach-Object { $_.HostName + '.' + $_.ZoneName } -join ', '))
            $script:Summary['SharedIPs'] = $script:Summary['SharedIPs'] | Select-Object -Unique

            $choice = Read-Host -Prompt 'Choose action: (A) Update anyway, (B) Remove others, (C) Skip'
            Switch ($choice.ToUpper()) {
                'C' {
                    Write-Host '[i] Skipping A record update due to user selection.' @script:Ye
                    return
                }
                'B' {
                    ForEach ($conflict in $ipConflicts) {
                        $conflictFqdn = $conflict.HostName + '.' + $conflict.ZoneName
                        Write-Host ('[!] Removing conflicting A record: {0}' -f $conflictFqdn) @script:Ma
                        If ($PSCmdlet.ShouldProcess($conflictFqdn, 'Remove conflicting A record')) {
                            Remove-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $conflict.ZoneName -Name $conflict.HostName -RRType A -Force -WhatIf:$WhatIfPreference
                        }
                    }
                }
                'A' { Write-Host '[i] Proceeding with update despite shared IP.' @script:Ye }
                Default {
                    Write-Host '[!] Invalid input. Skipping.' @script:Ye
                    return
                }
            }
        }

        ### Continue with normal update logic
        If ($existing) {
            $currentIPs = $existing | ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString }
            $currentIP  = $currentIPs -join ','

            If (-not $currentIPs) {
                Write-Warning -Message ('[!] No IP found in existing A record for {0}' -f $HostFQDN)
                return
            }

            Write-Host ('[=] Found A record: {0} -> {1}' -f $HostFQDN, $currentIP) @script:Gy

            $isDynamic = ($existing | Where-Object { $_.Timestamp }).Count -gt 0

            If ($currentIPs -contains $ExpectedIP -and -not $isDynamic -and $currentIPs.Count -eq 1) {
                Write-Host ('[OK] A record OK for {0}' -f $HostFQDN) @script:Gr
                return
            }

            If ($isDynamic) {
                Write-Host ('[!] A record is dynamic. Replacing with static for {0}' -f $HostFQDN) @script:Ye
            }

            If ($currentIPs -notcontains $ExpectedIP -or $currentIPs.Count -gt 1 -or $isDynamic) {
                Write-Host ('[!] A record mismatch. Expected {0}, found {1}. Will replace.' -f $ExpectedIP, $currentIP) @script:Ye

                If ($WhatIfPreference) {
                    Write-Host ('[WhatIf] Remove-DnsServerResourceRecord -ComputerName {0} -ZoneName {1} -Name {2} -RRType A -Force' -f $DnsServer, $zone, $short) @script:Ma
                    Write-Host $WAdd @script:Ma
                }

                If ($PSCmdlet.ShouldProcess("$HostFQDN [$zone]", 'Replace mismatched A record')) {
                    Remove-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $short -RRType A -Force -WhatIf:$WhatIfPreference
                    Add-DnsServerResourceRecordA   -ComputerName $DnsServer -ZoneName $zone -Name $short -IPv4Address $ExpectedIP -TimeToLive 01:00:00 -AllowUpdateAny -WhatIf:$WhatIfPreference
                    $script:Summary['UpdatedARecords'] += $HostFQDN
                }
            } Else {
                Write-Host ('[OK] A record OK for {0}' -f $HostFQDN) @script:Gr
            }
        } Else {
            Write-Host ('[X] A record missing for {0}' -f $HostFQDN) @script:Re

            If ($WhatIfPreference) {
                Write-Host $WAdd @script:Ma
            }

            If ($PSCmdlet.ShouldProcess("$HostFQDN [$zone]", 'Add missing A record')) {
                Add-DnsServerResourceRecordA -ComputerName $DnsServer -ZoneName $zone -Name $short -IPv4Address $ExpectedIP -TimeToLive 01:00:00 -AllowUpdateAny -WhatIf:$WhatIfPreference
                $script:Summary['UpdatedARecords'] += $HostFQDN
            }
        }
    }

    Function Update-PTRRecord            {
        <#
            .SYNOPSIS
            Verifies and updates the PTR (reverse DNS) record for a given IP address.

            .DESCRIPTION
            This function ensures that the reverse DNS record (PTR) for a given IP address exists and matches
            the expected FQDN. If mismatched or shared, prompts the user for action. Honors `WhatIf` and logs all steps.

            .PARAMETER DnsServer
            The DNS server to query and update.

            .PARAMETER HostFQDN
            The expected FQDN that should be returned by the PTR.

            .PARAMETER IP
            The IP address for which the PTR should be validated.

            .EXAMPLE
            Update-PTRRecord -DnsServer 'dns01' -HostFQDN 'host01.domain.local' -IP '192.168.1.10'
        #>
        [CmdletBinding(SupportsShouldProcess = $true)]
        Param (
            [Parameter(Mandatory=$false)]
            [string]$DnsServer = $script:DnsServer,

            [Parameter(Mandatory=$true,HelpMessage='Host Fully Qualified Domain Name')]
            [string]$HostFQDN,

            [Parameter(Mandatory=$true,HelpMessage='Host IP Address')]
            [string]$IP
        )

        $WAdd = '[WhatIf] Add-DnsServerResourceRecordPtr -ComputerName {0} -ZoneName {1} -Name {2} -PtrDomainName {3}'
        $upDR = '{0} -> {1}'

        Try {
            $zone = Get-ReverseZone -ip $IP

            ### Confirm PTR zone is writable
            Try {
                $zoneMeta = Get-DnsServerZone -ComputerName $DnsServer -Name $zone @script:EA0
                If ($zoneMeta.IsReadOnly) {
                    Write-Host ('[!] PTR zone {0} is read-only. Skipping PTR update.' -f $zone) @script:Re
                    return
                }
            } Catch {
                Write-Warning -Message ("[!] Could not verify write access to PTR zone '{0}': {1}" -f $zone, $_.Exception.Message)
                return
            }

            $name = Get-ReverseName -ip $IP
        } Catch {
            Write-Host ('[!] Skipping PTR for {0} - reason: {1}' -f $IP, $_.Exception.Message) @script:DY
            return
        }

        $existing = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $name @script:EA1 |
                    Where-Object { $_.RecordType -eq 'PTR' }

        If ($existing) {
            $conflicts = $existing | Where-Object { $_.RecordData.PtrDomainName -ne $HostFQDN }

            If ($conflicts.Count -gt 0) {
                $conflictNames = $conflicts | ForEach-Object { $_.RecordData.PtrDomainName }
                Write-Host ('[!] PTR conflict at {0}: Found {1}' -f $IP, ($conflictNames -join ', ')) @script:Ye

                $script:Summary['PTRConflicts'] += ('{0} => {1}' -f $IP, ($conflictNames -join ', '))
                $script:Summary['PTRConflicts'] = $script:Summary['PTRConflicts'] | Select-Object -Unique

                If (-not $WhatIfPreference) {
                    $choice = Read-Host -Prompt 'PTR conflict. Choose: (A) Update, (B) Remove other(s), (C) Skip'
                    Switch ($choice.ToUpper()) {
                        'C' {
                            Write-Host ('[i] Skipping PTR update for {0} due to user choice.' -f $IP) @script:DY
                            return
                        }
                        'B' {
                            ForEach ($conflict in $conflicts) {
                                $ptrTarget = $conflict.RecordData.PtrDomainName
                                Write-Host ('[!] Removing conflicting PTR: {0} -> {1}' -f $IP, $ptrTarget) @script:Ma
                                If ($PSCmdlet.ShouldProcess($ptrTarget, 'Remove conflicting PTR')) {
                                    Remove-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $name -RRType PTR -Force -WhatIf:$WhatIfPreference
                                }
                            }
                        }
                        'A' {
                            Write-Host ('[i] Proceeding to replace PTR with expected value: {0}' -f $HostFQDN) @script:Ye
                            # falls through to update logic
                        }
                        Default {
                            Write-Host '[!] Invalid input. Skipping PTR update.' @script:Ye
                            return
                        }
                    }
                }
            } Else {
                Write-Host ('[OK] PTR record OK for {0}' -f $IP) @script:Gr
                return
            }
        } Else {
            Write-Host ('[X] PTR missing for {0}' -f $IP) @script:Re
        }

        If ($WhatIfPreference) {
            Write-Host ($WAdd -f $DnsServer, $zone, $name, $HostFQDN) @script:Ma
        }

        If ($PSCmdlet.ShouldProcess("$IP [$zone]", 'Add or replace PTR record')) {
            Try {
                Add-DnsServerResourceRecordPtr -ComputerName $DnsServer -ZoneName $zone -Name $name -PtrDomainName $HostFQDN -TimeToLive 01:00:00 -AllowUpdateAny -WhatIf:$WhatIfPreference
                $script:Summary['UpdatedPTRRecords'] += $upDR
            } Catch {
                $script:Summary['SkippedPTR'] += ('{0}: {1}' -f $IP, $_.Exception.Message)
                Write-Host ('[!] Failed to update PTR: {0}' -f $_.Exception.Message) @script:Re
            }
        }
    }

    Function Get-CandidateFqdnsFromEntry {
        <#
            .SYNOPSIS
            Returns a list of possible FQDNs for a hostname, based on default or specified domain suffix.

            .DESCRIPTION
            This function generates potential FQDNs for a given hostname entry. If the name already includes a domain,
            it preserves the original and optionally adds a version using the provided domain suffix if it differs.

            It ensures:
            - Output is in uppercase
            - Deduplicated list of candidate FQDNs
            - Robust handling of names with or without existing domain components

            This is useful when verifying or generating expected A and PTR records, especially during bulk DNS operations.

            .PARAMETER Entry
            A [PSCustomObject] that includes at least a `Name` property (e.g., 'host01' or 'host01.domain.com').

            .PARAMETER DomainSuffix
            Optional. A domain suffix to append to names that don't already include one.
            Defaults to `$env:USERDNSDOMAIN`.

            .EXAMPLE
            $entry = [pscustomobject]@{ Name = 'host01'; IP = '10.0.0.10' }
            Get-CandidateFqdnsFromEntry -Entry $entry

            Returns:
            - HOST01.MYDOMAIN.LOCAL  (assuming USERDNSDOMAIN = MYDOMAIN.LOCAL)

            .EXAMPLE
            $entry = [pscustomobject]@{ Name = 'host01.sub.contoso.com'; IP = '10.0.0.11' }
            Get-CandidateFqdnsFromEntry -Entry $entry -DomainSuffix 'corp.contoso.com'

            Returns:
            - HOST01.SUB.CONTOSO.COM
            - HOST01.CORP.CONTOSO.COM

            .OUTPUTS
            System.String[] - Array of uppercase FQDN strings

            .NOTES
            - Uses only the `.Name` field of the entry.
            - Automatically deduplicates and uppercases output.
            - Future suggestion: integrate with `Split-FQDNIntoZoneAndHost` to normalize across functions.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,HelpMessage='PSCustomObject with .Name')]
            [pscustomobject]$Entry,

            [Parameter(HelpMessage='Optional domain suffix')]
            [string]$DomainSuffix = $env:USERDNSDOMAIN
        )

        $fqdnList     = @()
        $originalName = $Entry.Name

        If (-not $originalName) {
            Write-Warning -Message 'Entry.Name is null or empty.'
            return $null
        }

        ### Normalize input casing
        $originalName = $originalName.Trim()

        If ($originalName -match '\.') {
            ### Already has a domain part
            $splitName  = $originalName -split '\.', 2
            $hostPart   = $splitName[0]
            $domainPart = $splitName[1]

            $fqdnList += "$hostPart.$domainPart".ToUpper()

            If ($domainPart -ne $DomainSuffix) {
                $fqdnList += "$hostPart.$DomainSuffix".ToUpper()
            }
        } Else {
            $fqdnList += "$originalName.$DomainSuffix".ToUpper()
        }

        return $fqdnList | Select-Object -Unique
    }

    Function Confirm-FinalDnsState       {
        <#
            .SYNOPSIS
            Performs a final forward and reverse DNS consistency check for a list of host entries.

            .DESCRIPTION
            This function validates that:
            - Each FQDN resolves to the expected IP (A record)
            - The reverse DNS entry for the IP (PTR record) points to the correct FQDN

            It uses cached forward and reverse lookups to reduce duplicate queries.
            Results are displayed in a color-coded table.

            It collects and displays results in a table with status indicators:
            - [OK]         Both A and PTR records are correct
            - [!] PTR mismatch   PTR record exists but points to the wrong hostname
            - [!] Missing PTR    No PTR record exists for the IP
            - [!] IP mismatch    A record exists but doesn't match the expected IP
            - [X]         A record lookup failed

            .PARAMETER DnsServer
            The DNS server to query for both A and PTR record lookups.

            .PARAMETER Entries
            An array of PSCustomObjects with `Name` and `IP` properties.

            .EXAMPLE
            $entries = @(
                [pscustomobject]@{ Name = 'HOST01'; IP = '192.168.0.1' },
                [pscustomobject]@{ Name = 'HOST02'; IP = '192.168.0.2' }
            )
            Confirm-FinalDnsState -DnsServer '192.168.0.10' -Entries $entries

            .OUTPUTS
            System.Object[]
            A formatted table showing forward/reverse DNS consistency status.

            .NOTES
            - Uses `Split-FQDNIntoZoneAndHost` to normalize hostnames.
            - Assumes FQDN = `$entry.Name + '.' + $env:USERDNSDOMAIN` if not already a full name.
            - Uses script-scoped color variables (`@script:Gr`, `@script:Re`, etc.).
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,HelpMessage='DNS Server to query')]
            [string]$DnsServer = $script:DnsServer,

            [Parameter(Mandatory=$true,HelpMessage='Array of entries (Name + IP)')]
            [array]$Entries
        )

        $NF = '<not found>'
        Write-Host "`n=== Final DNS Verification Pass ===" @script:Cy

        If (-not $script:Summary.ContainsKey('ReverseAliasesFound')) {
            $script:Summary['ReverseAliasesFound'] = @()
        }

        $BogusPTRNames = @(
            'localhost',
            'localhost.localdomain',
            '.',
            ''
        )

        $Results = @()

        ForEach ($entry in $Entries) {
            $name = $entry.Name
            $ip   = $entry.IP

            Try {
                $fqdnParts = Split-FQDNIntoZoneAndHost -Fqdn $name
                $fqdn      = ('{0}.{1}' -f $fqdnParts.Host, $fqdnParts.Zone)
            } Catch {
                Write-Warning -Message ('[!] Invalid DNS name: {0}' -f $name)
                continue
            }

            $result = [PSCustomObject]@{
                Hostname   = $fqdn.ToUpper()
                ExpectedIP = $ip
                ActualIP   = $NF
                PTRName    = $NF
                PTRIP      = $NF
                Status     = '[X]'
            }

            Try {
                $resolvedIPs = Get-CachedARecordByFQDN -FQDN $fqdn

                If (-not $resolvedIPs) {
                    $resolvedIPs = Get-CachedForwardLookup -Fqdn $fqdn -DnsServer $DnsServer
                }

                If ($resolvedIPs.Count -gt 1) {
                    $script:Summary['SharedIPs'] += ('{0} → {1}' -f $fqdn, ($resolvedIPs -join ', '))
                    $script:Summary['SharedIPs'] = $script:Summary['SharedIPs'] | Select-Object -Unique
                }
                $result.ActualIP = $resolvedIPs -join ','

                If ($resolvedIPs -contains $ip) { $ipMatch = $true } Else { $ipMatch = $false }

                If ($ipMatch) {
                    $ptrQuery = '{0}.in-addr.arpa' -f (Get-IPFoolery -ip $ip -do 'Zone')

                    Try {
                        $ptr = Resolve-DnsName -Name $ptrQuery -Type PTR -Server $DnsServer @script:EA0
                        $result.PTRName = $ptr.NameHost
                        $result.PTRIP   = $ip

                        If ($ptr.NameHost -eq $fqdn -and $ptr.NameHost -eq $ptrQuery) {
                            $result.Status = '[!] PTR loops back to query'
                            $script:Summary['PTRConflicts'] += ('{0} → {1} (loopback)' -f $ip, $ptr.NameHost)
                            continue
                        }

                        $ptrName = Get-CachedReverseLookup -IP $ip -DnsServer $DnsServer

                        If ($BogusPTRNames -contains $ptrName) {
                            $result.Status  = '[!] Bogus PTR'
                            $result.PTRName = $ptr.NameHost
                            $script:Summary['SkippedPTR'] += ('{0} → {1}' -f $ip, $ptr.NameHost)
                        } ElseIf ($ptr.NameHost -ieq $fqdn) {
                            $result.Status = '[OK]'
                        } Else {
                            $result.Status = '[!] PTR mismatch'
                            $script:Summary['ReverseAliasesFound'] += ('{0} → {1}' -f $ip, $ptr.NameHost)
                            $script:Summary['PTRConflicts'] += ('{0} → {1} (expected {2})' -f $ip, $ptr.NameHost, $fqdn)
                            $script:Summary['PTRConflicts']  = $script:Summary['PTRConflicts'] | Select-Object -Unique
                        }
                    } Catch {
                        $result.PTRName = '<no PTR>'
                        $result.Status  = '[!] Missing PTR'
                    }
                } Else {
                    $result.Status = '[!] IP mismatch'
                }
            } Catch {
                $result.ActualIP = '<no A record>'
            }

            $Results += $result
        }

        $Results | Sort-Object -Property Hostname | Format-Table -AutoSize
    }

    Function Export-ConflictReports      {
        <#
            .SYNOPSIS
            Exports CSV reports for Shared IPs and PTR Conflicts if any exist.
            .DESCRIPTION
            Writes CSV files to $env:TEMP\MassRename_SharedIPs.csv and MassRename_PTRConflicts.csv
        #>
        [CmdletBinding()]
        Param ()

        $base = Join-Path -Path $env:TEMP -ChildPath 'MassRename_'

        If ($script:Summary['SharedIPs'] -and $script:Summary['SharedIPs'].Count -gt 0) {
            $path = $base + 'SharedIPs.csv'
            $script:Summary['SharedIPs'] | Sort-Object | Set-Content -Path $path
            Write-Host ('[i] Shared IP report written: {0}' -f $path) @script:Cy
        }

        If ($script:Summary['PTRConflicts'] -and $script:Summary['PTRConflicts'].Count -gt 0) {
            $path = $base + 'PTRConflicts.csv'
            $script:Summary['PTRConflicts'] | Sort-Object | Set-Content -Path $path
            Write-Host ('[i] PTR conflict report written: {0}' -f $path) @script:Cy
        }
    }
    
    Function Show-WhatIfSummary          {
        <#
            .SYNOPSIS
            Displays a readable summary of what actions would have been taken in WhatIf mode.
            .DESCRIPTION
            Iterates through the $script:Summary hash and writes each category with relevant items,
            excluding empty ones, color-coded for readability.
            .NOTES
            Called only when $TestMode = $true
        #>
        [CmdletBinding()]
        Param ()

        Write-Host "`n=== WHATIF SUMMARY ===" @script:Cy

        ForEach ($key in $script:Summary.Keys) {
            $items = $script:Summary[$key]
            If (-not $items -or $items.Count -eq 0) { Continue }

            Write-Host ('{0,-20}: {1}' -f $key, $items.Count) @script:Ye

            $items | Sort-Object | ForEach-Object {
                Write-Host (' - {0}' -f $_) @script:Gy
            }
        }

        If ($script:Summary['ReverseAliasesFound'].Count -gt 0) {
            Write-Host "`n[!] PTR mismatches (Reverse Aliases):" @script:Ye
            $script:Summary['ReverseAliasesFound'] | Sort-Object | ForEach-Object {
                Write-Host (' - {0}' -f $_) @script:Ye
            }
        }

        If ($script:Summary['SkippedPTR'].Count -gt 0) {
            Write-Host "`n[!] Skipped PTR entries:" @script:Ye
            $script:Summary['SkippedPTR'] | Sort-Object | ForEach-Object {
                Write-Host (' - {0}' -f $_) @script:Ye
            }
        }

        Write-Host "`n[i] This was a simulation. No changes were made." @script:WI
    }
    #endregion Helper Functions

    ### Step 2: Create Variables
    ### Check credentials
    Test-DnsAdminRights

    ### Prompt to populate $script:ServerList
    Show-ServerInputDialog

    If (-not $script:ServerList -or $script:ServerList.Count -eq 0) {
        Write-Host '[!] No valid server entries provided. Exiting.' @script:Re
        return
    }

    ### Use advanced PTR zone fetcher
    $script:ReverseLookupZones = Get-AllPTRZones

    ### Load and cache all A records
    Write-Host '[i] Caching existing A records...' @script:Gy
    $script:AllARecords = Get-AllARecords
    Write-Host ('[i] Found {0} A records' -f $script:AllARecords.Count) @script:Ye

    $sharedConflicts = Get-SharedIPConflicts

    If ($sharedConflicts.Count -gt 0) {
        Write-Host "`n[!] Shared A record IPs detected:" @script:Ye

        ForEach ($ip in $sharedConflicts.Keys) {
            $fqdnList = $sharedConflicts[$ip] -join ', '
            Write-Host (' - {0}: {1}' -f $ip, $fqdnList) @script:Ye
            $script:Summary['SharedIPs'] += ('{0} ⇨ {1}' -f $ip, $fqdnList)
        }

        $script:Summary['SharedIPs'] = $script:Summary['SharedIPs'] | Sort-Object -Unique
    }

    $script:ServerList = Convert-ToServerList -RawText $List


    ### Step 3: Enforce DNS records against the PDC FSMO
    ForEach ($entry in $script:ServerList) {
        $entryStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $ip    = $entry.IP
        $fqdns = Get-CandidateFqdnsFromEntry -Entry $entry

        ForEach ($fqdn in $fqdns) {
            Write-Host ("`n--- Processing {0} ({1}) ---" -f $fqdn, $ip) @script:Cy

            Try {
                Update-ARecord   -DnsServer $script:DnsServer -HostFQDN $fqdn -ExpectedIP $ip
                Update-PTRRecord -DnsServer $script:DnsServer -HostFQDN $fqdn -IP $ip
            } Catch {
                Write-Host ('[X] Error processing {0}: {1}' -f $fqdn, $_) @script:Re
            }
        }

        $entryStopwatch.Stop()
        $elapsed = '{0:N2} sec' -f $entryStopwatch.Elapsed.TotalSeconds
        Write-Host ("[i] Time for {0}: {1}" -f $entry.Name, $elapsed) @script:Gy
    }

    ### Step 4: Write Summary
    Write-Host "`n=== Summary ===" @script:Cy

    $script:Summary.Keys | ForEach-Object {
        $category = $_
        $items    = $script:Summary[$category]
        Write-Host ('{0,-20}: {1}' -f $category, $items.Count) @script:Gy

        If ($script:Summary['ReverseAliasesFound'].Count -gt 0) {
            Write-Host "`n[i] PTR mismatches (Reverse Aliases):" @script:Ye
            $script:Summary['ReverseAliasesFound'] | Sort-Object | ForEach-Object {
                Write-Host (' - {0}' -f $_) @script:Ye
            }
        }

        If ($script:Summary['SkippedPTR'].Count -gt 0) {
            Write-Host "`n[i] PTR entries skipped due to invalid reverse target:" @script:Ye
            $script:Summary['SkippedPTR'] | Sort-Object | ForEach-Object {
                Write-Host (' - {0}' -f $_) @script:Ye
            }
        }
    }

    ### Show FQDN conflicts (same FQDN with multiple IPs)
    $script:Summary['FQDNConflicts'] = Get-FQDNReuseConflicts
    If ($script:Summary['FQDNConflicts'].Count -gt 0) {
        Write-Host "`n[!] FQDNs with multiple IPs detected:" @script:Ye
        $script:Summary['FQDNConflicts'] | Sort-Object | ForEach-Object {
            Write-Host (" - {0}" -f $_) @script:Ye
        }
    }

    If ($TestMode) {
        Show-WhatIfSummary
    } Else {
        Write-Host "`n[i] Changes applied. Review summary above." @script:Gr
    }

    Confirm-FinalDnsState -DnsServer $script:DnsServer -Entries $script:ServerList
    Export-ConflictReports

    $script:stopwatch.Stop()
    $ts = $script:stopwatch.Elapsed

    $runtimeFormatted = "{0} minute{1}, {2:D2}.{3:D3} seconds" -f $ts.Minutes, ($(If ($ts.Minutes -eq 1) { '' } Else { 's' })), $ts.Seconds, $ts.Milliseconds
    Write-Host ('[i] Total runtime: {0}' -f $runtimeFormatted) @script:Gr
}
Get-MassRename
