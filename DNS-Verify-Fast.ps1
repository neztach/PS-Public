function Get-DNSIssues {
    <#
      .SYNOPSIS
      Check for DNS mismatches and errors
      .DESCRIPTION
      This iterates through DNS reverse records looking for mismatches and errors
      .PARAMETER
      If you're looking for a specific PC entries, type that in after Get-DNSIssues
      .EXAMPLE
      Get-DNSIssues | Select-Object -Property Subnet,DNSName,FWD,PTR | Format-Table

      Will output all mismatch records and show those without FWD entries in red.
      .EXAMPLE
      Get-DNSIssues testmachine

      Will iterate through all DNS records and show only those that match the word testmachine
    #>
    Param ([string]$PCName)

    Import-Module -Name dnsserver
    
    ### Get PDC to use as DNS server to query
    $PDC    = ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers | Select-Object -Property Forest,@{n='Name';e={$_.Name.Split('.')[0]}}, Roles | Where-Object {$_.Roles -contains 'pdc'} | Select-Object -ExpandProperty Name
    
    ### If you would rather specify the DNS server to query, comment 
    ### out the above and uncomment out the below
    #$PDC   = 'DNSServer'
    
    $DNSErr  = New-Object -TypeName System.Collections.Arraylist
    $PCFound = New-Object -TypeName System.Collections.Arraylist
    $pi      = 0
    
    ### Define Write-Progress Splat Variables
    $Progress = @{
        Activity         = 'Working through records . . .'
        CurrentOperation = 'Loading'
        PercentComplete  = 0
    }
    
    ### Get Reverse Lookup Zones
    $ReverseLookupZones = Get-DnsServerZone -ComputerName $PDC | Where-Object IsReverseLookupZone -eq $True | Where-Object IsAutoCreated -eq $False | Where-Object ZoneName -notlike '*ip6*'
  
    ### Iterate through the Reverse lookup zones
    ForEach ($ReverseLookupZone in $ReverseLookupZones) {
        #region Variables
        $Servers         = $Null
        ### Get Zone Information
        $DNSZoneName     = $ReverseLookupZone.ZoneName
        #endregion Variables
        
        ### Get IP Information
        $ReverseIP       = $ReverseLookupZone.ZoneName.TrimEnd('.in-addr.arpa')
        $ReverseIPSuffix = $ReverseIP.Split('.')
        [array]::reverse($ReverseIPSuffix)
        $ReverseIPSuffix = $ReverseIPSuffix -join '.'
        
        ### Get Servers
        $Servers = Get-DnsServerResourceRecord -ZoneName $DNSZoneName -ComputerName $PDC | Where-Object HostName -ne '@'
        
        ### Iterate through $Servers
        ForEach ($Server in $Servers) {
            ### Get Server IP Address
            $ServerHostName  = $Server.HostName
            $ServerIPSuffix  = $ServerHostName.Split('.')
            [array]::reverse($ServerIPSuffix)
            $ServerIPSuffix  = $ServerIPSuffix -join '.'
            $ServerIPAddress = $ReverseIPSuffix + '.' + $ServerIPSuffix
            
            ### Get Server DNS Hostname
            $ServerDNSName   = $Server.RecordData.PtrDomainName
            $ServerDNSName   = $ServerDNSName.TrimEnd('.')
            
            ### Display and update Write-Progress
            $pi++
            [int]$percentage           = ($pi / $Servers.Count)*100  
            $Progress.CurrentOperation = "$pi of $($Servers.Count) - $ServerDNSName"
            $Progress.PercentComplete  = $percentage
            Write-Progress @Progress
            
            ### Get Server DNS Subnet
            $ServerDNSSubnet = $ServerIPAddress.Split('.')[0] + '.' + $ServerIPAddress.Split('.')[1] + '.' + $ServerIPAddress.Split('.')[2] + '.0/24'
            
            ### Resolve DNS Name
            Try {
                $DNSName = (Resolve-DnsName -Name $ServerDNSName -ErrorAction Stop)
            } Catch {
                If ($PCName){
                    If ($ServerDNSName.split('.')[0] -match $PCName){
                        $null = $PCFound.add((New-Object -TypeName PSObject -Property @{
                                    PTR     = $ServerIPAddress
                                    Subnet  = $ServerDNSSubnet
                                    DNSName = $ServerDNSName
                                    FWD     =''
                                }))
                        Break
                    }
                } Else {
                    Write-Host (('FWD Record not found for {0} of PTR Record {1}' -f $ServerDNSName, $ServerIPAddress)) -ForegroundColor Red
                    $DNSName = $null
                }
            }
            
            ### If DNSName resolves
            If ($DNSName) {
                ### Clear Values
                $Control = 0
                ForEach ($DNSRecord in $DNSName) {
                    ### Get Reverse DNS Name
                    $DNSIPAddress = $DNSRecord.IPAddress
                    
                    $sip = $ServerIPAddress
                    $sdn = $ServerDNSSubnet
                    $sds = $ServerDNSName
                    $dip = $DNSIPAddress
                    
                    If ($sds.split('.')[0] -match $PCName){
                        $null = $PCFound.add((New-Object -TypeName PSObject -Property @{
                            PTR     = $sip
                            Subnet  = $sdn
                            DNSName = $sds
                            FWD     = $dip
                        }))
                    }
                    ### If FWD Address patches PTR address - set $Control to 1
                    if ($DNSIPAddress -eq $ServerIPAddress) {
                        $Control = 1
                    }
                }
                ### If Control is not set to 1 that means FWD record doesn't match PTR record.
                ### These are the DNS entries that are bad.
                If ($Control -eq '0') {
                    #$Output = $ServerIPAddress + ";" + $ServerDNSSubnet + ";" + $ServerDNSName + ";" + $DNSIPAddress ### If Sending to ouput file
                    $null = $DNSErr.add((New-Object -TypeName PSObject -Property @{
                                PTR     = $sip
                                Subnet  = $sdn
                                DNSName = $sds
                                FWD     = $dip
                            }))
                    # Add-Content -Value $Output -Path "C:\down\PTRError.txt" ### If Sending to ouput file 
                    # Write-Warning $Output                                   ### If Sending to ouput file 
                }
            }
        }
    }
    If ($PCName){
        $PCFound = $PCFound | Select-Object -Property Subnet,DNSName,FWD,PTR
        Return $PCFound
    } Else {
        $DNSErr = $DNSErr | Select-Object -Property Subnet,DNSName,FWD,PTR
        Return $DNSErr
    }
}
