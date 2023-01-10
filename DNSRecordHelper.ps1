$script:PDC = 'dcs'

$dnsRecords = @()
$dnsRecords += [pscustomobject]@{hostname = 'k8slb';       ip = '192.168.34.60'; zonename = 'vcloud-lab.com'}
$dnsRecords += [pscustomobject]@{hostname = 'k8smaster01'; ip = '192.168.34.61'; zonename = 'vcloud-lab.com'}
$dnsRecords += [pscustomobject]@{hostname = 'k8smaster02'; ip = '192.168.34.62'; zonename = 'vcloud-lab.com'}
$dnsRecords += [pscustomobject]@{hostname = 'k8smaster03'; ip = '192.168.34.63'; zonename = 'vcloud-lab.com'}
$dnsRecords += [pscustomobject]@{hostname = 'k8sworker01'; ip = '192.168.34.66'; zonename = 'vcloud-lab.com'}
$dnsRecords += [pscustomobject]@{hostname = 'k8sworker02'; ip = '192.168.34.67'; zonename = 'vcloud-lab.com'}
$dnsRecords += [pscustomobject]@{hostname = 'k8sworker03'; ip = '192.168.34.68'; zonename = 'vcloud-lab.com'}

### Add new A Record with PTR
Function Create-DNSARecordwPTR {
    Param (
        [String]$hostname, 
        [ipaddress]$ip, 
        [string]$zonename,
        [switch]$wPTR
    )

    #ForEach ($dnsRecord in $dnsRecords) {
    
    #region Zone Construction
    $ip = $ip.Split('.')
    [array]::Reverse($ip)
    $ptrZoneName = '{0}.{1}.{2}.in-addr.arpa' -f $ip[1], $ip[2], $ip[3]
    #endregion Zone Construction

    ### Create Record
    $NewRecord = @{
        Name           = $hostname
        IPv4Address    = $ip
        ZoneName       = $zonename
        Server         = $PDC
        #CreatePtr      = $true
        AllowUpdateAny = $true
    }
    If ($wPTR) {$NewRecord.CreatePtr = $true}
    Add-DnsServerResourceRecordA @NewRecord

    ### Verify Record
    $recordA   = Get-DnsServerResourceRecord -Name $hostname -ZoneName $zonename    -RRType A   -Server $PDC
    $recordPtr = Get-DnsServerResourceRecord -Name $ip       -ZoneName $ptrZoneName -RRType PTR -Server $PDC
    [PSCustomObject]@{
        ForwardZoneName    = $dnsRecord.zonename
        RecordA_Name       = $recordA.HostName
        RecordA_IP         = $recordA.RecordData.IPv4Address
        BackwardZoneName   = $ptrZoneName 
        RecordPtr_Name     = $recordPtr.HostName 
        RecordPtr_HostName = $recordPtr.RecordData.PtrDomainName
    }

    #}
}

Function Create-PTRRecord {
    # Creates ptr records in a reverse lookup zone matching the subnet for each A record in a given forward zone.
    # This script assumes a /24 for each RLZ. You should modify the regex for $name and $rzname
    # to something that makes sense for you if your IP scheme is set up differently.

    # User input asking "which Domain Controller do I use?" and "which Forward Lookup Zone do I query?".
    Param (
	    [Parameter(Mandatory)][string]$forwardZoneName
    )

    # Get the DNS A records within the specified FLZ from the specified DC.
    $records = Get-DnsServerResourceRecord -ZoneName $forwardZoneName -RRType A -ComputerName $domainController
    ForEach ($record in $records) {
        # The reverse lookup domain name.  This is the PTR Response. This should look like host.forward.zone.tld or similar.
        $ptrDomain = $record.HostName + '.' + $forwardZoneName; 

        # Grab the last octet of the IP address for the record being processed. When creating the PTR record for a /24 the first three octets are already in place due to the RLZ naming schemes so we only need the last octet.
        $name = ($record.RecordData.IPv4Address.ToString() -replace '^(\d+)\.(\d+)\.(\d+).(\d+)$','$4');

        # Reverse the IP Address for the Zone Name. Leave off the last octet to place in proper /24 subnet. Once again if you're carving your subnets up differently you'll want to change this.
        $rzname = ($record.RecordData.IPv4Address.ToString() -replace '^(\d+)\.(\d+)\.(\d+).(\d+)$','$3.$2.$1') + '.in-addr.arpa';

        # Add the new PTR record.
        $PTRAddition = @{
            Name          = $name
            ZoneName      = $rzname
            ComputerName  = $domainController
            PtrDomainName = $ptrDomain
        }
        Add-DnsServerResourceRecordPtr @PTRAddition
    }
}

### CNAME
Function Create-CNAMERecord {
    Param (
        [Array]$CNAMERecord
    )
    $CNParams = @{
        Name          = $dnsRecord.hostname
        ZoneName      = $dnsRecord.zonename
        HostNameAlias = $dnsRecord.cname
        ComputerName  = $PDC
    }
    Add-DnsServerResourceRecordCName @CNParams
}

Function Change-DNSRecordTTL {
    Param (
        [string]$HostName, 
        [string]$ZoneName, 
        [Switch]$Static, 
        [Switch]$Dynamic
    )
    If ($Dynamic) {
        $OldObj = Get-DnsServerResourceRecord -Name $HostName -ZoneName $ZoneName -RRType "A"
        $NewObj = [ciminstance]::new($OldObj)
        $NewObj.TimeToLive = [System.TimeSpan]::FromHours(2)
        Set-DnsServerResourceRecord -NewInputObject $NewObj -OldInputObject $OldObj -ZoneName "contoso.com" -PassThru
    } ElseIf ($Static) {
        $OldObj = Get-DnsServerResourceRecord -Name $server -ZoneName $ZoneName -RRType "A"
        $NewObj = $OldObj.Clone()
        $NewObj.TimeToLive = [System.TimeSpan]::FromHours(0)
        Set-DnsServerResourceRecord -NewInputObject $NewObj -OldInputObject $OldObj -ZoneName $ZoneName -PassThru
    }
}
