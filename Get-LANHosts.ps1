Function Find-LANHosts {
    [Cmdletbinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage='IPs', 
            Position = 1
        )]
        [string[]]$IP,
        [Parameter(
            Mandatory = $false, 
            Position = 2
        )]
        [ValidateRange(0,15000)]
        [int]$DelayMS = 2,
        [ValidateScript({
            $IsAdmin = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
            If ($IsAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $True
            } Else {
                Throw 'Must be running an elevated prompt to use ClearARPCache'
            }
        })]
        [switch]$ClearARPCache
    )

    $ASCIIEncoding = New-Object -TypeName System.Text.ASCIIEncoding
    $Bytes         = $ASCIIEncoding.GetBytes('a')
    $UDP           = New-Object -TypeName System.Net.Sockets.Udpclient

    if ($ClearARPCache) {arp -d}
    $Timer = [System.Diagnostics.Stopwatch]::StartNew()

    $IP | ForEach-Object {
        $UDP.Connect($_,1)
        [void]$UDP.Send($Bytes,$Bytes.length)
        If ($DelayMS) {
            [System.Threading.Thread]::Sleep($DelayMS)
        }
    }

    $Hosts = arp -a

    $Timer.Stop()
    $msg = 'Scan took longer than 15 seconds, ARP entries may have been flushed. Recommend lowering DelayMS parameter'
    If ($Timer.Elapsed.TotalSeconds -gt 15) {
        Write-Warning -Message $msg
    }

    $Hosts = $Hosts | Where-Object {$_ -match 'dynamic'} | ForEach-Object {
                 ($_.trim() -replace ' {1,}',',') | ConvertFrom-Csv -Header 'IP','MACAddress'
             }
    $Hosts = $Hosts | Where-Object {$_.IP -in $IP}

    Write-Output -InputObject $Hosts
}


#Find-LANHosts -ip @((1..255|%{"192.168.0.$_"})+(0..254|%{"192.168.1.$_"})) -OutVariable lanresults
#$results = Find-LANHosts -ip @(1..255|%{"192.168.2.$_"}) -OutVariable lanresults
#$results | Select IP,@{n='MACAddress';e={$_.MACAddress.replace('-',':').toUpper()}}
Find-LANHosts -ip @(1..255 | ForEach-Object {"192.168.2.$_"}) -OutVariable lanresults | 
Select-Object -Property IP,@{n='MACAddress';e={$_.MACAddress.replace('-',':').toUpper()}}
