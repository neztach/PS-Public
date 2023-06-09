Function Find-LANHosts {
    <#
      .SYNOPSIS
      Quickly scan IP ranges.
      .DESCRIPTION
      What makes it quick is using a drastic step of parsing the arp table.
      .PARAMETER IP
      IP(s)
      .PARAMETER DelayMS
      how many Milliseconds to wait on connection attempts - default is 2.
      .PARAMETER ClearARPCache
      *Must be Administrator* - Clears your ARP cache before running.
      .EXAMPLE
      Find-LANHosts -IP '192.168.2.10','192.168.2.11','192.168.2.12'
    #>
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

    If ($ClearARPCache) {
        arp -d
    }
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
                 ($_.Trim() -replace ' {1,}',',') | 
                 ConvertFrom-Csv -Header 'IP','MACAddress'
             }
    $Hosts = $Hosts | Where-Object {$_.IP -in $IP}

    Write-Output -InputObject $Hosts
}


#Find-LANHosts -ip @((1..255|%{"192.168.0.$_"})+(0..254|%{"192.168.1.$_"})) -OutVariable lanresults
#$results = Find-LANHosts -ip @(1..255|%{"192.168.2.$_"}) -OutVariable lanresults
#$results | Select IP,@{n='MACAddress';e={$_.MACAddress.replace('-',':').toUpper()}}

$Subnet = '192.168.2'
Find-LANHosts -ip @(
  1..255 | ForEach-Object {
      "$($Subnet).$_"
  }
) -OutVariable lanresults | 
Select-Object -Property IP, 
                        @{
                            n = 'MACAddress'
                            e = {$_.MACAddress.replace('-',':').toUpper()}
                        }
