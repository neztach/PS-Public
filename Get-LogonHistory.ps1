Function Get-LogOnHistory {
    [CmdletBinding()]
    Param (
        [Parameter()][String]$Username, 
        [Parameter()][datetime]$StartTime, 
        [Parameter()][datetime]$EndTime, 
        [Parameter()][switch]$IncludeLogOff, 
        [Parameter()][string]$ComputerName = $env:COMPUTERNAME
    )
    $filter = @{
        LogName      = 'Security'
        ID           = @('4624')
        ProviderName = 'Microsoft-Windows-Security-Auditing'
    }
    If ($IncludeLogOff) {$filter['ID'] += '4634'}
    If ($StartTime)     {$filter.Add('StartTime', $StartTime)}
    If ($EndTime)       {$filter.Add('EndTime', $EndTime)}
    If ($Username)      {$filter.Add('Data', $Username)}
    $logOnTypeTable  = @{
        '2'  = 'Interactive'
        '3'  = 'Network'
        '4'  = 'Batch'
        '5'  = 'Service'
        '6'  = 'Unlock'
        '7'  = 'NetworkCleartext'
        '8'  = 'NewCredentials'
        '9'  = 'RemoteInteractive'
        '10' = 'RemoteInteractive'
        '11' = 'CachedInteractive'
    }
    Try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop -ComputerName $ComputerName
        ForEach ($event in $events) {
            [PSCustomObject]@{
                Server       = $env:COMPUTERNAME
                TimeStamp    = $event.TimeCreated
                EventType    = $(If ($event.Id -eq '4624') {'LogOn'} Else {'LogOff'})
                User         = $(If ($Username) {$Username} ElseIf ($event.Id -eq '4624') {$event.Properties[5].Value} Else {$event.Properties[1].Value})
                SourceIP     = $(If ($event.Id -eq '4624') {$event.Properties[18].Value} Else {$null})
                ComputerName = $ComputerName
                LogOnType    = $logOnTypeTable["$($event.Properties[8].value)"]
            }
        }
    } Catch {
        $_.Exception.Message | Out-Default
        return $null
    }
}
Get-LogOnHistory | ConvertTo-Csv -NoTypeInformation -Delimiter ',' | clip
 
# Get-LogOnHistory
#   -Username is string
#   -StartDate is a datetime = (Get-Date).AddDays(-14)
#   -EndDate is a datetime
#   -IncludeLogOff is a switch
#
# Get-LogOnHistory -StartDate (Get-Date).AddDays(-14) -IncludeLogOff | Where-Object {$_.User -match 'aregin'} | Format-Table -Autosize
