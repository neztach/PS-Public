Function Find-LockoutSource {
    [CmdletBinding()]
    Param ($User)
    $ErrorActionPreference = 'SilentlyContinue'
    $DCs = (Get-ADDomainController -Filter *).Name
    ForEach ($DC in ($DCs | Sort-Object)) {
        Write-Output -InputObject "Checking events on $dc for User: $user"
        $eventParams = @{
            ComputerName = $DC
            Logname      = 'Security'
            FilterXPath  = "*[System[EventID=4740 or EventID=4625 or EventID=4770 or EventID=4771 and TimeCreated[timediff(@SystemTime) <= 3600000]] and EventData[Data[@Name='TargetUserName']='$User']]"
        }
        Get-WinEvent @eventParams | 
        Select-Object -Property TimeCreated, 
                                @{n='User Name';e={$_.Properties[0].Value}}, 
                                @{n='Source Host';e={$_.Properties[1].Value}} `
                      -ErrorAction SilentlyContinue | 
        Where-Object {$_.'Source Host' -notmatch 'S-1-5'} | 
        Format-Table -AutoSize
    }
}
Find-LockoutSource -User '<username>'
