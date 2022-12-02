### Get Non-Windows Services
Param ([string]$CN)
If ($CN) {
    $toReturn = Invoke-Command -ComputerName $CN -ScriptBlock {
        $NonDefaultServices = Get-wmiobject -Class Win32_Service | Where-Object {
            $_.Caption -notmatch 'Windows' -and $_.PathName -notmatch 'Windows' -and 
            $_.PathName -notmatch 'policyhost.exe' -and $_.Name -ne 'LSM' -and 
            $_.PathName -notmatch 'OSE.EXE' -and $_.PathName -notmatch 'OSPPSVC.EXE' -and 
            $_.PathName -notmatch 'Microsoft Security Client'
        }

        $Results = @()
        ForEach ($svc in $NonDefaultServices) {
            $Results += [pscustomobject]@{
                DisplayName = $svc.DisplayName
                Executable  = $svc.PathName
                StartMode   = $svc.StartMode
                StartName   = $svc.StartName
                State       = $svc.State
                Status      = $svc.Status
                Started     = $svc.Started
                Description = $svc.Description
            }
        }
        $Results
    }
} Else {
    $NonDefaultServices = Get-wmiobject -Class Win32_Service | Where-Object {
        $_.Caption -notmatch 'Windows' -and $_.PathName -notmatch 'Windows' -and 
        $_.PathName -notmatch 'policyhost.exe' -and $_.Name -ne 'LSM' -and 
        $_.PathName -notmatch 'OSE.EXE' -and $_.PathName -notmatch 'OSPPSVC.EXE' -and 
        $_.PathName -notmatch 'Microsoft Security Client'
    }

    $Results = @()
    ForEach ($svc in $NonDefaultServices) {
        $Results += [pscustomobject]@{
            DisplayName = $svc.DisplayName # Service Display Name (full name)
            Executable  = $svc.PathName    # Service Executable
            StartMode   = $svc.StartMode   # Service Startup mode
            StartName   = $svc.StartName   # Service RunAs Account
            State       = $svc.State       # Service State (running/stopped etc)
            Status      = $svc.Status      # Service Status
            Started     = $svc.Started     # Service Started status
            Description = $svc.Description # Service Description
        }
    }
    $toReturn = $Results
}
return $toReturn
