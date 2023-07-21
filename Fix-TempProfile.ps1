#region variables
$ErrorActionPreference = 'Stop'
$ScriptPath = '\\server\path\to\Scripts'
$ScriptName = 'Fix-TempProfile-RegOnly.ps1'
$ScriptRun  = $ScriptPath + '\' + $ScriptName
$PSExec     = 'c:\down\pstools\psexec.exe'

$username   = Read-Host -Prompt 'Input Username'
$PServers   = Read-Host -Prompt 'Input PC Name'

### Colors
$script:Gr  = @{ForegroundColor = 'Green'}
#endregion variables

Function script:Fix-TemporaryProfile {

    ### Path in the registry we need to be
    $PathProfiles = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $BAKKeys      = Get-ChildItem -Path Registry::$PathProfiles | Where-Object {$_.Name -clike '*.bak'} 
    If ($BAKKeys -eq $null) {
        Write-Warning -Message 'Registry has no .bak profiles'
    } Else { 
        ForEach ($key in $BAKKeys) { 
            $PathBAKKey      = $key.Name 
            $NameOriginalKey = ($key.PSChildName) -replace '.bak' 
            $PathOriginalKey = $PathBAKKey -replace '.bak' 
            $PathTempKey     = $PathOriginalKey + '.temp' 
            $NameTempKey     = $NameOriginalKey + '.temp' 
            $TempKeyExists   = Test-Path -Path Registry::$PathTempKey 
            $retry           = 3
            Do {
                If ($TempKeyExists -eq $true) { 
                    Remove-Item -Path Registry::$PathTempKey -Force -Recurse -Confirm:$false
                    Start-Sleep -Seconds 1
                }
                $TempKeyExists = Test-Path -Path Registry::$PathTempKey 
                $retry-- 
            } While (($TempKeyExists -eq $false) -and ($retry -gt 0)) 
            If ($TempKeyExists -eq $false) {
                Rename-Item -Path Registry::$PathOriginalKey -NewName $NameTempKey -Force
                Rename-Item -Path Registry::$PathBAKKey -NewName $NameOriginalKey -Force
            }
            $BAKKeyExist = Test-Path -Path Registry::$PathBAKKey
            If ($BAKKeyExist -eq $false) {
                Write-Host 'This fix worked. You may need to restart your computer.' @script:Gr
            } Else {
                Write-Warning -Message 'This fix has not worked. Do it manually.'
                $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit'
                $name    = 'LastKey'
                $value   = 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
                $null    = New-ItemProperty -Path $regPath -Name $name -Value $value -PropertyType String -Force
                Start-Process -FilePath RegEdit
            }
            Write-Host ('[INFO] SID : {0}' -f $NameOriginalKey)
            Write-Host
        }
    }
}

### If pc name isn't specified use local hostname
If (-not $Pservers) {$Pservers = $env:computername}
$Pservers | ForEach-Object {
    $Srv = $_
    Try {
        ### Try to delete username on target pc
        (Get-WmiObject -Class Win32_UserProfile -ComputerName $Srv | Where-Object {$_.LocalPath -like "c:\users\$username"}).Delete()
        Write-Host ('Deleted profile of {0} from {1}' -f $username, $Srv) @Gr
    } Catch {
        Write-Host ('Error For {0} from {1} - Error {2}' -f $username, $Srv, $_.Exception.Message)
    }
}
 
If ($Pservers) {
    #cmd /c "$PSExec \\$Pservers PowerShell -Execution Bypass -file $ScriptRun 2>&1"
    Invoke-Command -ComputerName ([Net.Dns]::GetHostAddresses("$Pservers")).IpAddressToString -FilePath $ScriptRun
} Else {
    Fix-TemporaryProfile
}
