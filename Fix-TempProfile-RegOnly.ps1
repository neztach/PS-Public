Function script:Fix-TemporaryProfile {
    $PathProfiles = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $BAKKeys      = Get-ChildItem Registry::$PathProfiles | Where-Object {$_.Name -clike '*.bak'}
    If ($BAKKeys -eq $null) {
        Write-Warning "Registry has no .bak profiles"
    } Else {
        ForEach ($key in $BAKKeys) {
            $PathBAKKey      = $key.Name
            $NameOriginalKey = ($key.PSChildName) -replace '.bak'
            $PathOriginalKey = $PathBAKKey -replace '.bak'
            $PathTempKey     = $PathOriginalKey + ".temp"
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
                Write-Host "This fix worked. You may need to restart your computer." -ForegroundColor Green
            } Else {
                Write-Warning "This fix has not worked. Do it manually."
                $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
                $name    = "LastKey"
                $value   = "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                New-ItemProperty -Path $regPath -Name $name -Value $value -PropertyType String -Force | Out-Null
                Start-Process RegEdit
            }
            Write-Host "[INFO] SID : $NameOriginalKey"
            Write-Host
        }
    }
}
Fix-TemporaryProfile
