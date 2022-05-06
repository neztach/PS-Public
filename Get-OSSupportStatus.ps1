<#09/03/2021
        EDIT : Adding Extended Support Check (ESU program)
#>
Begin {
    
    Function Write-Support {
        Param (
            [Parameter(Mandatory=$true,HelpMessage='Array')][Array]$Data,
            [Parameter(Mandatory=$true)][bool]$JU
        )
        $G     = @{ForegroundColor = 'Green'}
        $Y     = @{ForegroundColor = 'Yellow'}
        $R     = @{ForegroundColor = 'Red'}
        $today = Get-Date

        If ($JU) {
            $End = $Data | Where-Object {$_.Name -Match $_.DisplayName} | Select-Object -ExpandProperty End
            If ($today -lt $End){
                Write-Host ('{0} - Still Supported (EOL: {1})' -f $Data.Name, ($End)) @G
            } Else {
                Write-Host 'OS out of support' @R
                If ($_.Extended) {
                    $End = $Data | Where-Object {$_.Name -Match $_.DisplayName} | Select-Object -ExpandProperty Extended
                    If ($today -lt $End) {Write-Host ('{0} - ESU is still supported (EOL: {1})' -f $Data.Name, ($End)) @Y}
                }
            }
        } Else {
            $End = $Data | Select-Object -ExpandProperty End
            If ($today -lt $End){
                Write-Host ('{0} - OS currently supported (EOL: {1})' -f $Data.Name, ($End)) @G
            } Else{
                If ($_.Extended) {
                    $End = $Data | Select-Object -ExpandProperty Extended
                    Write-Host ('{0} - ' -f $Data.Name) -NoNewLine
                    If ($today -lt $End) {
                        Write-Host ('{0} - ESU is still supported (EOL: {1})' -f $Data.Name, ($End)) @Y
                    } Else {
                        Write-Host ('{0} - OS out of support (EOL: {1})' -f $Data.Name, ($End)) @R
                    }
                }
            }
        }
    }

    Function Get-OSEOL {
        $PreURL     = 'https://docs.microsoft.com/api/contentbrowser/search/lifecycles?locale=en-us&terms='
        $PostURL    = '&facet=products&%24top=1'
        $PreHeaders = @{
            'method'          = 'GET'
            'authority'       = 'docs.microsoft.com'
            'scheme'          = 'https'
            'sec-fetch-site'  = 'same-origin'
            'sec-fetch-mode'  = 'cors'
            'sec-fetch-dest'  = 'empty'
            'accept-encoding' = 'gzip, deflate, br'
        }
        Try {
            #Works on 2016/W10/W8
            $TryHeaders         = $PreHeaders
            $TryHeaders.Add('user-agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36')
            $TryHeaders.Add('accept','*/*')
            $wrongly_called_api = Invoke-WebRequest -ErrorAction SilentlyContinue -Uri "$($PreURL)$search$($PostURL)" -Headers $TryHeaders
        } Catch {
            #Workaround for older version of Powershell
            $wrongly_called_api = Invoke-WebRequest -UseBasicParsing -Uri "$($PreURL)$search$($PostURL)" -Headers $PreHeaders 
        }
        Return $wrongly_called_api
    }

    $REG         = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $os_name     = (Get-Item -Path $REG).GetValue('ProductName')
    $search      = $os_name.ToString().Replace(' ','%20')
    $display     = (Get-Item -Path $REG).GetValue('DisplayVersion')
    If ($null -eq $display) {$display = [Environment]::OSVersion.Version.Build}
}
Process {
    $OSEOL       = Get-OSEOL
    $json        = $OSEOL.Content | ConvertFrom-Json
    If ($null -eq ($json.results.end)) {
        $JsonC         = $true
        $search_result = Invoke-WebRequest -Uri ('https://docs.microsoft.com/en-us' + $json.results.Url)
        $dates         = ($search_result.Content -split '<tbody>' -split '</tbody>' )[1,3] -split '</tr>'
        $headers       = (($search_result.Content -split '<tbody>' -split '</tbody>' )[0] -split '<thead>' -split '</thead>')[1] -split '<tr>' -split '</tr>'
        $headers       = (($headers -split '<th align="right">')[2..(($headers -split '<th align="right">').Count)] -replace '</th>').Trim() | Where-Object {$_}
    } Else {
        $JsonC         = $false
        $headers       = @('Start Date','Retirement Date')
        $dates         = @"
        <tr>
          <td>$($json.results.title)</td>
            <local-time datetime="$($json.results.start.split('T')[0])">$($json.results.start.split('T')[0])</local-time>
          </td>
          <td align="right">
            <local-time datetime="$($json.results.end.split('T')[0])">$($json.results.end.split('T')[0])</local-time>
          </td>
        </tr>
"@
    }

    $sorted_info = @()
    $dates | ForEach-Object {
        $minmax = ($_ -split "<local-time datetime=`"")[1..(($_ -split "<local-time datetime=`"").Count -1)] | ForEach-Object {(($_ -split '</local-time>')[0] -split '">')[1]}
        If ($minmax -ne $null) {
            $value = [PSCustomObject]@{
                Name  = ($_ -split'<td>' -split '</td>')[1]
                Start = [Datetime]$minmax[0]
                End   = [Datetime]$minmax[1]
            }
            If ($headers[-1] -like 'Extended End Date') {
                $extended = [Datetime]$minmax[2]
                $value | Add-Member -MemberType NoteProperty -Name 'Extended' -Value $extended
            }
            $sorted_info += $value
        }
    }
    $sorted_info | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $display
}
End {
    Write-Support -Data $sorted_info -JU $JsonC
}
