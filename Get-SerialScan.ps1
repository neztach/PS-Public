Function Get-SerialScan {
    Begin {
        Remove-Job -Name *

        #region Computerlist File
        Function Read-OpenFileDialog{
            <#
                .SYNOPSIS
                An Open file GUI dialog.

                .DESCRIPTION
                Open File GUI.

                .PARAMETER WindowTitle
                Optional: Self-explanatory Window Title.

                .PARAMETER InitialDirectory
                Optional: Specify directory to start search in.

                .PARAMETER Filter
                SYNTAX: 'Name of file type (*.ext)|*.ext'
                  ex: 'All files (*.*)|*.*'
                  ex: 'Text Files (*.txt)|*.txt'
                  ex: 'Executable Files (*.exe, *.cmd)|*.exe,*.cmd'

                .PARAMETER AllowMultiSelect
                Optional: Self-explanatory.

                .EXAMPLE
                $Params = @{
                    WindowTitle     = "Simple multiple choice"
                    InitialDirectory = "$env:HOMEDRIVE"
                    Filter           = "Text Files (*.txt)|*.txt"
                    AllowMultiSelect = $true
                }
                $temp = Read-OpenFileDialog @Params

                Open a file browser dialog with the following options:
                  - Window Title             : 'Simple multiple choice'
                  - Start browsing from      : C:\
                  - Matching File Type       : *.txt
                  - Selecting Multiple Files : Enabled
                Store chosen files in $temp

                .EXAMPLE
                Read-OpenFileDialog -WindowTitle 'Browse for file' -InitialDirectory "$env:USERPROFILE\Desktop"

                Open a file browser dialog with the following options:
                  - Window Title             : 'Browse for file'
                  - Start browsing from      : Users Desktop
                  - Matching File Type       : *.*
                  - Selecting Multiple Files : Disabled
            #>

            [CmdletBinding()]
            Param (
                [string]$WindowTitle,
                [string]$InitialDirectory,
                [string]$Filter = 'All files (*.*)|*.*',
                [switch]$AllowMultiSelect
            )
            Add-Type -AssemblyName System.Windows.Forms
            $openFileDialog = New-Object -TypeName System.Windows.Forms.OpenFileDialog
            $openFileDialog.Title = $WindowTitle
            If (![string]::IsNullOrWhiteSpace($InitialDirectory)){
                $openFileDialog.InitialDirectory = $InitialDirectory
            }
            $openFileDialog.Filter = $Filter
            If ($AllowMultiSelect){
                $openFileDialog.MultiSelect = $true
            }
            $openFileDialog.ShowHelp = $true
            $openFileDialog.ShowDialog() > $null
            If ($AllowMultiSelect){
                Return $openFileDialog#.Filenames
            } else {
                Return $openFileDialog#.Filename
            }
        }
        
        ### Get file containing computernames
        $fileParams = @{
            WindowTitle = 'Text file with list of computers'
            Filter      = 'Text Files (*.txt)|*.txt'
        }
        $computerList      = Read-OpenFileDialog @fileParams
        $list_of_computers = (Get-Content -Path $computerList.Filename).Split()
        If ($list_of_computers.Count -lt 1){Break}
        #endregion Computerlist File        
        
        ### Variables
        #$credential            = Get-Credential
        #$id_array              = @()
        $ErrorActionPreference = 'SilentlyContinue'
        $OutputFile            = "$home\Desktop\Serial_list.csv"
        $computerlist          = @()
        New-Item    -Path $OutputFile -ItemType File -Force
        Set-Content -Path $OutputFile -Value 'Computer Name, Serial'
        
        #region Progress Meter
        $pi = 0
        $Progress = @{
            Activity         = 'Working through Computers . . .'
            CurrentOperation = 'Loading'
            PercentComplete  = 0
        }
        #endregion Progress Meter
    }
    Process {
        <# Old Code
            Foreach ($comp in $list_of_computers){
                Clear-Host
                $i++
                Write-Host "$i / $($list_of_computers.Count) -> $comp"
                Write-Host 'Step 1: Starting Job'
                Try {
                    $id = Invoke-Command -ComputerName $comp -Credential $credential -ThrottleLimit 50 -AsJob -ScriptBlock {
                        (Get-WmiObject -Class Win32_Bios).Serialnumber
                    }
                    Write-Output -InputObject $id
                } Catch {
                    Continue
                }
                $id_array += $id.Id
            }

            $x = 0
            ForEach ($job in $id_array) {
                Clear-Host
                Write-Host "$x / $($id_array.Count) --> $($list_of_computers[$x])"
                Write-Host 'Step 2: Writing Job Results to file'
                Try {
                    Wait-Job -Id $job -Timeout 30 -ErrorAction Stop
                } Catch {
                    Add-Content -Path $OutputFile -Value "$($list_of_computers[$x]),Offline";$x++
                    Continue
                }
                $serial = Receive-Job -Id $job
                If ($serial -eq $null) {
                    Add-Content -Path $OutputFile -Value "$($list_of_computers[$x]),Offline"
                    $x++
                    Continue
                }
                Add-Content -Path $OutputFile -Value "$($list_of_computers[$x]),$serial"
                $x++
            }
        #> ### Old Code

        Foreach ($comp in $list_of_computers){
            #region Progress Meter
            $pi++
            [int]$percentage           = ($pi / $($list_of_computers.Count))*100  
            $Progress.CurrentOperation = "$pi of $($list_of_computers.Count) - $comp"
            $Progress.PercentComplete  = $percentage
            Write-Progress @Progress
            #endregion Progress Meter
            
            $tempObj = New-Object -TypeName System.Management.Automation.PSObject
            $tempObj | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $comp.trim()
            $tempCompName = $comp
            If (Test-Connection -ComputerName $comp -Quiet -Count 1) {
                $computerHold   = Get-WmiObject -ComputerName $comp -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
                $computerMan    = $computerHold.Manufacturer
                $computerMod    = $computerHold.Model

                ### PC Serial Number
                $computerSerial = (Get-WmiObject -ComputerName $comp -Class Win32_Bios -ErrorAction SilentlyContinue).SerialNumber
                If ($computerSerial -match 'VMware')   {$computerSerial = 'VMware'}
                If ($computerSerial -notmatch 'VMware'){
                    ### Get Monitor WMI Objects
                    $monitorWmi     = Get-WmiObject -ComputerName $comp -Class WMIMonitorID -Namespace 'root\wmi' -ErrorAction SilentlyContinue
                    $monitorSerials = @()
                    $monitorWmi | ForEach-Object {
                        $Man                 = ($_.ManufacturerName -notmatch 0 | ForEach-Object {[char]$_}) -join ''
                        $Nam                 = Try {
                            ($_.UserFriendlyName -notmatch 0 | ForEach-Object {[char]$_}) -join ''
                        } Catch {
                            ($_.UserFriendlyName -notMatch 0 | ForEach-Object {$_}) -join ''
                        }
                        $Ser                 = ($_.SerialNumberID -notmatch 0 | ForEach-Object {[char]$_}) -join ''
                        $MonInst             = $_.InstanceName.split('\')[-1]
                        
                        ### $MonInfHold will fetch and store computername, monitor instance id, horizontal size, vertical size, do the match for overall size, and aspect ratio
                        $MonInfHold          = Get-WmiObject -ComputerName $tempCompName -Namespace root\wmi -Class WmiMonitorBasicDisplayParams | 
                                               Select-Object -Property @{N='Computer';E={$_.__SERVER}},
                                                                       InstanceName,
                                                                       @{N='Horizontal';E={[Math]::Round(($_.MaxHorizontalImageSize/2.54), 2)}},
                                                                       @{N='Vertical';E={[Math]::Round(($_.MaxVerticalImageSize/2.54), 2)}},
                                                                       @{N='Size';E={[Math]::Round(([Math]::Sqrt([Math]::Pow($_.MaxHorizontalImageSize, 2) + [Math]::Pow($_.MaxVerticalImageSize, 2))/2.54),2)}},
                                                                       @{N='Ratio';E={[Math]::Round(($_.MaxHorizontalImageSize)/($_.MaxVerticalImageSize),2)}}
                        $MonSize             = $MonInfHold | Where-Object {$_.InstanceName.split('\')[-1] -match $MonInst} | Select-Object -ExpandProperty Size
                        $monitorSerials     += "$Man,$Nam,$Ser,$MonSize inch"
                        $monitorSerialOutput = '{' + $($monitorSerials -join ' / ') + '}' # Convert $monitor serials to string
                    }
                } else {
                    $monitorSerialOutput = '{NA}'
                }
                ### Add the details to our $tempObj
                $tempObj | Add-Member -MemberType NoteProperty -Name 'CompManufacturer'     -Value $computerMan
                $tempObj | Add-Member -MemberType NoteProperty -Name 'ComputerModel'        -Value $computerMod
                $tempObj | Add-Member -MemberType NoteProperty -Name 'ComputerSerialNumber' -Value $computerSerial
                $tempObj | Add-Member -MemberType NoteProperty -Name 'MonitorSerialNumbers' -Value $monitorSerialOutput
                $tempObj | Add-Member -MemberType NoteProperty -Name 'Status'               -Value 'ONLINE'
            } else {
                ### If the computer is off, set the status property to offline so we can easily sort and filter them
                $tempObj | Add-Member -MemberType NoteProperty -Name 'Status'               -Value 'UNREACHABLE'
            }
            $computerList += $tempObj # Add the $temoObj to the $computerList array
        }
    }
    End {
        $computerlist = $computerList | 
                        Select-Object -Property ComputerName,
                                                CompManufacturer,
                                                ComputerModel,
                                                ComputerSerialNumber,
                                                MonitorSerialNumbers,
                                                Status | 
        Sort-Object -Property Status,ComputerName
        
        #Return $computerlist
        $computerlist | Export-CSV -Path $OutputFile -NoTypeInformation -Delimiter ',' -Encoding UTF8
        Write-Host 'COMPLETED' -ForegroundColor Green
    }
}

Get-SerialScan
