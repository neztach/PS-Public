Function FunctionConfig {
    ### Default Information (information output when executed Get-SystemInfo without parameters)
    $DefaultInfoConfig = @(
        'OsCaption',
        'OsArchitecture',
        'OsUpTime',
        'OsLoggedInUser',
        'CPUName',
        'MotherboardModel',
        'DeviceModel',
        'MemoryTotal',
        'MemoryModules',
        'HddDevices',
        'VideoModel',
        'MonitorName',
        'CdRom'
    )

    $FunctionConfig    = @{
        ### OS Section
        OsVersion              = '-Class Win32_OperatingSystem -Property Version'
        OsCaption              = '-Class Win32_OperatingSystem -Property Caption'
        OSArchitecture         = '-Class Win32_OperatingSystem -Property OSArchitecture'
        OsInstallDate          = '-Class Win32_OperatingSystem -Script OS\OsInstallDate.ps1'
        OsUpTime               = '-Class Win32_OperatingSystem -Script OS\OsUptime.ps1 '
        OsProductKey           = '-Class StdRegProv            -Script OS\OsProductKey.ps1'
        OsLoggedInUser         = '-Class Win32_ComputerSystem  -Property UserName'
        OsAdministrators       = '-Query SELECT * FROM Win32_Group WHERE SID="S-1-5-32-544" -Script OS\OsAdministrators.ps1'
        OsActivationStatus     = '-Query Select * From SoftwareLicensingProduct Where ApplicationID = "55c92734-d682-4d71-983e-d6ec3f16059f" And Licensestatus > 0 -Script OS\OsActivationStatus.ps1'
        OsLastUpdateDaysAgo    = '-Class Win32_QuickFixEngineering -Script OS\OsLastUpdated.ps1'
        OsTimeZone             = '-Class Win32_TimeZone -Property Caption'
        OsVolumeShadowCopy     = '-Class Win32_Volume,Win32_ShadowCopy -Script OS\VolumeShadowCopy.ps1'
        OsTenLatestHotfix      = '-Class Win32_QuickFixEngineering -Script OS\TenLatestUpdates.ps1'
        OsUpdateAgentVersion   = '-Class Win32_OperatingSystem -Script OS\UpdateAgentVersion.ps1'
        OSRebootRequired       = '-Class Win32_OperatingSystem,StdRegProv -Script OS\RebootRequired.ps1'
        OsProfileList          = '-Class Win32_UserProfile -Script OS\UserProfileList.ps1'
        OsSRPSettings          = '-Class Win32_UserProfile,StdRegprov -Script OS\OsSRPSettings.ps1'
        AntivirusStatus        = '-Class Win32_OperatingSystem       -Script OS\AntivirusStatus.ps1'
        UserProxySettings      = '-Class Win32_UserProfile,StdRegprov -Script OS\UserProxySettings.ps1'
        MsOfficeInfo           = '-Class StdRegprov -Script OS\MsOfficeInfo.ps1'
        NetFolderShortcuts     = '-Class Win32_UserProfile -Script OS\NetFolderShortcuts.ps1'
        NetMappedDrives        = '-Class Win32_UserProfile,StdRegprov -Script OS\NetMappedDrives.ps1'
        OsGuid                 = '-Class StdRegprov -Script OS\OsGuid.ps1'
        OsSrpLog               = '-Class Win32_LocalTime -Script OS\OsSrpLog.ps1 -FormatList'
        OsKernelPowerFailCount = '-Class Win32_LocalTime -Script Os\OsKernelPowerFailCount.ps1'
        MseLastUpdateDate      = '-Class Win32_OperatingSystem,StdRegprov -Script os\MseLastUpdateDate.ps1'
        
        ### Powershell Section
        PsVersion              = '-Class StdRegProv -Script Ps\PsVersion.ps1'

        ### ActiveDirectory Section
        ADSiteName             = '-Class StdRegProv -Script ad\ADSiteName.ps1'

        ### Memory Section
        MemoryTotal            = '-Class Win32_PhysicalMemory      -Script Memory\MemoryTotal.ps1'
        MemoryAvailable        = '-Class Win32_OperatingSystem     -Script Memory\MemoryAvailable.ps1'
        MemoryFree             = '-Class Win32_OperatingSystem     -Script Memory\MemoryFree.ps1'                           
        MemoryModules          = '-Class Win32_PhysicalMemory       -Script Memory\MemoryModules.ps1'
        MemoryModInsCount      = '-Class Win32_PhysicalMemory      -Script Memory\MemoryModInsCount.ps1'
        MemoryMaxIns           = '-Class Win32_PhysicalMemoryArray -Script Memory\MemoryMaxIns.ps1'
        MemorySlots            = '-Class Win32_PhysicalMemoryArray -Script Memory\MemorySlots.ps1'
        ECCType                = '-Class Win32_PhysicalMemoryArray -Script Memory\ECCType.ps1'

        ### GPU section
        VideoModel             = '-Class Win32_VideoController -Script gpu\VideoModel.ps1'
        VideoRam               = '-Class Win32_VideoController -Script gpu\VideoRamMb.ps1'
        VideoProcessor         = '-Class Win32_VideoController -Script gpu\VideoProcessor.ps1'

        ### CPU section
        CPUName                = '-Class Win32_Processor -Script CPU\CpuName.ps1'
        CPUSocket              = '-Class Win32_Processor -Script CPU\CpuSocket.ps1'
        MaxClockSpeed          = '-Class Win32_Processor -Property MaxClockSpeed'
        CPUCores               = '-Class Win32_Processor -Property NumberOfCores'
        CPULogicalCore         = '-Class Win32_Processor -Property NumberOfLogicalProcessors'
        CPULoad                = '-Class Win32_Processor -Property LoadPercentage'
        CPUDescription         = '-Class Win32_Processor -Property Description'

        ### Motherboard section
        Motherboard            = '-Class win32_baseboard      -Property Manufacturer'
        MotherboardModel       = '-Class Win32_BaseBoard      -Property Product'
        DeviceModel            = '-Class Win32_Computersystem -Property model'

        ### BIOS Section
        SerialNumber           = '-Class Win32_Bios -Property SerialNumber'

        ### Monitor Section
        MonitorManuf           = '-Class wmiMonitorID -Script Monitor\MonitorManuf.ps1'
        MonitorPCode           = '-Class wmiMonitorID -Script Monitor\MonPCode.ps1'
        MonitorSN              = '-Class wmiMonitorID -Script Monitor\MonSn.ps1'
        MonitorName            = '-Class wmiMonitorID -Script Monitor\MonName.ps1'
        MonitorYear            = '-Class wmiMonitorID -Property YearOfManufacture'

        #Network Section
        NetworkAdapters        = '-Class Win32_NetworkAdapterConfiguration,Win32_NetworkAdapter,MSNdis_LinkSpeed,StdRegProv -Script Network\NetworkAdapters.ps1 -FormatList'
        NetworkAdaptersPowMan  = '-Class Win32_NetworkAdapter,StdRegProv,MSPower_DeviceEnable,MSPower_DeviceWakeEnable,MSNdis_DeviceWakeOnMagicPacketOnly -Script Network\NetworkAdaptersPowMan.ps1 -FormatList'
        NetPhysAdapCount       = '-Class Win32_NetworkAdapter -Script Network\NetPhysAdapCount.ps1'

        #Printer Section
        Printers               = '-Class Win32_Printer -Script Printer\Printers.ps1'
        UsbConPrCount          = '-Class Win32_Printer -Script Printer\UsbConPrCount.ps1'
        IsPrintServer          = '-Class Win32_Printer -Script Printer\IsPrintServer.ps1'
        UsbConPrOnline         = '-Class Win32_Printer -Script Printer\UsbConPrOnline.ps1'

        #CDROM Section
        Cdrom                  = '-Class Win32_CDROmDrive -Property Caption'
        CdromMediatype         = '-Class Win32_CDROMDrive -Property MediaType'

        ###USB Device Section
        UsbDevices             = '-Class Win32_USBControllerDevice -Script UsbDevice\UsbDevice.ps1'

        ### Software Section
        SoftwareList           = '-Class StdRegProv -Script Software\SoftwareList.ps1 -FormatList'
        SkypeInfo              = '-Class StdRegProv -Script Software\SkypeInfo.ps1 -FormatList'
        GoogleChromeInfo       = '-Class StdRegProv -Script Software\GoogleChromeInfo.ps1 -FormatList'
        SysmonInfo             = '-Class StdRegprov -Script Software\SysmonInfo.ps1'
        
        #HDD Section
        HddDevices             = '-Class Win32_DiskDrive,MSStorageDriver_FailurePredictStatus,MSStorageDriver_FailurePredictData,Win32_OperatingSystem -Script Storage\HddDevices.ps1'
        HDDSmart               = '-Class MSStorageDriver_FailurePredictStatus,MSStorageDriver_FailurePredictData,Win32_DiskDrive,Win32_OperatingSystem -Script Storage\HddSmart.ps1 -FormatList'
        HddSmartStatus         = '-Class MSStorageDriver_FailurePredictStatus,MSStorageDriver_FailurePredictData,Win32_DiskDrive -Script Storage\HddSmartStatus.ps1'
        HddPartitions          = '-Class Win32_DiskDrive -Script Storage\HddPartitions.ps1'
        HddVolumes             = '-Class Win32_Volume,Win32_LogicalDiskToPartition -Script Storage\HddVolumes.ps1'

        ### Vulnerabilities Section
        MeltdownSpectreStatus  = '-Class Win32_OperatingSystem,StdRegProv,Win32_Processor,Win32_QuickFixEngineering   -Script Vulnerabilities\MeltdownSpectreStatus.ps1'
        EternalBlueStatus      = '-Class Win32_OperatingSystem,StdRegProv                                             -Script Vulnerabilities\EternalBlueStatus.ps1'
    }

    $ManualNamespace   = @{
        wmiMonitorID                         = '-Namespace Root\wmi'
        MSStorageDriver_FailurePredictStatus = '-Namespace Root\wmi'
        MSStorageDriver_FailurePredictData   = '-Namespace Root\wmi'
        StdRegProv                           = '-Namespace ROOT\default'
        MSNdis_LinkSpeed                     = '-Namespace Root\wmi'
        MSPower_DeviceEnable                 = '-Namespace Root\wmi'
        MSPower_DeviceWakeEnable             = '-Namespace Root\wmi'
        MSNdis_DeviceWakeOnMagicPacketOnly   = '-Namespace Root\wmi'
        MSSMBios_RawSMBiosTables             = '-Namespace Root\wmi'
    }

    #################################################################################################################################
    ### Config Switch Param
    $SwitchConfig      = @{
        OSInfo               = 'OsVersion','OSArchitecture','OsCaption','OsInstallDate','OsUpTime','OsLoggedInUser','OsTimeZone','OsActivationStatus','OsAdministrators','AntivirusStatus'
        Cpu                  = 'CPUName','CPUSocket','MaxClockSpeed','CPUCores','CPULogicalCore','CPULoad'
        Hdd                  = 'HddDevices','HddPartitions','HddVolumes'
        Motherboard          = 'Motherboard','MotherboardModel','DeviceModel'
        Memory               = 'MemoryTotal','MemoryFree','MemoryModules','MemoryMaxIns','MemorySlots','MemoryAvailable','MemoryModInsCount','ECCType'
        Video                = 'VideoModel','VideoRam','VideoProcessor'
        Monitor              = 'MonitorManuf','MonitorName','MonitorPCode','MonitorSN','MonitorYear'
        NetworkAdapter       = 'NetworkAdapters','NetworkAdaptersPowMan'
        PrinterInfo          = 'Printers','UsbConPrCount','IsPrintServer','UsbConPrOnline'
        UsbDevices           = 'UsbDevices'
        SoftwareList         = 'SoftwareList'
        CheckVulnerabilities = 'OsCaption','OsLoggedInUser','MeltdownSpectreStatus','EternalBlueStatus'
    }

    ### Exclude switch Param
    $ExcludeParam = 'Verbose','AppendToResult','Debug'

    #################################################################################################################################
    ### Other Params
    $LocalComputer = $env:COMPUTERNAME,'Localhost','127.0.0.1'
    $AdminRequired = 'HDDSmart','HddDevices','HddSmartStatus','OsVolumeShadowCopy','NetworkAdaptersPowMan','SysmonInfo'
}

Function CreateErrorObject {
    Param ($Err,$ComputerName,$Protocol,$ExceptionJob)
    If ($Protocol -eq 'Wsman') {
        $WsmanErrorCodes=@{
            '5'           = 'access denied'
            '53'          = 'unreachable'
            '-2144108103' = 'unreachable'
            '-2144108250' = 'connection failed'
        }
        If ($err.Exception.ErrorCode) {
            If ($WsmanErrorCodes["$($err.Exception.ErrorCode)"]) {
                $WarningMessage = $WsmanErrorCodes["$($err.Exception.ErrorCode)"]
            } Else {
                $WarningMessage = $err.Exception.Message
            }
        } Else {
            $WarningMessage = $err.Exception.Message
        }
        If ($ExceptionJob) {$MainJobs.remove($ExceptionJob)}
    } ElseIf ($Protocol -eq 'Dcom') {
        $RunspaceErrorCodes = @{}
        If ($err.Exception.ErrorCode) {
            If ($RunspaceErrorCodes["$($err.Exception.ErrorCode)"]) {
                $WarningMessage = $RunspaceErrorCodes["$($err.Exception.ErrorCode)"]
            } Else {
                $WarningMessage = $err.Exception.Message
            }
        } Else {
            $WarningMessage=$err.Exception.Message
        }
        If ($ExceptionJob) {
            If ($Err.Exception.Message -eq 'Timeout expired') {
                #Write-Verbose "$($ExceptionJob.location) begin stop timeout job"
                #$Callback = {(New-Object System.Threading.ManualResetEvent($false)).Set()}
                #[void]$ExceptionJob.powershell.BeginStop($callback,$null)
            } Else {
                Write-Verbose -Message "$($ExceptionJob.location) Dispose Error Job"
                $ExceptionJob.powershell.dispose()
            }
            $ExceptionJob.State      = $null
            $ExceptionJob.powershell = $null
            $MainJobs.remove($ExceptionJob)
        }
    }
    Write-Warning -Message "$Computername $WarningMessage"
    $ErTmp = '' | Select-Object -Property ComputerName,Warning,Error
    $ErTmp.ComputerName  = $ComputerName
    $ErTmp.Warning       = $WarningMessage
    $ErTmp.Error         = $err
    $Global:ErrorResult += $ErTmp
}

Function OutResult {
    Param ([parameter(ValueFromPipeline=$true)]$Result)
    Process {
        If($Result) {
            $Result.PSObject.Properties.Remove('RunspaceId') 
            $Result.PSObject.Properties.Remove('PsComputerName')
            $Result | Get-Member | Where-Object {$_.definition -match 'Object' -or $_.definition -match 'ModuleSystemInfo'} | ForEach-Object {
                $PropertyName = $_.name
                $CompName     = $Result.computername
                $Result.$PropertyName | ForEach-Object {
                    $_ | Add-Member -MemberType NoteProperty -Name PsComputerName     -Value $CompName
                    $_ | Add-Member -MemberType NoteProperty -Name PSShowComputerName -Value $true
                }
            }
            If ($UpdateFormatData) {
                #Remove old ps1xml file
                If (Test-Path -Path $($env:TEMP+'\SystemInfoAutoformat.ps1xml')) {
                    Write-Verbose -Message "Remove old ps1xml file $($env:TEMP+'\SystemInfoAutoformat.ps1xml')"
                    Remove-Item -Path $($env:TEMP+'\SystemInfoAutoformat.ps1xml') -Force
                }
                CreateFormatPs1xml -ForObject $Result -ErrorAction Stop
                Update-FormatData -PrependPath $($env:TEMP+'\SystemInfoAutoformat.ps1xml') -ErrorAction SilentlyContinue
                Set-Variable -Name UpdateFormatData -Value $false -Scope 1 -Force
            }
            $Result.PSObject.TypeNames.Insert(0,'ModuleSystemInfo.Systeminfo.AutoFormatObject') 
            $Result
            $Global:Result += $Result
        }
    }
}

Function CreateResult {
    #$HashtableWMi[$computername] | Get-Member -MemberType NoteProperty | foreach {New-Variable -Name $_.Name -Value $HashtableWMi[$computername].$($_.Name)[0]}
    $HashtableWMi.Keys | ForEach-Object {
        Write-Verbose -Message "Create variable $_"
        New-Variable -Name $_ -Value $HashtableWMi[$_]
    }
    $Result = New-Object -TypeName psobject
    $Result | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computername
    $WmiParamArray | ForEach-Object {
        If ($_.Property) {
            $Property       = $_.Property
            $Class          = $_.class
            $Action         = $_.Action
            $ActionProperty = $_.Actionproperty
            If ($ActionProperty -eq 'Property') {
                Write-Verbose -Message ("$ComputerName Add to result $Property=$" + "$Class.$Action")  
                $WmiVar = $HashtableWMi[$class]
                #$WmiVar | fl
                If ($WmiVar.count -gt 1) {  
                    $ResultParamProperty = $WmiVar | ForEach-Object {$_.$Action}
                } Else {  
                    $ResultParamProperty = $WmiVar.$Action
                }
            } ElseIf ($ActionProperty -eq 'Function') {
                Write-Verbose -Message ("$ComputerName Add to result $Property=$($_.Action)")
                $ResultParamProperty = & $Action    
            }
            If ($null -eq $ResultParamProperty) {
                $ResultParamProperty = 'NotSupported'
            }
            $Result | Add-Member -MemberType NoteProperty -Name $Property -Value $ResultParamProperty
        }
    }
    $Result
}

Function FormatObject {
    Function CreateFormatPs1xml {
        [CmdletBinding()]
        Param ($ForObject)
        $ConvertToGb           = 'MemoryTotal','MemoryMaxIns','MemoryFree','MemoryAvailable','VideoRam'
        $FormatTableFor        = 'PSCustomObject','ManagementObject'
        [string]$XmlFormatList = ''
        #ScriptBlock Variable
        $DollarUnder           = '$_'
        $ScriptBlockTypeObject = '$ScriptBlockTypeObject'
        $SelectObjects         = '[Array]$SelectObjects'
        $SelectObject          = '$SelectObject'
        $SBfalse               = '$false'
        $SbNull                = '$Null'
        $AllProperties | ForEach-Object {
            $Property = $_
            If ($Forobject.$Property.count -gt 1) {
                $ForObjectProperty = $Forobject.$Property[0]
            } Else {
                $ForObjectProperty = $Forobject.$Property
            }
            If ($null -eq $ForObjectProperty) {
                $XmlFormatList += "
                    <ListItem>
                        <PropertyName>$Property</PropertyName>
                    </ListItem>"
            } ElseIf ($ForObject.RunspaceId) {
                
            } ElseIf ($PropertyParams[$Property].FormatList) {
                $XmlFormatList += "
                    <ListItem>
                        <Label>$Property</Label>
                        <ScriptBlock> 
                            $DollarUnder.$Property | Format-List | Out-String
                        </ScriptBlock>
                    </ListItem>"
            } ElseIf ($FormatTableFor -eq ($ForObjectProperty).GetType().name) {
                $XmlFormatList += "
                    <ListItem>
                        <Label>$Property</Label>
                        <ScriptBlock>
                            If ($DollarUnder.$Property.count -eq $SbNull) {$ScriptBlockTypeObject = $DollarUnder.$Property.psobject.typenames[0]} else {$ScriptBlockTypeObject = $DollarUnder.$Property[0].psobject.typenames[0]}
                            $SelectObjects+=$DollarUnder.$Property | Select-object -property * -ExcludeProperty PsComputername,PSShowComputerName
                            ForEach ($SelectObject in $SelectObjects) {$SelectObject.psobject.typenames.insert(0,$ScriptBlockTypeObject)}
                            $SelectObjects | Format-Table -AutoSize | Out-String
                        </ScriptBlock>
                    </ListItem>"
            } ElseIf ($ConvertToGb -eq $Property) {
                $XmlFormatList += "<ListItem>
                    <Label>$Property</Label>
                    <ScriptBlock>
		                [string]('{0:N1}' -f ($DollarUnder.$property/1gb))+'Gb'
                    </ScriptBlock>
                </ListItem>"
            } Else {
                $XmlFormatList += "
                    <ListItem>
                        <PropertyName>$Property</PropertyName>
                    </ListItem>"
            }
        }
        #$XmlFormatList
        $XmlAutoFormat  = '<?xml version="1.0" encoding="utf-8" ?>'
        $XmlAutoFormat += "
            <Configuration>
                <ViewDefinitions>
                    <View>
                        <Name>Default</Name>
                        <ViewSelectedBy>
                            <TypeName>ModuleSystemInfo.Systeminfo.AutoFormatObject</TypeName>
                        </ViewSelectedBy>
                        <ListControl>
                            <ListEntries>
                                <ListEntry>
                                    <ListItems>
                                        <ListItem>
                                            <PropertyName>ComputerName</PropertyName>
                                        </ListItem>
                                        $XmlFormatList
                                    </ListItems>
                                </ListEntry>
                            </ListEntries>
                        </ListControl>
                    </View>
                </ViewDefinitions>
            </Configuration>"
        Write-Verbose -Message "Create ps1xml file $($env:TEMP+'\SystemInfoAutoformat.ps1xml')"
        $XmlAutoFormat | Out-File -FilePath $($env:TEMP+'\SystemInfoAutoformat.ps1xml') -Force -ErrorAction Stop
    }
}

Function GetHddSmart {
    Param ($OsVersion)
    Function ConvertTo-Hex {
        Param($DEC)
        '{0:x2}' -f [int]$DEC
    }
    Function ConvertTo-Dec {
        Param ($HEX)
        [Convert]::ToInt32( $HEX, 16 )
    }
    Function Get-AttributeDescription {
        Param ($Value)
        Switch ($Value) {
            '01' {'Raw Read Error Rate'}
            '02' {'Throughput Performance'}
            '03' {'Spin-Up Time'}
            '04' {'Number of Spin-Up Times (Start/Stop Count)'}
            '05' {'Reallocated Sector Count'}
            '07' {'Seek Error Rate'}
            '08' {'Seek Time Performance'}
            '09' {'Power On Hours Count (Power-on Time)'}
            '0a' {'Spin Retry Count'}
            '0b' {'Calibration Retry Count (Recalibration Retries)'}
            '0c' {'Power Cycle Count'}
            'aa' {'Available Reserved Space'}
            'ab' {'Program Fail Count'}
            'ac' {'Erase Fail Count'}
            'ae' {'Unexpected power loss count'}
            'b7' {'SATA Downshift Error Count'}
            'b8' {'End-to-End Error'}
            'bb' {'Reported Uncorrected Sector Count (UNC Error)'}
            'bc' {'Command Timeout'}
            'bd' {'High Fly Writes'}
            'be' {'Airflow Temperature'}
            'bf' {'G-Sensor Shock Count (Mechanical Shock)'}
            'c0' {'Power Off Retract Count (Emergency Retry Count)'}
            'c1' {'Load/Unload Cycle Count'}
            'c2' {'Temperature'}
            'c3' {'Hardware ECC Recovered'}
            'c4' {'Reallocated Event Count'}
            'c5' {'Current Pending Sector Count'}
            'c6' {'Offline Uncorrectable Sector Count'}
            'c7' {'UltraDMA CRC Error Count'}
            'c8' {'Write Error Rate (MultiZone Error Rate)'}
            'c9' {'Soft Read Error Rate'}
            'cb' {'Run Out Cancel'}
            'cà' {'Data Address Mark Error'}
            'dc' {'Disk Shift'}
            'e1' {'Load/Unload Cycle Count'}
            'e2' {'Load ''In''-time'}
            'e3' {'Torque Amplification Count'}
            'e4' {'Power-Off Retract Cycle'}
            'e8' {'Endurance Remaining'}
            'e9' {'Media Wearout Indicator'}
            'f0' {'Head Flying Hours'}
            'f1' {'Total LBAs Written'}
            'f2' {'Total LBAs Read'}
            'f9' {'NAND Writes (1GiB)'}
            'fe' {'Free Fall Protection'}
            default {$Value}
        }
    }
    $PnpDev      = @{}
    $hdddev      = $Win32_DiskDrive | Select-Object -Property Model,Size,MediaType,InterfaceType,FirmwareRevision,SerialNumber,PNPDeviceID,Index
    $hdddev | ForEach-Object {$PnpDev.Add($($_.pnpdeviceid -replace '\\','\\'),$_)}
    $AllHddSmart = @()
    $PnpDev.Keys | ForEach-Object {
        $PnpDevid          = $_
        $TmpFailData       = $MSStorageDriver_FailurePredictData | Where-Object  {$_.InstanceName -Match $PnpDevid}
        $TmpFailStat       = $MSStorageDriver_FailurePredictStatus | Where-Object  {$_.InstanceName -Match $PnpDevid}
        If ($TmpFailStat) {
            $PnpDev[$PnpDevid] | Add-Member -MemberType NoteProperty -Name PredictFailure -Value $TmpFailStat.PredictFailure
        } Else {
            $PnpDev[$PnpDevid] | Add-Member -MemberType NoteProperty -Name PredictFailure -Value 'Unknown'
        }
        If ($TmpFailData) {
            $Disk  = $TmpFailData
            $i     = 0
            #$Report = @()
            $pByte = $null
            ForEach ($Byte in $Disk.VendorSpecific) {
                $i++
                If (($i - 3) % 12 -eq 0 ) {
                    If ($Byte -eq 0) {break}
                    $Attribute = '{0:x2}' -f [int]$Byte
                } Else {
                    $post  = ConvertTo-Hex -DEC $pByte
                    $pref  = ConvertTo-Hex -DEC $Byte
                    $Value = ConvertTo-Dec -HEX "$pref$post"
                    If (($i - 3) % 12 -eq 6 ) {
                        If ($Attribute -eq '09') {[int]$Value = $Value / 24}
                        $PnpDev[$PnpDevid] | Add-Member -MemberType NoteProperty -Name $(Get-AttributeDescription -Value $Attribute) -Value $Value
                    }
                }
                $pByte = $Byte
            }
        } Else {
            $PnpDev[$PnpDevid] | Add-Member -MemberType NoteProperty -Name SmartStatus -Value 'Unknown' 
        }
        $HddSmart          = $PnpDev[$PnpDevid]
        $WarningThreshold  = @{
            'Temperature'                        = 48,54
            'Reallocated Sector Count'           = 1,10
            'Reallocated Event Count'            = 1,10
            'Offline Uncorrectable Sector Count' = 1,10
            'Current Pending Sector Count'       = 1,10
        }
        $CriticalThreshold = @{
            'Temperature'                        = 55
            'Reallocated Sector Count'           = 11
            'Reallocated Event Count'            = 11
            'Offline Uncorrectable Sector Count' = 11
            'Current Pending Sector Count'       = 11
        }
        $HddWarning        = $False
        $HddCritical       = $False
        $HddSmart | Get-Member | ForEach-Object {
            $Property = $_.name
            If (!$HddCritical) {
                If ($WarningThreshold[$Property]) {
                    $MinWarningThreshold = $WarningThreshold[$Property][0]
                    $MaxWarningThreshold = $WarningThreshold[$Property][1]
                    If ($HddSmart.$Property -le $MaxWarningThreshold -and $HddSmart.$Property -ge $MinWarningThreshold) {
                        $HddWarning = $true
                        $Cause      = $($Property -replace ' ') + ' ' + [string]$($HddSmart.$Property)
                        If ($HddSmart.$Property -ge $WarningEventCount) {
                            $RootCause         = $Cause
                            $WarningEventCount = $HddSmart.$Property
                        }
                        Write-Verbose -Message "Smart Warning $cause"
                    }
                }
            }
            If ($CriticalThreshold[$Property]) {
                $MinCriticalThreshold = $CriticalThreshold[$Property]
                If($HddSmart.$Property -ge $MinCriticalThreshold) {
                    $HddCritical = $true
                    $Cause       = $($Property -replace ' ') + ' ' + [string]$($HddSmart.$Property)
                    If ($HddSmart.$Property -ge  $CriticalEventCount) {
                        $RootCause         =$Cause
                        $CriticalEventCount=$HddSmart.$Property
                    }
                    Write-Verbose -Message "Smart Critical $cause" 
                } 
            }
        }
        If ($HddSmart.smartstatus -ne 'Unknown') {
            If ($HddWarning) {
                $HddSmart | Add-Member -MemberType NoteProperty -Name SmartStatus -Value "Warning:$RootCause" 
            } ElseIf ($HddCritical -or $HddSmart.PredictFailure) {
                $HddSmart | Add-Member -MemberType NoteProperty -Name SmartStatus -Value "Critical:$RootCause"   
            } Else {
                $HddSmart | Add-Member -MemberType NoteProperty -Name SmartStatus -Value 'Ok'   
            }
        }
        $AllHddSmart      += $HddSmart
    }
    If ([version]$OsVersion -ge [version]'6.2') {
        #https://msdn.microsoft.com/en-us/library/windows/desktop/hh830532(v=vs.85)#methods
        $BusTypeHashTable   = @{
            '0'  = 'Unknown'
            '1'  = 'SCSI'
            '2'  = 'ATAPI'
            '3'  = 'ATA'
            '4'  = 'IEEE 1394'
            '5'  = 'SSA'
            '6'  = 'FibreChannel'
            '7'  = 'USB'
            '8'  = 'RAID'
            '9'  = 'iSCSI'
            '10' = 'SAS'
            '11' = 'SATA'
            '12' = 'SD'
            '13' = 'MMC'
            '15' = 'FileBackedVirtual'
            '16' = 'StorageSpaces'
        }
        $MediaTypeHashTable = @{
            '0' = 'Unknown'
            '3' = 'HDD'
            '4' = 'SSD'
            '5' = 'SCM'
        }
        Write-Verbose -Message "$ComputerName Windows 8 or later detected"
        If ($null -eq $credential) {
            $MSFT_PhysicalDisk = Get-WmiObject -Class MSFT_PhysicalDisk -Namespace root\Microsoft\Windows\Storage -ComputerName $computername -ErrorAction SilentlyContinue
        } Else {
            $MSFT_PhysicalDisk = Get-WmiObject -Class MSFT_PhysicalDisk -Namespace root\Microsoft\Windows\Storage -ComputerName $computername -Credential $credential -ErrorAction SilentlyContinue
        }
        If ($null -ne $MSFT_PhysicalDisk) {
            $AllHddSmart | ForEach-Object {
                $HddSmart      = $_
                $MsftDisk      = $MSFT_PhysicalDisk | Where-Object {$_.DeviceId -eq $HddSmart.index} 
                $InterfaceType = $BusTypeHashTable["$($MsftDisk.bustype)"]
                $MediaType     = $MediaTypeHashTable["$($MsftDisk.mediatype)"]
                If ($null -ne $InterfaceType) {$HddSmart.InterfaceType = $InterfaceType}
                $HddSmart | Add-Member -MemberType NoteProperty -Name Type -Value $MediaType
            }
            $AllHddSmart
        } Else {
            $AllHddSmart | ForEach-Object {
                $_ | Add-Member -MemberType NoteProperty -Name Type -Value 'Unknown'
                $_
            }
        }
    } Else {
        $AllHddSmart | ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name Type -Value 'Unknown'
            $_
        }
    }
}

Function GetInstalledSoftware {
    [cmdletbinding()]
    Param ([string]$SoftwareName,[string]$MatchSoftwareName,[array]$MatchExcludeSoftware,[switch]$DisplayAdvInfo)
    Try {
        Function GetSoftwareFromRegistry {
            Param ([string]$RootKey,[array]$SubKeys,[string]$MatchSoftwareName,[string]$SoftwareName,[string]$DisplayOSArch)
            Function CreateSoftwareInfo {
                $Version   = RegGetValue -key $ChildPath -Value 'DisplayVersion' -GetValue GetStringValue -ErrorAction SilentlyContinue
                $Publisher = RegGetValue -key $ChildPath -Value 'Publisher' -GetValue GetStringValue -ErrorAction SilentlyContinue
                $TmpObject = New-Object -TypeName PSObject
                $TmpObject | Add-Member -MemberType NoteProperty -Name AppName      -Value $AppName
                $TmpObject | Add-Member -MemberType NoteProperty -Name Architecture -Value $DisplayOSArch
                $TmpObject | Add-Member -MemberType NoteProperty -Name Version      -Value $Version
                If ($DisplayAdvInfo.IsPresent) {
                    $InstallLocation = RegGetValue -key $ChildPath -Value 'InstallLocation' -GetValue GetStringValue -ErrorAction SilentlyContinue
                    $UninstallString = RegGetValue -key $ChildPath -Value 'UninstallString' -GetValue GetStringValue -ErrorAction SilentlyContinue
                    $TmpObject | Add-Member -MemberType NoteProperty -Name InstallLocation -Value $InstallLocation
                    $TmpObject | Add-Member -MemberType NoteProperty -Name UninstallString -Value $UninstallString
                }
                $TmpObject | Add-Member -MemberType NoteProperty -Name Publisher -Value $Publisher
                $TmpObject
            }
            $SubKeys | ForEach-Object {
                $ChildPath = Join-Path -Path $RootKey -ChildPath $_      
                $AppName   = $null
                $AppName   = RegGetValue -key $ChildPath -Value 'DisplayName' -GetValue GetStringValue -ErrorAction SilentlyContinue
                If ($null -ne $AppName) {
                    If ($null -ne $PSBoundParameters['MatchSoftwareName']) {
                        If ($AppName -match $MatchSoftwareName) {CreateSoftwareInfo} Else {Write-Verbose -Message "Skip $AppName"}
                    } ElseIf ($null -ne $PSBoundParameters['SoftwareName']) {
                        If ($AppName -eq $SoftwareName) {CreateSoftwareInfo} Else {Write-Verbose -Message "Skip $AppName"}
                    } Else {
                        CreateSoftwareInfo   
                    }
                } Else {
                    Write-Verbose -Message "$Computername $ChildPath Value DisplayName is Null"
                }
            }
        }
        $GetArch = RegGetValue -key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Value 'PROCESSOR_ARCHITECTURE' -GetValue GetStringValue -ErrorAction Stop
        If ($GetArch -eq 'AMD64') {$OSArch = '64-bit'} Else {$OSArch = '32-bit'}
        $AllSoftWare = @()
        If ($OSArch -eq '64-bit') {
            $RootUninstallKeyX64 = 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'  
            [array]$SubKeysX64 = RegEnumKey -key $RootUninstallKeyX64
            If ($null -ne $PSBoundParameters['MatchSoftwareName']) {
                $AllSoftWare += GetSoftwareFromRegistry -RootKey $RootUninstallKeyX64 -SubKeys $SubKeysX64 -DisplayOSArch '32-bit' -MatchSoftwareName $MatchSoftwareName
            } ElseIf ($null -ne $PSBoundParameters['SoftwareName']) {
                $AllSoftWare += GetSoftwareFromRegistry -RootKey $RootUninstallKeyX64 -SubKeys $SubKeysX64 -DisplayOSArch '32-bit' -SoftwareName $SoftwareName
            } Else {
                $AllSoftWare += GetSoftwareFromRegistry -RootKey $RootUninstallKeyX64 -SubKeys $SubKeysX64 -DisplayOSArch '32-bit'
            }
        }
        $RootUninstallKey = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        [array]$SubKeys   = RegEnumKey -key $RootUninstallKey
        If ($null -ne $PSBoundParameters['MatchSoftwareName']) {
            $AllSoftWare += GetSoftwareFromRegistry -RootKey $RootUninstallKey -SubKeys $SubKeys -DisplayOSArch $OSArch -MatchSoftwareName $MatchSoftwareName
        } ElseIf ($null -ne $PSBoundParameters['SoftwareName']) {
            $AllSoftWare += GetSoftwareFromRegistry -RootKey $RootUninstallKey -SubKeys $SubKeys -DisplayOSArch $OSArch -SoftwareName $SoftwareName
        } Else {
            $AllSoftWare += GetSoftwareFromRegistry -RootKey $RootUninstallKey -SubKeys $SubKeys -DisplayOSArch $OSArch
        }
        If ($AllSoftWare.count -ne 0) {
            $AllSoftWare | Sort-Object -Property {$_.AppName} -Unique | ForEach-Object {
                $ReturnSoftware = $True
                $Software       = $_
                If ($null -ne $PSBoundParameters['MatchExcludeSoftware']) {
                    $MatchExcludeSoftware | ForEach-Object {
                        If ($Software.AppName -match "^$_") {$ReturnSoftware = $false}
                    }
                } 
                If ($ReturnSoftware) {$Software}
            }
        } Else {
            Write-Error -Message 'not found'
        }
    } Catch {
        Write-Error -Message $_
    }
}

Function GetSmbiosStruct {
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$true)][int]$Type,
        [parameter(Mandatory=$true)][string]$Offset,
        [parameter(Mandatory=$true)][ValidateSet('String','Other')]$Value
    )
    Function ConvertToHex {
        Param ($DEC)
        '{0:x2}' -f [int]$DEC
    }

    Function ConvertToDec {
        Param ($HEX)
        [Convert]::ToInt32($HEX, 16)
    }
    If ($Offset -match '(.+)h$') {
        [string]$OffsetHexValue = $Matches[1]    
        [int]$OffsetDecValue    = ConvertToDec -HEX $OffsetHexValue
    } Else {
        Write-Error -Message 'Unknown offset..'
    }
    If ($null -eq $MSSMBios_RawSMBiosTables) {
        If ($null -eq $Computername) {$Computername = $env:COMPUTERNAME}
        If ($credential) {
            $MSSMBiosData = (Get-WmiObject -Class MSSMBios_RawSMBiosTables -Namespace root\wmi -ComputerName $Computername -Credential $credential -ErrorAction SilentlyContinue).SMBiosData
        } Else {
            $MSSMBiosData = (Get-WmiObject -Class MSSMBios_RawSMBiosTables -Namespace root\wmi -ComputerName $Computername -ErrorAction SilentlyContinue).SMBiosData
        }
    } Else {
        $MSSMBiosData = $MSSMBios_RawSMBiosTables | ForEach-Object {$_.SmBiosData}    
    }
    If ($null -ne $MSSMBiosData) {
        $i      = 0
        $Struct = $null
        While (($null -ne $MSSMBiosData[$i+1]) -and ($MSSMBiosData[$i+1] -ne 0)) {
            # While the structure has non-0 length
            $i0 = $i
            $n  = $MSSMBiosData[$i]   # Structure type
            $l  = $MSSMBiosData[$i+1] # Structure length
            #Write-Verbose "Skipping structure $n body"
            $i += $l # Skip the structure body
            If ($MSSMBiosData[$i] -eq 0) {$i++} # If there's no trailing string, skip the extra NUL
            While ($MSSMBiosData[$i] -ne 0) { # And skip the trailing strings
                $s = ''
                While ($MSSMBiosData[$i] -ne 0) {$s += [char]$MSSMBiosData[$i++]}
                #Write-Verbose "Skipping string $s"
                $i++ # Skip the string terminator NUL
            }
            $i1 = $i
            $i++ # Skip the string list terminator NUL
            If ($n -eq $Type) {$Struct = $MSSMBiosData[$i0..$i1]}
        }
        If ($null -ne $Struct) {
            If ($Value -eq 'String') {
                $StringIndex = $Struct[$OffsetDecValue]
                If ($StringIndex -ne 0) {
                    $i          = $Struct[1]
                    $CountIndex = 0
                    While ($Struct[$i] -ne 0) {
                        $retry = $true
                        $CountIndex++
                        $s     = ''
                        While ($Struct[$i] -ne 0) {$s += [char]$Struct[$i++]}
                        Write-Verbose -Message "Skipping string $s"
                        $i++ # Skip the string terminator NUL
                        If ($CountIndex -eq $StringIndex) {$String = $s}
                    }
                    $String
                } Else {
                    Write-Verbose -Message 'Empty string' -Verbose
                }
            } Else {
                $Struct[$OffsetDecValue]    
            }
        } Else {
            Write-Error -Message "Unknown Type $type"   
        }
    }
}

#$Computername=$env:COMPUTERNAME
#$Win32_UserProfile=Get-WmiObject -Class Win32_UserProfile -Namespace root\cimv2 -ComputerName $Computername
Function GetUserProfile {
    [CmdletBinding()]
    Param([switch]$OnlyLoaded)
    Try {
        If ($null -eq $win32_userprofile) {Write-Error -Message 'Variable Win32_UserProfile is null' -ErrorAction Stop}
        $AllUserProfiles      = @()
        [string[]]$ExcludeSid = 'S-1-5-18','S-1-5-19','S-1-5-20'
        If ($credential) {
            $LocalAccount = Get-WmiObject -Class Win32_UserAccount -ComputerName $Computername -Filter "LocalAccount=$true" -Credential $credential
        } Else {
            $LocalAccount = Get-WmiObject -Class Win32_UserAccount -ComputerName $Computername -Filter "LocalAccount=$true"
        }
        If ($PSBoundParameters['OnlyLoaded'].IsPresent) {
            $Win32UserProfiles = $Win32_UserProfile | Where-Object {!($ExcludeSid -eq $_.sid) -and $_.loaded} 
            If ($null -eq $Win32UserProfiles) {Write-Error -Message 'User profile is not loaded'}
        } Else {
            $Win32UserProfiles = $Win32_UserProfile | Where-Object {!($ExcludeSid -eq $_.sid)} 
        }
        $Win32UserProfiles | Select-Object -Property * | ForEach-Object {
            $Sid              = $_.sid
            $LastUseTime      = $null
            $User             = $null
            $ProfileDirectory = $null
            $LocalPath        = $_.localpath
            $objSID           = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ($Sid) 
            Try {
                $objUser = $objSID.Translate([Security.Principal.NTAccount])
                $User    = $objUser.Value
                Write-Verbose -Message "$Computername Translate sid $sid succesfully"
            } Catch {
                Write-Verbose -Message "$Computername Unknown sid $sid"
                $User = ($LocalAccount | Where-Object {$_.sid -eq $Sid}).caption
                If ($null -eq $User) {$User = 'Unknown'}
            }
            $_ | Add-Member -MemberType NoteProperty -Name User -Value $User
            $_
        } | Select-Object -Property User,SID,LocalPath,Loaded | ForEach-Object {$AllUserProfiles+=$_}    
        $AllUserProfiles
    } Catch {
        Write-Error -Message $_
    }
}

Function ParseFunctionConfig {
    [cmdletbinding()]
    Param ([parameter(ValueFromPipeline=$true)]$Property,[Hashtable]$FunctionConfig,$Protocol)
    Begin {
        If ($Protocol -eq 'Wsman') {[Array]$PassParams = 'Class','Query','Script'} Else {[Array]$PassParams = 'Class','Query'}
        $PropertyParams = @{}
    }
    Process {
        If (!($FunctionConfig[$Property])) {Write-Error -Message "Property $Property not found in $('$FunctionConfig')" -ErrorAction Stop}
        $ObjectParam = ParseParam -ParamString $FunctionConfig[$Property] -Property $Property -ErrorAction Stop
        If ($ObjectParam | Get-Member -MemberType NoteProperty | ForEach-Object {if ($PassParams -eq $_.name){$True}}) {
            If (!($PropertyParams.ContainsKey($Property))) {$PropertyParams.Add($Property,$ObjectParam)}
        } Else {
            Write-Error -Message "$Property missing parameter.At least one parameter is required from $PassParams. Check FunctionConfig" -ErrorAction Stop
        }
    }
    End {
        $PropertyParams
    }
}

Function ParseParam {
    [cmdletbinding()]
    Param([parameter(Mandatory=$true)][string]$ParamString,[String]$Property)
    $PermitParams        = 'Class','ScriptBlock','UseRunspace','RunspaceImportVariable','Property','Query','Namespace','Script','FormatList'
    [array]$SwitchParam  = 'FormatList'
    $ArrayHashTableParam = @()
    $ArrayParamString    = (((($ParamString -replace '\s+',' ') -replace '\s+$','') -replace '^-',' -') -replace ' -',' --') -split '\s-'
    $HashTableParam      = @{}
    $ArrayParamString | ForEach-Object {
        If ($_ -match '^-(.+?)\s(.+)$') {
            $ParseParam = $Matches[1]
            $ParseValue = $Matches[2]
            If ($ParseValue -match ',') {
                $ArrayParseValue = $ParseValue -split ','
                $ParseValue      = $ArrayParseValue
            }
            $HashTableParam.Add($ParseParam,$ParseValue)
        } ElseIf ($_ -match '-(.+\S)') {
            If ($SwitchParam -eq $Matches[1]) {$HashTableParam.Add($Matches[1],$True)} Else {$HashTableParam.Add($Matches[1],$null)}
        }
    }
    $ObjectParam         = New-Object -TypeName PSObject -Property $HashTableParam
    $DifObj              = $ObjectParam | Get-Member -MemberType NoteProperty | ForEach-Object {$_.name}
    $CompareParam        = Compare-Object -ReferenceObject $PermitParams -DifferenceObject $DifObj
    If ($CompareParam | Where-Object {$_.sideindicator -eq '=>'}) {Write-Error -Message "$Property Parameter -$(($CompareParam | Where-Object {$_.SideIndicator -eq '=>'}).inputobject) not allowed. Check FunctionConfig" -ErrorAction Stop}
    $ObjectParam
}

Function PsJob {
    Function StartPsJob {
        Param($ComputerName,$ScriptBlock,$ArgumentList,$PSSessionOption,$Credential)
        Try {
            Write-Verbose -Message "$Computername InvokeCommand"   
            $InvokeParam = @{
                ComputerName    = $ComputerName
                ScriptBlock     = $InvokeScriptBlock
                ArgumentList    = $ArgumentList
                ThrottleLimit   = 254
            }
            If ($Credential) {$InvokeParam.Add('Credential',$Credential)}
            If ($PSBoundParameters['PSSessionOption']) {$InvokeParam.Add('SessionOption',$PSSessionOption)}
            $TmpPsJob           = Invoke-Command @InvokeParam -AsJob -ErrorAction Stop
            $temp               = '' | Select-Object -Property PSJobTypeName,PsJob,StartTime,Location
            $temp.PSJobTypeName = 'PsJob'
            $temp.PsJob         = $TmpPsJob
            $temp.StartTime     = Get-Date
            $Temp.Location      = $ComputerName
            $temp
        } Catch {
            CreateErrorObject -Err $_ -ComputerName $ComputerName -Protocol $protocol
        }
    }

    Function GetPsJob {
        Try {
            $AllFailedPsJobs = $MainJobs | Where-Object {$_.PsJob.State -eq 'Failed'}
            If ($AllFailedPsJobs) {
                $AllFailedPsJobs | ForEach-Object {
                    $Job      = $_
                    $PsJob    = $_.PsJob
                    $TmpErRec = $PsJob | Receive-Job -ErrorAction Stop
                    If ($null -eq $TmpErRec) {Write-Warning -Message "$($PsJob.location) Job state failed, no error returned"}
                    Remove-Job -Id $PsJob
                    $MainJobs.Remove($Job)
                }
            }
            $AllCompletedJobs=$MainJobs | Where-Object {$_.PsJob.State -eq 'Completed'} 
            If ($AllCompletedJobs) {
                $AllCompletedJobs | ForEach-Object {
                    $Job           = $_
                    $PsJob         = $_.PsJob
                    $Computername  = $Job.location
                    $ReceivePsJob  = @()
                    $ReceivePsJob += Receive-Job -Job $PsJob -ErrorAction Stop
                    If ($ReceivePsJob.Count -eq 0 -or $null -eq $ReceivePsJob[0]) {
                        Write-Warning -Message "$Computername InvokeCommand return empty value.."
                    } Else {
                        Write-Verbose -Message "$Computername Information Completed"
                        $ReceivePsJob
                    }
                    Remove-Job -Id $PsJob -Force
                    $MainJobs.Remove($Job)
                }
            }
            $AllTimeOutJob = $MainJobs | Where-Object {(New-TimeSpan -start $_.StartTime).TotalSeconds -gt $JobTimeOut}
            If ($null -ne $AllTimeOutJob) {
                $AllTimeOutJob | ForEach-Object {
                    Try {
                        $Job = $_
                        Write-Error -Message 'Timeout expired' -ErrorAction Stop
                    } Catch {
                        CreateErrorObject -Err $_ -ComputerName $Job.Location -Protocol $Protocol -ExceptionJob $Job
                    }
                }
            }
        } Catch {
            CreateErrorObject -Err $_ -ComputerName $Job.Location -Protocol $Protocol -ExceptionJob $Job
        }
    }

    Function StartWmiJob {
        Param ($Computername,$WmiParamArray)
        $WmiParamArray | Sort-Object -Property Name -Unique | ForEach-Object {
            If ($_.class) {
                $WmiParam = $_
                $Wmi      = @{}
                If ($null -ne $Credential) {If (!($LocalComputer -eq $ComputerName)) {If (!($WmiParam['Credential'])) {$WmiParam.Add('Credential',$Credential)}}}
                If ($jobs.count -ge $MaxWmiJob) {
                    Do {
                        $repeat=$true
                        GetWmiJob
                        If ($Jobs.Count -lt $MaxWmiJob) {$repeat = $false} Else {Start-Sleep -Milliseconds 20}
                    } While ($repeat)
                }
                If ($WmiParam.Query) {
                    $Wmi.add('Query',$WmiParam.Query)  
                    Write-Verbose -Message "$Computername Start Job Get-WmiObject -Query $($WmiParam.Query) -NameSpace $($WmiParam.Namespace)"
                } ElseIf ($WmiParam.class) {
                    If ($WmiParam.class -eq 'StdRegprov') {
                        $Wmi.Add('Query','SELECT * FROM meta_class WHERE __class="StdRegProv"')
                        Write-Verbose -Message "$Computername Start Job Get-WmiObject -Query SELECT * FROM meta_class WHERE __class=StdRegProv -NameSpace $($WmiParam.Namespace)" 
                    } Else {
                        $Wmi.add('Class',$WmiParam.Class) 
                        Write-Verbose -Message "$Computername Start Job Get-WmiObject -Class $($WmiParam.Class) -NameSpace $($WmiParam.Namespace)" 
                    }
                }
                $Wmi.add('Namespace',$WmiParam.Namespace)
                $TmpWmiJob = Get-WmiObject @Wmi -computername $ComputerName -ErrorAction Stop -AsJob   
                If ($?) {
                    $temp               = '' | Select-Object -Property PSJobTypeName,WmiJob,StartTime,Location,Class,WmiName
                    $temp.PSJobTypeName = 'WmiJob'
                    $temp.WmiJob        = $TmpWmiJob
                    $temp.StartTime     = Get-Date
                    $Temp.Location      = $ComputerName
                    $temp.WmiName       = $WmiParam.name    
                    [void]$Jobs.Add($temp) 
                }
            }
        }
    }

    Function GetWmiJob {
        $AllFailedWmiJobs = $Jobs | Where-Object  {$_.WmiJob.State -eq 'Failed'}
        If ($AllFailedWmiJobs) {
            $AllFailedWmiJobs | ForEach-Object {
                Try {
                    $Job      = $_.WmiJob
                    $TmpErRec = $Job | Receive-Job -ErrorAction Stop
                    If ($null -eq $TmpErRec) {If ($VerbosePreference -eq 'Continue') {Write-Warning -Message "$($Job.location) $($_.Class) JobState Failed Get-WmiObject return Null Value"}}
                    Remove-Job -Id $Job
                    $Jobs.Remove($_)
                } Catch {
                    Write-Error -Message $_ -ErrorAction Stop
                }
            }
        }
        $AllCompletedJobs = $Jobs | Where-Object {$_.WmiJob.State -eq 'Completed'} 
        if ($AllCompletedJobs) {
            $AllCompletedJobs | ForEach-Object {
                $wminame      = $_.wminame
                $Job          = $_.WmiJob
                $Computername = $_.location
                $GetWmi       = @()
                $GetWmi      += Receive-Job -Job $Job -ErrorAction Stop
                If ($GetWmi.Count -eq 0 -or $null -eq $GetWmi[0]) {
                    If ($VerbosePreference -eq 'Continue') {Write-Warning -Message "$Computername $($_.Class) Get-Wmiobject return empty value.."}
                } ElseIf ($GetWmi.count -eq 1) {
                    Write-Verbose -Message "$Computername Receive-Job $wminame Completed"
                    $HashtableWMi[$wminame]=$GetWmi[0]
                } Else {
                    Write-Verbose -Message "$Computername Receive-Job $wminame Completed"
                    $HashtableWMi[$wminame]=$GetWmi
                }
                Remove-Job -Id $Job -Force
                $Jobs.Remove($_)
            } # End Foreach
        }
    }

    [Scriptblock]$InvokeScriptBlock = {
        Param ($HashtableParam,$ComputerName)  
        Try {
            #Create Functions
            $HashtableParam['ImportFunctions'] | ForEach-Object {
                Write-Verbose -Message "Exporting function $($_.name)"
                [void]$(New-Item -path function: -name $_.name -Value $_.definition -ErrorAction Stop)
            }
            #Create Scriptblock variables
            $HashtableParam['ImportScriptFunction'] | ForEach-Object {
                If ($_.name) {
                    Write-Verbose -Message "Exporting function $($_.name)"
                    [void]$(New-Item -Path Function: -Name $_.name -Value $_.definition -ErrorAction Stop)
                }
            } 
            $HashtableParam['ImportVariables'] | ForEach-Object {
                Write-Verbose -Message "Exporting Variable $($_.name)"
                New-Variable -Name $_.name -Value $_.value
            }
        } Catch {
            Write-Error -Message "$_ Error create functions or scriptblock variable" -ErrorAction Stop
        }
        $VerbosePreference = $VerboseStatus
        $HashtableWMi      = @{}
        $WmiParamArray | ForEach-Object {
            $WmiParam = $_
            If ($WmiParam.Name) {
                If (!($HashtableWMi.ContainsKey($($WmiParam.Name)))) {
                    #$HashtableWMi[$($WmiParam.Name)]
                    $HashtableWMi.Add($WmiParam.Name,$null)
                }
            }
        }
        $jobs = New-Object -TypeName System.Collections.ArrayList
        StartWmiJob -ComputerName $Computername -WmiParamArray $WmiParamArray
        Do {GetWmiJob} While ($jobs.Count -ne 0)
        CreateResult
    }
}

Function Registry {
    Function RegGetValue {
        Param(
            [parameter(Mandatory=$true)][string]$Key,
            [parameter(Mandatory=$true)][string]$Value,
            [parameter(Mandatory=$true)][ValidateSet('GetStringValue','GetBinaryValue','GetDWORDValue','GetQWORDValue','GetMultiStringValue')][string]$GetValue
        )
        If ($null -eq $stdregprov) {Write-Error -Message 'Variable StdRegProv Null'}
        $ResultProp = @{
            'GetStringValue'      = 'Svalue'
            'GetBinaryValue'      = 'Uvalue'
            'GetDWORDValue'       = 'UValue'
            'GetQWORDValue'       = 'UValue'
            'GetMultiStringValue' = 'Svalue'
        }
        $ErrorCode  = @{
            '1'          = "Value doesn't exist"
            '2'          = "Key doesn't exist"
            '2147749893' = 'Wrong value type'
            '5'          = 'Access Denied'
            '6'          = 'Wrong Key String'
        }
        $hk         = @{
            'HKEY_CLASSES_ROOT'   = 2147483648
            'HKEY_CURRENT_USER'   = 2147483649
            'HKEY_LOCAL_MACHINE'  = 2147483650
            'HKEY_USERS'          = 2147483651
            'HKEY_CURRENT_CONFIG' = 2147483653
        }
        If ($Key -match '(.+?)\\(.+)') {
            If ($hk.Keys -eq $matches[1]) {
                $RootHive         = $hk[$matches[1]]
                $KeyString        = $matches[2]
                $StdRegProvResult = $StdRegProv | Invoke-WmiMethod -Name $GetValue -ArgumentList $RootHive,$KeyString,$Value
            } Else {
                Write-Error -Message "$($matches[1]) Does not belong to the set $($hk.Keys)" -ErrorAction Stop
            }
            If ($StdRegProvResult.returnvalue -ne 0) {
                If ($null -ne $ErrorCode["$($StdRegProvResult.returnvalue)"]) {
                    $er = $ErrorCode["$($StdRegProvResult.returnvalue)"]
                    Write-Error -Message "$Er! Key $Key Value $Value "
                } Else {
                    $er = $StdRegProvResult.returnvalue
                    Write-Error -Message "$GetValue return $Er! Key $Key Value $Value "
                }
            } Else {
                $StdRegProvResult.($ResultProp["$GetValue"])
            }
        } Else {
            Write-Error -Message "$Key not valid"
        }
    }

    Function RegEnumKey {
        Param ([parameter(Mandatory=$true)][string]$Key)
        $ErrorActionPreference = 'Stop'
        If ($null -eq $stdregprov) {Write-Error -Message 'Variable StdRegProv Null'}
        $ErrorCode = @{
            '1' = "Value doesn't exist"
            '2' = "Key doesn't exist"
            '5' = 'Access Denied'
            '6' = 'Wrong Key String'
        }
        $hk        = @{
            'HKEY_CLASSES_ROOT'   = 2147483648
            'HKEY_CURRENT_USER'   = 2147483649
            'HKEY_LOCAL_MACHINE'  = 2147483650
            'HKEY_USERS'          = 2147483651
            'HKEY_CURRENT_CONFIG' = 2147483653
        }
        If ($Key -match '(.+?)\\(.+)') {
            $StdRegProvResult = $StdRegProv.EnumKey($hk[$matches[1]],$matches[2])
            If ($StdRegProvResult.returnvalue -ne 0) {
                If ($null -ne $ErrorCode["$($StdRegProvResult.returnvalue)"]) {$er = $ErrorCode["$($StdRegProvResult.returnvalue)"]} Else {$er = $StdRegProvResult.returnvalue}
                Write-Error -Message "$Er key $Key"
            } Else {
                $StdRegProvResult.snames
            }
        } Else {
            Write-Error -Message "$Key not valid"
        }
    }

    Function RegEnumValues {
        Param ([parameter(Mandatory=$true)][string]$Key)
        $ErrorActionPreference = 'Stop'
        If ($null -eq $stdregprov) {Write-Error -Message 'Variable StdRegProv Null'}
        $ErrorCode = @{
            '1' = "Value doesn't exist"
            '2' = "Key doesn't exist"
            '5' = 'Access Denied'
            '6' = 'Wrong Key String'
        }
        $hk        = @{
            'HKEY_CLASSES_ROOT'   = 2147483648
            'HKEY_CURRENT_USER'   = 2147483649
            'HKEY_LOCAL_MACHINE'  = 2147483650
            'HKEY_USERS'          = 2147483651
            'HKEY_CURRENT_CONFIG' = 2147483653
        }
        If ($Key -match '(.+?)\\(.+)') {
            $StdRegProvResult = $StdRegProv.EnumValues($hk[$matches[1]],$matches[2])
            If ($StdRegProvResult.returnvalue -ne 0) {
                If ($null -ne $ErrorCode["$($StdRegProvResult.returnvalue)"]) {$er = $ErrorCode["$($StdRegProvResult.returnvalue)"]} Else {$er = $StdRegProvResult.returnvalue}
                Write-Error -Message "$Er key $Key"
            } Else {
                $StdRegProvResult.snames
            }
        } Else {
            Write-Error -Message "$Key not valid"
        }
    }
}

Function Runspacejob {
    Function StartWmi {
        [cmdletbinding()]
        Param ($Computername,$WmiParamArray)
        $WmiParamArray | Sort-Object -Property name -Unique | ForEach-Object {
            $WmiName = $_.name
            If ($_.class) {
                $WmiParam = $_
                $Wmi      = @{}
                If ($null -ne $Credential) {  
                    $Wmi.Add('Credential',$Credential)
                    <#if (!($WmiParam["Credential"]))
                    {
                    }#>          
                }
            }
            If ($WmiParam.Query) {
                $Wmi.add('Query',$WmiParam.Query)  
                Write-Verbose -Message "$Computername Start Get-WmiObject -Query $($WmiParam.Query) -NameSpace $($WmiParam.Namespace)"
            } ElseIf ($WmiParam.class) {
                If ($WmiParam.class -eq 'StdRegprov') {
                    $Wmi.Add('Query','SELECT * FROM meta_class WHERE __class="StdRegProv"')
                    Write-Verbose -Message "$Computername Start Get-WmiObject -Query SELECT * FROM meta_class WHERE __class=StdRegProv -NameSpace $($WmiParam.Namespace)" 
                } Else {
                    $Wmi.add('Class',$WmiParam.Class) 
                    Write-Verbose -Message "$Computername Start Get-WmiObject -Class $($WmiParam.Class) -NameSpace $($WmiParam.Namespace)" 
                }
            }
            $Wmi.add('Namespace',$WmiParam.Namespace)
            $TmpRes = Get-WmiObject @Wmi -ComputerName $computername -ErrorAction SilentlyContinue
            If ($?) {$HashtableWMi[$wmiName] = $tmpres} ElseIf ($Error[0].Exception.ErrorCode -ne 'NotSupported') {Write-Error -Message $Error[0]}
        }
    }

    Function StartRunspaceJob {
        Param($Computername,$RunspacePool)
        $PowerShell              = [powershell]::Create()
        [void]$PowerShell.AddScript($SbRunspace)
        $ParamList               = @{}
        $ParamList.Add('Computername',$(get-variable -Name Computername -ValueOnly))
        [void]$PowerShell.AddParameters($ParamList)
        $PowerShell.Runspacepool = $RunspacePool
        $State                   = $PowerShell.BeginInvoke()
        $temp                    = '' | Select-Object -Property PSJobTypeName,PowerShell,State,Location,StartTime,Property,Runspace
        $temp.PSJobTypeName      = 'RunspaceJob'
        $temp.powershell         = $PowerShell
        $temp.state              = $State
        $temp.location           = $Computername
        $temp.StartTime          = get-date
        $temp.runspace           = $Runspace
        $temp
    }

    Function GetRunspaceJob {
        Try {
            $AllCompletedRunspaceJob = $MainJobs | Where-Object {$_.State.IsCompleted}
            If ($AllCompletedRunspaceJob) {
                Write-Verbose -Message 'Available Completed Job'
                $AllCompletedRunspaceJob | ForEach-Object {
                    $Job    = $_
                    Write-Verbose -Message "$($_.location) End Invoke"
                    $TmpRes = $_.powershell.EndInvoke($_.State)
                    If ($null -ne $_.PowerShell.Streams.Error[0]) {
                        Write-Error -Message "$($_.PowerShell.Streams.Error[0])" -ErrorAction Stop
                        <#if ($TmpRes.count -eq 0)
                        {
                            Write-Error "Scriptblock HadErrors, use try{}catch{} in the ScriptBlock to find out the details" -ErrorAction Stop
                        } elseif ($TmpRes[0].GetType().name -eq "ErrorRecord") {
                            Write-Error $TmpRes[0] -ErrorAction Stop
                        } else {
                            Write-Error "Unknown Error $($TmpRes[0])" -ErrorAction Stop
                        }#>
                    } ElseIf ($null -ne $TmpRes[0]) {
                        If ($TmpRes[0].GetType().name -eq 'ErrorRecord') {Write-Error -Message $TmpRes[0] -ErrorAction Stop}
                        Write-Verbose -Message "$($Job.location) RunspaceJob Completed"
                        $TmpRes
                        Write-Verbose -Message "$($_.location) Dispose completed job"
                        $_.powershell.dispose()
                        $_.State      = $null
                        $_.powershell = $null
                        $MainJobs.Remove($Job)
                    } Else {
                        Write-Error -Message 'Scriptblock return empty value' -ErrorAction Stop
                    }
                }
            }
            $AllTimeOutJob = $MainJobs | Where-Object {(New-TimeSpan -start $_.StartTime).TotalSeconds -gt $JobTimeOut}
            If ($AllTimeOutJob) {
                $AllTimeOutJob | ForEach-Object {
                    Try {
                        $Job = $_
                        Write-Error -Message 'Timeout expired' -ErrorAction Stop
                    } Catch {
                        CreateErrorObject -Err $_ -ComputerName $Job.Location -Protocol $Protocol -ExceptionJob $Job
                    }
                }
            }
        } Catch {
            CreateErrorObject -Err $_ -ComputerName $Job.Location -Protocol $Protocol -ExceptionJob $Job
        }
    }

    [scriptblock]$SbRunspace = {
        Param ($Computername)
        Try {
            $HashtableWMi = @{}
            $WmiParamArray | ForEach-Object {
                $WmiParam = $_
                If ($WmiParam.Name) {If (!($HashtableWMi.ContainsKey($($WmiParam.Name)))) {$HashtableWMi.Add($WmiParam.Name,$null)}}
            }
            StartWmi -WmiParamArray $WmiParamArray -Computername $Computername -ErrorAction Stop
            CreateResult
        } Catch {
            Write-Error -Message $_
        }
    }
}

Function wmi {
    Function GetNamespace {
        Param(
            [parameter(Mandatory=$true)][string]$Class,
            [parameter(Mandatory=$true)]$ManualNamespace
        )
        If ($ManualNamespace[$Class]) {
            $ManualNamespaceParams         = ParseParam -ParamString $($ManualNamespace[$Class])
            $ManualNamespaceParamNamespace = $ManualNamespaceParams | Where-Object {$_.namespace}
            If ($ManualNamespaceParams.Namespace) {$Namespace = $ManualNamespaceParams.Namespace}
        } Else {
            Try {
                If ((Get-WmiObject -query "SELECT * FROM meta_class WHERE __class = '$Class'").__NAMESPACE -eq 'ROOT\cimv2') {
                    $Namespace = 'ROOT\cimv2'
                } Else {
                    Write-Error -Message 'Cannot retrieve Namespace use $ManualNamespace hashtable' -ErrorAction Stop
                }
            } Catch {
                Write-Error -Message "Cannot retrieve Namespace for class $Class check Functionconfig or use hashtable $('$ManualNamespace') " -ErrorAction Stop
            }
        }
        $Namespace
    }

    Function CreateWmiObject {
        Param(
            [parameter(Mandatory=$true)]$PropertyParams,
            [parameter(Mandatory=$true)]$ManualNamespace
        )
        $ObjectWmiArray = @()
        $ClassNamespace = @{}
        $PropertyParams.Keys | ForEach-Object {
            $Property = $_
            $PropertyParams[$_]
        } | ForEach-Object {
            $ArrayClassObject = $null
            $ArrayObject      = @()
            $Object           = New-Object -TypeName psobject
            $ArrayObject     += $Object
            If ($_.Property) {
                $Object | Add-Member -MemberType NoteProperty -Name ActionProperty -Value 'Property'
                $Object | Add-Member -MemberType NoteProperty -Name Action -Value $_.Property 
            } ElseIf ($_.Function) {
                $Object | Add-Member -MemberType NoteProperty -Name ActionProperty -Value 'Function'
                $Object | Add-Member -MemberType NoteProperty -Name Action -Value $_.Function
            }
            If ($_.class) {
                If ($_.class.gettype() -eq [string]) {
                    $Object | Add-Member -MemberType NoteProperty -Name Class -Value $_.class 
                    $Object | Add-Member -MemberType NoteProperty -Name Name -Value $_.class
                } ElseIf ($_.class.gettype() -eq [string[]]) {
                    $ArrayClassObject = @()
                    $Object | Add-Member -MemberType NoteProperty -Name Class -Value $_.class[0] 
                    $Object | Add-Member -MemberType NoteProperty -Name Name -Value $_.class[0]
                    $_.class | ForEach-Object {
                        $ClassObject = New-Object -TypeName psobject
                        $ClassObject | Add-Member -MemberType NoteProperty -Name Class -Value $_
                        $ClassObject | Add-Member -MemberType NoteProperty -Name Name -Value $_
                        $ArrayObject += $ClassObject
                    }
                } Else {
                    Write-Error -Message "$($_.class) Unknown type"
                }
            } ElseIf ($_.query) {
                If ($_.query -match '.+from\s(.+?)\s') {
                    $Name = 'Query_'+$Matches[1]+'_'+$Property
                    $Object | Add-Member -MemberType NoteProperty -Name Class -Value $Matches[1]
                    $Object | Add-Member -MemberType NoteProperty -Name Query -Value $_.query
                    $Object | Add-Member -MemberType NoteProperty -Name Name -Value $Name
                } Else {
                    Write-Error -Message "Query $($_.query) not support"
                }
            }
            $Object | Add-Member -MemberType NoteProperty -Name Property -Value $Property   
            $ArrayObject | ForEach-Object {
                $Class = $_.class
                If ($Class) {
                    If (!($ClassNamespace[$Class])) {
                        $Namespace = GetNamespace -Class $Class -ManualNamespace $ManualNamespace
                        [void]$ClassNamespace.Add($Class,$Namespace)  
                    }
                    $_ | Add-Member -MemberType NoteProperty -Name Namespace -Value $ClassNamespace[$Class] 
                }
            }
            $ObjectWmiArray += $ArrayObject
        }
        $ObjectWmiArray 
    }
}

Function ADSiteName {
    Try {
        RegGetValue -Key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Value DynamicSiteName -GetValue GetStringValue -ErrorAction Stop
    } Catch {
        Write-Error -Message $_
    }
}

Function CpuName {$Win32_processor | ForEach-Object {$_.name -replace '\s+',' '}}

Function CpuSocket {
    # 'UpgradeMethod' value from:
    # https://schemas.dmtf.org/wbem/cim-html/2.49.0+/CIM_Processor.html
    $CPU_UpgradeMethod = DATA {ConvertFrom-StringData -StringData @'
15 = Socket 478
16 = Socket 754
17 = Socket 940
18 = Socket 939
19 = Socket mPGA604
20 = Socket LGA771
21 = Socket LGA775
22 = Socket S1
23 = Socket AM2
24 = Socket F (1207)
25 = Socket LGA1366
26 = Socket G34
27 = Socket AM3
28 = Socket C32
29 = Socket LGA1156
30 = Socket LGA1567
31 = Socket PGA988A
32 = Socket BGA1288
33 = rPGA988B
34 = BGA1023
35 = BGA1224
36 = LGA1155
37 = LGA1356
38 = LGA2011
39 = Socket FS1
40 = Socket FS2
41 = Socket FM1
42 = Socket FM2
43 = Socket LGA2011-3
44 = Socket LGA1356-3
45 = Socket LGA1150
46 = Socket BGA1168
47 = Socket BGA1234
48 = Socket BGA1364
49 = Socket AM4
50 = Socket LGA1151
51 = Socket BGA1356
52 = Socket BGA1440
53 = Socket BGA1515
54 = Socket LGA3647-1
55 = Socket SP3
56 = Socket SP3r2
'@}
    $CpuNameSocket     = @{
        'Intel(R) Core(TM) i3-2100 CPU @ 3.10GHz'  = 'FCLGA1155'
        'Pentium(R) Dual-Core CPU E5400 @ 2.70GHz' = 'LGA775'
        'Intel(R) Pentium(R) CPU G4500 @ 3.50GHz'  = 'FCLGA1151'
        'Intel(R) Celeron(R) CPU E3300 @ 2.50GHz'  = 'LGA775'
        'Intel(R) Celeron(R) CPU G540 @ 2.50GHz'   = 'FCLGA1155'
        'Intel(R) Core(TM) i3-2105 CPU @ 3.10GHz'  = 'FCLGA1155'
        'Intel(R) Core(TM) i5-2310 CPU @ 2.90GHz'  = 'LGA1155'
        'Intel(R) Pentium(R) CPU G4600 @ 3.60GHz'  = 'FCLGA1151'
        'Intel(R) Pentium(R) CPU G620 @ 2.60GHz'   = 'FCLGA1155'
        'Pentium(R) Dual-Core CPU E6600 @ 3.06GHz' = 'LGA775'
        'Genuine Intel(R) CPU 2140 @ 1.60GHz'      = 'LGA775,PLGA775'
        'Intel(R) Celeron(R) CPU E3400 @ 2.60GHz'  = 'LGA775'
        'Intel(R) Pentium(R) CPU G645 @ 2.90GHz'   = 'FCLGA1155'
        'Intel(R) Celeron(R) CPU G550 @ 2.60GHz'   = 'FCLGA1155'
        'Pentium(R) Dual-Core CPU E5300 @ 2.60GHz' = 'LGA775'
        'Pentium(R) Dual-Core CPU T4400 @ 2.20GHz' = 'PGA478'
        'Intel(R) Xeon(R) CPU E5420 @ 2.50GHz'     = 'LGA771'
    }
    $Win32_Processor | ForEach-Object {
        $CpuName = $($_.name -replace '\s+',' ')
        If ($null -eq $CpuNameSocket[$CpuName]) {
            If (($_.SocketDesignation -replace '\s+','') -match '\w+\d{2,}' -and $_.SocketDesignation -ne $_.name ) {
                $_.SocketDesignation
            } Else {
                If ($null -eq $CPU_UpgradeMethod["$($_.UpgradeMethod)"]) {'Unknown'} Else {$CPU_UpgradeMethod["$($_.UpgradeMethod)"]}
            }
        } Else {
            $CpuNameSocket[$CpuName] 
        }
    }
}

Function VideoModel {
    $Win32_VideoController | ForEach-Object {
        If ($_.name -notmatch 'Radmin.+' -and $_.name -notmatch 'DameWare.+') {$_.name}
    }
}

Function VideoProcessor {
    $Win32_VideoController | ForEach-Object {
        If ($_.name -notmatch 'Radmin.+' -and $_.name -notmatch 'DameWare.+') {$_.VideoProcessor} 
    }
}

Function VideoRamMb {
    $Win32_VideoController | ForEach-Object {
        If ($_.name -notmatch 'Radmin.+' -and $_.name -notmatch 'DameWare.+') {$_.AdapterRAM} 
    }
}

Function ECCType {
    $MemoryEccArray = @{
        '0' = 'Reserved';
        '1' = 'Other';
        '2' = 'Unknown';
        '3' = 'None';
        '4' = 'Parity';
        '5' = 'Single-bit ECC';
        '6' = 'Multi-bit ECC';
        '7' = 'CRC'
    }
    $Win32_PhysicalMemoryArray | ForEach-Object {$MemoryEccArray[[string]$_.MemoryErrorCorrection]}
}

Function MemoryAvailable {$Win32_OperatingSystem.TotalVisibleMemorySize * 1kb}

Function MemoryFree {$Win32_OperatingSystem.FreePhysicalMemory*1kb}

Function MemoryMaxIns {
    $MemMaxinsCount = 0
    $Win32_PhysicalMemoryArray | ForEach-Object {$MemMaxinsCount += $_.MaxCapacity*1kb}
    $MemMaxinsCount
}

Function MemoryModInsCount {
    $count = 0
    $Win32_PhysicalMemory | ForEach-Object {$count++}
    $count
}

Function MemoryModules {
    $MemTypeWmi      = @{
        '0'  = 'Unknown'
        '1'  = 'Other'
        '2'  = 'DRAM'
        '4'  = 'Cache DRAM'
        '5'  = 'EDO'
        '6'  = 'EDRAM'
        '7'  = 'VRAM'
        '8'  = 'SRAM'
        '9'  = 'RAM'
        '10' = 'ROM'
        '11' = 'Flash'
        '12' = 'EEPROM'
        '13' = 'FEPROM'
        '14' = 'EPROM'
        '15' = 'CDRAM'
        '16' = '3DRAM'
        '17' = 'SDRAM'
        '18' = 'SGRAM'
        '19' = 'RDRAM'
        '20' = 'DDR'
        '21' = 'DDR-2'
        '22' = 'DDR2 FB-DIMM'
        '24' = 'DDR3'
        '25' = 'FBD2'
    }
    $MemTypeSmbios   = @{
        '1'  = 'Other'
        '2'  = 'Unknown'
        '3'  = 'DRAM'
        '4'  = 'EDRAM'
        '5'  = 'VRAM'
        '6'  = 'SRAM'
        '7'  = 'RAM'
        '8'  = 'ROM'
        '9'  = 'FLASH'
        '10' = 'EEPROM'
        '11' = 'FEPROM'
        '12' = 'EPROM'
        '13' = 'CDRAM'
        '14' = '3DRAM'
        '15' = 'SDRAM'
        '16' = 'SGRAM'
        '17' = 'RDRAM'
        '18' = 'DDR'
        '19' = 'DDR2'
        '20' = 'DDR2FB-DIMM'
        '24' = 'DDR3'
        '25' = 'FBD2'
        '26' = 'DDR4'
        '27' = 'LPDDR'
        '28' = 'LPDDR2'
        '29' = 'LPDDR3'
        '30' = 'LPDDR4'
    }
    $MemTypeCpuIntel = @{
        '94'  = 'DDR4'
        '158' = 'DDR4'
        '58'  = 'DDR3'
        '42'  = 'DDR3'
        '15'  = 'DDR2'
    }
    #$MemModules=$Win32_PhysicalMemory | Select-Object Capacity,MemoryType,Speed,Manufacturer,PartNumber
    $MemModules      = @()
    $TypeWmi         = @()
    $Win32_PhysicalMemory | ForEach-Object {$TypeWmi += $_.memorytype}
    $TypeWmi         = $TypeWmi[0]
    $Smbios          = $false
    $MemoryType      = $null
    If ($TypeWmi -eq 0 -or $TypeWmi -eq 1) {
        Write-Verbose -Message "$Computername GetSmbiosStruct"
        $DecMemtype = GetSmbiosStruct -Type 17 -Offset 12h -Value Other -ErrorAction SilentlyContinue  
        Write-Verbose -Message "DecMemtype $DecMemtype"
        If ($DecMemtype -ne 1 -and $DecMemtype -ne 2 -and $null -ne $DecMemtype) {$Smbios = $true}
        If (!$Smbios) {
            If ($null -eq $win32_processor) {
                If ($credential) {
                    $win32_processor = Get-WmiObject -Class win32_processor -Namespace root\cimv2 -ComputerName $computername -Credential $credential -ErrorAction SilentlyContinue
                } Else {
                    Write-Verbose -Message "$Computername Get-WmiObject -Class win32_processor"
                    $win32_processor = Get-WmiObject -Class win32_processor -Namespace root\cimv2 -ComputerName $computername -ErrorAction SilentlyContinue
                }
            }
            If ($null -ne $win32_processor) {
                If ($Win32_Processor.Manufacturer -eq 'GenuineIntel') {
                    Write-Verbose -Message 'Intel Processor'
                    $CpuDescript = $win32_processor.Description
                    $Regex       = [regex]'Family \d+ Model (\d+) Stepping \d+'
                    $result      = $regex.Match($CpuDescript)
                    If ($result.Success) {
                        $Model      = $result.Groups[1].Value
                        Write-Verbose -Message "Model $model"
                        $MemoryType = $MemTypeCpuIntel["$Model"]
                    }
                }
            }
        }
    }
    $Win32_PhysicalMemory | ForEach-Object {
        If ($Smbios) {$MemoryType = $MemTypeSmbios[[string]$DecMemtype]} ElseIf ($null -eq $MemoryType) {$MemoryType = $MemTypeWmi[[string]$_.memorytype]}
        $Property = @{
            Capacity     = $_.capacity
            MemoryType   = $MemoryType
            Speed        = $_.speed
            Manufacturer = $_.Manufacturer
            PartNumber   = $_.PartNumber
        }
        $MemModule   = New-Object -TypeName PSObject -Property $Property
        $MemModule.psobject.typenames.insert(0,'ModuleSystemInfo.SystemInfo.Memory.Modules')
        $MemModules += $MemModule
    }
    $MemModules
}

Function MemorySlots {$Win32_PhysicalMemoryArray | ForEach-Object {$_.memorydevices}}

Function MemoryTotal {
    $Win32_PhysicalMemory | Select-Object -Property Capacity | ForEach-Object {$MemTotalCount += $_.capacity}
    $MemTotalCount
}

Function MonName {
    If ($null -ne $wmiMonitorID.UserFriendlyName) {
	    $dispname = $null
	    $dispname = ([Text.Encoding]::ASCII.GetString($wmiMonitorID.UserFriendlyName)).Replace("$([char]0x0000)",'')		
        $dispname
    } Else {
        'NotSupported'
    }
}

Function MonPCode {
    If ($null -ne $wmiMonitorID.ProductCodeID) {		
	    $dispproduct = $null
        $dispproduct = ([Text.Encoding]::ASCII.GetString($wmiMonitorID.ProductCodeID)).Replace("$([char]0x0000)",'')			
	    $dispproduct	
    }
}

Function MonSn {
    If ($null -ne $wmiMonitorID.SerialNumberID) {		
        $dispserial = $null
        $dispserial = ([Text.Encoding]::ASCII.GetString($wmiMonitorID.SerialNumberID)).Replace("$([char]0x0000)",'')			
        $dispserial
    }
}

Function MonitorManuf {
    $ManufacturerHashTable = @{ 
        'AAC' =	'AcerView'
        'ACR' = 'Acer'
        'AOC' = 'AOC'
        'AIC' = 'AG Neovo'
        'APP' = 'Apple Computer'
        'AST' = 'AST Research'
        'AUO' = 'Asus'
        'BNQ' = 'BenQ'
        'CMO' = 'Acer'
        'CPL' = 'Compal'
        'CPQ' = 'Compaq'
        'CPT' = 'Chunghwa Pciture Tubes, Ltd.'
        'CTX' = 'CTX'
        'DEC' = 'DEC'
        'DEL' = 'Dell'
        'DPC' = 'Delta'
        'DWE' = 'Daewoo'
        'EIZ' = 'EIZO'
        'ELS' = 'ELSA'
        'ENC' = 'EIZO'
        'EPI' = 'Envision'
        'FCM' = 'Funai'
        'FUJ' = 'Fujitsu'
        'FUS' = 'Fujitsu-Siemens'
        'GSM' = 'LG Electronics'
        'GWY' = 'Gateway 2000'
        'HEI' = 'Hyundai'
        'HIT' = 'Hyundai'
        'HSL' = 'Hansol'
        'HTC' = 'Hitachi/Nissei'
        'HWP' = 'HP'
        'IBM' = 'IBM'
        'ICL' = 'Fujitsu ICL'
        'IVM' = 'Iiyama'
        'KDS' = 'Korea Data Systems'
        'LEN' = 'Lenovo'
        'LGD' = 'Asus'
        'LPL' = 'Fujitsu'
        'MAX' = 'Belinea'
        'MEI' = 'Panasonic'
        'MEL' = 'Mitsubishi Electronics'
        'MS_' = 'Panasonic'
        'NAN' = 'Nanao'
        'NEC' = 'NEC'
        'NOK' = 'Nokia Data'
        'NVD' = 'Fujitsu'
        'OPT' = 'Optoma'
        'PHL' = 'Philips'
        'REL' = 'Relisys'
        'SAN' = 'Samsung'
        'SAM' = 'Samsung'
        'SBI' = 'Smarttech'
        'SGI' = 'SGI'
        'SNY' = 'Sony'
        'SRC' = 'Shamrock'
        'SUN' = 'Sun Microsystems'
        'SEC' = 'Hewlett-Packard'
        'TAT' = 'Tatung'
        'TOS' = 'Toshiba'
        'TSB' = 'Toshiba'
        'VSC' = 'ViewSonic'
        'ZCM' = 'Zenith'
        'UNK' = 'Unknown'
        '_YV' = 'Fujitsu'
        'ENV'='Envision'      
        'HSD'='Hanns.G'
    }
    If ($null -ne $wmiMonitorID.ManufacturerName) {
        $manuf = $null
        $manuf = ([Text.Encoding]::ASCII.GetString($wmiMonitorID.ManufacturerName)).Replace("$([char]0x0000)",'')			 			
        if ($ManufacturerHashTable["$manuf"]) {
            $ManufacturerHashTable["$manuf"]
        } else {
            $manuf
        }
    }
}

Function NetPhysAdapCount {
    $Count = 0
    $Win32_NetworkAdapter | ForEach-Object {If ($_.physicaladapter){$count++}}
    $count
}

Function NetworkAdapters {
    Function GetStatusFromValue {
        Param($SV)
        Switch($SV) {
            0       {'Disconnected'}
            1       {'Connecting'}
            2       {'Connected'}
            3       {'Disconnecting'}
            4       {'Hardware not present'}
            5       {'Hardware disabled'}
            6       {'Hardware malfunction'}
            7       {'Media disconnected'}
            8       {'Authenticating'}
            9       {'Authentication succeeded'}
            10      {'Authentication failed'}
            11      {'Invalid Address'}
            12      {'Credentials Required'}
            Default {'Not connected'}
        }
    }

    Function GetSpeedDuplexFromValue {
        Param($SV)
        Switch($SV) {      
            0       {'AutoNegotiation'}
            1       {'10Mbps HalfDuplex'}
            2       {'10Mbps FullDuplex'}
            3       {'100Mbps HalfDuplex'}
            4       {'100Mbps FullDuplex'}
            6       {'1Gbps FullDuplex'}
            Default {$SV}
        }
    }

    Function GetAdapterTypeFromValue {
        Param($SV)
        Switch($SV) {      
            0       {'Ethernet'}
            16      {'Wireless'}
            Default {$SV}
        }
    }

    $AdaptersHashTable = @{}
    $Win32_NetworkAdapter | ForEach-Object {
        $Adapter     = $_
        $ZerroString = $null
        $SpeedDuplex = $null
        $AdapterType = $null
        $LinkSpeed   = ($MSNdis_LinkSpeed | Where-Object {$_.InstanceName -eq $Adapter.Name}).NdisLinkSpeed/10000
        If ($Adapter.PhysicalAdapter) {
            [string]$DeviceId = $_.DeviceId
            If ($DeviceId.Length -lt 4) {1..$(4-$DeviceId.Length) | ForEach-Object {[string]$ZerroString += '0'}}
            $Key              = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\' + $ZerroString + $DeviceId
            $SpeedDuplexValue = RegGetValue -Key $Key -Value *SpeedDuplex -GetValue GetStringValue -ErrorAction SilentlyContinue     
            If ($null -ne $SpeedDuplexValue) {$SpeedDuplex = GetSpeedDuplexFromValue -SV $([int]$SpeedDuplexValue)}
            $AdapterTypeValue = RegGetValue -Key $Key -Value *MediaType -GetValue GetDWORDValue -ErrorAction SilentlyContinue
            If ($null -ne $AdapterTypeValue) {$AdapterType = GetAdapterTypeFromValue -SV $([int]$AdapterTypeValue)}
	        $DriverVersion    = RegGetValue -key $Key -Value DriverVersion -GetValue GetStringValue -ErrorAction SilentlyContinue
        }
        $Status    = GetStatusFromValue -Sv $Adapter.NetConnectionStatus
        $TmpObject = New-Object -TypeName PSObject
        $TmpObject | Add-Member -MemberType NoteProperty -Name Index           -Value $Adapter.deviceid
        $TmpObject | Add-Member -MemberType NoteProperty -Name Name            -Value $Adapter.Name
        $TmpObject | Add-Member -MemberType NoteProperty -Name NetConnectionID -Value $Adapter.NetConnectionID
        $TmpObject | Add-Member -MemberType NoteProperty -Name MediaType       -Value $AdapterType
        $TmpObject | Add-Member -MemberType NoteProperty -Name Status          -Value $Status
        $TmpObject | Add-Member -MemberType NoteProperty -Name MACAddress      -Value $Adapter.MACAddress
    	$TmpObject | Add-Member -MemberType NoteProperty -Name DriverVersion   -Value $([version]$DriverVersion)
        $TmpObject | Add-Member -MemberType NoteProperty -Name SpeedDuplex     -Value $SpeedDuplex
        $TmpObject | Add-Member -MemberType NoteProperty -Name SpeedMbps       -Value $LinkSpeed
        $AdaptersHashTable.Add("$($Adapter.deviceid)",$TmpObject) 
    }
    $Win32_NetworkAdapterConfiguration | ForEach-Object {
        If ($($_.MACAddress -or $_.IPAddress -or $_.DHCPServer -or $_.DefaultIPGateway -or $_.DNSServerSearchOrder)) {
            $AdapterObject = $AdaptersHashTable["$($_.index)"]
            $AdapterObject | Add-Member -MemberType NoteProperty -Name DHCPEnabled          -Value $_.DHCPEnabled
            $AdapterObject | Add-Member -MemberType NoteProperty -Name DHCPServer           -Value $_.DHCPServer
            $AdapterObject | Add-Member -MemberType NoteProperty -Name IPAddress            -Value $_.IPAddress
            $AdapterObject | Add-Member -MemberType NoteProperty -Name DefaultIPGateway     -Value $_.DefaultIPGateway
            $AdapterObject | Add-Member -MemberType NoteProperty -Name DNSServerSearchOrder -Value $_.DNSServerSearchOrder
            If ($AdapterObject.name -ne 'RAS Async Adapter') {$AdapterObject}
        }
    }
}

Function NetworkAdaptersPowMan {
    $Win32_NetworkAdapter | ForEach-Object {
        $Adapter           = $_
        $WakeOnMagicPacket = $null
        $WakeOnPattern     = $null
        If ($Adapter.PhysicalAdapter -and $Adapter.AdapterTypeID -eq '0') {
            [string]$DeviceId = $_.DeviceId
            $ZerroString      = $null
            If ($DeviceId.Length -lt 4) {1..$(4-$DeviceId.Length) | ForEach-Object {[string]$ZerroString += '0'}}
            $Key                    = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\' + $ZerroString + $DeviceId
            $WakeOnMagicPacketValue = RegGetValue -Key $Key -Value *WakeOnMagicPacket -GetValue GetStringValue -ErrorAction SilentlyContinue
            $WakeOnPatternValue     = RegGetValue -Key $Key -Value *WakeOnPattern -GetValue GetStringValue -ErrorAction SilentlyContinue
            If ($null -ne $WakeOnMagicPacketValue -or $null -ne $WakeOnMagicPacketValue) {
                If ($null -ne $WakeOnMagicPacketValue) {
                    If([int]$WakeOnMagicPacketValue -eq 1) {$WakeOnMagicPacket = $true} ElseIf ([int]$WakeOnMagicPacketValue -eq 0) {$WakeOnMagicPacket = $false}
                }
                If ($null -ne $WakeOnMagicPacketValue) {
                    If ([int]$WakeOnPatternValue -eq 1) {$WakeOnPattern = $true} ElseIf ([int]$WakeOnPatternValue -eq 0) {$WakeOnPattern = $false}
                }
                Write-Verbose -Message 'CreateObject'
                $TmpObject = New-Object -TypeName psobject
                $TmpObject | Add-Member -MemberType NoteProperty -Name Index             -Value $Adapter.deviceid    
                $TmpObject | Add-Member -MemberType NoteProperty -Name Name              -Value $Adapter.name
                $TmpObject | Add-Member -MemberType NoteProperty -Name MACAddress        -Value $Adapter.MACAddress
                $TmpObject | Add-Member -MemberType NoteProperty -Name WakeOnMagicPacket -Value $WakeOnMagicPacket 
                $TmpObject | Add-Member -MemberType NoteProperty -Name WakeOnPattern     -Value $WakeOnPattern 
                $MSPowerEnable         = ($MSPower_DeviceEnable | Where-Object {$_.instancename -match [regex]::escape($Adapter.PNPDeviceID)}).enable
                $MSPowerWakeEnable     = ($MSPower_DeviceWakeEnable | Where-Object {$_.instancename -match [regex]::escape($Adapter.PNPDeviceID)}).enable
                $WakeOnMagicPacketOnly = ($MSNdis_DeviceWakeOnMagicPacketOnly | Where-Object {$_.instancename -match [regex]::escape($Adapter.PNPDeviceID)}).EnableWakeOnMagicPacketOnly
                If ($MSPowerEnable -eq $false) {
                    $MSPowerWakeEnable     = $false
                    $WakeOnMagicPacketOnly = $false
                }
                If ($MSPowerWakeEnable -eq $false) {
                    $WakeOnMagicPacketOnly = $false
                }
                $TmpObject | Add-Member -MemberType NoteProperty -Name MSPowerEnable         -Value $MSPowerEnable
                $TmpObject | Add-Member -MemberType NoteProperty -Name MSPowerWakeEnable     -Value $MSPowerWakeEnable
                $TmpObject | Add-Member -MemberType NoteProperty -Name WakeOnMagicPacketOnly -Value $WakeOnMagicPacketOnly
                $TmpObject 
            }
        }
    }
}

Function AntivirusStatus {
    Try { 
        If ($win32_operatingsystem.producttype -eq 1) {
            [version]$OSVersion = $win32_operatingsystem.version 
            If ($Credential) {
                If ($OSVersion -ge [version]'6.0.0.0') { 
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $Computername -ErrorAction Stop -Credential $Credential 
                } Else {
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computername -ErrorAction Stop -Credential $Credential 
                }
            } Else {
                If ($OSVersion -ge [version]'6.0.0.0') { 
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $Computername -ErrorAction Stop 
                } Else {   
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computername -ErrorAction Stop 
                }
            }
            $productState = $AntiVirusProduct.productState 
            # convert to hex, add an additional '0' left if necesarry 
            $hex = [Convert]::ToString($productState, 16).PadLeft(6,'0') 
            # Substring(int startIndex, int length)   
            $WSC_SECURITY_PRODUCT_STATE    = $hex.Substring(2,2) 
            $WSC_SECURITY_SIGNATURE_STATUS = $hex.Substring(4,2) 
            $RealTimeProtectionStatus      = Switch ($WSC_SECURITY_PRODUCT_STATE) { 
                '00'    {'OFF'}  
                '01'    {'EXPIRED'} 
                '10'    {'ON'} 
                '11'    {'SNOOZED'} 
                default {'UNKNOWN'} 
            }
            $DefinitionStatus              = Switch ($WSC_SECURITY_SIGNATURE_STATUS) { 
                '00'    {'Updated'} 
                '10'    {'NotUpdated'} 
                default {'UNKNOWN'} 
            }
            # Output PSCustom Object 
            $Object = New-Object -TypeName PSObject -ErrorAction Stop -Property @{  
                AvName             = $AntiVirusProduct.displayName
                Definition         = $DefinitionStatus
                RealTimeProtection = $RealTimeProtectionStatus
            } | Select-Object -Property AvName,Definition,RealTimeProtection  
            $Object 
        } else {
            Write-Error -Message 'NotSupported' -ErrorAction Stop
        }
    } Catch { 
        Write-Error -Message $_ 
    }
}

Function MsOfficeInfo {
    #$stdregProv = Get-Wmiobject -list "StdRegProv" -namespace root\default -computername localhost
    Try {
        $RootUninstallKeyX64  = 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        $RootUninstallKey     = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        $RootOfficeKeylKeyX64 = 'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Office'
        $RootOfficeKeylKey    = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office'
        $GetArch = RegGetValue -key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Value 'PROCESSOR_ARCHITECTURE' -GetValue GetStringValue -ErrorAction Stop
        $AllInstalledOffice   = @()
        Function GetOfficeInfo {
            Param (
                [string]$RootOfficeKeylKey,
                [string]$DisplayArch,
                [string]$RootUninstallKey
            )
            RegEnumKey -key $RootOfficeKeylKey -ErrorAction SilentlyContinue | Where-Object {$_ -match '\d{2}\.\d'} | ForEach-Object {
                $ChildConfigPath  = $_+'\Common\Config'
                $OfficeConfigPath = Join-Path -Path $RootOfficeKeylKey -ChildPath $ChildConfigPath  
                Try {
                    If ($null -ne $OfficeConfigPath) {
                        RegEnumKey -key $OfficeConfigPath -ErrorAction SilentlyContinue | ForEach-Object {
                            $DisplayName             = $null
                            $DisplayVersion          = $null
                            $ChildUninstallPath      = $_
                            $OfficeUninstallPath     = Join-Path -path $RootUninstallKey -ChildPath $ChildUninstallPath
                            $DisplayName             = RegGetValue -Key $OfficeUninstallPath -Value DisplayName    -GetValue GetStringValue -ErrorAction SilentlyContinue
                            [version]$DisplayVersion = RegGetValue -Key $OfficeUninstallPath -Value DisplayVersion -GetValue GetStringValue -ErrorAction SilentlyContinue
                            if ($DisplayName -and $DisplayVersion) {
                                $TmpObject = New-Object -TypeName PSObject
                                $TmpObject | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
                                $TmpObject | Add-Member -MemberType NoteProperty -Name Bitness     -Value $DisplayArch
                                $TmpObject | Add-Member -MemberType NoteProperty -Name Version     -Value $DisplayVersion
                                $TmpObject
                            }
                        }
                    }
                } Catch {
                    Write-Verbose -Message "$ComputerName $_"
                }
            }
        }
        If($GetArch -eq 'AMD64') {$OSArch = '64-bit'} Else {$OSArch = '32-bit'}
        If ($OSArch -eq '64-bit') {
           $AllInstalledOffice  += GetOfficeInfo -RootOfficeKeylKey $RootOfficeKeylKeyX64 -DisplayArch '32-bit' -RootUninstallKey $RootUninstallKeyX64
           $AllInstalledOffice  += GetOfficeInfo -RootOfficeKeylKey $RootOfficeKeylKey    -DisplayArch '64-bit' -RootUninstallKey $RootUninstallKey   
        } Else {
            $AllInstalledOffice += GetOfficeInfo -RootOfficeKeylKey $RootOfficeKeylKey    -DisplayArch '32-bit' -RootUninstallKey $RootUninstallKey    
        }
        If ($AllInstalledOffice.Count -eq 0) {'MsOffice not found'} Else {$AllInstalledOffice}
    } Catch {
        Write-Error -Message $_
    }
}

Function MseLastUpdateDate {
    #$stdregprov=Get-WmiObject -Class stdregprov -List
    #$win32_operatingsystem=Get-WmiObject -Class win32_operatingsystem
    #$Computername="Localhost"
    Try { 
        If ($win32_operatingsystem.producttype -eq 1) {
            [version]$OSVersion = $win32_operatingsystem.version 
            If ($Credential) {
                If ($OSVersion -ge [version]'6.0.0.0') { 
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $Computername -ErrorAction Stop -Credential $Credential 
                } Else {   
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computername -ErrorAction Stop -Credential $Credential 
                } # end IF 
            } Else {
                If ($OSVersion -ge [version]'6.0.0.0') { 
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $Computername -ErrorAction Stop 
                } Else {   
                    $AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computername -ErrorAction Stop 
                } # end IF 
            }
            $AvName = $AntiVirusProduct.displayName; 
            If ($AvName -match '^Microsoft') {
                $ARegKey = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Microsoft Antimalware\Signature Updates'
            } ElseIf ($AvName -match '^Windows') {
                $ARegKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Signature Updates'
            } Else {
                Write-Error -Message 'MSE not found' -ErrorAction Stop
            }
            $BinData    = RegGetValue -Key $ARegKey -Value SignaturesLastUpdated -GetValue GetBinaryValue -ErrorAction Stop
            $SigLastUpd = [DateTime]::FromFileTime( (((((($BinData[7]*256 + $BinData[6])*256 + $BinData[5])*256 + $BinData[4])*256 + $BinData[3])*256 + $BinData[2])*256 + $BinData[1])*256 + $BinData[0])
            $SigLastUpd
        } Else {
            Write-Error -Message 'NotSupported' -ErrorAction Stop
        }
    } Catch { 
        Write-Error -Message $_ 
    }
}

Function NetFolderShortcuts {
    Try {
        $AllLoadedProfile    = GetUserProfile -OnlyLoaded -ErrorAction Stop
        $AllNetworkShortcuts = @()
        $AllLoadedProfile | ForEach-Object {
            $User        = $_.User
            $ProfilePath = $_.LocalPath
            $NetworkShortcutsLocation = Join-Path -Path $ProfilePath -ChildPath 'AppData\Roaming\Microsoft\Windows\Network Shortcuts'
            If ($Credential) {
                $NetworkShortcutsSubFolder = Get-WmiObject -query "ASSOCIATORS OF {Win32_Directory.Name='$NetworkShortcutsLocation'} WHERE AssocClass = Win32_Subdirectory" -Namespace root\cimv2 -ComputerName $Computername -Credential $Credential -ErrorAction Stop
            } Else {
                $NetworkShortcutsSubFolder = Get-WmiObject -query "ASSOCIATORS OF {Win32_Directory.Name='$NetworkShortcutsLocation'} WHERE AssocClass = Win32_Subdirectory" -Namespace root\cimv2 -ComputerName $Computername -ErrorAction Stop
            }
            $AllNetworkShortcutsUser = @()
            If ($null -ne $NetworkShortcutsSubFolder) {
                $NetworkShortcutsSubFolder | ForEach-Object { 
                    $FolderName           = $_.FileName
                    $NetworkShortcutsPath = (Join-Path -Path $_.name -ChildPath 'target.lnk') -replace '\\','\\' 
                    If ($credential) {
                        $ShortcutFile = Get-WmiObject  -Query "SELECT * FROM Win32_ShortcutFile WHERE Name='$NetworkShortcutsPath'" -Namespace root\cimv2 -ComputerName $Computername -Credential $credential -ErrorAction Stop
                    } Else {
                        $ShortcutFile = Get-WmiObject  -Query "SELECT * FROM Win32_ShortcutFile WHERE Name='$NetworkShortcutsPath'" -Namespace root\cimv2 -ComputerName $Computername -ErrorAction Stop
                    }
                    If ($null -ne $ShortcutFile) {
                        $ShortcutFile | ForEach-Object {
                            If ($null -ne $_.target) {
                                $TmpObject = New-Object -TypeName psobject | Select-Object -Property User,FolderName,Target
                                $TmpObject.User           = $User
                                $TmpObject.FolderName     = $FolderName
                                $TmpObject.Target         = $_.target
                                $AllNetworkShortcutsUser += $TmpObject
                            }
                        }
                    }
                }
            } Else {
                $TmpObject = New-Object -TypeName PSObject | Select-Object -Property User,FolderName,Target 
                $TmpObject.User       = $User
                $TmpObject.FolderName = 'NoNetResCon'
                $TmpObject.Target     = $null
                $AllNetworkShortcuts += $TmpObject
            }
            If ($AllNetworkShortcutsUser.Count -eq 0) {
                $TmpObject = New-Object -TypeName PSObject | Select-Object -Property User,FolderName,Target 
                $TmpObject.User           = $User
                $TmpObject.FolderName     = $null
                $TmpObject.Target         = $null
                $AllNetworkShortcutsUser += $TmpObject
            }
        $AllNetworkShortcuts+=$AllNetworkShortcutsUser
        }
        $AllNetworkShortcuts  
    } Catch {
        Write-Error -Message $_
    }
}

Function NetMappedDrives {
    #$StdregProv=Get-WmiObject -Class Stdregprov -List
    #$Win32_UserProfile= Get-WmiObject -Class Win32_UserProfile
    Try {
        $AllLoadedProfile = GetUserProfile -OnlyLoaded -ErrorAction Stop
        $AllMappedDrivers = @()
        $AllLoadedProfile | ForEach-Object {
            $UserName        = $_.user
            $NetDriveKey     = "HKEY_USERS\$($_.sid)\Network"
            $AllNetDrivesKey = RegEnumKey -Key $NetDriveKey -ErrorAction SilentlyContinue
            If ($null -ne $AllNetDrivesKey) {
                $AllNetDrivesKey | ForEach-Object {
                    $DriverLetter          = $_
                    $DriverLetterRegKey    = Join-Path -Path $NetDriveKey -ChildPath $DriverLetter  
                    $RemotePath            = RegGetValue -Key $DriverLetterRegKey -Value RemotePath -GetValue GetStringValue
                    $TmpObject             = New-Object -TypeName PSObject | Select-Object -Property User,DriveLetter,Target
                    $TmpObject.User        = $UserName
                    $TmpObject.DriveLetter = $DriverLetter
                    $TmpObject.Target      = $RemotePath
                    $AllMappedDrivers     += $TmpObject
                }
            } Else {
                $TmpObject = New-Object -TypeName PSObject | Select-Object -Property User,DriveLetter,Target 
                $TmpObject.User        = $UserName
                $TmpObject.DriveLetter =$null
                $TmpObject.Target      =$null   
                $AllMappedDrivers     += $TmpObject
            }
        }
        $AllMappedDrivers      
    } Catch {
        Write-Error -Message $_
    }
}

Function OsActivationStatus {
    $ActStat=@{
        '1' = 'Licensed'
        '2' = 'Out-Of-Box Grace Period'
        '3' = 'Out-Of-Tolerance Grace Period'
        '4' = 'Non-Genuine Grace Period'
        '5' = 'Notification'
        '6' = 'Extended Grace'
    }
    If ($Query_SoftwareLicensingProduct_OsActivationStatus) {
        $LicStat = ($Query_SoftwareLicensingProduct_OsActivationStatus.Licensestatus).tostring()
        $Stat    = $ActStat[$LicStat]
        If (!$Stat) {$Stat = "Unknown value $($Query_SoftwareLicensingProduct_OsActivationStatus.Licensestatus)"}
        If ($Query_SoftwareLicensingProduct_OsActivationStatus.Description -match '.+,\s?(.+)') {$Descr = $Matches[1]} Else {$Query_SoftwareLicensingProduct_OsActivationStatus.Description}
        $KmsPort   = $Query_SoftwareLicensingProduct_OsActivationStatus.KeyManagementServicePort
        $KmsServer = $Query_SoftwareLicensingProduct_OsActivationStatus.KeyManagementServiceMachine
        If ($KmsServer -and $KmsPort) {$FullKms = $KmsServer + ':' + $KmsPort} Else {$FullKms = $null}
    } Else {
        $Stat = 'Unlicensed or Unknown'
    }
    $Prop = @{
        'Status'      = $Stat
        'Description' = $Descr
    }
    If ($FullKms) {$Prop.Add('KMSServer',$FullKms)}
    $DispObj = New-Object -TypeName PSObject -Property $Prop
    $DispObj
}

Function OsAdministrators {
    Try {
        $GroupName=$Query_Win32_Group_OsAdministrators.Name
        $Computername=$Query_Win32_Group_OsAdministrators.__SERVER
        Function GetLastPasswordChange {
            Param ($LocalAccountName,$CurrentDate,$Computer)
            $user     = ([adsi]"WinNT://$computer/$($LocalAccountName),user")
            $pwAge    = $user.PasswordAge.Value
            If ($pwAge -eq 0) {$pwLastSet = $null} Else {$pwLastSet = $CurrentDate.AddSeconds(-$pwAge)}
            $pwLastSet
        }
        Write-Verbose -Message "Administrators GroupName $GroupName"
        If ($Credential) {
            $wmitmp = Get-WmiObject -ComputerName $ComputerName -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$ComputerName',Name='$GroupName'`"" -ErrorAction Stop -Credential $Credential
        } Else {
            $wmitmp = Get-WmiObject -ComputerName $ComputerName -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$ComputerName',Name='$GroupName'`"" -ErrorAction Stop
        }
        If ($null -ne $wmitmp) {
            $DispObjArray=@()       
            If ($Credential) {
                $LocalUserAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace root\cimv2  -ComputerName $ComputerName -Filter "LocalAccount=$true" -ErrorAction Stop -Credential $Credential
            } Else {
                Write-Verbose -Message "Get-WmiObject -Filter LocalAccount=$true"
                $LocalUserAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace root\cimv2  -ComputerName $ComputerName -Filter "LocalAccount=$true" -ErrorAction Stop
            }
            $wmitmp | ForEach-Object {
                If ($_.PartComponent -match '(.+:)?win32_(.+)\..+?="(.+?)",Name="(.+?)"') {
                    $LastPasswordChange = $null
                    $Type               = $Matches[2]
                    $Type               = $Type -replace 'User',''
                    $Domain             = $matches[3]
                    $Name               = $Matches[4]
                    $FullName           = "$Domain\$Name"
                    $AccountStatus      = $null
                    $PasswordRequired   = $null
                    If ($domain -eq $computername) {$IsLocalAccount = $True} Else {$IsLocalAccount = $false}
                    If ($type -eq 'Account' -and $IsLocalAccount) {
                        $UserAccount   = $LocalUserAccounts | Where-Object {$_.caption -eq $FullName}
                        $AccountStatus = $UserAccount.status   
                        If ($protocol -eq 'WSMAN') {
                            $Now                = Get-Date
                            $LastPasswordChange = GetLastPasswordChange -LocalAccountName $UserAccount.name -CurrentDate $Now -Computer $Computername
                        }
                    }
                    $DispObj = New-Object -TypeName PSObject 
                    $DispObj | Add-Member -MemberType NoteProperty -Name FullName -Value "$Domain\$Name"
                    $DispObj | Add-Member -MemberType NoteProperty -Name Type -Value $Type
                    $DispObj | Add-Member -MemberType NoteProperty -Name IsLocal -Value $IsLocalAccount
                    If ($protocol -eq 'WSMAN') {$DispObj | Add-Member -MemberType NoteProperty -Name LastPassChange -Value $LastPasswordChange}
                    $DispObj | Add-Member -MemberType NoteProperty -Name Status -Value $AccountStatus
                    $DispObjArray += $DispObj 
                }
            }
            $DispObjArray | Sort-Object -Property IsLocal,Type -Descending
        } Else {
            Write-Error -Message "Query SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$ComputerName',Name='$GroupName'`" return null value" -ErrorAction Stop
        }
    } Catch {
        Write-Error -Message $_
    }
}

Function OsGuid {RegGetValue -Key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography -Value MachineGuid -GetValue GetStringValue}

Function OsInstallDate {[Management.ManagementDateTimeConverter]::ToDateTime($Win32_OperatingSystem.installdate)}

Function OsKernelPowerFailCount {
    [int]$SeeHours   = 24
    #$Win32_LocalTime = Get-WmiObject -class Win32_LocalTime 
    $currentDate     = Get-Date -Year $Win32_LocalTime.Year -Month $Win32_LocalTime.Month -Day $Win32_LocalTime.Day -Hour $Win32_LocalTime.Hour -Minute $Win32_LocalTime.Minute -Second $Win32_LocalTime.Second
    $date            = $currentDate.AddHours(-$SeeHours)
    [wmi]$WmiObject  = ''
    $datewmi         = $WmiObject.ConvertFromDateTime($date)
    If ($Credential) {
        [array]$ErrorLog = Get-WmiObject -query "Select * From Win32_NTLogEvent Where LogFile = 'System' And TimeWritten > '$datewmi' And EventCode = 41" -Namespace root\cimv2 -ComputerName $ComputerName -Credential $Credential
    } Else {
        [array]$ErrorLog = Get-WmiObject -query "Select * From Win32_NTLogEvent Where LogFile = 'System' And TimeWritten > '$datewmi' And EventCode = 41" -Namespace root\cimv2 -ComputerName $ComputerName
        #[array]$ErrorLog=get-wmiobject -query "Select * From Win32_NTLogEvent Where LogFile = 'Application' And TimeWritten > '$datewmi' And EventCode = 1015" -Namespace root\cimv2 -ComputerName $ComputerName
    }
    Write-Verbose -Message "errors in $SeeHours hours"
    [string]$Result = ''
    $ErrorLog | ForEach-Object {
        If ($_.TimeWritten) {
            $Date    = $WmiObject.ConvertToDateTime($($_.TimeWritten))
            $Result += $Date.ToString()+'; '
        }
    }
    If ($ErrorLog) {
        Write-Verbose -Message "ToString $($ErrorLog.count)"
        $ErrCount = ($ErrorLog.Count).ToString()
        $ErrCount + ' ' + $Result
    } Else {
        Return '0'
    }
}

Function OsLastUpdated {
    Try {
        $CurrentDate = Get-date
        If ($Win32_QuickFixEngineering | Where-Object {$null -ne $_.installedon} | Where-Object {$_.installedon.gettype() -eq [datetime]}) {
            $LastUpdate = ($Win32_QuickFixEngineering | Sort-Object -Property {$_.InstalledOn} -Descending -ErrorAction Stop | Select-Object -First 1 -ErrorAction Stop).InstalledOn
            If ($Protocol -eq 'Wsman') {
                $Win32_OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem
                If ([version]$Win32_OperatingSystem.Version -lt [Version]'10.0.14393' -and $Win32_OperatingSystem.locale -eq '0419') {
                    $LastUpdate = Get-Date -Day $LastUpdate.month -Month $LastUpdate.day -Year $LastUpdate.year -Hour 0 -Minute 0 -Second 0  
                }
            }
        } Else {
            $Win32_QuickFixEngineeringDate=$Win32_QuickFixEngineering | ForEach-Object {
                If ($_.installedon) {
                    If ($_.installedon -match '(.+)/(.+)/(.+)') {
                        $Month               = $matches[1]
                        $Day                 = $matches[2]
                        $Year                = $matches[3]    
                        $DateUpdateInstalled = Get-Date -Day $Day -Month $Month -Year $Year -Hour 0 -Minute 0 -Second 0
                        $_ | Add-Member -MemberType NoteProperty -Name DateUpdateInstalled -Value $DateUpdateInstalled -Force
                        $_
                    }
                }
            }
            $LastUpdate = ($Win32_QuickFixEngineeringDate | Sort-Object -Property {$_.DateUpdateInstalled} -Descending -ErrorAction Stop | Select-Object -First 1 -ErrorAction Stop).DateUpdateInstalled
        }
        ($CurrentDate - $LastUpdate).Days
    } Catch {
        Write-Error -Message $_
    }
}

Function OsProductKey {
    Try {
        $map = 'BCDFGHJKMPQRTVWXY2346789' 
        If ((RegGetValue -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Value 'PROCESSOR_ARCHITECTURE' -GetValue GetStringValue -ErrorAction Stop) -eq 'AMD64') {            
            $value = (RegGetValue -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Value 'DigitalProductId4' -GetValue GetBinaryValue -ErrorAction Stop)[0x34..0x42]
        } Else {
            $value = (RegGetValue -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Value 'DigitalProductId' -GetValue GetBinaryValue -ErrorAction Stop)[0x34..0x42]       
        }
        $ProductKey = ''
        For ($i = 24; $i -ge 0; $i--) { 
            $r = 0 
            For ($j = 14; $j -ge 0; $j--) { 
                $r         = ($r * 256) -bxor $value[$j] 
                $value[$j] = [math]::Floor([double]($r/24)) 
                $r         = $r % 24 
            } 
            $ProductKey = $map[$r] + $ProductKey 
            If (($i % 5) -eq 0 -and $i -ne 0) {$ProductKey = '-' + $ProductKey} 
        }
        $ProductKey
    } Catch {
        Write-Error -Message $_
    }
}

Function OsSRPSettings {
    #$Computername=$env:COMPUTERNAME
    #$Win32_UserProfile=Get-WmiObject -Class Win32_UserProfile
    #$StdregProv=Get-WmiObject -Class Stdregprov -List
    Try {
        $SRPKeyPath        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers'   
        $SRPKey            = RegGetValue -Key $SRPKeyPath -Value DefaultLevel -GetValue GetDWORDValue -ErrorAction SilentlyContinue
        $ComputerSrpEnable = $false
        If ($SRPKey -eq 0) {$ComputerSrpEnable = $true}
        [string[]]$ExcludeSid = 'S-1-5-18','S-1-5-19','S-1-5-20'
        If ($credential) {
            $LocalAccount = Get-WmiObject -Class Win32_UserAccount -ComputerName $Computername -Filter "LocalAccount=$true" -Credential $credential
        } Else {
            $LocalAccount = Get-WmiObject -Class Win32_UserAccount -ComputerName $Computername -Filter "LocalAccount=$true"
        }
        $LoadedProfile        = $Win32_UserProfile |Select-Object -Property * | Where-Object {!($ExcludeSid -eq $_.sid) -and $_.loaded}
        If ($null -eq $LoadedProfile -and !$ComputerSrpEnable) {
            Write-Error -Message 'No uploaded user profile' -ErrorAction Stop        
        } ElseIf ($ComputerSrpEnable) {
            $Obj           = '' | Select-Object -Property User,Loaded,SrpEnable
            $Obj.User      = [string]$('$'+$computername)
            $Obj.SrpEnable = $ComputerSrpEnable
            $Obj
        }
        $LoadedProfile | ForEach-Object {
            $Sid              = $_.sid
            $LastUseTime      = $null
            $User             = $null
            $ProfileDirectory = $null
            $LocalPath        = $_.localpath
            $objSID           = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ($Sid) 
            Try {
                $objUser = $objSID.Translate([Security.Principal.NTAccount])
                $User    = $objUser.Value
                Write-Verbose -Message "$Computername Translate sid $sid succesfully"
            } Catch {
                Write-Verbose -Message "$Computername Unknown sid $sid"
                $User = ($LocalAccount | Where-Object {$_.sid -eq $Sid}).caption
                if ($null -eq $User) {$User = 'Unknown'}
            }
            $_ | Add-Member -MemberType NoteProperty -Name User -Value $User
            $_
        } | ForEach-Object {
            If ($ComputerSrpEnable) {
                $SrpEnable = $true
            } Else {
                $SRPKeyPath = "HKEY_USERS\$($_.sid)\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers"   
                $SRPKey     = RegGetValue -Key $SRPKeyPath -Value DefaultLevel -GetValue GetDWORDValue -ErrorAction SilentlyContinue
                If ($SRPKey -eq 0) {
                    $SrpEnable = $true    
                } Else {
                    $SrpEnable = $false        
                }
            }
            $_ | Add-Member -MemberType NoteProperty -Name SrpEnable -Value $SrpEnable
            $_
        } | Sort-Object -Property SrpEnable -Descending | Select-Object -Property User,SrpEnable
    } Catch {
        Write-Error -Message $_
    }
}

Function OsSrpLog {
    #$ComputerName="LocalHost"
    #$Win32_LocalTime=Get-WmiObject -Class Win32_LocalTime -Namespace root\cimv2 -ComputerName $ComputerName
    [int]$SeeHours  = 24
    $currentDate    = Get-Date -Year $Win32_LocalTime.Year -Month $Win32_LocalTime.Month -Day $Win32_LocalTime.Day -Hour $Win32_LocalTime.Hour -Minute $Win32_LocalTime.Minute -Second $Win32_LocalTime.Second
    $date           =$currentDate.AddHours(-$SeeHours)
    [wmi]$WmiObject = ''
    $datewmi        = $WmiObject.ConvertFromDateTime($date)
    If ($Credential) {
        [array]$SrpLogEntries = Get-WmiObject -query "Select * From Win32_NTLogEvent Where LogFile = 'Application' And TimeWritten > '$datewmi' And EventCode = 865" -Namespace root\cimv2 -Credential $Credential -ComputerName $ComputerName 
    } Else {
        [array]$SrpLogEntries = Get-WmiObject -query "Select * From Win32_NTLogEvent Where LogFile = 'Application' And TimeWritten > '$datewmi' And EventCode = 865" -Namespace root\cimv2 -ComputerName $ComputerName 
    }
    If ($SrpLogEntries.Count -ne 0) {
        $SrpLogEntries | ForEach-Object {
            $SrpLogEntry = $_
            $TmpObject = New-Object -TypeName PSObject
            $TmpObject | Add-Member -MemberType NoteProperty -Name Path -Value $SrpLogEntry.InsertionStrings
            $TmpObject | Add-Member -MemberType NoteProperty -Name TimeGenerated -Value $WmiObject.ConvertToDateTime($($SrpLogEntry.TimeGenerated))
            $TmpObject
        }
    } Else {
        Write-Error -Message "There are no SRP constraint records for the last $SeeHours hours"
    }
}

Function OsUptime {
    Try {
        $Uptime = $Win32_OperatingSystem.ConvertToDateTime($Win32_OperatingSystem.LocalDateTime) - $Win32_OperatingSystem.ConvertToDateTime($Win32_OperatingSystem.LastBootUpTime)
        $Uptime
        #"$($Uptime.days)"+":"+"$($Uptime.hours)"+":"+"$($Uptime.minutes)"+":"+"$($Uptime.seconds)"
    } catch {
        Write-Error -Message $_
    }
}

Function RebootRequired {
    Try {
        <#
            Component-Based Servicing 
            http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
            PendingFileRename/Auto Update:
              http://support.microsoft.com/kb/2723674
              http://technet.microsoft.com/en-us/library/cc960241.aspx
              http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx
        #>
        $OsBuild = $Win32_OperatingSystem.BuildNumber
        $CompPendRen,$PendFileRename,$Pending = $false,$false,$false
        ## If Vista/2008 & Above query the CBS Reg Key
        If ([Int32]$OsBuild -ge 6001) {
            $RegSubKeysCBS = RegEnumKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
            $CBSRebootPend = $RegSubKeysCBS -contains 'RebootPending'		
        }
        ## Query WUAU from the registry
        $RegWUAURebootReq  = RegEnumKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
        $WUAURebootReq     = $RegWUAURebootReq -contains 'RebootRequired'
        ## Query PendingFileRenameOperations from the registry
        $RegValuePFRO      = RegGetValue -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations' -GetValue GetMultiStringValue -ErrorAction SilentlyContinue
        ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
        $Netlogon          = RegEnumKey -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon'
        $PendDomJoin       = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')
        ## Query ComputerName and ActiveComputerName from the registry
        $ActCompNm         = RegGetValue -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Value 'ComputerName' -GetValue GetStringValue
        $CompNm            = RegGetValue -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Value 'ComputerName' -GetValue GetStringValue 
        If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {$CompPendRen = $true}
        If ($RegValuePFRO) {$PendFileRename = $true}
        $PsObject = New-Object -TypeName PSObject
        $PsObject | Add-Member -MemberType NoteProperty -Name CBServicing    -Value $CBSRebootPend
        $PsObject | Add-Member -MemberType NoteProperty -Name WindowsUpdate  -Value $WUAURebootReq
        $PsObject | Add-Member -MemberType NoteProperty -Name ComputerRename -Value $CompPendRen
        $PsObject | Add-Member -MemberType NoteProperty -Name FileRename     -Value $PendFileRename
        $PsObject | Add-Member -MemberType NoteProperty -Name RebootRequired -Value ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $PendFileRename)
        $PsObject
    } Catch {
        Write-Error -Message $_
    }
}

Function TenLatestUpdates {
    Try {
        #$CurrentDate=Get-date
        If ($Win32_QuickFixEngineering | Where-Object {$null -ne $_.installedon} | Where-Object {$_.installedon.gettype() -eq [datetime]}) {
            $LastTenUpdate = $Win32_QuickFixEngineering | Sort-Object -Property {$_.InstalledOn} -Descending -ErrorAction Stop | Select-Object -First 10 -ErrorAction Stop        
        } Else {
            $Win32_QuickFixEngineeringDate = $Win32_QuickFixEngineering | ForEach-Object {
                If ($_.installedon) {
                    If ($_.installedon -match '(.+)/(.+)/(.+)') {
                        $Month               = $matches[1]
                        $Day                 = $matches[2]
                        $Year                = $matches[3]    
                        $DateUpdateInstalled = Get-Date -Day $Day -Month $Month -Year $Year -Hour 0 -Minute 0 -Second 0
                        $_ | Add-Member -MemberType NoteProperty -Name DateUpdateInstalled -Value $DateUpdateInstalled -Force
                        $_
                    }
                }
            }
            $LastTenUpdate = $Win32_QuickFixEngineeringDate | Sort-Object -Property {$_.DateUpdateInstalled} -Descending -ErrorAction Stop | Select-Object -First 10 -ErrorAction Stop
        }
        If ($LastTenUpdate) {$LastTenUpdate | Select-Object -Property Description,HotFixID,InstalledBy,InstalledOn} Else {Write-Error -Message 'NoLastUpdate' -ErrorAction Stop}
    } Catch {
        Write-Error -Message $_
    }
}

Function UpdateAgentVersion {
    Try {
        $SystemDir = $Win32_OperatingSystem.SystemDirectory
        $File      = $SystemDir+'\wuaueng.dll'
        $filewmi   = $file -replace '\\','\\'
        If ($Credential) {
            $UpdateAgentVersion = (Get-WmiObject -Class CIM_DataFile -namespace 'root\cimv2' -Filter "Name='$filewmi'" -ComputerName $Computername -Credential $Credential -ErrorAction Stop).version
        } Else {
            $UpdateAgentVersion = (Get-WmiObject -Class CIM_DataFile -namespace 'root\cimv2' -Filter "Name='$filewmi'" -ComputerName $Computername -ErrorAction Stop).version
        }
        [version]$UpdateAgentVersion
    } Catch {
        Write-Error -Message $_
    }
}

Function UserProfileList {
    Try {
        GetUserProfile | ForEach-Object {
            $LocalPath = $_.LocalPath
            If ($null -ne $LocalPath) {
                $LastUseTime = $null
                $ProfilePath = $LocalPath -replace '\\','\\'
                If ($credential) {
                    $ProfileDirectory = Get-WmiObject -Class Win32_Directory -Filter "Name='$ProfilePath'" -ComputerName $Computername -ErrorAction Stop -Credential $credential
                } Else {
                    $ProfileDirectory = Get-WmiObject -Class Win32_Directory -Filter "Name='$ProfilePath'" -ComputerName $Computername -ErrorAction Stop
                }
                If ($null -ne $ProfileDirectory) {
                    $LastUseTime = ([wmi]'').ConvertToDateTime($ProfileDirectory.LastModified)
                }
            }
            $_ | Add-Member -MemberType NoteProperty -Name LastModified -Value $LastUseTime
            $_
        } | Sort-Object -Property LastModified -Descending | Select-Object -Property User,LocalPath,Loaded,LastModified
    } catch {
        Write-Error -Message $_
    }
}

Function UserProxySettings {
    #$Computername=$env:COMPUTERNAME
    #$Win32_UserProfile=Get-WmiObject -Class Win32_UserProfile
    #$StdregProv=Get-WmiObject -Class Stdregprov -List
    Try {
        [string[]]$ExcludeSid   = 'S-1-5-18','S-1-5-19','S-1-5-20'    
        $AutoDetectSettingsHash = @{
            1  = $False
            3  = $False
            11 = $true
            9  = $true
        }
        $LoadedProfile = $Win32_UserProfile | Select-Object -Property * | Where-Object {!($ExcludeSid -eq $_.sid) -and $_.loaded} 
        If ($null -eq $LoadedProfile) {Write-Error -Message 'No uploaded user profile' -ErrorAction Stop}
        $LoadedProfile | ForEach-Object {
            $Sid              = $_.sid
            $LastUseTime      = $null
            $User             = $null
            $ProfileDirectory = $null
            $LocalPath        = $_.localpath
            $objSID           = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ($Sid) 
            Try {
                $objUser = $objSID.Translate([Security.Principal.NTAccount])
                $User    = $objUser.Value
                Write-Verbose -Message "$Computername Translate sid $sid succesfully"
            } Catch {
                Write-Verbose -Message "$Computername Unknown sid $sid"
                If ($null -eq $LocalAccount) {
                    If ($credential) {
                        $LocalAccount = Get-WmiObject -Class Win32_UserAccount -ComputerName $Computername -Filter "LocalAccount=$true" -Credential $credential
                    } Else {
                        $LocalAccount = Get-WmiObject -Class Win32_UserAccount -ComputerName $Computername -Filter "LocalAccount=$true"
                    }
                }
                $User    = ($LocalAccount | Where-Object {$_.sid -eq $Sid}).caption
                if ($null -eq $User) {$User = 'Unknown'}
            }
            $_ | Add-Member -MemberType NoteProperty -Name User -Value $User
            $_
        } | ForEach-Object {
            $ISKey         = "HKEY_USERS\$($_.sid)\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
            #$ISKey
            $ProxyEnable   = RegGetValue -Key $ISKey               -Value ProxyEnable               -GetValue GetDWORDValue  -ErrorAction SilentlyContinue
            $ProxyServer   = RegGetValue -Key $ISKey               -Value ProxyServer               -GetValue GetStringValue -ErrorAction SilentlyContinue
            $ProxyOverride = RegGetValue -Key $ISKey               -Value ProxyOverride             -GetValue GetStringValue -ErrorAction SilentlyContinue
            $DefConnectSet = RegGetValue -Key "$ISKey\connections" -Value DefaultConnectionSettings -GetValue GetBinaryValue -ErrorAction SilentlyContinue
            If ($ProxyOverride -match '<Local>') {$BypassForLocal = $True} Else {$BypassForLocal = $False}
            if ($null -ne $DefConnectSet) {$AutoDetectSettings = $AutoDetectSettingsHash[[int]$($DefConnectSet[8])]}
            if ($proxyenable -eq 1) {$proxyenable = $true} else {$proxyenable = $false}
            $_ | Add-Member -MemberType NoteProperty -Name Proxy              -Value $ProxyServer
            $_ | Add-Member -MemberType NoteProperty -Name AutoDetectSettings -Value $AutoDetectSettings
            $_ | Add-Member -MemberType NoteProperty -Name BypassForLocal     -Value $BypassForLocal
            $_ | Add-Member -MemberType NoteProperty -Name ProxyEnable        -Value $ProxyEnable   
            $_
        } | Select-Object -Property User,Proxy,AutoDetectSettings,BypassForLocal,ProxyEnable | Sort-Object -Property ProxyEnable -Descending
    } Catch {
        Write-Error -Message $_
    }
}

Function VolumeShadowCopy {
    Try {
        Function GetDriveLetter {
            Param([string]$VolumeID)
            ($Win32_Volume | Where-Object {$_.deviceid -eq $VolumeID }).driveletter    
        }
        If ($Win32_ShadowCopy) {
            $Win32_ShadowCopy | ForEach-Object {
                $Psobject = New-Object -TypeName psobject
                $InstallDate = $_.ConvertToDateTime($_.InstallDate)
                $Psobject | Add-Member -MemberType NoteProperty -Name InstallDate -Value $InstallDate
                $DrLetter = GetDriveLetter -VolumeID $_.volumename
                $Psobject | Add-Member -MemberType NoteProperty -Name Drive -Value $DrLetter
                $Psobject | Add-Member -MemberType NoteProperty -Name ID -Value $_.ID
                $Psobject
            }
        } Else {
            'NoShadowCopies'
        }
    } Catch {
        Write-Error -Message $_
    }
}

Function PSVersion {
    #$stdregprov    = Get-WmiObject -Class stdregprov -List
    $PsEnumKeyKeys = RegEnumKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell'
    $PsEnginekey   = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\' + "$(($PsEnumKeyKeys | Sort-Object -Descending)[0])" + '\powershellengine'
    $PsVersion     = RegGetValue -Key $PsEnginekey -Value PowerShellVersion -GetValue GetStringValue
    [version]$PsVersion
}

Function IsPrintServer {
    $IsPrintServer = $false
    $dispPrinter   = $Win32_Printer | Select-Object -Property Name,DriverName,Network,Local,PortName,WorkOffline,Published,Shared,ShareName,Direct,PrinterStatus,PrintProcessor
    $dispPrinter | ForEach-Object {
        If (($_.portname -match 'Usb') -and ($_.local -eq $True) -and ($_.workOffline -eq $false)) {                                                     
            If ($_.shared -eq $true) {$IsPrintServer = $True}
        }
    }
    $IsPrintServer 
}

Function Printers {
    #$dispPrinter = $Win32_Printer | Select-Object -Property Name,DriverName,Network,Local,PortName,WorkOffline,Published,Shared,ShareName,Direct,PrinterStatus,PrintProcessor                                                          
    $dispPrinter = $Win32_Printer | ForEach-Object {
        $Property = @{
            Name       = $_.Name
            DriverName = $_.DriverName
            Local      = $_.Local
            ShareName  = $_.ShareName
        }
        $TmpObj = New-Object -TypeName PSObject -Property $Property
        $TmpObj.psobject.typenames.insert(0,'ModuleSystemInfo.Systeminfo.Printers.Printer')
        $TmpObj
    }
    $dispPrinter
}

Function UsbConPrCount {
    $count       = 0
    $dispPrinter = $Win32_Printer | Select-Object -Property Name,DriverName,Network,Local,PortName,WorkOffline,Published,Shared,ShareName,Direct,PrinterStatus,PrintProcessor
    $dispPrinter | ForEach-Object {
        If (($_.portname -match 'Usb') -and ($_.local -eq $True) -and ($_.workOffline -eq $false)) {$Count++}
    }
    $count
}

Function UsbConPrOnline {
    $ObjUsbConnectPrinters = @()
    $dispPrinter           = $Win32_Printer | Select-Object -Property Name,DriverName,Network,Local,PortName,WorkOffline,Published,Shared,ShareName,Direct,PrinterStatus,PrintProcessor
    $dispPrinter | ForEach-Object {
        If (($_.portname -match 'Usb') -and ($_.local -eq $True) -and ($_.workOffline -eq $false)) {
            $ObjUsbConnectPrinter = New-Object -TypeName PSObject
            $ObjUsbConnectPrinter | Add-Member -NotePropertyName PrinterName -NotePropertyValue $_.name
            $ObjUsbConnectPrinter | Add-Member -NotePropertyName DriverName -NotePropertyValue $_.DriverName
            $ObjUsbConnectPrinters += $ObjUsbConnectPrinter
        }
    }
    $ObjUsbConnectPrinters
}

Function GoogleChromeInfo {GetInstalledSoftware -SoftwareName 'Google Chrome' -DisplayAdvInfo}

Function SkypeInfo {
    GetInstalledSoftware -MatchSoftwareName 'Skype' -DisplayAdvInfo | Where-Object {$_.publisher -eq 'Skype Technologies S.A.' -or $_.publisher -match 'Microsoft'} | ForEach-Object {
        if ($_.appname -match '\d+') {
            [version]$SkypeVersion = $_.version
            $_.version             = $SkypeVersion
            $_
        }
    }
}

Function SoftwareList {
    #To exclude from the output software starting with
    $MatchExcludeSoftware = @(
        'Security Update for Windows',
        'Update for Windows',
        'Update for Microsoft',
        'Security Update for Microsoft',
        'Hotfix',
        'Update for Microsoft Office',
        ' Update for Microsoft Office'
    )
    GetInstalledSoftware -MatchExcludeSoftware $MatchExcludeSoftware
}

Function SysmonInfo {
    #$ComputerName = "localhost"
    #$StdregProv   = Get-WmiObject -Class StdregProv -List -ComputerName $ComputerName
    #Hide:
    #sc sdset Sysmon D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
    #Restore:
    #sc sdset Sysmon D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
    Try {
        $RegistryServiceKey = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\'
        Function ComputeHash {
            [cmdletbinding()]
            Param ($Data,$FilePath,[validateset('Md5','Sha1','Sha256')][string]$HashAlgorithm='Sha256')
            $ServiceProv = [Security.Cryptography.HashAlgorithm]::Create($HashAlgorithm)
            If ($null -ne $PSBoundParameters['Data']) {
                If ($Data.GetType() -eq [string]) {
                    $enc   = [Text.Encoding]::UTF8    
                    $Bytes = $enc.GetBytes($Data)
                } ElseIf ($Data.GetType() -eq [string[]]) {
                    $Data  = $Data | Out-String
                    $enc   = [Text.Encoding]::UTF8    
                    $Bytes = $enc.GetBytes($Data)
                } Else {
                    $Bytes = $Data
                }
                $Hash = [BitConverter]::ToString($ServiceProv.ComputeHash($Bytes)) -replace '-',''
            } ElseIf ($null -ne $PSBoundParameters['FilePath']) {
                If (Test-Path -Path $FilePath) {$Hash = [BitConverter]::ToString($ServiceProv.ComputeHash([IO.File]::ReadAllBytes($FilePath))) -replace '-',''} else {Write-Error -Message "File $FilePath not exist" -ErrorAction Stop}
            }
            $Hash
        }
        
        Function GetRuleHash {
            Param ([string]$SysmonPath,[string]$Algorithm='sha1')
            $Command                 = $Sysmonpath+' -c'
            [scriptblock]$SbRunspace = {
                Param ($Command)
                Invoke-Expression -Command $Command
            }
            $PowerShell = [powershell]::Create()
            [void]$PowerShell.AddScript($SbRunspace)
            $ParamList  = @{Command = $Command}
            [void]$PowerShell.AddParameters($ParamList)
            $State      = $PowerShell.BeginInvoke()
            Do {
                $retry = $True
                If ($State.IsCompleted) {
                    $SysmonOut  = $PowerShell.EndInvoke($State) 
                    $PowerShell.Dispose()
                    $PowerShell = $null
                    $State      = $null
                    $retry      = $false
                }
            } While ($retry)
            $ExcludeString = 'RuleConfiguration','Servicename','Drivername','SystemMonitor','Copyright','Sysinternals'
            #$SysmonOut     = Invoke-Expression $Command -ErrorAction Stop
            [Collections.ArrayList]$SysmonOut = $SysmonOut | ForEach-Object {$($_ -replace ' ','').Trim()}
            $ExcludeString | ForEach-Object {
                $Exclude = $_
                If ($m = $SysmonOut -match $Exclude) {
                    $rindex = $SysmonOut.IndexOf("$m")
                    $SysmonOut.RemoveAt($rindex)
                }
            }
            $Rul = New-Object -TypeName System.Text.StringBuilder
            $SysmonOut | ForEach-Object {[void]$Rul.Append($_)}
            $str = $rul.ToString()
            If ($str.Length -le 80) {Write-Verbose -Message "$ComputerName SysmonOut: $str RuleHash may be incorrect.." -Verbose}
            If (!([string]::IsNullOrEmpty($str))) {
                ComputeHash -Data $str -HashAlgorithm $Algorithm
            } Else {
                Write-Error -Message 'Impossible to calculate rule hash. Config string is null or empty' -ErrorAction Stop
            }
        }
        
        Function GetSysmon {
            Param ([switch]$UseLogNameFind)
            If ($PSBoundParameters['UseLogNameFind'].ispresent) {
                Try {
                    $OwningPublisherGuid = RegGetValue -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational' -Value OwningPublisher -GetValue GetStringValue -ErrorAction Stop
                    Write-Verbose -Message "Found OwningPublisher $OwningPublisherGuid"
                    $SysmonPath          = RegGetValue -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$OwningPublisherGuid" -Value MessageFileName -GetValue GetStringValue -ErrorAction Stop
                    Write-Verbose -Message "SysmonPath $SysmonPath"
                    $resmatch            = ([regex]::Match($SysmonPath,'.+\\(.+)\.exe$')).groups[1]
                    If ($resmatch.success) {$SysmonName = $resmatch.value} Else {Write-Error -Message "Value $SysmonPath not match" -ErrorAction Stop}
                    $ServiceKey          = Join-Path -Path $RegistryServiceKey -ChildPath $SysmonName
                    Write-Verbose -Message "Service key $serviceKey"
                    $DriverName          = RegGetValue -Key "$ServiceKey\Parameters" -Value DriverName -GetValue GetStringValue -ErrorAction Stop
                    Write-Verbose -Message "DriverName $DriverName"
                    Return @{
                        SysmonName = $SysmonName
                        SysmonPath = $SysmonPath
                        DriverName = $DriverName
                    }
                } Catch {
                    Write-Error -Message 'Sysmon Not Found'
                }
            } Else {
                ForEach ($ServiceName in $(RegEnumKey -Key $RegistryServiceKey)) {
                    $ServiceKey = Join-Path -Path $RegistryServiceKey -ChildPath "$ServiceName"
                    Try {
                        $DriverName   = RegGetValue -Key "$ServiceKey\Parameters" -Value DriverName -GetValue GetStringValue -ErrorAction Stop
                        $DriverRegKey = Join-Path -Path $RegistryServiceKey -ChildPath "$DriverName\Instances\Sysmon Instance"
                        $Altitude     = RegGetValue -Key $DriverRegKey -Value Altitude -GetValue GetStringValue -ErrorAction Stop
                        $SysmonPath   = RegGetValue -Key $ServiceKey -Value ImagePath -GetValue GetStringValue -ErrorAction Stop
                        return @{SysmonName=$serviceName;SysmonPath=$SysmonPath;DriverName=$DriverName}
                    } catch {
                        Write-Verbose -Message "Skip $ServiceKey"
                    }
                }
                Write-Error -Message 'Sysmon Not Found' -ErrorAction Stop
            }
        }
        Write-Verbose -Message 'Start function GetSysmon -UseLogNameFind'
        $SysmonInfo     = GetSysmon -UseLogNameFind
        $SysmonFilePath = "'" + ($SysmonInfo['SysmonPath'] -replace '\\','\\') + "'"
        $SrvName        = $SysmonInfo['SysmonName']
        $SrvPath        = $SysmonInfo['SysmonPath']
        If ($Credential) {
            $SysmonDrFile  = Get-WmiObject -Class CIM_DataFile -namespace 'root\cimv2' -filter "Name=$SysmonFilePath" -ComputerName $Computername -Credential $Credential -ErrorAction Stop
            $SysmonService = Get-WmiObject -Class win32_service -Filter "Name='$SrvName'" -ComputerName $computername -Credential $credential
            Write-Verbose -Message "Service state $($SysmonService.State)"
        } Else {
            $SysmonDrFile  = Get-WmiObject -Class CIM_DataFile -namespace 'root\cimv2' -filter "Name=$SysmonFilePath" -ComputerName $Computername -ErrorAction Stop 
            $SysmonService = Get-WmiObject -Class win32_service -Filter "Name='$SrvName'" -ComputerName $computername
            Write-Verbose -Message "Service state $($SysmonService.State)"
        }
        If ($SysmonService.State -eq 'Running') {$SysmonStatus = 'OK'} Else {$SysmonStatus = 'NotWorking'}
        $Res = New-Object -TypeName PSObject
        $Res | Add-Member -MemberType NoteProperty -Name ServiceName -value $SrvName
        $Res | Add-Member -MemberType NoteProperty -Name Path -value $SrvPath
        $Res | Add-Member -MemberType NoteProperty -Name Version -value $SysmonDrFile.Version
        If ($protocol -eq 'WSMAN') {
            $ServiceState = $SysmonService.State 
            $DriverState  = (Get-Service -Name $SysmonInfo['DriverName']).status
            $RuleHash     = GetRuleHash -SysmonPath $SrvPath  
            $Res | Add-Member -MemberType NoteProperty -Name RuleHash -value $RuleHash
            If ($ServiceState -eq 'Running' -and $DriverState -eq 'Running') {
                $SysmonStatus = 'OK'  
            } ElseIf ($ServiceState -ne 'Running') {
                $SysmonStatus = 'Service not working'
            } ElseIf ($DriverState -ne 'Running') {
                $SysmonStatus = 'Driver not working'
            }
        }
        $Res | Add-Member -MemberType NoteProperty -Name Status -value $SysmonStatus
        $Res
    } Catch {
        Write-Error -Message $_
    }
}

Function HddDevices {
    $DispInfo = GetHddSmart -OsVersion $($Win32_OperatingSystem.version) | ForEach-Object {
        $Property = @{
            Size          = $_.Size
            InterfaceType = $_.InterfaceType
            Model         = $_.Model
            Type          = $_.Type
            SmartStatus   = $_.SmartStatus
        }
        $TmpObj = New-Object -TypeName PSObject -Property $Property
        $TmpObj.psobject.typenames.insert(0,'ModuleSystemInfo.Systeminfo.Hdd.Devices')
        $TmpObj
    }
    $DispInfo
}

Function HddPartitions {
    Try {
        $Win32_DiskDrive | ForEach-Object {
            $Disk = $_
            If ($Credential) {
                $Partitions=Get-WmiObject -query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($Disk.DeviceID)'} WHERE AssocClass = Win32_DiskDriveToDiskPartition" -ComputerName $Computername -Credential $Credential
            } Else {
                $Partitions=Get-WmiObject -query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($Disk.DeviceID)'} WHERE AssocClass = Win32_DiskDriveToDiskPartition" -ComputerName $Computername
            }
            $Partitions | ForEach-Object {
                $Partition = $_
                If ($partition.Name -match '.+#(.+),.+#(.+)') {
                    $DiskNumber      = $Matches[1]
                    $PartitionNumber = $Matches[2]
                } Else {
                    Write-Error -Message "Unknown partition name $($partition.Name)" -ErrorAction Stop
                } 
                If ($partition.type -match 'Installable File System') {
                    $PartType = 'MBR:IFS'
                } Else {
                    $PartType = $partition.type -replace ' '
                }
                $Psobject = New-Object -TypeName psobject      
                $Psobject | Add-Member -MemberType NoteProperty -Name Partition -Value  $PartitionNumber
                $Psobject | Add-Member -MemberType NoteProperty -Name Type -Value $PartType
                $Psobject | Add-Member -MemberType NoteProperty -Name Size -Value $Partition.size
                $Psobject | Add-Member -MemberType NoteProperty -Name BootPartition -Value $Partition.bootpartition
                $Psobject | Add-Member -MemberType NoteProperty -Name BooTable -Value $Partition.bootable
                $Psobject | Add-Member -MemberType NoteProperty -Name Disk -Value  $DiskNumber
                $Psobject | Add-Member -MemberType NoteProperty -Name HddModel -Value  $Disk.model
                $Psobject.psobject.typenames.insert(0,'ModuleSystemInfo.Systeminfo.Hdd.Partitions')
                $Psobject
            }
        }
    } Catch {
        Write-Error -Message $_
    }
}

Function HddSmart {GetHddSmart -OsVersion $($Win32_OperatingSystem.version)}

Function HddSmartStatus {GetHddSmart | ForEach-Object {$_.smartstatus}}

Function HddVolumes {
    Try {
        $DrTypehash = @{
            2 = 'Removable'
            3 = 'Fixed'
            4 = 'Network'
            5 = 'Compact'
        }
        $ASSOCIATORSTable = @{}
        $Win32_LogicalDiskToPartition | ForEach-Object{
            If ($_.Dependent -match '.+=\"(.+:)\"') {$DDrive    = $Matches[1]}
            If ($_.Antecedent -match '.+=\"(.+)\"') {$DiskIndex = $Matches[1] -replace ' '}
            $ASSOCIATORSTable.add($DDrive,$DiskIndex)
        }
        $Win32_Volume | ForEach-Object {
            $Volume             = $_
            $DiskIndexPartIndex = $null
            $Disk               = $null
            $Partition          = $null
            If ($Volume.DriveLetter) {
                $DiskIndexPartIndex = $ASSOCIATORSTable[$Volume.DriveLetter]
                If ($DiskIndexPartIndex -match '.+#(.+),.+#(.+)') {
                    $Disk      = $Matches[1]
                    $Partition = $Matches[2]
                }
            }
            $DriveType = $DrTypehash[[int]$($Volume.DriveType)]
            If ($null -eq $DriveType) {$DriveType = $Volume.DriveType}
            $Psobject = New-Object -TypeName PSObject
            $Psobject | Add-Member -MemberType NoteProperty -Name Drive           -Value $Volume.DriveLetter
            $Psobject | Add-Member -MemberType NoteProperty -Name Label           -Value $Volume.label
            $Psobject | Add-Member -MemberType NoteProperty -Name Size            -Value $Volume.Capacity
            $Psobject | Add-Member -MemberType NoteProperty -Name FreeSpace       -Value $Volume.FreeSpace
            $Psobject | Add-Member -MemberType NoteProperty -Name BootVolume      -Value $Volume.BootVolume
            $Psobject | Add-Member -MemberType NoteProperty -Name FS              -Value $Volume.FileSystem
            $Psobject | Add-Member -MemberType NoteProperty -Name PageFilePresent -Value $Volume.PageFilePresent
            $Psobject | Add-Member -MemberType NoteProperty -Name Antecedent      -Value $DiskIndexPartIndex
            $Psobject | Add-Member -MemberType NoteProperty -Name Disk            -Value $Disk
            $Psobject | Add-Member -MemberType NoteProperty -Name Partition       -Value $Partition
            $Psobject | Add-Member -MemberType NoteProperty -Name Compressed      -Value $Volume.Compressed
            $Psobject | Add-Member -MemberType NoteProperty -Name DriveType       -Value $DriveType
            $Psobject.psobject.typenames.insert(0,'ModuleSystemInfo.Systeminfo.Hdd.Volumes')
            $Psobject
        }
    } Catch {
        Write-Error -Message $_
    }
}

Function UsbDevice {$Win32_USBControllerDevice | ForEach-Object {[wmi]($_.dependent)} | Select-Object -Property Name}

Function EternalBlueStatus {
    Try {
        #https://support.microsoft.com/en-us/help/4023262/how-to-verify-that-ms17-010-is-installed
        $OsVerFileVer       = @{
            '5.1.2600'   = '5.1.2600.7208'    #Windows XP
            '5.2.3790'   = '5.2.3790.6021'    #Windows Server 2003 SP2
            '6.1.7601'   = '6.1.7601.23689'   #Windows 7 Windows Server 2008 R2
            '6.2.9200'   = '6.2.9200.22099'   #Windows 8 Windows Server 2012
            '6.3.9600'   = '6.3.9600.18604'   #Windows 8.1 Windows Server 2012 R2
            '10.0.10240' = '10.0.10240.17319' #Windows 10 TH1 v1507
            '10.0.10586' = '10.0.10586.839'   #Windows 10 TH2 v1511
            '10.0.14393' = '10.0.14393.953'   #Windows 10 RS1 v1607 Windows Server 2016
        }
        $Status             = 'NotPatched'
        $OsVersion          = $Win32_OperatingSystem.version
        $MinimumFileVersion = $OsVerFileVer[$OsVersion]
        $SystemDir          = $Win32_OperatingSystem.SystemDirectory
        $File               = $SystemDir + '\drivers\srv.sys'
        $filewmi            = $file -replace '\\','\\'
        If ($Credential) {
            $SrvSysVer = (Get-WmiObject -Class CIM_DataFile -namespace 'root\cimv2' -Filter "Name='$filewmi'" -ComputerName $Computername -Credential $Credential -ErrorAction Stop).version
        } Else {
            $SrvSysVer = (Get-WmiObject -Class CIM_DataFile -namespace 'root\cimv2' -Filter "Name='$filewmi'" -ComputerName $Computername -ErrorAction Stop).version
        }
        If ($OsVersion -eq '5.1.2600') {If ($SrvSysVer -match '.+\s') {$SrvSysVer = $Matches[0]}}
        If ([version]$OsVersion -ge [Version]'10.0.14393') {
            $Status='NotRequired'
        } else {
            If ($null -ne $MinimumFileVersion) {
                If ([version]$SrvSysVer -ge [version]$MinimumFileVersion) {$Status = 'Patched'}
            } Else {
                Write-Warning -Message "$Computername Unknown OS version. Check OsVerFileVer hashtable"
            }
        }
        $smb1Protocol = RegGetValue -key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Value 'SMB1' -GetValue GetDWORDValue -ErrorAction SilentlyContinue 
        If ($smb1Protocol -eq 0) {$smb1ProtocolDisabled = $True} Else {$smb1ProtocolDisabled = $false}
        $PsObject=New-Object -TypeName psobject
        $PsObject | Add-Member -MemberType NoteProperty -Name SrvSysVersion -Value $SrvSysVer
        $PsObject | Add-Member -MemberType NoteProperty -Name Smb1ProtocolDisabled -Value $smb1ProtocolDisabled
        $PsObject | Add-Member -MemberType NoteProperty -Name Status -Value $Status
        $PsObject
    } Catch {
        Write-Error -Message $_
    }
}

Function MeltdownSpectreStatus {
    try {
        $HotfixEnabled=$False
        $HotfixInstalled=$false
        $kvaShadowRequired=$true
        If ($Win32_Processor -is [array]) {$Win32_Processor = $Win32_Processor[0]}
        $manufacturer = $Win32_Processor.Manufacturer
        If ($manufacturer -eq 'AuthenticAMD') {
            $kvaShadowRequired = $false
        } ElseIf ($manufacturer -eq 'GenuineIntel') {
            $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
            $result = $regex.Match($cpu.Description)
            If ($result.Success) {
                $family   = [uint32]$result.Groups[1].Value
                $model    = [uint32]$result.Groups[2].Value
                $stepping = [uint32]$result.Groups[3].Value
                If (($family -eq 0x6) -and (($model -eq 0x1c) -or ($model -eq 0x26) -or ($model -eq 0x27) -or ($model -eq 0x36) -or ($model -eq 0x35))) {$kvaShadowRequired = $false}
            }
        } Else {
            $kvaShadowRequired="Unsupported processor $manufacturer"
        }
        $AntivirusUpdatedKey         = RegGetValue -key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -Value 'cadca5fe-87d3-4b96-b7fb-a231484277cc' -GetValue GetDWORDValue -ErrorAction SilentlyContinue
        If ($AntivirusUpdatedKey -eq 0) {$AntivirusUpdatedKeyIsPresent = $true} Else {$AntivirusUpdatedKeyIsPresent = $False}
        $FeatureSettingsOverride     = RegGetValue -key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Value 'FeatureSettingsOverride' -GetValue GetDWORDValue -ErrorAction SilentlyContinue 
        $FeatureSettingsOverrideMask = RegGetValue -key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Value 'FeatureSettingsOverrideMask' -GetValue GetDWORDValue -ErrorAction SilentlyContinue   
        If ($FeatureSettingsOverride -eq 3) {$HotfixEnabled = $False} ElseIf($FeatureSettingsOverride -eq 0) {$HotfixEnabled = $true}
        If ($Win32_OperatingSystem.ProductType -eq 1) {
            If ($null -eq $FeatureSettingsOverride -and $null -eq $FeatureSettingsOverrideMask) {$HotfixEnabled = $true}
        } Else {
            If ($null -eq $FeatureSettingsOverride -and $null -eq $FeatureSettingsOverrideMask) {$HotfixEnabled = $False}
        }
        if ($Protocol -eq 'Dcom') {
            Write-Warning -Message "$Computername The information received with the help of Dcom protocol may be incorrect. Use the protocol Wsman to determine MeltdownSpectreStatus"
            $HotfixArray = @(
                'KB4056892',
                'KB4056891',
                'KB4056890',
                'KB4056888',
                'KB4056893',
                'KB4056894',
                'KB4056897'
            )
            $Kb = $Win32_QuickFixEngineering | Where-Object {$HotfixArray -eq $_.HotFixID}
            If ($Kb) {$HotfixInstalled = $true} Else {$HotfixInstalled = $False}
        } Else {
            $NtQSIDefinition = @'
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength);
'@
            $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru
            [IntPtr]$systemInformationPtr    = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
            [IntPtr]$returnLengthPtr         = [Runtime.InteropServices.Marshal]::AllocHGlobal(4)
            [uint32]$systemInformationClass  = 201
            [uint32]$systemInformationLength = 4
            $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)
            if ($retval -eq 0) {
                [uint32]$scfBpbEnabled              = 0x01
                [uint32]$scfBpbDisabledSystemPolicy = 0x02
                [uint32]$flags = [uint32][Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)
                $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)
                $HotfixEnabled = (($flags -band $scfBpbDisabledSystemPolicy) -eq 0)
                $HotfixInstalled = $true
            }
            If (!$HotfixEnabled) {$HotfixEnabled = $False}
        }
        $PsObject = New-Object -TypeName Psobject
        $PsObject | Add-Member -MemberType NoteProperty -Name CpuIsVulnerable -Value $kvaShadowRequired
        $PsObject | Add-Member -MemberType NoteProperty -Name FixInstalled -Value $HotfixInstalled
        $PsObject | Add-Member -MemberType NoteProperty -Name FixEnabled -Value $HotfixEnabled
        $PsObject | Add-Member -MemberType NoteProperty -Name AntivUpKeyIsPresent -Value $AntivirusUpdatedKeyIsPresent
        if ($HotfixInstalled -and $HotfixEnabled) {
            $status='Patched'
        } elseif($HotfixInstalled -and !$HotfixEnabled) {
            $status='DisabledBySystemPolicy'
        } elseif(!$kvaShadowRequired) {
            $status='NotRequired'
        } else {
            $status='NotPatched'
        }
        $PsObject | Add-Member -MemberType NoteProperty -Name Status -Value $Status
        $PsObject
    } catch {
        Write-Error -Message $_
    }
}

Function Systeminfo {
    <#
    .SYNOPSIS
        Very fast displays system information on a local or remote computer.
    .DESCRIPTION
        The function uses WMI to collect information related to the characteristics of the computer
        The function uses multithreading. Multithreading is implemented through powershell runspace and PsJob
        The function allows you to quickly get the system information of a large number of computers on the network
        After executing, two variables are created: 
        $Result-contains successful queries, 
        $ErrorResult-contains computers that have errors.
    .PARAMETER ProcessFor
        This parameter determines the maximum number of computers for which WMI operations that can be executed simultaneously.
        By default, the value of this parameter is 50.
    .PARAMETER JobTimeout
        Specifies the amount of time that the function waits for a response from the wmi job or runspace job.
        By default, the value of this parameter is 120 seconds.
    .PARAMETER Protocol
        Defines the connection protocol to remote machine
        By default DCOM protocol
    .PARAMETER AppendToResult
        Adds the output to the $Result global variable. Without this parameter, $Result global variable replaces.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user. Type a user n
        ame, such as "User01", "Domain01\User01", or User@domain01.com. Or, enter a PSCredential object, such as an object t
        hat is returned by the Get-Credential cmdlet. When you type a user name, you are prompted for a password.
    .EXAMPLE
        Get-SystemInfo
        ComputerName     : Localhost
        OsCaption        : Майкрософт Windows 10 Pro
        OsArchitecture   : 64-разрядная
        OsUpTime         : 10:1:17:41
        OsLoggedInUser   : Domain\Username
        CPUName          : Intel(R) Core(TM) i3-2105 CPU @ 3.10GHz
        MotherboardModel : H61M-S1
        DeviceModel      : To be filled by O.E.M.
        MemoryTotal      : 4,0Gb
        MemoryModules    :
                           Capacity MemoryType Speed Manufacturer PartNumber
                           -------- ---------- ----- ------------ ----------
                           2Gb      DDR3       1333  Kingston     99U5595-005.A00LF
                           2Gb      DDR3       1333  Kingston     99U5595-005.A00LF
        HddDevices       :
                           Size  InterfaceType Model                           SmartStatus
                           ----  ------------- -----                           --------------
                           112Gb IDE           KINGSTON SHFS37A120G ATA Device ОК
                           149Gb IDE           ST3160813AS ATA Device          OK
        VideoModel       : Intel(R) HD Graphics 3000
        MonitorName      : E2042
        CdRom            : TSSTcorp CDDVDW SH-222BB
        This command get the system information on the local computer.
    .EXAMPLE
        Get-SystemInfo -Computername comp1,comp2,comp3
        This command receives system information from computers comp1, comp2, comp3. By default, the current account must be a member of the Administrators group on the
        remote computer.
    .EXAMPLE
        1..254 | foreach {"192.168.1.$_"} | Get-SystemInfo -Properties OsCaption,OSArchitecture,OsInstallDate -Credential Domain01\administrator01 | Out-GridView
        Get OsCaption, OSArchitecture, OsInstallDate from the computers that are in the 192.168.1.0/24 network and sends them to a grid view window. This command uses 
        the Credential parameter. The value of the Credential parameter is a user account name. The user is prompted for a password.
    .EXAMPLE
        Get-ADComputer -Filter * | Get-SystemInfo -Cpu -Motherboard -Memory -Properties OsVersion,OsProductKey -ProcessFor 100 -JobTimeOut 30
        Get CPU, Motherboard, Memory and OsVersion, OsProductKey information from all domain computers. The module activedirectory must be installed and loaded. 
        This command uses -ProcessFor and JobTimeOut parameter.
    .EXAMPLE 
        Get-ADComputer -Filter * | Get-SystemInfo -Protocol WSMAN
        This command gets system information from all domain computers. Wsman protocol is used for connection
        If errors occur, such as timeout expired  or other errors.
        After some time, you can repeat the command for computers that have had errors.To do this, you need to use the variable $ErrorResult and -AppendToResult parameter to add the result to a variable $Result. 
        PS C:\>$ErrorResult | Get-SystemInfo -Protocol WSMAN -AppendToResult
    .EXAMPLE
        Get-Content -Path C:\Computers.txt | Get-SystemInfo -Properties MemoryTotal,OsLoggedInUser -WarningAction SilentlyContinue | Where-Object {$_.memorytotal -lt 1.5gb}
        This command gets computers that have a RAM size less than 1.5 gb. List of computers is taken from the file C:\Computers.txt. This command use parameter -WarningAction SilentlyContinue to ignore warning.
    .EXAMPLE
        Get-Content -Path C:\Computers.txt  | Get-SystemInfo -Properties OsLoggedInUser,HddSmart | Where-Object {$_.hddsmart.smartstatus -Match "Critical" -or $_.hddsmart.smartstatus -Match "Warning"}
        This command gets computers that have hard disk problems. List of computers is taken from the file C:\Computers.txt
    .EXAMPLE
        Get-ADComputer -Filter * | Get-SystemInfo -Properties OsUpTime -JobTimeOut 30 | Where-Object {$_.OsUpTime -gt $(New-TimeSpan -Days 1)}
        This command gets computers which have uptime is more than 1 day. The module activedirectory must be installed and loaded
    .EXAMPLE
        Get-ADComputer -filter * | Get-SystemInfo -SoftwareList -JobTimeOut 240 | foreach {$_.SoftwareList} | Where-Object {$_.AppName -match "Google Chrome"} | Out-GridView
        This command gets computers with google chrome browser installed. The module activedirectory must be installed and loaded
    .EXAMPLE
        $Computers=Get-Content -Path C:\Computers.txt
        Get-SystemInfo -Computername $Computers | ConvertTo-Html -Head "SystemInformation" | Out-File -FilePath C:\report.html
        This command create html report
    .NOTES
        Author: SAGSA
        https://github.com/SAGSA/SystemInfo
        Requires: Powershell 2.0
    #>
    Function Get-SystemInfo {
        Param (
            [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][Alias('CN','Computername','DnsHostname','PsComputerName')][string[]]$Name=$Env:COMPUTERNAME,          
            [switch]$OsInfo,
            [switch]$Cpu,
            [switch]$Motherboard,
            [switch]$Memory,
            [switch]$HDD,
            [switch]$Video,
            [switch]$Monitor,
            [switch]$NetworkAdapter,
            [switch]$PrinterInfo,
            [switch]$UsbDevices,
            [switch]$SoftwareList,
            [switch]$CheckVulnerabilities,
            [Management.Automation.Remoting.PSSessionOption]$PSSessionOption,
            $Credential,
            [ValidateSet('Dcom','Wsman')]$Protocol='Dcom',
            [Alias('ThrottleLimit')][ValidateRange(1,500)][int]$ProcessFor=50,
            [ValidateRange(1,500)][int]$MaxWmiJob=20,
            [Alias('Timeout')][ValidateRange(1,6000)][int]$JobTimeOut=120,
            [switch]$AppendToResult,
            [ValidateSet(
                '*',
                'OsVersion',
                'OSArchitecture',
                'OsCaption',
                'OsGuid',
                'OsLastUpdateDaysAgo',
                'OsInstallDate',
                'OsUpTime',
                'OsLoggedInUser',
                'OsTimeZone',
                'OsProductKey',
                'OsVolumeShadowCopy',
                'OsTenLatestHotfix',
                'OsUpdateAgentVersion',
                'OSRebootRequired',
                'OsAdministrators',
                'OsActivationStatus',
                'OsProfileList',
                'OsSRPSettings',
                'OsSrpLog',
                'SerialNumber',
                'ADSiteName',
                'MsOfficeInfo',
                'UserProxySettings',
                'NetFolderShortcuts',
                'NetMappedDrives',
                'PsVersion',
                'MemoryTotal',
                'MemoryFree',
                'MemoryModules',
                'MemoryModInsCount',
                'MemoryMaxIns',
                'MemorySlots',
                'ECCType',
                'MemoryAvailable',
                'Motherboard',
                'MotherboardModel',
                'DeviceModel',
                'Cdrom',
                'CdromMediatype',
                'HddDevices',
                'HDDSmart',
                'HddSmartStatus',
                'HddPartitions',
                'HddVolumes',
                'VideoModel',
                'VideoRam',
                'VideoProcessor',
                'CPUName',
                'CPUDescription',
                'CPUSocket',
                'MaxClockSpeed',
                'CPUCores',
                'CPULogicalCore',
                'CPULoad',
                'MonitorManuf',
                'MonitorPCode',
                'MonitorSN',
                'MonitorName',
                'MonitorYear',
                'NetPhysAdapCount',
                'NetworkAdapters',
                'NetworkAdaptersPowMan',
                'Printers',
                'IsPrintServer',
                'UsbConPrOnline',
                'UsbDevices',
                'SoftwareList',
                'MeltdownSpectreStatus',
                'EternalBlueStatus',
                'AntivirusStatus',
                'SkypeInfo',
                'GoogleChromeInfo',
                'SysmonInfo',
                'OsKernelPowerFailCount',
                'MseLastUpdateDate'
            )] 
            [string[]]$Properties
        )
        Begin {
            $TestAdmin               = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $([Security.Principal.WindowsIdentity]::GetCurrent())
            $IsAdmin                 = $TestAdmin.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
            Write-Verbose -Message "IsAdmin $IsAdmin"
            $CurrentExecutionPolicy  = Get-ExecutionPolicy
            $ExecutionPolicyChanged  = $false
            $RequiredExecutionPolicy = 'Unrestricted','RemoteSigned'
            If (!($RequiredExecutionPolicy -eq $CurrentExecutionPolicy)) {
                Write-Verbose -Message 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force'
                Try {
                    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -Confirm:$false 
                    If ($?) {$ExecutionPolicyChanged=$true} Else {Write-Error -Message 'Formatting objects does not work. Run the command Set-ExecutionPolicy -ExecutionPolicy RemoteSigned and retry now' -ErrorAction Stop}
                } Catch {
                    Write-Error -Message "RequiredExecutionPolicy $RequiredExecutionPolicy" -ErrorAction Stop
                }
            }

            #LoadFunctions
            #####################################################################################################
            <#
            $FunctionFolderName = 'Function'
            $LoadScripts        = @(
                & {functionconfig},
                & {ParseParam},
                & {CreateResult},
                & {FormatObject},
                & {GetHddSmart},
                & {wmi},
                & {Registry},
                & {CreateErrorObject},
                & {PsJob},
                & {RunspaceJob},
                & {GetUserProfile},
                & {GetSmBiosStruct},
                & {GetInstalledSoftware}
            )
            $LoadScripts | ForEach-Object {
                .(Join-Path -Path $PSScriptRoot -ChildPath $_)
                If (!$?) {Break}
            }
            #>
            #####################################################################################################
            $BeginFunction = Get-Date
            If ($PSCmdlet.MyInvocation.BoundParameters['Credential']) {If (!($Credential.gettype().name -eq 'PSCredential')) {$Credential = Get-Credential -Credential $Credential}}
            If (!($PSCmdlet.MyInvocation.BoundParameters['PSSessionOption']) -and $Protocol -eq 'Wsman') {
                #Default PSSessionOption
                Write-Verbose -Message 'New-PSSessionOption -NoMachineProfile'
                $PSSessionOption = New-PSSessionOption -NoMachineProfile  
            }
            #Clear Old Job
            Write-Verbose -Message 'Clear old Job'
            Get-Job | Where-Object {$_.state -ne 'Running'} | Remove-Job -Force
            #Collection all Properties
            [string[]]$AllPropertiesSwitch+=$PSCmdlet.MyInvocation.BoundParameters.keys | ForEach-Object {If ($PSCmdlet.MyInvocation.BoundParameters[$_].ispresent -and !($ExcludeParam -eq $_)) {$SwitchConfig[$_]}}
            If ($Null -eq $AllPropertiesSwitch -and $null -eq $Properties) {$AllPropertiesSwitch = $DefaultInfoConfig}
            $AllProperties += $AllPropertiesSwitch + $Properties
            $AllProperties  = $AllProperties | Select-Object -Unique
            If ($AllProperties -match '\*') {
                Write-Verbose -Message "Property: $($FunctionConfig.Keys)"
                $AllProperties=$FunctionConfig.Keys -ne 'RegistryValue'
            } Else {
                Write-Verbose -Message "Property: $AllProperties"
            }
            #Parse FunctionConfig
            $PropertyParams = $AllProperties | ParseFunctionConfig -FunctionConfig $FunctionConfig -Protocol $Protocol 
            $Propertyparams.Keys | ForEach-Object {$PropertyParams[$_] | Where-Object {$_.script}} | ForEach-Object {
                $ScriptTmp  = $_
                $ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "scripts\$($ScriptTmp.script)" 
                $Script     = Get-Content -Path $ScriptPath -ErrorAction Stop | Out-String 
                If ((Split-Path -Path $ScriptPath) -match '.+\\(.+)') {
                    $RootFoolder=$Matches[1]
                    $FunctionName='FunctInf'+$RootFoolder+$((Split-Path -Path $ScriptPath -Leaf) -replace '\.ps1','')
                } Else {
                    Write-Error -Message "$FunctionProperty incorrect path" -ErrorAction Stop
                }
                [void](New-Item -Path function: -Name $FunctionName -Value $Script -ErrorAction Stop)
                $ScriptTmp | Add-Member -MemberType NoteProperty -Name Function -Value $FunctionName
            }
            #Create wmi param
            $WmiParamArray               = CreateWmiObject -PropertyParams $PropertyParams -ManualNamespace $ManualNamespace
            $computers                   = @()
            $MainJobs                    = New-Object -TypeName System.Collections.ArrayList
            $GetWmicompletedForComputers = New-Object -TypeName System.Collections.ArrayList
            $HashtableRunspace           = @()
            $Global:ErrorResult          = @()
            $UpdateFormatData            = $true
            If ($PSBoundParameters['AppendToResult'].IsPresent) {
                If (!(Get-Variable -Name Result -Scope Global)) {
                    $Global:Result = @()
                } ElseIf ($null -eq (Get-Variable -Name Result -Scope Global -ValueOnly).Count) {
                    $OldRes         = $Global:Result
                    $Global:Result  = @()
                    $Global:Result += $OldRes
                }
            } Else {
                $Global:Result=@()
            }
            [ScriptBlock]$SbLocalHost = {
                $HashtableWMi = @{}
                $WmiParamArray | ForEach-Object {
                    $WmiParam = $_
                    If ($WmiParam.Name) {
                        If (!($HashtableWMi.ContainsKey($($WmiParam.Name)))) {
                            #$HashtableWMi[$($WmiParam.Name)]
                            $HashtableWMi.Add($WmiParam.Name,$null)
                        }
                    }
                }
                $jobs = New-Object -TypeName System.Collections.ArrayList
                StartWmiJob -ComputerName $Computername -WmiParamArray $WmiParamArray
                Do {GetWmiJob} While ($jobs.Count -ne 0)
                CreateResult  
            }
            $CountComputers                             = 0
            [Array]$ExportFunctionsName                 = 'StartWmiJob','GetWmiJob','CreateResult'
            [Array]$PropertyReqHddSmartFunctions        = 'HddDevices','HddSmartStatus','HddSmart'
            [Array]$PropertyReqGetUserProfileFunctions  = 'NetFolderShortcuts','OsProfileList','NetMappedDrives'
            [Array]$PropertyReqGetSmBiosStructFunctions = 'MemoryModules'
            [Array]$PropertyReqGetInstalledSoftware     = 'SoftwareList','SkypeInfo','GoogleChromeInfo'
            #$PropertyReqRegistryFunctions="OsProductKey","SoftwareList","MeltdownSpectreStatus","EternalBlueStatus"
            $WmiParamArray | ForEach-Object {
                If ($PropertyReqHddSmartFunctions -eq $_.property)       {If (!($ExportFunctionsName -eq 'GetHddSmart'))         {$ExportFunctionsName += 'GetHddSmart'}}
                If ($PropertyReqGetUserProfileFunctions -eq $_.property) {If (!($ExportFunctionsName -eq 'GetUserProfile'))      {$ExportFunctionsName += 'GetUserProfile'}}
                If ($PropertyReqGetSmBiosStructFunctions -eq $_.property){If (!($ExportFunctionsName -eq 'GetSmBiosStruct'))     {$ExportFunctionsName += 'GetSmBiosStruct'}}
                If ($PropertyReqGetInstalledSoftware -eq $_.property)    {If (!($ExportFunctionsName -eq 'GetInstalledSoftware')){$ExportFunctionsName += 'GetInstalledSoftware'}}
                If ($_.class -eq 'StdRegProv'){If (!($ExportFunctionsName -eq 'RegGetValue')){$ExportFunctionsName += 'RegGetValue','RegEnumKey'}}
            }
            Write-Verbose -Message "$protocol protocol"
            If ($Protocol -eq 'DCOM' -and $PSCmdlet.MyInvocation.InvocationName -ne $PSCmdlet.MyInvocation.line) {
                $ExportFunctionsName += 'StartWmi'
                #$RunspaceImportVariables="WmiParamArray","Credential","Protocol"    
                $SessionState         = [initialsessionstate]::CreateDefault()
                Get-Command -CommandType Function -Name $ExportFunctionsName | ForEach-Object {
                    $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.name, $_.Definition         
                    Write-Verbose -Message "Add Function $($_.name)"
                    $SessionState.Commands.Add($SessionStateFunction)
                }
                Get-Command -CommandType Function -Name FunctInf* | ForEach-Object {
                    $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.name, $_.Definition         
                    Write-Verbose -Message "Add script Function $($_.name)"
                    $SessionState.Commands.Add($SessionStateFunction)
                }
                $SessionStateVariables = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'WmiParamArray', $WmiParamArray, 'WmiParamArray'
                $SessionState.Variables.Add($SessionStateVariables)       
                $SessionStateVariables = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'Credential', $Credential, 'Credential'
                $SessionState.Variables.Add($SessionStateVariables) 
                $SessionStateVariables = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'VerbosePreference', $VerbosePreference, 'VerbosePreference'
                $SessionState.Variables.Add($SessionStateVariables)
                $SessionStateVariables = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'Protocol', $Protocol, 'Protocol'
                $SessionState.Variables.Add($SessionStateVariables)   
                $RunspacePool = [runspacefactory]::CreateRunspacePool(1,$ProcessFor,$SessionState,$Host)
                Write-Verbose -Message 'Open Runspace'
                $RunspacePool.Open()
            } Else {
                $VerboseStatus              = $VerbosePreference
                $ExportFunctions            = @()
                $ExportFunctionsName | ForEach-Object {$ExportFunctions += Get-ChildItem -Path function:$_}
                $ExportScriptFunction       = @()
                $ExportScriptFunction       = Get-ChildItem -Path function:\FunctInf*
                [Array]$ExportVariablesName = 'WmiParamArray','MaxWmiJob','VerboseStatus','Protocol'
                $ExportVariables            = @()
                $ExportVariablesName | ForEach-Object {$ExportVariables += Get-Variable -Name $_}
                $HashtableParam=@{
                    ImportFunctions      = $ExportFunctions
                    ImportScriptFunction = $ExportScriptFunction
                    ImportVariables      = $ExportVariables
                }
            }
        }
        Process {
            $computers = @()
            If ($null -ne $Name) {$computers += $Name}
            $computers | ForEach-Object {
                $ComputerName = $_
                $CountComputers++
                $AllProperties | ForEach-Object {
                    If (!$IsAdmin) {
                        If ($LocalComputer -eq $ComputerName) {
                            If ($AdminRequired -eq $_) {
                                Write-Warning -Message "$ComputerName Information may be incomplete. The $_ property requires administrator privileges. Close powershell and run as administrator"
                            }
                        }
                    }
                }
                If ($LocalComputer -eq $ComputerName) {
                    Write-Verbose -Message "$Computername running local"
                    & $SbLocalHost  | OutResult        
                } ElseIf ($Protocol -eq 'Wsman') {
                    #Protocol WSMAN
                    If ($MainJobs.count -ge $ProcessFor) {
                        Do {
                            $repeat = $true
                            GetPsJob | OutResult
                            If ($MainJobs.Count -lt $ProcessFor) {$repeat = $false} Else {Start-Sleep -Milliseconds 20}
                        } While ($repeat)
                    }
                    $NewJob = StartPsJob -ComputerName $ComputerName -ScriptBlock $InvokeScriptBlock -ArgumentList $HashtableParam,$ComputerName -Credential $Credential -PSSessionOption $PSSessionOption
                    If ($NewJob) {[void]$MainJobs.Add($NewJob)}
                } Else {
                    #Protocol DCOM
                    If ($MainJobs.count -ge $ProcessFor) {
                        Do {
                            $repeat = $true
                            GetRunspaceJob | OutResult
                            If ($MainJobs.Count -lt $ProcessFor) {$repeat = $false} else {Start-Sleep -Milliseconds 20}
                        } While ($repeat)
                    }
                    Write-Verbose -Message "$Computername StartRunspaceJob"
                    $RunspaceJob = StartRunspaceJob -Computername $Computername -RunspacePool $RunspacePool
                    If ($?) {[void]$MainJobs.Add($RunspaceJob)}
                }
            }
        }
        End {
            If ($MainJobs.Count -eq 1 -and $LocalComputer -eq $MainJobs[0].location) {
                Do {GetPsJob | OutResult} While ($MainJobs.Count -ne 0)
            } ElseIf ($Protocol -eq 'Wsman' -and $MainJobs.Count -ne 0) {
                Do {GetPsJob | OutResult} While ($MainJobs.Count -ne 0)  
            } ElseIf ($mainjobs.Count -ne 0) {
                Do {GetRunspaceJob | OutResult} while($MainJobs.Count -ne 0)
                [Scriptblock]$CloseRunspacePool = {
                    Param ($RunspacePool)
                    $RunspacePool.Dispose()
                    $RunspacePool.Close()
                }
                Write-Verbose -Message 'RunspacePool close'
                $PowerShell = [powershell]::Create()
                [void]$PowerShell.AddScript($CloseRunspacePool)
                [void]$PowerShell.AddParameter('RunspacePool',$RunspacePool)
                $State = $PowerShell.BeginInvoke() 
            }
            $Global:ErrorResult = $Global:ErrorResult | Sort-Object -Property Warning
            If ($null -eq $Global:ErrorResult) {$ErrResCount = 0} ElseIf ($null -eq $Global:ErrorResult.count) {$ErrResCount = 1} Else {$ErrResCount = $Global:ErrorResult.Count}
            $ResultCount=$Global:Result.Count
            If ($Global:Result.Count -eq 1) {$Global:Result=$Global:Result | ForEach-Object {$_}}
            If ($ExecutionPolicyChanged) {Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy $CurrentExecutionPolicy -Force -Confirm:$false -ErrorAction SilentlyContinue}
            #Write-Verbose "Clear all failed wmi job"
            #Get-Job | Where-Object {$_.State -eq "Failed"} | Remove-Job -Force
            $RunnningTime = (New-TimeSpan -Start $BeginFunction).TotalSeconds
            If ($CountComputers -gt 1) {
                Write-Verbose  -Message "Function running  $RunnningTime seconds" -Verbose
                Write-Verbose  -Message "Speed             $([math]::Round($($CountComputers/$RunnningTime),2)) cps" -Verbose
                Write-Verbose  -Message "Total Computers   $CountComputers" -Verbose
                Write-Verbose  -Message "Success           $ResultCount" -Verbose
                Write-Verbose  -Message "Errors            $ErrResCount" -Verbose
            }
        }
    }
}
