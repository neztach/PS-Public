Import-Module -Name PSWinReportingV2

#region mail vars
$SMTPServer = 'crrc-mail01.comanche.local'
$from       = 'ADEventReport@comanchemail.com' 
#$to         = 'jamess@comanchemail.com','dereka@comanchemail.com','shawnb@comanchemail.com'
$to         = 'jamess@comanchemail.com'#,'dereka@comanchemail.com','Michael.Weaver@comanchemail.com','gregp@comanchemail.com'
$subject    = 'Daily Report'
#endregion mail vars

#region htmlregion
$html             = "<body style=`"font-family: Lucida Sans Unicode, Lucida Grande, Sans-Serif; font-size: 12pt;`">`n"
$htmlEnd          = "</body>`n"
$TableStart       = "  <table style = `"font-family: Lucida Sans Unicode, Lucida Grande, Sans-Serif; font-size: 12pt; background: #fff; margin: 10px; border-collapse: collapse; text-align: left;`">`n"
$TableEnd         = "  </table><br />`n"
$HeaderRowStart   = "    <thead>`n      <tr>`n        <th style = `"font-size: 14px; font-weight: normal; color: #039; padding: 0px 5px; border-bottom: 2px solid #6678b1;`">"
$HeaderRowBetween = "</th>`n        <th style = `"font-size: 14px; font-weight: normal; color: #039; padding: 0px 5px; border-bottom: 2px solid #6678b1;`">"
$HeaderRowEnd     = "</th>`n      </tr>`n    </thead>`n"
$TableBodyStart   = "    <tbody>`n"
$TableBodyEnd     = "    </tbody>`n"
$TableRowStart    = "      <tr>`n        <td style = `"font-size: 12px; border-bottom: 1px solid #ccc; color: #669; padding: 0px 8px;`">"
$CellBetween      = "</td>`n        <td style = `"font-size: 12px; border-bottom: 1px solid #ccc; color: #669; padding: 0px 8px;`">"
$TableRowEnd      = "</td>`n      </tr>`n"
#endregion htmlregion

#region Function
Function Get-ThisTable{
    param (
        [Parameter(Mandatory,HelpMessage='Event')]$Event,
        [Parameter(Mandatory,HelpMessage='Header')][string]$Header
    )
    $tempeventheads = $Event | 
                      Get-Member -MemberType 'NoteProperty' | 
                      Where-Object {($_.Definition).split('=')[1] -notlike ''} | 
                      Where-Object {$_.Name -notlike '*Domain Controller*'} | 
                      Where-Object {$_.Name -notlike '*Record ID*'} | 
                      Select-Object -ExpandProperty 'Name'
    $htmltable  = "  <strong>$($Header)</strong>`n"
    ### Start Table - Start Header
    $htmltable += $TableStart + $HeaderRowStart
    For ($i=0; $i -lt $tempeventheads.count; $i++){
        $htmltable     += $tempeventheads[$i]
        If ($i -le ($tempeventheads.count - 2)){
            $htmltable += $HeaderRowBetween
        } Else {
            $htmltable += $HeaderRowEnd
        }
    }
    $htmltable += $TableBodyStart
    Foreach ($ADCCC in $Event){
        $htmltable += $TableRowStart
        For ($j=0; $j -lt $tempeventheads.count; $j++){
            $field          = $($tempeventheads[$j])
            $htmltable     += $ADCCC.$field
            If ($j -le ($tempeventheads.count - 2)){
                $htmltable += $CellBetween
            } Else {
                $htmltable += $TableRowEnd
            }
        }
    }
    $htmltable += $TableBodyEnd + $TableEnd
    Return $htmltable
}
#endregion Function


################################### Borrowed ###############################
$Options       = [ordered]@{
    RemoveDuplicates     = @{
        Enabled    = $true # when multiple sources are used it's normal for duplicates to occur. This cleans it up.
        Properties = 'RecordID', 'Computer'
    }
}

$Target        = [ordered]@{
    DomainControllers = [ordered]@{
        Enabled = $true
    }
}

$Yesterday     = [DateTime]::Today.AddDays(-1).AddHours(7)
$Today         = [DateTime]::Today.AddHours(7)

$Times         = @{
    CustomDate           = @{
        Enabled  = $true
        DateFrom = $Yesterday
        DateTo   = $Today
    }
}

## Define reports
$DefinitionsAD = [ordered]@{
    ADUserChanges                       = @{
        Enabled   = $true
        Events    = @{
            Enabled     = $true
            Events      = 4720, 4738
            LogName     = 'Security'
            Fields      = [ordered]@{
                'Action'              = 'Action'
                'ObjectAffected'      = 'User Affected'
                'SamAccountName'      = 'SamAccountName'
                'DisplayName'         = 'DisplayName'
                'UserPrincipalName'   = 'UserPrincipalName'
                'PasswordLastSet'     = 'Password Last Set'
                'Who'                 = 'Who'
                'Date'                = 'When'
                # Common Fields
                'ID'                  = 'Event ID'
                'RecordID'            = 'Record ID'
                'GatheredFrom'        = 'Gathered From'
                'GatheredLogName'     = 'Gathered LogName'
            }
            Ignore      = @{
                # Cleanup Anonymous LOGON (usually related to password events) # https://social.technet.microsoft.com/Forums/en-US/5b2a93f7-7101-43c1-ab53-3a51b2e05693/eventid-4738-user-account-was-changed-by-anonymous?forum=winserverDS
                SubjectUserName = 'ANONYMOUS LOGON'
                Who             = 'NT AUTHORITY\ANONYMOUS LOGON'
                # Test value
                #ProfilePath     = 'C*'
            }
            Functions   = @{
                'ProfilePath'        = 'Convert-UAC'
                'OldUacValue'        = 'Remove-WhiteSpace', 'Convert-UAC'
                'NewUacValue'        = 'Remove-WhiteSpace', 'Convert-UAC'
                'UserAccountControl' = 'Remove-WhiteSpace', 'Split-OnSpace', 'Convert-UAC'
            }
            IgnoreWords = @{
                #'Profile Path' = 'TEMP*'
            }
            SortBy      = 'When'
        }
    }           # 4720,4738
    ADUserChangesDetailed               = [ordered]@{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 5136, 5137, 5141
            LogName     = 'Security'
            Filter      = @{
                'ObjectClass' = 'user'
            }
            Functions   = @{
                'OperationType' = 'ConvertFrom-OperationType'
            }
            Fields      = [ordered] @{
                'Action'                   = 'Action'
                'OperationType'            = 'Action Detail'
                'Who'                      = 'Who'
                'Date'                     = 'When'
                'ObjectDN'                 = 'User Object'
                'AttributeLDAPDisplayName' = 'Field Changed'
                'AttributeValue'           = 'Field Value'
                # Common Fields
                'RecordID'                 = 'Record ID'
                'ID'                       = 'Event ID'
                'GatheredFrom'             = 'Gathered From'
            }
            SortBy      = 'Record ID'
            Descending  = $false
            IgnoreWords = @{
                'Who' = '*$'
            }
        }
    } # 5136,5137,5141
    ADComputerChangesDetailed           = [ordered]@{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 5136, 5137, 5141
            LogName     = 'Security'
            Filter      = @{
                'ObjectClass' = 'computer'
            }
            Functions   = @{
                'OperationType' = 'ConvertFrom-OperationType'
            }
            Fields      = [ordered] @{
                'Action'                   = 'Action'
                'OperationType'            = 'Action Detail'
                'Who'                      = 'Who'
                'Date'                     = 'When'
                'ObjectDN'                 = 'Computer Object'
                'AttributeLDAPDisplayName' = 'Field Changed'
                'AttributeValue'           = 'Field Value'
                # Common Fields
                'RecordID'                 = 'Record ID'
                'ID'                       = 'Event ID'
                'GatheredFrom'             = 'Gathered From'
            }
            Ignore      = @{
                # Cleanup Anonymous LOGON (usually related to password events) # https://social.technet.microsoft.com/Forums/en-US/5b2a93f7-7101-43c1-ab53-3a51b2e05693/eventid-4738-user-account-was-changed-by-anonymous?forum=winserverDS
                'Who' = '$'
                # Test value
                #ProfilePath     = 'C*'
            }
            SortBy      = 'Record ID'
            Descending  = $false
            IgnoreWords = @{
                'Who' = '*$'
            }
        }
    } # 5136,5137,5141
    ADOrganizationalUnitChangesDetailed = [ordered]@{
        Enabled        = $true
        OUEventsModify = @{
            Enabled          = $true
            Events           = 5136, 5137, 5139, 5141
            LogName          = 'Security'
            Filter           = @{
                'ObjectClass' = 'organizationalUnit'
            }
            Functions        = @{
                'OperationType' = 'ConvertFrom-OperationType'
            }
            Fields           = [ordered] @{
                'Computer'                 = 'Domain Controller'
                'Action'                   = 'Action'
                'OperationType'            = 'Action Detail'
                'Who'                      = 'Who'
                'Date'                     = 'When'
                'ObjectDN'                 = 'Organizational Unit'
                'AttributeLDAPDisplayName' = 'Field Changed'
                'AttributeValue'           = 'Field Value'
                # Common Fields
                'RecordID'                 = 'Record ID'
                'ID'                       = 'Event ID'
                'GatheredFrom'             = 'Gathered From'
                'GatheredLogName'          = 'Gathered LogName'
            }
            Overwrite        = @{
                'Action Detail#1' = 'Action', 'A directory service object was created.', 'Organizational Unit Created'
                'Action Detail#2' = 'Action', 'A directory service object was deleted.', 'Organizational Unit Deleted'
                'Action Detail#3' = 'Action', 'A directory service object was moved.', 'Organizational Unit Moved'
            }
            OverwriteByField = @{
                'Organizational Unit' = 'Action', 'A directory service object was moved.', 'OldObjectDN'
                #'Field Changed'       = 'Action', 'A directory service object was moved.', ''
                'Field Value'         = 'Action', 'A directory service object was moved.', 'NewObjectDN'
            }
            SortBy           = 'Record ID'
            Descending       = $false
            IgnoreWords      = @{}
        }
    } # 5136,5137,5139,5141
    ADUserStatus                        = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4722, 4725, 4767, 4723, 4724, 4726
            LogName     = 'Security'
            IgnoreWords = @{}
            Fields      = [ordered] @{
                'Action'          = 'Action'
                'Who'             = 'Who'
                'Date'            = 'When'
                'ObjectAffected'  = 'User Affected'
                # Common Fields
                'ID'              = 'Event ID'
                'RecordID'        = 'Record ID'
                'GatheredFrom'    = 'Gathered From'
            }
            SortBy      = 'When'
        }
    }           # 4722,4723,4724,4725,4726,4767
    ADUserLockouts                      = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4740
            LogName     = 'Security'
            IgnoreWords = @{}
            Fields      = [ordered] @{
                'Action'           = 'Action'
                'TargetDomainName' = 'Computer Lockout On'
                'ObjectAffected'   = 'User Affected'
                'Date'             = 'When'
                # Common Fields
                'ID'               = 'Event ID'
                'GatheredFrom'     = 'Gathered From'
                'GatheredLogName'  = 'Gathered LogName'
            }
            SortBy      = 'When'
        }
    }           # 4740
    ADUserUnlocked                      = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4767
            LogName     = 'Security'
            IgnoreWords = @{}
            Functions   = @{}
            Fields      = [ordered] @{
                'Action'           = 'Action'
                'TargetDomainName' = 'Computer Lockout On'
                'ObjectAffected'   = 'User Affected'
                'Who'              = 'Who'
                'Date'             = 'When'
                # Common Fields
                'ID'               = 'Event ID'
                'GatheredFrom'     = 'Gathered From'
                'GatheredLogName'  = 'Gathered LogName'
            }
            SortBy      = 'When'
        }
    }           # 4767
    ADComputerCreatedChanged            = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4741, 4742 # created, changed
            LogName     = 'Security'
            Ignore      = @{
                # Cleanup Anonymous LOGON (usually related to password events)
                # https://social.technet.microsoft.com/Forums/en-US/5b2a93f7-7101-43c1-ab53-3a51b2e05693/eventid-4738-user-account-was-changed-by-anonymous?forum=winserverDS
                SubjectUserName = 'ANONYMOUS LOGON'
            }
            Fields      = [ordered] @{
                'Action'              = 'Action'
                'ObjectAffected'      = 'Computer Affected'
                'PasswordLastSet'     = 'Password Last Set'
                'Who'                 = 'Who'
                'Date'                = 'When'
                # Common Fields
                'ID'                  = 'Event ID'
                'GatheredFrom'        = 'Gathered From'
                'GatheredLogName'     = 'Gathered LogName'
            }
            IgnoreWords = @{
                'Who' = 'NT AUTHORITY\ANONYMOUS LOGON'
            }
        }
    }           # 4741,4742
    ADComputerDeleted                   = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4743 # deleted
            LogName     = 'Security'
            IgnoreWords = @{}
            Fields      = [ordered] @{
                'Action'          = 'Action'
                'ObjectAffected'  = 'Computer Affected'
                'Who'             = 'Who'
                'Date'            = 'When'
                # Common Fields
                'ID'              = 'Event ID'
                'GatheredFrom'    = 'Gathered From'
            }
            SortBy      = 'When'
        }
    }           # 4743
    ADGroupMembershipChanges            = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4728, 4729, 4732, 4733, 4746, 4747, 4751, 4752, 4756, 4757, 4761, 4762, 4785, 4786, 4787, 4788
            LogName     = 'Security'
            IgnoreWords = @{
                'Who' = '*ANONYMOUS*'
            }
            Fields      = [ordered] @{
                'Action'              = 'Action'
                'TargetUserName'      = 'Group Name'
                'MemberNameWithoutCN' = 'Member Name'
                'Who'                 = 'Who'
                'Date'                = 'When'
                # Common Fields
                'ID'                  = 'Event ID'
                'RecordID'            = 'Record ID'
                'GatheredFrom'        = 'Gathered From'
            }
            SortBy      = 'When'
        }
    }           # 4728,4729,4732,4733,4746,4747,4751,4752,4756,4757,4761,4762,4785,4786,4787,4788
    ADGroupChanges                      = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4735, 4737, 4745, 4750, 4760, 4764, 4784, 4791
            LogName     = 'Security'
            IgnoreWords = @{
                'Who' = '*ANONYMOUS*'
            }
            Fields      = [ordered] @{
                'Action'          = 'Action'
                'TargetUserName'  = 'Group Name'
                'Who'             = 'Who'
                'Date'            = 'When'
                'GroupTypeChange' = 'Changed Group Type'
                'SamAccountName'  = 'Changed SamAccountName'
                'SidHistory'      = 'Changed SidHistory'
                # Common Fields
                'ID'              = 'Event ID'
                'RecordID'        = 'Record ID'
                'GatheredFrom'    = 'Gathered From'
            }
            SortBy      = 'When'
        }
    }           # 4735,4737,4745,4750,4760,4764,4784,4791
    ADGroupCreateDelete                 = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4727, 4730, 4731, 4734, 4744, 4748, 4749, 4753, 4754, 4758, 4759, 4763
            LogName     = 'Security'
            IgnoreWords = @{
                # 'Who' = '*ANONYMOUS*'
            }
            Fields      = [ordered] @{
                'Action'          = 'Action'
                'TargetUserName'  = 'Group Name'
                'Who'             = 'Who'
                'Date'            = 'When'
                # Common Fields
                'ID'              = 'Event ID'
                'RecordID'        = 'Record ID'
                'GatheredFrom'    = 'Gathered From'
            }
            SortBy      = 'When'
        }
    }           # 4727,4730,4731,4734,4744,4748,4749,4753,4754,4758,4759,4763
    ADGroupChangesDetailed              = [ordered]@{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 5136, 5137, 5141
            LogName     = 'Security'
            Filter      = @{
                # Filter is special
                # if there is just one object on the right side it will filter on that field
                # if there are more objects filter will pick all values on the right side and display them (using AND)
                'ObjectClass' = 'group'
            }
            Functions   = @{
                'OperationType' = 'ConvertFrom-OperationType'
            }
            Fields      = [ordered] @{
                'Action'                   = 'Action'
                'OperationType'            = 'Action Detail'
                'Who'                      = 'Who'
                'Date'                     = 'When'
                'ObjectDN'                 = 'Computer Object'
                'ObjectClass'              = 'ObjectClass'
                'AttributeLDAPDisplayName' = 'Field Changed'
                'AttributeValue'           = 'Field Value'
                # Common Fields
                'RecordID'                 = 'Record ID'
                'ID'                       = 'Event ID'
                'GatheredFrom'             = 'Gathered From'
            }
            SortBy      = 'Record ID'
            Descending  = $false
            IgnoreWords = @{

            }
        }
    } # 5136,5137,5141
    ADGroupPolicyChanges                = [ordered]@{
        Enabled                     = $true
        'Group Policy Name Changes' = @{
            Enabled     = $true
            Events      = 5136, 5137, 5141
            LogName     = 'Security'
            Filter      = @{
                # Filter is special, if there is just one object on the right side
                # If there are more objects filter will pick all values on the right side and display them as required
                'ObjectClass'              = 'groupPolicyContainer'
                #'OperationType'            = 'Value Added'
                'AttributeLDAPDisplayName' = $null, 'displayName' #, 'versionNumber'
            }
            Functions   = @{
                'OperationType' = 'ConvertFrom-OperationType'
            }
            Fields      = [ordered] @{
                'RecordID'                 = 'Record ID'
                'Action'                   = 'Action'
                'Who'                      = 'Who'
                'Date'                     = 'When'
                'ObjectDN'                 = 'ObjectDN'
                'ObjectGUID'               = 'ObjectGUID'
                'ObjectClass'              = 'ObjectClass'
                'AttributeLDAPDisplayName' = 'AttributeLDAPDisplayName'
                'AttributeValue'           = 'AttributeValue'
                'OperationType'            = 'OperationType'
                'OpCorrelationID'          = 'OperationCorelationID'
                'AppCorrelationID'         = 'OperationApplicationCorrelationID'
                'DSName'                   = 'DSName'
                'DSType'                   = 'DSType'
                'Task'                     = 'Task'
                'Version'                  = 'Version'
                # Common Fields
                'ID'                       = 'Event ID'
                'GatheredFrom'             = 'Gathered From'
            }

            SortBy      = 'Record ID'
            Descending  = $false
            IgnoreWords = @{

            }
        }  # 5136, 5137, 5141
        'Group Policy Edits'        = @{
            Enabled     = $true
            Events      = 5136, 5137, 5141
            LogName     = 'Security'
            Filter      = @{
                # Filter is special, if there is just one object on the right side
                # If there are more objects filter will pick all values on the right side and display them as required
                'ObjectClass'              = 'groupPolicyContainer'
                #'OperationType'            = 'Value Added'
                'AttributeLDAPDisplayName' = 'versionNumber'
            }
            Functions   = @{
                'OperationType' = 'ConvertFrom-OperationType'
            }
            Fields      = [ordered] @{
                'RecordID'                 = 'Record ID'
                'Action'                   = 'Action'
                'Who'                      = 'Who'
                'Date'                     = 'When'
                'ObjectDN'                 = 'ObjectDN'
                'ObjectGUID'               = 'ObjectGUID'
                'ObjectClass'              = 'ObjectClass'
                'AttributeLDAPDisplayName' = 'AttributeLDAPDisplayName'
                'AttributeValue'           = 'AttributeValue'
                'OperationType'            = 'OperationType'
                'OpCorrelationID'          = 'OperationCorelationID'
                'AppCorrelationID'         = 'OperationApplicationCorrelationID'
                'DSName'                   = 'DSName'
                'DSType'                   = 'DSType'
                'Task'                     = 'Task'
                'Version'                  = 'Version'
                # Common Fields
                'ID'                       = 'Event ID'
                'GatheredFrom'             = 'Gathered From'
            }
            SortBy      = 'Record ID'
            Descending  = $false
            IgnoreWords = @{
            }
        }  # 5136, 5137, 5141
        'Group Policy Links'        = @{
            Enabled     = $true
            Events      = 5136, 5137, 5141
            LogName     = 'Security'
            Filter      = @{
                # Filter is special, if there is just one object on the right side
                # If there are more objects filter will pick all values on the right side and display them as required
                'ObjectClass' = 'domainDNS'
                #'OperationType'            = 'Value Added'
                #'AttributeLDAPDisplayName' = 'versionNumber'
            }
            Functions   = @{
                'OperationType' = 'ConvertFrom-OperationType'
            }
            Fields      = [ordered] @{
                'RecordID'                 = 'Record ID'
                'Action'                   = 'Action'
                'Who'                      = 'Who'
                'Date'                     = 'When'
                'ObjectDN'                 = 'ObjectDN'
                'ObjectGUID'               = 'ObjectGUID'
                'ObjectClass'              = 'ObjectClass'
                'AttributeLDAPDisplayName' = 'AttributeLDAPDisplayName'
                'AttributeValue'           = 'AttributeValue'
                'OperationType'            = 'OperationType'
                'OpCorrelationID'          = 'OperationCorelationID'
                'AppCorrelationID'         = 'OperationApplicationCorrelationID'
                'DSName'                   = 'DSName'
                'DSType'                   = 'DSType'
                'Task'                     = 'Task'
                'Version'                  = 'Version'
                # Common Fields
                'ID'                       = 'Event ID'
                'GatheredFrom'             = 'Gathered From'
            }

            SortBy      = 'Record ID'
            Descending  = $false
            IgnoreWords = @{

            }
        }  # 5136, 5137, 5141
    } # 5136,5137,5141
}

#Start-WinReporting -Options $Options -Times $Times -Definitions $DefinitionsAD -Target $Target -Verbose

###########################################################################


$Reports    = @(
    'ADUserChanges'
    'ADUserChangesDetailed'
    'ADComputerChangesDetailed'
    'ADUserStatus'
    'ADUserLockouts'
    #ADUserLogon
    'ADUserUnlocked'
    'ADComputerCreatedChanged'
    'ADComputerDeleted'
    #'ADUserLogonKerberos'
    'ADGroupMembershipChanges'
    'ADGroupEnumeration'
    'ADGroupChanges'
    'ADGroupCreateDelete'
    'ADGroupChangesDetailed'
    'ADGroupPolicyChanges'
    'ADLogsClearedSecurity'
    'ADLogsClearedOther'
    #ADEventsReboots
)

$yesterday  = [DateTime]::Today.AddDays(-1).AddHours(7)
$today      = [DateTime]::Today.AddHours(7)
$ServerList = Get-WinADForestControllers | Select-Object -ExpandProperty HostName | ForEach-Object {$_.split('.')[0]}

$Events     = Find-Events -Report $Reports -DateFrom $yesterday -DateTo $today -Servers $ServerList
#$Events     = Find-Events -Options $Options -Definitions $DefinitionsAD -DateFrom $yesterday -DateTo $today -Servers $ServerList

#region Strings
$act = 'Action'
$whn = 'When'
$who = 'Who'
$evt = 'Event ID'
$cpa = 'Computer Affected'
$pls = 'Password Last Set'
$adt = 'Action Detail'
$fdc = 'Field Changed'
$fdv = 'Field Value'
$cpo = 'Computer Object'
$gpn = 'Group Name'
$mbn = 'Member Name'
$cgt = 'Changed Group Type'
$ojc = 'ObjectClass'
$usa = 'User Affected'
$uso = 'User Object'
$clo = 'Computer Lockout On'
$rpb = 'Reported By'
#endregion Strings

#region Computer Changes
$cChangeSel1  = @{Property = $act, $cpa, $evt, $pls, $whn, $who}
$cChangeSel2  = @{Property = $act, $cpa, $evt, $whn, $who}
$cChangeSel3  = @{Property = $act, $adt, $cpa, $evt, $fdc, $fdv, $whn, $who}
$cChangeSort1 = @{Property = $whn, $act, $cpa, $evt, $pls, $who}
$cChangeSort2 = @{Property = $whn, $act, $cpa, $evt, $who}
$cChangeSort3 = @{Property = $whn, $act, $adt, $cpo, $evt, $fdc, $fdv, $who}
Write-Host 'Compiling AD Computer Created Changed'
$utility    = $Events.ADComputerCreatedChanged | Select-Object @cChangeSel1 | Sort-Object @cChangeSort1 | Where-Object {$_.Who -notmatch 'NT AUTHORITY'}
If ($utility -ne $null){$ADComputerCreatedChanged = $Utility | Get-Unique -asString}

Write-Host 'Compiling AD Computer Deleted'
$utility    = $Events.ADComputerDeleted | Select-Object @cChangeSel2 | Sort-Object @cChangeSort2
If ($utility -ne $null){$ADComputerDeleted = $Utility | Get-Unique -asString}

Write-Host 'Compiling AD Computer Changes Detailed'
$utility    = $Events.ADComputerChangesDetailed | 
              Select-Object @cChangeSel3 | Sort-Object @cChangeSort3 | 
              Where-Object {$_.'Field Value' -notmatch 'WSMAN|TERMSRV|CmRcService|RestrictedKrbHost'} | 
              Where-Object {$_.Who -notmatch 'NT AUTHORITY'}
If ($utility -ne $null){$ADComputerChangesDetailed = $Utility | Get-Unique -asString}

If ($ADComputerCreatedChanged -OR ($ADComputerDeleted) -OR ($ADComputerChangesDetailed)) {
    $html += "  <h1>Computer Changes</h1>`n"
    If ($ADComputerCreatedChanged) {$html += Get-ThisTable -Event $ADComputerCreatedChanged -Header 'AD Computer Created/Changed'}
    If ($ADComputerDeleted)        {$html += Get-ThisTable -Event $ADComputerDeleted -Header 'AD Computer Deleted'}
    If ($ADComputerChangesDetailed){$html += Get-ThisTable -Event $ADComputerChangesDetailed -Header 'AD Computer Changes Detailed'}
}
#endregion Computer Changes

#region Group Changes
$gChangeSel1  = @{Property = $act, $evt, $gpn, $whn, $who}
$gChangeSel2  = @{Property = $act, $evt, $gpn, $mbn, $whn, $who}
$gChangeSel3  = @{Property = $act, $cgt, $evt, $gpn, $whn, $who}
$gChangeSel4  = @{Property = $act, $adt, $cpo, $evt, $fdc, $fdv, $gpn, $ojc, $whn, $who}
$gChangeSort1 = @{Property = $whn, $act, $evt, $gpn, $who}
$gChangeSort2 = @{Property = $whn, $act, $evt, $gpn, $mbn, $who}
$gChangeSort3 = @{Property = $whn, $act, $cgt, $evt, $gpn, $who}
$gChangeSort4 = @{Property = $whn, $act, $adt, $cpo, $evt, $fdc, $fdv, $gpn, $ojc, $who}
If (($Events.ADGroupCreateDelete) -OR ($Events.ADGroupMembershipChanges) -OR ($Events.ADGroupEnumeration) -OR ($Events.ADGroupChanges) -OR ($Events.ADGroupChangesDetailed)) {
    $html += "  <h1>Group Changes</h1>`n"
    If ($Events.ADGroupCreateDelete){
        Write-Host 'Compiling Group Created Deleted'
        $utility = $Events.ADGroupCreateDelete | Select-Object @gChangeSel1 | Sort-Object @gChangeSort1 | Get-Unique -asString
        $html   += Get-ThisTable -Event $utility -Header 'AD Group Create/Delete'
    }
    If ($Events.ADGroupMembershipChanges) {
        Write-Host 'Compiling AD Group Membership Changes'
        $utility = $Events.ADGroupMembershipChanges | Select-Object @gChangeSel2 | Sort-Object @gChangeSort2 | Get-Unique -asString
        $html   += Get-ThisTable -Event $Events.ADGroupMembershipChanges -Header 'AD Group Membership Changes'
    }
    If ($Events.ADGroupEnumeration) {$html += Get-ThisTable -Event $Events.ADGroupEnumeration -Header 'AD Group Enumeration'}
    If ($Events.ADGroupChanges){
        Write-Host 'Compiling AD Group Changes'
        $utility = $Events.ADGroupChanges | Select-Object @gChangeSel3 | Sort-Object @gChangeSort3 | Get-Unique -asString
        $html   += Get-ThisTable -Event $utility -Header 'AD Group Changes'
    }
    If ($Events.ADGroupChangesDetailed){
        Write-Host 'Compiling AD Group Changes Detailed'
        $utility = $Events.ADGroupChangesDetailed | Select-Object @gChangeSel4 | Sort-Object @gChangeSort4 | Get-Unique -asString
        $html   += Get-ThisTable -Event $utility -Header 'AD Group Changes Detailed'
    }
}
#endregion Group Changes

#region User Changes
$uChangeSel1  = @{Property = $act, $evt, $pls, $usa, $whn, $who}
$uChangeSel2  = @{Property = $act, $adt, $evt, $fdc, $fdv, $uso, $whn, $who}
$uChangeSel3  = @{Property = $act, $clo, $evt, $rpb, $usa, $whn}
$uChangeSel4  = @{Property = $act, $evt, $usa, $whn, $who}
$uChangeSel5  = @{Property = $act, $clo, $evt, $usa, $whn, $who}
$uChangeSort1 = @{Property = $whn, $act, $evt, $pls, $usa, $whn, $who}
$uChangeSort2 = @{Property = $whn, $act, $adt, $evt, $fdc, $fdv, $uso, $who}
$uChangeSort3 = @{Property = $whn, $act, $clo, $evt, $rpb, $usa}
$uChangeSort4 = @{Property = $whn, $act, $evt, $usa, $who}
$uChangeSort5 = @{Property = $whn, $act, $clo, $evt, $usa, $whn, $who}
If (($Events.ADUserChanges) -OR ($Events.ADUserChangesDetailed) -OR ($Events.ADUserLockouts) -OR ($Events.ADUserStatus) -OR ($Events.ADUserUnlocked)) {
    $html += "  <h1>User Changes</h1>`n"
    If ($Events.ADUserChanges){
        Write-Host 'Compiling AD User Changes'
        $utility = $Events.ADUserChanges | Select-Object @uChangeSel1 | Sort-Object @uChangeSort1 | Where-Object {$_.Who -notmatch 'NT AUTHORITY'} | Get-Unique -asString
        $html    += Get-ThisTable -Event $utility -Header 'AD User Changes'
    }
    If ($Events.ADUserChangesDetailed){
        Write-Host 'Compiling AD User Changes Detailed'
        $utility = $Events.ADUserChangesDetailed | Select-Object @uChangeSel2 | Sort-Object @uChangeSort2 | Get-Unique -asString
        $html   += Get-ThisTable -Event $utility -Header 'AD user Changes Detailed'
    }
    If ($Events.ADUserLockouts){
        Write-Host 'Compiling AD User Lockouts'
        $utility = $Events.ADUserLockouts | Select-Object @uChangeSel3 | Sort-Object @uChangeSort3 | Get-Unique -asString
        $html   += Get-ThisTable -Event $utility -Header 'AD User Lockouts'
    }
    If ($Events.ADUserStatus){
        Write-Host 'Compiling AD User Status'
        $utility = $Events.ADUserStatus | Select-Object @uChangeSel4 | Sort-Object @uChangeSort4 | Where-Object {$_.Who -notmatch 'NT AUTHORITY'} | Get-Unique -asString
        $html   += Get-ThisTable -Event $utility -Header 'AD User Status Changes'
    }
    If ($Events.ADUserUnlocked){
        Write-Host 'Compiling AD User Unlocked'
        $utility = $Events.ADUserUnlocked | Select-Object @uChangeSel5 | Sort-Object @uChangeSort5 | Get-Unique -asString
        $html += Get-ThisTable -Event $utility -Header 'AD User Unlocks'
    }
}
#endregion User Changes

### Group Policy Changes
If ($Events.ADGroupPolicyChanges) {
    $html += "  <h1>Group Policy Changes</h1>`n"
    If ($Events.ADGroupPolicyChanges) {$html += Get-ThisTable -Event $Events.ADGroupPolicyChanges -Header 'AD Group Policy Changes'}
}

### Logs
<#
        If (($Events.ADLogsClearedOther) -OR ($Events.ADLogsClearedSecurity)) {
        $html += "  <h2>Logs</h2>`n"
        If ($Events.ADLogsClearedOther)       {$html += Get-ThisTable -Event $Events.ADLogsClearedOther        -Header "AD Logs Cleared (Other)"}
        If ($Events.ADLogsClearedSecurity)    {$html += Get-ThisTable -Event $Events.ADLogsClearedSecurity     -Header "AD Logs Cleared (Security)"}
        }
#>
$html += $htmlend

If ($Events) {Send-MailMessage -smtpserver $smtpserver -from $from -to $to -subject $subject -body $html -bodyashtml}


