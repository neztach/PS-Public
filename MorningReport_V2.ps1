$rootPath          = 'C:\down'
$VerbosePreference = 'Continue'

#region mail vars
$emailParameters = @{
    SMTPServer = 'smtp.contoso.com'
    From       = 'ADEventReport@contoso.com' 
    To         = 'me@contoso.com'
    Subject    = '[Morning Report] Event Changes for period <<DateFrom>> to <<DateTo>>'
}
#endregion mail vars

#region Morning Report
$Options       = [ordered]@{
    AsExcel          = @{
        Enabled     = $true
        OpenAsFile  = $false
        Path        = $rootPath
        FilePattern = "MorningReport_$((Get-Date -Format yyyy-MM-dd_HH-mm).ToString()).xlsx"
        DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
    }
    AsCSV            = @{
        Enabled     = $false
        OpenAsFile  = $false
        Path        = $rootPath
        FilePattern = 'MorningReport.csv'
        DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
    }
    AsHTML           = @{
        Enabled     = $false # creates report in HTML
        OpenAsFile  = $false # requires AsHTML set to $true
        Path        = $rootPath
        FilePattern = "MorningReport_$((Get-Date -Format yyyy-MM-dd_HH-mm).ToString()).html"
        DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
        Formatting  = @{
            CompanyBranding        = @{
                Logo   = ''
                Width  = '200'
                Height = ''
                Link   = ''
                Inline = $false
            }
            FontFamily             = 'Calibri Light'
            FontSize               = '9pt'
            FontHeadingFamily      = 'Calibri Light'
            FontHeadingSize        = '12pt'
            FontTableHeadingFamily = 'Calibri Light'
            FontTableHeadingSize   = '9pt'
            FontTableDataFamily    = 'Calibri Light'
            FontTableDataSize      = '9pt'
            Colors                 = @{
                # case sensitive
                Red   = 'removed', 'deleted', 'locked out', 'lockouts', 'disabled', 'Domain Admins', 'was cleared'
                Blue  = 'changed', 'changes', 'change', 'reset'
                Green = 'added', 'enabled', 'unlocked', 'created'
            }
            Styles                 = @{
                # case sensitive
                B = 'status', 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'was cleared', 'lockouts' # BOLD
                I = '' # Italics
                U = 'status'# Underline
            }
            Links                  = @{

            }
        }
    }
    AsDynamicHTML    = @{
        Enabled     = $true # creates report in Dynamic HTML
        OpenAsFile  = $true
        Title       = 'Morning Report - Windows Events'
        Path        = $rootPath
        FilePattern = "MorningReport_$((Get-Date -Format yyyy-MM-dd_HH-mm).ToString()).html"
        DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
        Branding    = @{
            Logo = @{
                Show      = $false
                RightLogo = @{
                    ImageLink = ''
                    Width     = '200'
                    Height    = ''
                    Link      = ''
                    Inline    = $false
                }
            }
        }
        #EmbedCSS    = $true
        #EmbedJS     = $true
        #Online      = $true
    }
    SendMail         = @{
        Enabled     = $true
        InlineHTML  = $true # this goes inline - if empty email will have no content
        Attach      = @{
            XLSX        = $true # this goes as attachment
            CSV         = $false # this goes as attachment
            DynamicHTML = $false # this goes as attachment
            HTML        = $false # this goes as attachment
            # if all 4 above are false email will have no attachment
            # remember that for this to work each part has to be enabled
            # using attach XLSX without generating XLSX won't magically let it attach
        }
        KeepReports = @{
            XLSX        = $false # keeps files after reports are sent
            CSV         = $false # keeps files after reports are sent
            HTML        = $false # keeps files after reports are sent
            DynamicHTML = $false # keeps files after reports are sent
        }
        Parameters  = @{
            From             = $emailParameters.From
            To               = $emailParameters.To
            CC               = ''
            BCC              = ''
            ReplyTo          = ''
            Server           = $emailParameters.SMTPServer
            Password         = ''
            PasswordAsSecure = $false
            PasswordFromFile = $false
            Port             = '25'
            Login            = ''
            EnableSSL        = 0
            Encoding         = 'Unicode'
            Subject          = $emailParameters.Subject
            Priority         = 'Low'
        }
    }
    RemoveDuplicates = @{
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
    CustomDate = @{
        Enabled  = $true
        DateFrom = $Yesterday
        DateTo   = $Today
    }
}

## Define reports
$DefinitionsAD = [ordered] @{
    ADUserChanges                       = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4720, 4738
            LogName     = 'Security'
            Fields      = [ordered] @{
                'Action'            = 'Action'
                'ObjectAffected'    = 'User Affected'
                'SamAccountName'    = 'SamAccountName'
                'DisplayName'       = 'DisplayName'
                'UserPrincipalName' = 'UserPrincipalName'
                'PasswordLastSet'   = 'Password Last Set'
                'Who'               = 'Who'
                'Date'              = 'When'
                # Common Fields
                'ID'                = 'Event ID'
                'RecordID'          = 'Record ID'
                'GatheredFrom'      = 'Gathered From'
                'GatheredLogName'   = 'Gathered LogName'
            }
            Ignore      = @{
                # Cleanup Anonymous LOGON (usually related to password events)
                SubjectUserName = 'ANONYMOUS LOGON'
                Who             = 'NT AUTHORITY\ANONYMOUS LOGON'
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
            Fields      = [ordered]@{
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
            IgnoreWords = @{'Who' = '*$' }
        }
    }  # 5136,5137,5141
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
                # Cleanup Anonymous LOGON (usually related to password events)
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
    }  # 5136,5137,5141
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
            Fields           = [ordered]@{
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
    }  # 5136,5137,5139,5141
    ADUserStatus                        = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4722, 4725, 4767, 4723, 4724, 4726
            LogName     = 'Security'
            IgnoreWords = @{}
            Fields      = [ordered]@{
                'Action'         = 'Action'
                'Who'            = 'Who'
                'Date'           = 'When'
                'ObjectAffected' = 'User Affected'
                # Common Fields
                'ID'             = 'Event ID'
                'RecordID'       = 'Record ID'
                'GatheredFrom'   = 'Gathered From'
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
            Fields      = [ordered]@{
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
            Fields      = [ordered]@{
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
                SubjectUserName = 'ANONYMOUS LOGON'
            }
            Fields      = [ordered]@{
                'Computer'            = 'Domain Controller'
                'Action'              = 'Action'
                'ObjectAffected'      = 'Computer Affected'
                'SamAccountName'      = 'SamAccountName'
                'DisplayName'         = 'DisplayName'
                'UserPrincipalName'   = 'UserPrincipalName'
                'HomeDirectory'       = 'Home Directory'
                'HomePath'            = 'Home Path'
                'ScriptPath'          = 'Script Path'
                'ProfilePath'         = 'Profile Path'
                'UserWorkstations'    = 'User Workstations'
                'PasswordLastSet'     = 'Password Last Set'
                'AccountExpires'      = 'Account Expires'
                'PrimaryGroupId'      = 'Primary Group Id'
                'AllowedToDelegateTo' = 'Allowed To Delegate To'
                'OldUacValue'         = 'Old Uac Value'
                'NewUacValue'         = 'New Uac Value'
                'UserAccountControl'  = 'User Account Control'
                'UserParameters'      = 'User Parameters'
                'SidHistory'          = 'Sid History'
                #'Action'              = 'Action'
                #'ObjectAffected'      = 'Computer Affected'
                #'PasswordLastSet'     = 'Password Last Set'
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
            Fields      = [ordered]@{
                'Action'         = 'Action'
                'ObjectAffected' = 'Computer Affected'
                'Who'            = 'Who'
                'Date'           = 'When'
                # Common Fields
                'ID'             = 'Event ID'
                'GatheredFrom'   = 'Gathered From'
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
            Fields      = [ordered]@{
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
            Events      = 4735, 4737, 4745, 4750, 4755, 4760, 4764, 4784, 4791
            LogName     = 'Security'
            IgnoreWords = @{
                'Who' = '*ANONYMOUS*'
            }
            Fields      = [ordered]@{
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
    }           # 4735,4737,4745,4750,4755,4760,4764,4784,4791
    ADGroupCreateDelete                 = @{
        Enabled = $true
        Events  = @{
            Enabled     = $true
            Events      = 4727, 4730, 4731, 4734, 4744, 4748, 4749, 4753, 4754, 4758, 4759, 4763
            LogName     = 'Security'
            IgnoreWords = @{
                # 'Who' = '*ANONYMOUS*'
            }
            Fields      = [ordered]@{
                'Action'         = 'Action'
                'TargetUserName' = 'Group Name'
                'Who'            = 'Who'
                'Date'           = 'When'
                # Common Fields
                'ID'             = 'Event ID'
                'RecordID'       = 'Record ID'
                'GatheredFrom'   = 'Gathered From'
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
            Fields      = [ordered]@{
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
            IgnoreWords = @{}
        }
    }  # 5136,5137,5141
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
            Fields      = [ordered]@{
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
            IgnoreWords = @{ }
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
            Fields      = [ordered]@{
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
            Fields      = [ordered]@{
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
            IgnoreWords = @{ }
        }  # 5136, 5137, 5141
    }  # 5136,5137,5141
}
#endregion Morning Report

Start-WinReporting -Options $Options -Times $Times -Definitions $DefinitionsAD -Target $Target -Verbose

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

[Array]$Events  = Find-Events -Report $Reports -DateFrom $yesterday -DateTo $today -Servers $ServerList

If ($Events.Count -gt 0) {
    Email -Email {
        EmailHeader -EmailHeader {
            EmailFrom -Address $emailParameters.From
            EmailTo -Addresses $emailParameters.To
            EmailServer -Server $emailParameters.SMTPServer -Port 25
            EmailOptions -Priority High -DeliveryNotifications Never
            EmailSubject -Subject '[Morning Report 2] Summary of Active Directory Tests'
        }
        EmailBody -FontFamily 'Calibri' -FontSize 15 -EmailBody {
            EmailText -Text 'Summary of Active Directory Tests' -Color None, Blue -LineBreak

            EmailTable -DataTable $Events -HTML {
                EmailTableCondition -ComparisonType 'string' -Name 'Status' -Operator eq -Value 'True' -BackgroundColor Green -Color White -Inline -Row
                EmailTableCondition -ComparisonType 'string' -Name 'Status' -Operator ne -Value 'True' -BackgroundColor Red -Color White -Inline -Row
            } -HideFooter
        }
    } -AttachSelf -Suppress $false
}
