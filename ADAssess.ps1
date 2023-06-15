#Requires -RunAsAdministrator
Import-Module -Name PSWinDocumentation.AD -Force
Import-Module -Name Documentimo -Force

#region Variables
$script:mypath            = (Get-Item -Path .).FullName
$script:Date1             = (Get-Date -Format MMM-dd-yyyy).ToString()
$script:Date2             = (Get-Date -Format yyyy-MM-dd_HH-mm).ToString()
$script:Business          = 'BusinessName'
$script:Logo              = 'https://URL/logo.png'
$script:www               = 'https://URL/'

### Reports
$script:SavePath          = ('{0}\Reports' -f $myPath)

### AD Change Report - what changed in the past 24 hours
$GetChangeReport          = $true
$script:MorningReportName = ('24HourChange_{0}.html' -f $Date2)

### AD Eval to Word Document - Evaluate AD and build a report of what-is
$GetADEvalWord            = $true
$script:WordReportName    = ('{0}-AD-Evaluation_{1}.docx' -f ($Business), $Date1)
$script:WordOutFile       = ('{0}\{1}' -f $SavePath, $WordReportName)

### GPO Report - Evaluate all GPOs looking for issues
$GetGPOReport             = $true
$script:GPOReportName     = ('{0}-GPO-Report_full_{1}.html' -f ($Business), $Date1)
$script:GPOOutfile        = ('{0}\{1}' -f $SavePath, $GPOReportName)

### AD Health Report - Evaluate AD looking for issues
$ADHealthReport           = $true
$script:ADHTReportName    = ('{0}_Full_ADTestSummary_{1}.html' -f ($Business), $Date1)
$script:ADHTOutfile       = ('{0}\{1}' -f $SavePath, $ADHTReportName)

#endregion Variables

#region Functions
Function Get-ChangeReport {
    $Options       = [ordered]@{
        AsExcel          = @{
            Enabled     = $true
            OpenAsFile  = $false
            Path        = $SavePath
            FilePattern = $MorningReportName
            DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
        }
        AsCSV            = @{
            Enabled     = $false
            OpenAsFile  = $false
            Path        = $SavePath
            FilePattern = $MorningReportName
            DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
        }
        AsHTML           = @{
            Enabled     = $false # creates report in HTML
            OpenAsFile  = $false # requires AsHTML set to $true
            Path        = $SavePath
            FilePattern = $MorningReportName
            DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
            Formatting  = @{
                CompanyBranding        = @{
                    Logo   = $Logo
                    Width  = '200'
                    Height = ''
                    Link   = $www
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
                    I = '' # Italian
                    U = 'status'# Underline
                }
                Links                  = @{

                }
            }
        }
        AsDynamicHTML    = @{
            Enabled     = $true # creates report in Dynamic HTML
            OpenAsFile  = $false
            Title       = 'Morning Report - Windows Events'
            Path        = $SavePath
            FilePattern = $MorningReportName
            DateFormat  = 'yyyy-MM-dd-HH_mm_ss'
            Branding    = @{
                Logo = @{
                    Show      = $true
                    RightLogo = @{
                        ImageLink = $Logo
                        Width     = '200'
                        Height    = ''
                        Link      = $www
                        Inline    = $false
                    }
                }
            }
            EmbedCSS    = $true
            EmbedJS     = $true
            Online      = $true
        }
        RemoveDuplicates = @{
            Enabled    = $true # when multiple sources are used it's normal for duplicates to occur. This cleans it up.
            Properties = 'RecordID', 'Computer'
        }
    }
    $Target        = [ordered]@{
        Servers           = [ordered]@{
            Enabled = $false
            Server2 = 'Test-Server01'#, 'Test-Server02'
        }
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
            Enabled   = $true
            Events    = @{
                Enabled     = $true
                Events      = 4720, 4738
                LogName     = 'Security'
                Fields      = [ordered] @{
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
                    # Cleanup Anonymous LOGON (usually related to password events) 
                    # https://social.technet.microsoft.com/Forums/en-US/5b2a93f7-7101-43c1-ab53-3a51b2e05693/eventid-4738-user-account-was-changed-by-anonymous?forum=winserverDS
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
            Enabled   = $true
            Events    = @{
                Enabled     = $true
                Events      = 5136, 5137, 5141
                LogName     = 'Security'
                Filter      = @{
                    'ObjectClass'   = 'user'
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
                IgnoreWords = @{'Who' = '*$'}
            }
        }  # 5136,5137,5141
        ADComputerChangesDetailed           = [ordered]@{
            Enabled   = $true
            Events    = @{
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
                    # https://social.technet.microsoft.com/Forums/en-US/5b2a93f7-7101-43c1-ab53-3a51b2e05693/eventid-4738-user-account-was-changed-by-anonymous?forum=winserverDS
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
                Events      = 4735, 4737, 4745, 4750, 4760, 4764, 4784, 4791
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
                Fields      = [ordered]@{
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
            Enabled = $true
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

    Start-WinReporting -Options $Options -Times $Times -Definitions $DefinitionsAD -Target $Target -Verbose
}

Function Get-ADEvaltoWord {
    If ($null -eq $ADForest) {
        $ADForest = Get-WinADForestInformation -Verbose -PasswordQuality -DontRemoveEmpty
    }
    $CompanyName   = $Business
    $CurrentForest = Get-ADForest -Current LoggedOnUser

    Documentimo -FilePath $WordOutFile -Content {
        DocTOC -Title 'Table of contents'
        DocPageBreak
        DocText -TextBlock {('This document provides low-level documentation of Active Directory infrastructure in the {0} organization. This document contains general data that has been exported from Active Directory and provides an overview of the whole environment.' -f ($CompanyName))}
        #region 1. General Information - Forest Summary
        DocNumbering -Text 'General Information - Forest Summary' -Level 0 -Type Numbered -Heading Heading1 -Content {
            DocText  -TextBlock {('Active Directory at {0} has a forest named {1}. The following table contains the forest summary, with important information:' -f $CompanyName, ($CurrentForest))}
            DocTable -DataTable $ADForest.ForestInformation -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Forest Summary'
            DocText  -LineBreak
            DocText  -Text 'The following table contains Forest-level FSMO servers:'
            DocTable -DataTable $ADForest.ForestFSMO -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'FSMO Roles'
            DocText  -LineBreak
            DocText  -Text 'The following table contains optional forest features:'
            DocTable -DataTable $ADForest.ForestOptionalFeatures -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Optional Features'
            DocText  -LineBreak
            DocText  -Text 'The following UPN suffixes were created in this forest:'
            DocTable -DataTable $ADForest.ForestUPNSuffixes -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'UPN Suffixes'
            DocText  -LineBreak
            If ($ADForest.ForestSPNSuffixes) {
                DocText -Text 'Following SPN suffixes were created in this forest:'
                DocTable -DataTable $ADForest.ForestSPNSuffixes -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'UPN Suffixes'
            } Else {
                DocText -Text 'No SPN suffixes were created in this forest.'
            }
            DocPageBreak
            DocNumbering -Text 'General Information - Forest Sites' -Level 1 -Type Numbered -Heading Heading1 -Content {
                DocText  -Text 'A Forest Sites list can be found below:'
                DocTable -DataTable $ADForest.ForestSites1 -Design ColorfulGridAccent5 -AutoFit Window #-OverwriteTitle 'Forest Summary'
                DocText  -LineBreak
                Foreach ($Fsite2 in $ADForest.ForestSites2){
                    If (
                        ($Fsite2.TopologyCleanupEnabled) -or 
                        ($Fsite2.TopologyDetectStaleEnabled) -or 
                        ($Fsite2.TopologyMinimumHopsEnabled) -or 
                        ($Fsite2.UniversalGroupCachingEnabled) -or 
                        ($Fsite2.UniversalGroupCachingRefreshSite)
                    ){
                        DocText -Text 'Forest Sites (expanded) list can be found below:'
                        DocTable -DataTable $ADForest.ForestSites2 -Design ColorfulGridAccent5 -AutoFit Window #-OverwriteTitle 'Forest Summary'
                    }
                }
                #  DocText -LineBreak
            }
            DocNumbering -Text 'General Information - Subnets' -Level 1 -Type Numbered -Heading Heading1 -Content {
                DocText  -Text 'The table below contains information regarding relation between Subnets and sites'
                DocTable -DataTable $ADForest.ForestSubnets1 -Design ColorfulGridAccent5 -AutoFit Window #-OverwriteTitle 'Forest Summary'
                DocText  -LineBreak
                DocText  -Text 'The table below contains information regarding relation between Subnets and sites (Cont.)'
                DocTable -DataTable $ADForest.ForestSubnets2 -Design ColorfulGridAccent5 -AutoFit Window #-OverwriteTitle 'Forest Summary'
                # DocText -LineBreak
            }
            DocNumbering -Text 'General Information - Site Links' -Level 1 -Type Numbered -Heading Heading1 -Content {
                DocText  -Text 'Forest Site Links information is available in table below'
                $fForestSiteLinks = @()
                ($ADForest.ForestSiteLinks | Out-String).split("`n") | ForEach-Object {
                    If ($_.split(':')[0].trim() -ne ''){
                        $fForestSiteLinks += [pscustomobject][ordered]@{
                            Category = $_.split(':')[0].trim()
                            Value    = $_.split(':')[-1].trim()
                        }
                    }
                }
                #$fForestSiteLinks
                DocTable -DataTable $fForestSiteLinks -Design ColorfulGridAccent5 -AutoFit Window #-OverwriteTitle 'Forest Summary'
                # DocText -LineBreak
            }
        }
        #endregion 1.
        #region 2. General Information - Domains
        ForEach ($Domain in $ADForest.FoundDomains.Keys) {
            DocPageBreak
            DocNumbering -Text ('General Information - Domain {0}' -f $Domain) -Level 0 -Type Numbered -Heading Heading1 -Content {
                DocNumbering -Text 'General Information - Domain Summary' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText  -Text ('The following domains exists within forest {0}:' -f $ADForest.ForestName)
                    DocList  -Type Bulleted -ListItems {
                        DocListItem -Level 1 -Text ('Domain: {0}' -f $ADForest.FoundDomains.$Domain.DomainInformation.DistinguishedName)
                        DocListItem -Level 2 -Text ('Name for fully qualified domain name (FQDN): {0}' -f $ADForest.FoundDomains.$Domain.DomainInformation.DNSRoot)
                        DocListItem -Level 2 -Text ('Name for NetBIOS: {0}' -f $ADForest.FoundDomains.$Domain.DomainInformation.NetBIOSName)
                    }
                }
                DocNumbering -Text 'General Information - Domain Controllers' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText  -Text 'The following table contains domain controllers'
                    #Foreach ($fDC in ($ADForest.FoundDomains.$Domain.DomainControllers)){
                    DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainControllers | 
                        Select-Object -Property Name,
                        Site,
                        Ipv4,
                        @{n='GC';e={$_.'Global Catalog?'}},
                        @{n='RODC';e={$_.'Read Only?'}},
                    @{n='OS';e={$_.'Operating System'}}) -Design ColorfulGridAccent5 -AutoFit Window #-OverwriteTitle 'Forest Summary'
                    DocText  -LineBreak
                    #}
                    #DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainControllers) -Design ColorfulGridAccent5 -AutoFit Window #-OverwriteTitle 'Forest Summary'
                    DocText  -LineBreak
                    DocText  -Text ('The following table contains FSMO servers with roles for domain {0}' -f $Domain)
                    DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainFSMO) -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle ('FSMO Roles for {0}' -f $Domain)
                }
                DocNumbering -Text 'General Information - Password Policies' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText  -Text ('The following table contains password policies for all users within {0}' -f $Domain)
                    DocTable -DataTable $ADForest.FoundDomains.$Domain.DomainDefaultPasswordPolicy -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle ('Default Password Policy for {0}' -f $Domain)
                }
                DocNumbering -Text 'General Information - Fine-grained Password Policies' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    If ($ADForest.FoundDomains.$Domain.DomainFineGrainedPolicies) {
                        DocText  -Text 'The following table contains Fine-grained password policies'
                        DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainFineGrainedPolicies -Design ColorfulGridAccent5 -AutoFit Window # -OverwriteTitle  "Fine-grained Password Policy for <Domain>"
                    } Else {
                        DocText -Text ('This section should cover fine-grained password policies, but no fine-grained password polices were found defined in {0}. There was no formal requirement to have them set up.' -f $Domain)
                    }
                }
                DocNumbering -Text 'General Information - Group Policies' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText  -Text ('The following table contains group policies for {0}' -f $Domain)
                    DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainGroupPolicies | Sort-Object -Property 'Display Name') -Design ColorfulGridAccent5 -AutoFit Window
                }
                DocNumbering -Text 'General Information - Group Policies Details' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText  -Text ('The following table contains group policies for {0}' -f $Domain)
                    DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainGroupPoliciesDetails | Sort-Object -Property Name) -Design ColorfulGridAccent5 -AutoFit Window -MaximumColumns 6 ### revisit
                }
                DocNumbering -Text 'General Information - DNS A/SRV Records' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText  -Text 'The following table contains SRV records for Kerberos and LDAP'
                    DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainDNSSRV | Sort-Object -Property Target) -Design ColorfulGridAccent5 -AutoFit Window -MaximumColumns 10
                    DocText  -LineBreak
                    DocText  -Text 'The following table contains A records for Kerberos and LDAP'
                    DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainDNSA | Select-Object -Property Address,IPAddress,IP4Address,Name,TTL | Sort-Object -Property Address) -Design ColorfulGridAccent5 -AutoFit Window -MaximumColumns 10
                }
                DocNumbering -Text 'General Information - Trusts' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText -Text 'The following table contains trusts established with domains...'
                    ForEach ($fTrust in ($ADForest.FoundDomains.$Domain.DomainTrusts)){
                        $fFTrusts = @()
                        ($fTrust | Out-String).split("`n") | ForEach-Object {
                            If ($_.split(':')[0].trim() -ne ''){
                                $fFTrusts += [pscustomobject][ordered]@{
                                    Category = $_.Split(':')[0].trim()
                                    Value    = $_.split(':')[-1].trim()
                                }
                            }
                        }
                        DocTable -DataTable ($fFTrusts | Sort-Object -Property Category) -Design ColorfulGridAccent5 -AutoFit Window -MaximumColumns 10
                        DocText -LineBreak
                    }
                }
                DocNumbering -Text 'General Information - Organizational Units' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText -Text ("The following table contains all OU's created in {0}" -f $Domain)
                    DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainOrganizationalUnits | Select-Object -Property 'Canonical Name',Protected,Description,Modified | Sort-Object -Property 'Canonical Name') -Design ColorfulGridAccent5 -AutoFit Window -MaximumColumns 4
                    DocText -LineBreak
                }
                DocNumbering -Text 'General Information - Privileged Groups' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocText  -Text 'The following table contains list of privileged groups and count of the members in it.'
                    $PrivGroups = $ADForest.FoundDomains.$Domain.DomainGroupsPriviliged | 
                    Select-Object -Property 'Group Name',
                    'Group Category',
                    'Group Scope',
                    @{n='Privileged High';e={$_.'High Privileged Group'}},
                    'Member Count',
                    'MemberOf Count'
                    DocTable -DataTable ($PrivGroups | Sort-Object -Property 'Group Name') -Design ColorfulGridAccent5 -AutoFit Window
                    DocChart -Title 'Priviliged Group Members' -DataTable  $ADForest.FoundDomains.$Domain.DomainGroupsPriviliged -Key 'Group Name' -Value 'Member Count'
                }
                DocNumbering -Text ('General Information - Domain Users in {0}' -f $Domain) -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocNumbering -Text 'General Information - Users Count' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText  -Text 'The following table and chart shows number of users in its categories'
                        DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainUsersCount -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Users Count'
                        DocChart -Title 'Servers Count' -DataTable  $ADForest.FoundDomains.$Domain.DomainUsersCount
                    }
                    DocNumbering -Text 'General Information - Domain Administrators' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainAdministratorsRecursive) {
                            DocText -Text 'The following users have highest privileges and are able to control a lot of Windows resources.'
                            $fDomainAdmins = $ADForest.FoundDomains.$Domain.DomainAdministratorsRecursive | 
                            Select-Object -Property 'Display Name',Name,@{n='username';e={$_.'Sam Account Name'}},Enabled,Manager
                            DocTable -DataTable ($fDomainAdmins | Sort-Object -Property Name) -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText -Text 'No Domain Administrators users were defined for this domain.'
                        }
                    }
                    DocNumbering -Text 'General Information - Enterprise Administrators' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainEnterpriseAdministratorsRecursive) {
                            DocText  -Text 'The following users have highest privileges across Forest, and are able to control a lot of Windows resources.'
                            $fEntAdmins = $ADForest.FoundDomains.$Domain.DomainEnterpriseAdministratorsRecursive | 
                            Select-Object -Property 'Display Name',Name,@{n='username';e={$_.'Sam Account Name'}},Enabled,Manager
                            DocTable -DataTable ($fEntAdmins | Sort-Object -Property Name) -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText -Text 'No Enterprise Administrators users were defined for this domain.'
                        }
                    }
                }
                DocNumbering -Text ('General Information - Computer Objects in {0}' -f $Domain) -Level 1 -Type Numbered -Heading Heading1 -Content {
                    DocNumbering -Text 'General Information - Computers' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText  -Text 'The following table and chart shows number of computers and their versions'
                        DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainComputersCount -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Computers Count'
                        DocChart -Title 'Servers Count' -DataTable $ADForest.FoundDomains.$Domain.DomainComputersCount -Key 'System Name' -Value  'System Count'
                    }
                    DocNumbering -Text 'General Information - Servers' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText  -Text 'The following table and chart shows number of servers and their versions'
                        DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainServersCount -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Servers Count'
                        DocChart -Title 'Servers Count' -DataTable $ADForest.FoundDomains.$Domain.DomainServersCount -Key 'System Name' -Value  'System Count'
                    }
                    DocNumbering -Text 'General Information - Unknown Computers' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText  -Text 'The following table and chart shows number of unknown object computers in domain.'
                        DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainComputersUnknownCount -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Unknown Computers Count'
                        DocChart -Title 'Servers Count' -DataTable $ADForest.FoundDomains.$Domain.DomainComputersUnknownCount -Key 'System Name' -Value  'System Count'
                    }
                }
                DocNumbering -Text 'Domain Password Quality' -Level 1 -Type Numbered -Heading Heading1 -Content {
                    Doctext      -TextBlock {('This section provides overview about password quality used in {0}. One should review if all those potentially' -f $Domain) + ' dangerous approaches to password quality should be left as is or addressed in one way or another.'}
                    DocNumbering -Text 'Password Quality - Passwords with Reversible Encryption' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText  -Text 'Passwords of these accounts are stored using reversible encryption.'
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordClearTextPassword) {
                            DocTable -DataTable $ADForest.FoundDomains.$Domain.DomainPasswordClearTextPassword -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText -Text 'There are no accounts that have passwords stored using reversible encryption.'
                        }
                    }
                    DocNumbering -Text 'Password Quality - Passwords with LM Hash' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText -TextBlock {'LM-hashes is the oldest password storage used by Windows, dating back to OS/2 system.' + ' Due to the limited charset allowed, they are fairly easy to crack.'}
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordLMHash) {
                            DocText  -LineBreak
                            DocText  -Text 'The following accounts are affected:'
                            DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainPasswordLMHash -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText  -LineBreak
                            DocText  -Text 'There were no accounts found that use LM Hashes.'
                        }
                    }
                    DocNumbering -Text 'Password Quality - Empty Passwords' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordEmptyPassword) {
                            DocText  -LineBreak
                            DocText  -Text  'The following accounts have no password set:'
                            DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainPasswordEmptyPassword | Select-Object -Property Name,SamAccountName,PasswordNeverExpires,Enabled,CanonicalName | Sort-Object -Property Name) -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText  -LineBreak
                            DocText  -Text ('No accounts were found in {0} that have no password set.' -f $Domain)
                        }
                    }
                    DocNumbering -Text 'Password Quality - Default Computer Password' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordDefaultComputerPassword) {
                            DocText  -LineBreak
                            DocText  -Text 'These computer objects have their password set to default:'
                            DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainPasswordDefaultComputerPassword -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText  -LineBreak
                            DocText  -Text 'There were no accounts found that match default computer password criteria.'
                        }
                    }
                    DocNumbering -Text 'Password Quality - Password Not Required' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText -TextBlock {'These accounts are not required to have a password. For some accounts it may be perfectly acceptable, ' + 'but for some it may not. Those accounts should be reviewed and accepted or changed to proper security.'}
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordPasswordNotRequired) {
                            DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainPasswordPasswordNotRequired | 
                                Select-Object -Property Name,SamAccountName,Enabled,CanonicalName | 
                            Sort-Object -Property Name) -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText  -TextBlock {'There were no accounts found that does not require password.'}
                        }
                    }
                    DocNumbering -Text 'Password Quality - Non expiring passwords' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText -TextBlock {'The following accounts have "do not expire password" policy set on them. Those accounts should be reviewed whether ' + 'allowing them to never expire is good idea and an accepted risk.'}
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordPasswordNeverExpires) {
                            DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainPasswordPasswordNeverExpires -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText -TextBlock {('There are no accounts in {0} that never expire.' -f $Domain)}
                        }
                    }
                    DocNumbering -Text 'Password Quality - AES Keys Missing' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordAESKeysMissing) {
                            DocText  -LineBreak
                            DocText  -Text 'Following accounts have their Kerberos AES keys missing'
                            DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainPasswordAESKeysMissing -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText  -LineBreak
                            DocText  -Text 'There are no accounts that have their Kerberos AES keys missing.'
                        }
                    }
                    DocNumbering -Text 'Password Quality - Kerberos Pre-Auth Not Required' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordPreAuthNotRequired) {
                            DocText  -LineBreak
                            DocText  -Text 'Kerberos pre-authentication is not required for these accounts'
                            DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainPasswordPreAuthNotRequired -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText  -LineBreak
                            DocText  -Text 'There were no accounts found that do not require pre-authentication.'
                        }
                    }
                    DocNumbering -Text 'Password Quality - Only DES Encryption Allowed' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordDESEncryptionOnly) {
                            DocText -LineBreak
                            DocText -Text 'Only DES-encryption is allowed to be used with these accounts'
                            DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainPasswordDESEncryptionOnly -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText -LineBreak
                            DocText -Text 'There are no account that require only DES encryption.'
                        }
                    }
                    DocNumbering -Text 'Password Quality - Delegable to Service' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordDelegatableAdmins) {
                            DocText  -LineBreak
                            DocText  -Text 'These accounts are allowed to be delegated to a service:'
                            DocTable -DataTable ($ADForest.FoundDomains.$Domain.DomainPasswordDelegatableAdmins | Select-Object -Property Name,SamAccountName,Enabled,CanonicalName | Sort-Object -Property Name) -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText -LineBreak
                            DocText -Text 'No accounts were found that are allowed to be delegated to a service.'
                        }
                    }
                    DocNumbering -Text 'Password Quality - Groups of users with the same password' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordDuplicatePasswordGroups) {
                            $fPassDups = $ADForest.FoundDomains.$Domain.DomainPasswordDuplicatePasswordGroups | Select-Object -Property Name,SamAccountName,Enabled,PasswordLastSet,CanonicalName
                            DocText  -LineBreak
                            DocText  -Text 'Following groups of users have same passwords:'
                            DocTable -DataTable ($fPassDups | Sort-Object -Property Name) -Design ColorfulGridAccent5 -AutoFit Window
                        } Else {
                            DocText  -LineBreak
                            DocText  -Text ('There are no 2 passwords that are the same in {0}.' -f $Domain)
                        }
                    }
                    DocNumbering -Text 'Password Quality - Statistics' -Level 2 -Type Numbered -Heading Heading2 -Content {
                        DocText -TextBlock {'Following table and chart shows password statistics'}
                        If ($ADForest.FoundDomains.$Domain.DomainPasswordStats) {
                            DocTable -DataTable  $ADForest.FoundDomains.$Domain.DomainPasswordStats -Design ColorfulGridAccent5 -AutoFit Window -OverwriteTitle 'Password Quality - Statistics'
                        } Else {
                            DocText  -TextBlock {'There were no passwords found that match in given dictionary.'}
                        }
                        DocChart -Title 'Password Statistics' -DataTable $ADForest.FoundDomains.$Domain.DomainPasswordStats # Hashtables don't require Key/Value pair
                    }
                }
            }
        }
        #endregion 2.
    }
}

Function Get-ADHealthTest {
    ### Get list of sections to test: Get-TestimoConfiguration
    ### https://github.com/EvotecIT/Testimo/blob/master/Example/Example-LoadConfigurationFromHash.ps1
    <#
            Name                                         Value
            ----                                         -----
            ForestBackup                                 {Enable, Source, Tests}
            ForestReplication                            {Enable, Tests}
            ForestReplicationStatus                      {Enable, Tests}
            ForestOptionalFeatures                       {Enable, Source, Tests}
            ForestSites                                  {Enable, Source, Tests}
            ForestSiteLinks                              {Enable, Source, Tests}
            ForestSiteLinksConnections                   {Enable, Source, Tests}
            ForestRoles                                  {Enable, Source, Tests}
            ForestSubnets                                {Enable, Source, Tests}
            ForestOrphanedAdmins                         {Enable, Source, Tests}
            ForestTombstoneLifetime                      {Enable, Source, Tests}
            ForestTrusts                                 {Enable, Tests}
            ForestConfigurationPartitionOwners           {Enable, Source, Tests}
            ForestConfigurationPartitionOwnersContainers {Enable, Source, Tests}
            DomainLDAP                                   {Enable, Source, Tests}
            DomainDomainControllers                      {Enable, Source, Tests}
            DomainRoles                                  {Enable, Source, Tests}
            DomainWellKnownFolders                       {Enable, Source, Tests}
            DomainPasswordComplexity                     {Enable, Source, Tests}
            DomainGroupPolicyAssesment                   {Enable, Source, Tests}
            DomainGroupPolicyPermissions                 {Enable, Source, Tests}
            DomainGroupPolicyPermissionConsistency       {Enable, Source, Tests}
            DomainGroupPolicyOwner                       {Enable, Source, Tests}
            DomainGroupPolicyADM                         {Enable, Source, Tests}
            DomainGroupPolicySysvol                      {Enable, Source, Tests}
            DomainOrphanedForeignSecurityPrincipals      {Enable, Source, Tests}
            DomainOrganizationalUnitsEmpty               {Enable, Source, Tests}
            DomainOrganizationalUnitsProtected           {Enable, Source, Tests}
            DomainNetLogonOwner                          {Enable, Source, Tests}
            DomainDNSScavengingForPrimaryDNSServer       {Enable, Source, Tests}
            DomainDNSForwaders                           {Enable, Source, Tests}
            DomainDnsZonesAging                          {Enable, Source, Tests}
            DomainSecurityComputers
            DomainSecurityGroupsAccountOperators         {Enable, Source, Tests}
            DomainSecurityGroupsSchemaAdmins             {Enable, Source, Tests}
            DomainSecurityUsers                          {Enable, Source, Tests}
            DomainSecurityUsersAcccountAdministrator     {Enable, Source, Tests}
            DomainSecurityKRBGT                          {Enable, Source, Tests}
            DomainSysVolDFSR                             {Enable, Source, Tests}
            DomainDNSZonesForest0ADEL                    {Enable, Source, Tests}
            DomainDNSZonesDomain0ADEL                    {Enable, Source, Tests}
            DomainDHCPAuthorized                         {Enable, Source, Tests}
            DomainComputersUnsupported                   {Enable, Source, Tests}
            DomainComputersUnsupportedMainstream         {Enable, Source, Tests}
            DomainExchangeUsers                          {Enable, Source, Tests}
            DomainDuplicateObjects                       {Enable, Source, Tests}
            DCInformation                                {Enable, Source, Tests}
            DCWindowsRemoteManagement                    {Enable, Source, Tests}
            DCEventLogs                                  {Enable, Source, Tests}
            DCOperatingSystem                            {Enable, Source, Tests}
            DCServices                                   {Enable, Source, Tests}
            DCLDAP                                       {Enable, Source, Tests}
            DCLDAPInsecureBindings                       {Enable, Source, Tests}
            DCPingable                                   {Enable, Source, Tests}
            DCPorts                                      {Enable, Source, Tests}
            DCRDPPorts                                   {Enable, Source, Tests}
            DCRDPSecurity                                {Enable, Source, Tests}
            DCDiskSpace                                  {Enable, Source, Tests}
            DCTimeSettings                               {Enable, Source, Tests}
            DCTimeSynchronizationInternal                {Enable, Source, Tests}
            DCTimeSynchronizationExternal                {Enable, Source, Tests}
            DCNetworkCardSettings                        {Enable, Source, Tests}
            DCWindowsUpdates                             {Enable, Source, Tests}
            DCWindowsRolesAndFeatures                    {Enable, Source, Tests}
            DCDnsResolveInternal                         {Enable, Source, Tests}
            DCDnsResolveExternal                         {Enable, Source, Tests}
            DCDnsNameServes                              {Enable, Source, Tests}
            DCSMBProtocols                               {Enable, Source, Tests}
            DCSMBShares                                  {Enable, Source, Tests}
            DCSMBSharesPermissions                       {Enable, Source, Tests}
            DCDFS                                        {Enable, Source, Tests}
            DCNTDSParameters                             {Enable, Source, Tests}
            DCGroupPolicySYSVOLDC                        {Enable, Source, Tests}
            DCLanManagerSettings                         {Enable, Source, Tests}
            DCDiagnostics                                {Enable, Source, Tests}
            DCLanManServer                               {Enable, Source, Tests}
            DCMSSLegacy                                  {Enable, Source, Tests}
            DCFileSystem                                 {Enable, Source, Tests}
            DCNetSessionEnumeration                      {Enable, Source, Tests}
            DCServiceWINRM                               {Enable, Source, Tests}
            DCUNCHardenedPaths                           {Enable, Source, Tests}
            DCDNSForwaders                               {Enable, Source, Tests}
    #>

    #region custom config
    $OutputOrderedDictionary = Get-TestimoConfiguration
    $OutputOrderedDictionary.DCSMBProtocols.Tests.AsynchronousCredits.Parameters.OperationType = 'ge'
    $OutputOrderedDictionary.DCSMBProtocols.Tests.AutoDisconnectTimeout.Parameters.OperationType = 'ge'
    $OutputOrderedDictionary.DCSMBProtocols.Tests.CachedOpenLimit.Parameters.OperationType = 'ge'
    $OutputOrderedDictionary.DCSMBProtocols.Tests.DurableHandleV2TimeoutInSeconds.Parameters.OperationType = 'ge'
    $OutputOrderedDictionary.DCSMBProtocols.Tests.Smb2CreditsMin.Parameters.OperationType = 'ge'
    $OutputOrderedDictionary.DCSMBProtocols.Tests.Smb2CreditsMax.Parameters.OperationType = 'ge'
    #endregion

    ### AD Health Check
    $Sources = @(
        'ForestBackup'
        #ForestReplication
        'ForestReplicationStatus'
        #ForestSites
        #ForestSiteLinks
        #ForestSiteLinksConnections
        'ForestRoles'
        'ForestOptionalFeatures'
        #ForestSubnets
        'ForestOrphanedAdmins'
        #ForestTombstoneLifetime
        #ForestTrusts
        #ForestConfigurationPartitionOwners
        #ForestConfigurationPartitionOwnersContainers
        'DomainLDAP'
        #DomainDomainControllers
        #DomainRoles
        #DomainWellKnownFolders
        'DomainPasswordComplexity'
        'DomainSecurityComputers'
        #DomainGroupPolicyAssesment
        #DomainGroupPolicyPermissions
        #DomainGroupPolicyPermissionConsistency
        #DomainGroupPolicyOwner
        #DomainGroupPolicyADM
        #DomainGroupPolicySysvol
        'DomainOrphanedForeignSecurityPrincipals'
        'DomainOrganizationalUnitsEmpty'
        'DomainOrganizationalUnitsProtected'
        #DomainNetLogonOwner
        #'DomainKerberosAccountAge'
        'DomainDNSScavengingForPrimaryDNSServer'
        #DomainDNSForwaders
        #DomainDnsZonesAging
        #DomainSecurityGroupsAccountOperators
        #DomainSecurityGroupsSchemaAdmins
        #DomainSecurityUsers
        #DomainSecurityUsersAcccountAdministrator
        #DomainSecurityKRBGT
        'DomainSysVolDFSR'
        #DomainDNSZonesForest0ADEL
        #DomainDNSZonesDomain0ADEL
        #DomainDHCPAuthorized
        #DomainComputersUnsupported
        #DomainComputersUnsupportedMainstream
        #DomainExchangeUsers
        #DomainDuplicateObjects
        'DCInformation'
        #DCWindowsRemoteManagement
        #DCEventLogs
        #DCOperatingSystem
        #DCServices
        #DCLDAP
        #DCLDAPInsecureBindings
        #DCPingable
        #DCPorts
        #DCRDPPorts
        'DCRDPSecurity'
        'DCSMBShares'
        #'DomainGroupPolicyMissingPermissions'
        #DCDiskSpace
        #DCTimeSettings
        #DCTimeSynchronizationInternal
        #DCTimeSynchronizationExternal
        #DCNetworkCardSettings
        'DCWindowsRolesAndFeatures'
        'DCWindowsUpdates'
        #DCDnsResolveInternal
        #DCDnsResolveExternal
        #DCDnsNameServes
        'DCSMBProtocols'
        #DCSMBShares
        #DCSMBSharesPermissions
        #DCDFS
        'DCNTDSParameters'
        #DCGroupPolicySYSVOLDC
        #DCLanManagerSettings
        #DCDiagnostics
        #DCLanManServer
        #DCMSSLegacy
        #DCFileSystem
        #DCNetSessionEnumeration
        #DCServiceWINRM
        #DCUNCHardenedPaths
        #DCDNSForwaders
    )

    #$TestResults = Invoke-Testimo -HideSteps -ExtendedResults -Sources $Sources -ReportPath ".\Innovative_ADTestSummary_$((Get-Date -Format MMM-dd-yyyy).ToString()).html"
    ### Run All: 
    Invoke-Testimo -HideSteps -ReturnResults -ExtendedResults -ReportPath $ADHTOutfile
}
#endregion Functions

### Execute
If ($GetGPOReport) {
    Invoke-GPOZaurr -HideSteps -FilePath $GPOOutFile
} ElseIf ($GetADEvalWord) {
    Get-ADEvaltoWord
} ElseIf ($ADHealthReport) {
    Get-ADHealthTest
} ElseIf ($GetChangeReport) {
    Get-ChangeReport
}
