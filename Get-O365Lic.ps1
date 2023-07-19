Function Get-O365LicenseReport {
    #Using this script administrator can identify all licensed users with their assigned licenses, services, and its status.
    [CmdletBinding()]
    Param ([string]$UserNamesFile)
    Begin   {
        #FriendlyName list for license plan and service
        $FriendlyNameHash  = @{
            AAD_BASIC                          = 'Azure Active Directory Basic'
            AAD_PREMIUM                        = 'Azure Active Directory Premium'
            AAD_PREMIUM_P1                     = 'Azure Active Directory Premium P1'
            AAD_PREMIUM_P2                     = 'Azure Active Directory Premium P2'
            ADALLOM_O365                       = 'Office 365 Advanced Security Management'
            ADALLOM_STANDALONE                 = 'Microsoft Cloud App Security'
            ADALLOM_S_O365                     = 'POWER BI STANDALONE'
            ADALLOM_S_STANDALONE               = 'Microsoft Cloud App Security'
            ATA                                = 'Azure Advanced Threat Protection for Users'
            ATP_ENTERPRISE                     = 'Exchange Online Advanced Threat Protection'
            ATP_ENTERPRISE_FACULTY             = 'Exchange Online Advanced Threat Protection'
            BI_AZURE_P0                        = 'Power BI (free)'
            BI_AZURE_P1                        = 'Power BI Reporting and Analytics'
            BI_AZURE_P2                        = 'Power BI Pro'
            CCIBOTS_PRIVPREV_VIRAL             = 'Dynamics 365 AI for Customer Service Virtual Agents Viral SKU'
            CRMINSTANCE                        = 'Microsoft Dynamics CRM Online Additional Production Instance (Government Pricing)'
            CRMIUR                             = 'CRM for Partners'
            CRMPLAN1                           = 'Microsoft Dynamics CRM Online Essential (Government Pricing)'
            CRMPLAN2                           = 'Dynamics CRM Online Plan 2'
            CRMSTANDARD                        = 'CRM Online'
            CRMSTORAGE                         = 'Microsoft Dynamics CRM Online Additional Storage'
            CRMTESTINSTANCE                    = 'CRM Test Instance'
            DESKLESS                           = 'Microsoft StaffHub'
            DESKLESSPACK                       = 'Office 365 (Plan K1)'
            DESKLESSPACK_GOV                   = 'Microsoft Office 365 (Plan K1) for Government'
            DESKLESSPACK_YAMMER                = 'Office 365 Enterprise K1 with Yammer'
            DESKLESSWOFFPACK                   = 'Office 365 (Plan K2)'
            DESKLESSWOFFPACK_GOV               = 'Microsoft Office 365 (Plan K2) for Government'
            DEVELOPERPACK                      = 'Office 365 Enterprise E3 Developer'
            DEVELOPERPACK_E5                   = 'Microsoft 365 E5 Developer(without Windows and Audio Conferencing)'
            DMENTERPRISE                       = 'Microsoft Dynamics Marketing Online Enterprise'
            DYN365_ENTERPRISE_CUSTOMER_SERVICE = 'Dynamics 365 for Customer Service Enterprise Edition'
            DYN365_ENTERPRISE_P1_IW            = 'Dynamics 365 P1 Trial for Information Workers'
            DYN365_ENTERPRISE_PLAN1            = 'Dynamics 365 Plan 1 Enterprise Edition'
            DYN365_ENTERPRISE_SALES            = 'Dynamics 365 for Sales Enterprise Edition'
            DYN365_ENTERPRISE_SALES_CUSTOMERSERVICE = 'Dynamics 365 for Sales and Customer Service Enterprise Edition'
            DYN365_ENTERPRISE_TEAM_MEMBERS     = 'Dynamics 365 for Team Members Enterprise Edition'
            DYN365_FINANCIALS_BUSINESS_SKU     = 'Dynamics 365 for Financials Business Edition'
            DYN365_MARKETING_USER              = 'Dynamics 365 for Marketing USL'
            DYN365_MARKETING_APP               = 'Dynamics 365 Marketing'
            DYN365_SALES_INSIGHTS              = 'Dynamics 365 AI for Sales'
            D365_SALES_PRO                     = 'Dynamics 365 for Sales Professional'
            Dynamics_365_for_Operations        = 'Dynamics 365 Unf Ops Plan Ent Edition'
            ECAL_SERVICES                      = 'ECAL'
            EMS                                = 'Enterprise Mobility + Security E3'
            EMSPREMIUM                         = 'Enterprise Mobility + Security E5'
            ENTERPRISEPACK                     = 'Office 365 Enterprise E3'
            ENTERPRISEPACKLRG                  = 'Office 365 Enterprise E3 LRG'
            ENTERPRISEPACKWITHOUTPROPLUS       = 'Office 365 Enterprise E3 without ProPlus Add-on'
            ENTERPRISEPACK_B_PILOT             = 'Office 365 (Enterprise Preview)'
            ENTERPRISEPACK_FACULTY             = 'Office 365 (Plan A3) for Faculty'
            ENTERPRISEPACK_GOV                 = 'Microsoft Office 365 (Plan G3) for Government'
            ENTERPRISEPACK_STUDENT             = 'Office 365 (Plan A3) for Students'
            ENTERPRISEPREMIUM                  = 'Enterprise E5 (with Audio Conferencing)'
            ENTERPRISEPREMIUM_NOPSTNCONF       = 'Enterprise E5 (without Audio Conferencing)'
            ENTERPRISEWITHSCAL                 = 'Office 365 Enterprise E4'
            ENTERPRISEWITHSCAL_FACULTY         = 'Office 365 (Plan A4) for Faculty'
            ENTERPRISEWITHSCAL_GOV             = 'Microsoft Office 365 (Plan G4) for Government'
            ENTERPRISEWITHSCAL_STUDENT         = 'Office 365 (Plan A4) for Students'
            EOP_ENTERPRISE                     = 'Exchange Online Protection'
            EOP_ENTERPRISE_FACULTY             = 'Exchange Online Protection for Faculty'
            EQUIVIO_ANALYTICS                  = 'Office 365 Advanced Compliance'
            EQUIVIO_ANALYTICS_FACULTY          = 'Office 365 Advanced Compliance for Faculty'
            ESKLESSWOFFPACK_GOV                = 'Microsoft Office 365 (Plan K2) for Government'
            EXCHANGEARCHIVE                    = 'Exchange Online Archiving'
            EXCHANGEARCHIVE_ADDON              = 'Exchange Online Archiving for Exchange Online'
            EXCHANGEDESKLESS                   = 'Exchange Online Kiosk'
            EXCHANGEENTERPRISE                 = 'Exchange Online Plan 2'
            EXCHANGEENTERPRISE_FACULTY         = 'Exch Online Plan 2 for Faculty'
            EXCHANGEENTERPRISE_GOV             = 'Microsoft Office 365 Exchange Online (Plan 2) only for Government'
            EXCHANGEESSENTIALS                 = 'Exchange Online Essentials'
            EXCHANGESTANDARD                   = 'Office 365 Exchange Online Only'
            EXCHANGESTANDARD_GOV               = 'Microsoft Office 365 Exchange Online (Plan 1) only for Government'
            EXCHANGESTANDARD_STUDENT           = 'Exchange Online (Plan 1) for Students'
            EXCHANGETELCO                      = 'Exchange Online POP'
            EXCHANGE_ANALYTICS                 = 'Microsoft MyAnalytics'
            EXCHANGE_L_STANDARD                = 'Exchange Online (Plan 1)'
            EXCHANGE_S_ARCHIVE_ADDON_GOV       = 'Exchange Online Archiving'
            EXCHANGE_S_DESKLESS                = 'Exchange Online Kiosk'
            EXCHANGE_S_DESKLESS_GOV            = 'Exchange Kiosk'
            EXCHANGE_S_ENTERPRISE              = 'Exchange Online (Plan 2) Ent'
            EXCHANGE_S_ENTERPRISE_GOV          = 'Exchange Plan 2G'
            EXCHANGE_S_ESSENTIALS              = 'Exchange Online Essentials'
            EXCHANGE_S_FOUNDATION              = 'Exchange Foundation for certain SKUs'
            EXCHANGE_S_STANDARD                = 'Exchange Online (Plan 2)'
            EXCHANGE_S_STANDARD_MIDMARKET      = 'Exchange Online (Plan 1)'
            FLOW_FREE                          = 'Microsoft Flow (Free)'
            FLOW_O365_P2                       = 'Flow for Office 365'
            FLOW_O365_P3                       = 'Flow for Office 365'
            FLOW_P1                            = 'Microsoft Flow Plan 1'
            FLOW_P2                            = 'Microsoft Flow Plan 2'
            FORMS_PLAN_E3                      = 'Microsoft Forms (Plan E3)'
            FORMS_PLAN_E5                      = 'Microsoft Forms (Plan E5)'
            INFOPROTECTION_P2                  = 'Azure Information Protection Premium P2'
            INTUNE_A                           = 'Windows Intune Plan A'
            INTUNE_A_VL                        = 'Intune (Volume License)'
            INTUNE_O365                        = 'Mobile Device Management for Office 365'
            INTUNE_STORAGE                     = 'Intune Extra Storage'
            IT_ACADEMY_AD                      = 'Microsoft Imagine Academy'
            LITEPACK                           = 'Office 365 (Plan P1)'
            LITEPACK_P2                        = 'Office 365 Small Business Premium'
            LOCKBOX                            = 'Customer Lockbox'
            LOCKBOX_ENTERPRISE                 = 'Customer Lockbox'
            MCOCAP                             = 'Command Area Phone'
            MCOEV                              = 'Skype for Business Cloud PBX'
            MCOIMP                             = 'Skype for Business Online (Plan 1)'
            MCOLITE                            = 'Lync Online (Plan 1)'
            MCOMEETADV                         = 'PSTN conferencing'
            MCOPLUSCAL                         = 'Skype for Business Plus CAL'
            MCOPSTN1                           = 'Skype for Business Pstn Domestic Calling'
            MCOPSTN2                           = 'Skype for Business Pstn Domestic and International Calling'
            MCOSTANDARD                        = 'Skype for Business Online Standalone Plan 2'
            MCOSTANDARD_GOV                    = 'Lync Plan 2G'
            MCOSTANDARD_MIDMARKET              = 'Lync Online (Plan 1)'
            MCVOICECONF                        = 'Lync Online (Plan 3)'
            MDM_SALES_COLLABORATION            = 'Microsoft Dynamics Marketing Sales Collaboration'
            MEE_FACULTY                        = 'Minecraft Education Edition Faculty'
            MEE_STUDENT                        = 'Minecraft Education Edition Student'
            MEETING_ROOM                       = 'Meeting Room'
            MFA_PREMIUM                        = 'Azure Multi-Factor Authentication'
            MICROSOFT_BUSINESS_CENTER          = 'Microsoft Business Center'
            MICROSOFT_REMOTE_ASSIST            = 'Dynamics 365 Remote Assist'
            MIDSIZEPACK                        = 'Office 365 Midsize Business'
            MINECRAFT_EDUCATION_EDITION        = 'Minecraft Education Edition Faculty'
            'MS-AZR-0145P'                     = 'Azure'
            MS_TEAMS_IW                        = 'Microsoft Teams'
            NBPOSTS                            = 'Microsoft Social Engagement Additional 10k Posts (minimum 100 licenses) (Government Pricing)'
            NBPROFESSIONALFORCRM               = 'Microsoft Social Listening Professional'
            O365_BUSINESS                      = 'Microsoft 365 Apps for business'
            O365_BUSINESS_ESSENTIALS           = 'Microsoft 365 Business Basic'
            O365_BUSINESS_PREMIUM              = 'Microsoft 365 Business Standard'
            OFFICE365_MULTIGEO                 = 'Multi-Geo Capabilities in Office 365'
            OFFICESUBSCRIPTION                 = 'Microsoft 365 Apps for enterprise'
            OFFICESUBSCRIPTION_FACULTY         = 'Office 365 ProPlus for Faculty'
            OFFICESUBSCRIPTION_GOV             = 'Office ProPlus'
            OFFICESUBSCRIPTION_STUDENT         = 'Office ProPlus Student Benefit'
            OFFICE_FORMS_PLAN_2                = 'Microsoft Forms (Plan 2)'
            OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ = 'Office ProPlus'
            ONEDRIVESTANDARD                   = 'OneDrive'
            PAM_ENTERPRISE                     = 'Exchange Primary Active Manager'
            PLANNERSTANDALONE                  = 'Planner Standalone'
            POWERAPPS_INDIVIDUAL_USER          = 'Microsoft PowerApps and Logic flows'
            POWERAPPS_O365_P2                  = 'PowerApps'
            POWERAPPS_O365_P3                  = 'PowerApps for Office 365'
            POWERAPPS_VIRAL                    = 'PowerApps (Free)'
            POWERFLOW_P1                       = 'Microsoft PowerApps Plan 1'
            POWERFLOW_P2                       = 'Microsoft PowerApps Plan 2'
            POWER_BI_ADDON                     = 'Office 365 Power BI Addon'
            POWER_BI_INDIVIDUAL_USE            = 'Power BI Individual User'
            POWER_BI_INDIVIDUAL_USER           = 'Power BI for Office 365 Individual'
            POWER_BI_PRO                       = 'Power BI Pro'
            POWER_BI_STANDALONE                = 'Power BI Standalone'
            POWER_BI_STANDARD                  = 'Power-BI Standard'
            PREMIUM_ADMINDROID                 = 'AdminDroid Office 365 Reporter'
            PROJECTCLIENT                      = 'Project Professional'
            PROJECTESSENTIALS                  = 'Project Lite'
            PROJECTONLINE_PLAN_1               = 'Project Online (Plan 1)'
            PROJECTONLINE_PLAN_1_FACULTY       = 'Project Online for Faculty Plan 1'
            PROJECTONLINE_PLAN_1_STUDENT       = 'Project Online for Students Plan 1'
            PROJECTONLINE_PLAN_2               = 'Project Online and PRO'
            PROJECTONLINE_PLAN_2_FACULTY       = 'Project Online for Faculty Plan 2'
            PROJECTONLINE_PLAN_2_STUDENT       = 'Project Online for Students Plan 2'
            PROJECTPREMIUM                     = 'Project Online Premium'
            PROJECTPROFESSIONAL                = 'Project Online Pro'
            PROJECTWORKMANAGEMENT              = 'Office 365 Planner Preview'
            PROJECT_CLIENT_SUBSCRIPTION        = 'Project Pro for Office 365'
            PROJECT_ESSENTIALS                 = 'Project Lite'
            PROJECT_MADEIRA_PREVIEW_IW_SKU     = 'Dynamics 365 for Financials for IWs'
            PROJECT_ONLINE_PRO                 = 'Project Online Plan 3'
            RIGHTSMANAGEMENT                   = 'Azure Rights Management Premium'
            RIGHTSMANAGEMENT_ADHOC             = 'Windows Azure Rights Management'
            RIGHTSMANAGEMENT_STANDARD_FACULTY  = 'Azure Rights Management for faculty'
            RIGHTSMANAGEMENT_STANDARD_STUDENT  = 'Information Rights Management for Students'
            RMS_S_ENTERPRISE                   = 'Azure Active Directory Rights Management'
            RMS_S_ENTERPRISE_GOV               = 'Windows Azure Active Directory Rights Management'
            RMS_S_PREMIUM                      = 'Azure Information Protection Plan 1'
            RMS_S_PREMIUM2                     = 'Azure Information Protection Premium P2'
            SCHOOL_DATA_SYNC_P1                = 'School Data Sync (Plan 1)'
            SHAREPOINTDESKLESS                 = 'SharePoint Online Kiosk'
            SHAREPOINTDESKLESS_GOV             = 'SharePoint Online Kiosk'
            SHAREPOINTENTERPRISE               = 'SharePoint Online (Plan 2)'
            SHAREPOINTENTERPRISE_EDU           = 'SharePoint Plan 2 for EDU'
            SHAREPOINTENTERPRISE_GOV           = 'SharePoint Plan 2G'
            SHAREPOINTENTERPRISE_MIDMARKET     = 'SharePoint Online (Plan 1)'
            SHAREPOINTLITE                     = 'SharePoint Online (Plan 1)'
            SHAREPOINTPARTNER                  = 'SharePoint Online Partner Access'
            SHAREPOINTSTANDARD                 = 'SharePoint Online Plan 1'
            SHAREPOINTSTANDARD_EDU             = 'SharePoint Plan 1 for EDU'
            SHAREPOINTSTORAGE                  = 'SharePoint Online Storage'
            SHAREPOINTWAC                      = 'Office Online'
            SHAREPOINTWAC_EDU                  = 'Office Online for Education'
            SHAREPOINTWAC_GOV                  = 'Office Online for Government'
            SHAREPOINT_PROJECT                 = 'SharePoint Online (Plan 2) Project'
            SHAREPOINT_PROJECT_EDU             = 'Project Online Service for Education'
            SMB_APPS                           = 'Business Apps (free)'
            SMB_BUSINESS                       = 'Office 365 Business'
            SMB_BUSINESS_ESSENTIALS            = 'Office 365 Business Essentials'
            SMB_BUSINESS_PREMIUM               = 'Office 365 Business Premium'
            'SPZA IW'                          = 'Microsoft PowerApps Plan 2 Trial'
            SPB                                = 'Microsoft 365 Business'
            SPE_E3                             = 'Secure Productive Enterprise E3'
            SQL_IS_SSIM                        = 'Power BI Information Services'
            STANDARDPACK                       = 'Office 365 (Plan E1)'
            STANDARDPACK_FACULTY               = 'Office 365 (Plan A1) for Faculty'
            STANDARDPACK_GOV                   = 'Microsoft Office 365 (Plan G1) for Government'
            STANDARDPACK_STUDENT               = 'Office 365 (Plan A1) for Students'
            STANDARDWOFFPACK                   = 'Office 365 (Plan E2)'
            STANDARDWOFFPACKPACK_FACULTY       = 'Office 365 (Plan A2) for Faculty'
            STANDARDWOFFPACKPACK_STUDENT       = 'Office 365 (Plan A2) for Students'
            STANDARDWOFFPACK_FACULTY           = 'Office 365 Education E1 for Faculty'
            STANDARDWOFFPACK_GOV               = 'Microsoft Office 365 (Plan G2) for Government'
            STANDARDWOFFPACK_IW_FACULTY        = 'Office 365 Education for Faculty'
            STANDARDWOFFPACK_IW_STUDENT        = 'Office 365 Education for Students'
            STANDARDWOFFPACK_STUDENT           = 'Microsoft Office 365 (Plan A2) for Students'
            STANDARD_B_PILOT                   = 'Office 365 (Small Business Preview)'
            STREAM                             = 'Microsoft Stream'
            STREAM_O365_E3                     = 'Microsoft Stream for O365 E3 SKU'
            STREAM_O365_E5                     = 'Microsoft Stream for O365 E5 SKU'
            SWAY                               = 'Sway'
            TEAMS1                             = 'Microsoft Teams'
            TEAMS_COMMERCIAL_TRIAL             = 'Microsoft Teams Commercial Cloud Trial'
            THREAT_INTELLIGENCE                = 'Office 365 Threat Intelligence'
            VIDEO_INTEROP                      = 'Skype Meeting Video Interop for Skype for Business'
            VISIOCLIENT                        = 'Visio Online Plan 2'
            VISIOONLINE_PLAN1                  = 'Visio Online Plan 1'
            VISIO_CLIENT_SUBSCRIPTION          = 'Visio Pro for Office 365'
            WACONEDRIVEENTERPRISE              = 'OneDrive for Business (Plan 2)'
            WACONEDRIVESTANDARD                = 'OneDrive for Business with Office Online'
            WACSHAREPOINTSTD                   = 'Office Online STD'
            WHITEBOARD_PLAN3                   = 'White Board (Plan 3)'
            WIN_DEF_ATP                        = 'Windows Defender Advanced Threat Protection'
            WIN10_PRO_ENT_SUB                  = 'Windows 10 Enterprise E3'
            WIN10_VDA_E3                       = 'Windows E3'
            WIN10_VDA_E5                       = 'Windows E5'
            WINDOWS_STORE                      = 'Windows Store'
            YAMMER_EDU                         = 'Yammer for Academic'
            YAMMER_ENTERPRISE                  = 'Yammer for the Starship Enterprise'
            YAMMER_ENTERPRISE_STANDALONE       = 'Yammer Enterprise'
            YAMMER_MIDSIZE                     = 'Yammer'
        }
        $ServiceArray      = @(
            'MCOEV', 
            'Cloud PBX', 
            'MCOPSTN2', 
            'PSTN International', 
            'mcomeetadv', 
            'PSTN Conf', 
            '^mco', 
            'Skype', 
            'Voice', 
            'Skype', 
            'microsoftcommunicationonline', 
            'Skype',
            '^rms', 
            'Azure Rights Management', 
            'officesubscription', 
            'Office Pro+', 
            'crm', 
            'CRM', 
            'onedrive', 
            'One Drive', 
            'yammer', 
            'Yammer', 
            'sway', 
            'Sway', 
            'multifactorservice', 
            'Multi Factor Service',
            'mfa', 
            'Multi Factor Service', 
            'aadpremiumservice', 
            'AAD Premium Service', 
            'sco', 
            'SCO', 
            'projectworkmanagement', 
            'Project Work Mgmt', 
            'netbreeze', 
            'NetBreeze', 
            'dynamicsmarketing', 
            'Dynamics Marketing',
            'adallom', 
            'Cloud App Security', 
            'teams', 
            'Teams', 
            'powerapps', 
            'Power Apps', 
            '^flow', 
            'Flow', 
            '^processsimple', 
            'Flow', 
            'intune', 
            'Moblile Device Mgmt', 
            'atp', 
            'ATP', 
            'bi_azure_p2', 
            'Power BI Pro', 
            'equivio', 
            'Equivio', 
            'lockbox', 
            'Lockbox', 
            'exchange_analytics', 
            'Exch Analytics', 
            'forms', 
            'Forms', 
            'EXCHANGE_S_ARCHIVE', 
            'Exch Archive', 
            'VISIOCLIENT', 
            'Visio Pro', 
            'PROJECTCLIENT',
            'Project Pro', 
            'todo', 
            'To-Do', 
            'to-do', 
            'To-Do', 
            'deskless', 
            'Deskless', 
            'stream', 
            'Stream', 
            'THREAT_INTELLIGENCE', 
            'Threat Intelligence', 
            'SHAREPOINTWAC', 
            'Office Web Apps', 
            '^exchange', 
            'Exchange', 
            '^share', 
            'SharePoint', 
            'office', 
            'Office', 
            '^powerbi', 
            'Power BI', 
            'azureanalysis', 
            'Power BI'
        )

        #region output files
        $Path              = 'C:\down\Scripting\O365 License Report'
        $DateTime          = (Get-Date -Format 'yyyy-MMM-dd-ddd').ToString()
        $ExcelOutput       = $Path + "\O365UserLicenseReport_$DateTime.xlsx"
        $CSVName           = "DetailedO365UserLicenseReport_$DateTime.csv"
        $SimName           = "SimpleO365UserLicenseReport_$DateTime.csv"
        $ExportCSV         = $Path + '\' + $CSVName
        $ExportSimpleCSV   = $Path + '\' + $SimName
        $outs              = @()
        $outs             += @{
            Path = $Path
            Name = $CSVName
            Full = $ExportCSV
        }
        $outs             += @{
            Path = $Path
            Name = $SimName
            Full = $ExportSimpleCSV
        }

        ForEach ($tuo in $outs) {
            If (-not (Test-Path -Path $tuo.Full)) {
                New-Item -Path $tuo.Path -Name $tuo.Name -Type File
                Write-Host "Created new file"
            } Else {
                Write-Host "File already exists"
            }
        }
        #endregion output files

        #region Progress Meter Set up
        $Act      = 'Enumerating Users'
        $Progress = @{
            ID               = 1
            Activity         = $Act
            CurrentOperation = 'Loading'
            PercentComplete  = 0
        }
        #endregion Progress Meter Set up

        #region Functions
        Function Convert-HTMLTableToArray        {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU / Service plans info (GUID, String ID, Product Name).
                .DESCRIPTION
                Get last Microsoft Office 365 SKU / Service plans info (GUID, String ID, Product Name).
                Resolve SKU and Service Plans from GUID, String ID, Name.
                Get all SKUs that include a Service Plan.
                Cache last catalog from Microsoft locally.
                .EXAMPLE
                Get-O365SKUCatalog
                Get last Microsoft Office 365 SKU / Service Plans catalog from Microsoft website and return an array of custom psobjects
                .EXAMPLE
                Get-O365SKUinfo
                Get SKU info using a GUID, String ID or Product Name
                .EXAMPLE
                Get-O365SKUInfoFromPlan
                Get all SKU and related info including a Service Plan (using GUID, String ID or Plan Name)
                .EXAMPLE
                Get-O365Planinfo
                Get Service Plan info using a GUID, String ID or Plan Name
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory = $true)]
                $HTMLObject,
                [Parameter(Mandatory = $true)]
                [int]$TableNumber
            )
            Process {
                $tables = @($HTMLObject.getElementsByTagName('TABLE'))
                $table  = $tables[$TableNumber]
                $titles = @()
                $rows   = @($table.Rows)
                ForEach ($row in $rows) {
                    $cells = @($row.Cells)
                    If ($cells[0].tagName -eq 'TH') {
                        $titles = @($cells | ForEach-Object {('' + $_.InnerText).Trim()})
                        continue
                    }
                    If (-not ($titles)) {
                        $titles = @(1..($cells.Count + 2) | ForEach-Object {"P$_"})
                    }
                    $resultObject = [Ordered]@{}
                    For ($counter = 0; $counter -lt $cells.Count; $counter++) {
                        $title = $titles[$counter]
                        If (-not ($title)) {continue}
                        $resultObject[$title] = ('' + $cells[$counter].InnerText).Trim()
                    }
                    [PSCustomObject]$resultObject
                }
            }
        }

        Function Get-O365SKUCatalog              {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU / Service Plans information from Microsoft Website
                .DESCRIPTION
                Get last Microsoft Office 365 SKU / Service Plans information from Microsoft Website
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                .PARAMETER ServicePlansInfoAsStrings
                -ServicePlansInfoAsStrings [switch]
                add a new property 'Service plans included as strings' so the object could be easily exported to an external file like a CSV file.
                .PARAMETER AsGlobalVariable
                -AsGlobalVariable [switch]
                save objets into global variable O365SKUsInfos
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365SKUCatalog
                Get all MS O365 SKUs / Service Plans info
                .EXAMPLE
                Get-O365SKUCatalog -AsGlobalVariable
                Get all MS O365 SKUs / Service Plans info and save psobjets to $global:O365SKUsInfos
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$false)]
                [Switch]$ServicePlansInfoAsStrings,
                [Parameter(Mandatory=$false)]
                [Switch]$AsGlobalVariable
            )
            Process {
                #$script:URICatalog = "https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference"
                $script:URICatalog = 'https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/enterprise-users/licensing-service-plan-reference.md'
                $script:tempfile   = [IO.Path]::GetTempFileName()
                Write-Verbose -Message "Microsoft O365 SKU catalog URL : $($script:URICatalog)"
                Write-Verbose -Message "Temporary html file : $($script:tempfile)"
                Try {
                    $request = Invoke-WebRequest -Uri $script:URICatalog -OutFile $script:tempfile -UseBasicParsing
                } Catch {
                    throw "Microsoft O365 SKU online catalog $($script:URICatalog) is not available. Please check your network / internet connection."
                }
                If (-not (Test-Path -Path $script:tempfile)) {
                    throw "not able to dowload licensing-service-plan-reference HTML content to $($script:tempfile)"
                } Else {
                    Write-Verbose -Message "Temporary html file $($script:tempfile) created successfully"
                }
                $htmlcontent = Get-Content -Raw -Path $script:tempfile
                Try {
                    $htmlobj = New-Object -ComObject 'HTMLFile'
                } Catch {
                    throw 'not able to create HTMLFile com object'
                }
                Try {
                    If ($host.Version.Major -gt 5) {
                        $encodedhtmlcontent = [Text.Encoding]::Unicode.GetBytes($htmlcontent)
                        $htmlobj.write($encodedhtmlcontent)
                    } Else {
                        $htmlobj.IHTMLDocument2_write($htmlcontent)
                    }
                } Catch {
                    throw "not able to create Com HTML object from temporary file $($script:tempfile)"
                }
                If ($htmlobj) {
                    $skuinfo = Convert-HTMLTableToArray -HTMLObject $htmlobj -TableNumber 1
                }
                $skuinfo
                ForEach ($sku in $skuinfo) {
                    If ($sku.'Service plans included') {
                        $tmpserviceplan     = $sku.'Service plans included'.split("`n")
                        $tmpserviceplanname = $sku.'Service plans included (friendly names)'.split("`n")
                        $resultserviceplan  = @()
                        For ($i=0;$i -le ($tmpserviceplan.count -1);$i++) {
                            $tmpstringid        = ($tmpserviceplan[$i]).substring(0,$tmpserviceplan[$i].length - 39)
                            $tmpguid            = ($tmpserviceplan[$i]).substring($tmpstringid.length,$tmpserviceplan[$i].length - $tmpstringid.length)
                            $tmpplanname        = ($tmpserviceplanname[$i]).substring(0,$tmpserviceplanname[$i].length - 39)
                            $resultserviceplan += [PSCustomObject]@{
                                'String ID' = $tmpstringid.replace(' ','')
                                'GUID'      = ((($tmpguid.replace('(','')).replace(')','')).replace(' ','')).replace("`r",'')
                                'Plan Name' = If (($tmpplanname.substring($tmpplanname.length - 1,1)) -eq ' ') {
                                    $tmpplanname.substring(0, $tmpplanname.length - 1)
                                } Else {
                                    $tmpplanname
                                }
                            }
                        }
                        If ($ServicePlansInfoAsStrings.IsPresent) {
                            $sku | Add-Member -NotePropertyName 'Service plans included as strings' -NotePropertyValue $sku.'Service plans included'
                        }
                        $sku.'Service plans included' = $resultserviceplan
                        $sku.PSObject.Properties.Remove('Service plans included (friendly names)')
                    }
                }
                If ($AsGlobalVariable.IsPresent) {
                    $script:O365SKUsInfos = $skuinfo
                    Write-Verbose -message 'Global Variable O365SKUsInfos set with SKUs Infos'
                }
                return $skuinfo
            }
        }
        $script:O365SKUsInfos = Get-O365SKUCatalog
        #$script:O365SKUsInfos | Select-Object -first 2 | Format-List

        Function Get-O365SKUinfo                 {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU information from Microsoft Website.
                .DESCRIPTION
                Get last Microsoft Office 365 SKU information from Microsoft Website.
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                You can search the SKU info based on its GUID, String ID or Product Name
                .PARAMETER GUID
                -GUID [GUID]
                search a SKU using its GUID
                .PARAMETER StringID
                -StringID [string]
                search a SKU using its StringID
                .PARAMETER ProductName
                -ProductName [string]
                search a SKU using its Product Name
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365SKUinfo -GUID 8f0c5670-4e56-4892-b06d-91c085d7004f
                Get SKU info based on GUID 8f0c5670-4e56-4892-b06d-91c085d7004f
                .EXAMPLE
                Get-O365SKUinfo -ProductName "Microsoft 365 F1"
                Get SKU info of "Microsoft 365 F1"
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$false)]
                [guid]$GUID,
                [Parameter(Mandatory=$false)]
                [ValidateNotNullOrEmpty()]
                [String]$StringID,
                [Parameter(Mandatory=$false)]
                [ValidateNotNullOrEmpty()]
                [String]$ProductName
            )
            Process {
                If (-not $script:O365SKUsInfos) {
                    Get-O365SKUCatalog -AsGlobalVariable | out-null
                }
                If ($GUID) {
                    $script:O365SKUsInfos | Where-Object {$_.GUID -eq $GUID}
                } ElseIf ($StringID) {
                    $script:O365SKUsInfos | Where-Object {$_.'String ID' -eq $StringID}
                } ElseIf ($ProductName) {
                    $script:O365SKUsInfos | Where-Object {$_.'Product Name' -eq $ProductName}
                } Else {
                    throw 'please use GUID or StringID or ProductName parameters'
                }
            }
        }

        Function Get-O365SKUInfoFromPlan         {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 SKU information that included a specific Service Plan.
                .DESCRIPTION
                Get last Microsoft Office 365 SKU information that included a specific Service Plan.
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                You can search the Service Plan info based on its GUID, String ID or Plan Name
                .PARAMETER GUID
                -GUID [GUID]
                search a SP using its GUID
                .PARAMETER StringID
                -StringID [string]
                search a SP using its StringID
                .PARAMETER PlanName
                -PlanName [string]
                search a SP using its Plan Name
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365SKUInfoFromPlan -GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                Get all SKU including Service Plan GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                .EXAMPLE
                Get-O365SKUInfoFromPlan -PlanName "AZURE ACTIVE DIRECTORY PREMIUM P1"
                Get all SKU including Service Plan "AZURE ACTIVE DIRECTORY PREMIUM P1"
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$false)]
                [guid]$GUID,
                [Parameter(Mandatory=$false)]
                [ValidateNotNullOrEmpty()]
                [String]$StringID,
                [Parameter(Mandatory=$false)]
                [ValidateNotNullOrEmpty()]
                [String]$PlanName
            )
            Process {
                If (-not $script:O365SKUsInfos) {
                    Get-O365SKUCatalog -AsGlobalVariable | out-null
                }
                If ($GUID) {
                    $script:O365SKUsInfos | Where-Object {$_.'Service plans included'.GUID -contains $GUID}
                } ElseIf ($StringID) {
                    $script:O365SKUsInfos | Where-Object {$_.'Service plans included'.'String ID' -contains $StringID}
                } ElseIf ($PlanName) {
                    $script:O365SKUsInfos | Where-Object {$_.'Service plans included'.'Plan Name' -contains $PlanName}
                } Else {
                    throw 'please use GUID or StringID or PlanName parameters'
                }
            }
        }

        Function Get-O365Planinfo                {
            <#
                .SYNOPSIS
                Get last Microsoft Office 365 Service Plan information from Microsoft Website.
                .DESCRIPTION
                Get last Microsoft Office 365 Service Plan information from Microsoft Website.
                Downloaded from https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
                You can search the Service Plan info based on its GUID, String ID or Plan Name
                .PARAMETER GUID
                -GUID [GUID]
                search a SP using its GUID
                .PARAMETER StringID
                -StringID [string]
                search a SP using its StringID
                .PARAMETER PlanName
                -PlanName [string]
                search a SP using its Plan Name
                .OUTPUTS
                TypeName : pscustomobject
                .EXAMPLE
                Get-O365Planinfo -GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                Get Service Plan info based on GUID 41781fb2-bc02-4b7c-bd55-b576c07bb09d
                .EXAMPLE
                Get-O365Planinfo -PlanName "AZURE ACTIVE DIRECTORY PREMIUM P1"
                Get Service Plan info of "AZURE ACTIVE DIRECTORY PREMIUM P1"
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$false)]
                [guid]$GUID,
                [Parameter(Mandatory=$false)]
                [ValidateNotNullOrEmpty()]
                [String]$StringID,
                [Parameter(Mandatory=$false)]
                [ValidateNotNullOrEmpty()]
                [String]$PlanName
            )
            Process {
                If (-not $script:O365SKUsInfos) {
                    Get-O365SKUCatalog -AsGlobalVariable | out-null
                }
                If ($GUID) {
                    ($script:O365SKUsInfos | Where-Object {$_.'Service plans included'.GUID -contains $GUID})[0].'Service plans included' | 
                    Where-Object {$_.GUID -eq $GUID}
                } ElseIf ($StringID) {
                    ($script:O365SKUsInfos | Where-Object {$_.'Service plans included'.'String ID' -contains $StringID})[0].'Service plans included' | 
                    Where-Object {$_.'String ID' -eq $StringID}
                } ElseIf ($PlanName) {
                    ($script:O365SKUsInfos | Where-Object {$_.'Service plans included'.'Plan Name' -contains $PlanName})[0].'Service plans included' | 
                    Where-Object {$_.'Plan Name' -eq $PlanName}
                } Else {
                    throw 'please use GUID or StringID or PlanName parameters'
                }
            }
        }

        Function UserHasLicenseAssignedDirectly  {
            Param (
                [Microsoft.Online.Administration.User]$user, 
                [string]$skuId
            )

            ForEach ($license in $user.Licenses) {
                ### We look for the specific license SKU in all licenses assigned to the user
                If ($license.AccountSkuId -ieq $skuId) {
                    # GroupsAssigningLicense contains a collection of IDs of objects assigning the license
                    # This could be a group object or a user object (contrary to what the name suggests)
                    # If the collection is empty, this means the license is assigned directly - this is the case for users who have never been licensed via groups in the past
                    If ($license.GroupsAssigningLicense.Count -eq 0) {
                        return $true
                    }

                    # If the collection contains the ID of the user object, this means the license is assigned directly
                    # Note: the license may also be assigned through one or more groups in addition to being assigned directly
                    ForEach ($assignmentSource in $license.GroupsAssigningLicense) {
                        If ($assignmentSource -ieq $user.ObjectId) {
                            return $true
                        }
                    }
                    return $false
                }
            }
            return $false
        }

        #Returns TRUE if the user is inheriting the license from a group
        Function UserHasLicenseAssignedFromGroup {
            Param (
                [Microsoft.Online.Administration.User]$user, 
                [string]$skuId
            )

            ForEach ($license in $user.Licenses) {
                # We look for the specific license SKU in all licenses assigned to the user
                If ($license.AccountSkuId -ieq $skuId) {
                    # GroupsAssigningLicense contains a collection of IDs of objects assigning the license
                    # This could be a group object or a user object (contrary to what the name suggests)
                    ForEach ($assignmentSource in $license.GroupsAssigningLicense) {
                        # If the collection contains at least one ID not matching the user ID this means that the license is inherited from a group.
                        # Note: the license may also be assigned directly in addition to being inherited
                        If ($assignmentSource -ine $user.ObjectId) {
                            return $true
                        }
                    }
                    return $false
                }
            }
            return $false
        }

        Function script:Get_UsersLicenseInfo     {
            $s                                    = ', '
            $LicensePlanWithEnabledService        = ''
            $FriendlyNameOfLicensePlanWithService = ''
            $upn                                  = $_.userprincipalname
            $Country                              = $_.Country
            If ([string]$Country -eq '') {$Country = '-'}
            Write-Progress -Id 2 -ParentId 1 -Activity "`n     Exported user count: $LicensedUserCount Currently Processing: $upn"

            ### Get all asssigned SKU for current user
            $Skus                                 = $_.licenses.accountSKUId
            $LicenseCount                         = $skus.count
            $count                                = 0

            ### Loop through each SKUid
            ForEach ($Sku in $Skus) {
                #Convert Skuid to friendly name
                $LicenseItem = $Sku -Split ':' | Select-Object -Last 1
                $EasyName    = $FriendlyNameHash[$LicenseItem]
                If (!($EasyName)) {
                    $NamePrint = $LicenseItem
                } Else {
                    $NamePrint = $EasyName
                }
                
                #Get all services for current SKUId
                $Services    = $_.licenses[$count].ServiceStatus
                If (($Count -gt 0) -and ($count -lt $LicenseCount)) {
                    $LicensePlanWithEnabledService        = $LicensePlanWithEnabledService + $s
                    $FriendlyNameOfLicensePlanWithService = $FriendlyNameOfLicensePlanWithService + $s
                }
                $DisabledServiceCount                = 0
                $EnabledServiceCount                 = 0
                $serviceExceptDisabled               = ''
                $FriendlyNameOfServiceExceptDisabled = ''

                ForEach ($Service in $Services) {
                    $flag          = 0
                    $ServiceName   = $Service.ServicePlan.ServiceName
                    If ($service.ProvisioningStatus -eq 'Disabled') {
                        $DisabledServiceCount++
                    } Else {
                        $EnabledServiceCount++
                        If ($EnabledServiceCount -ne 1) {
                            $serviceExceptDisabled = $serviceExceptDisabled + $s
                        }
                        $serviceExceptDisabled = $serviceExceptDisabled + $ServiceName
                        $flag                  = 1
                    }
                    
                    #Convert ServiceName to friendly name
                    For ($i=0;$i -lt $ServiceArray.length;$i +=2) {
                        $ServiceFriendlyName = $ServiceName
                        $Condition           = $ServiceName -Match $ServiceArray[$i]
                        If ($Condition -eq 'True') {
                            $ServiceFriendlyName = $ServiceArray[$i+1]
                            break
                        }
                    }
                    If ($flag -eq 1) {
                        If ($EnabledServiceCount -ne 1) {
                            $FriendlyNameOfServiceExceptDisabled = $FriendlyNameOfServiceExceptDisabled + $s
                        }
                        $FriendlyNameOfServiceExceptDisabled = $FriendlyNameOfServiceExceptDisabled + $ServiceFriendlyName
                    }

                    #Store Service and its status in Hash table
                    $Result        = @{
                        'DisplayName'               = $_.Displayname
                        'UserPrinciPalName'         = $upn
                        'LicensePlan'               = $Licenseitem
                        'FriendlyNameofLicensePlan' = $nameprint
                        'ServiceName'               = $service.ServicePlan.ServiceName
                        'FriendlyNameofServiceName' = $serviceFriendlyName
                        'ProvisioningStatus'        = $service.ProvisioningStatus
                    }
                    $Results       = New-Object -TypeName PSObject -Property $Result
                    $resultsSelect = 'DisplayName', 'UserPrinciPalName', 'LicensePlan', 'FriendlyNameofLicensePlan', 'ServiceName', 'FriendlyNameofServiceName', 'ProvisioningStatus'

                    ### Export Findings (Append)
                    $Results | Select-Object -Property $resultsSelect | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8 -Delimiter ',' -Append
                }

                If ($Disabledservicecount -eq 0) {
                    $serviceExceptDisabled               = 'All services'
                    $FriendlyNameOfServiceExceptDisabled = 'All services'
                }
                $LicensePlanWithEnabledService        = $LicensePlanWithEnabledService        + $Licenseitem + '[' + $serviceExceptDisabled               + ']'
                $FriendlyNameOfLicensePlanWithService = $FriendlyNameOfLicensePlanWithService + $NamePrint   + '[' + $FriendlyNameOfServiceExceptDisabled + ']'
                #Increment SKUid count
                $count++
            }
            $Output  = @{
                Displayname                                = $_.Displayname
                UserPrincipalName                          = $upn
                Country                                    = $Country
                LicensePlanWithEnabledService              = $LicensePlanWithEnabledService
                FriendlyNameOfLicensePlanAndEnabledService = $FriendlyNameOfLicensePlanWithService
            }
            $Outputs = New-Object -TypeName PSObject -Property $output
            $Outputs | 
            Select-Object -Property Displayname, UserPrincipalName, Country, LicensePlanWithEnabledService, FriendlyNameOfLicensePlanAndEnabledService | 
            Export-Csv -path $ExportSimpleCSV -NoTypeInformation -Append
        }

        Function Get-EmailAddress                {
            [CmdletBinding()]
            Param (
                [Parameter(
                    Mandatory = $True, 
                    ValueFromPipeline = $True, 
                    ValueFromPipelineByPropertyName = $True, 
                    HelpMessage = 'find what user'
                )]
                [String[]]$EmailAddress
            )
            Begin   {
                Function IsValidEmail { 
                    Param ([string]$EmailAddress)
                    Try {
                        $null = [mailaddress]$EmailAddress
                        return $true
                    } Catch {
                        return $false
                    }
                }
                $Email = IsValidEmail -EmailAddress $EmailAddress
            }
            Process {
                ForEach ($address in $EmailAddress) {
                    If ($Email) {
                        Try {
                            $adSplat = @{
                                Filter      = "mail -like '*$address*' -or proxyAddresses -like '*$address*' -or userprincipalname -like '*$address*'"
                                Properties  = 'mail', 'proxyAddresses', 'userPrincipalName', 'Enabled'
                                ErrorAction = 'Stop'
                            }
                            Get-ADObject @adSplat
                        } Catch {
                            return $false
                        }
                    } Else {
                        Try {
                            Get-ADUser -Filter {anr -like $address} -Properties Mail, proxyAddresses, userPrincipalName, Enabled
                        } Catch {
                            return $false
                        }
                    }
                }
            }
        }
        #endregion Functions

        #Clean up session
        Get-PSSession | Remove-PSSession
        #Connect AzureAD from PowerShell
        Connect-MsolService
    }
    Process {
        #region Variables
        $Result            = ''
        $Results           = @()
        $output            =''
        $outputs           = @()

        #Get licensed user
        $LicensedUserCount = 0
        #endregion Variables

        ### Check for input file/Get users from input file
        If ([string]$UserNamesFile -ne '') {
            #We have an input file, read it into memory
            $UserNames = @()
            #$UserNames = Import-Csv -Header 'DisplayName' -Path $UserNamesFile

            ForEach ($item in $UserNames) {
                Get-MsolUser -UserPrincipalName $item.displayname | 
                Where-Object {$_.islicensed -eq 'true'} | 
                ForEach-Object {
                    Get_UsersLicenseInfo
                    $LicensedUserCount++
                }
            }
        } Else {
            #Get all licensed users
            $AllMSOLUsers = Get-MsolUser -All | 
                            Where-Object {$_.islicensed -eq 'true'} | 
                            Sort-Object -Property UserPrincipalName
            ForEach ($MSOLUser in $AllMSOLUsers) {
                ### Progress Meter
                Write-Progress -Id 1 -Activity 'Enumerating Users' -PercentComplete ([array]::IndexOf($AllMSOLUsers,$MSOLUser)/$AllMSOLUsers.Count*100) -Status "$($AllMSOLUsers.IndexOf($MSOLUser)) of $($AllMSOLUsers.Count)"

                $PSItem = $MSOLUser
                Get_UsersLicenseInfo
                $LicensedUserCount++
            }
        }
    }
    End     {
        #region Convert to Excel
        #region Import CSV
        $Files = Get-ChildItem -Path $Path | 
                 Where-Object {$_.Extension -eq '.csv'} | 
                 Sort-Object -Property LastWriteTime -Descending | 
                 Select-Object -First 2
        $Files | ForEach-Object {
            If ($_.Name -match 'Simple') {
                $sReport = Import-CSV -Path $_.FullName
            } ElseIf ($_.Name -match 'Detail') {
                $dReport = Import-CSV -Path $_.FullName
            }
        }
        $sReport.Count
        $dReport.Count
        #endregion Import CSV

        #region Get-ADUsers
        $AllADUsers = Get-ADUser -Filter * -Properties Enabled, MemberOf | 
                      Select-Object -Property UserPrincipalName, 
                                              Enabled, 
                                              @{
                                                  n = 'Profile'
                                                  e = {($_.Memberof | Where-Object {$_ -match 'Profile_'}).split(',')[0].split('=')[-1]}
                                              }
        #$AllADUsers | select -first 5
        #endregion Get-ADUsers

        $simplewAD = @()
        ForEach ($CSVUser in $sReport) {
            Write-Progress -Id 1 -Activity 'Enumerating CSV Users' -PercentComplete ([array]::IndexOf($sReport,$CSVUser)/$sReport.Count*100) -Status "$($sReport.IndexOf($CSVUser)) of $($sReport.Count)"

            If ($AllADUsers.UserPrincipalName -Contains $CSVUser.UserPrincipalName) {
                $Found      = $AllADUsers | Where-Object {$_.UserPrincipalName -eq $CSVUser.UserPrincipalName}
                $simplewAD += [PSCustomObject]@{
                    Displayname                                = $CSVUser.DisplayName
                    UserPrincipalName                          = $CSVUser.UserPrincipalName
                    OnPremEnabled                              = $Found.Enabled
                    OnPremProfile                              = If (-not [String]::IsNullOrWhiteSpace($Found.Profile)) {$Found.Profile} Else {'No Profile Membership'}
                    Country                                    = $CSVUser.Country
                    LicensePlanWithEnabledService              = $CSVUser.LicensePlanWithEnabledService
                    FriendlyNameOfLicensePlanAndEnabledService = $CSVUser.FriendlyNameOfLicensePlanAndEnabledService
                }
            } Else {
                $simplewAD += [PSCustomObject]@{
                    Displayname                                = $CSVUser.DisplayName
                    UserPrincipalName                          = $CSVUser.UserPrincipalName
                    OnPremEnabled                              = 'NotFound'
                    OnPremProfile                              = 'NotFound'
                    Country                                    = $CSVUser.Country
                    LicensePlanWithEnabledService              = $CSVUser.LicensePlanWithEnabledService
                    FriendlyNameOfLicensePlanAndEnabledService = $CSVUser.FriendlyNameOfLicensePlanAndEnabledService
                }
            }
        }
        #$simplewAD | ogv
        $dReport = Import-CSV -Path $ExportCSV
        Remove-Item -LiteralPath $ExcelOutput -ErrorAction SilentlyContinue
        $simplewAD | ConvertTo-Excel -Path $ExcelOutput -AutoSize -FreezeTopRow -ExcelWorkSheetName 'Simple License Report'   -TableStyle Light19  -Verbose
        $dReport   | ConvertTo-Excel -Path $ExcelOutput -AutoSize -FreezeTopRow -ExcelWorkSheetName 'Detailed License Report' -TableStyle Medium20 -Verbose
        #endregion Convert to Excel

        #region Open output file after execution
        Write-Host "Detailed report available in: $ExportCSV"
        Write-host "Simple report available in: $ExportSimpleCSV"
        $Prompt    = New-Object -ComObject wscript.shell
        $UserInput = $Prompt.popup('Do you want to open output files?', 0,'Open Files',4)
        If ($UserInput -eq 6) {
            Invoke-Item -Path "$ExportCSV"
            Start-Sleep -Seconds 5
            Invoke-Item -Path "$ExportSimpleCSV"
        }
        #endregion Open output file after execution
    }
}
Get-O365LicenseReport

<#
$Path = "$Env:TEMP\11.xlsx"
Remove-Item -LiteralPath $Path -ErrorAction SilentlyContinue
$myitems0 | ConvertTo-Excel -Path $Path -AutoFilter -AutoSize -ExcelWorkSheetName 'MyRandomName' -TableStyle Medium19 
$InvoiceEntry1 | ConvertTo-Excel -Path $Path -AutoFilter -AutoSize -ExcelWorkSheetName 'MyRandom1Name1' -TableStyle Light19
$InvoiceEntry1 | ConvertTo-Excel -Path $Path -AutoSize -ExcelWorkSheetName 'MyRandom1Name2' -TableStyle Medium20
$InvoiceEntry1 | ConvertTo-Excel -Path $Path -AutoSize -ExcelWorkSheetName 'MyRandom1Name3' -TableStyle Dark7
$InvoiceEntry1 | ConvertTo-Excel -Path $Path -AutoSize -ExcelWorkSheetName 'MyRandom1Name3' -TableStyle Medium9 -OpenWorkBook
#>
