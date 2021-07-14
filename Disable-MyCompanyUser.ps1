#Requires -Modules ActiveDirectory, MSOnline, ExchangeOnlineManagement

#AzureAD, Microsoft.Online.SharePoint.PowerShell, SkypeOnlineConnector, MicrosoftTeams
Function Disable-MyCompanyUser {
    <#
            .Synopsis
            This PowerShell module will disable a user's access to local Active Directory and disable access to Office 365.
            .DESCRIPTION
            The module Disabe-MyCompanyUser will disable the user account in local Active Directory by resetting the user's
            password.  It will also remove the Description/Login Script/Home Directory and Drive fields, remove from all
            Active Directory groupings except for Domain Users, and hide them from the Global Address List (GAL) on the local
            Exchange server.
 
            Disabling the user in Office 365, this module will move the user into the appropriate Active Directory grouping
            according to the license that they have to keep SharePoint/OneDrive and Exchange Online licensed in case a manager
            or another user will need access to those items.  They will also have all ActiveSync devices removed, ActiveSync/OWA/Outlook for Mobile
            disabled, signed out of all Office 365 sessions, sign in blocked, and their email forwarded as requested.
 
            Lastly, the module will connect to SharePoint Online to update the IT user list fields accordingly, then open an Excel
            file located on Accounting's SharePoint site to update the appropriate items there.  This file is used by Accounting
            for billback purposes to bill licenses to each property accordingly.
            .EXAMPLE
            Disable-MyCompanyUser -Identity 01ABC -RemoveLicense
            .EXAMPLE
            Disable-MyCompanyUser -Identity 01ABC -RemoveLicense -MFA
            .EXAMPLE
            Disable-MyCompanyUser -Identity 01ABC -Domain 'mydomain.com' -RemoveLicense -DisableActiveSync
            .EXAMPLE
            Disable-MyCompanyUser -Identity 01ABC -Domain 'mydomain.com' -RemoveLicense -DisableActiveSync -MFA
            .EXAMPLE
            Disable-MyCompanyUser -Identity 01ABC -RemoveLicense -DisableActiveSync -UpdateSharePointList -MFA
            .EXAMPLE
            Disable-MyCompanyUser -Identity 01ABC -RemoveLicense -DisableActiveSync -UpdateSharePointList -UpdateWorkbook -MFA
            .INPUTS
            -Identity
            -Domain (optional)
            .OUTPUTS
            .NOTES
            Thank you to Bradley Wyatt and others for creating the Connect-Office365.ps1.  I have modified the code on
            my local PowerShell Profile to connect using Exchange Online V2 module via Thumbprint.  Credit for their work can
            be found at the links below:
            Created on:     2/4/2019 10:42 PM
            Created by:     Bradley Wyatt
            E-Mail:         Brad@TheLazyAdministrator.com
            GitHub:         https://github.com/bwya77
            Website:        https://www.thelazyadministrator.com
            Organization:   Porcaro Stolarek Mete Partners; The Lazy Administrator
 
            Disconnect-O365Sessions is a custom Function that is in my PowerShell Profile to disconnect from on-prem or Office 365
            PowerShell sessions as needed.
            .FUNCTIONALITY
    #>
    [CmdletBinding ()]
    Param(
        [Parameter(Mandatory=$True,Position = 1,HelpMessage = "Enter the user's Username in the format 12ABC")][ValidateNotNullorEmpty()][Alias('Identity')][Alias('UserPrincipalName')][Alias('SamAccountName')][String]$Initials,
        [Parameter(Mandatory = $False,Position = 2,HelpMessage = 'Enter the domain name in the format:  mydomain.com')][ValidateNotNullorEmpty()][String]$Domain = "$((Get-ADForest).Name.split('.')[0]).com",
        [Switch]$RemoveLicense,
        [Switch]$RemoveMobileDevice,
        [Switch]$DisableActiveSync,
        [Switch]$ForwardEmail,
        [Switch]$BlockCredential,
        [Switch]$RevokeAzureAdUserToken,
        [Switch]$RemoveUnifiedGroup,
        [Switch]$UpdateSharePointList,
        [Switch]$UpdateWorkbook,
        [Switch]$MFA
    )

    #region Functions
    
    Function Connect-Office365 {
        <#
                .NOTES
                ===========================================================================
                Created on:   	2/4/2019 10:42 PM
                Created by:   	Bradley Wyatt
                E-Mail:			Brad@TheLazyAdministrator.com
                GitHub:			https://github.com/bwya77
                Website:		https://www.thelazyadministrator.com
                Organization: 	Porcaro Stolarek Mete Partners; The Lazy Administrator
                Filename:     	Connect-Office365.ps1
                Version: 		1.0.5
                Contributors:   /u/Sheppard_Ra
                Changelog:
                1.0.5
                    - Updated comment based help
                1.0.4
                    - Host title will add a service or services you are connected to. If unable to connect it will not display connection status until connection is valid
                ===========================================================================
                .SYNOPSIS
                Connect to Office 365 Services
                .DESCRIPTION
                Connect to different Office 365 Services using PowerShell function. Supports MFA.
                .PARAMETER MFA
                Description: Specifies MFA requirement to sign into Office 365 services. If set to $True it will use the Office 365 ExoPSSession Module to sign into Exchange & Compliance Center using MFA. Other modules support MFA without needing another external module
                .PARAMETER Service
                Description: Specify service to connect to (Exchange, AzureAD, MSOnline, Teams, SecurityandCompliance, SharePoint, SkypeForBusiness)
                .EXAMPLE
                Description: Connect to SharePoint Online
                C:\PS> Connect-Office365 -SharePoint
                .EXAMPLE
                Description: Connect to Exchange Online and Azure AD V1 (MSOnline)
                C:\PS> Connect-Office365 -Service Exchange, MSOnline
                .EXAMPLE
                Description: Connect to Exchange Online and Azure AD V1 using Multi-Factor Authentication
                C:\PS> Connect-Office365 -Service Exchange, MSOnline -MFA
                .EXAMPLE
                Description: Connect to Teams and Skype for Business
                C:\PS> Connect-Office365 -Service Teams, SkypeForBusiness
                .EXAMPLE
                Description: Connect to SharePoint Online
                C:\PS> Connect-Office365 -Service SharePoint -SharePointOrganizationName bwya77 -MFA
                .LINK
                Online version:  https://www.thelazyadministrator.com/2019/02/05/powershell-function-to-connect-to-all-office-365-services
        #>
        [OutputType()]
        [CmdletBinding(DefaultParameterSetName)]
        Param (
            [Parameter(Mandatory = $True,HelpMessage='AzureAD, Exchange, EXOv2, OnPrem, MSOnline, SecurityAndCompliance, SharePoint, SkypeForBusiness, Teams', Position = 1)]
            [ValidateSet('AzureAD', 'Exchange', 'EXOv2', 'MSOnline', 'OnPrem', 'SecurityAndCompliance', 'SharePoint', 'SkypeForBusiness', 'Teams')][string[]]$Service,
            [Parameter(Mandatory = $False, Position = 2)][Alias('SPOrgName')][string]$SharePointOrganizationName,
            [Parameter(Mandatory = $False, Position = 3, ParameterSetName = 'Credential')][System.Management.Automation.Credential()][PSCredential]$Credential,
            [Parameter(Mandatory = $False, Position = 3, ParameterSetName = 'MFA')][Switch]$MFA
        )
        #region Variables
        $SC             = 'SilentlyContinue'
        $Bas            = 'Basic'
        $ConEx          = 'Connecting to Exchange Online'
        $ExoNF          = 'The Exchange Online MFA Module was not found! https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps'
        $CrExPsSePS     = 'CreateExoPSSession.ps1'
        $CrExPsSes      = "$Env:LOCALAPPDATA\Apps\2.0\*\CreateExoPSSession.ps1"
        $ConExO = @{
            CertificateThumbPrint = 'CERTIFICATE THUMBPRINT HERE' # Set Certificate ThumbPrint
            appID                 = 'APP ID GOES HERE' # Set the App ID
            tenantID              = 'YOURTENANTNAMEHERE.onmicrosoft.com' ## set the tenant ID (directory ID or domain)
        }
        $getModuleSplat = @{
            ListAvailable = $True
            Verbose	      = $False
        }
        #endregion Variables
        If ($MFA -ne $True) {
            Write-Verbose -Message 'Gathering PSCredentials object for non MFA sign on'
            If (-not $PSBoundParameters.ContainsKey('Credential')) {$Credential = Get-Credential -Message 'Please enter your Office 365 credentials'}
        }
        ForEach ($Item in $PSBoundParameters.Service) {
            Write-Verbose -Message ('Attempting connection to {0}' -f $Item)
            Switch ($Item) {
                AzureAD {
                    $AzAct = {
                        If (($host.ui.RawUI.WindowTitle) -notlike '*Connected To:*') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: AzureAD'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - AzureAD'
                        }
                    }
                    If ($null -eq (Get-Module @getModuleSplat -Name 'AzureAD')) {
                        Write-Error -Message 'AzureAD Module is not present!'
                        Continue
                    } Else {
                        If ($MFA -eq $True) {
                            $Connect = Connect-AzureAD
                            If ($null -ne $Connect) {& $AzAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToAz} Else {$host.ui.RawUI.WindowTitle += $Az}}
                        } Else {
                            $Connect = Connect-AzureAD -Credential $Credential
                            If ($Null -ne $Connect) {& $AzAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToAz} Else {$host.ui.RawUI.WindowTitle += $Az}}
                        }
                    }
                    Continue
                }
                Exchange {
                    $ExAct = {
                        If (($host.ui.RawUI.WindowTitle) -notlike '*Connected To:*') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: Exchange'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - Exchange'
                        }
                    }
                    If ($MFA -eq $True) {
                        $getChildItemSplat = @{
                            Path        = $CrExPsSes
                            Recurse     = $true
                            ErrorAction = $SC
                            Verbose     = $false
                        }
                        $MFAExchangeModule = ((Get-ChildItem @getChildItemSplat | Select-Object -ExpandProperty Target -First 1).Replace($CrExPsSePS, ''))
                        If ($null -eq $MFAExchangeModule) {
                            Write-Error -Message $ExoNF
                            Continue
                        } Else {
                            Write-Verbose -Message 'Importing Exchange MFA Module'
                            . "$MFAExchangeModule\CreateExoPSSession.ps1"

                            Write-Verbose -Message $ConEx
                            Connect-EXOPSSession
                            If ($Null -ne (Get-PSSession | Where-Object {$_.ConfigurationName -like '*Exchange*'})) {& $ExAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToEx} Else {$host.ui.RawUI.WindowTitle += $Ex}}
                        }
                    } Else {
                        $newPSSessionSplat = @{
                            ConfigurationName = 'Microsoft.Exchange'
                            ConnectionUri	  = 'https://ps.outlook.com/powershell/'
                            Authentication    = $Bas
                            Credential	      = $Credential
                            AllowRedirection  = $true
                        }
                        $Session = New-PSSession @newPSSessionSplat
                        Write-Verbose -Message $ConEx
                        Import-PSSession -Session $Session -AllowClobber
                        If ($Null -ne (Get-PSSession | Where-Object {$_.ConfigurationName -like '*Exchange*'})) {& $ExAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToEx} Else {$host.ui.RawUI.WindowTitle += $Ex}}
                    }
                    Continue
                }
                EXOv2 {
                    $EXOAct2 = {
                        If (($host.ui.RawUI.WindowTitle) -notlike '*Connected To:*') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: EXO V2'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - EXO V2'
                        }
                    }
                    If ($null -eq (Get-Module @getModuleSplat -Name 'ExchangeOnlineManagement')) {
                        Write-Error -Message 'ExchangeOnlineManagement Module is not present!'
                        Continue
                    } Else {
                        # Connect to Exchange Online
                        Connect-ExchangeOnline -CertificateThumbPrint @ConExO
                        & $EXOAct2
                        Continue
                    }
                }
                OnPrem {
                    # Connect to local Exchange Server PowerShell
                    [String]$ExchServer = "YOUR LOCAL EXCHANGE SERVER NAME"
                    $EXOnPrem = @{
                        ConfigurationName = 'Microsoft.Exchange'
                        ConnectionUri     = "http://$ExchServer.YOURDOMAINNAME.com/PowerShell"
                        Authentication    = 'Kerberos'
                        Credential        = Get-Credential
                        Name              = 'OnPrem Exch PoSH'
                    }
                    $OnPremExSession = New-PSSession @EXOnPrem
                    Import-PSSession $OnPremExSession -AllowClobber
                }
                MSOnline {
                    $MSOAct = {
                        If (($host.ui.RawUI.WindowTitle) -notlike ' - Connected To: AzureAD') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: MSOnline'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - MSOnline'
                        }
                    }
                    If ($null -eq (Get-Module @getModuleSplat -Name 'MSOnline')) {
                        Write-Error -Message 'MSOnline Module is not present!'
                        Continue
                    } Else {
                        Write-Verbose -Message 'Connecting to MSOnline'
                        If ($MFA -eq $True) {
                            Connect-MsolService
                            If ($Null -ne (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)) {& $MSOAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToMSO} Else {$host.ui.RawUI.WindowTitle += $MSO}
                        } Else {
                            Connect-MsolService -Credential $Credential
                            If ($Null -ne (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)) {& $MSOAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToMSO} Else {$host.ui.RawUI.WindowTitle += $MSO}}
                        }
                    }
                    Continue
                }
                SecurityAndCompliance {
                    $SecAct = {
                        If (($host.ui.RawUI.WindowTitle) -notlike '*Connected To:*') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: Security and Compliance Center'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - Security and Compliance Center'
                        }
                    }
                    If ($MFA -eq $True) {
                        $getChildItemSplat = @{
                            Path        = $CrExPsSes
                            Recurse     = $true
                            ErrorAction = $SC
                            Verbose     = $false
                        }
                        $MFAExchangeModule = ((Get-ChildItem @getChildItemSplat | Select-Object -ExpandProperty Target -First 1).Replace($CrExPsSePS, ''))
                        If ($null -eq $MFAExchangeModule) {
                            Write-Error -Message $ExoNF
                            Continue
                        } Else {
                            Write-Verbose -Message 'Importing Exchange MFA Module (Required)'
                            . "$MFAExchangeModule\CreateExoPSSession.ps1"
						
                            Write-Verbose -Message 'Connecting to Security and Compliance Center'
                            Connect-IPPSSession
                            If ($Null -ne (Get-PSSession | Where-Object { $_.ConfigurationName -like '*Exchange*' })) {& $SecAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToSec} Else {$host.ui.RawUI.WindowTitle += $Sec}
                        }
                    } Else {
                        $newPSSessionSplat = @{
                            ConfigurationName = 'Microsoft.SecurityAndCompliance'
                            ConnectionUri	  = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
                            Authentication    = $Bas
                            Credential	      = $Credential
                            AllowRedirection  = $true
                        }
                        $Session = New-PSSession @newPSSessionSplat
                        Write-Verbose -Message 'Connecting to SecurityAndCompliance'
                        Import-PSSession -Session $Session -DisableNameChecking
                        If ($Null -ne (Get-PSSession | Where-Object { $_.ConfigurationName -like '*Exchange*' })) {& $SecAct} # If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToSec} Else {$host.ui.RawUI.WindowTitle += $Sec}}
                    }
                    Continue
                }
                SharePoint {
                    $SPAct = {
                        If (($host.ui.RawUI.WindowTitle) -notlike '*Connected To:*') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: SharePoint Online'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - SharePoint Online'
                        }
                    }
                    If ($null -eq (Get-Module @getModuleSplat -Name Microsoft.Online.SharePoint.PowerShell)) {
                        Write-Error -Message 'Microsoft.Online.SharePoint.PowerShell Module is not present!'
                        Continue
                    } Else {
                        If (-not ($PSBoundParameters.ContainsKey('SharePointOrganizationName'))) {
                            Write-Error -Message 'Please provide a valid SharePoint organization name with the -SharePointOrganizationName parameter.'
                            Continue
                        }
                        $SharePointURL = 'https://{0}-admin.sharepoint.com' -f $SharePointOrganizationName
                        Write-Verbose -Message ('Connecting to SharePoint at {0}' -f $SharePointURL)
                        If ($MFA -eq $True) {
                            Connect-SPOService -Url $SharePointURL
                            If ($Null -ne (Get-SPOTenant)) {& $SPAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToSP} Else {$host.ui.RawUI.WindowTitle += $SP}}
                        } Else {
                            Connect-SPOService -Url $SharePointURL -Credential $Credential
                            If ($Null -ne (Get-SPOTenant)) {& $SPAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToSP} Else {$host.ui.RawUI.WindowTitle += $SP}}
                        }
                    }
                    Continue
                }
                SkypeForBusiness {
                    $SkAct = {
                        If (($host.ui.RawUI.WindowTitle) -notlike '*Connected To:*') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: Skype for Business'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - Skype for Business'
                        }
                    }
                    Write-Verbose -Message 'Connecting to SkypeForBusiness'
                    If ($null -eq (Get-Module @getModuleSplat -Name 'SkypeOnlineConnector')) {
                        Write-Error -Message 'SkypeOnlineConnector Module is not present!'
                    } Else {
                        # Skype for Business module
                        Import-Module -Name SkypeOnlineConnector
                        If ($MFA -eq $True) {
                            $CSSession = New-CsOnlineSession
                            Import-PSSession -Session $CSSession -AllowClobber
                            If ($Null -ne (Get-CsOnlineDirectoryTenant)) {& $SkAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToSk} Else {$host.ui.RawUI.WindowTitle += $Sk}}
                        } Else {
                            $CSSession = New-CsOnlineSession -Credential $Credential
                            Import-PSSession -Session $CSSession -AllowClobber
                            If ($Null -ne (Get-CsOnlineDirectoryTenant)) {& $SkAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToSk} Else {$host.ui.RawUI.WindowTitle += $Sk}}
                        }
                    }
                    Continue
                }
                Teams {
                    $TeAct = {
                        If (($host.ui.RawUI.WindowTitle) -notlike '*Connected To:*') {
                            $host.ui.RawUI.WindowTitle += ' - Connected To: Microsoft Teams'
                        } Else {
                            $host.ui.RawUI.WindowTitle += ' - Microsoft Teams'
                        }
                    }
                    If ($null -eq (Get-Module @getModuleSplat -Name 'MicrosoftTeams')) {
                        Write-Error -Message 'MicrosoftTeams Module is not present!'
                    } Else {
                        Write-Verbose -Message 'Connecting to Teams'
                        If ($MFA -eq $True) {
                            $TeamsConnect = Connect-MicrosoftTeams
                            If ($Null -ne ($TeamsConnect)) {& $TeAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToTe} Else {$host.ui.RawUI.WindowTitle += $Te}}
                        } Else {
                            $TeamsConnect = Connect-MicrosoftTeams -Credential $Credential
                            If ($Null -ne ($TeamsConnect)) {& $TeAct} #If (($host.ui.RawUI.WindowTitle) -notlike $ConTo) {$host.ui.RawUI.WindowTitle += $ConToTe} Else {$host.ui.RawUI.WindowTitle += $Te}}
                        }
                    }
                    Continue
                }
                Default { }
            }
        }
    }

    Function Find-ExchangeServer {
        <#
                .NOTES
                Special Thanks to /u/MadBoyEvo from EVOTEC (https://evotec.xyz/)
                for his wonderful module PSSharedGoods (https://github.com/EvotecIT/PSSharedGoods)
                Install-Module -Name PSSharedGoods
        #>
        [CmdletBinding()]
        param()
        $ExchangeServers = Get-ADGroup -Identity 'Exchange Servers' | Get-ADGroupMember | Where-Object {$_.objectClass -eq 'computer'}
        ForEach ($Server in $ExchangeServers) {
            $Data = Get-ADComputer -Identity $Server.SamAccountName -Properties Name, DNSHostName, OperatingSystem, DistinguishedName, ServicePrincipalName
            [PSCustomObject] @{Name = $Data.Name
                FQDN                = $Data.DNSHostName
                OperatingSystem     = $Data.OperatingSystem
                DistinguishedName   = $Data.DistinguishedName
                Enabled             = $Data.Enabled
            }
        }
    }
    
    # Function to validate if a user account exists in Active Directory, if so, return TRUE and continue with script,
    # if FALSE, re-prompt for user's information.
    Function Validate-User() {
        Param([Parameter(Mandatory = $True)][String]$User)
        # Null variable IsValid before validation
        $IsValid = $False
        # Try/Catch to verify if user can be found in Active Directory
        Try {
            $IsValid = Get-ADUser -Identity $User -ErrorAction SilentlyContinue
            Write-Verbose -Message "Validate-User function, value for IsValid if TRUE:  $IsValid"
        } Catch {
            Write-Verbose -Message "Could not find $Initials in Active Directory"
            Write-Verbose -Message "Validate-User function, value for IsValid if FALSE:  $IsValid"
        }
        # If found, return value of user from Active Directory, if not found, return FALSE.
        Return $IsValid
    }

    Function Get-O365LicenseType() {
        Param([Parameter(Mandatory = $True)][String]$User)
        Try {
            $GetMsolUser = Get-MsolUser -UserPrincipalName $User
        } Catch {
            Write-Host "Could not get user information using Get-MsolUser for $User!" @Problem
        }
        $GetAssignedLicense = ($GetMsolUser.Licenses.AccountSkuId)
        If ($GetAssignedLicense.count -gt 0) {
            Write-Verbose -Message "Get-O365LicenseType function, value for GetAssignedLicense:  $GetAssignedLicense"
            Return $GetAssignedLicense
        } Else {
            Write-Verbose -Message "Get-O365LicenseType function, value for value for GetAssignedLicense:  $GetAssignedLicense"
            Return $False 
        }
    }
 
    # Function to validate the email address of the user who the disabled account will forward to
    Function Validate-ForwardEmail {
        $ForwardTo          = $null
        $ValidatedEmail     = $null
        # If Parameter -ForwardEmail is used, forward user's email to another user
        [String]$ForwardTo  = Read-Host -Prompt 'Please enter the email address you would like to forward to'
        Try {
            $ValidatedEmail = Get-EXOMailbox -Identity "$ForwardTo" -ErrorAction Stop
        } Catch {
            Write-Host "Could not locate email address $ForwardTo, please verify and try again!" @Problem
        }
        If ($null -ne $ValidatedEmail) {Return $ValidatedEmail} Else {Return $False}
    }
    #endregion Functions

    #region Variables
    # If -Domain parameter specificed, use that input, else use default company Domain
    If (!$Domain) {
        [String]$Domain = '@YOURDOMAINNAME'
    } Else {
        [String]$Domain = "@$Domain"
    }
 
    # Create our variables for use in the module/script
    # Local Exchange and Exchange Online server name variables and URL's to connect to them via PowerShell
    $DomainActual = (Get-ADForest).Name
    [String]$ExServerName    = Find-ExchangeServer | Select-Object -First 1
    [String]$ExServerURL     = "http://$ExServerName.$DomainActual/PowerShell"
    [String]$ExOnlineURL     = 'https://outlook.office365.com/powershell-liveid/'

    # Disabled Users OU location in Active Directory
    [String]$DisabledUsersOU = 'OU=Disabled Users,DC=YOURDOMAINNAME,DC=com'
 
    # SharePoint Online Excel file path for Accounting - For license billbacks to properties
    [String]$ExcelFilePath   = 'SHAREPOINT ONLINE EXCEL FILE PATH'
 
    # Office 365 Tenant Name
    [String]$O365TenantName  = 'OFFICE365TENANTNAME'
 
    # Office 365 License SKU's for F3, E3, and ATP
    [String]$E3LicenseSKU    = "$O365TenantName`:ENTERPRISEPACK"
    [String]$F3LicenseSKU    = "$O365TenantName`:DESKLESSPACK"
    [String]$ATPLicenseSKU   = "$O365TenantName`:ATP_ENTERPRISE"
 
    # SharePoint Online link to User List
    [String]$SPOUserListName = 'USER LIST NAME GOES HERE'
    [String]$SPOUserListURL  = 'https://LINK TO SHAREPOINT LIST GOES HERE'
 
    # Try to import Active Directory Module which is required to run this module to verify user exists in Active Directory.
    Try {
        Import-Module -Name ActiveDirectory -ErrorAction Stop
    } Catch {
        Write-Warning -Message 'The ActiveDirectory Module needs to be installed in order to run this script, exiting...'
        Break
    }
 
    # Create splatting for different text colors for success, warning, error, other.
    $Success = @{
        ForegroundColor = 'Green'
        BackgroundColor = 'Black'
    }
    $Warn    = @{
        ForegroundColor = 'Yellow'
        BackgroundColor = 'Black'
    }
    $Problem = @{
        ForegroundColor = 'Red'
        BackgroundColor = 'Black'
    }
    $Other   = @{
        ForegroundColor = 'Cyan'
        BackgroundColor = 'Black'
    }

    # Re-Occurring New Line
    $NewLine = {Write-Host ''}
    #endregion Variables
    

    #region Step 1 - Validate User
    # Send $Initials to Validate-User function to verify if user exists in Active Directory,
    # if return is TRUE then user was found in Active Directory and user attributes will be returned.
    # If FALSE then user could not be found in Active Directory, $False is returned,
    # so re-prompt for user's initials and try again.
    $UserValidation = Validate-User -User $Initials
    If ($UserValidation -eq $False) {
        Do {
            Write-Verbose -Message "Value of UserValidation returned from Validate-User:  $UserValidation"
            $Initials       = $null
            Write-Host "Could not locate $Initials in Active Directory!" @Problem
            $Initials       = Read-Host -Prompt 'Please re-enter the user initials'
            $UserValidation = $null
            $UserValidation = Validate-User -User $Initials
        } While ($UserValidation -eq $False)
    } Else {
        Write-Verbose -Message "Value of UserValidation returned from Validate-User:  $UserValidation"
        Write-Host "$Initials was found in Active Directory!" @Success
        # Set ADUserObj to value of UserValidation for ease of use later on
        $ADUserObj = $UserValidation
    }
    #endregion Step 1
    & $NewLine
 
    #region Step 2 - Verify if user is disabled
    # Check if user is Enabled, if not - disable, If so - skip
    Write-Host "Checking if $($ADUserObj.SamAccountName) is already disabled..." @Other
    If ($ADUserObj.Enabled -eq $False) {
        Write-Host "$($ADUserObj.SamAccountName) account is already disabled, skipping..." @Warn
    } Else {
        Write-Host "$($ADUserObj.SamAccountName) is currently Enabled, will now Disable $($ADUserObj.SamAccountName)'s account..." @Other
        Try {
            Disable-ADAccount -Identity ($ADUserObj.SamAccountName) -Confirm:$False
        } Catch {
            Write-Host "Could not disable $($ADUserObj.SamAccountName) at this time, please check Active Directory and verify Enable/Disable status!" @Problem
            Break
        }
    }
 
    # Sleep for a few seconds before making changes to AD User Object
    Start-Sleep -Seconds 3
    #endregion Step 2
    & $NewLine
 
    #region Step 3 - Clear AD Attributes
    # Clear AD Attributes for Script Path/Description/Home Directory/Home Drive from user's account in Active Directory
    Write-Host 'Clearing Login Script, Description, Home Drive and Home Directory fields...' @Warn
    Try {
        Set-ADUser -Identity ($ADUserObj.SamAccountName) -Clear ScriptPath,Description -HomeDrive $null -HomeDirectory $null
    } Catch {
        Write-Host "Could not clear fields for Login Script, Description, Home Drive or Home Path for $($ADUserObj.SamAccountName).  Please verify user object in Active Directory manually!" @Problem
    }
    #endregion Step 3
    & $NewLine
 
    #region Step 4 - Remove AD group Memberships
    # Remove all Active Directory groups from user account except for Domain Users
    Write-Host "Removing all Active Directory Groups from $($ADUserObj.SamAccountName)'s account..." @Other
    Get-ADPrincipalGroupMembership -Identity ($ADUserObj.SamAccountName) | ForEach-Object {
        If ($_.SamAccountName -ne 'Domain Users') {
            Remove-ADGroupMember -Identity $_.SamAccountName -Member ($ADUserObj.SamAccountName) -Confirm:$False
        }
    }
    #endregion Step 4
    & $NewLine
 
    #region Step 5 - Reset user pass
    # Prompt Host to reset disabled user account's password in Active Directory
    Set-ADAccountPassword -Identity ($ADUserObj.SamAccountName) -Reset
    #endregion Step 5
    & $NewLine
 
    # Time to connect to local Exchange server to make local account attribute changes
    Write-Host "Connecting to local on-prem Exchange Server called $ExServerName..." @Warn

    & $NewLine
 
    # Connect external module called Connect-Office365.
    # Connects to Exchange on-prem server (See NOTES section above).
    Connect-Office365 -Service OnPrem

    & $NewLine
 
    #region Step 6 - Get Mailbox ID and hide from GAL
    # Get user mailbox object information
    $IsUserHidden = Get-RemoteMailbox -Identity ($ADUserObj.SamAccountName)
 
    # Check to see if user is hidden from the Global Address Book: hide, if so: skip
    If ($IsUserHidden.HiddenFromAddressListsEnabled -eq $False) {
        Write-Host "Hiding $($ADUserObj.SamAccountName) from Exchange GAL..." @Other
        Try {
            Set-RemoteMailbox -Identity ($ADUserObj.SamAccountName) -HiddenFromAddressListsEnabled $True -Confirm:$False
        } Catch {
            Write-Host "Could not hide $($ADUserObj.SamAccountName) from Exchange GAL at this time!  Please check $ExServername manually to verify user setting!" @Problem
        }
    } Else {
        Write-Host "$($ADUserObj.SamAccountName) is already hidden from Exchange GAL, skipping..." @Warn
    }
    #endregion Step 6
    & $NewLine
 
    #region Step 7 - Check user is in proper Disabled OU
    # Test to see if user account is in OU for Disabled Users in Active Directory
    $DisabledOU = Select-String -Pattern 'OU=Disabled Users' -InputObject ($ADUserObj.DistinguishedName)
 
    # If user in not in Disabled Users OU, move user to OU=Disabled Users
    # If already in OU, skip moving user
    If ($DisabledOU -eq $null) {
        Write-Host "$($ADUserObj.SamAccountName) is not in the Disabled Users OU, moving now..." @Other
        ($ADUserObj.DistinguishedName) | Move-ADObject -TargetPath "$DisabledUsersOU"
    } Else {
        Write-Host "$($ADUserObj.SamAccountName) is already in the Disabled Users OU, skipping move..." @Warn
    }
    #endregion Step 7
    
    # Disconnect from Exchange server on-prem by calling Disconnect-O365Sessions function in PowerShell Profile
    Disconnect-O365Sessions -OnPrem
 
    # Connect to Exchange Online V2 module via custom Function in PowerShell Profile
    # If MFA parameter specified and Administrator account uses MFA, connect using MFA
    # If MFA parameter not specified and Administrator account does not use MFA, do not connect using MFA
    If ($MFA) {
        Write-Verbose -Message 'Connecting to Exchange Online using multi-factor authentication...'
        Connect-Office365 -Service ExoV2,MSOnline -MFA
    } Else {
        Write-Verbose -Message 'Connecting to Exchange Online without multi-factor authentication...'
        Connect-Office365 -Service ExoV2,MSOnline
    }
 
    & $NewLine
 
    # If specific Switches are specified, connect to Exchange Online 
    If (($RemoveLicense) -or ($DisableActiveSync)) {
        $LicenseType = Get-O365LicenseType -User ($ADUserObj.UserPrincipalName)
    }
 
    # For Groups-based licensing, add user to proper Active Directory group based off of their Office 365 license type.
    # This will automatically remove all other licenses and options underneath as setup in Office 365 for the  license groups.
    If ($RemoveLicense) {
        $License = $null
 
        # Set Active Directory variables for disabled license groups
        [String]$Office365F3Disabled = 'Office 365 - Disabled F3 Accounts'
        [String]$Office365E3Disabled = 'Office 365 - Disabled E3 Accounts'
        # [String]$Office365E5Disabled = 'Office 365 - Disabled E5 Accounts'
 
        ForEach ($License in $LicenseType) { 
            # E3 license       
            If ($License -eq $E3LicenseSKU) {
                $PromptToRemove = Read-Host -Prompt "Add $($ADUserObj.SamAccountName) to the $Office365E3Disabled Active Directory Group?  (Y/N)"
        
                Switch ($PromptToRemove) {
                    Default {
                        Write-Host "Not removing E3 License options and not adding $($ADUserObj.SamAccountName) to $Office365E3Disabled..." @Warn
                        Write-Verbose -Message "E3 License, Variable PromptToRemove value is:  $PromptToRemove"
                    }
                    y {
                        Write-Host "Adding $($ADUserObj.SamAccountName) to Active Directory Group called $Office365E3Disabled..." @Other
                        Add-ADPrincipalGroupMembership -Identity ($ADUserObj.SamAccountName) -MemberOf $Office365E3Disabled
                    }
                }
            } ElseIf ($License -eq $F3LicenseSKU) {
                # F3 license
                $PromptToRemove = Read-Host -Prompt "Add $($ADUserObj.SamAccountName) to the $Office365F3Disabled Active Directory Group?  (Y/N)"
        
                Switch ($PromptToRemove) {
                    Default {
                        Write-Host "Not removing F3 License options and not adding $($ADUserObj.SamAccountName) to $Office365F3Disabled..." @Warn
                        Write-Verbose -Message "F3 License, Variable PromptToRemove value is:  $PromptToRemove"
                    }
                    y {
                        Write-Host "Adding $($ADUserObj.SamAccountName) to Active Directory Group called $Office365F3Disabled..." @Success
                        Add-ADPrincipalGroupMembership -Identity ($ADUserObj.SamAccountName) -MemberOf $Office365F3Disabled
                    }
                }
            }
        }
    }
 
    # Disable OWA, ActiveSync, Outlook Mobile depending on user license type
    If ($DisableActiveSync) {
        # Set default license parameters for a user with a F3 license
        $LicenseParams = [ordered]@{
            'Identity'             = $ADUserObj.SamAccountName
            'OWAEnabled'           = $False
            'OWAforDevicesEnabled' = $False
            'OutlookMobileEnabled' = $False
            'ActiveSyncEnabled'    = $False
        }
 
        # If user has an E3 license, add two parameters to disable
        If ($LicenseType -contains $E3LicenseRemoval) {
            $LicenseParams['EwsEnabled'] = $False
            $LicenseParams['MAPIEnabled'] = $False
            Set-CASMailbox -Identity ($ADUserObj.SamAccountName) -OWAEnabled $False -OWAforDevicesEnabled $False -OutlookMobileEnabled $False -ActiveSyncEnabled $False -EwsEnabled $False -MAPIEnabled $False
        }
 
        # Run the command to disable the options for the user account
        Write-Host "Disabling OWA, Outlook for Mobile, ActiveSync, and other options for $($ADUserObj.SamAccountName)..." @Other
        Set-CASMailbox @LicenseParams
    } Else {
        Write-Verbose -Message "DisableActiveSync value:  $DisableActiveSync"
        Write-Verbose -Message "LicenseType value:  $LicenseType"
    }
 
    # If -RemoveMobile Switch is specificed, prompt for removal of user's ActiveSync devices
    If ($RemoveMobileDevice) {
        # See if user has any ActiveSync devices, if so, prompt Host to remove them or not
        Write-Host 'Checking for any mobile device ActiveSync associations...' @Warn
 
        # Try to locate any mobile devices associated with user's account
        Try {
            $FindDevice = Get-MobileDevice -Mailbox "$($ADUserObj.UserPrincipalName)" -ErrorAction Stop
        } Catch {
            Write-Host "Error locating mobile devices for $($ADUserObj.UserPrincipalName)." @Problem
        }
 
        # Store mobile device GUIDs into variable
        $MobileDevice = $FindDevice.GUID.GUID
 
        # If the count is above 0, then user has mobile devices so we'll remove them
        If ($MobileDevice.count -gt 0) {
            Write-Host 'Mobile devices found!' @Success
 
            $RemoveDevice = Read-Host -Prompt "Do you wish to remove $($ADUserObj.SamAccountName) mobile device associations?  (Y/N)"
            Switch ($RemoveDevice) {
                Default {
                    Write-Host 'Skipping mobile device association removal...' @Warn
                    Write-Verbose -Message "Variable RemoveDevice is:  $RemoveDevice"
                }
                y {
                    ForEach ($Device in $MobileDevice) {
                        Write-Host "Removing mobile device Identity $Device for $($ADUserObj.SamAccountName)..." @Other
                        Try {
                            Remove-MobileDevice -Identity "$Device" -Confirm:$False
                        } Catch {
                            Write-Host "Could not remove mobile device $Device for $($ADUserObj.SamAccountName)" @Problem
                        }
                    }
                }
            }
        } Else {
            Write-Host "No mobile devices for $($ADUserObj.SamAccountName) have been found, nothing to remove, skipping..." @Warn
        }
    }
 
    # If Parameter -ForwardEmail is used, forward user's email to another user
    If ($ForwardEmail) {
        # Go to function called Validate-ForwardEmail to validate the email address of the user forwarding to
        $EmailForwardTo = Validate-ForwardEmail
 
        # If function returns valid user, perform the email forward.
        # If function returns FALSE, perform nothing notifying console that manual action is required.
        If ($EmailForwardTo -ne $False) {
            Write-Host "Forwarding $($ADUserObj.SamAccountName)'s email to $($EmailForwardTo.PrimarySmtpAddress)..." @Other
 
            # Perform the email forward on the user's mailbox to forward to a different internal user
            Try {
                Set-Mailbox -Identity ($ADUserObj.SamAccountName) -DeliverToMailboxAndForward $True -ForwardingAddress "$($EmailForwardTo.PrimarySmtpAddress)"
            } Catch {
                Write-Host "Error in setting email forward for $($ADUserObj.SamAccountName) to forward to $($EmailForwardTo.PrimarySmtpAddress), please re-verify and set via Office 365 Admin Center!" @Problem
            }
        } Else {
            Write-Host "Could not set email forward to $($EmailForwardTo.PrimarySmtpAddress), please set via Office 365 Admin Center!" @Problem
        }
    }
 
    & $NewLine
 
    # 
    If ($BlockCredential) {
        # Connect to SharePoint Online PowerShell module
        If ($MFA) {
            Write-Host 'Connecting to SharePoint Online PowerShell using multi-factor authentication...'
            Connect-Office365 -Service SharePoint -SharePointOrganizationName $O365TenantName -MFA
        } Else {
            Write-Host 'Connecting to SharePoint Online PowerShell without using multi-factor authentication...'
            Connect-Office365 -Service SharePoint -SharePointOrganizationName $O365TenantName
        }
 
        # 
        Write-Host "Revoking $($ADUserObj.SamAccountName) user sessions from Office 365..." @Warn
        Try {
            Revoke-SPOUserSession -User ($ADUserObj.UserPrincipalName) -Confirm:$False
        } Catch {
            Write-Host 'Could not revoke user sessions from Office 365!  Please verify via Office 365 Admin Center.' @Problem
        }
    }
 
    # 
    If ($RevokeAzureAdUserToken) {
        # Connect to AzureAD PowerShell module
        If ($MFA) {
            Write-Host 'Connecting to Azure AD PowerShell module using multi-factor authentication...'
            Connect-Office365 -Service AzureAD -MFA
        } Else {
            Write-Host 'Connecting to Azure AD PowerShell module without using multi-factor authentication...'
            Connect-Office365 -Service AzureAD
        }
 
        Write-Host 'Getting Azure AD user information and expiring Azure AD refresh token validity period...' @Warn
        Try {
            Get-AzureAdUser -ObjectId "$($ADUserObj.UserPrincipalName)" | Revoke-AzureADUserAllRefreshToken
        } Catch {
            Write-Host "There was an error getting $($ADUserObj.SamAccountName) Azure AD user information and/or expiring the $($ADUserObj.SamAccountName)'s refresh token.  Please connect to AzureAD and attempt manually." @Problem
        }
    }
 
    # Block user sign-in to Office 365
    Write-Host "Blocking $($ADUserObj.SamAccountName) sign-in to Office 365..." @Other
    Try {
        Set-MsolUser -UserPrincipalName ($ADUserObj.UserPrincipalName) -BlockCredential:$True -ErrorAction Stop
    } Catch {
        Write-Host "Could not block sign into Office 365 for $($ADUserObj.UserPrincipalName)!  Please verify via Office 365 Admin Center." @Problem
    }
 
    & $NewLine
 
    #
    If ($UpdateSharePointList) {
        # Connect to SPO using PnP.PowerShell module for SharePoint Online
        Connect-Office365 -Service SharePoint-PnPOnline -SPOSiteName "$SPOUserListURL"
 
        Write-Host "Looking for $($ADUserObj.SamAccountName) in $SPOUserListName..." @Warn
        $FindListItem = $null
        $FindListItem = Get-PnPListItem -List "$SPOUserListName" -Query "<View><Query><Where><Eq><FieldRef Name='Title'/><Value Type='Text'>$($ADUserObj.SamAccountName)</Value></Eq></Where></Query></View>"
 
        If ($FindListItem) {
            Write-Verbose -Message "FindListItem has value:  $FindListItem"
            Write-Host "Setting appropriate fields in $SPOUserListName for $($ADUserObj.SamAccountName)..." @Warn
            $SetSPListItem = Set-PnPListItem -List "$SPOUserListName" -Identity $FindListItem -Values @{
                'Visio'                           = 'NONE'
                'Intune'                          = "$False"
                'AdvThreatProtect'                = "$False"
                'Current_x0020_Team_x0020_Member' = "$False"
                'PMT_x003f_'                      = "$False"
                'ProfitSword_x0020_User'          = "$False"
            }
        } Else {
            Write-Verbose -Message "FindListItem has value:  $FindListItem"
            Write-Verbose -Message "Could not find $($ADUserObj.SamAccountName) in $SPOUserListName."
            Write-Host "Could not locate $($ADUserObj.SamAccountName) in $SPOUserListName, please manually locate this user in the list and disable accordingly." @Problem
        }
    }
 
    & $NewLine
 
    # Open to update Excel workbook on SharePoint Accounting site for billing purposes
    If ($UpdateWorkbook) {
        Write-Host 'Now opening IT Fees Excel workbook...' @Other
 
        # Create new comobject for Excel
        $Excel = New-Object -ComObject Excel.Application
 
        # Open Excel window, by default .Visible set to $False
        $Excel.Visible = $True
 
        # Set the path to the IT Fees Excel file in SharePoint
        $FilePath = "$ExcelFilePath"
 
        # Open IT Fees file from SharePoint
        $OpenWorkbook = $Excel.Workbooks.Open($FilePath)
    } Else {
        Write-Host 'Skipping updating of IT Fees Workbook, use -UpdateWorkbook parameter to update the workbook...' @Warn
    }
 
    # Disconnect from all Office 365 PowerShell connections
    Disconnect-O365Sessions -Exchange -PnP -SharePoint -AzureAD
}

