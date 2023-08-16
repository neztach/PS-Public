#region Basics
Get-Command                                               # Retrieves a list of all the commands available to PowerShell
# (native binaries in $env:PATH + cmdlets / functions from PowerShell modules)
Get-Command -Module Microsoft*                            # Retrieves a list of all the PowerShell commands exported from modules named Microsoft*
Get-Command -Name *item                                   # Retrieves a list of all commands (native binaries + PowerShell commands) ending in "item"

Get-Help                                                  # Get all help topics
Get-Help -Name about_Variables                            # Get help for a specific about_* topic (aka. man page)
Get-Help -Name Get-Command                                # Get help for a specific PowerShell function
Get-Help -Name Get-Command -Parameter Module              # Get help for a specific parameter on a specific command


###################################################
#region Operators
###################################################

$a = 2                                                    # Basic variable assignment operator
$a += 1                                                   # Incremental assignment operator
$a -= 1                                                   # Decrement assignment operator

$a -eq 0                                                  # Equality comparison operator
$a -ne 5                                                  # Not-equal comparison operator
$a -gt 2                                                  # Greater than comparison operator
$a -lt 3                                                  # Less than comparison operator

$FirstName = 'Trevor'
$FirstName -like 'T*'                                     # Perform string comparison using the -like operator, which supports the wildcard (*) character. Returns $true

$BaconIsYummy = $true
$FoodToEat = $BaconIsYummy ? 'bacon' : 'beets'            # Sets the $FoodToEat variable to 'bacon' using the ternary operator

'Celery' -in @('Bacon', 'Sausage', 'Steak', 'Chicken')    # Returns boolean value indicating if left-hand operand exists in right-hand array
'Celery' -notin @('Bacon', 'Sausage', 'Steak')            # Returns $true, because Celery is not part of the right-hand list

5 -is [string]                                            # Is the number 5 a string value? No. Returns $false.
5 -is [int32]                                             # Is the number 5 a 32-bit integer? Yes. Returns $true.
5 -is [int64]                                             # Is the number 5 a 64-bit integer? No. Returns $false.
'Trevor' -is [int64]                                      # Is 'Trevor' a 64-bit integer? No. Returns $false.
'Trevor' -isnot [string]                                  # Is 'Trevor' NOT a string? No. Returns $false.
'Trevor' -is [string]                                     # Is 'Trevor' a string? Yes. Returns $true.
$true -is [bool]                                          # Is $true a boolean value? Yes. Returns $true.
$false -is [bool]                                         # Is $false a boolean value? Yes. Returns $true.
5 -is [bool]                                              # Is the number 5 a boolean value? No. Returns $false.
#endregion Operators

###################################################
#region Regular Expressions
###################################################

'Trevor' -match '^T\w*'                                   # Perform a regular expression match against a string value. # Returns $true and populates $matches variable
$matches[0]                                               # Returns 'Trevor', based on the above match

@('Trevor', 'Billy', 'Bobby') -match '^B'                 # Perform a regular expression match against an array of string values. Returns Billy, Bobby

$regex = [regex]'(\w{3,8})'
$regex.Matches('Trevor Bobby Dillon Joe Jacob').Value     # Find multiple matches against a singleton string value.
#endregion Regular Expressions

###################################################
#region Flow Control
###################################################

If (1 -eq 1) { }                                          # Do something if 1 is equal to 1

Do { 'hi' } While ($false)                                # Loop while a condition is true (always executes at least once)

While ($false) { 'hi' }                                   # While loops are not guaranteed to run at least once
While ($true) { }                                         # Do something indefinitely
While ($true) { if (1 -eq 1) { break } }                  # Break out of an infinite while loop conditionally

For ($i = 0; $i -le 10; $i++) { Write-Host $i }           # Iterate using a for..loop
ForEach ($item in (Get-Process)) { }                      # Iterate over items in an array

Switch ('test') { 'test' { 'matched'; break } }           # Use the switch statement to perform actions based on conditions. Returns string 'matched'
Switch -Regex (@('Trevor', 'Daniel', 'Bobby')) {          # Use the switch statement with regular expressions to match inputs
    'o' { $PSItem; break }                                  # NOTE: $PSItem or $_ refers to the "current" item being matched in the array
}
Switch -Regex (@('Trevor', 'Daniel', 'Bobby')) {          # Switch statement omitting the break statement. Inputs can be matched multiple times, in this scenario.
    'e' { $PSItem }
    'r' { $PSItem }
}
#endregion Flow Control

###################################################
#region Variables
###################################################

$a = 0                                                    # Initialize a variable
[int] $a = 'Trevor'                                       # Initialize a variable, with the specified type (throws an exception)
[string] $a = 'Trevor'                                    # Initialize a variable, with the specified type (doesn't throw an exception)

Get-Command -Name *varia*                                 # Get a list of commands related to variable management

Get-Variable                                              # Get an array of objects, representing the variables in the current and parent scopes 
Get-Variable | ? { $PSItem.Options -contains 'constant' } # Get variables with the "Constant" option set
Get-Variable | ? { $PSItem.Options -contains 'readonly' } # Get variables with the "ReadOnly" option set

New-Variable -Name FirstName -Value Trevor
New-Variable FirstName -Value Trevor -Option Constant     # Create a constant variable, that can only be removed by restarting PowerShell
New-Variable FirstName -Value Trevor -Option ReadOnly     # Create a variable that can only be removed by specifying the -Force parameter on Remove-Variable

Remove-Variable -Name FirstName                           # Remove a variable, with the specified name
Remove-Variable -Name FirstName -Force                    # Remove a variable, with the specified name, that has the "ReadOnly" option set
#endregion Variables

###################################################
#region Functions
###################################################

Function add ($a, $b) { $a + $b }                         # A basic PowerShell function

Function Do-Something {                                   # A PowerShell Advanced Function, with all three blocks declared: BEGIN, PROCESS, END
    [CmdletBinding()]
    Param ()
    Begin { }
    Process { }
    End { }
}
#endregion Functions

###################################################
#region Working with Modules
###################################################

Get-Command -Name *module* -Module mic*core                 # Which commands can I use to work with modules?

Get-Module -ListAvailable                                   # Show me all of the modules installed on my system (controlled by $env:PSModulePath)
Get-Module                                                  # Show me all of the modules imported into the current session

$PSModuleAutoLoadingPreference = 0                          # Disable auto-loading of installed PowerShell modules, when a command is invoked

Import-Module -Name NameIT                                  # Explicitly import a module, from the specified filesystem path or name (must be present in $env:PSModulePath)
Remove-Module -Name NameIT                                  # Remove a module from the scope of the current PowerShell session

New-ModuleManifest                                          # Helper function to create a new module manifest. You can create it by hand instead.

New-Module -Name trevor -ScriptBlock {                      # Create an in-memory PowerShell module (advanced users)
Function Add($a,$b) { $a + $b } }

New-Module -Name trevor -ScriptBlock {                      # Create an in-memory PowerShell module, and make it visible to Get-Module (advanced users)
Function Add($a,$b) { $a + $b } } | Import-Module
#endregion Working with Modules

###################################################
#region Module Management
###################################################

Get-Command -Module PowerShellGet                           # Explore commands to manage PowerShell modules

Find-Module -Tag cloud                                      # Find modules in the PowerShell Gallery with a "cloud" tag
Find-Module -Name ps*                                       # Find modules in the PowerShell Gallery whose name starts with "PS"

Install-Module -Name NameIT -Scope CurrentUser -Force       # Install a module to your personal directory (non-admin)
Install-Module -Name NameIT -Force                          # Install a module to your personal directory (admin / root)
Install-Module -Name NameIT -RequiredVersion 1.9.0          # Install a specific version of a module

Uninstall-Module -Name NameIT                               # Uninstall module called "NameIT", only if it was installed via Install-Module

Register-PSRepository -Name <repo> -SourceLocation <uri>    # Configure a private PowerShell module registry
Unregister-PSRepository -Name <repo>                        # Deregister a PowerShell Repository
#endregion Module Management

###################################################
#region Filesystem
###################################################

New-Item -Path c:\test -ItemType Directory                  # Create a directory
mkdir -Path c:\test2                                              # Create a directory (short-hand)

New-Item -Path c:\test\myrecipes.txt                        # Create an empty file
Set-Content -Path c:\test.txt -Value ''                     # Create an empty file
[System.IO.File]::WriteAllText('testing.txt', '')           # Create an empty file using .NET Base Class Library

Remove-Item -Path testing.txt                               # Delete a file
[System.IO.File]::Delete('testing.txt')                     # Delete a file using .NET Base Class Library
#endregion Filesystem

###################################################
#region Hashtables (Dictionary)
###################################################

$Person = @{
    FirstName = 'Trevor'
    LastName = 'Sullivan'
    Likes = @(
        'Bacon',
        'Beer',
        'Software'
    )
}                                                           # Create a PowerShell HashTable

$Person.FirstName                                           # Retrieve an item from a HashTable
$Person.Likes[-1]                                           # Returns the last item in the "Likes" array, in the $Person HashTable (software)
$Person.Age = 50                                            # Add a new property to a HashTable
#endregion Hashtables (Dictionary)

###################################################
#region Windows Management Instrumentation (WMI) (Windows only)
###################################################

Get-CimInstance -ClassName Win32_BIOS                       # Retrieve BIOS information
Get-CimInstance -ClassName Win32_DiskDrive                  # Retrieve information about locally connected physical disk devices
Get-CimInstance -ClassName Win32_PhysicalMemory             # Retrieve information about install physical memory (RAM)
Get-CimInstance -ClassName Win32_NetworkAdapter             # Retrieve information about installed network adapters (physical + virtual)
Get-CimInstance -ClassName Win32_VideoController            # Retrieve information about installed graphics / video card (GPU)

Get-CimClass -Namespace root\cimv2                          # Explore the various WMI classes available in the root\cimv2 namespace
Get-CimInstance -Namespace root -ClassName __NAMESPACE      # Explore the child WMI namespaces underneath the root\cimv2 namespace
#endregion Windows Management Instrumentation (WMI) (Windows only)

###################################################
#region Asynchronous Event Registration
###################################################

#### Register for filesystem events
$Watcher = [System.IO.FileSystemWatcher]::new('c:\tmp')
Register-ObjectEvent -InputObject $Watcher -EventName Created -Action {
    Write-Host -Object 'New file created!!!'
}                                                           

#### Perform a task on a timer (ie. every 5000 milliseconds)
$Timer = [System.Timers.Timer]::new(5000)
Register-ObjectEvent -InputObject $Timer -EventName Elapsed -Action {
    Write-Host -ForegroundColor Blue -Object 'Timer elapsed! Doing some work.'
}
$Timer.Start()
#endregion Asynchronous Event Registration

###################################################
#region PowerShell Drives (PSDrives)
###################################################

Get-PSDrive                                                 # List all the PSDrives on the system
New-PSDrive -Name videos -PSProvider Filesystem -Root x:\data\content\videos  # Create a new PSDrive that points to a filesystem location
New-PSDrive -Name h -PSProvider FileSystem -Root '\\storage\h$\data' -Persist # Create a persistent mount on a drive letter, visible in Windows Explorer
Set-Location -Path videos:                                  # Switch into PSDrive context
Remove-PSDrive -Name xyz                                    # Delete a PSDrive
#endregion PowerShell Drives (PSDrives)

###################################################
#region Data Management
###################################################

Get-Process | Group-Object -Property Name                   # Group objects by property name
Get-Process | Sort-Object -Property Id                      # Sort objects by a given property name
Get-Process | Where-Object -FilterScript { $PSItem.Name -match '^c' } # Filter objects based on a property matching a value
Get-Process | Where-Object Name -match '^c'                 # Abbreviated form of the previous statement
#endregion Data Management

###################################################
#region PowerShell Classes
###################################################

class Person {
    [string] $FirstName                                       # Define a class property as a string
    [string] $LastName = 'Sullivan'                           # Define a class property with a default value
    [int] $Age                                                # Define a class property as an integer
  
    Person() {                                                # Add a default constructor (no input parameters) for a class
    }
  
    Person([string] $FirstName) {                             # Define a class constructor with a single string parameter
        $this.FirstName = $FirstName
    }
  
    [string] FullName() {
        return '{0} {1}' -f $this.FirstName, $this.LastName
    }
}
$Person01 = [Person]::new()                                 # Instantiate a new Person object.
$Person01.FirstName = 'Trevor'                              # Set the FirstName property on the Person object.
$Person01.FullName()                                        # Call the FullName() method on the Person object. Returns 'Trevor Sullivan'


class Server {                                              # Define a "Server" class, to manage remote servers. Customize this based on your needs.
    [string] $Name
    [System.Net.IPAddress] $IPAddress                         # Define a class property as an IPaddress object
    [string] $SSHKey = "$HOME/.ssh/id_rsa"                    # Set the path to the private key used to authenticate to the server
    [string] $Username                                        # Set the username to login to the remote server with
  
    RunCommand([string] $Command) {                           # Define a method to call a command on the remote server, via SSH
        ssh -i $this.SSHKey $this.Username@$this.Name $this.Command
    }
}

$Server01 = [Server]::new()                                 # Instantiate the Server class as a new object
$Server01.Name = 'webserver01.local'                        # Set the "name" of the remote server
$Server01.Username = 'root'                                 # Set the username property of the "Server" object
$Server01.RunCommand("hostname")                            # Run a command on the remote server
#endregion PowerShell Classes

###################################################
#region REST APIs
###################################################

$Params = @{
    Uri = 'https://api.github.com/events'
    Method = 'Get'
}
Invoke-RestMethod @Params                                   # Call a REST API, using the HTTP GET method
#endregion REST APIs

#endregion Basics

#region Active Directory

#region Support Functions
### Check if we are running as admin
# PowerShell 5.x only runs on Windows so use .NET types to determine isAdminProcess
# -OR If we are on v6 or higher, check the $IsWindows pre-defined variable.
If (($PSVersionTable.PSVersion.Major -le 5) -or $IsWindows) {
    $currentUser = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
    Return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
Write-Output (0 -eq (id -u)) # Must be Linux or OSX, so use the id util. Root has userid of 0.

### Test if computer is trusted to domain
Test-ComputerSecureChannel -Verbose

### Change size output to human readable format
$size = ''                                                ### Size is usually populated by a command that gets a file size
Switch ($size) {
    {$_ -ge 1PB} {"{0:#.#' PB'}" -f ($size / 1PB); Break}
    {$_ -ge 1TB} {"{0:#.#' TB'}" -f ($size / 1TB); Break}
    {$_ -ge 1GB} {"{0:#.#' GB'}" -f ($size / 1GB); Break}
    {$_ -ge 1MB} {"{0:#.#' MB'}" -f ($size / 1MB); Break}
    {$_ -ge 1KB} {"{0:#' KB'}" -f ($size / 1KB); Break}
    default      {'{0:n0}' -f ($size) + ' Bytes'}
}

### Unix equivalent of touch
$file = 'path\to\filename.ext'
If (Test-Path -Path $file){
    (Get-ChildItem -Path $file).LastWriteTime = Get-Date
} Else {
    Write-Output -InputObject $null > $file
}

### Convert Phone numbers to a standardized format
Function Convert-StandardPhone ([String]$N) {
    If ($N -match '[0-9]'){
        $p = $N -replace '[^0-9]',''
        $p = $p -replace '^0' -replace '^1' -replace '\s' -as [LONG]
        $l = ($p | Measure-Object -Character).Characters

        If ($l -eq 7) {
            $PN  = '{0:###-####}' -f ([long]$p)
        } ElseIf ($l -eq 11) {
            $p = $p.Substring(1); $PN  = '{0:(###) ###-####}' -f ([long]$p)
        } ElseIf ($l -eq 10) {
            $PN  = '{0:(###) ###-####}' -f ([long]$p)
        } Else {
            $PN = $N
        }
    } Else {
        $PN = $null
    }
    Return $PN
}
### Usage: Get-ADUser $env:USERNAME -prop mobile | Select @{n='mobile';e={Convert-StandardPhone $_.mobile}}
#endregion Support Functions

#region Schema Level
### Get Schema Version
$SchemaVersion = (Get-ADObject -Identity (Get-ADRootDSE).schemaNamingContext -Properties objectVersion).objectVersion
Switch ($SchemaVersion) {
    {'13'} {'Windows Server 2000'}
    {'30'} {'Windows Server 2003'}
    {'31'} {'Windows Server 2003 R2'}
    {'44'} {'Windows Server 2008'}
    {'47'} {'Windows Server 2008 R2'}
    {'56'} {'Windows Server 2012'}
    {'69'} {'Windows Server 2012 R2'}
    {'87'} {'Windows Server 2016'}
    {'88'} {'Windows Server 2019'}
}
#endregion Schema Level

#region Domain Controllers
(Get-AdDomainController -Filter {OperationMasterRoles -like '*PDCEmulator*'}).HostName ### Get the Primary Domain Controller Emulator

### Get List of all Domain Controllers including which have FSMO Roles
Get-AdDomainController -Filter * | 
Select-Object -Property Forest, Name, OperatingSystem, IPv4Address, Site, OperationMasterRoles | 
Format-Table -Autosize

#endregion Domain Controllers

#region DNS & IPs

### Check if IP address given is a valid format
Function Get-IPValid ([String]$testip) {
    If ($testip -ne '0.0.0.0') {
        ### REGEX Pattern
        [regex]$pattern = '^(?:(?:1\d\d|2[0-5][0-4]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-4]|2[0-4]\d|0?[1-9]\d|0?0?\d)$'

        ### Evaluate if the test IP matches the REGEX
        If ($testip -match $pattern) {
            return $true
        } Else {
            return $false
        }
    } Else {
        return $false
    }
}

### Get a list of all DNS Servers
$DNSServers = @()
$Results    = (
    (
        & "$env:windir\system32\nltest.exe" /DnsGetDC:$env:USERDNSDOMAIN | 
        Select-Object -Skip 2 | 
        Select-Object -SkipLast 1
    ).Trim() -Replace '\s+',','
)
$Results | ForEach-Object {
    If ($_ -notmatch 'WARNING|successfully'){
        $DNSServers += [pscustomobject][ordered]@{
            Name = $_.Split(',')[0].Split('.')[0].toUpper()
            IP   = $_.Split(',')[1]
        }
    }
}
$results = @()
$DNSServers | Group-Object -Property Name,IP | ForEach-Object {
    $results += [pscustomobject][ordered]@{
        Name = $_.Name.split(',')[0].trim()
        IP   = $_.Name.split(',')[1].trim()
    }
}
$results | Format-Table -AutoSize
#endregion DNS & IPs

### Get Bitlocker Password
$C = Get-ADComputer -Identity 'ComputerName'
Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $C.DistinguishedName -Properties 'msFVE-RecoveryPassword' | 
Select-Object -ExpandProperty 'msFVE-RecoveryPassword'

#region Getting AD user objects
Get-ADUser -Identity 'samaccountname'                     ### Standard basic get AD User
Get-ADUser -Filter {} `                                   ### Attribute -(ceq/eq/ne $true/$false) -(AND/OR) Attribute -(clike/like/cnotlike/notlike) 'text with wildcards*' etc.
           -SearchBase OU=orgUnit,CN=domain,CN-local `    ### DistinguishedName of an OU
           -Properties attribute `                        ### Any attributes in AD that are in the current Schema
           -Server ServerName ` |                         ### Domain Controller to send the query to
Where-Object <#?#> {$_.attribute -match 'blah'}           ### Where-Object {theobject.attribute -matches 'the text of blah'}
### $_          The current object
### .attribute  The attribute you're selecting to scrutinize (ex: $_.samaccountname)
### <condition> The condition is how we want to look at that attribute - in this case we're looking for text matches (not case sensitive)
### 'blah'      The text we're trying to find.

### NOTE: Get-ADComputer works in almost the exact same way
###       It is always better/faster to apply as much in the filter as possible before resorting to the Where statement

### Most useful/viewed attributes
# Attribute          : Inline Expression
# -------------------:-------------------
# DistinguishedName  : 
# SamAccountname     : 
# Name               : 
# DisplayName        : 
# EmailAddress       : 
# Enabled            : 
# EmployeeID         : 
# GivenName          : 
# Surname            : 
# Company            : 
# Title              : 
# Description        : 
# Department         : 
# MemberOf           : @{n='MemberOf';e={[string]$_.Memberof -join ', '}}
# Manager            : @{n='Manager';e={If ($_.Manager) {(Get-ADUser -Identity $_.Manager).Name}}
# CanonicalName      : @{n='Container';e={$_.CanonicalName -ireplace '\/[^\/]+$',''}}
# UserPrincipalName  :
# mobile             : @{n='MobilePhone';e={Convert-StandardPhone -NumtoConv $_.mobile}} ## Convert-StandardPhone is above
# OfficePhone        : @{n='OfficePhone';e={Convert-StandardPhone -NumtoConv $_.OfficePhone}}
# otherTelephone     : @{n='otherTelephone';e={(@($_.otherTelephone | ForEach-Object {Convert-StandardPhone -NumtoConv $_}) -join ', ').TrimEnd(', ')}}
# Fax                : @{n='Fax';e={Convert-StandardPhone -NumtoConv $_.Fax}}
# PasswordLastSet    : 
# whenCreated        : 
# whenChanged        : 
# LastLogonTimeStamp : @{n='LastLogonTimeStamp';e={[datetime]::FromFileTime($_.LastLogonTimeStamp)}}

Search-ADAccount -LockedOut | Select-Object -Property Name, SamAccountName ### Get users locked out
Get-ADUser -Identity 'samaccountname' | Unlock-ADAccount                   ### Unlock user
#endregion Getting user objects

#region Groups

### Find Empty Groups
Try {
    $EmptyGroups = @(
        Get-ADGroup -Filter * -Properties isCriticalSystemObject, Members -ErrorAction Stop
    ).Where(
        {
            (-not $_.isCriticalSystemObject) -and 
            ($_.Members.Count -eq 0)
        }
    ) | 
    Sort-Object -Property Name
} Catch {
    $PSCmdlet.ThrowTerminatingError($_)
}

$EmptyGroupTotal = @()
$Act      = 'Working through Groups . . .'
$pi       = 0
$Progress = @{Activity = $Act; CurrentOperation = 'Loading'; PercentComplete  = 0}

Foreach ($EmptyGroup in $EmptyGroups) {
    $pi++
    [int]$percentage           = ($pi / $EmptyGroups.Count)*100
    $Progress.CurrentOperation = "$pi of $($EmptyGroups.Count) - $($EmptyGroup.Name)"
    $Progress.PercentComplete  = $percentage
    Write-Progress @Progress

    $cParam = @{
        Identity   = $EmptyGroup.Distinguishedname
        Properties = 'CanonicalName', 'Created', 'Description', 'GroupCategory', 'GroupScope', 'MemberOf', 'Membership', 'Modified', 'Name'
    }
    $cGroup = Get-ADGroup @cParam
    $EmptyGroupTotal += [PsCustomObject][Ordered]@{
        Name          = $cGroup.Name
        Description   = $cGroup.Description
        GroupScope    = $cGroup.GroupScope
        GroupCategory = $cGroup.GroupCategory
        Memberof      = $cGroup.MemberOf
        Membership    = ($cGroup.Membership).Count
        Created       = $cGroup.Created
        Modified      = $cGroup.Modified
        CanonicalName = $cGroup.CanonicalName
    }
}
Write-Progress -Activity $Act -Status 'Ready' -Completed
$EmptyGroupTotal | Out-GridView

### Find empty OUs
$ad_objects = Get-ADObject -Filter "ObjectClass -eq 'user' -or ObjectClass -eq 'computer' -or ObjectClass -eq 'group' -or ObjectClass -eq 'organizationalUnit'"
$aOuDns     = @()
ForEach ($o in $ad_objects) {
    If ($o.DistinguishedName -like '*OU=*' -and $o.DistinguishedName -notlike '*LostAndFound*') {
        $aOuDns += $o.DistinguishedName.Substring($o.DistinguishedName.IndexOf('OU='))
    }
}
$a0CountOus = $aOuDns | Group-Object | Where-Object {$_.Count -eq 1} | ForEach-Object {$_.Name}
$empty_ous  = 0
ForEach ($sOu in $a0CountOus) {
    If (-not 
        (
            Get-ADObject -Filter "ObjectClass -eq 'organizationalUnit'" | 
            Where-Object {$_.DistinguishedName -like "*$sOu*" -and $_.DistinguishedName -ne $sOu}
        )
    ) {
        $ou = Get-AdObject -Filter {DistinguishedName -eq $sOu}
        $ou
        $empty_ous++
    }
}
Write-Output -InputObject "-------------------`nTotal Empty OUs: $empty_ous"
#endregion Groups
#endregion Active Directory
