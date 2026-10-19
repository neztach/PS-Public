<#
    .SYNOPSIS
    Collects detailed local Windows hardware inventory and optionally emails an HTML report.

    .DESCRIPTION
    PowerShell 5.1-compatible, read-only local inventory collector intended for repeated use
    across Windows laptops, desktops, workstations, and physical servers.

    The report focuses on physical and operationally useful inventory rather than dumping every
    WMI property. Empty optional sections are omitted from console and HTML output.

    Inventory includes:
      - Computer identity, chassis/form factor, Dell computer Service Tag and support link.
      - Windows edition, release, full OS build, install date, last boot, uptime, and last update.
      - CPU, physical memory arrays/slots/modules, physical disks, disk/partition/volume correlation,
        local volumes, and display adapters.
      - Battery details when a battery is present.
      - Physical Ethernet/Wi-Fi adapters only, enriched with IP/DHCP/DNS/gateway configuration; VPN
        and virtual adapters are excluded.
      - Monitor manufacturer/model/serial, active state, connection technology, current resolution,
        preferred/native resolution, refresh rate, and EDID product code.
      - Physical and network printer queues, including TCP/IP port and vendor driver details; common
        software/virtual print devices are excluded.
      - Dell dock information when a Dell dock is actually detected.
      - Physical/virtual platform classification plus system, chassis, baseboard, and BIOS identity.
      - On Hyper-V hosts: physical NIC-to-vSwitch-to-VM relationships, LLDP switch/port discovery,
        iSCSI/storage paths, AD site Servers subnet discovery, and calculated replacement IP addresses.

    Dell dock discovery is layered:
      1. Dell Command | Monitor DCIM_Chassis, when available.
      2. Dell Command | Monitor DCIM_Docked, when available.
      3. Native Windows USB/PnP bus-reported dock identity and USB descriptor serial.
      4. Native Windows PnP container correlation.

    The Dell Support link is generated for the COMPUTER Service Tag only. Dock serial numbers are
    never assumed to be Dell Service Tags.

    .PARAMETER OutputDirectory
    Directory where the HTML and JSON reports are written.

    .PARAMETER SendEmail
    Sends the generated HTML report using the SMTP configuration embedded in the script.

    .PARAMETER EmailSubjectPrefix
    Prefix used when constructing the inventory email subject.

    .PARAMETER NoAttachments
    Sends the HTML report without attaching the generated HTML, JSON, hardware CSV, or Hyper-V network CSV files.

    .PARAMETER LLDPCaptureSeconds
    Number of seconds to passively capture LLDP advertisements on Hyper-V hosts. The default is 35.
    Set this parameter to 0 to disable Pktmon LLDP discovery.

    .PARAMETER SkipResponsibilityInventory
    Skips the system responsibility inventory (roles, services, shares, scheduled tasks, software,
    security posture and recent errors). It is collected by default and typically adds 10-60 seconds.

    .NOTES
    Author       : James Stephens
    Target       : Windows PowerShell 5.1
    Privilege    : Administrative rights are not normally required for the core collectors.
    Network      : Not required unless -SendEmail is used.
    Version      : 7.2.0

    .EXAMPLE
    .\Get-LocalHardwareInventory7_2.ps1

    Collects local inventory, writes HTML and JSON reports, displays the inventory, and returns the
    complete inventory object to the pipeline.

    .EXAMPLE
    .\Get-LocalHardwareInventory7_2.ps1 -OutputDirectory C:\down\HardwareInventory

    Writes the report files to C:\down\HardwareInventory.

    .EXAMPLE
    .\Get-LocalHardwareInventory7_2.ps1 -SendEmail

    Collects detailed local Windows hardware inventory and optionally emails an HTML report.
    Prompts for the approved user credential and uses that credential's password as the passphrase
    to decrypt the stored SMTP password.

    .EXAMPLE
    .\Get-LocalHardwareInventory7_2.ps1 -SendEmail -NoAttachments

    Sends the HTML report without attaching the generated HTML, JSON, hardware CSV, or Hyper-V network CSV files.
#>
<#
    LESSON 1: A script can take parameters exactly like a function
    [CmdletBinding()] and Param ( ) at the top make the script behave like a cmdlet: it accepts
    named parameters (-OutputDirectory), validation attributes, and the common parameters such
    as -Verbose. Param must be the first STATEMENT in the file. Only comments, including the help
    block above, and #Requires lines may come before it. That is why Set-StrictMode appears
    after the Param block.
#>
[CmdletBinding()]
Param (
    <#
        LESSON 2: A default value is evaluated when the script runs
        "$env:TEMP\HardwareInventory" is in double quotes, so $env:TEMP expands to the CURRENT
        user's temp folder each time the script runs. On a different machine, or for a different
        user, the default adapts automatically.
    #>
    [Parameter()]
    [string]$OutputDirectory = "$env:TEMP\HardwareInventory",

    <#
        LESSON 3: A switch that defaults to ON is a deliberate exception
        A switch normally means "off unless you type it", so -Verbose turns something on. Here
        SendEmail and ScanNativeSubnet default to $true because this script's normal job is to
        scan and send. Typing -SendEmail therefore changes nothing; turning it off requires
        -SendEmail:$false, using a colon to pass a value to a switch. PSScriptAnalyzer flags
        this pattern (PSAvoidDefaultValueSwitchParameter). It is a reasonable trade-off for a
        single-purpose script, but in a reusable tool, prefer a switch that turns behavior OFF,
        such as -NoEmail.
    #>
    [Parameter()]
    [switch]$SendEmail = $true,

    [Parameter()]
    [string]$EmailSubjectPrefix = 'Collected Hardware Inventory',

    [Parameter()]
    [switch]$NoAttachments = $false,

    [Parameter()]
    [ValidateRange(0,300)]
    [int]$LLDPCaptureSeconds = 35,

    [switch]$ScanNativeSubnet = $true,

    [ValidateRange(1,256)]
    [int]$SubnetScanThrottle = 100,

    [ValidateRange(100,10000)]
    [int]$SubnetPingTimeout = 2000,

    [ValidateRange(100,10000)]
    [int]$SubnetPortTimeout = 1000,

    [ValidateRange(10,3600)]
    [int]$SubnetScanMaxSeconds = 300,

    [switch]$SkipResponsibilityInventory = $false
)

<#
    LESSON 4: Set-StrictMode turns silent mistakes into errors
    By default, PowerShell treats many mistakes as $null and carries on, so a typo in a variable
    name quietly produces wrong results. StrictMode makes them errors. Each version adds rules:
      -Version 1.0 : reading a variable that was never assigned is an error, except inside a
                     double-quoted string.
      -Version 2.0 : also inside strings, plus reading a property that does not exist, and
                     calling a function like a method, f(1,2), which passes ONE array argument
                     instead of two. (This script uses 2.0.)
      -Version 3.0 : also reading past the end of an array ($Array[5] on a two-item array).
      -Version Latest : the newest rules, which can change when PowerShell is upgraded.
    StrictMode is scoped: set here, it applies to this script and every function it calls, but it
    does not change the console session that ran the script.
    Windows PowerShell 5.1 is stricter than PowerShell 7 in one place that matters: reading .Count
    on a single object throws in 5.1 under StrictMode, which is why this script wraps values in
    @( ) before counting.
#>
<#
    LESSON 5: Real bugs StrictMode exposed in this script
    Each failed loudly instead of quietly producing wrong data:
      - Cancelling the credential prompt left $SACredential as $null, and $null.Password threw.
        Fix: test the result and Throw a clear message (see Lesson 12).
      - A one-row table produced a single object, and .Count threw in 5.1.
        Fix: @( ) around the If statement (New-ResponsibilityTableHtml, Lesson 2).
      - Reading $Result.Error on a successful child-process result, which has no Error property.
        Fix: PSObject.Properties['Error'] (Get-LastInteractiveLogonUser, Lesson 12).
      - Older iDRAC firmware omits some Redfish properties. Fix: check that each property exists
        before reading it.
    The general rule: when a value might be missing, CHECK first (PSObject.Properties,
    .ContainsKey, @( ).Count) rather than turning StrictMode off.
#>
Set-StrictMode -Version 2.0

#region Runtime Variables
$ST                    = 'Stop'

<#
    LESSON 6: Choose one error policy for the whole script
    Most cmdlet errors are NON-terminating: PowerShell reports them and continues with the next
    line. $ErrorActionPreference = 'Stop' makes every error terminating, so it jumps to the
    nearest Catch instead of being silently skipped. Nothing fails quietly; every optional step is
    wrapped deliberately (Invoke-InventoryCollector, $Collect).
    The preference is inherited by every function the script calls, which has consequences:
      - Write-Error stops the function, so code after it never runs. Use Write-Warning to report
        and continue, or Throw to stop on purpose.
      - Native programs writing to stderr can stop the script (Get-SystemResponsibilityInventory,
        Lesson 10).
#>
$ErrorActionPreference = $ST

$ScriptVersion         = '7.2.0'

<#
    LESSON 7: Script-scope constants, and why the $script: prefix helps
    At the top level of a script, $script:NA and $NA are the same variable. Inside a function,
    $NA could also mean a LOCAL variable that happens to have the same name, which hides
    ("shadows") the script one. Writing $script:NA everywhere makes the meaning unambiguous.
    This script has one example of shadowing: Get-MemoryTypeName assigns its own local
    $UN = 'Unknown', which hides $script:UN inside that function. It works, because both hold the
    same text, but it means the same constant is defined twice.
#>
$script:NA             = 'N/A'
$script:UN             = 'Unknown'

<#
    LESSON 8: Error-action splats, named after the ActionPreference values they hold
    -ErrorAction accepts an [ActionPreference] value, by name or by number:
      0 SilentlyContinue  hide the error but STILL record it in $Error
      1 Stop              make it terminating, so it jumps to the nearest Catch
      2 Continue          show it and carry on (PowerShell's default)
      3 Inquire           ask the user (never in unattended scripts)
      4 Ignore            hide it and do NOT record it (-ErrorAction only in Windows PowerShell 5.1)
      5 Suspend           Workflow only; rejected elsewhere
      6 Break             open the debugger (PowerShell 7 and later only)
    EA0 and EA1 are named after those numbers. Use @script:EA0 when failure is a normal answer
    (probing a registry key that may not exist) and check the result afterwards. Use
    @script:EA1 for real work inside Try, because Try/Catch catches only TERMINATING errors:
    without Stop, a cmdlet's error prints and execution walks straight past the Catch.
    -ErrorAction never affects errors that are already terminating (Throw, .NET method failures,
    parameter binding errors). Add -ErrorVariable Name to stay silent but still capture the error.
    These splats exist only in THIS script; runspaces and child processes use -ErrorAction Stop
    directly.
#>
$script:EA0            = @{ErrorAction = 'SilentlyContinue'}
$script:EA1            = @{ErrorAction = $ST}

<#
    LESSON 9: Two CSV splats, and Windows PowerShell 5.1 CSV quirks
    In Windows PowerShell 5.1, Export-Csv and ConvertTo-Csv write a '#TYPE ...' line at the top
    unless you pass -NoTypeInformation. PowerShell 7 dropped that behaviour, so 5.1 scripts must
    ask for it every time.
    Export-Csv in 5.1 writes ASCII by default, so letters such as é or ü become '?'.
    -Encoding UTF8 preserves them, and in 5.1 it adds a byte-order mark, which helps Excel detect
    UTF-8.
    Why two splats? eCSV2 is for Export-Csv, which writes a file and therefore has -Encoding.
    eCSV1 is for ConvertTo-Csv, which returns text and has no -Encoding parameter; passing one
    would fail.
#>
$script:eCSV1          = @{
    NoTypeInformation = $true
    Delimiter         = ','
}

$script:eCSV2          = @{
    NoTypeInformation = $true
    Encoding          = 'UTF8'
    Delimiter         = ','
}

<#
    LESSON 10: #region is only a comment
    #region and #endregion do nothing when the script runs. Editors such as VS Code and the ISE
    use them to fold sections out of sight, and regions can be nested, as this one is inside
    Runtime Variables. Repeating the name on #endregion shows which region a long section closes.
#>
#region Embedded Native Sources
<#
    LESSON 11: Keeping C# source in a variable
    The C# code lives in single-quoted here-strings (@' ... '@), so PowerShell does not expand $ or
    other characters inside it. It is compiled only when first needed, by Add-Type with an
    -as [type] check (Get-NativeSubnetDiscovery, Lesson 15). Defining it here, before any
    function, keeps all native code in one place and lets any function use it.
#>
### Compiled on first use with Add-Type (the C# compiler is part of the .NET Framework). C# 5 syntax only,
### so the same source compiles under Windows PowerShell 5.1.

### DHCP Server management API (dhcpsapi.dll ships with the DHCP Server role).
$script:DhcpNativeSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HardwareInventory
{
    public class DhcpScope
    {
        public string ScopeId;
        public string SubnetMask;
        public string Name;
        public string Comment;
        public string State;
        public string StartRange;
        public string EndRange;
        public long   InUse = -1;
        public long   Free  = -1;
    }

    public static class DhcpNative
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct DHCP_IP_ARRAY { public uint NumElements; public IntPtr Elements; }

        [StructLayout(LayoutKind.Sequential)]
        private struct DHCP_HOST_INFO { public uint IpAddress; public IntPtr NetBiosName; public IntPtr HostName; }

        [StructLayout(LayoutKind.Sequential)]
        private struct DHCP_SUBNET_INFO
        {
            public uint           SubnetAddress;
            public uint           SubnetMask;
            public IntPtr         SubnetName;
            public IntPtr         SubnetComment;
            public DHCP_HOST_INFO PrimaryHost;
            public int            SubnetState;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DHCP_SUBNET_ELEMENT_INFO_ARRAY { public uint NumElements; public IntPtr Elements; }

        [StructLayout(LayoutKind.Sequential)]
        private struct DHCP_SUBNET_ELEMENT_DATA { public int ElementType; public IntPtr Element; }

        [StructLayout(LayoutKind.Sequential)]
        private struct DHCP_IP_RANGE { public uint StartAddress; public uint EndAddress; }

        [StructLayout(LayoutKind.Sequential)]
        private struct DATE_TIME { public uint Low; public uint High; }

        [StructLayout(LayoutKind.Sequential)]
        private struct DHCP_MIB_INFO
        {
            public uint      Discovers;
            public uint      Offers;
            public uint      Requests;
            public uint      Acks;
            public uint      Naks;
            public uint      Declines;
            public uint      Releases;
            public DATE_TIME ServerStartTime;
            public uint      Scopes;
            public IntPtr    ScopeInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SCOPE_MIB_INFO { public uint Subnet; public uint NumAddressesInuse; public uint NumAddressesFree; public uint NumPendingOffers; }

        [DllImport("dhcpsapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint DhcpEnumSubnets(string ServerIpAddress, ref uint ResumeHandle, uint PreferredMaximum, out IntPtr EnumInfo, out uint ElementsRead, out uint ElementsTotal);

        [DllImport("dhcpsapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint DhcpGetSubnetInfo(string ServerIpAddress, uint SubnetAddress, out IntPtr SubnetInfo);

        [DllImport("dhcpsapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint DhcpEnumSubnetElements(string ServerIpAddress, uint SubnetAddress, int EnumElementType, ref uint ResumeHandle, uint PreferredMaximum, out IntPtr EnumElementInfo, out uint ElementsRead, out uint ElementsTotal);

        [DllImport("dhcpsapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint DhcpGetMibInfo(string ServerIpAddress, out IntPtr MibInfo);

        [DllImport("dhcpsapi.dll")]
        private static extern void DhcpRpcFreeMemory(IntPtr BufferPointer);

        private const uint ERROR_SUCCESS       = 0;
        private const uint ERROR_MORE_DATA     = 234;
        private const uint ERROR_NO_MORE_ITEMS = 259;
        private const int  DhcpIpRanges        = 0;

        private static string Ip(uint v)
        {
            return string.Format("{0}.{1}.{2}.{3}", (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255);
        }

        private static string StateName(int s)
        {
            switch (s)
            {
                case 0:  return "Active";
                case 1:  return "Inactive";
                case 2:  return "Active (switched)";
                case 3:  return "Inactive (switched)";
                default: return "Invalid";
            }
        }

        private static void Free(IntPtr p)
        {
            if (p != IntPtr.Zero) { DhcpRpcFreeMemory(p); }
        }

        private static void Check(uint rc, string call)
        {
            if (rc != ERROR_SUCCESS && rc != ERROR_MORE_DATA && rc != ERROR_NO_MORE_ITEMS)
            {
                throw new Win32Exception((int)rc, call + " failed: " + new Win32Exception((int)rc).Message + " (" + rc + ")");
            }
        }

        public static List<DhcpScope> GetScopes()
        {
            List<uint> subnets = new List<uint>();
            uint resume = 0;

            while (true)
            {
                IntPtr buffer;
                uint read, total;
                uint rc = DhcpEnumSubnets(null, ref resume, 65536, out buffer, out read, out total);
                Check(rc, "DhcpEnumSubnets");

                if (buffer != IntPtr.Zero)
                {
                    try
                    {
                        DHCP_IP_ARRAY array = (DHCP_IP_ARRAY)Marshal.PtrToStructure(buffer, typeof(DHCP_IP_ARRAY));
                        for (int i = 0; i < array.NumElements; i++)
                        {
                            subnets.Add((uint)Marshal.ReadInt32(array.Elements, i * 4));
                        }
                    }
                    finally
                    {
                        Free(buffer);
                    }
                }

                if (rc != ERROR_MORE_DATA) { break; }
            }

            List<DhcpScope> scopes = new List<DhcpScope>();
            Dictionary<uint, DhcpScope> bySubnet = new Dictionary<uint, DhcpScope>();

            foreach (uint subnet in subnets)
            {
                DhcpScope scope = new DhcpScope();
                scope.ScopeId = Ip(subnet);

                IntPtr info;
                uint rc = DhcpGetSubnetInfo(null, subnet, out info);
                Check(rc, "DhcpGetSubnetInfo");
                if (info != IntPtr.Zero)
                {
                    try
                    {
                        DHCP_SUBNET_INFO s = (DHCP_SUBNET_INFO)Marshal.PtrToStructure(info, typeof(DHCP_SUBNET_INFO));
                        scope.SubnetMask = Ip(s.SubnetMask);
                        scope.Name       = s.SubnetName    == IntPtr.Zero ? null : Marshal.PtrToStringUni(s.SubnetName);
                        scope.Comment    = s.SubnetComment == IntPtr.Zero ? null : Marshal.PtrToStringUni(s.SubnetComment);
                        scope.State      = StateName(s.SubnetState);
                        Free(s.SubnetName);
                        Free(s.SubnetComment);
                        Free(s.PrimaryHost.NetBiosName);
                        Free(s.PrimaryHost.HostName);
                    }
                    finally
                    {
                        Free(info);
                    }
                }

                uint elementResume = 0;
                IntPtr elements;
                uint elementsRead, elementsTotal;
                rc = DhcpEnumSubnetElements(null, subnet, DhcpIpRanges, ref elementResume, 65536, out elements, out elementsRead, out elementsTotal);
                Check(rc, "DhcpEnumSubnetElements");
                if (elements != IntPtr.Zero)
                {
                    try
                    {
                        DHCP_SUBNET_ELEMENT_INFO_ARRAY array = (DHCP_SUBNET_ELEMENT_INFO_ARRAY)Marshal.PtrToStructure(elements, typeof(DHCP_SUBNET_ELEMENT_INFO_ARRAY));
                        int size = Marshal.SizeOf(typeof(DHCP_SUBNET_ELEMENT_DATA));
                        for (int i = 0; i < array.NumElements; i++)
                        {
                            DHCP_SUBNET_ELEMENT_DATA element = (DHCP_SUBNET_ELEMENT_DATA)Marshal.PtrToStructure(new IntPtr(array.Elements.ToInt64() + (long)i * size), typeof(DHCP_SUBNET_ELEMENT_DATA));
                            if (element.Element == IntPtr.Zero) { continue; }
                            DHCP_IP_RANGE range = (DHCP_IP_RANGE)Marshal.PtrToStructure(element.Element, typeof(DHCP_IP_RANGE));
                            if (scope.StartRange == null)
                            {
                                scope.StartRange = Ip(range.StartAddress);
                                scope.EndRange   = Ip(range.EndAddress);
                            }
                        }
                    }
                    finally
                    {
                        Free(elements);
                    }
                }

                scopes.Add(scope);
                bySubnet[subnet] = scope;
            }

            IntPtr mib;
            uint mibRc = DhcpGetMibInfo(null, out mib);
            if (mibRc == ERROR_SUCCESS && mib != IntPtr.Zero)
            {
                try
                {
                    DHCP_MIB_INFO m = (DHCP_MIB_INFO)Marshal.PtrToStructure(mib, typeof(DHCP_MIB_INFO));
                    int size = Marshal.SizeOf(typeof(SCOPE_MIB_INFO));
                    for (int i = 0; i < m.Scopes; i++)
                    {
                        SCOPE_MIB_INFO s = (SCOPE_MIB_INFO)Marshal.PtrToStructure(new IntPtr(m.ScopeInfo.ToInt64() + (long)i * size), typeof(SCOPE_MIB_INFO));
                        DhcpScope scope;
                        if (bySubnet.TryGetValue(s.Subnet, out scope))
                        {
                            scope.InUse = s.NumAddressesInuse;
                            scope.Free  = s.NumAddressesFree;
                        }
                    }
                }
                finally
                {
                    Free(mib);
                }
            }

            return scopes;
        }
    }
}
'@

### HTTPS GET for the local iDRAC pass-through link only. Certificate validation is relaxed on this one
### request object (never process-wide) because the iDRAC presents a self-signed certificate.
$script:LocalHttpsSource = @'
using System;
using System.IO;
using System.Net;

namespace HardwareInventory
{
    public static class LocalHttps
    {
        public static string Get(string url, int timeoutMilliseconds)
        {
            ServicePointManager.SecurityProtocol = ServicePointManager.SecurityProtocol | SecurityProtocolType.Tls12;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method           = "GET";
            request.Accept           = "application/json";
            request.Proxy            = null;
            request.Timeout          = timeoutMilliseconds;
            request.ReadWriteTimeout = timeoutMilliseconds;
            request.ServerCertificateValidationCallback = delegate { return true; };

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream stream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
'@
#endregion Embedded Native Sources

<#
    LESSON 12: Fail fast, before doing any work
    The credential is needed later to read the Security log and to decrypt the SMTP password.
    Asking for it FIRST means a cancelled prompt stops the script immediately with a clear
    message, rather than after several minutes of collection. Get-Credential returns $null when
    cancelled, and the check below turns that into a readable error instead of a StrictMode
    failure on $null.Password.
#>
$ME = $env:USERDOMAIN + '\' + $env:USERNAME
$SACredential = Read-Host -Prompt "What's the password"
If (-not $SACredential) {
    Throw 'The SA credential prompt was cancelled. The credential is required to read the Security log and to decrypt the SMTP password.'
}

$Keyword      = $SACredential.Password

#region Email Configuration
<#
    LESSON 13: Keep settings in one place, and never store secrets in plain text
    Every email setting lives in this one hashtable, so changing a recipient or server means
    editing one place, and the email function receives everything as a single -EmailConfig
    parameter.
    The SMTP password is stored only in encrypted form (Convert-PasswordCipher), because a script
    file is easily copied or shared. Encryption protects it only as well as the keyword is
    protected. A secret vault, such as Azure Automation credentials, is the next step up.
#>
$EmailConfig = @{
    To         = 'emailaddress@mycompany.com'
    From       = 'senderaddress@mycompany.com'
    SmtpServer = 'smtp.mycompany.com'
    SmtpPort   = 587
    UseSsl     = $true
    UserName   = 'mailsenderuser.username'
}

<#
    $EncryptedSmtpPassword: the Azure Communication Services SMTP password, encrypted with
    Convert-PasswordCipher (AES-256 + HMAC-SHA256, key derived with PBKDF2).

    The script decrypts it with the SA credential's password as the keyword
    ($Keyword = $SACredential.Password), so the value must be encrypted with that SAME password.

    To create or replace it, in a Windows PowerShell 5.1 console where Convert-PasswordCipher is
    loaded (paste the function in, or run it from a copy of this script):
      1. $Encrypted = Convert-PasswordCipher -Encrypt
           Keyword             : type the account's password
           Password to encrypt : type the ACS SMTP password
      2. $Encrypted
           Copy the printed Base64 text and paste it between the quotes below.
      3. Convert-PasswordCipher -Decrypt -CipherText $Encrypted
           Optional check: enter the SA password as the keyword; the ACS password should appear.

    Both prompts use Read-Host -AsSecureString, so neither password is echoed or saved in history.
    Re-encrypt whenever the SA password or the ACS SMTP password changes.
#>
### I am the best.
$EncryptedSmtpPassword = 'UFdDMUANAwCRodR+hlXUIiG5qitG1/fq7++6Sbu1gPd46gPFnCo9qK2jgcCZaUBl+g0ag4f80dkQRTSl6H1dADCv0zMiojarHtrGZ0wwpW5RtZLDpOr+msGxEWtzmJ6tOX0uSC1urNw='
#endregion Email Configuration

#region Embedded Report Assets
<#
    LESSON 14: Self-contained assets, and naming repeated values
    Every icon and the logo are stored as Base64 text, so the script needs no image files and the
    report loads no remote images. It stays a single file that works anywhere.
    $imgpng holds the MIME type used by most icons, and $common holds one icon's data shared by
    several keys (Workstation, Display, Monitor). Naming a repeated value once avoids typos and
    makes a later change a one-line edit.
    $script:HardwareInventoryImageAssets is the shared image cache described in Lesson 3 of
    Get-VolumeFreeSpaceChartHtml.
#>
$imgpng = 'image/png'
$common = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAT0lEQVR42mNgGOyAEZkjbhb7nxxDXp5aDDeHiVLD0PWy4LONVMNQXEgtMGrgqIFkABZCCZVsF5KaQyjJXXCXE+P6wR8pjMSUIKSEHdVdCACvdhkgmYFdJQAAAABJRU5ErkJggg=='

$script:HardwareInventoryImageAssets = @{
    'Logo'               = @{
        MimeType = $imgpng
        Width    = 104
        Height   = 91
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAAGAAAAC2CAYAAAAm/4gKAAAliklEQVR42u2deXxkZZX3v+e5Vdl674beYEQQUWnHrVl0VNKNMKJiL2hCg4OCrwwuoDIusziQ1LzMiM7igjiiDAgINFUgIMg4LpOO44IKo/DSzTgKCtJLmt7SSaeTVN3nvH88z5PcLrJUVaqS7g7388mnlyR17z37Oc85vwPT9FJVo6oRwHUPaVpVP62qu3Ibe/rec2/XWQAtWff9Wl6p6Uh4QEQk9v8+A/jb/905eMpNj/Tu/eW2wUaD1cl6ntQ0IboABrAiYgEGBwdPSqfTf9E7EK/JPd6nd27at7dgVZrqDHGMfZ4B1SM6XtpjgL5B/ZPGNJcAq/7r6f1NN/yyd89Te/LMboiiukisKkDE8wyYgHkpJrqqzh+MeUtdxPnAG5/ak6+/4Zc9e3/yzMDuupRE8xojYgWrIIKK4XkTVKKEBylXEYmDefHfnw28rmA521r+tC7i2IGCLWQ39fbe9XhfX1+eaFa9iRSIdereI3UImhQBYhFRQIEk0V8EnAKsBF4fW45NGVLAvp8+07/r67/q5Ynd+WhGnYlm1jGiq1UF4XkNKJbwQPA48f05wPHAMmA58BrgxcD82EJk6IsMPZv35vXmR3vND58aiASYU+9inNHiHAFUCjJtGVAUJg5JuKou9UQ+GXiVJ/5iYIZn0qCFfrXsigwUYmvu/fV+c8emfezeb5lZ72g6lebmoGaAT4o02HHPiNcAbwJOA14OLADqEs9dAAaA3tgikSHCED3SNcANv+xh07MFGtPCrHopObJXQDQ1fUyQJ7xNJEYvAs4B1niiNwH93vykgH3Ab4CNQDfwQmttc2SM7uyLC7c82iPf+10/1sKsekHHMDfT2gR5CacoI73QS/yRnug9QB8wH9gG3AjcCTwkIgOJz3prx+/23/zVX/bIjn0xM+sMElFRPnvYa0CIZhKEfwvwUeAN/nl6gGe97Z/jTcwXgGtE5A9FmiO5HCoiD6y5fdvPBi0rZzdEe2OrkR5ktn60y0y21IuIikisqstU9U7gm8AbgV5gtye8AIuAXwFvFpFPisgfVDXyRTTxcX8h5z83neKpuhSp2FoOpctMIvEjEbGqmlLVvwI2AGd7O77XP0t4nvnAl4AzROQh/zuB6NaHpABs37hBRMTmY+lXRUD0UGJAapKInxKRgqq+BLjWJ0q7vMSnkuYXmAlcLiLXJhhXKMF56iFF+cliQCCgqr4d+IqX7i5/7yTx8cT/kIjcoKopn4DFHMaXqSHhxRM/VtXLgDuARmAPkA5FM39ZYB7wcU/8tIgUkqZm/PtZeZ4BI0Q6qtoOfM472fwIWlfwCdYXRORab67y5d5TxOjzDEh8rif+VcCVwI5R7hcDs4GfAH/tQ8uKTI7yvAYkHW6sqp8E/sbbe1NkcsIV+YTrsiD15Zid533A6A73PODvge2eyCMRv+Dt/jUi8mhgXKX3Fqa5CfJJVqyqy32o2T2G5Kt3yE8CX/BliZhpeJkqEV/8n3OAf8NVLAujED/Y/pnA10Rkt7M8EzM9090HGF9GvgpXwdzL6Cfb6hnUBdzumTdh8zGZp1gHFQMSsf4bgPcCO32cP9plcYcoPxGRZ7z0W6bpZapjgTQC/q4oq2UMDYiA7yZbRw7inPLgZUAosAGrceXksUxPMvTcB/zC2/1pK/3VEBvrpf8yn+WaEqQ/jav3P1WixjzPgDGkX4HXA6fiDlLKYUD3dEy8amE43+mJqmXcs8efDQjT/DIVSr/4yKce17Gwf6q94HTLA8LLvgQ4xtdzTMm0cnnAtDc/E2FA+L1lPqYvp4xQAOZ57aFaZmi61oJeUuZniI+WFuK62hijXFFuQDatNCBI2xKGuxhKZUA4gHl1dRMxpiUD5lYgeurve2aiw3niTnianohV8vsR7njyTF89rUo4KsrzJ2JlmKF+4FjgHK8FEdP0mmgYuq9CJ2p87nCZqjZWSwuqJR2T2Zw7UQbs9J+hFdx3H/AK4MO+oDdBLZheUVC4tkwgjIxwnXF/qaqv8mfJ084UTTQK+q1PwqRCLYp9Vvw1VZ3hTVFl5ZFpFgWFl32c0s4AxtKCHuCVwFe9Q5ZK/IFMp864xBHik/6rYQJGOOV9yTpV/WffmhJNlVOe7AGNiZ4HFHBdbRNhQGDCduAjqnqF/9xoOpSrq5EH3I+r70yUWClcC2NbgglmspngwlDkUGBAkPgfeV/QVIVY0CSYcJU3RzL5mlA4+DVARNS3Ew4Ad1eJAaE49yyuWfeaMBEzXnRUrSjokPEBRVrwDS+56SpZgeATPqCq61W1yR9hRmM5JapwwHMomSACUUTk97hhuzlV1N/AhHcA96vqEn8MOtpUTyPuqNROCxN0oOyp4IYw9njCVUuFQwfFnwDfT2TMQ0xYuGyFOsnVh0GNKvWg8XQxQSEnMCLyG+CruJbzanY6p33J4gXAd1R1bShbqKrkWiWmrc3cvW7JjQbWoRqDzER18sR4ijWARAnhH3EwAo1UtzoWIArqgNtU9ZN+ZNU550zGtqmau9ctyaWUMxF+jciCSphwSPmAZETk/pA9wF9XKSIaqWyR96WPf1DV61W1MfihjIht7uhI3XX+4kdnFAbOAO5WYSFIjB683XdVO5DxDjISkXuAm4EjPMGq/bzi/cKF3iQdG5xz58qVhZZsNrrtXcfsvnfd4nMjw1WozlOIyvMLhUOPAUWm6BPAr3FDGNWefEmGqacAP1DVlcEvZFtaLKrS1qbm7tYlbSnDhcZgVWVGKSbpkHPCo5ii3cD7GG5Fr8ULpX3UNR+4R1UvHfILIJmM2Oa2jtRd5y6+vUnsWZGRJ9V1Y+QPSxM0gil6EPgwlXVOlOOcB4BB4POq+pWkX+jMrCw0t3Wkbmtd+vDMdMPp6cjcD7oI9KDxCzWBKgg2WURuUtXjgCtweD/pGgmRer/wPuClqnqhiPw+YFS0ZDW65RzZKSLnnJvruro/tn8RK3sNUoADs+tD5Uy4lCtoQpvPDxbVUP2TfuFU4D9V9fRhv4BFVfTKK836dy78qzl18ud1EcaqbSr2C4e0DxjBHwSn/EHg1hozYSS/8P6kXyCTsS1ZjW5au+jrC5vk7MaUbFWYp1PoF2raF5TofFPcAN/6SWBC8AsDwDWq+kVVrQt+IdcqcXOHpv717EU/edkRqTfNbYx+hLLQqhamolu75o1ZiZeKgXf7HGFxjYPt4Bd2eO27X1WXDucLzi9kVh7xzE2rj3zbUXOiG9KRHBlbq0bQww60L1HPt14T+oD3e8c52jR9Nf3Cad4vXCgiDwbn3NamRkQGDPz5pzp2/u8Tu+L27gEbRSaKDxsNKCra+b/Kh4B/wMXlUNuuqlDMWwp8W1XP987ZtLejqIrNZqP/u3LBP51+TPrPls5O57E0HXYMSPoEHx1dAVzus+UUtcWKSHmtU+BGVc0MnbSB0NoaN3d0pN530rx73nZs6oyTlqafBDhxY+1zhalp/XDnBwFZZS3wNVylc1+NzWKYSz7SBwSXiEhvmPZvyWajXGvrpIKGTGnbRwLM77W4Y82lDEOa1fIq+GLhz4B3i8iTQ35B1bQ7CGU97BlQxIQXeiac6p1zrZmQ92WSbcBFItKZAAo89BOxMvxCIXGu/Bbc2fIiL6W1JEQaNyy+ALhXVd/re5EmtQ3moJjP8vG5EZEeYB3wT95ESI0jpBRuWCQPfEVVry61DeawMUEjOOeQN1zsGaG4YY7Jcs7fBN4rIj3BOU8bBiSYEODPTschcC2aJOec90x4EDjf41WnSkHuPWwYMIJzPs6XL071pYXUJDBhHg7N5XwR+e9aMuGgndFNOOcngbOALG7AO54E57wHOAp4QFXPKu5FmhYMKHLOvSLyLuDTPmqZDOcc2mByqnpBshdp2jAg1JA8DrURkb8FLvFSWk9tK6qhDaYfuF5VP+YdclVb5g+ZAYii8sVK4CavDd01ds7hPGMBcLWI/K0PUauSLU9lLWgkadcSfje5i+BW3KjrjklgQghT/1VELk2GzAc1A4o24CluY5KO8fNR4md1pG7nBFTmPB+mrvLli6jG71TwIfGNwMX+GSfUkS01JvpoBEzh+kfrGYaw6ReR/jLuEZggwD/jWmB2MQwGUsswdZHXvotCMFCpJkiVCX/AsmT/f3NwaLqvxAE8vdCHkzOLGLAfNy35B+AJXGfd48DvcRhzOsr91GfOlwFXM9wnFE0CE9YD7/FMqMgnSBUJT2IL3hLgDF9cW44rMzd46Sz4LxsenGE0xVmJZ+rCbVG60ydi+VGYkMyc3wZc75nbW+OkLakJ7wlms1wmSDVMTWIn2Mm4M9+3eKKHOs4ABwI7ScKxNeJgz3qA/wa+D/wQ2CgieyvInF/piXK8N0npSWDC9SJySWIroNacAT4uDxL/SuCTuLVUjV76BhgeupMRnFkg/BNADrhLRH41EpNLfaEEE5Z4JpyGO5SvJROCY/6siPxVuWWLVIXEDw5wBm5Lxvu92nfjzl6jUT479t87AjfI8WXgVt/Mm3TQQ9FSqcT3HQ6hfLFVVc/GdeSdx9iLJKqRNXcBn1DVbSLy+XKYIBMg/sm4RQ3LvarH4zi+grfxeeAa4HOB8MWbVCea22hiWE9VPwN8zDt4qRETgh+bA6wTkXtKLWWbcux9YkvGRcB/ACd67lMC8RcAj+JWE14pIrtDbaV4HXmZ7y4Aa25/5oS2tjYXFbUf8Lx/CXwctyzI1KiGlASwut4PE8alwO+YUonvna1V1YxXbett/Xj2NfYZ5E241YQ/L1pNOKFMsrltg3/J6C8eWXZpdvl1D6XJiG0HMWZojPbzPmZP+wJbLQ5ZjNfueuBmnySOe7JmyiB+rKqfxbWa7/QMiEogfqihXCwifQHko+oH3yJ7ovrGdxw1++i7WrJPz8+I2HfeMWQuUyKyHodzPYCbYatFIS/A77wM+Bev1TJRDYgSO8E+7k1OKQ4ttH58xhewhsxNraqXhf09/cAZg3Hdd96e3XpsrlXi5raOEBmlROR7wFt92WJ2jZiQ9rWpC1T1PeOZIlNiWHcZwzvBSomcgs2/xRM/VW58XLYCGBQkJcJOhZeL5XtrsluWd2ZWFpo7NMmE/8Yd8PwWd/KVr5EmdOOmOY9hDCQwM060U1DVNwGfSRS7xrvCjpiNOFREU2viF4eFAt2CLFQr3169vuvNnSulkNCEyA+VvwV4mNpMc4ovhxwJXBVm50pmQKixqOpC4F/9h5UTtkbAR0Skl6lY0iOkQPtA6kBzq2/vuqAzs7LQkh3yCZGIbAHeBvynJ1S1mZDy4fk7VfXM0UyRGdWlOaJdjQNYLXU/QNiOd4uI/HAy2jqG1O45m7Ql8pMvA4pev3r9to/lWiVua1Mj3iT4wfI1uFaUhTXShBiHf5RmGFdjdAYkEq0zgPN9xFOK3Q8FtZ3Ap6u1H6z0IOi5eEECBkUR9qjymTW3b/lMJiMWAWlvD+WUfv+eYYSqmo7Z+KjoVOAdAVdjPA1QVa0D2hl7G95IIeccYL2IPMXwcrfJuUbbJS+IgIjwrIr5+Kr1W2788+tIkcnY9vahMNuKyHtwC6cX1oAJA94fposTQTOC9FvgHEpfzJO0+/uAm6YEbG9sxCwZrtmYC7bN7rrrrFt2zM5kxLbmciZRXPwQ8MUqM8H4hPUk4Cx/dhGNpgEBler9nmulEj9EPr8CHvFO5GBczpkW2C7CWXXpwv0t2a7FudbWuDXnTu+y2WwkIpfXgAnBRF+U+PuBDEispXodcLKX5nIYUA/8YMrQ0G3J61DSwA5BTh6w9rtvz3Ydn2uVeEX7hqilpSWULi4HvuSjo2owIWTIp6nqS31Jx4zmA8719RJbppoN4hAUYQqWs6kp655p1O4R5EXG6r+vzna9qjOzsrCifUPEcIT0EeCGKkZHBdw8wjuSwh/sX1hLNRN4k5f+qAzVCun34wmNmGQOlMl0kRTKXlVdjNX712R3nNKZWVlYsWFDlCiifQC4q0p5QoDsf2tydbspMkWvxq2lGigj+gkM2Iw7+JiS9VQVtiSkRNgHOktt/ltrsl1v6Fy5stDePvTuFodL9F+46ftCFRiwDHhFcMamKMN9rbfltsx3TwFbk7bt0LkkAvarSoPG+s212a2nZzJipX0oIe3zecKTTBz/KCyyPmO4hHWgyXg1lcHRR0H6map2R1GdCBNEtB+hzlpue3t267FkRGV4pHYbbnJnP+WtbRwpHM7jUCABrAnHd75i+SLvTKVMDRDv5aeMARNf5OY0AZVZUd4eBWhLLmcS5wmPep8wcwI+LiRly1R1tojYpLmYm3A2lRDxMFhLKEbQWKKoUFQYC6Xsu3BdeEdU6A9ClXQJ8OLAkUDseQnuVroRYwppR7Wwo0XjEd8lVDPbvFOeU6E/iHEtOctGYsBE9gCkp1Z6qxP5qjNGzy3seZgFEckDl3p/UCkengAvLU7EGir8wDCtMndKTVEVM4/CqKmD85UishH4LJWhBId1ji+E6nURx94uTk0SNrlX7EPtL/q614wy3zkwYKmqiilifKXqFD6wzicYh+3qkQQ0537czFpDmXQL9JoHzEguYdvrPbSpgAF5HApWlVfUlmG7q7HAwfehih07pwjDg7jFFT+rIDQN1eOZSWLvYfjoUStgwDxcP8zUR0STc4Wu8K+VWT0IPrMJmJMk9k7cIXIlDbuhHnTK1DFg0l1PcL734Dq8G8sQ3FC+aTDBZnub9rQnZLlvE8rRbyh6uEmsREwu00Mxzc8wPEB5q91D9WCoGBdKz/+vwlqHwbWlv1pVXzSZaCNV9yVlBhD+5/+d8s7Ph1Pvotj9wQlkwnlcyfbtCaYcqlFOyXbP//zDuMWm9SUKb+gYiYuroT9jGK2qEi3oxzUipSbbDE3FMs+E+d4F/G8ZDAhCXzCJDzIistUzodzkIjCgFzewcXrx6f+h44QVkypL+MI7birRf2pCWHtMEQHBjV5WsqQ5eV02pWWJiUq2rQi8+3eU17rZC+wxRSl2cCi/KTOsSn7wXuAMj15uD70lzaJqnBSf2NKiJZoScAdSpfjP0DWy6wANCO0kvqH260zs+M0CVwaMnUOmNCGIojYuxO4Avr2s3+4t0Q6GnOmp4gOZpBb8G25CvYHKnPFenxNcHPYDT0JiWiUeoBUugisVSCokYb9+zlN7LTDeq38ON0VSycOEAYU2VT0+YDXX1nBUaaO2ikpc0flyQ4lSEDqmHx1NbEJnw/U+IppFZTXvvGfgV3xTak3xOFUmqgKiqogKBdXCYJnvis+Bxgtekj1UD43IgES5dQA3E1bpbG3QghW4ObGarioXlYl9rioiCKqDktI+gEx7Web3mBIdcCPwqIhsLj4PSDIhTJH8BDeeVGlnWMondpep6kfDqvKaMMAQVaEhTBApDKbS5bxrcLwnllCOsLi2z+8EIR1LbUMI+fc+NF1AZZ0AIeS6WlUvDh0G1dYE69pKJuzJBfbF/dJXah3Ih9ozgT/2ydVYNA3m5+7w2Gacmoh60/Fe3FThrAqYEEzYXtxOlw/WYl+8WDsxHyCiqBqUgV37Nw8eYN3HYJh/hz/BnfH2j/Fbsafff4jIU2EWw4xT6wjt2l1AK+7QpqlCp4z3CZ/3CxTiapQrwj5hRCIm0BynoR9C6Hn4kpPywbOUWLx7VwkRUOgJuras4DnhDzbiWqv7vCOpVBN2AZ9S1ZtVddY4W7LLiYJSbqV5ZVolqCIYkF3g0FfGMT/Gm+mX4WB69o7h38IZ8D0eqmEIY8mUpp1D7Xk/A1Z7Sa7UHEXeMZ+H25L9Gu8XZCLaYKqDbBuhdgfApmXjGiDjpf+KcaoGIfTsBv5u3CnJMZgQ2vN+jhtyfprKJ81T3hktA76rqpf70Df2kAZl23NVSU2s9jd0iNQFsH3jBhlD+sPQ9zneKuweR/rn+1D8NxQNL5b1oolJ8424FusfU/myhZSvn4DbxP09VX1DgK4plxEqmlad+FyCqm4e5/uB+C8GvsDYo1yB+P/hfV/EWFOSZZijMGkeUKmO8BJQKFvl3QM9i5tNeEBVv6qqL04wwoyF2Rw2HQnSKBPqD1URkUKUSv3hAOc+MvEXAnd4CzBaN3nsA5YtuGVBBUYA9asodEuAau8XkQ/gtpgO+AcqUH6nWArX3t6Pm0j5oap+XlWX+Y0WQxGTZ8jQCyey1UZVbMVFORUjsD8d6TMAJ7YMM9PfMxD/WOA+XG9nzyimJ8adjuVxCFpPJ0aAq1NCTIBqRyJyE9CcSNjqKzBLAQJnp3daHwI2qOotqvpmVa0PWpFgRtTmpU9E60WorCtPURVSxsjuo+cXNodSdNA+f8+Cx6H7Pg4HtZuRW3gCIGHsif/zsSAbqoUbGiWgKy8APoWDjexmGES13KGP2L9gqMhuwrV/3Ac8nJSmbDYb3W5P+0mseqIfKSpXsKy12jS3wWy8ee3CN27YgK5cOQy65+39J3GjSgFRfSTJD5uZdgDnishPxwPwqwqwaaJVT0XkFlV9APgo8H98HanbP1ypjJDEs+32/z4Bh777YWCTqv4A2AD8sj1HrzHbm+JYLYpUAkUoInUz683/+PbzEOefDPwZDmlrgX8WRiB+GOta5CvIF4nIr0tBT5RKjOUBhqXIqRRpw4twvfTrPCN6EvWSsqWUYZi0RqDBWvLG8MyW3njLR/9958v6Y41MRY5YY0HmnvOyGbde8IqZ37SWZmN4HQ6ZvdEnWfkRBDY802yvtV8BrkxAs1UJNVFVmts6Ui47FEUSXwd8b0gbgm94wk+dv9GHmjt8xDSTYRjjUh228QQQn43vUMfQI3sG4pP6YzWm4ihIIqva87qj6tbioJIvxw0sDjCMj5cqkvhg64/A9QWdLSIf98Q3pUI1pMYjfEsOkxOJO6HQCbRkH6vrZvbMGVE6lYpNX06kd/h7bhejD7XiBJj3b4G/VtV/BtbipvFPwrW/9OOagoMal7LeNqlB+a7eeHCgoGZGnWDLZIEAeYW5dYb5TSYGujFDrSOB6VqkgbP9/z+GgzS4OeRIuGatkqPAURnQks1GOZE4B/Hau7YvsfnCKsWcPmj1xQ0w21pJDaJ9q+/o2oyNfwhyS651ye/b2tRkMhIg3W3CnoqI7MB1E39NVZfjcP/f7EO6md5hh8VqNlE/GutQSJ7dZ8VOYHA0LijzmyJm1x0A32AT9f0At1/nk8cf4gDF7/Y9tVQKTiUjE9+t/j771s1HRFH0Me/9lwIxqoMqEosrIBqEtCr1Do9Hr/rWuUuubVM1mZH3BhwA9h2SG+9c3+RD2WU4fIY6T4BBz5AQ1g7hr8UWiQxc+4tuc8//7GdWffkaYAR6B5Q3HlMfX3HaPLHukCTgi6Y8I3b7KOz7wANJjOtKALvH1IBA/DW3d/2pin5R4XiBblR3IAhiRBKxtioDgu5VJG2IvrTq9m31GZF/GWk1bDBNRVpR8Db0YeCzqrrIH24s94x5sWf+HE+UgH5rxRADdkdfPGAmkAVb4I9mRXOBvFp6MGzG7RHbhEN0f1hEnigWJE/4CbVgpkYi/qr1XRcp+iWgILAdJYVIaihElwNUSHzkN2DVbhfhU+fcuf2+3DsX/iZpjkZK5BIvE14o9mcPXV7agoYswZ25vtD/eRSw0MC82NqZO/rsCyJDWiuoxllFG1Kk9xXsFcCP84YtEWwbaZtHAn7TUqXe19RzJP+Obeep2utAukFi0PSo1ldR1w8iM1W1QUR6UZ1dyNtW4O83sGFcrOZw8hZ+rmjnjPUa8gf/9aPi3+9QTW3eG/84bTjRKn1STnjrnr8+JfL0pafM+8dLn1vvD10OGrJhqnyZcPiQa5V47fpnT1bVryiyVx0EUjR6gIR18JAyF9VfCXxK0bVGeEUhkn8D6MysKN8pOcj62MMbD+0Q86WHlP+Ksr5A137blrlWOVJE8mUPaYi6BRIuY5XsY4/VhVpTIPjEgMVL0gAVaOesB7Te7t3+BZCUoPsZ85BbYsE2gXSj8pG6aNFtudaRbGEV9mwNa8hzorTW1lZdk916nFqOUKVfpLLSitr4uyKizW0dtvXlk4txapo7iDKZjK3v3vZnip7iygZjEt+q2gYV2Wktb7v3vEW35FqwzW0dqZZsNmprU8Mk9IJu33ikeBv+cqBRpEybrKgDdpUt9Sk6ATrbV0z6aFWqcwVxS1brBm3X+2V4+8XYZROI4theeP+7lj7akn2sLicy2Jk8C8jU/sGH6vWW5S4wKJPnolZVZoB+O9e69NnRQueaawAiOmC3vhZ4OeNWEjVGmAt84/53Le1cft1D6VzryweZgivXKnFLNhsh8ipE+rWi0rqi7mCFTbmpGa01/izoTNA6dLy+DjEK+4jky6jKcfOenBJYglB36su/7jhBT1DVgbKjH6UJkU0NUf4HjqFTA7HgCmiW14AMqo6Bpg4WpEmUR+9tWfSYe+jWKcEG9eGtpNJ1rweZG0rI5VQ/FWlC9bZc6wv2N7d1pKoRMFTEgDNv3jpDhKNRzcsYRTABi9p6hUcQ0Zbc1E1BrmCFBVStPVNVbVm9QIoiUo/wTJTnJlCZCuc75ISb0vF8SM1BKIzXWK0gGH4HsP3IDVMz9aIqGRG75qZnFijyOoR9viZVuvQr80XMNXe/e/H2lqxGuSlE+TU2Fc0GbVCwY54lOfVQsbrb24EpuZrbN0SgYuuj00GPBh0s+QzMS78gm22jfhlVyW1sn9JBQuNw9suJ4cyUYkI78yMqSAuUGzZqrMpsRK69b/XirpYchkxmSvGNTFSweVG1JSVPboKhcaoeNhT33nbrtuOAZoVeSmxLdxouTYhsqjN8ua2tzeRaph5cyljNdyPGxf9jwf+qK5RZYYkXxamKfkhHnK+qC0RLb4sUxaLaZIkzudZFvZuWtQsiUz7HnJo3YHftadA9InIkyOCoEYWooBILejzAihUrbOckO99OiFe9+tlZ2h+fL0gvpU7bqBYQWYCSu3/d0rtC5ZeD4DI3XXRsP8IWxsWHMCKiAygntmQfq3Np++TN/za3b4gQUQbid6nqCcD+0pyvWBUaULYWovQnUJXQznhQMMDb9l+B1jHmhIMaVPoRjh8oLFwGKi3ZnJk86d9gW7JdM0W51AFulzprZhWkycKHv916xOaWXG7UQ6IpY4CJbQcq+XErWkKsygyR+ByXObZMnvRnMnbQxpeo6ktR+koMPfMoC0H/6b7zFt/b3NaRmqrsfYzoHs6+bnOTmZN6UNBjQPphlLZw10OZFniW+vpT7l0zt9trUM1U2kU+6Fu/sfUFqUh+Kkg9EJfAgDxwJOi3XnXu4pZNOcTVe+SgAhAxzR0dqfsvOarPYG9XZQZq7RjsEoF+VT2O/oEPIqIuMaph5LNigwHRVGQ+CyxANF8i8ecr+uBAvueiDKhLuOSgQ28xnRs2WFCJrdwgwmaE+nG2UUS4BWgfXZV95iVuQ122Jkxo7tBU58qVhVV3bLsY9B0OQmHcuD8PzFN4XBvlnd+54IS9be3IVCdco/uATMa2ZDH3nb+4C/gcyByVMQctRNCCwkyxqS83d/jZrCqfgjW3daQ6V0ph1W1bT8XqZ0XM7vEdrwbYtMelPr3qvtWLu1qy2ehgcrojOuFcK7ZN1SzqXnQtSqcMD1qMxoNI0G7Q0+Z2dX0+19oat+So2lFkc1tHqjOzsrD67t0vxMitIhhX9RzT9ORVWaiqv7CWt9y7dsEfRupNOigZAKK0w1cvkbwWCh8A9ig0uImTUfUghWtcvWTV+m1X51olRkRbshOb+23u0FRnZmXhnDu3HKMDA3cLLAHpk1HAOBSsuprQIkTupDH11vvOd5J/sBOfYokKD716/eY3q5o7gUFECjLeMSWyAPTGOpP/SDjgWMEKW7rqq7RkMblWsYCuXb/l5Bj5hiBH41rDU6NnuMxAJVLh099at/iqZM2IQ+CS0dR/1W3b1orhFmAQdHAc51dAOQL4WSz28vvXLf1F8AvN7Ruihcue1RM3btRM+3Dpt60dCbO4oSyw/LqH0n80++gPWrhC0DqEvpHvK7GiguoCMeZx1fzl31p39PdpazO0t+vBUOOpmAFFTFiF4QZxYER7GWtJg2oBZDaiA6jeZiT62t3rFj1SykO0ZJ9uHLANZwv2w8Cp6u4VF2ueghXUgsz2/3VjnRm8Mtf6gl0HU31nwgxIMmFNdstyG8v1wB+LmB2eFKNog8SgEapzcd11DwI/QOxD1jT8vjBg98yqjy0M1A1gjhQbnSAqb1DRM0EC3EuYPEw2AFuRIcTxBpSfAn9373mLf+AYeGgSn3GiiqEXW33j7+bS2PgPKBe6XS3a49smx5oOT6HMQEjjJk26gR5FLVAnyByUWQgRqvsR+hSRIal3e4BjdR3kM732PaLYa1597pJvZERsSzYb5Vpa7KFkcspiQNIxA6xav+0MUf5G4fXeRPQCsQpmZEctMa7XxYiSUjQSBBVUoOAduHoiG2disC7V0AbQGbgu5Z+j9ut7+gdynRcd21/8XIfyVeJZqkpLLmdyra0xqvL29VvXGuRi3KF4GDPqDwT14DsiyYlFLRrvcz/lywMqIJHrsKYBpKDwO5Tvm0iy97Qu+lGxVnKYXGUlTsVStyb77HJbKKwWwxmovARhtjo7UnCJkcYiEoe+fc8QcaZLUuqag1OiWBXpRu0TItGPRePv9Rd6f/ydC07YeyDhD75i2qQy4ABitDBse1VlzfqtL8WYV1nlleKmWo5SmCfQpG6yBVRjRAZE2YewQ9HNovxGhY2Y1KP1dPw2yWCX1OU4HExNVRkwFMurmg3tG0xnZmVhpIx21pYtc+vqo9mxZYYtIJGY/nxk9sUD9HzngiP2jhZ9LVy2Qg9g8GF8/X8CB7TwfqHwOwAAAABJRU5ErkJggg=='
    }
    'Laptop'             = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAUElEQVR42mNgGHGAEZkjbhb7nxxDXp5aDDeHiVLD0PWy4LONVMNQXEgtMGrgSDCQhVC6ItuFpCZoSjID6YUDpd5EdikTTVxIbsRgCzuquxAAsL0Zy445FUgAAAAASUVORK5CYII='
    }
    'Workstation'        = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = $common
    }
    'Server'             = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAP0lEQVR42mNgGOyAEV1A3Cz2PykGvDy1mBGnJMwwcbPY/8QajK6OidpeZiHZG/QOQyaaRvlopIxGynCJlBEIABfAKwwpfC/1AAAAAElFTkSuQmCC'
    }
    'LaptopSummary'      = @{
        MimeType = $imgpng
        Width    = 28
        Height   = 28
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAXklEQVR42mNgGAVUBozIHHGz2P+0sOTlqcVwe5hobRm62Sz4XENty1B8SC8wauGohaMWjlo4auGohYQBC6H6i2Y+pHbFS8tKnfRGFK2DEdmnTAPiQ1olHGxxR3cfAgB8DxnbcdDdZQAAAABJRU5ErkJggg=='
    }
    'WorkstationSummary' = @{
        MimeType = $imgpng
        Width    = 28
        Height   = 28
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAXUlEQVR42mNgGO6AEZkjbhb7nxaWvDy1GG4PE60tQzebBZ9rqG0Zig/pBUYtHLVw1MJRC0ctHLVwEFrIQqjCpJkPqV3TU70VIW4W+5+c0Bj+iYaRmJYWNeOO7j4EABpWGTBobInPAAAAAElFTkSuQmCC'
    }
    'ServerSummary'      = @{
        MimeType = $imgpng
        Width    = 28
        Height   = 28
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAASklEQVR42mNgGO6AEV1A3Cz2PzUteHlqMSNOSZhl4max/6llMbo5TPQOUhaSg2GoxSHTgCbZ0UQzmmhGE83ISDSjYBSMglEwDAEAqH0rDBz7eI0AAAAASUVORK5CYII='
    }
    'WindowsSummary'     = @{
        MimeType = $imgpng
        Width    = 28
        Height   = 28
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAUklEQVR42mNgGKpA3Cz2PzHqWIg17OWpxYzEGkqUhdQwjBjARO+gH7Vw1MLBDxiJzYfEZPyXpxYzjsbhqIVD30IWYpI0vaoumtT4o2AUjIKBBwDLaBbKftUEmQAAAABJRU5ErkJggg=='
    }
    'MemorySummary'      = @{
        MimeType = $imgpng
        Width    = 28
        Height   = 28
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAaElEQVR42mNgGAWjYLADRmSOuFnsf1pY8vLUYrg9TLS2DN1sJmJdRiwfHaObyUQti4j1LRO9Ew0ToTAnh090xNIi4aCbOziCdNTCUQsHlYUshDI9zXxISnlISfWEt1ijFns0lY4CigAAHFlCyu8Sdt0AAAAASUVORK5CYII='
    }
    'DiskSummary'        = @{
        MimeType = $imgpng
        Width    = 28
        Height   = 28
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAhUlEQVR42u2WwQ3AIAhFhbCDm7iN03WbbuIU9mqMEYjgoYGz/vcBDaT09wDuQC61awTb+4AaqIVo4MCBOMcSs6MG3ujbaIKsezhnNt8nrvbWj4ZOBbSBt/9hAAMYwAAG0AlosWLkUvtKhySDVzqiJEbBOjNupqLnsF1pgscuszNv1htphT6I/DuJiboMCwAAAABJRU5ErkJggg=='
    }
    'CPU'                = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAVUlEQVR42mNgoCcQN4v9T4iNDpio7YjBbyAjMeGHDbw8tZiRaBcSMgyfGkZ8krhcgU89CzaNxLgQl4VUjxQWUlxEyOtDw8uMlHgZm4upnrBHS5tBCADnTjPCh1tMIgAAAABJRU5ErkJggg=='
    }
    'Memory'             = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAUklEQVR42mNgGAXDHzAic8TNYv+TY8jLU4vh5jBRahi6XiZibSaGj9NAcgwiyoXkACZCYUIMH2ssUxIpyMHAREy4kJJs8HqXVDb9ImVQGTj4AQDumStnsGzHqQAAAABJRU5ErkJggg=='
    }
    'Disk'               = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAbklEQVR42mNgGOyAEZeEuFnsf3waX55azEiUgYQMImQwIy7DcLmAkFomaoQbsuEs5IYhLsBESoCjq8GmjoXUWCTLhZSAUQMH2EBsaZUFn0JcSQdfomekRu7AmZfJSczoepgoySHY1DKSGuiELAUAD/w1gt5LV58AAAAASUVORK5CYII='
    }
    'Volume'             = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAARklEQVR42mNgGAXDHzAic8TNYv+TY8jLU4vh5jBRahi6XhZ8tpFqGIoLqQUGv4EshMKEYgMpjRSqu5CJXJdR4iuivDqCAQDHshkXfIWnxwAAAABJRU5ErkJggg=='
    }
    'Display'            = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = $common
    }
    'Battery'            = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAU0lEQVR42mNgGAXDHzAic8TNYv+TasDLU4tRzGCixDBs+lgI2UiKYVgNJNa1yBbD1L88tZiRidqRMvgNZKGGIcjhyUROhOBTx0ROciE3mY0C4gAAJi8dw7+Z1JAAAAAASUVORK5CYII='
    }
    'Monitor'            = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = $common
    }
    'Network'            = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAXElEQVR42mNgGOyAkRhF4max/2Hsl6cW49XDRIph2PgkG0gqoL+B6GFGcRgSY8gwC0OKEzahdEYonKnuQhZKYxbdR7R1Ia7ww1U4YFPPRKgQIFV8CCVsXIUAqeIARxM10IScaCgAAAAASUVORK5CYII='
    }
    'Printer'            = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAe0lEQVR42s1TwRHAIAjTHDu4ids4ndu4iVPYb8+qJWjvyhMhJEGc+3v4UTLE1DTNteRHP6xgs1phpmsG47SH+HQpjH8ze7AL1vcKu4w3RTjB6gjgTImwDO6AtWTf18F6emrJu6cHy3bpnxFiaiumq3ex+ETfskb+jkVUXGnFOxi6L3KrAAAAAElFTkSuQmCC'
    }
    'Dock'               = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAWUlEQVR42mNgGAWDDjAic8TNYv+TY8jLU4vh5jBRahi6XhZ8tpFqGIoLqQVYCNn68tRiRnx8dEB1FzLRLP2Im8X+Jyem0fXRPlIoSY8oLiQ1/VGSdkcBfgAAJ14iEIUHKcIAAAAASUVORK5CYII='
    }
    'Roles'              = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAP0lEQVR42mNgGHGAEZ+kuFnsf2ziL08txqmPia7Ox+ZCXK7G8DIhhYQALBio7uXBbyDRkUNsGI9GymiyGZYAAOpxEroeykF+AAAAAElFTkSuQmCC'
    }
    'Shield'             = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAeUlEQVR42mNgGDZA3Cz2PzHqGMkx6OWpxYwkGUisa7AZzkiuQbgMZqJEMzbARE3DSDYQZhi+oGEi1iXEGEbQhTBDiDUMa7JB1oTsSnyGIatjwicJM4RYw/DmFGK8hy3GmchNHrjkmahdiDCR4wqKcgqu9Ei38pDqAAAPEkbS0itwfgAAAABJRU5ErkJggg=='
    }
    'Services'           = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAbUlEQVR42mNgoDJgJKRA3Cz2PzL/5anFePUwUduFLOS4Bp86kl2IbhhJXiakmS5hSHIYEQpnRkJewxYxuNS/PLWYEa+XccUyvrRI9TCkfaQQk7iJTtjYAhtdjFDaZKFG7hi4SCFUVA3N8pDqAAAeVDkfxSxHOgAAAABJRU5ErkJggg=='
    }
    'Software'           = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAdklEQVR42mNgGDZA3Cz2PzHqGMkx6OWpxYwkG0iMi7AZzEiu13AZzESpYThdKG4W+x9mE7EGo6t/eWoxIws2FxIyGJ88C74IweYCQj5gISbJkBIUTNRM1EQbSAoY/AayEJMUSMkpLKSkMWLyMguxuYDY0mbwAwADIEkiM+k25QAAAABJRU5ErkJggg=='
    }
    'Share'              = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAOklEQVR42mNgGAWUAkYYQ9ws9j8uRS9PLWYk1kCmAXEhsQDFJ5QaCNPPgk2QEkD1MBw1cNTAUUAMAABhmA0UiM4hngAAAABJRU5ErkJggg=='
    }
    'Events'             = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAaElEQVR42mNgGDZA3Cz2PzHqmEgxjBhDmajtEyZSvUrIlfR1Icw1L08tZnx5ajEjMa5kIjdWccnTx8vEpjls6mjvQmJdh0s9IyWGIQNYKmAiVjFysiHKy5S4Dlk/CzVLGngYUuq6oQUA1mAptM4lE20AAAAASUVORK5CYII='
    }
    'Tasks'              = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAiUlEQVR42s1UwQ3AIAhUwg5u4jZO5zZu4hT2ZWKMeKBNWp5wwHGgzv3d/C4YYmorfy1ZzCNrMRTzCDyzQXGWOo3AXqSW7LtfYkmr7juN5oZzYdLogmzMJcsGNVg+ZSI1prcPm09HUx+2ZTkrLJ2wME0QYmoalhKO0Tjo6al/G5RoPpudLjd6f28PXq5NH6It+0wAAAAASUVORK5CYII='
    }
    'VM'                 = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAUklEQVR42mNgGOyAEZuguFnsf3IMe3lqMSMTtV3IRJdwIMfLMD1UdyELLhcR48qXpxYz0jwMaeNlXM4nJ+Jo50JqJS+KDByasUy7SCG3yBp6AAAedxbMWHOMLQAAAABJRU5ErkJggg=='
    }
    'Users'              = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAiUlEQVR42t2SwQ3AIAhF9ac7uInbOF236Sadwp5IjP0CIaaHcjIoTwIvpV9Gqa2X2jq7QwTGzhLZKrqvM2uA+Q00mAZZBTzFkh87Yd2FZjgC2AdHZMsMRDtcPZwXIyNg+sD63bPlMQ9LWE1iBkVUD3WGu2AhbazNYycs5KElNixRvUK/ZuiFfh4PrkRQcUsqSpQAAAAASUVORK5CYII='
    }
    'Web'                = @{
        MimeType = $imgpng
        Width    = 20
        Height   = 20
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAiElEQVR42s1U2w2AMAiEizu4ids4XbfpJp1Cv0yahmfVKJ9wkLuDlujvwVZx3fZDyrda1D5kh3k1joAvRlbNZdhqYUmallel9CwkRmN9xCDiS4SIKjksR8HyEwz74XjtwiWDvaVIfcgcbQSLmWWkFmndoneDRERL9r16lvDMB2DJxIwvd/z+Pk4XuVapiMNUrAAAAABJRU5ErkJggg=='
    }
    'RolesSummary'       = @{
        MimeType = $imgpng
        Width    = 28
        Height   = 28
        Base64   = 'iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAAUklEQVR42mNgGAVUBozEKhQ3i/2PT/7lqcVEmcVEbx/S3UIWUjWgBx2hoB5wHzKS61JyQ2b4J5pRCweuaMOVmokt0kbz4WgqHbVwBFs4CoY+AAB1xxQpHRJzdAAAAABJRU5ErkJggg=='
    }
}
#endregion Embedded Report Assets
#endregion Runtime Variables

#region Helper Functions
Function Convert-PasswordCipher {
    <#
        .SYNOPSIS
        Encrypts or decrypts a password using a user-supplied keyword.

        .DESCRIPTION
        Encrypts plaintext using AES-256-CBC and derives encryption/authentication
        keys from a keyword using PBKDF2.

        A random salt and initialization vector are generated for every encrypted
        value. HMAC-SHA256 is used to detect an incorrect keyword or altered data.

        The keyword is requested interactively as a SecureString and is not stored
        in the encrypted output.

        The encrypted result can be copied between computers and decrypted anywhere
        this function is available, provided the same keyword is supplied.

        .PARAMETER Encrypt
        Encrypt a password.

        .PARAMETER Decrypt
        Decrypt an encrypted value previously created by this function.

        .PARAMETER CipherText
        Encrypted text previously returned by this function.

        If omitted when -Decrypt is used, the function prompts for the value.

        .PARAMETER Keyword
        SecureString keyword used to derive the encryption keys. If omitted, the function prompts
        for it with Read-Host -AsSecureString.

        If omitted when -SendEmail is specified, the script prompts for the
        DOMAIN\USERNAME credential and uses that credential's password as
        the decryption passphrase.

        .PARAMETER Iterations
        PBKDF2 iteration count used when encrypting.

        The iteration count is embedded in the encrypted value so decryption uses
        the same value automatically.

        .OUTPUTS
        String

        .EXAMPLE
        Convert-PasswordCipher -Encrypt

        Prompts for a keyword and password and returns encrypted text.

        .EXAMPLE
        $Encrypted = Convert-PasswordCipher -Encrypt

        Stores the encrypted representation in $Encrypted.

        .EXAMPLE
        Convert-PasswordCipher -Decrypt -CipherText $Encrypted

        Prompts for the keyword and returns the original plaintext password.

        .NOTES
        Requires      : .NET Framework 4.7.2 or later (PBKDF2 with SHA256)
        Target        : Windows PowerShell 5.1
        Encryption    : AES-256-CBC
        Authentication: HMAC-SHA256
        Key derivation: PBKDF2
    #>
    [CmdletBinding(DefaultParameterSetName = 'Encrypt')]
    Param (
        [Parameter(Mandatory, ParameterSetName = 'Encrypt', HelpMessage = 'Encrypt a plaintext password.')]
        [switch]$Encrypt,

        [Parameter(Mandatory, ParameterSetName = 'Decrypt', HelpMessage = 'Decrypt a value previously encrypted by this function.')]
        [switch]$Decrypt,

        [Parameter(ParameterSetName = 'Decrypt')]
        [string]$CipherText,

        [Parameter()]
        [securestring]$Keyword,

        [Parameter(ParameterSetName = 'Encrypt')]
        [ValidateRange(10000,2000000)]
        [int]$Iterations = 200000
    )

    <#
        LESSON 1: Functions defined inside a function are private
        ConvertFrom-SecureStringToPlainText and Get-DerivedKeys exist only while
        Convert-PasswordCipher runs. Callers cannot see them and they cannot clash with commands
        elsewhere. Defining them first, before the main logic, makes them available to the code
        below.
    #>
    Function ConvertFrom-SecureStringToPlainText {
        <#
            .SYNOPSIS
            Converts a SecureString to plaintext in memory.

            .DESCRIPTION
            Converts a SecureString to a temporary plaintext string using the
            Windows SecureString marshaling APIs.

            .PARAMETER SecureString
            SecureString value to convert.

            .OUTPUTS
            String

            .EXAMPLE
            ConvertFrom-SecureStringToPlainText -SecureString $Secure
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'SecureString value to convert to plaintext temporarily.')]
            [securestring]$SecureString
        )

        $Ptr = [IntPtr]::Zero

        Try {
            <#
                LESSON 2: Getting text out of a SecureString, and what that costs
                SecureStringToBSTR copies the secret into unmanaged memory and returns a pointer
                to it. PtrToStringBSTR reads that memory into a normal .NET string, and
                ZeroFreeBSTR in Finally overwrites the unmanaged copy with zeros before freeing it.
                The returned .NET string cannot be wiped: .NET strings cannot be changed in place,
                so it stays in memory until the garbage collector reclaims it. Keep plaintext
                secrets short-lived, and treat SecureString as damage limitation, not strong
                protection.
            #>
            $Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)

            Return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)
        } Catch {
            Throw ('Unable to convert SecureString: {0}' -f $_.Exception.Message)
        } Finally {
            If ($Ptr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)
            }
        }
    }

    Function Get-DerivedKeys {
        <#
            .SYNOPSIS
            Derives encryption and HMAC keys from a keyword.

            .DESCRIPTION
            Uses PBKDF2 to derive 64 bytes of key material from a keyword and salt.
            The first 32 bytes are used for AES-256 and the remaining 32 bytes are
            used for HMAC-SHA256.

            .PARAMETER Keyword
            Plaintext keyword used for key derivation.

            .PARAMETER Salt
            Random salt used for PBKDF2.

            .PARAMETER Iterations
            Number of PBKDF2 iterations.

            .OUTPUTS
            PSCustomObject

            .EXAMPLE
            Get-DerivedKeys -Keyword 'example' -Salt $Salt -Iterations 200000
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Keyword used to derive encryption and authentication keys.')]
            [string]$Keyword,

            [Parameter(Mandatory, HelpMessage = 'Random salt used during PBKDF2 key derivation.')]
            [byte[]]$Salt,

            [Parameter(Mandatory, HelpMessage = 'Specify the PBKDF2 iteration count.')]
            [int]$Iterations
        )

        $Derive = $null

        Try {
            <#
                LESSON 3: Turning a keyword into a key, slowly on purpose
                A keyword is not a key: people choose short, guessable words. PBKDF2
                (Rfc2898DeriveBytes) hashes the keyword with a salt over and over, 200,000 times
                by default, to produce key material. One derivation takes a fraction of a second;
                an attacker guessing millions of keywords pays that cost for every guess.
                This four-argument constructor, the one that accepts SHA256, requires
                .NET Framework 4.7.2 or later. On older systems it fails, and decryption fails
                with it.
            #>
            $Derive = New-Object -TypeName System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @(
                $Keyword,
                $Salt,
                $Iterations,
                [Security.Cryptography.HashAlgorithmName]::SHA256
            )

            <#
                LESSON 4: One key per job
                The derivation produces 64 bytes, split into two 32-byte keys: one for AES
                encryption and one for the HMAC signature. Reusing one key for two different
                algorithms is a classic cryptographic mistake.
                $KeyMaterial[0..31] uses the range operator to take bytes 0 to 31. Slicing returns
                a general [object[]], so [byte[]] converts it back to the byte array the
                cryptography classes expect.
            #>
            $KeyMaterial = $Derive.GetBytes(64)

            [PSCustomObject]@{
                EncryptionKey = [byte[]]$KeyMaterial[0..31]
                HmacKey       = [byte[]]$KeyMaterial[32..63]
            }
        } Catch {
            Throw ('Unable to derive encryption keys: {0}' -f $_.Exception.Message)
        } Finally {
            If ($Derive) {
                $Derive.Dispose()
            }
        }
    }

    <#
        LESSON 5: One function, two modes, chosen by parameter sets
        -Encrypt and -Decrypt are mandatory switches in different parameter sets, so PowerShell
        accepts exactly one of them and rejects both together. $PSCmdlet.ParameterSetName reports
        which set the caller used. Parameters can belong to one set (-CipherText only makes sense
        when decrypting) or to all sets (-Keyword). DefaultParameterSetName chooses a set when the
        call is ambiguous.
    #>
    If ($PSCmdlet.ParameterSetName -eq 'Encrypt') {
        If (-not $Keyword) {
            $Keyword = Read-Host -Prompt 'Keyword' -AsSecureString
        }

        $PasswordSecure = Read-Host -Prompt 'Password to encrypt' -AsSecureString

        $KeywordPlainText = ConvertFrom-SecureStringToPlainText -SecureString $Keyword
        $Password         = ConvertFrom-SecureStringToPlainText -SecureString $PasswordSecure

        <#
            LESSON 6: Get-Random is not for secrets
            Get-Random is fine for shuffling a list but is predictable, so it must never produce
            keys, salts or IVs. RandomNumberGenerator draws on the operating system's
            cryptographic random source.
        #>
        $Rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $Aes = [Security.Cryptography.Aes]::Create()

        Try {
            <#
                LESSON 7: Salt and IV make every result unique
                A new random salt means the same keyword produces different keys for every
                encrypted value, so an attacker cannot precompute guesses once and reuse them. A
                new random IV (initialization vector) means the same password encrypts to
                different bytes every time. Neither one is secret: both are stored in the output
                so decryption can read them back.
            #>
            $Salt = New-Object -TypeName byte[] -ArgumentList 32
            $Rng.GetBytes($Salt)

            $Keys = Get-DerivedKeys -Keyword $KeywordPlainText -Salt $Salt -Iterations $Iterations

            <#
                LESSON 8: AES settings
                AES encrypts in 128-bit (16-byte) blocks with a 256-bit key. CBC mode chains each
                block to the previous one, starting from the IV. PKCS7 padding fills the final
                block, which is why the encrypted length is always a multiple of 16. The password
                becomes bytes with UTF8 before encryption, and decryption reverses that with
                UTF8.GetString.
            #>
            $Aes.KeySize   = 256
            $Aes.BlockSize = 128
            $Aes.Mode      = [Security.Cryptography.CipherMode]::CBC
            $Aes.Padding   = [Security.Cryptography.PaddingMode]::PKCS7
            $Aes.Key       = $Keys.EncryptionKey

            $Aes.GenerateIV()

            $PlainBytes = [Text.Encoding]::UTF8.GetBytes($Password)

            <#
                LESSON 9: Dispose cryptographic objects as soon as you are done
                Encryptors, HMAC objects and the AES object hold key material and operating-system
                handles. They implement IDisposable, and Dispose() releases them. The small nested
                Try/Finally guarantees the encryptor is disposed immediately, even when
                TransformFinalBlock fails, instead of waiting for the outer cleanup.
            #>
            $Encryptor  = $Aes.CreateEncryptor()

            Try {
                $EncryptedBytes = $Encryptor.TransformFinalBlock($PlainBytes,0,$PlainBytes.Length)
            } Finally {
                $Encryptor.Dispose()
            }

            <#
                LESSON 10: Design the output format so it can change later
                The encrypted value is laid out as:
                  'PWC1' (4 bytes) | iterations (4) | salt (32) | IV (16) | ciphertext (16+) | HMAC (32)
                The version tag lets a future version recognise and still read old values. Storing
                the iteration count means it can be raised later without breaking existing
                values. [Array]::Copy places each part at a running $Offset.
            #>
            $VersionBytes   = [Text.Encoding]::ASCII.GetBytes('PWC1')
            $IterationBytes = [BitConverter]::GetBytes([int]$Iterations)

            $Payload = New-Object -TypeName byte[] -ArgumentList (
                $VersionBytes.Length + 
                $IterationBytes.Length + 
                $Salt.Length + 
                $Aes.IV.Length + 
                $EncryptedBytes.Length
            )

            $Offset  = 0

            [Array]::Copy($VersionBytes,0,$Payload,$Offset,$VersionBytes.Length)
            $Offset += $VersionBytes.Length

            [Array]::Copy($IterationBytes,0,$Payload,$Offset,$IterationBytes.Length)
            $Offset += $IterationBytes.Length

            [Array]::Copy($Salt,0,$Payload,$Offset,$Salt.Length)
            $Offset += $Salt.Length

            [Array]::Copy($Aes.IV,0,$Payload,$Offset,$Aes.IV.Length)
            $Offset += $Aes.IV.Length

            [Array]::Copy($EncryptedBytes,0,$Payload,$Offset,$EncryptedBytes.Length)

            <#
                LESSON 11: Encryption hides data; a signature proves it was not changed
                AES alone cannot tell whether the stored value was altered or the wrong keyword
                was typed; decryption may simply produce garbage. HMAC-SHA256 computes a signature
                over the whole payload (version, iterations, salt, IV and ciphertext) using the
                second key. Signing the encrypted data, rather than the plaintext, is called
                encrypt-then-MAC.
                (,$Keys.HmacKey) is the unary comma again: it passes the byte array as ONE
                constructor argument.
            #>
            $Hmac = New-Object -TypeName Security.Cryptography.HMACSHA256 -ArgumentList (,$Keys.HmacKey)

            Try {
                $Signature = $Hmac.ComputeHash($Payload)
            } Finally {
                $Hmac.Dispose()
            }

            $Final = New-Object -TypeName byte[] -ArgumentList ($Payload.Length + $Signature.Length)

            [Array]::Copy($Payload,0,$Final,0,$Payload.Length)
            [Array]::Copy($Signature,0,$Final,$Payload.Length,$Signature.Length)

            <#
                LESSON 12: Return inside Try still runs Finally
                Return leaves the function, but the Finally block below runs first: the AES and
                random-number objects are disposed and the plaintext variables are cleared, even on
                this success path. Base64 turns the binary result into plain text that is safe to
                paste into a script.
            #>
            Return [Convert]::ToBase64String($Final)
        } Catch {
            Throw ('Encryption failed: {0}' -f $_.Exception.Message)
        } Finally {
            $Aes.Dispose()
            $Rng.Dispose()

            $KeywordPlainText = $null
            $Password         = $null
        }
    }

    If ([string]::IsNullOrWhiteSpace($CipherText)) {
        $CipherText = Read-Host -Prompt 'Encrypted password'
    }

    If (-not $Keyword) {
        $Keyword = Read-Host -Prompt 'Keyword' -AsSecureString
    }

    $KeywordPlainText = ConvertFrom-SecureStringToPlainText -SecureString $Keyword

    Try {
        $Final = [Convert]::FromBase64String($CipherText.Trim())

        <#
            LESSON 13: Check untrusted input before using it
            The encrypted text could be truncated, mistyped or deliberately altered. Each check
            here (total length, whole AES blocks, a known version tag) rejects bad input early
            with a clear message, before any cryptography runs. The total length must be at least
            104 bytes: 4 + 4 + 32 + 16 + 16 + 32.
        #>
        ### Version (4) + iterations (4) + salt (32) + IV (16) + at least one AES block (16) + HMAC (32).
        If ($Final.Length -lt 104 -or (($Final.Length - 88) % 16) -ne 0) {
            Throw 'Encrypted value is too short or invalid.'
        }

        $Signature = New-Object -TypeName byte[] -ArgumentList 32
        $Payload   = New-Object -TypeName byte[] -ArgumentList ($Final.Length - 32)

        [Array]::Copy($Final,0,$Payload,0,$Payload.Length)
        [Array]::Copy($Final,$Payload.Length,$Signature,0,32)

        $Version = [Text.Encoding]::ASCII.GetString($Payload,0,4)

        If ($Version -ne 'PWC1') {
            Throw 'Encrypted value uses an unsupported format.'
        }

        $Iterations = [BitConverter]::ToInt32($Payload,4)
        If ($Iterations -lt 10000 -or $Iterations -gt 2000000) {
            Throw 'Encrypted value has an invalid iteration count.'
        }

        $Salt = New-Object -TypeName byte[] -ArgumentList 32
        [Array]::Copy($Payload,8,$Salt,0,32)

        $IV   = New-Object -TypeName byte[] -ArgumentList 16
        [Array]::Copy($Payload,40,$IV,0,16)

        $EncryptedLength = $Payload.Length - 56
        $EncryptedBytes  = New-Object -TypeName byte[] -ArgumentList $EncryptedLength
        [Array]::Copy($Payload,56,$EncryptedBytes,0,$EncryptedLength)

        $Keys = Get-DerivedKeys -Keyword $KeywordPlainText -Salt $Salt -Iterations $Iterations

        $Hmac = New-Object -TypeName Security.Cryptography.HMACSHA256 -ArgumentList (,$Keys.HmacKey)

        Try {
            $ExpectedSignature = $Hmac.ComputeHash($Payload)
        } Finally {
            $Hmac.Dispose()
        }

        <#
            LESSON 14: Compare signatures in constant time, and verify before decrypting
            A loop that stopped at the first mismatching byte would finish sooner the earlier the
            mismatch occurred, and an attacker measuring that timing could learn the correct
            signature byte by byte. This loop always compares all 32 bytes.
            The signature is checked BEFORE decrypting. A wrong keyword or a modified value is
            rejected with a clear message, and the decryptor never processes tampered data. Some
            attacks rely on probing a decryptor with altered input.
        #>
        $Valid = $true

        For ($i = 0; $i -lt $Signature.Length; $i++) {
            If ($Signature[$i] -ne $ExpectedSignature[$i]) {
                $Valid = $false
            }
        }

        If (-not $Valid) {
            Throw 'Incorrect keyword or encrypted value has been modified.'
        }

        $Aes = [Security.Cryptography.Aes]::Create()

        Try {
            $Aes.KeySize   = 256
            $Aes.BlockSize = 128
            $Aes.Mode      = [Security.Cryptography.CipherMode]::CBC
            $Aes.Padding   = [Security.Cryptography.PaddingMode]::PKCS7
            $Aes.Key       = $Keys.EncryptionKey
            $Aes.IV        = $IV

            $Decryptor = $Aes.CreateDecryptor()

            Try {
                $PlainBytes = $Decryptor.TransformFinalBlock($EncryptedBytes,0,$EncryptedBytes.Length)
            } Finally {
                $Decryptor.Dispose()
            }

            Return [Text.Encoding]::UTF8.GetString($PlainBytes)
        } Finally {
            $Aes.Dispose()
        }
    } Catch {
        Throw ('Decryption failed: {0}' -f $_.Exception.Message)
    } Finally {
        $KeywordPlainText = $null
    }
} ### Lessons

Function Optimize-HumanReadable {
    <#
        .SYNOPSIS
        Converts a raw byte count to a human-readable size.

        .DESCRIPTION
        Converts a numeric byte count to Bytes, KB, MB, GB, TB, or PB using PowerShell binary-size
        constants. This function is used throughout the inventory report instead of exposing raw
        byte counts in presentation fields.

        .PARAMETER Size
        Raw size in bytes to convert.

        .EXAMPLE
        Get-ChildItem .\file.xlsx | Measure-Object Length -Sum | Select-Object @{N='Size';E={Optimize-HumanReadable -Size $_.Sum}}

        .EXAMPLE
        Optimize-HumanReadable -Size 17179869184

        Returns 16 GB.

        .INPUTS
        System.Object

        .OUTPUTS
        System.String

        .NOTES
        Author       : James Stephens
        Created On   : 12/16/2022
        Alias        : HR
    #>
    [CmdletBinding()]
    [Alias('HR')]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the raw size in bytes to convert to a human-readable value.')]
        $Size
    )

    If ($null -eq $Size -or "$Size" -eq '') {
        Return $null
    }

    Switch ([double]$Size) {
        {$_ -ge 1PB} { Return ("{0:#.#' PB'}" -f ([double]$Size / 1PB)) }
        {$_ -ge 1TB} { Return ("{0:#.#' TB'}" -f ([double]$Size / 1TB)) }
        {$_ -ge 1GB} { Return ("{0:#.#' GB'}" -f ([double]$Size / 1GB)) }
        {$_ -ge 1MB} { Return ("{0:#.#' MB'}" -f ([double]$Size / 1MB)) }
        {$_ -ge 1KB} { Return ("{0:#' KB'}" -f ([double]$Size / 1KB)) }
        Default { Return ('{0:n0}' -f [double]$Size) + ' Bytes' }
    }
}

Function Get-HardwareInventoryImageHtml {
    <#
        .SYNOPSIS
        Returns an embedded fixed-size report image.

        .DESCRIPTION
        Builds an HTML IMG element from a pre-sized Base64 PNG in HardwareInventoryImageAssets.
        Assets are stored at their actual display dimensions so the script does not carry larger
        images than the report requires.

        .PARAMETER Key
        Image asset key.

        .PARAMETER Alt
        Alternate text for the image.

        .PARAMETER CssClass
        Optional CSS class for the IMG element.

        .EXAMPLE
        Get-HardwareInventoryImageHtml -Key 'Logo' -Alt 'MyCompany' -CssClass 'header-logo'

        Returns an IMG element for the embedded MyCompany logo.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the embedded image asset key.')]
        [string]$Key,

        [Parameter(Mandatory, HelpMessage = 'Specify alternate text for the image.')]
        [AllowEmptyString()]
        [string]$Alt,

        [Parameter()]
        [string]$CssClass
    )

    $Asset = $script:HardwareInventoryImageAssets[$Key]
    If (-not $Asset) {
        Return ''
    }

    $ClassHtml = ''
    If (-not [string]::IsNullOrWhiteSpace($CssClass)) {
        $ClassHtml = ' class="{0}"' -f [System.Net.WebUtility]::HtmlEncode($CssClass)
    }

    $Source = 'data:{0};base64,{1}' -f $Asset.MimeType,$Asset.Base64
    Return '<img{0} src="{1}" width="{2}" height="{3}" alt="{4}" border="0" style="display:block;width:{2}px;height:{3}px;border:0;">' -f $ClassHtml,$Source,$Asset.Width,$Asset.Height,[System.Net.WebUtility]::HtmlEncode($Alt)
}

Function Get-VolumeFreeSpaceChartHtml {
    <#
        .SYNOPSIS
        Creates a small embedded free-space chart for a volume.

        .DESCRIPTION
        Creates a fixed-size 28x28 PNG donut chart entirely in memory using System.Drawing.

        The colored arc represents the percentage of free space:
        - 20 percent or greater: green
        - 10 through less than 20 percent: yellow
        - Less than 10 percent: red

        The remaining used-space portion is rendered in light gray.

        Generated PNGs are cached in HardwareInventoryImageAssets using the free-space
        percentage rounded to one decimal place. This allows the existing HTML and SMTP
        image pipeline to embed the chart as Base64 in standalone HTML and convert it to
        a CID-linked resource for email.

        No temporary files are created.

        .PARAMETER FreePercent
        Percentage of free space remaining on the volume.

        .EXAMPLE
        Get-VolumeFreeSpaceChartHtml -FreePercent 64.4

        Returns an IMG element containing a green 64.4-percent free-space donut.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the percentage of free space remaining on the volume.')]
        <#
            LESSON 1: Validate the range before the function runs
            [ValidateRange(0,100)] rejects -FreePercent 150 or -5 with a clear error before any code
            in the function runs. Validation attributes keep impossible values out, so the code
            below never has to check them itself.
        #>
        [ValidateRange(0,100)]
        [double]$FreePercent
    )

    <#
        LESSON 2: Rounding, and turning a number into a cache key
        Two volumes at 44.31% and 44.34% free look identical in a 28-pixel chart, so the value is
        rounded to one decimal place and only one image is drawn for both. Multiplying by 10 gives
        a whole number (443) for the key 'VolumeFree_443', which avoids a decimal point in the name.
        .NET rounds exact halves to the nearest EVEN number ("banker's rounding"): [int]2.5 is 2
        and [int]3.5 is 4. Pass [MidpointRounding]::AwayFromZero to [Math]::Round when you need
        2.5 to become 3.
    #>
    $Percent = [Math]::Round($FreePercent,1)
    $Tenths  = [int][Math]::Round(($Percent * 10),0)
    $Key     = 'VolumeFree_{0}' -f $Tenths

    <#
        LESSON 3: A cache shared through script scope
        $script: refers to the variable defined at the top of the script, not a copy local to this
        function. Every embedded image (logo, icons and these charts) lives in that one hashtable.
        The chart is drawn only the first time its key is requested; after that the stored image
        is reused. The HTML report and the email both read the same hashtable, so a new chart
        automatically appears in both.
    #>
    If (-not $script:HardwareInventoryImageAssets.ContainsKey($Key)) {
        $Bitmap        = $null
        $Graphics      = $null
        $BackgroundPen = $null
        $FreePen       = $null
        $Stream        = $null

        Try {
            <#
                LESSON 4: Loading a .NET assembly on demand
                Windows PowerShell does not load every .NET library at startup. System.Drawing,
                the drawing library, must be loaded before its types can be used.
                Add-Type -AssemblyName loads a library that is already installed with the .NET
                Framework, and does nothing if it is already loaded. Compare Add-Type
                -TypeDefinition elsewhere in this script, which COMPILES new C# code.
            #>
            Add-Type -AssemblyName System.Drawing @script:EA1

            <#
                LESSON 4: Drawing a percentage as an arc
                A full circle is 360 degrees, so each percent is 3.6 degrees: $Sweep = $Percent * 3.6.
                Drawing angles start at 3 o'clock and run clockwise, so a start angle of -90 begins
                at 12 o'clock, like a clock or a progress ring.
                A pen line is centred on its path, so a 5-pixel pen extends 2.5 pixels outside the
                circle. The 3-pixel inset keeps it from being cut off at the image edge.
                [Type]::new(...) creates objects like New-Object does, and has been available since
                PowerShell 5.0.
            #>
            $Size     = 28
            $PenWidth = 5.0
            $Inset    = [float]3
            $Diameter = [float]($Size - 6)
            $Sweep    = [float]($Percent * 3.6)

            $StatusColor     = If ($Percent -ge 20) {
                [System.Drawing.Color]::FromArgb(46,125,50)
            } ElseIf ($Percent -ge 10) {
                [System.Drawing.Color]::FromArgb(212,160,23)
            } Else {
                [System.Drawing.Color]::FromArgb(198,40,40)
            }

            $BackgroundColor = [System.Drawing.Color]::FromArgb(229,231,235)

            <#
                LESSON 6: Declare disposable objects BEFORE the Try
                Finally must dispose only what was actually created. Setting each variable to $null
                first means that if the Try fails halfway, say after creating the Bitmap but before
                the pens, Finally can test If ($Pen) and skip objects that do not exist. Under
                StrictMode, reading a variable that was never assigned would itself throw inside
                Finally.
            #>
            $Bitmap        = [System.Drawing.Bitmap]::new($Size,$Size,[System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
            $Graphics      = [System.Drawing.Graphics]::FromImage($Bitmap)
            $BackgroundPen = [System.Drawing.Pen]::new($BackgroundColor,[float]$PenWidth)
            $FreePen       = [System.Drawing.Pen]::new($StatusColor,[float]$PenWidth)
            $Stream        = [System.IO.MemoryStream]::new()

            <#
                LESSON 7: Smooth edges and a transparent background
                Without anti-aliasing, a curve this small looks jagged and stair-stepped.
                SmoothingMode.AntiAlias blends edge pixels with the background. Clearing to
                Transparent, together with the 32-bit ARGB pixel format (which has an alpha,
                meaning transparency, channel), lets the chart sit on any background color. Round
                line caps give the arc soft ends.
            #>
            $Graphics.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $Graphics.PixelOffsetMode    = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $Graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $Graphics.Clear([System.Drawing.Color]::Transparent)

            $BackgroundPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $BackgroundPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
            $FreePen.StartCap       = [System.Drawing.Drawing2D.LineCap]::Round
            $FreePen.EndCap         = [System.Drawing.Drawing2D.LineCap]::Round

            $Graphics.DrawEllipse($BackgroundPen,$Inset,$Inset,$Diameter,$Diameter)

            If ($Percent -ge 100) {
                $Graphics.DrawEllipse($FreePen,$Inset,$Inset,$Diameter,$Diameter)
            } ElseIf ($Percent -gt 0) {
                $Graphics.DrawArc($FreePen,$Inset,$Inset,$Diameter,$Diameter,[float]-90,$Sweep)
            }

            <#
                LESSON 8: An image that never touches the disk
                Bitmap.Save normally writes a file, but it also accepts any stream. Saving to a
                MemoryStream keeps the PNG bytes in memory, ToArray() returns them, and Base64
                turns them into text that can be embedded directly in HTML as
                src="data:image/png;base64,...". No temporary file is created or left behind.
            #>
            $Bitmap.Save($Stream,[System.Drawing.Imaging.ImageFormat]::Png)

            $script:HardwareInventoryImageAssets[$Key] = @{
                MimeType = 'image/png'
                Width    = $Size
                Height   = $Size
                Base64   = [Convert]::ToBase64String($Stream.ToArray())
            }
        } Catch {
            <#
                LESSON 9: Fail small
                A missing chart is cosmetic. If drawing fails, for example because the graphics
                library is unavailable, the function warns and returns an empty string. The volume
                row still shows its free-space numbers, and the rest of the report is unaffected.
            #>
            Write-Warning -Message ('Unable to create volume free-space chart for {0}% free: {1}' -f $Percent,$_.Exception.Message)
            Return ''
        } Finally {
            <#
                LESSON 10: Graphics objects hold scarce operating-system resources
                Bitmaps, Graphics objects and pens each hold a Windows GDI+ handle, and a process
                can hold only a limited number of them. Leaked handles eventually cause confusing
                errors such as "Parameter is not valid" or "Out of memory". Dispose each one
                explicitly. They are released in reverse order of creation, so objects that depend
                on others go first: the Graphics object draws on the Bitmap, so the Graphics object
                is released before the Bitmap.
            #>
            If ($Stream)        { $Stream.Dispose() }
            If ($FreePen)       { $FreePen.Dispose() }
            If ($BackgroundPen) { $BackgroundPen.Dispose() }
            If ($Graphics)      { $Graphics.Dispose() }
            If ($Bitmap)        { $Bitmap.Dispose() }
        }
    }

    Return Get-HardwareInventoryImageHtml -Key $Key -Alt ('{0}% free' -f $Percent) -CssClass 'volume-space-chart'
} ### Lessons

Function Get-HardwareInventoryPlatformIconKey {
    <#
        .SYNOPSIS
        Selects the appropriate computer icon for the inventoried platform.

        .DESCRIPTION
        Returns Laptop, Workstation, or Server according to the collected operating system and
        chassis description. Virtual machines use Server when running Windows Server and
        Workstation otherwise.

        .PARAMETER Computer
        Computer inventory object.

        .EXAMPLE
        Get-HardwareInventoryPlatformIconKey -Computer $Inventory.Computer

        Returns Laptop, Workstation or Server.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the computer inventory object.')]
        [object]$Computer
    )

    $OS      = [string]$Computer.OS
    $Chassis = [string]$Computer.Chassis

    If ($OS -match 'Windows Server' -or $Chassis -match 'Server|Rack|Blade') {
        Return 'Server'
    }

    If ($Chassis -match 'Portable|Laptop|Notebook|Sub Notebook|Convertible|Detachable') {
        Return 'Laptop'
    }

    Return 'Workstation'
}

Function New-HardwareInventorySectionTitle {
    <#
        .SYNOPSIS
        Builds a report section heading with an embedded icon.

        .DESCRIPTION
        Returns the table-based section heading used throughout the report: a 20x20 embedded icon
        followed by the HTML-encoded title. Table layout keeps the heading aligned in Outlook.

        .PARAMETER Title
        Section title.

        .PARAMETER IconKey
        Embedded icon asset key.

        .EXAMPLE
        New-HardwareInventorySectionTitle -Title 'Volumes' -IconKey 'Volume'
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the section title.')]
        [string]$Title,

        [Parameter(Mandatory, HelpMessage = 'Specify the embedded icon asset key.')]
        [string]$IconKey
    )

    $Icon      = Get-HardwareInventoryImageHtml -Key $IconKey -Alt '' -CssClass 'section-icon'
    $SafeTitle = [System.Net.WebUtility]::HtmlEncode($Title)

    Return '<table class="section-heading" width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td class="section-icon-cell" width="30">{0}</td><td class="section-title-text">{1}</td></tr></table>' -f $Icon,$SafeTitle
}

Function Convert-EdidString {
    <#
        .SYNOPSIS
        Converts an EDID byte array to a clean ASCII string.

        .DESCRIPTION
        Converts byte-array properties returned by WmiMonitorID to ASCII while removing NUL bytes.
        Null and invalid values return $null instead of terminating inventory collection.

        .PARAMETER Value
        EDID byte array to convert.

        .EXAMPLE
        Convert-EdidString -Value $Monitor.SerialNumberID

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [object]$Value
    )

    If ($null -eq $Value) {
        Return $null
    }

    Try {
        $Bytes = @(
            $Value | Where-Object {
                [int]$_ -ne 0
            } | ForEach-Object {
                [byte]$_
            }
        )

        If ($Bytes.Count -eq 0) {
            Return $null
        }

        Return ([System.Text.Encoding]::ASCII.GetString([byte[]]$Bytes)).Trim()
    } Catch {
        Write-Verbose -Message ('Unable to convert EDID value: {0}' -f $_.Exception.Message)

        Return $null
    }
}

Function Convert-CimDateTime {
    <#
        .SYNOPSIS
        Converts CIM/WMI date values to DateTime.

        .DESCRIPTION
        Accepts either an existing DateTime value or a DMTF-formatted WMI date string and returns a
        DateTime value. Invalid values return $null.

        .PARAMETER Value
        Date/time value to normalize.

        .EXAMPLE
        Convert-CimDateTime -Value $OperatingSystem.InstallDate

        .OUTPUTS
        System.DateTime
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [object]$Value
    )

    If ($null -eq $Value) {
        Return $null
    }

    If ($Value -is [datetime]) {
        Return [datetime]$Value
    }

    Try {
        Return [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)
    } Catch {
        Write-Verbose -Message ('Unable to convert CIM date value [{0}]: {1}' -f $Value,$_.Exception.Message)

        Return $null
    }
}

Function Get-LastInteractiveLogonUser {
    <#
        .SYNOPSIS
        Returns the most recent interactive user from the local Security event log.

        .DESCRIPTION
        Queries successful Security event 4624 records for interactive (2), remote interactive (10)
        and cached interactive (11) logon types.

        The current PowerShell security context is attempted first. If the Security log cannot be
        read and an alternate credential was supplied, a temporary Windows PowerShell 5.1 process
        is started under that credential and its result is returned directly through redirected
        standard output.

        No temporary files are created.

        Computer accounts and common Windows service identities are excluded.

        .PARAMETER Credential
        Optional credential used to launch the fallback PowerShell process when the current process
        cannot read the Security event log.

        .EXAMPLE
        Get-LastInteractiveLogonUser -Credential $SACredential

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        <#
            LESSON 1: Accepting a credential flexibly
            [System.Management.Automation.Credential()] lets a caller pass just a user name, such
            as -Credential 'DOMAIN\username', and PowerShell prompts for the password. Without
            it, -Credential accepts only a complete PSCredential object.
        #>
        [System.Management.Automation.Credential()]
        [pscredential]$Credential
    )

    Function Get-LastInteractiveLogonFromSecurityLog {
        <#
            .SYNOPSIS
            Queries the local Security log for the most recent interactive user.

            .DESCRIPTION
            Reads event 4624 records and returns the most recent valid type 2, 10 or 11 user.

            .EXAMPLE
            Get-LastInteractiveLogonFromSecurityLog

            .OUTPUTS
            PSCustomObject
        #>
        [CmdletBinding()]
        Param ()

        <#
            LESSON 2: Let the event log do the filtering
            The Security log on a busy server holds hundreds of thousands of events. -FilterXPath
            sends the query to the event log service, which returns only matching events: logon
            event 4624 with LogonType 2, 10 or 11. Piping everything into Where-Object would read
            and convert every event first, then discard most of them.
            Get-WinEvent returns the NEWEST events first, so the first valid match below is the
            most recent interactive user. -MaxEvents 200 limits the search.
        #>
        ### Interactive (2), remote interactive (10) and cached interactive (11) logons only. Cached
        ### logons are how laptop users sign in away from the domain network.
        $XPath  = "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]"
        $Events = Get-WinEvent -LogName 'Security' -FilterXPath $XPath -MaxEvents 200 @script:EA1

        ForEach ($LogonEvent in $Events) {
            <#
                LESSON 3: Reading event details from the event's XML
                An event's message text is formatted for people and changes with the Windows
                language. Its XML holds the same details as named fields:
                <Data Name="TargetUserName">jsmith</Data>. Reading them into a hashtable keyed by
                Name gives reliable values such as $Data.TargetUserName on any Windows language.
                '#text' must be quoted because # would otherwise start a comment; it is how
                PowerShell exposes an XML element's inner text.
            #>
            $Xml  = [xml]$LogonEvent.ToXml()
            $Data = @{}

            ForEach ($Item in $Xml.Event.EventData.Data) {
                $Data[[string]$Item.Name] = [string]$Item.'#text'
            }

            If ($Data.LogonType -notin '2','10','11') {
                Continue
            }

            $User   = [string]$Data.TargetUserName
            $Domain = [string]$Data.TargetDomainName

            If ([string]::IsNullOrWhiteSpace($User)) {
                Continue
            }

            <#
                LESSON 4: Skip accounts that are not people, then stop at the first real one
                Computer accounts end in $, and '\$$' means "a literal $ at the end": the first $ is
                escaped, the second is the end-of-text anchor. DWM-n and UMFD-n are virtual
                accounts Windows creates for the desktop and font drivers at every sign-in.
                Return inside the ForEach ends the WHOLE function with the first real user. Because
                events arrive newest first, that is the most recent one.
            #>
            If ($User -match '\$$' -or $User -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+)$') {
                Continue
            }

            Return [PSCustomObject][ordered]@{
                UserName    = If (-not [string]::IsNullOrWhiteSpace($Domain)) { '{0}\{1}' -f $Domain,$User } Else { $User }
                TimeCreated = $LogonEvent.TimeCreated
                LogonType   = [int]$Data.LogonType
            }
        }

        Return $null
    }

    <#
        LESSON 5: Try the simple way first, and fall back only when needed
        Reading the Security log needs rights the current user may not have. The function first
        tries in its own session. Only if that fails AND a credential was supplied does it pay for
        the expensive fallback: starting a separate PowerShell process as another user.
    #>
    Try {
        $Result = Get-LastInteractiveLogonFromSecurityLog
        If ($Result -and -not [string]::IsNullOrWhiteSpace([string]$Result.UserName)) {
            Return [string]$Result.UserName
        }
    } Catch {
        Write-Verbose -Message ('Current security context cannot query the Security event log: {0}' -f $_.Exception.Message)
    }

    If (-not $Credential) {
        Return $null
    }

    <#
        LESSON 6: A script written for a separate process
        @' ... '@ is a single-quoted here-string: everything inside, including $variables, is
        kept as literal text and is not expanded here. That matters because this text is the
        program the child process runs.
        The child is a brand-new powershell.exe. None of this script's functions or variables
        exist there, which is why it repeats the query and uses -ErrorAction Stop instead of
        @script:EA1. A function's text can be sent with ${function:Name}, but only when it
        depends on nothing else from the parent script, and the nested function above uses
        @script:EA1.
        A process can return only text, so the child converts its result to one line of JSON and
        the parent converts it back into an object. JSON is a simple way to pass structured data
        between processes.
    #>
    $ChildScript = @'
$Result = $null
Try {
    $XPath  = "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]"
    $Events = Get-WinEvent -LogName 'Security' -FilterXPath $XPath -MaxEvents 200 -ErrorAction Stop
    ForEach ($LogonEvent in $Events) {
        $Xml  = [xml]$LogonEvent.ToXml()
        $Data = @{}
        ForEach ($Item in $Xml.Event.EventData.Data) { $Data[[string]$Item.Name] = [string]$Item.'#text' }
        If ($Data.LogonType -notin '2','10','11') { Continue }
        $User   = [string]$Data.TargetUserName
        $Domain = [string]$Data.TargetDomainName
        If ([string]::IsNullOrWhiteSpace($User)) { Continue }
        If ($User -match '\$$' -or $User -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+)$') { Continue }

        $Result = [PSCustomObject][ordered]@{
            UserName    = If (-not [string]::IsNullOrWhiteSpace($Domain)) { '{0}\{1}' -f $Domain,$User } Else { $User }
            TimeCreated = $LogonEvent.TimeCreated
            LogonType   = [int]$Data.LogonType
        }

        Break
    }
} Catch {
    $Result = [PSCustomObject][ordered]@{
        UserName    = $null
        TimeCreated = $null
        LogonType   = $null
        Error       = $_.Exception.Message
    }
}

$Result | ConvertTo-Json -Compress
'@

    <#
        LESSON 7: Passing a script safely with -EncodedCommand
        A script passed on a command line must survive quoting: its quotes, $ signs and line
        breaks would all be interpreted by the command line. powershell.exe -EncodedCommand
        accepts the script as Base64 text, which contains only letters, digits, + / and =.
        PowerShell expects the bytes to be UTF-16LE, which .NET calls [Text.Encoding]::Unicode,
        so that is the encoding used here.
    #>
    $EncodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($ChildScript)
    )

    $Domain   = $null
    $UserName = $Credential.UserName

    <#
        LESSON 8: Named capture groups
        (?<Domain>...) names a capture group, so the value is read as $Matches.Domain instead of
        a numbered $Matches[1]. Names make the intent obvious. [^\\]+ means "one or more
        characters that are not a backslash", and \\ is one literal backslash, because backslash
        is the escape character in regular expressions. 'DOMAIN\username' splits into the domain
        and user name that ProcessStartInfo needs separately.
    #>
    If ($UserName -match '^(?<Domain>[^\\]+)\\(?<User>.+)$') {
        $Domain   = $Matches.Domain
        $UserName = $Matches.User
    }

    <#
        LESSON 9: Why ProcessStartInfo rather than Start-Process
        Start-Process -Credential can run a program as another user, but it can redirect output
        only to FILES. This function promises not to create temporary files. ProcessStartInfo
        returns the output directly as streams:
          UseShellExecute = $false   required for redirection and for running as another user.
          Redirect...     = $true    sends stdout and stderr back to this script.
          Password                   is a SecureString; the plaintext password is never needed.
          LoadUserProfile = $false   skips loading the user's profile, which is faster.
        The full path to Windows PowerShell 5.1 prevents a different powershell.exe found earlier
        on PATH from running instead.
    #>
    $StartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo

    $StartInfo.FileName               = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $StartInfo.Arguments              = "-NoProfile -NonInteractive -EncodedCommand $EncodedCommand"
    $StartInfo.UseShellExecute        = $false
    $StartInfo.CreateNoWindow         = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError  = $true
    $StartInfo.UserName               = $UserName
    $StartInfo.Password               = $Credential.Password
    $StartInfo.LoadUserProfile        = $false

    If (-not [string]::IsNullOrWhiteSpace($Domain)) {
        $StartInfo.Domain = $Domain
    }

    $Process = New-Object -TypeName System.Diagnostics.Process

    $Process.StartInfo = $StartInfo

    Try {
        $null = $Process.Start()

        <#
            LESSON 10: The redirected-output deadlock, and never waiting forever
            Each redirected stream passes through a pipe with a small buffer. If the child fills the
            stderr buffer while the parent is still waiting on stdout, the child blocks on stderr,
            the parent blocks on stdout, and both wait forever. ReadToEndAsync() drains stderr in
            the background while stdout is read; $ErrorTask.Result collects it afterwards.
            WaitForExit(60000) returns $false if the process is still running after 60 seconds,
            instead of waiting indefinitely, and Kill() then ends it.
        #>
        ### Read stderr asynchronously while stdout is drained; reading both streams one after the
        ### other can deadlock when the child fills the stderr pipe buffer.
        $ErrorTask      = $Process.StandardError.ReadToEndAsync()
        $StandardOutput = $Process.StandardOutput.ReadToEnd()

        If (-not $Process.WaitForExit(60000)) {
            Try {
                $Process.Kill()
            } Catch {
                Write-Verbose -Message ('Unable to stop the Security-log helper process: {0}' -f $_.Exception.Message)
            }

            Write-Verbose -Message 'Security-log helper did not finish within 60 seconds.'

            Return $null
        }

        $StandardError = $ErrorTask.Result

        <#
            LESSON 11: Check how the child process finished before trusting its output
            An exit code of 0 means success by convention. A non-zero code, empty output, or text
            that is not valid JSON each means "no answer". Each is handled separately with a
            verbose message, so -Verbose shows exactly which step failed.
        #>
        If ($Process.ExitCode -ne 0) {
            Write-Verbose -Message ('Security-log helper exited with code {0}: {1}' -f $Process.ExitCode,$StandardError)

            Return $null
        }

        If ([string]::IsNullOrWhiteSpace($StandardOutput)) {
            If (-not [string]::IsNullOrWhiteSpace($StandardError)) {
                Write-Verbose -Message ('Security-log helper returned no result: {0}' -f $StandardError)
            }

            Return $null
        }

        Try {
            $Result = $StandardOutput.Trim() | ConvertFrom-Json @script:EA1
        } Catch {
            Write-Verbose -Message ('Unable to parse Security-log helper result: {0}' -f $_.Exception.Message)

            Return $null
        }

        <#
            LESSON 12: Check that a property exists before reading it
            The child adds an Error property only when it failed. Under Set-StrictMode, reading
            $Result.Error on a successful result, which has no Error property, would THROW. An
            earlier version did exactly that: it discarded every successful answer because the
            Catch block swallowed the StrictMode error. PSObject.Properties['Error'] checks
            whether the property exists first.
        #>
        If ($Result.PSObject.Properties['Error'] -and $Result.Error) {
            Write-Verbose -Message ('Alternate credential could not query the Security event log: {0}' -f $Result.Error)

            Return $null
        }

        If (-not [string]::IsNullOrWhiteSpace([string]$Result.UserName)) {
            Return [string]$Result.UserName
        }

        Return $null
    } Catch {
        Write-Verbose -Message ('Unable to launch alternate-credential Security-log query: {0}' -f $_.Exception.Message)

        Return $null
    } Finally {
        $Process.Dispose()
    }
} ### Lessons

Function Get-InteractiveUserName {
    <#
        .SYNOPSIS
        Returns the currently interactive user name or the most recent interactive logon.

        .DESCRIPTION
        Prefers Win32_ComputerSystem.UserName and falls back to the owner of explorer.exe when the
        primary property is unavailable.

        If no user is currently logged on, the function queries the local Security event log for the
        most recent successful interactive or remote-interactive logon event and returns that account.

        .PARAMETER ComputerSystem
        Win32_ComputerSystem CIM instance already collected by the caller.

        .PARAMETER Credential
        Optional alternate credential used to read the Security event log when the current user
        cannot, and no interactive user is signed in.

        .EXAMPLE
        Get-InteractiveUserName -ComputerSystem $ComputerSystem

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the Win32_ComputerSystem CIM instance used to determine the interactive user.')]
        [object]$ComputerSystem,

        [Parameter()]
        [System.Management.Automation.Credential()]
        [pscredential]$Credential
    )

    If ($ComputerSystem -and -not [string]::IsNullOrWhiteSpace([string]$ComputerSystem.UserName)) {
        Return [string]$ComputerSystem.UserName
    }

    Try {
        $Explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" @script:EA1 | Select-Object -First 1
        If ($Explorer) {
            $Owner = Invoke-CimMethod -InputObject $Explorer -MethodName GetOwner @script:EA1
            If ($Owner.ReturnValue -eq 0 -and $Owner.User) {
                If ($Owner.Domain) {
                    Return ('{0}\{1}' -f $Owner.Domain,$Owner.User)
                }

                Return [string]$Owner.User
            }
        }
    } Catch {
        Write-Verbose -Message ('Unable to determine explorer.exe owner: {0}' -f $_.Exception.Message)
    }

    If ($Credential) {
        Try {
            $LastUser = Get-LastInteractiveLogonUser -Credential $Credential
            If (-not [string]::IsNullOrWhiteSpace([string]$LastUser)) {
                Return $LastUser
            }
        } Catch {
            Write-Verbose -Message ('Unable to determine the last interactive logon user: {0}' -f $_.Exception.Message)
        }
    }

    Return $null
}

Function Convert-SpeedToGbps {
    <#
        .SYNOPSIS
        Converts bits per second to gigabits per second.

        .DESCRIPTION
        Converts a network adapter bit-rate value to a rounded Gbps value.

        .PARAMETER BitsPerSecond
        Network speed in bits per second.

        .EXAMPLE
        Convert-SpeedToGbps -BitsPerSecond 1000000000

        .OUTPUTS
        System.Double
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [object]$BitsPerSecond
    )

    If (
        $null -eq $BitsPerSecond -or
        [uint64]$BitsPerSecond -eq 0 -or
        [uint64]$BitsPerSecond -gt 1PB
    ) {
        Return $null
    }

    ### Network link speeds are decimal (1 Gbps = 1,000,000,000 bits per second), not binary.
    Return [Math]::Round(([double]$BitsPerSecond / 1e9),2)
}

Function Get-ChassisTypeName {
    <#
        .SYNOPSIS
        Converts SMBIOS chassis type numbers to readable names.

        .DESCRIPTION
        Maps Win32_SystemEnclosure.ChassisTypes values to descriptive chassis/form-factor names.

        .PARAMETER ChassisTypes
        One or more SMBIOS chassis type numbers.

        .EXAMPLE
        Get-ChassisTypeName -ChassisTypes @(31)

        Returns Convertible.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify one or more SMBIOS chassis type values to translate.')]
        [int[]]$ChassisTypes
    )

    $Map = @{
        1  = 'Other'
        2  = 'Unknown'
        3  = 'Desktop'
        4  = 'Low Profile Desktop'
        5  = 'Pizza Box'
        6  = 'Mini Tower'
        7  = 'Tower'
        8  = 'Portable'
        9  = 'Laptop'
        10 = 'Notebook'
        11 = 'Hand Held'
        12 = 'Docking Station'
        13 = 'All in One'
        14 = 'Sub Notebook'
        15 = 'Space-Saving'
        16 = 'Lunch Box'
        17 = 'Main System Chassis'
        18 = 'Expansion Chassis'
        19 = 'SubChassis'
        20 = 'Bus Expansion Chassis'
        21 = 'Peripheral Chassis'
        22 = 'Storage Chassis'
        23 = 'Rack Mount Chassis'
        24 = 'Sealed-Case PC'
        30 = 'Tablet'
        31 = 'Convertible'
        32 = 'Detachable'
        35 = 'Mini PC'
        36 = 'Stick PC'
    }

    $Names = @()
    ForEach ($Type in @($ChassisTypes)) {
        If ($Map.ContainsKey($Type)) {
            $Names += $Map[$Type]
        } Else {
            $Names += ('Type {0}' -f $Type)
        }
    }

    Return ($Names -join ', ')
}

Function Get-MemoryTypeName {
    <#
        .SYNOPSIS
        Converts SMBIOS memory type numbers to readable names.

        .DESCRIPTION
        Maps Win32_PhysicalMemory.SMBIOSMemoryType to common memory technology names.

        .PARAMETER SmbiosMemoryType
        SMBIOS memory type number.

        .EXAMPLE
        Get-MemoryTypeName -SmbiosMemoryType 26

        Returns DDR4.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the SMBIOS memory type number to translate.')]
        [int]$SmbiosMemoryType
    )

    $script:UN  = 'Unknown'

    $Map = @{
        0  = $script:UN
        1  = 'Other'
        2  = $script:UN
        3  = 'DRAM'
        4  = 'EDRAM'
        5  = 'VRAM'
        6  = 'SRAM'
        7  = 'RAM'
        8  = 'ROM'
        9  = 'FLASH'
        10 = 'EEPROM'
        11 = 'FEPROM'
        12 = 'EPROM'
        13 = 'CDRAM'
        14 = '3DRAM'
        15 = 'SDRAM'
        16 = 'SGRAM'
        17 = 'RDRAM'
        18 = 'DDR'
        19 = 'DDR2'
        20 = 'DDR2 FB-DIMM'
        24 = 'DDR3'
        25 = 'FBD2'
        26 = 'DDR4'
        27 = 'LPDDR'
        28 = 'LPDDR2'
        29 = 'LPDDR3'
        30 = 'LPDDR4'
        34 = 'DDR5'
        35 = 'LPDDR5'
        36 = 'HBM3'
    }

    If ($Map.ContainsKey($SmbiosMemoryType)) {
        Return $Map[$SmbiosMemoryType]
    }

    Return ('Type {0}' -f $SmbiosMemoryType)
}

Function Get-MemoryFormFactorName {
    <#
        .SYNOPSIS
        Converts Win32_PhysicalMemory FormFactor values to readable names.

        .DESCRIPTION
        Maps SMBIOS/Win32_PhysicalMemory FormFactor values to common package names such as DIMM,
        SODIMM, BGA, and LGA. Unknown values are preserved numerically.

        .PARAMETER FormFactor
        Numeric Win32_PhysicalMemory FormFactor value.

        .EXAMPLE
        Get-MemoryFormFactorName -FormFactor 12

        Returns SODIMM.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,HelpMessage='Specify the Win32_PhysicalMemory FormFactor value to translate.')]
        [int]$FormFactor
    )

    $Map = @{
        0  = 'Unknown'
        1  = 'Other'
        2  = 'SIP'
        3  = 'DIP'
        4  = 'ZIP'
        5  = 'SOJ'
        6  = 'Proprietary'
        7  = 'SIMM'
        8  = 'DIMM'
        9  = 'TSOP'
        10 = 'PGA'
        11 = 'RIMM'
        12 = 'SODIMM'
        13 = 'SRIMM'
        14 = 'SMD'
        15 = 'SSMP'
        16 = 'QFP'
        17 = 'TQFP'
        18 = 'SOIC'
        19 = 'LCC'
        20 = 'PLCC'
        21 = 'BGA'
        22 = 'FPBGA'
        23 = 'LGA'
    }

    If ($Map.ContainsKey($FormFactor)) {
        Return $Map[$FormFactor]
    }

    Return ('FormFactor {0}' -f $FormFactor)
}

Function Get-MemoryTypeDetailName {
    <#
        .SYNOPSIS
        Converts the Win32_PhysicalMemory TypeDetail bitmask to readable text.

        .DESCRIPTION
        Expands the TypeDetail bitmask into one or more descriptive values. This preserves useful
        SMBIOS detail such as Synchronous, Nonvolatile, EDO, or RAMBUS when firmware exposes it.

        .PARAMETER TypeDetail
        Numeric Win32_PhysicalMemory TypeDetail bitmask.

        .EXAMPLE
        Get-MemoryTypeDetailName -TypeDetail 128

        Returns Synchronous.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,HelpMessage='Specify the Win32_PhysicalMemory TypeDetail bitmask to translate.')]
        [uint32]$TypeDetail
    )

    If ($TypeDetail -eq 0) {
        Return $script:UN
    }

    $Map = [ordered]@{
        1    = 'Reserved'
        2    = 'Other'
        4    = $script:UN
        8    = 'Fast-paged'
        16   = 'Static column'
        32   = 'Pseudo-static'
        64   = 'RAMBUS'
        128  = 'Synchronous'
        256  = 'CMOS'
        512  = 'EDO'
        1024 = 'Window DRAM'
        2048 = 'Cache DRAM'
        4096 = 'Nonvolatile'
    }

    $Names = @()
    ForEach ($Bit in $Map.Keys) {
        If ($TypeDetail -band [uint32]$Bit) {
            $Names += $Map[$Bit]
        }
    }

    If ($Names.Count -eq 0) {
        Return ('TypeDetail {0}' -f $TypeDetail)
    }

    Return ($Names -join ', ')
}

Function Get-NetworkConnectionStatusName {
    <#
        .SYNOPSIS
        Converts Win32_NetworkAdapter NetConnectionStatus to readable text.

        .DESCRIPTION
        Maps the numeric NetConnectionStatus value reported by Win32_NetworkAdapter to the
        corresponding connection state while preserving unknown values numerically.

        .PARAMETER Status
        Numeric Win32_NetworkAdapter NetConnectionStatus value.

        .EXAMPLE
        Get-NetworkConnectionStatusName -Status 2

        Returns Connected.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the Win32_NetworkAdapter NetConnectionStatus value to translate.')]
        [int]$Status
    )

    $Map = @{
        0  = 'Disconnected'
        1  = 'Connecting'
        2  = 'Connected'
        3  = 'Disconnecting'
        4  = 'Hardware not present'
        5  = 'Hardware disabled'
        6  = 'Hardware malfunction'
        7  = 'Media disconnected'
        8  = 'Authenticating'
        9  = 'Authentication succeeded'
        10 = 'Authentication failed'
        11 = 'Invalid address'
        12 = 'Credentials required'
    }

    If ($Map.ContainsKey($Status)) {
        Return $Map[$Status]
    }

    Return ('Status {0}' -f $Status)
}

Function Get-VirtualPlatformInfo {
    <#
        .SYNOPSIS
        Determines whether the current Windows instance appears physical or virtual.

        .DESCRIPTION
        Uses computer-system manufacturer/model plus BIOS identity to identify common Hyper-V,
        VMware, VirtualBox, Xen, KVM/QEMU, Nutanix, and other virtual-machine platforms. The function
        returns a compact classification object and does not change system state.

        .PARAMETER ComputerSystem
        Win32_ComputerSystem instance to inspect.

        .PARAMETER Bios
        Win32_BIOS instance to inspect.

        .EXAMPLE
        Get-VirtualPlatformInfo -ComputerSystem $ComputerSystem -Bios $Bios

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the Win32_ComputerSystem instance to classify.')]
        [object]$ComputerSystem,

        [Parameter(Mandatory, HelpMessage = 'Provide the Win32_BIOS instance to classify.')]
        [object]$Bios
    )

    $Manufacturer = [string]$ComputerSystem.Manufacturer
    $Model        = [string]$ComputerSystem.Model
    $BiosText     = ('{0} {1}' -f ([string]$Bios.Manufacturer),([string]$Bios.Version))
    $VirtualType  = $null

    If ($Manufacturer -match '(?i)VMware' -or $Model -match '(?i)VMware' -or [string]$Bios.SerialNumber -match '(?i)VMware') {
        $VirtualType = 'VMware'
    } ElseIf (($Manufacturer -match '(?i)Microsoft' -and $Model -match '(?i)Virtual Machine') -or $BiosText -match '(?i)Hyper-V') {
        $VirtualType = 'Hyper-V'
    } ElseIf ($Manufacturer -match '(?i)innotek|Oracle' -or $Model -match '(?i)VirtualBox') {
        $VirtualType = 'VirtualBox'
    } ElseIf ($Manufacturer -match '(?i)Xen' -or $Model -match '(?i)Xen' -or $BiosText -match '(?i)Xen') {
        $VirtualType = 'Xen'
    } ElseIf ($Manufacturer -match '(?i)QEMU|Red Hat' -or $Model -match '(?i)KVM|QEMU' -or $BiosText -match '(?i)SeaBIOS') {
        $VirtualType = 'KVM/QEMU'
    } ElseIf ($Manufacturer -match '(?i)Nutanix' -or $Model -match '(?i)Nutanix') {
        $VirtualType = 'Nutanix AHV'
    } ElseIf ($Model -match '(?i)Virtual|HVM domU') {
        $VirtualType = 'Virtual Machine'
    }

    [PSCustomObject][ordered]@{
        IsVirtual   = [bool]$VirtualType
        SystemType  = If ($VirtualType) {'Virtual'} Else {'Physical'}
        VirtualType = $VirtualType
    }
}

Function Get-MonitorManufacturerName {
    <#
        .SYNOPSIS
        Converts a three-character EDID manufacturer code to a friendly manufacturer name.

        .DESCRIPTION
        Maps common EDID manufacturer codes encountered on enterprise endpoints. Unknown codes are
        returned unchanged rather than discarded.

        .PARAMETER Code
        Three-character EDID manufacturer code.

        .EXAMPLE
        Get-MonitorManufacturerName -Code 'DEL'

        Returns Dell.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]$Code
    )

    $EIZ = 'EIZO'
    $ENV = 'Envision'
    $FUJ = 'Fujitsu'
    $PAN = 'Panasonic'
    $SAM = 'Samsung'
    $TOS = 'Toshiba'

    $Map = @{
        'AAC' = 'AcerView'
        'ACR' = 'Acer'
        'AIC' = 'AG Neovo'
        'AOC' = 'AOC'
        'APP' = 'Apple'
        'AST' = 'AST Research'
        'AUS' = 'ASUS'
        'AUO' = 'AU Optronics'
        'BNQ' = 'BenQ'
        'CMO' = 'Chi Mei Optoelectronics'
        'CPL' = 'Compal'
        'CPQ' = 'Compaq'
        'CPT' = 'Chunghwa Picture Tubes'
        'CTX' = 'CTX'
        'DEC' = 'DEC'
        'DEL' = 'Dell'
        'DPC' = 'Delta'
        'DWE' = 'Daewoo'
        'EIZ' = $EIZ
        'ELS' = 'ELSA'
        'ENC' = $EIZ
        'ENV' = $ENV
        'EPI' = $ENV
        'FCM' = 'Funai'
        'FUJ' = $FUJ
        'FUS' = 'Fujitsu-Siemens'
        'GSM' = 'LG Electronics'
        'GWY' = 'Gateway'
        'HEI' = 'Hyundai'
        'HIT' = 'Hitachi'
        'HPN' = 'HP'
        'HSD' = 'Hanns.G'
        'HSL' = 'Hansol'
        'HTC' = 'Hitachi/Nissei'
        'HWP' = 'HP'
        'IBM' = 'IBM'
        'ICL' = 'Fujitsu ICL'
        'IVM' = 'Iiyama'
        'KDS' = 'Korea Data Systems'
        'LEN' = 'Lenovo'
        'LGD' = 'LG Display'
        'LPL' = 'LG Philips'
        'MAX' = 'Belinea'
        'MEI' = $PAN
        'MEL' = 'Mitsubishi'
        'MS_' = $PAN
        'NAN' = 'Nanao'
        'NEC' = 'NEC'
        'NOK' = 'Nokia'
        'NVD' = $FUJ
        'OPT' = 'Optoma'
        'PHL' = 'Philips'
        'REL' = 'Relisys'
        'SAM' = $SAM
        'SAN' = $SAM
        'SBI' = 'SMART Technologies'
        'SEC' = $SAM
        'SGI' = 'SGI'
        'SHP' = 'Sharp'
        'SNY' = 'Sony'
        'SRC' = 'Shamrock'
        'SUN' = 'Sun Microsystems'
        'TAT' = 'Tatung'
        'TOS' = $TOS
        'TSB' = $TOS
        'VSC' = 'ViewSonic'
        'ZCM' = 'Zenith'
    }

    If ([string]::IsNullOrWhiteSpace($Code)) {
        Return $null
    }

    If ($Map.ContainsKey($Code)) {
        Return $Map[$Code]
    }

    Return $Code
}

Function Get-VideoOutputTechnologyName {
    <#
        .SYNOPSIS
        Converts WmiMonitorConnectionParams.VideoOutputTechnology to a readable connector type.

        .DESCRIPTION
        Maps D3DKMDT_VIDEO_OUTPUT_TECHNOLOGY values exposed by WmiMonitorConnectionParams. This
        distinguishes internal laptop panels from VGA, DVI, HDMI, DisplayPort, Miracast, indirect
        wired displays such as DisplayLink, and other connection technologies.

        .PARAMETER Value
        VideoOutputTechnology numeric value to translate.

        .EXAMPLE
        Get-VideoOutputTechnologyName -Value 5

        Returns HDMI.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the WmiMonitorConnectionParams VideoOutputTechnology value to translate.')]
        [object]$Value
    )

    $Numeric = [uint64]$Value

    $Map     = @{
        '0'          = 'VGA'
        '1'          = 'S-Video'
        '2'          = 'Composite Video'
        '3'          = 'Component Video'
        '4'          = 'DVI'
        '5'          = 'HDMI'
        '6'          = 'LVDS / MIPI DSI'
        '8'          = 'D-JPN'
        '9'          = 'SDI'
        '10'         = 'DisplayPort'
        '11'         = 'Embedded DisplayPort'
        '12'         = 'UDI'
        '13'         = 'Embedded UDI'
        '14'         = 'SDTV Dongle'
        '15'         = 'Miracast'
        '16'         = 'Indirect Wired Display'
        '2147483648' = 'Internal Display'
        '4294967294' = 'Uninitialized'
        '4294967295' = 'Other'
    }

    $Key = [string]$Numeric
    If ($Map.ContainsKey($Key)) {
        Return $Map[$Key]
    }

    Return ('Technology {0}' -f $Value)
}

Function Get-CurrentDisplayTopology {
    <#
        .SYNOPSIS
        Returns current display-to-monitor mappings and active resolutions.

        .DESCRIPTION
        Uses the Win32 EnumDisplayDevices and EnumDisplaySettings APIs to obtain the display source,
        monitor PnP identifier, current configured resolution, refresh rate, primary-display state,
        and desktop-attachment state. This complements EDID data from root\wmi and allows current
        resolution to be correlated to individual monitor product identifiers.

        .EXAMPLE
        Get-CurrentDisplayTopology

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    If (-not ('HardwareInventory.NativeDisplay' -as [type])) {
        $Source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace HardwareInventory
{
    public class DisplayInfo
    {
        public string DisplayName { get; set; }
        public string DisplayString { get; set; }
        public string MonitorDeviceId { get; set; }
        public string MonitorString { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public int Frequency { get; set; }
        public bool Primary { get; set; }
        public bool AttachedToDesktop { get; set; }
    }

    public static class NativeDisplay
    {
        private const int ENUM_CURRENT_SETTINGS = -1;
        private const int EDD_GET_DEVICE_INTERFACE_NAME = 1;
        private const int DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 0x1;
        private const int DISPLAY_DEVICE_PRIMARY_DEVICE = 0x4;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DISPLAY_DEVICE
        {
            public int cb;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
            public int StateFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DEVMODE
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
            public short dmSpecVersion;
            public short dmDriverVersion;
            public short dmSize;
            public short dmDriverExtra;
            public int dmFields;
            public int dmPositionX;
            public int dmPositionY;
            public int dmDisplayOrientation;
            public int dmDisplayFixedOutput;
            public short dmColor;
            public short dmDuplex;
            public short dmYResolution;
            public short dmTTOption;
            public short dmCollate;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
            public short dmLogPixels;
            public int dmBitsPerPel;
            public int dmPelsWidth;
            public int dmPelsHeight;
            public int dmDisplayFlags;
            public int dmDisplayFrequency;
            public int dmICMMethod;
            public int dmICMIntent;
            public int dmMediaType;
            public int dmDitherType;
            public int dmReserved1;
            public int dmReserved2;
            public int dmPanningWidth;
            public int dmPanningHeight;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);

        public static List<DisplayInfo> GetDisplays()
        {
            List<DisplayInfo> result = new List<DisplayInfo>();

            for (uint adapterIndex = 0; ; adapterIndex++)
            {
                DISPLAY_DEVICE adapter = new DISPLAY_DEVICE();
                adapter.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
                if (!EnumDisplayDevices(null, adapterIndex, ref adapter, 0))
                    break;

                if ((adapter.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) == 0)
                    continue;

                DEVMODE mode = new DEVMODE();
                mode.dmSize = (short)Marshal.SizeOf(typeof(DEVMODE));
                bool haveMode = EnumDisplaySettings(adapter.DeviceName, ENUM_CURRENT_SETTINGS, ref mode);

                bool foundMonitor = false;
                for (uint monitorIndex = 0; ; monitorIndex++)
                {
                    DISPLAY_DEVICE monitor = new DISPLAY_DEVICE();
                    monitor.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
                    if (!EnumDisplayDevices(adapter.DeviceName, monitorIndex, ref monitor, EDD_GET_DEVICE_INTERFACE_NAME))
                        break;

                    foundMonitor = true;
                    result.Add(new DisplayInfo
                    {
                        DisplayName = adapter.DeviceName,
                        DisplayString = adapter.DeviceString,
                        MonitorDeviceId = monitor.DeviceID,
                        MonitorString = monitor.DeviceString,
                        Width = haveMode ? mode.dmPelsWidth : 0,
                        Height = haveMode ? mode.dmPelsHeight : 0,
                        Frequency = haveMode ? mode.dmDisplayFrequency : 0,
                        Primary = (adapter.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0,
                        AttachedToDesktop = true
                    });
                }

                if (!foundMonitor)
                {
                    result.Add(new DisplayInfo
                    {
                        DisplayName = adapter.DeviceName,
                        DisplayString = adapter.DeviceString,
                        MonitorDeviceId = null,
                        MonitorString = null,
                        Width = haveMode ? mode.dmPelsWidth : 0,
                        Height = haveMode ? mode.dmPelsHeight : 0,
                        Frequency = haveMode ? mode.dmDisplayFrequency : 0,
                        Primary = (adapter.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0,
                        AttachedToDesktop = true
                    });
                }
            }

            return result;
        }
    }
}
'@

        Try {
            Add-Type -TypeDefinition $Source -Language CSharp @script:EA1
        } Catch {
            Write-Verbose -Message ('Unable to compile display topology helper: {0}' -f $_.Exception.Message)

            Return @()
        }
    }

    Try {
        Return @([HardwareInventory.NativeDisplay]::GetDisplays())
    } Catch {
        Write-Verbose -Message ('Unable to enumerate current display topology: {0}' -f $_.Exception.Message)

        Return @()
    }
}

Function Get-LastUpdateInfo {
    <#
        .SYNOPSIS
        Returns the most recent successful Windows Update installation event.

        .DESCRIPTION
        Uses the Windows Update Agent COM API to inspect per-machine update history and returns the
        newest successful or successful-with-errors installation event. If Windows Update history
        cannot be queried, falls back to Win32_QuickFixEngineering InstalledOn values.

        .EXAMPLE
        Get-LastUpdateInfo

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    Try {
        $Session  = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $Count    = $Searcher.GetTotalHistoryCount()

        If ($Count -gt 0) {
            $ReadCount         = [Math]::Min([int]$Count,200)
            $HistoryCollection = $Searcher.QueryHistory(0,$ReadCount)
            $History           = @(
                For ($Index = 0; $Index -lt $HistoryCollection.Count; $Index++) {
                    $HistoryCollection.Item($Index)
                }
            )

            $Latest            = $History | Where-Object {
                $_.Operation -eq 1 -and 
                $_.ResultCode -in 2,3 -and 
                $_.Date
            } | Sort-Object -Property Date -Descending | Select-Object -First 1

            If ($Latest) {
                Return [PSCustomObject][ordered]@{
                    DateTime = [datetime]$Latest.Date
                    Title    = [string]$Latest.Title
                    Source   = 'Windows Update Agent history'
                }
            }
        }
    } Catch {
        Write-Verbose -Message ('Windows Update Agent history lookup failed: {0}' -f $_.Exception.Message)
    }

    Try {
        $LatestQfe = Get-CimInstance -ClassName Win32_QuickFixEngineering @script:EA1 | Where-Object {
            $_.InstalledOn
        } | ForEach-Object {
            $Date = $null
            If ($_.InstalledOn -is [datetime]) {
                $Date = [datetime]$_.InstalledOn
            } Else {
                $Parsed = [datetime]::MinValue
                If ([datetime]::TryParse([string]$_.InstalledOn,[ref]$Parsed)) {
                    $Date = $Parsed
                }
            }

            If ($Date) {
                [PSCustomObject]@{
                    DateTime = $Date
                    Title    = ('{0} {1}' -f $_.Description,$_.HotFixID).Trim()
                }
            }
        } | Sort-Object -Property DateTime -Descending | Select-Object -First 1

        If ($LatestQfe) {
            Return [PSCustomObject][ordered]@{
                DateTime = $LatestQfe.DateTime
                Title    = $LatestQfe.Title
                Source   = 'Win32_QuickFixEngineering fallback'
            }
        }
    } Catch {
        Write-Verbose -Message ('Quick-fix update fallback failed: {0}' -f $_.Exception.Message)
    }

    Return $null
}

Function Get-WindowsVersionInfo {
    <#
        .SYNOPSIS
        Returns Windows release and full build information from the CurrentVersion registry key.

        .DESCRIPTION
        Reads DisplayVersion/ReleaseId, CurrentBuildNumber/CurrentBuild, and UBR from the Windows NT
        CurrentVersion registry key. Combining CurrentBuildNumber with UBR produces the same full
        OS-build notation shown by winver, for example 22631.7582.

        .EXAMPLE
        Get-WindowsVersionInfo

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $Key = $null
    Try {
        $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        If ($null -eq $Key) {
            Return $null
        }

        $DisplayVersion = [string]$Key.GetValue('DisplayVersion',$null)
        If ([string]::IsNullOrWhiteSpace($DisplayVersion)) {
            $DisplayVersion = [string]$Key.GetValue('ReleaseId',$null)
        }

        $CurrentBuild = [string]$Key.GetValue('CurrentBuildNumber',$null)
        If ([string]::IsNullOrWhiteSpace($CurrentBuild)) {
            $CurrentBuild = [string]$Key.GetValue('CurrentBuild',$null)
        }

        $Ubr       = $Key.GetValue('UBR',$null)
        $FullBuild = $CurrentBuild
        If ($CurrentBuild -and $null -ne $Ubr -and "$Ubr" -ne '') {
            $FullBuild = ('{0}.{1}' -f $CurrentBuild,$Ubr)
        }

        Return [PSCustomObject][ordered]@{
            DisplayVersion = $DisplayVersion
            CurrentBuild   = $CurrentBuild
            UBR            = $Ubr
            FullBuild      = $FullBuild
            BuildLabEx     = [string]$Key.GetValue('BuildLabEx',$null)
        }
    } Catch {
        Write-Verbose -Message ('Unable to read Windows CurrentVersion information: {0}' -f $_.Exception.Message)

        Return $null
    } Finally {
        If ($null -ne $Key) {
            $Key.Dispose()
        }
    }
}
#endregion Helper Functions

#region Inventory Functions
Function Get-DellObjectPropertyValue {
    <#
        .SYNOPSIS
        Safely returns a named property from an object.

        .DESCRIPTION
        Returns the value of a named PSObject property without causing a StrictMode
        exception when the property is not present.

        .PARAMETER InputObject
        Object containing the property to retrieve.

        .PARAMETER Name
        Name of the property to retrieve.

        .EXAMPLE
        Get-DellObjectPropertyValue -InputObject $Object -Name 'Firmware Version'

        .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the object containing the property to retrieve.')]
        [object]$InputObject,

        [Parameter(Mandatory, HelpMessage = 'Provide the property name to retrieve.')]
        [string]$Name
    )

    $Property = $InputObject.PSObject.Properties[$Name]

    If ($Property) {
        Return $Property.Value
    }

    Return $null
}

Function Get-DellNumericValue {
    <#
        .SYNOPSIS
        Extracts the first numeric value from vendor-formatted text.

        .DESCRIPTION
        Extracts the first signed integer or decimal number from a string and removes
        embedded thousands separators.

        Values such as [N/A], Not Applicable, Not Available, and blank strings return null.

        .PARAMETER Value
        Vendor-formatted value containing a numeric measurement.

        .EXAMPLE
        Get-DellNumericValue -Value '1,862.50 GB'

        Returns 1862.5.

        .OUTPUTS
        System.Double
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the vendor-formatted value containing the number to extract.')]
        [AllowEmptyString()]
        [object]$Value
    )

    If ($null -eq $Value) {
        Return $null
    }

    $Text = [string]$Value

    If (
        [string]::IsNullOrWhiteSpace($Text) -or 
        $Text -match '^\s*(\[?N/?A\]?|Not Applicable|Not Available|Unknown)\s*$'
    ) {
        Return $null
    }

    $Match = [regex]::Match($Text,'-?\d[\d,]*(?:\.\d+)?')
    If (-not $Match.Success) {
        Return $null
    }

    $NumericText = $Match.Value.Replace(',','')
    $Number      = 0.0

    If (
        [double]::TryParse(
            $NumericText,
            [Globalization.NumberStyles]::Float,
            [cultureinfo]::InvariantCulture,
            [ref]$Number
        )
    ) {
        Return $Number
    }

    Return $null
}

Function Get-DellCapacityBytes {
    <#
        .SYNOPSIS
        Extracts an exact byte count from Dell OpenManage capacity text.

        .DESCRIPTION
        Dell OpenManage commonly represents capacity as a human-readable value followed
        by an exact byte count in parentheses.

        .PARAMETER Value
        Capacity string returned by Dell OpenManage.

        .EXAMPLE
        Get-DellCapacityBytes -Value '372.00 GB (399431958528 bytes)'

        Returns 399431958528.

        .OUTPUTS
        System.UInt64
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the Dell OpenManage capacity string containing an exact byte count.')]
        [AllowEmptyString()]
        [string]$Value
    )

    If ([string]::IsNullOrWhiteSpace($Value)) {
        Return $null
    }

    $Match = [regex]::Match($Value,'\((?<Bytes>[\d,]+)\s+bytes\)','IgnoreCase')
    If (-not $Match.Success) {
        Return $null
    }

    $Bytes = [uint64]0
    If ([uint64]::TryParse($Match.Groups['Bytes'].Value.Replace(',',''),[ref]$Bytes)) {
        Return $Bytes
    }

    Return $null
}

Function Convert-DellCimSensorValue {
    <#
        .SYNOPSIS
        Converts a Dell CIM sensor reading to its normalized numeric value.

        .DESCRIPTION
        Applies the CIM UnitModifier to a raw sensor reading.

        Dell CIM commonly exposes temperature values such as CurrentReading=210 with
        UnitModifier=-1, representing 21.0 degrees.

        Dell also uses Int32.MinValue as an unavailable sensor threshold sentinel.
        That value is returned as null.

        .PARAMETER Value
        Raw CIM sensor value.

        .PARAMETER UnitModifier
        CIM UnitModifier applied to the raw sensor value.

        .EXAMPLE
        Convert-DellCimSensorValue -Value 210 -UnitModifier -1

        Returns 21.

        .OUTPUTS
        System.Double
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the raw Dell CIM sensor value.')]
        [object]$Value,

        [Parameter(Mandatory, HelpMessage = 'Provide the CIM UnitModifier used to scale the sensor value.')]
        [int]$UnitModifier
    )

    If ($null -eq $Value) {
        Return $null
    }

    $NumericValue = 0.0
    If (-not [double]::TryParse([string]$Value,[ref]$NumericValue)) {
        Return $null
    }

    If ($NumericValue -eq [int]::MinValue -or $NumericValue -eq [long]::MinValue) {
        Return $null
    }

    Return [Math]::Round(($NumericValue * [Math]::Pow(10,$UnitModifier)),2)
}

Function Convert-DellRedundancyStatus {
    <#
        .SYNOPSIS
        Converts Dell CIM redundancy codes to readable values.

        .DESCRIPTION
        Converts known Dell redundancy status codes to readable text.

        Dell CIM returned code 2 for fully redundant fan groups on the validated
        PowerEdge R430.

        Unknown values are retained as an explicit numeric code rather than guessed.

        .PARAMETER Status
        Dell CIM redundancy status code.

        .EXAMPLE
        Convert-DellRedundancyStatus -Status 2

        Returns Full.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the Dell CIM redundancy status code.')]
        [int]$Status
    )

    Switch ($Status) {
        2       { Return 'Full' }
        default { Return ('Unknown ({0})' -f $Status) }
    }
}

Function Get-DellOmReportPath {
    <#
        .SYNOPSIS
        Locates Dell OpenManage omreport.exe.

        .DESCRIPTION
        Attempts command discovery first, then checks known Dell OpenManage installation
        paths without recursively scanning Program Files.

        .EXAMPLE
        Get-DellOmReportPath

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param ()

    Try {
        $Command = Get-Command -Name 'omreport.exe' @script:EA1
        If ($Command -and -not [string]::IsNullOrWhiteSpace([string]$Command.Source)) {
            Return [string]$Command.Source
        }
    } Catch {
        Write-Verbose -Message ('omreport.exe was not available through command discovery: {0}' -f $_.Exception.Message)
    }

    $KnownPaths = @("$env:ProgramW6432\Dell\SysMgt\oma\bin\omreport.exe", "${env:ProgramFiles(x86)}\Dell\SysMgt\oma\bin\omreport.exe")
    ForEach ($Path in $KnownPaths) {
        If (Test-Path -LiteralPath $Path) {
            Return $Path
        }
    }

    Return $null
}

Function Invoke-DellOmReport {
    <#
        .SYNOPSIS
        Executes Dell OpenManage omreport.exe and returns its output as text lines.

        .DESCRIPTION
        Executes the supplied omreport executable with a provided argument list.

        Non-zero exit codes are treated as unavailable data for inventory purposes and
        are reported through Write-Verbose.

        .PARAMETER Path
        Full path to omreport.exe.

        .PARAMETER ArgumentList
        Arguments passed to omreport.exe.

        .EXAMPLE
        Invoke-DellOmReport -Path $OmReport -ArgumentList @('storage','controller')

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the full path to omreport.exe.')]
        [string]$Path,

        [Parameter(Mandatory, HelpMessage = 'Provide the arguments to pass to omreport.exe.')]
        [string[]]$ArgumentList
    )

    If (-not (Test-Path -LiteralPath $Path)) {
        Write-Verbose -Message ('Dell OpenManage executable does not exist: {0}' -f $Path)
        Return @()
    }

    Try {
        $Output   = @(& $Path @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
        $ExitCode = $LASTEXITCODE
        If ($ExitCode -ne 0) {
            Write-Verbose -Message ('omreport {0} exited with code {1}.' -f ($ArgumentList -join ' '),$ExitCode)

            Return @()
        }

        Return $Output
    } Catch {
        Write-Verbose -Message ('Unable to execute omreport {0}: {1}' -f ($ArgumentList -join ' '),$_.Exception.Message)

        Return @()
    }
}

Function ConvertFrom-DellOmReportBlock {
    <#
        .SYNOPSIS
        Converts Dell OpenManage key/value blocks into PowerShell objects.

        .DESCRIPTION
        Parses Dell OpenManage text output where records are represented by Key : Value
        pairs separated by blank lines.

        Heading and separator lines that do not contain key/value data are ignored.

        .PARAMETER InputObject
        Text lines returned by omreport.exe.

        .EXAMPLE
        ConvertFrom-DellOmReportBlock -InputObject $Lines

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the text lines returned by Dell OpenManage omreport.exe.')]
        [AllowEmptyString()]
        [string[]]$InputObject
    )

    $Records = @()
    $Current = [ordered]@{}

    ForEach ($Line in $InputObject) {
        If ([string]::IsNullOrWhiteSpace($Line)) {
            If ($Current.Count -gt 0) {
                $Records += [PSCustomObject]$Current
                $Current  = [ordered]@{}
            }

            Continue
        }

        If ($Line -match '^\s*(?<Name>[^:]+?)\s*:\s*(?<Value>.*)$') {
            $Name  = $Matches.Name.Trim()
            $Value = $Matches.Value.Trim()

            If ($Current.Contains($Name)) {
                If ($Current.Count -gt 0) {
                    $Records += [PSCustomObject]$Current
                }

                $Current = [ordered]@{}
            }

            $Current[$Name] = $Value
        }
    }

    If ($Current.Count -gt 0) {
        $Records += [PSCustomObject]$Current
    }

    Return @($Records)
}

Function Get-DellCimServerInventory {
    <#
        .SYNOPSIS
        Collects Dell server hardware enrichment through the Dell CIM provider.

        .DESCRIPTION
        Queries the local root\cimv2\Dell provider for structured Dell server hardware
        information.

        Data collected when available includes:
        - Fan status, RPM, and thresholds
        - Fan redundancy
        - Power supplies and redundancy
        - Power consumption and headroom
        - Temperature probes and thresholds
        - iDRAC endpoint
        - iDRAC and Lifecycle Controller firmware
        - PERC controller identity visible through Windows

        The function is best-effort and returns an Available=False object when the Dell
        CIM provider is not installed.

        .EXAMPLE
        Get-DellCimServerInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $Namespace = 'root\cimv2\Dell'
    $Available = $false

    $DCIM = 'Dell CIM'
    $DEG  = 'Degraded'
    $OK   = 'OK'

    Try {
        $null = Get-CimClass -Namespace $Namespace -ClassName 'DELL_System' @script:EA1
        $Available = $true
    } Catch {
        Write-Verbose -Message ('Dell CIM provider is unavailable: {0}' -f $_.Exception.Message)
    }

    If (-not $Available) {
        Return [PSCustomObject][ordered]@{
            Available    = $false
            Source       = $DCIM
            Firmware     = @()
            Management   = $null
            Power        = $null
            Cooling      = $null
            Temperatures = $null
            Storage      = $null
        }
    }

    $Firmware = @()
    Try {
        $Firmware = @(
            Get-CimInstance -Namespace $Namespace -ClassName DELL_Firmware @script:EA1 | ForEach-Object {
                [PSCustomObject][ordered]@{
                    Name    = $_.Name
                    Version = $_.Version
                    Source  = $DCIM
                }
            }
        )
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell firmware through CIM: {0}' -f $_.Exception.Message)
    }

    $Management = $null

    Try {
        $Remote = Get-CimInstance -Namespace $Namespace -ClassName Dell_RemoteAccessServicePort @script:EA1 | Select-Object -First 1
        If ($Remote) {
            $IDracFirmware     = $Firmware | Where-Object { $_.Name -match '^iDRAC' } | Select-Object -First 1
            $LifecycleFirmware = $Firmware | Where-Object { $_.Name -match 'Lifecycle Controller' } | Select-Object -First 1

            $Management = [PSCustomObject][ordered]@{
                Product             = If ($IDracFirmware) { $IDracFirmware.Name } Else { 'BMC Remote Access Service Point' }
                IPv4Address         = $Remote.AccessInfo
                HttpsUrl            = $Remote.AccessInfoIPv4
                Firmware            = If ($IDracFirmware) { $IDracFirmware.Version } Else { $null }
                LifecycleController = If ($LifecycleFirmware) { $LifecycleFirmware.Version } Else { $null }
                EnabledState        = $Remote.EnabledState
                Source              = $DCIM
            }
        }
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell remote-access information through CIM: {0}' -f $_.Exception.Message)
    }

    $Fans = @()
    Try {
        $Fans = @(
            Get-CimInstance -Namespace $Namespace -ClassName CIM_Tachometer @script:EA1 | ForEach-Object {
                [PSCustomObject][ordered]@{
                    Name             = $_.Name
                    Status           = $_.Status
                    RPM              = If ($null -ne $_.CurrentReading) { [int]$_.CurrentReading } Else { $null }
                    WarningMinimum   = If ($_.LowerThresholdNonCritical -ne [int]::MinValue) { [int]$_.LowerThresholdNonCritical } Else { $null }
                    CriticalMinimum  = If ($_.LowerThresholdCritical -ne [int]::MinValue)    { [int]$_.LowerThresholdCritical } Else { $null }
                    WarningMaximum   = If ($_.UpperThresholdNonCritical -ne [int]::MinValue) { [int]$_.UpperThresholdNonCritical } Else { $null }
                    CriticalMaximum  = If ($_.UpperThresholdCritical -ne [int]::MinValue)    { [int]$_.UpperThresholdCritical } Else { $null }
                    Source           = $DCIM
                }
            }
        )
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell fan sensors through CIM: {0}' -f $_.Exception.Message)
    }

    $FanRedundancy = $null
    Try {
        $FanGroup = Get-CimInstance -Namespace $Namespace -ClassName DELL_FanRedundancyGroup @script:EA1 | Select-Object -First 1
        If ($FanGroup -and $null -ne $FanGroup.RedundancyStatus) {
            $FanRedundancy = Convert-DellRedundancyStatus -Status ([int]$FanGroup.RedundancyStatus)
        }
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell fan redundancy through CIM: {0}' -f $_.Exception.Message)
    }

    $Cooling = $null
    If ($Fans.Count -gt 0 -or $FanRedundancy) {
        $HealthyFans = @($Fans | Where-Object {$_.Status -match '^OK$'}).Count
        $Cooling     = [PSCustomObject][ordered]@{
            Status       = If ($Fans.Count -gt 0 -and $HealthyFans -eq $Fans.Count) { $OK } ElseIf ($Fans.Count -gt 0) { $DEG } Else { $null }
            Redundancy   = $FanRedundancy
            FanCount     = $Fans.Count
            HealthyCount = $HealthyFans
            Fans         = $Fans
            Source       = $DCIM
        }
    }

    $PowerSupplies = @()
    Try {
        $PowerSupplies = @(
            Get-CimInstance -Namespace $Namespace -ClassName CIM_PowerSupply @script:EA1 | ForEach-Object {
                [PSCustomObject][ordered]@{
                    Name                = $_.Name
                    Status              = $_.Status
                    Presence            = $_.ErrorDescription
                    InputRatedWatts     = If ($null -ne $_.InputRatedPower)  { [Math]::Round(([double]$_.InputRatedPower / 10),0) } Else { $null }
                    MaximumOutputWatts  = If ($null -ne $_.TotalOutputPower) { [Math]::Round(([double]$_.TotalOutputPower / 10),0) } Else { $null }
                    MonitoringCapable   = $_.PMCapable
                    Source              = $DCIM
                }
            }
        )
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell power supplies through CIM: {0}' -f $_.Exception.Message)
    }

    $PowerRedundancy = $null
    Try {
        $PowerGroup = Get-CimInstance -Namespace $Namespace -ClassName DELL_PSRedundancyGroup @script:EA1 | Select-Object -First 1
        If ($PowerGroup -and $null -ne $PowerGroup.RedundancyStatus) {
            $PowerRedundancy = Convert-DellRedundancyStatus -Status ([int]$PowerGroup.RedundancyStatus)
        }
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell power-supply redundancy through CIM: {0}' -f $_.Exception.Message)
    }

    $PowerData = $null
    Try {
        $PowerCim = Get-CimInstance -Namespace $Namespace -ClassName DELL_PowerConsumptionData @script:EA1 | Select-Object -First 1
        If ($PowerCim) {
            $CurrentWatts = $null
            Try {
                $PowerSensor = Get-CimInstance -Namespace $Namespace -ClassName DELL_PowerConsumptionWattsSensor @script:EA1 | Select-Object -First 1
                If ($PowerSensor -and $null -ne $PowerSensor.CurrentReading) {
                    $Modifier     = If ($null -ne $PowerSensor.UnitModifier) { [int]$PowerSensor.UnitModifier } Else { 0 }
                    $CurrentWatts = Convert-DellCimSensorValue -Value $PowerSensor.CurrentReading -UnitModifier $Modifier
                }
            } Catch {
                Write-Verbose -Message ('Unable to collect Dell instantaneous power sensor through CIM: {0}' -f $_.Exception.Message)
            }

            $PowerData = [PSCustomObject][ordered]@{
                Status                   = $PowerCim.Status
                CurrentWatts             = $CurrentWatts
                InstantaneousHeadroomW   = $PowerCim.instHeadRoom
                PeakHeadroomW            = $PowerCim.peakHeadRoom
                PeakWatts                = $PowerCim.peakWattReading
                PeakAmps                 = If ($null -ne $PowerCim.peakAmpReading) { [Math]::Round(([double]$PowerCim.peakAmpReading / 10),1) } Else { $null }
                CumulativeKWh            = If ($null -ne $PowerCim.cumulativePowerReading) { [Math]::Round(([double]$PowerCim.cumulativePowerReading / 1000),3) } Else { $null }
                PowerCapWatts            = $PowerCim.powerCap
                TrackingStart            = $PowerCim.cprStartTime
                PeakPowerTime            = $PowerCim.pwrTime
                Source                   = $DCIM
            }
        }
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell power-consumption information through CIM: {0}' -f $_.Exception.Message)
    }

    $Power = $null
    If ($PowerSupplies.Count -gt 0 -or $PowerData -or $PowerRedundancy) {
        $HealthySupplies = @($PowerSupplies | Where-Object {$_.Status -match '^OK$'}).Count
        $Power           = [PSCustomObject][ordered]@{
            Status          = If ($PowerSupplies.Count -gt 0 -and $HealthySupplies -eq $PowerSupplies.Count) { $OK } ElseIf ($PowerSupplies.Count -gt 0) { $DEG } ElseIf ($PowerData) { $PowerData.Status } Else { $null }
            Redundancy      = $PowerRedundancy
            SupplyCount     = $PowerSupplies.Count
            HealthyCount    = $HealthySupplies
            Supplies        = $PowerSupplies
            Consumption     = $PowerData
            Source          = $DCIM
        }
    }

    $TemperatureSensors = @()
    Try {
        $TemperatureSensors = @(
            Get-CimInstance -Namespace $Namespace -ClassName CIM_TemperatureSensor @script:EA1 | ForEach-Object {
                $Modifier = If ($null -ne $_.UnitModifier) { [int]$_.UnitModifier } Else { 0 }
                [PSCustomObject][ordered]@{
                    Name             = $_.Name
                    Status           = $_.Status
                    Celsius          = Convert-DellCimSensorValue -Value $_.CurrentReading -UnitModifier $Modifier
                    WarningMinimumC  = Convert-DellCimSensorValue -Value $_.LowerThresholdNonCritical -UnitModifier $Modifier
                    CriticalMinimumC = Convert-DellCimSensorValue -Value $_.LowerThresholdCritical -UnitModifier $Modifier
                    WarningMaximumC  = Convert-DellCimSensorValue -Value $_.UpperThresholdNonCritical -UnitModifier $Modifier
                    CriticalMaximumC = Convert-DellCimSensorValue -Value $_.UpperThresholdCritical -UnitModifier $Modifier
                    Source           = $DCIM
                }
            }
        )
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell temperature sensors through CIM: {0}' -f $_.Exception.Message)
    }

    $Temperatures = $null
    If ($TemperatureSensors.Count -gt 0) {
        $HealthyTemperatures = @($TemperatureSensors | Where-Object {$_.Status -match '^OK$'}).Count
        $Temperatures = [PSCustomObject][ordered]@{
            Status       = If ($HealthyTemperatures -eq $TemperatureSensors.Count) { $OK } Else { $DEG }
            SensorCount  = $TemperatureSensors.Count
            HealthyCount = $HealthyTemperatures
            Sensors      = $TemperatureSensors
            Source       = $DCIM
        }
    }

    $StorageControllers = @()
    Try {
        $StorageControllers = @(
            Get-CimInstance -ClassName Win32_SCSIController @script:EA1 | Where-Object {
                $_.Name -match '(?i)PERC'
            } | ForEach-Object {
                [PSCustomObject][ordered]@{
                    Name         = $_.Name
                    Manufacturer = $_.Manufacturer
                    Status       = $_.Status
                    PNPDeviceID  = $_.PNPDeviceID
                    DriverName   = $_.DriverName
                    Source       = 'Windows CIM'
                }
            }
        )
    } Catch {
        Write-Verbose -Message ('Unable to collect Windows-visible PERC controllers: {0}' -f $_.Exception.Message)
    }

    $Storage = [PSCustomObject][ordered]@{
        Source        = If ($StorageControllers.Count -gt 0) { 'Windows CIM' } Else { $null }
        Controllers   = $StorageControllers
        VirtualDisks  = @()
        PhysicalDisks = @()
        Enclosures    = @()
    }

    Return [PSCustomObject][ordered]@{
        Available    = $true
        Source       = $DCIM
        Firmware     = $Firmware
        Management   = $Management
        Power        = $Power
        Cooling      = $Cooling
        Temperatures = $Temperatures
        Storage      = $Storage
    }
}

Function Get-DellOmReportServerInventory {
    <#
        .SYNOPSIS
        Collects Dell server hardware enrichment through Dell OpenManage omreport.

        .DESCRIPTION
        Uses the locally installed Dell OpenManage omreport.exe utility to collect:
        - Chassis health
        - Power supplies
        - Fan information
        - Temperature probes
        - iDRAC and Lifecycle Controller information
        - Firmware versions
        - RAID controllers
        - RAID virtual disks
        - RAID physical disks
        - Storage enclosures

        The function is best-effort and returns Available=False when omreport.exe is not
        installed.

        .PARAMETER Path
        Optional full path to omreport.exe. If omitted, the executable is discovered.

        .EXAMPLE
        Get-DellOmReportServerInventory

        .EXAMPLE
        Get-DellOmReportServerInventory -Path 'C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe'

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]$Path
    )

    $OME = 'Dell OpenManage'
    $OK  = 'OK'
    $DEG = 'Degraded'
    $CHA = 'chassis'
    $SYS = 'system'

    If ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Get-DellOmReportPath
    }

    If ([string]::IsNullOrWhiteSpace($Path)) {
        Return [PSCustomObject][ordered]@{
            Available    = $false
            Source       = $OME
            Health       = $null
            Firmware     = @()
            Management   = $null
            Power        = $null
            Cooling      = $null
            Temperatures = $null
            Storage      = $null
        }
    }

    $HealthComponents = @()

    $HealthLines      = @(Invoke-DellOmReport -Path $Path -ArgumentList @($CHA))
    ForEach ($Line in $HealthLines) {
        If ($Line -match '^\s*(?<Status>Ok|Warning|Critical|Unknown)\s*:\s*(?<Component>.+?)\s*$') {
            $HealthComponents += [PSCustomObject][ordered]@{
                Component = $Matches.Component.Trim()
                Status    = $Matches.Status.Trim()
            }
        }
    }

    $Health = $null
    If ($HealthComponents.Count -gt 0) {
        $Health = [PSCustomObject][ordered]@{
            Status     = If (@($HealthComponents | Where-Object {$_.Status -notmatch '^Ok$'}).Count -eq 0) { $OK } Else { $DEG }
            Components = $HealthComponents
            Source     = $OME
        }
    }

    $VersionLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @($SYS,'version'))
    $VersionRecords = @(ConvertFrom-DellOmReportBlock -InputObject $VersionLines)

    $Firmware       = @(
        $VersionRecords | Where-Object {
            $Name    = Get-DellObjectPropertyValue -InputObject $_ -Name 'Name'
            $Version = Get-DellObjectPropertyValue -InputObject $_ -Name 'Version'

            $Name -and 
            $Version -and 
            $Name -notmatch '(?i)^Microsoft Windows|^Server Administrator$'
        } | ForEach-Object {
            [PSCustomObject][ordered]@{
                Name    = Get-DellObjectPropertyValue -InputObject $_ -Name 'Name'
                Version = Get-DellObjectPropertyValue -InputObject $_ -Name 'Version'
                Source  = 'Dell OpenManage'
            }
        }
    )

    $SummaryLines      = @(Invoke-DellOmReport -Path $Path -ArgumentList @($SYS,'summary'))
    $ManagementValues  = [ordered]@{}
    $InRemoteAccess    = $false
    ForEach ($Line in $SummaryLines) {
        If ($Line -match '^\s*Remote Access Controller Information\s*$') {
            $InRemoteAccess = $true

            Continue
        }

        If ($InRemoteAccess -and $Line -match '^\s*-{3,}\s*$') {
            Break
        }

        If ($InRemoteAccess -and $Line -match '^\s*(?<Name>[^:]+?)\s*:\s*(?<Value>.*)$') {
            $ManagementValues[$Matches.Name.Trim()] = $Matches.Value.Trim()
        }
    }

    $IDracFirmware     = $Firmware | Where-Object { $_.Name -match '^iDRAC' } | Select-Object -First 1
    $LifecycleFirmware = $Firmware | Where-Object { $_.Name -match 'Lifecycle Controller' } | Select-Object -First 1

    $Management = $null
    If ($ManagementValues.Count -gt 0 -or $IDracFirmware -or $LifecycleFirmware) {
        $Management = [PSCustomObject][ordered]@{
            Product             = If ($ManagementValues.Contains('Product'))    { $ManagementValues['Product'] } ElseIf ($IDracFirmware) { $IDracFirmware.Name } Else { $null }
            IPv4Address         = If ($ManagementValues.Contains('IP Address')) { $ManagementValues['IP Address'] } Else { $null }
            HttpsUrl            = If ($ManagementValues.Contains('IP Address') -and $ManagementValues['IP Address'] -match '^\d{1,3}(\.\d{1,3}){3}$') { 'https://{0}:443' -f $ManagementValues['IP Address'] } Else { $null }
            Subnet              = If ($ManagementValues.Contains('IP Subnet'))  { $ManagementValues['IP Subnet'] } Else { $null }
            Gateway             = If ($ManagementValues.Contains('IP Gateway')) { $ManagementValues['IP Gateway'] } Else { $null }
            Firmware            = If ($IDracFirmware) { $IDracFirmware.Version } Else { $null }
            LifecycleController = If ($LifecycleFirmware) { $LifecycleFirmware.Version } Else { $null }
            Source              = $OME
        }
    }

    $PowerLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @($CHA,'pwrsupplies'))
    $PowerRecords = @(ConvertFrom-DellOmReportBlock -InputObject $PowerLines)

    $PowerRedundancy = $null
    ForEach ($Record in $PowerRecords) {
        $Value = Get-DellObjectPropertyValue -InputObject $Record -Name 'Redundancy Status'
        If ($Value) {
            $PowerRedundancy = $Value
            Break
        }
    }

    $PowerSupplies = @(
        $PowerRecords | Where-Object {
            $null -ne (Get-DellObjectPropertyValue -InputObject $_ -Name 'Index')
        } | ForEach-Object {
            [PSCustomObject][ordered]@{
                Name                = Get-DellObjectPropertyValue -InputObject $_ -Name 'Location'
                Status              = Get-DellObjectPropertyValue -InputObject $_ -Name 'Status'
                Presence            = Get-DellObjectPropertyValue -InputObject $_ -Name 'Online Status'
                Type                = Get-DellObjectPropertyValue -InputObject $_ -Name 'Type'
                InputRatedWatts     = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Rated Input Wattage')
                MaximumOutputWatts  = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Maximum Output Wattage')
                Firmware            = Get-DellObjectPropertyValue -InputObject $_ -Name 'Firmware Version'
                MonitoringCapable   = Get-DellObjectPropertyValue -InputObject $_ -Name 'Power Monitoring Capable'
                Source              = $OME
            }
        }
    )

    $PowerMonitoringLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @($CHA,'pwrmonitoring'))

    $CurrentWatts           = $null
    $InstantaneousHeadroomW = $null
    $PeakHeadroomW          = $null
    $PeakWatts              = $null
    $CumulativeKWh          = $null

    ForEach ($Line in $PowerMonitoringLines) {
        If ($null -eq $CurrentWatts -and $Line -match '^\s*Reading\s*:\s*(?<Value>[\d,.]+)\s*W\s*$') {
            $CurrentWatts = Get-DellNumericValue -Value $Matches.Value
            Continue
        }

        If ($Line -match '^\s*System Instantaneous Headroom\s*:\s*(?<Value>[\d,.]+)\s*W\s*$') {
            $InstantaneousHeadroomW = Get-DellNumericValue -Value $Matches.Value
            Continue
        }

        If ($Line -match '^\s*System Peak Headroom\s*:\s*(?<Value>[\d,.]+)\s*W\s*$') {
            $PeakHeadroomW = Get-DellNumericValue -Value $Matches.Value
            Continue
        }

        If ($Line -match '^\s*Peak Reading\s*:\s*(?<Value>[\d,.]+)\s*W\s*$') {
            $PeakWatts = Get-DellNumericValue -Value $Matches.Value
            Continue
        }

        If ($Line -match '^\s*Reading\s*:\s*(?<Value>[\d,.]+)\s*kWh\s*$') {
            $CumulativeKWh = Get-DellNumericValue -Value $Matches.Value
        }
    }

    $Power = $null
    If ($PowerSupplies.Count -gt 0 -or $PowerRedundancy -or $null -ne $CurrentWatts) {
        $HealthySupplies = @($PowerSupplies | Where-Object {$_.Status -match '^Ok$'}).Count
        $Power = [PSCustomObject][ordered]@{
            Status       = If ($PowerSupplies.Count -gt 0 -and $HealthySupplies -eq $PowerSupplies.Count) { $OK } ElseIf ($PowerSupplies.Count -gt 0) { $DEG } Else { $null }
            Redundancy   = $PowerRedundancy
            SupplyCount  = $PowerSupplies.Count
            HealthyCount = $HealthySupplies
            Supplies     = $PowerSupplies
            Consumption  = [PSCustomObject][ordered]@{
                CurrentWatts           = $CurrentWatts
                InstantaneousHeadroomW = $InstantaneousHeadroomW
                PeakHeadroomW          = $PeakHeadroomW
                PeakWatts              = $PeakWatts
                CumulativeKWh          = $CumulativeKWh
                Source                 = $OME
            }
            Source       = $OME
        }
    }

    $FanLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @($CHA,'fans'))
    $FanRecords = @(ConvertFrom-DellOmReportBlock -InputObject $FanLines)

    $FanRedundancy = $null
    ForEach ($Record in $FanRecords) {
        $Value = Get-DellObjectPropertyValue -InputObject $Record -Name 'Redundancy Status'
        If ($Value) {
            $FanRedundancy = $Value
            Break
        }
    }

    $Fans = @(
        $FanRecords | Where-Object {
            $null -ne (Get-DellObjectPropertyValue -InputObject $_ -Name 'Index')
        } | ForEach-Object {
            [PSCustomObject][ordered]@{
                Name             = Get-DellObjectPropertyValue -InputObject $_ -Name 'Probe Name'
                Status           = Get-DellObjectPropertyValue -InputObject $_ -Name 'Status'
                RPM              = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Reading')
                WarningMinimum   = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Minimum Warning Threshold')
                CriticalMinimum  = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Minimum Failure Threshold')
                WarningMaximum   = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Maximum Warning Threshold')
                CriticalMaximum  = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Maximum Failure Threshold')
                Source           = $OME
            }
        }
    )

    $Cooling = $null
    If ($Fans.Count -gt 0 -or $FanRedundancy) {
        $HealthyFans = @($Fans | Where-Object {$_.Status -match '^Ok$'}).Count

        $Cooling = [PSCustomObject][ordered]@{
            Status       = If ($Fans.Count -gt 0 -and $HealthyFans -eq $Fans.Count) { $OK } ElseIf ($Fans.Count -gt 0) { $DEG } Else { $null }
            Redundancy   = $FanRedundancy
            FanCount     = $Fans.Count
            HealthyCount = $HealthyFans
            Fans         = $Fans
            Source       = $OME
        }
    }

    $TemperatureLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @($CHA,'temps'))
    $TemperatureRecords = @(ConvertFrom-DellOmReportBlock -InputObject $TemperatureLines)
    $TemperatureSensors = @(
        $TemperatureRecords | Where-Object {
            $null -ne (Get-DellObjectPropertyValue -InputObject $_ -Name 'Index')
        } | ForEach-Object {
            [PSCustomObject][ordered]@{
                Name             = Get-DellObjectPropertyValue -InputObject $_ -Name 'Probe Name'
                Status           = Get-DellObjectPropertyValue -InputObject $_ -Name 'Status'
                Celsius          = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Reading')
                WarningMinimumC  = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Minimum Warning Threshold')
                CriticalMinimumC = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Minimum Failure Threshold')
                WarningMaximumC  = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Maximum Warning Threshold')
                CriticalMaximumC = Get-DellNumericValue -Value (Get-DellObjectPropertyValue -InputObject $_ -Name 'Maximum Failure Threshold')
                Source           = $OME
            }
        }
    )

    $Temperatures = $null
    If ($TemperatureSensors.Count -gt 0) {
        $HealthyTemperatures = @($TemperatureSensors | Where-Object {$_.Status -match '^Ok$'}).Count
        $Temperatures = [PSCustomObject][ordered]@{
            Status       = If ($HealthyTemperatures -eq $TemperatureSensors.Count) { $OK } Else { $DEG }
            SensorCount  = $TemperatureSensors.Count
            HealthyCount = $HealthyTemperatures
            Sensors      = $TemperatureSensors
            Source       = $OME
        }
    }

    $ControllerLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @('storage','controller'))
    $ControllerRecords = @(ConvertFrom-DellOmReportBlock -InputObject $ControllerLines)
    $Controllers       = @(
        $ControllerRecords | Where-Object {
            $null -ne (Get-DellObjectPropertyValue -InputObject $_ -Name 'ID') -and
            (Get-DellObjectPropertyValue -InputObject $_ -Name 'Name')
        } | ForEach-Object {
            [PSCustomObject][ordered]@{
                ID                = Get-DellObjectPropertyValue -InputObject $_ -Name 'ID'
                Name              = Get-DellObjectPropertyValue -InputObject $_ -Name 'Name'
                Status            = Get-DellObjectPropertyValue -InputObject $_ -Name 'Status'
                State             = Get-DellObjectPropertyValue -InputObject $_ -Name 'State'
                Slot              = Get-DellObjectPropertyValue -InputObject $_ -Name 'Slot ID'
                Firmware          = Get-DellObjectPropertyValue -InputObject $_ -Name 'Firmware Version'
                Driver            = Get-DellObjectPropertyValue -InputObject $_ -Name 'Driver Version'
                StorportDriver    = Get-DellObjectPropertyValue -InputObject $_ -Name 'Storport Driver Version'
                Mode              = Get-DellObjectPropertyValue -InputObject $_ -Name 'Current Controller Mode'
                CacheMemory       = Get-DellObjectPropertyValue -InputObject $_ -Name 'Cache Memory Size'
                PatrolReadMode    = Get-DellObjectPropertyValue -InputObject $_ -Name 'Patrol Read Mode'
                PatrolReadState   = Get-DellObjectPropertyValue -InputObject $_ -Name 'Patrol Read State'
                Source            = $OME
            }
        }
    )

    $VirtualDiskLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @('storage','vdisk'))
    $VirtualDiskRecords = @(ConvertFrom-DellOmReportBlock -InputObject $VirtualDiskLines)
    $VirtualDisks       = @(
        $VirtualDiskRecords | Where-Object {
            $null -ne (Get-DellObjectPropertyValue -InputObject $_ -Name 'ID') -and
            (Get-DellObjectPropertyValue -InputObject $_ -Name 'Layout')
        } | ForEach-Object {
            $SizeText  = [string](Get-DellObjectPropertyValue -InputObject $_ -Name 'Size')
            $SizeBytes = Get-DellCapacityBytes -Value $SizeText

            [PSCustomObject][ordered]@{
                ID           = Get-DellObjectPropertyValue -InputObject $_ -Name 'ID'
                Name         = Get-DellObjectPropertyValue -InputObject $_ -Name 'Name'
                Status       = Get-DellObjectPropertyValue -InputObject $_ -Name 'Status'
                State        = Get-DellObjectPropertyValue -InputObject $_ -Name 'State'
                RaidLevel    = Get-DellObjectPropertyValue -InputObject $_ -Name 'Layout'
                Size         = If ($SizeBytes) { Optimize-HumanReadable -Size $SizeBytes } Else { $SizeText }
                SizeBytes    = $SizeBytes
                WindowsDisk  = Get-DellObjectPropertyValue -InputObject $_ -Name 'Device Name'
                BusProtocol  = Get-DellObjectPropertyValue -InputObject $_ -Name 'Bus Protocol'
                MediaType    = Get-DellObjectPropertyValue -InputObject $_ -Name 'Media'
                ReadPolicy   = Get-DellObjectPropertyValue -InputObject $_ -Name 'Read Policy'
                WritePolicy  = Get-DellObjectPropertyValue -InputObject $_ -Name 'Write Policy'
                StripeSize   = Get-DellObjectPropertyValue -InputObject $_ -Name 'Stripe Element Size'
                Source       = $OME
            }
        }
    )

    $PhysicalDisks = @()
    ForEach ($Controller in $Controllers) {
        If ($null -eq $Controller.ID -or [string]::IsNullOrWhiteSpace([string]$Controller.ID)) {
            Continue
        }

        $PhysicalDiskLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @('storage','pdisk',('controller={0}' -f $Controller.ID)))
        $PhysicalDiskRecords = @(ConvertFrom-DellOmReportBlock -InputObject $PhysicalDiskLines)

        $PhysicalDisks += @(
            $PhysicalDiskRecords | Where-Object {
                (Get-DellObjectPropertyValue -InputObject $_ -Name 'ID') -and
                (Get-DellObjectPropertyValue -InputObject $_ -Name 'Product ID')
            } | ForEach-Object {
                $CapacityText  = [string](Get-DellObjectPropertyValue -InputObject $_ -Name 'Capacity')
                $CapacityBytes = Get-DellCapacityBytes -Value $CapacityText
                $FailureText   = [string](Get-DellObjectPropertyValue -InputObject $_ -Name 'Failure Predicted')
                $CertifiedText = [string](Get-DellObjectPropertyValue -InputObject $_ -Name 'Certified')

                $HotSpareText  = [string](Get-DellObjectPropertyValue -InputObject $_ -Name 'Hot Spare')

                $IsHotSpare    = If ($HotSpareText -match '^(?i)(Global|Dedicated|Yes)$') {
                    $true
                } ElseIf ($HotSpareText -match '^(?i)No$') {
                    $false
                } Else {
                    $null
                }

                [PSCustomObject][ordered]@{
                    ControllerID     = $Controller.ID
                    ID               = Get-DellObjectPropertyValue -InputObject $_ -Name 'ID'
                    Name             = Get-DellObjectPropertyValue -InputObject $_ -Name 'Name'
                    Status           = Get-DellObjectPropertyValue -InputObject $_ -Name 'Status'
                    State            = Get-DellObjectPropertyValue -InputObject $_ -Name 'State'
                    MediaType        = Get-DellObjectPropertyValue -InputObject $_ -Name 'Media'
                    BusProtocol      = Get-DellObjectPropertyValue -InputObject $_ -Name 'Bus Protocol'
                    Model            = Get-DellObjectPropertyValue -InputObject $_ -Name 'Product ID'
                    SerialNumber     = Get-DellObjectPropertyValue -InputObject $_ -Name 'Serial No.'
                    PartNumber       = Get-DellObjectPropertyValue -InputObject $_ -Name 'Part Number'
                    Capacity         = If ($CapacityBytes) { Optimize-HumanReadable -Size $CapacityBytes } Else { $CapacityText }
                    CapacityBytes    = $CapacityBytes
                    Firmware         = Get-DellObjectPropertyValue -InputObject $_ -Name 'Revision'
                    NegotiatedSpeed  = Get-DellObjectPropertyValue -InputObject $_ -Name 'Negotiated Speed'
                    CapableSpeed     = Get-DellObjectPropertyValue -InputObject $_ -Name 'Capable Speed'
                    HotSpare         = $HotSpareText
                    IsHotSpare       = $IsHotSpare
                    Certified        = If ($CertifiedText -match '^Yes$') { $true } ElseIf ($CertifiedText -match '^No$') { $false } Else { $null }
                    FailurePredicted = If ($FailureText -match '^Yes$') { $true } ElseIf ($FailureText -match '^No$') { $false } Else { $null }
                    SectorSize       = Get-DellObjectPropertyValue -InputObject $_ -Name 'Sector Size'
                    WWN              = Get-DellObjectPropertyValue -InputObject $_ -Name 'WWN'
                    Source           = $OME
                }
            }
        )
    }

    $EnclosureLines   = @(Invoke-DellOmReport -Path $Path -ArgumentList @('storage','enclosure'))
    $EnclosureRecords = @(ConvertFrom-DellOmReportBlock -InputObject $EnclosureLines)
    $Enclosures       = @(
        $EnclosureRecords | Where-Object {
            (Get-DellObjectPropertyValue -InputObject $_ -Name 'ID') -and
            (Get-DellObjectPropertyValue -InputObject $_ -Name 'Name')
        } | ForEach-Object {
            [PSCustomObject][ordered]@{
                ID         = Get-DellObjectPropertyValue -InputObject $_ -Name 'ID'
                Name       = Get-DellObjectPropertyValue -InputObject $_ -Name 'Name'
                Status     = Get-DellObjectPropertyValue -InputObject $_ -Name 'Status'
                State      = Get-DellObjectPropertyValue -InputObject $_ -Name 'State'
                Connector  = Get-DellObjectPropertyValue -InputObject $_ -Name 'Connector'
                Firmware   = Get-DellObjectPropertyValue -InputObject $_ -Name 'Firmware Version'
                SASAddress = Get-DellObjectPropertyValue -InputObject $_ -Name 'SAS Address'
                Source     = $OME
            }
        }
    )

    $Storage = [PSCustomObject][ordered]@{
        Source        = $OME
        Controllers   = $Controllers
        VirtualDisks  = $VirtualDisks
        PhysicalDisks = $PhysicalDisks
        Enclosures    = $Enclosures
    }

    Return [PSCustomObject][ordered]@{
        Available    = $true
        Source       = $OME
        Path         = $Path
        Health       = $Health
        Firmware     = $Firmware
        Management   = $Management
        Power        = $Power
        Cooling      = $Cooling
        Temperatures = $Temperatures
        Storage      = $Storage
    }
}

Function Get-DellServerInventory {
    <#
        .SYNOPSIS
        Collects normalized Dell physical-server hardware enrichment.

        .DESCRIPTION
        Combines structured Dell CIM information with Dell OpenManage omreport data.

        Structured CIM data is preferred for cooling, temperatures, power, firmware,
        and remote-access information.

        Dell OpenManage is preferred for chassis health and detailed RAID topology.

        When OpenManage is unavailable, the function falls back to Dell CIM and native
        Windows controller discovery without failing the larger inventory script.

        .EXAMPLE
        Get-DellServerInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $Cim  = Get-DellCimServerInventory
    $OMSA = Get-DellOmReportServerInventory

    $FirmwareMap = [ordered]@{}
    ForEach ($Item in @($OMSA.Firmware)) {
        If ($Item -and -not [string]::IsNullOrWhiteSpace([string]$Item.Name)) {
            $FirmwareMap[[string]$Item.Name] = $Item
        }
    }

    ForEach ($Item in @($Cim.Firmware)) {
        If ($Item -and -not [string]::IsNullOrWhiteSpace([string]$Item.Name)) {
            $FirmwareMap[[string]$Item.Name] = $Item
        }
    }

    $Firmware   = @($FirmwareMap.Values)

    $Management = $null
    If ($Cim.Management) {
        $Management = $Cim.Management
        If (
            $OMSA.Management -and
            [string]::IsNullOrWhiteSpace([string]$Management.Product) -and
            -not [string]::IsNullOrWhiteSpace([string]$OMSA.Management.Product)
        ) {
            $Management.Product = $OMSA.Management.Product
        }

        If (
            $OMSA.Management -and
            [string]::IsNullOrWhiteSpace([string]$Management.IPv4Address) -and
            -not [string]::IsNullOrWhiteSpace([string]$OMSA.Management.IPv4Address)
        ) {
            $Management.IPv4Address = $OMSA.Management.IPv4Address
        }
    } ElseIf ($OMSA.Management) {
        $Management = $OMSA.Management
    }

    $Power        = If ($Cim.Power)        { $Cim.Power } Else { $OMSA.Power }
    $Cooling      = If ($Cim.Cooling)      { $Cim.Cooling } Else { $OMSA.Cooling }
    $Temperatures = If ($Cim.Temperatures) { $Cim.Temperatures } Else { $OMSA.Temperatures }

    $Storage      = If (
        $OMSA.Storage -and (
            @($OMSA.Storage.Controllers).Count -gt 0 -or 
            @($OMSA.Storage.VirtualDisks).Count -gt 0 -or 
            @($OMSA.Storage.PhysicalDisks).Count -gt 0
        )
    ) {
        $OMSA.Storage
    } Else {
        $Cim.Storage
    }

    Return [PSCustomObject][ordered]@{
        Available           = ($Cim.Available -or $OMSA.Available)
        Vendor              = 'Dell'
        DellCimAvailable    = [bool]$Cim.Available
        OpenManageAvailable = [bool]$OMSA.Available
        Health              = $OMSA.Health
        Management          = $Management
        Firmware            = $Firmware
        Power               = $Power
        Cooling             = $Cooling
        Temperatures        = $Temperatures
        Storage             = $Storage
    }
}

Function Get-ComputerInventory {
    <#
        .SYNOPSIS
        Collects computer, operating system, firmware, chassis, and platform identity.

        .DESCRIPTION
        Collects system manufacturer/model, current user, physical/virtual classification, chassis,
        baseboard, BIOS, system UUID, Dell computer Service Tag/support URL, Windows edition/release/
        full build, install date, last boot time, uptime, and latest successful Windows Update event.

        The richer identity fields are retained in the inventory object for JSON/reporting while the
        normal console view remains intentionally concise.

        .EXAMPLE
        Get-ComputerInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $Bios           = Get-CimInstance -ClassName Win32_BIOS
    $Os             = Get-CimInstance -ClassName Win32_OperatingSystem
    $Enclosure      = Get-CimInstance -ClassName Win32_SystemEnclosure @script:EA0 | Select-Object -First 1
    $Product        = Get-CimInstance -ClassName Win32_ComputerSystemProduct @script:EA0 | Select-Object -First 1
    $BaseBoard      = Get-CimInstance -ClassName Win32_BaseBoard @script:EA0 | Select-Object -First 1
    $WindowsVersion = Get-WindowsVersionInfo
    $LastUpdate     = Get-LastUpdateInfo
    $Platform       = Get-VirtualPlatformInfo -ComputerSystem $ComputerSystem -Bios $Bios
    $ServiceTag     = ([string]$Bios.SerialNumber).Trim()
    $DellSupportUrl = $null

    If ($ComputerSystem.Manufacturer -match '(?i)Dell' -and $ServiceTag -match '^[A-Za-z0-9]{7}$') {
        $DellSupportUrl = ('https://www.dell.com/support/home/en-us/product-support/servicetag/{0}/overview' -f $ServiceTag)
    }

    $InstallDate = Convert-CimDateTime -Value $Os.InstallDate
    $LastBoot    = Convert-CimDateTime -Value $Os.LastBootUpTime
    $Uptime      = $null

    If ($null -ne $LastBoot) {
        $Span   = New-TimeSpan -Start $LastBoot -End (Get-Date)
        $Uptime = '{0}d {1:00}:{2:00}:{3:00}' -f $Span.Days,$Span.Hours,$Span.Minutes,$Span.Seconds
    }

    [PSCustomObject][ordered]@{
        ComputerName          = $env:COMPUTERNAME
        CurrentUser           = Get-InteractiveUserName -ComputerSystem $ComputerSystem -Credential $SACredential
        ComputerType          = $Platform.SystemType
        IsVirtual             = $Platform.IsVirtual
        VirtualType           = $Platform.VirtualType
        Manufacturer          = ([string]$ComputerSystem.Manufacturer).Trim()
        Model                 = ([string]$ComputerSystem.Model).Trim()
        SystemFamily          = If ($ComputerSystem.PSObject.Properties.Name -contains 'SystemFamily') { $ComputerSystem.SystemFamily } ElseIf ($Product) { $Product.Version } Else { $null }
        SystemUUID            = If ($Product) { ([string]$Product.UUID).Trim() } Else { $null }
        Domain                = $ComputerSystem.Domain
        Chassis               = If ($Enclosure -and @($Enclosure.ChassisTypes).Count) { Get-ChassisTypeName -ChassisTypes $Enclosure.ChassisTypes } Else { $null }
        ChassisManufacturer   = If ($Enclosure) { ([string]$Enclosure.Manufacturer).Trim() } Else { $null }
        ChassisSerialNumber   = If ($Enclosure) { ([string]$Enclosure.SerialNumber).Trim() } Else { $null }
        ChassisAssetTag       = If ($Enclosure) { ([string]$Enclosure.SMBIOSAssetTag).Trim() } Else { $null }
        BaseBoardManufacturer = If ($BaseBoard) { ([string]$BaseBoard.Manufacturer).Trim() } Else { $null }
        BaseBoardProduct      = If ($BaseBoard) { ([string]$BaseBoard.Product).Trim() } Else { $null }
        BaseBoardSerialNumber = If ($BaseBoard) { ([string]$BaseBoard.SerialNumber).Trim() } Else { $null }
        ServiceTag            = $ServiceTag
        DellSupportUrl        = $DellSupportUrl
        OS                    = ([string]$Os.Caption).Trim()
        Version               = If ($WindowsVersion) { $WindowsVersion.DisplayVersion } Else { $null }
        OSBuild               = If ($WindowsVersion -and $WindowsVersion.FullBuild) { $WindowsVersion.FullBuild } Else { $Os.BuildNumber }
        KernelVersion         = $Os.Version
        Architecture          = $Os.OSArchitecture
        InstalledOn           = $InstallDate
        LastBootTime          = $LastBoot
        Uptime                = $Uptime
        LastUpdateDateTime    = If ($LastUpdate) { $LastUpdate.DateTime } Else { $null }
        LastUpdateTitle       = If ($LastUpdate) { $LastUpdate.Title } Else { $null }
        LastUpdateSource      = If ($LastUpdate) { $LastUpdate.Source } Else { $null }
        BIOSManufacturer      = ([string]$Bios.Manufacturer).Trim()
        BIOSVersion           = ($Bios.SMBIOSBIOSVersion -join ', ')
        BIOSReleaseDate       = Convert-CimDateTime -Value $Bios.ReleaseDate
        CollectedAt           = Get-Date
    }
}

Function Get-CpuInventory {
    <#
        .SYNOPSIS
        Collects processor inventory.

        .DESCRIPTION
        Returns one object per physical processor socket including processor name, manufacturer,
        physical cores, logical processors, clock rates, and firmware virtualization support.

        .EXAMPLE
        Get-CpuInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    ### Win32_Processor reports VirtualizationFirmwareEnabled as False once a hypervisor is running,
    ### because the hypervisor owns the extensions. Report that state instead of a misleading False.
    $HypervisorPresent = [bool](Get-CimInstance -ClassName Win32_ComputerSystem @script:EA0 | Select-Object -First 1 -ExpandProperty HypervisorPresent @script:EA0)

    @(
        Get-CimInstance -ClassName Win32_Processor @script:EA0 | ForEach-Object {
            [PSCustomObject][ordered]@{
                Socket             = $_.SocketDesignation
                Name               = ([string]$_.Name).Trim()
                Manufacturer       = $_.Manufacturer
                Cores              = $_.NumberOfCores
                LogicalProcessors  = $_.NumberOfLogicalProcessors
                MaxClockMHz        = $_.MaxClockSpeed
                CurrentClockMHz    = $_.CurrentClockSpeed
                Virtualization     = If ($HypervisorPresent) { 'In use (hypervisor running)' } Else { $_.VirtualizationFirmwareEnabled }
            }
        }
    )
}

Function Get-SmbiosProcessorSocketInventory {
    <#
        .SYNOPSIS
        Returns processor socket information reported by SMBIOS.

        .DESCRIPTION
        Reads the raw SMBIOS table exposed through MSSmBios_RawSMBiosTables and parses
        Processor Information structures (SMBIOS Type 4).

        Unlike Win32_Processor, SMBIOS can describe processor sockets that exist in the
        platform even when no processor is installed. This allows physical servers and
        workstations to report populated and empty CPU sockets accurately when firmware
        provides the information.

        The function is best-effort. If raw SMBIOS data is unavailable or malformed,
        an empty collection is returned and a verbose message is written.

        .EXAMPLE
        Get-SmbiosProcessorSocketInventory

        Returns one object for each SMBIOS processor socket.

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    <#
        LESSON 1: A private helper for a fiddly job
        Reading a text value out of an SMBIOS structure takes a dozen careful lines. Putting them
        in a nested function, private to this one (as in Lesson 1 of Convert-PasswordCipher),
        keeps the main loop readable: Get-SmbiosStringValue -StringIndex 1 states the intent, and
        the byte-walking details live in one place.
    #>
    Function Get-SmbiosStringValue {
        <#
            .SYNOPSIS
            Resolves a string from an SMBIOS structure string table.

            .DESCRIPTION
            SMBIOS formatted structures reference strings using a one-based index.
            This helper walks the null-terminated string area following a formatted
            structure and returns the requested string.

            .PARAMETER Data
            Complete SMBIOS byte array.

            .PARAMETER StartOffset
            Offset of the first byte in the structure string area.

            .PARAMETER StringIndex
            One-based SMBIOS string index.

            .EXAMPLE
            Get-SmbiosStringValue -Data $Data -StartOffset 100 -StringIndex 1

            .OUTPUTS
            System.String
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Provide the complete SMBIOS byte array.')]
            [byte[]]$Data,

            [Parameter(Mandatory, HelpMessage = 'Provide the offset where the SMBIOS structure string table begins.')]
            [int]$StartOffset,

            [Parameter(Mandatory, HelpMessage = 'Provide the one-based SMBIOS string index to resolve.')]
            [int]$StringIndex
        )

        If (
            $StringIndex -le 0 -or 
            $StartOffset -ge $Data.Length
        ) {
            Return $null
        }

        <#
            LESSON 2: How SMBIOS stores text
            A structure never contains text directly. Its fixed fields hold string NUMBERS (1 = the
            first string, 2 = the second, 0 = no string), and the strings follow the fixed area as
            ASCII text, each ending in a 0 byte:
              'CPU1' 0  'Intel' 0  0
            An extra 0 byte (two in a row) ends the string area. The loop walks forward string by
            string, counting, until it reaches the requested number. Each loop also checks
            $Position -lt $Data.Length, so malformed firmware data cannot make it read past the end
            of the array.
        #>
        $CurrentIndex = 1
        $Position     = $StartOffset
        While ($Position -lt $Data.Length) {
            If ($Data[$Position] -eq 0) {
                Return $null
            }

            $StringStart = $Position
            While (
                $Position -lt $Data.Length -and 
                $Data[$Position] -ne 0
            ) {
                $Position++
            }

            If ($CurrentIndex -eq $StringIndex) {
                $Length = $Position - $StringStart
                If ($Length -gt 0) {
                    Return [Text.Encoding]::ASCII.GetString($Data,$StringStart,$Length)
                }

                Return $null
            }

            $CurrentIndex++
            $Position++
        }

        Return $null
    }

    <#
        LESSON 3: Why read raw firmware tables at all
        Win32_Processor lists only INSTALLED processors. A two-socket server with one CPU looks
        exactly like a one-socket server. SMBIOS is the firmware's own description of the hardware,
        and its Processor Information structures (Type 4) describe every socket, including empty
        ones. That is how the report shows "1 populated / 2 reported sockets".
        $Results starts empty and grows with +=. That is fine here: a server has at most a handful
        of sockets (see Lesson 10 of New-ResponsibilityTableHtml).
    #>
    $Results = @()
    Try {
        <#
            LESSON 4: WMI can hand you raw bytes
            Most WMI classes live in the default root\cimv2 namespace. MSSmBios_RawSMBiosTables lives
            in root\wmi, so -Namespace is required. Its SMBiosData property is the entire firmware
            table as a byte array. Some virtual machines and older firmware do not provide it, so
            the property's existence and value are both checked before use.
        #>
        $Raw = Get-CimInstance -Namespace root\wmi -ClassName MSSmBios_RawSMBiosTables @script:EA1 | Select-Object -First 1
        If (
            -not $Raw -or
            -not ($Raw.PSObject.Properties.Name -contains 'SMBiosData') -or
            $null -eq $Raw.SMBiosData
        ) {
            Write-Verbose -Message 'Raw SMBIOS processor information is unavailable.'
            Return @()
        }

        <#
            LESSON 5: A type constraint on a variable lasts for its lifetime
            [byte[]]$Data = ... converts the value to a byte array, and also makes $Data a byte
            array for good: every later assignment is converted too, or fails. That guarantees
            $Data[$i] is always a single byte and that [Text.Encoding]::ASCII.GetString($Data, ...)
            receives the type it expects.
        #>
        [byte[]]$Data = $Raw.SMBiosData
        $Offset       = 0

        <#
            LESSON 6: Walking a table of variable-size records
            Every SMBIOS structure starts with a 4-byte header:
              byte 0    : Type (4 = processor, 17 = memory device, 127 = end of table)
              byte 1    : Length of the fixed area, header included
              bytes 2-3 : Handle, a unique ID for the structure
            The fixed area is followed by its string area (Lesson 2). There is no index of where
            each structure starts: the only way to find the next one is to read this one's length,
            then skip its strings.
            Firmware data can be wrong, so a structure whose Length is impossible (under 4, or past
            the end of the data) stops parsing instead of reading garbage.
        #>
        While ($Offset + 4 -le $Data.Length) {
            $Type   = [int]$Data[$Offset]
            $Length = [int]$Data[$Offset + 1]
            If ($Length -lt 4 -or ($Offset + $Length) -gt $Data.Length) {
                Write-Verbose -Message ('Stopping SMBIOS parsing because structure at offset {0} has invalid length {1}.' -f $Offset,$Length)
                Break
            }

            If ($Type -eq 4) {
                $SocketIndex = [int]$Data[$Offset + 4]
                $Socket      = Get-SmbiosStringValue -Data $Data -StartOffset ($Offset + $Length) -StringIndex $SocketIndex
                $Populated   = $null
                $StatusCode  = $null
                If ($Length -gt 24) {
                    <#
                        LESSON 7: Several facts packed into one byte
                        Byte 24 of a processor structure (0x18 in the specification) packs two
                        facts into one byte:
                          bit 6     (mask 0x40, binary 0100 0000) : 1 = a CPU is in the socket
                          bits 0-2  (mask 0x07, binary 0000 0111) : CPU status, 0 through 7
                        -band with a mask keeps only the bits that mask selects. -ne 0 turns the
                        socket bit into $true or $false, and the 3-bit status becomes a number that
                        the Switch below translates into words.
                        If ($Length -gt 24) first confirms this structure is long enough to contain
                        byte 24: older SMBIOS versions defined shorter structures.
                    #>
                    $ProcessorStatus = [int]$Data[$Offset + 24]
                    $Populated       = (($ProcessorStatus -band 0x40) -ne 0)
                    $StatusCode      = ($ProcessorStatus -band 0x07)
                }

                $ProcessorStatusText = Switch ($StatusCode) {
                    0       {'Unknown'}
                    1       {'Enabled'}
                    2       {'Disabled by User'}
                    3       {'Disabled by BIOS'}
                    4       {'Idle'}
                    7       {'Other'}
                    Default {$null}
                }

                $Results += [PSCustomObject][ordered]@{
                    Socket     = $Socket
                    Populated  = $Populated
                    Status     = $ProcessorStatusText
                    StatusCode = $StatusCode
                    Source     = 'SMBIOS Type 4'
                }
            }

            <#
                LESSON 8: Finding the next record: scan for two zero bytes
                The string area has no length field, so the only way past it is to scan forward for
                the two consecutive 0 bytes that end it. A structure with no strings at all still
                ends with 0 0, so the same scan works for every structure. The new offset is just
                past those two bytes.
            #>
            $NextOffset = $Offset + $Length
            While (
                $NextOffset + 1 -lt $Data.Length -and 
                -not ($Data[$NextOffset] -eq 0 -and $Data[$NextOffset + 1] -eq 0)
            ) {
                $NextOffset++
            }

            If ($NextOffset + 1 -ge $Data.Length) {
                Break
            }

            $Offset = $NextOffset + 2

            <#
                LESSON 9: Stop at the end-of-table marker
                Type 127 marks the end of the SMBIOS table, and some firmware places padding or
                unrelated data after it. Stopping here, as well as at the end of the array, means
                that data is never parsed as structures.
            #>
            If ($Type -eq 127) {
                Break
            }
        }
    } Catch {
        Write-Verbose -Message ('Unable to collect SMBIOS processor socket information: {0}' -f $_.Exception.Message)
        Return @()
    }

    <#
        LESSON 10: Best effort, and what Return @() really returns
        Socket counts are a detail of the report, so any failure is written as a verbose message
        and the function returns an empty result rather than stopping the inventory.
        A function's output passes through the pipeline, which unrolls arrays. Return @() therefore
        outputs NOTHING, and the caller receives $null, not an empty array. Return @(1) gives the
        caller a plain 1, not an array. The caller restores the array with
        $Sockets = @(Get-SmbiosProcessorSocketInventory), the same @( ) habit as Lesson 5 of
        Show-HardwareInventory.
    #>
    Return @($Results)
} ### Lessons

Function Get-CpuTopology {
    <#
        .SYNOPSIS
        Summarizes installed processors and physical processor sockets.

        .DESCRIPTION
        Combines the installed processor objects collected from Win32_Processor with
        SMBIOS Type 4 socket information.

        InstalledSocketCount represents processors currently installed and visible to
        Windows.

        ReportedSocketCount represents physical processor sockets described by SMBIOS.
        When firmware reports unpopulated sockets, EmptySocketCount identifies those
        locations.

        If SMBIOS socket information is unavailable, ReportedSocketCount and
        EmptySocketCount are left null rather than assuming that all sockets are filled.

        .PARAMETER Processors
        Installed processor inventory returned by Get-CpuInventory.

        .EXAMPLE
        $CPU = @(Get-CpuInventory)
        Get-CpuTopology -Processors $CPU

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the installed processor inventory returned by Get-CpuInventory.')]
        [AllowEmptyCollection()]
        [object[]]$Processors
    )

    $InstalledProcessors  = @($Processors | Where-Object {$null -ne $_})
    $Sockets              = @(Get-SmbiosProcessorSocketInventory)

    $InstalledSocketCount = $InstalledProcessors.Count
    $ReportedSocketCount  = $null
    $EmptySocketCount     = $null

    If ($Sockets.Count -gt 0) {
        $ReportedSocketCount = $Sockets.Count
        $ReportedPopulated   = @($Sockets | Where-Object {$_.Populated -eq $true}).Count
        If ($ReportedPopulated -le $ReportedSocketCount) {
            $EmptySocketCount = $ReportedSocketCount - $ReportedPopulated
        }
    }

    $TotalCores             = [int](($InstalledProcessors | Measure-Object -Property Cores -Sum).Sum)
    $TotalLogicalProcessors = [int](($InstalledProcessors | Measure-Object -Property LogicalProcessors -Sum).Sum)

    Return [PSCustomObject][ordered]@{
        InstalledSocketCount   = $InstalledSocketCount
        ReportedSocketCount    = $ReportedSocketCount
        EmptySocketCount       = $EmptySocketCount
        TotalCores             = $TotalCores
        TotalLogicalProcessors = $TotalLogicalProcessors
        Sockets                = $Sockets
        Source                 = If ($Sockets.Count -gt 0) {'SMBIOS Type 4'} Else {'Win32_Processor'}
    }
}

Function Get-MemoryManufacturerName {
    <#
        .SYNOPSIS
        Translates a JEDEC memory manufacturer code into a vendor name.

        .DESCRIPTION
        Many server BIOSes report DIMM manufacturers as JEDEC ID codes, for example 00CE00B300CE
        for Samsung. Known codes are translated and the original code is kept in parentheses.
        Values that are already vendor names are returned unchanged.

        .PARAMETER Manufacturer
        Manufacturer value reported by Win32_PhysicalMemory.

        .EXAMPLE
        Get-MemoryManufacturerName -Manufacturer '00CE00B300CE'

        Returns Samsung (00CE00B300CE).

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter()]
        [AllowNull()]
        [object]$Manufacturer
    )

    $Text = ([string]$Manufacturer).Trim()
    If ([string]::IsNullOrWhiteSpace($Text)) {
        Return $null
    }

    $Vendors = [ordered]@{
        'CE' = 'Samsung'
        'AD' = 'SK Hynix'
        '2C' = 'Micron'
        '98' = 'Kingston'
        '9B' = 'Crucial'
        'CB' = 'A-DATA'
        '0B' = 'Nanya'
        'C1' = 'Infineon'
        '51' = 'Qimonda'
        'FE' = 'Elpida'
        '4F' = 'Transcend'
        '94' = 'Mushkin'
        '85' = 'Corsair'
    }

    If ($Text -match '^(?i)(?:00|80)?([0-9A-F]{2})(?:00|80)?(?:[0-9A-F]{2})*$' -and $Text.Length -ge 4) {
        $Code = $Matches[1].ToUpper()
        If ($Text -match '^(?i)(00|80)') {
            $Code = $Text.Substring(2,2).ToUpper()
        } ElseIf ($Text -match '^(?i)[0-9A-F]{2}(00|80)') {
            $Code = $Text.Substring(0,2).ToUpper()
        }

        If ($Vendors.Contains($Code)) {
            Return ('{0} ({1})' -f $Vendors[$Code],$Text)
        }
    }

    Return $Text
}

Function Get-MemoryInventory {
    <#
        .SYNOPSIS
        Collects physical memory arrays, populated modules, and reported slot utilization.

        .DESCRIPTION
        Uses Win32_PhysicalMemory for populated devices and Win32_PhysicalMemoryArray for array-level
        capacity and reported memory-device counts. Each populated module is retained individually.

        When firmware reports more memory locations than populated Win32_PhysicalMemory instances,
        explicit empty placeholder rows are added to Slots. Windows normally does not expose the true
        SMBIOS locator name for an unpopulated slot, so empty rows are deliberately labeled as
        unreported instead of inventing DIMM socket names.

        .EXAMPLE
        Get-MemoryInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $RawModules = @(Get-CimInstance -ClassName Win32_PhysicalMemory @script:EA0)
    $Arrays     = @(Get-CimInstance -ClassName Win32_PhysicalMemoryArray @script:EA0)
    $ModuleNo   = 0

    $Modules = @(
        ForEach ($Module in $RawModules) {
            $ModuleNo++
            $ConfiguredSpeed = $null
            If ($Module.PSObject.Properties.Name -contains 'ConfiguredClockSpeed') {
                $ConfiguredSpeed = $Module.ConfiguredClockSpeed
            }

            [PSCustomObject][ordered]@{
                Slot          = $ModuleNo
                Status        = 'Populated'
                Bank          = $Module.BankLabel
                Locator       = $Module.DeviceLocator
                Capacity      = Optimize-HumanReadable -Size $Module.Capacity
                CapacityBytes = [uint64]$Module.Capacity
                Type          = Get-MemoryTypeName -SmbiosMemoryType ([int]$Module.SMBIOSMemoryType)
                FormFactor    = Get-MemoryFormFactorName -FormFactor ([int]$Module.FormFactor)
                TypeDetail    = Get-MemoryTypeDetailName -TypeDetail ([uint32]$Module.TypeDetail)
                SpeedMHz      = $Module.Speed
                ConfiguredMHz = $ConfiguredSpeed
                Manufacturer  = Get-MemoryManufacturerName -Manufacturer $Module.Manufacturer
                PartNumber    = ([string]$Module.PartNumber).Trim()
                SerialNumber  = If (([string]$Module.SerialNumber).Trim() -match '^(0+|N/A|None|Unknown)$') { $null } Else { ([string]$Module.SerialNumber).Trim() }
            }
        }
    )

    $ArrayInventory = @(
        ForEach ($Array in $Arrays) {
            $MaxBytes = [uint64]0
            If (
                $Array.PSObject.Properties.Name -contains 'MaxCapacityEx' -and 
                [double]$Array.MaxCapacityEx -gt 0
            ) {
                $MaxBytes = [uint64]$Array.MaxCapacityEx * 1KB
            } ElseIf ([double]$Array.MaxCapacity -gt 0) {
                $MaxBytes = [uint64]$Array.MaxCapacity * 1KB
            }

            [PSCustomObject][ordered]@{
                Tag              = $Array.Tag
                Location         = $Array.Location
                Use              = $Array.Use
                MemoryDevices    = $Array.MemoryDevices
                MaxCapacity      = If ($MaxBytes -gt 0) { Optimize-HumanReadable -Size $MaxBytes } Else { $null }
                MaxCapacityBytes = $MaxBytes
                ErrorCorrection  = $Array.MemoryErrorCorrection
            }
        }
    )

    $TotalBytes       = [uint64](($Modules | Measure-Object -Property CapacityBytes -Sum).Sum)
    $SlotCount        = [int](($Arrays | Measure-Object -Property MemoryDevices -Sum).Sum)
    $InstalledCount   = @($Modules).Count
    $EmptyCount       = If ($SlotCount -gt $InstalledCount) { $SlotCount - $InstalledCount } Else { 0 }
    $MaxCapacityBytes = [uint64](($ArrayInventory | Measure-Object -Property MaxCapacityBytes -Sum).Sum)
    $Slots            = @($Modules)

    For ($EmptyIndex = 1; $EmptyIndex -le $EmptyCount; $EmptyIndex++) {
        $Slots += [PSCustomObject][ordered]@{
            Slot          = $InstalledCount + $EmptyIndex
            Status        = 'Empty'
            Bank          = $null
            Locator       = ('Unreported Empty Slot {0}' -f $EmptyIndex)
            Capacity      = $null
            CapacityBytes = [uint64]0
            Type          = $null
            FormFactor    = $null
            TypeDetail    = $null
            SpeedMHz      = $null
            ConfiguredMHz = $null
            Manufacturer  = $null
            PartNumber    = $null
            SerialNumber  = $null
        }
    }

    [PSCustomObject][ordered]@{
        Total                 = If ($TotalBytes -gt 0) { Optimize-HumanReadable -Size $TotalBytes } Else { $null }
        TotalBytes            = $TotalBytes
        InstalledModuleCount  = $InstalledCount
        ReportedLocationCount = $SlotCount
        EmptyLocationCount    = $EmptyCount
        MaxCapacity           = If ($MaxCapacityBytes -gt 0) { Optimize-HumanReadable -Size $MaxCapacityBytes } Else { $null }
        MaxCapacityBytes      = $MaxCapacityBytes
        Arrays                = $ArrayInventory
        Modules               = $Modules
        Slots                 = $Slots
    }
}

Function Get-DiskInventory {
    <#
        .SYNOPSIS
        Collects physical disks, fixed volumes, and disk-to-partition-to-volume correlation.

        .DESCRIPTION
        Uses Win32_DiskDrive as the baseline physical-disk source and enriches it with Get-PhysicalDisk
        data when available. Controller Interface and Storage-module BusType are intentionally retained
        separately because NVMe storage can legitimately appear behind RAID/RST.

        The Layout collection correlates each physical disk to its partitions and associated logical
        drive letters using the Win32_DiskDriveToDiskPartition and Win32_LogicalDiskToPartition
        associations. Partitions without a drive letter are retained rather than silently discarded.

        .EXAMPLE
        Get-DiskInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $StorageDisks = @()
    If (Get-Command -Name Get-PhysicalDisk @script:EA0) {
        Try {
            $StorageDisks = @(Get-PhysicalDisk @script:EA1)
        } Catch {
            Write-Verbose -Message ('Get-PhysicalDisk enrichment unavailable: {0}' -f $_.Exception.Message)
            $StorageDisks = @()
        }
    }

    $RawDisks = @(Get-CimInstance -ClassName Win32_DiskDrive @script:EA0)
    $Disks    = @(
        ForEach ($Disk in $RawDisks) {
            $Serial        = ([string]$Disk.SerialNumber).Trim()
            $StorageMatch  = $null
            $InterfaceHint = [string]$Disk.InterfaceType

            If ($Disk.Model -match '(?i)NVMe') {
                $InterfaceHint = 'NVMe'
            } ElseIf ($Disk.PNPDeviceID -match '(?i)^SCSI\\Disk&Ven_NVMe|^PCI\\.*NVME') {
                $InterfaceHint = 'NVMe'
            }

            If ($StorageDisks.Count -gt 0) {
                $StorageMatch = $StorageDisks | Where-Object {
                    $PhysicalSerial = ([string]$_.SerialNumber).Trim()
                    ($Serial -and $PhysicalSerial -and $PhysicalSerial -eq $Serial) -or
                    ($_.FriendlyName -and $Disk.Model -and ([string]$Disk.Model).Trim() -like "*$([string]$_.FriendlyName)*")
                } | Select-Object -First 1
            }

            [PSCustomObject][ordered]@{
                Index             = $Disk.Index
                DeviceID          = $Disk.DeviceID
                Model             = ([string]$Disk.Model).Trim()
                Manufacturer      = ([string]$Disk.Manufacturer).Trim()
                SerialNumber      = $Serial
                Size              = Optimize-HumanReadable -Size $Disk.Size
                SizeBytes         = [uint64]$Disk.Size
                Interface         = $InterfaceHint
                MediaType         = If ($StorageMatch) { [string]$StorageMatch.MediaType } Else { [string]$Disk.MediaType }
                BusType           = If ($StorageMatch) { [string]$StorageMatch.BusType } Else { $null }
                HealthStatus      = If ($StorageMatch) { [string]$StorageMatch.HealthStatus } Else { $null }
                OperationalStatus = If ($StorageMatch) { ($StorageMatch.OperationalStatus -join ', ') } Else { $Disk.Status }
                FirmwareRevision  = $Disk.FirmwareRevision
                PNPDeviceID       = $Disk.PNPDeviceID
            }
        }
    )

    $Volumes = @(
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' @script:EA0 | ForEach-Object {
            [PSCustomObject][ordered]@{
                Drive              = $_.DeviceID
                Label              = $_.VolumeName
                FileSystem         = $_.FileSystem
                Size               = If ($_.Size) { Optimize-HumanReadable -Size $_.Size } Else { $null }
                Free               = If ($null -ne $_.FreeSpace) { Optimize-HumanReadable -Size $_.FreeSpace } Else { $null }
                FreePercent        = If ($_.Size) { [Math]::Round(([double]$_.FreeSpace / [double]$_.Size) * 100,1) } Else { $null }
                SizeBytes          = If ($_.Size) { [uint64]$_.Size } Else { $null }
                FreeBytes          = If ($null -ne $_.FreeSpace) { [uint64]$_.FreeSpace } Else { $null }
                VolumeSerialNumber = $_.VolumeSerialNumber
            }
        }
    )

    $Layout = @()
    ForEach ($Disk in $RawDisks) {
        Try {
            $Partitions = @(Get-CimAssociatedInstance -InputObject $Disk -Association Win32_DiskDriveToDiskPartition @script:EA1)
        } Catch {
            Write-Verbose -Message ('Unable to correlate partitions for physical disk {0}: {1}' -f $Disk.Index,$_.Exception.Message)
            $Partitions = @()
        }

        ForEach ($Partition in $Partitions) {
            Try {
                $LogicalDisks = @(Get-CimAssociatedInstance -InputObject $Partition -Association Win32_LogicalDiskToPartition @script:EA1)
            } Catch {
                Write-Verbose -Message ('Unable to correlate logical disks for partition "{0}": {1}' -f $Partition.DeviceID,$_.Exception.Message)
                $LogicalDisks = @()
            }

            If ($LogicalDisks.Count -eq 0) {
                $Layout += [PSCustomObject][ordered]@{
                    DiskIndex        = $Disk.Index
                    DiskModel        = ([string]$Disk.Model).Trim()
                    Partition        = $Partition.DeviceID
                    PartitionIndex   = $Partition.Index
                    PartitionSize    = If ($Partition.Size) { Optimize-HumanReadable -Size $Partition.Size } Else { $null }
                    PrimaryPartition = $Partition.PrimaryPartition
                    Drive            = $null
                    Label            = $null
                    FileSystem       = $null
                    VolumeSize       = $null
                    Free             = $null
                    FreePercent      = $null
                }
                Continue
            }

            ForEach ($LogicalDisk in $LogicalDisks) {
                $Layout += [PSCustomObject][ordered]@{
                    DiskIndex        = $Disk.Index
                    DiskModel        = ([string]$Disk.Model).Trim()
                    Partition        = $Partition.DeviceID
                    PartitionIndex   = $Partition.Index
                    PartitionSize    = If ($Partition.Size) { Optimize-HumanReadable -Size $Partition.Size } Else { $null }
                    PrimaryPartition = $Partition.PrimaryPartition
                    Drive            = $LogicalDisk.DeviceID
                    Label            = $LogicalDisk.VolumeName
                    FileSystem       = $LogicalDisk.FileSystem
                    VolumeSize       = If ($LogicalDisk.Size) { Optimize-HumanReadable -Size $LogicalDisk.Size } Else { $null }
                    Free             = If ($null -ne $LogicalDisk.FreeSpace) { Optimize-HumanReadable -Size $LogicalDisk.FreeSpace } Else { $null }
                    FreePercent      = If ($LogicalDisk.Size) { [Math]::Round(([double]$LogicalDisk.FreeSpace / [double]$LogicalDisk.Size) * 100,1) } Else { $null }
                }
            }
        }
    }

    [PSCustomObject][ordered]@{
        Disks   = $Disks
        Volumes = $Volumes
        Layout  = @($Layout | Sort-Object -Property DiskIndex,PartitionIndex,Drive)
    }
}

Function Get-DisplayAdapterInventory {
    <#
        .SYNOPSIS
        Collects Windows display-adapter inventory.

        .DESCRIPTION
        Returns Win32_VideoController devices. The section is intentionally named Display Adapters
        because Windows may expose indirect adapters such as DisplayLink alongside integrated and
        discrete GPUs.

        .EXAMPLE
        Get-DisplayAdapterInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    @(
        Get-CimInstance -ClassName Win32_VideoController @script:EA0 | ForEach-Object {
            [PSCustomObject][ordered]@{
                Name          = $_.Name
                AdapterMemory = If ($_.AdapterRAM) { Optimize-HumanReadable -Size $_.AdapterRAM } Else { $null }
                DriverVersion = $_.DriverVersion
                VideoMode     = ([string]$_.VideoModeDescription) -replace '\b4294967296 colors\b','32-bit color' -replace '\b16777216 colors\b','24-bit color' -replace '\b65536 colors\b','16-bit color'
                Status        = $_.Status
            }
        }
    )
}

Function Get-BatteryInventory {
    <#
        .SYNOPSIS
        Collects battery inventory when batteries are present.

        .DESCRIPTION
        Returns Win32_Battery information and suppresses unrealistic EstimatedRunTime sentinel or
        firmware values. Systems without batteries return an empty collection and therefore omit the
        battery report section.

        .EXAMPLE
        Get-BatteryInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    @(
        Get-CimInstance -ClassName Win32_Battery @script:EA0 | ForEach-Object {
            $Runtime = $null
            If ($null -ne $_.EstimatedRunTime -and [uint64]$_.EstimatedRunTime -gt 0 -and [uint64]$_.EstimatedRunTime -le 10080) {
                $Runtime = [uint64]$_.EstimatedRunTime
            }

            [PSCustomObject][ordered]@{
                Name                    = $_.Name
                DeviceID                = $_.DeviceID
                Status                  = $_.Status
                EstimatedChargePercent  = $_.EstimatedChargeRemaining
                EstimatedRunTimeMinutes = $Runtime
                DesignVoltageMv         = $_.DesignVoltage
            }
        }
    )
}

Function Get-PhysicalNetworkInventory {
    <#
        .SYNOPSIS
        Collects physical Ethernet and wireless adapters with network configuration.

        .DESCRIPTION
        Starts with Win32_NetworkAdapter PhysicalAdapter=True, then requires a physical PCI or USB
        PnP path and Ethernet/Wireless adapter type. This excludes VPN, Hyper-V, VMware, PAN, tunnel,
        and other software adapters that can incorrectly advertise PhysicalAdapter=True.

        Each physical adapter is correlated to Win32_NetworkAdapterConfiguration by adapter index so
        disconnected hardware is still inventoried while configured adapters include IP addresses,
        subnets, gateway, DNS, DHCP, and interface-index details.

        .EXAMPLE
        Get-PhysicalNetworkInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $Configurations = @{}
    Try {
        ForEach ($Config in @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration @script:EA1)) {
            $Configurations[[int]$Config.Index] = $Config
        }
    } Catch {
        Write-Verbose -Message ('Unable to enumerate Win32_NetworkAdapterConfiguration: {0}' -f $_.Exception.Message)
    }

    @(
        Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' @script:EA0 | Where-Object {
            $_.PNPDeviceID -match '^(?i)(PCI|USB)\\' -and $_.AdapterTypeID -in 0,9
        } | ForEach-Object {
            $Adapter = $_
            $Config  = $null
            If ($Configurations.ContainsKey([int]$Adapter.Index)) {
                $Config = $Configurations[[int]$Adapter.Index]
            }

            $AdapterType = If (
                $Adapter.NetConnectionID -match '(?i)Wi-?Fi|Wireless' -or
                $Adapter.Name -match '(?i)Wireless|Wi-?Fi|802\.11|WLAN'
            ) {
                'Wireless'
            } Else {
                'Ethernet'
            }

            $ConnectionStatus = $null
            If ($null -ne $Adapter.NetConnectionStatus) {
                $ConnectionStatus = Get-NetworkConnectionStatusName -Status ([int]$Adapter.NetConnectionStatus)
            }

            $Addresses = @()
            $Subnets   = @()

            If ($Config) {
                $Addresses = @($Config.IPAddress)
                $Subnets   = @($Config.IPSubnet)
            }

            $IPv4 = @($Addresses | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
            $IPv6 = @($Addresses | Where-Object { $_ -match ':' -and $_ -notmatch '^(?i)fe80:' })

            [PSCustomObject][ordered]@{
                Type                 = $AdapterType
                Name                 = $Adapter.Name
                Manufacturer         = $Adapter.Manufacturer
                MACAddress           = If ($Config -and $Config.MACAddress) { $Config.MACAddress } Else { $Adapter.MACAddress }
                LinkGbps             = Convert-SpeedToGbps -BitsPerSecond $Adapter.Speed
                Enabled              = $Adapter.NetEnabled
                Connection           = $Adapter.NetConnectionID
                ConnectionStatus     = $ConnectionStatus
                InterfaceIndex       = If ($Config) { $Config.InterfaceIndex } Else { $Adapter.InterfaceIndex }
                IPv4Address          = If (@($IPv4).Count -gt 0) { $IPv4 -join ', ' } Else { $null }
                IPv6Address          = If (@($IPv6).Count) { $IPv6 -join ', ' } Else { $null }
                Subnet               = If (@($Subnets).Count) { $Subnets -join ', ' } Else { $null }
                DefaultGateway       = If ($Config -and $Config.DefaultIPGateway) { @($Config.DefaultIPGateway) -join ', ' } Else { $null }
                DHCPEnabled          = If ($Config) { $Config.DHCPEnabled } Else { $null }
                DHCPServer           = If ($Config) { $Config.DHCPServer } Else { $null }
                DNSServers           = If ($Config -and $Config.DNSServerSearchOrder) { @($Config.DNSServerSearchOrder) -join ', ' } Else { $null }
                DNSDomain            = If ($Config) { $Config.DNSDomain } Else { $null }
                DNSRegistration      = If ($Config) { $Config.DomainDNSRegistrationEnabled } Else { $null }
                PNPDeviceID          = $Adapter.PNPDeviceID
            }
        } | Sort-Object -Property Type,Name
    )
}

Function Get-MonitorInventory {
    <#
        .SYNOPSIS
        Collects detailed monitor identity, connection, and resolution information.

        .DESCRIPTION
        Uses WmiMonitorID for EDID identity, WmiMonitorConnectionParams for connector technology,
        WmiMonitorListedSupportedSourceModes for preferred/native resolution, and Win32 display APIs
        for current configured resolution and refresh rate. Internal laptop/tablet panels with blank
        friendly names or serials are normalized to Internal Display instead of showing blank/zero
        EDID values.

        .EXAMPLE
        Get-MonitorInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $Results     = @()
    $Connections = @()
    $Modes       = @()
    $Topology    = @(Get-CurrentDisplayTopology)

    Try {
        $Monitors = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID @script:EA1)
    } Catch {
        Write-Verbose -Message ('WmiMonitorID is unavailable: {0}' -f $_.Exception.Message)

        Return @()
    }

    Try {
        $Connections = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams @script:EA1)
    } Catch {
        Write-Verbose -Message ('WmiMonitorConnectionParams is unavailable: {0}' -f $_.Exception.Message)
    }

    Try {
        $Modes = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorListedSupportedSourceModes @script:EA1)
    } Catch {
        Write-Verbose -Message ('WmiMonitorListedSupportedSourceModes is unavailable: {0}' -f $_.Exception.Message)
    }

    ForEach ($Monitor in $Monitors) {
        $ManufacturerCode  = Convert-EdidString -Value $Monitor.ManufacturerName
        $Model             = Convert-EdidString -Value $Monitor.UserFriendlyName
        $Serial            = Convert-EdidString -Value $Monitor.SerialNumberID
        $ProductCode       = Convert-EdidString -Value $Monitor.ProductCodeID
        $Connection        = $Connections | Where-Object {$_.InstanceName -eq $Monitor.InstanceName} | Select-Object -First 1
        $ModeInfo          = $Modes | Where-Object {$_.InstanceName -eq $Monitor.InstanceName} | Select-Object -First 1
        $ConnectionType    = $null
        $NativeResolution  = $null
        $CurrentResolution = $null
        $RefreshRateHz     = $null
        $Primary           = $null

        If ($Connection) {
            $ConnectionType = Get-VideoOutputTechnologyName -Value $Connection.VideoOutputTechnology
        }

        If ($ModeInfo -and $ModeInfo.MonitorSourceModes) {
            Try {
                $PreferredIndex = [int]$ModeInfo.PreferredMonitorSourceModeIndex
                $PreferredMode  = @($ModeInfo.MonitorSourceModes)[$PreferredIndex]
                If ($PreferredMode -and $PreferredMode.HorizontalActivePixels -and $PreferredMode.VerticalActivePixels) {
                    $NativeResolution = ('{0} x {1}' -f $PreferredMode.HorizontalActivePixels,$PreferredMode.VerticalActivePixels)
                }
            } Catch {
                Write-Verbose -Message ('Unable to determine preferred resolution for monitor [{0}]: {1}' -f $Monitor.InstanceName,$_.Exception.Message)
            }
        }

        $ProductToken = $null
        If ($Monitor.InstanceName -match '^DISPLAY\\([^\\]+)\\') {
            $ProductToken = $Matches[1]
        }

        $TopologyMatch = $null
        If ($ProductToken) {
            $TopologyMatch = $Topology | Where-Object {
                $_.MonitorDeviceId -and 
                $_.MonitorDeviceId -match ('(?i){0}' -f [regex]::Escape($ProductToken))
            } | Select-Object -First 1
        }

        If (-not $TopologyMatch -and @($Topology).Count -eq @($Monitors | Where-Object Active).Count -and $Monitor.Active) {
            $ActiveIndex = [array]::IndexOf(@($Monitors | Where-Object Active),$Monitor)
            If ($ActiveIndex -ge 0 -and $ActiveIndex -lt @($Topology).Count) {
                $TopologyMatch = @($Topology)[$ActiveIndex]
            }
        }

        If ($TopologyMatch) {
            If ($TopologyMatch.Width -gt 0 -and $TopologyMatch.Height -gt 0) {
                $CurrentResolution = ('{0} x {1}' -f $TopologyMatch.Width,$TopologyMatch.Height)
            }
            If ($TopologyMatch.Frequency -gt 0) {
                $RefreshRateHz = $TopologyMatch.Frequency
            }
            $Primary = $TopologyMatch.Primary
        }

        If ($Serial -match '^(0+|N/A|None|Unknown)$') {
            $Serial = $null
        }

        $IsInternal = $ConnectionType -match 'Internal Display|Embedded DisplayPort|LVDS'
        If ([string]::IsNullOrWhiteSpace($Model) -and $IsInternal) {
            $Model = 'Internal Display'
        }

        If (
            [string]::IsNullOrWhiteSpace($Model) -and 
            [string]::IsNullOrWhiteSpace($Serial) -and 
            [string]::IsNullOrWhiteSpace($ManufacturerCode)
        ) {
            Continue
        }

        $Results += [PSCustomObject][ordered]@{
            Manufacturer     = Get-MonitorManufacturerName -Code $ManufacturerCode
            Model            = $Model
            SerialNumber     = $Serial
            Connection       = $ConnectionType
            CurrentResolution = $CurrentResolution
            NativeResolution = $NativeResolution
            RefreshRateHz    = $RefreshRateHz
            Primary          = $Primary
            ProductCode      = $ProductCode
            Active           = $Monitor.Active
            ManufacturerCode = $ManufacturerCode
            InstanceName     = $Monitor.InstanceName
        }
    }

    Return @($Results)
}

Function Get-DellDockInventory {
    <#
        .SYNOPSIS
        Collects attached Dell dock inventory using layered discovery.

        .DESCRIPTION
        Prefers Dell Command | Monitor DCIM_Chassis because it can expose Dell dock Service Tag,
        serial, model, and firmware as distinct fields. Falls back to older DCIM_Docked and then
        native Windows USB/PnP descriptor and container correlation. Native USB serials are reported
        as dock serial numbers only and are never promoted to Dell Service Tags.

        Systems with no detected Dell dock return an empty collection so no dock section is shown.

        .EXAMPLE
        Get-DellDockInventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param ()

    $Results = @()
    $Seen    = @{}

    Try {
        $DcimDocks = @(
            Get-CimInstance -Namespace root\dcim\sysman -ClassName DCIM_Chassis @script:EA1 | Where-Object {
                $_.CreationClassName -eq 'DCIM_DockingStation'
            }
        )

        ForEach ($Dock in $DcimDocks) {
            $Model  = If ($Dock.Name) {
                [string]$Dock.Name
            } ElseIf ($Dock.Model) {
                [string]$Dock.Model
            } Else {
                'Dell Dock'
            }

            $Serial = ([string]$Dock.SerialNumber).Trim()
            $Key    = ('{0}|{1}' -f $Model,$Serial)

            If (-not $Seen.ContainsKey($Key)) {
                $Seen[$Key] = $true
                $Results += [PSCustomObject][ordered]@{
                    Manufacturer = 'Dell'
                    Model        = $Model
                    ServiceTag   = ([string]$Dock.Tag).Trim()
                    SerialNumber = $Serial
                    Firmware     = ([string]$Dock.Version).Trim()
                    Source       = 'Dell Command | Monitor (DCIM_Chassis)'
                    InstanceId   = $null
                }
            }
        }
    } Catch {
        Write-Verbose -Message ('Dell Command | Monitor DCIM_Chassis unavailable: {0}' -f $_.Exception.Message)
    }

    If ($Results.Count -eq 0) {
        Try {
            $DockRelations = @(Get-CimInstance -Namespace root\dcim\sysman -ClassName DCIM_Docked @script:EA1)
            ForEach ($Relation in $DockRelations) {
                $DockRef    = $Relation.Antecedent
                $Model      = 'Dell Dock'
                $ServiceTag = $null
                $Serial     = $null

                If ($DockRef) {
                    If ($DockRef.PSObject.Properties.Name -contains 'Name' -and $DockRef.Name) {
                        $Model = [string]$DockRef.Name
                    } ElseIf ($DockRef.PSObject.Properties.Name -contains 'Model' -and $DockRef.Model) {
                        $Model = [string]$DockRef.Model
                    }

                    If ($DockRef.PSObject.Properties.Name -contains 'Tag') {
                        $ServiceTag = ([string]$DockRef.Tag).Trim()
                    }

                    If ($DockRef.PSObject.Properties.Name -contains 'SerialNumber') {
                        $Serial = ([string]$DockRef.SerialNumber).Trim()
                    }
                }

                If (-not $Serial -and $Relation.PSObject.Properties.Name -contains 'SerialNumber') {
                    $Serial = ([string]$Relation.SerialNumber).Trim()
                }

                $Key = ('{0}|{1}|{2}' -f $Model,$Serial,$ServiceTag)
                If (-not $Seen.ContainsKey($Key)) {
                    $Seen[$Key] = $true
                    $Results += [PSCustomObject][ordered]@{
                        Manufacturer = 'Dell'
                        Model        = $Model
                        ServiceTag   = $ServiceTag
                        SerialNumber = $Serial
                        Firmware     = $null
                        Source       = 'Dell Command | Monitor (DCIM_Docked)'
                        InstanceId   = $null
                    }
                }
            }
        } Catch {
            Write-Verbose -Message ('Dell Command | Monitor DCIM_Docked unavailable: {0}' -f $_.Exception.Message)
        }
    }

    If (
        $Results.Count -eq 0 -and 
        (Get-Command -Name Get-PnpDevice @script:EA0) -and 
        (Get-Command -Name Get-PnpDeviceProperty @script:EA0)
    ) {
        Try {
            $UsbParents = @(
                Get-PnpDevice -PresentOnly -Class USB @script:EA1 | Where-Object {
                    $_.InstanceId -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\[^&\\]+$'
                }
            )

            ForEach ($Device in $UsbParents) {
                $BusName = $null
                Try {
                    $BusName = (Get-PnpDeviceProperty -InstanceId $Device.InstanceId -KeyName DEVPKEY_Device_BusReportedDeviceDesc @script:EA1).Data
                } Catch {
                    Write-Verbose -Message ('Unable to read bus-reported description for [{0}]: {1}' -f $Device.InstanceId,$_.Exception.Message)
                }

                If ($BusName -notmatch '(?i)(Dell.*Dock|Dock.*Dell)') {
                    Continue
                }

                $Serial = ($Device.InstanceId -split '\\')[-1]
                $Key    = ('{0}|{1}' -f $BusName,$Serial)

                If (-not $Seen.ContainsKey($Key)) {
                    $Seen[$Key] = $true
                    $Results += [PSCustomObject][ordered]@{
                        Manufacturer = 'Dell'
                        Model        = [string]$BusName
                        ServiceTag   = $null
                        SerialNumber = $Serial
                        Firmware     = $null
                        Source       = 'Windows USB/PnP descriptor'
                        InstanceId   = $Device.InstanceId
                    }
                }
            }
        } Catch {
            Write-Verbose -Message ('Native USB/PnP dock discovery failed: {0}' -f $_.Exception.Message)
        }
    }

    If (
        $Results.Count -eq 0 -and 
        (Get-Command -Name Get-PnpDevice @script:EA0) -and 
        (Get-Command -Name Get-PnpDeviceProperty @script:EA0)
    ) {
        Try {
            $DockDevices = @(
                Get-PnpDevice -PresentOnly @script:EA1 | Where-Object {
                    $_.FriendlyName -match '(?i)(Dell.*Dock|Dock.*Dell)'
                }
            )
            $UsbParents = @(
                Get-PnpDevice -PresentOnly -Class USB @script:EA1 | Where-Object {
                    $_.InstanceId -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\[^&\\]+$'
                }
            )

            ForEach ($DockDevice in $DockDevices) {
                $ContainerId = $null
                Try {
                    $ContainerId = (Get-PnpDeviceProperty -InstanceId $DockDevice.InstanceId -KeyName DEVPKEY_Device_ContainerId @script:EA1).Data
                } Catch {
                    Write-Verbose -Message ('Unable to read dock container ID for [{0}]: {1}' -f $DockDevice.InstanceId,$_.Exception.Message)
                }

                If ($null -eq $ContainerId) {
                    Continue
                }

                ForEach ($Parent in $UsbParents) {
                    $ParentContainer = $null
                    Try {
                        $ParentContainer = (Get-PnpDeviceProperty -InstanceId $Parent.InstanceId -KeyName DEVPKEY_Device_ContainerId @script:EA1).Data
                    } Catch {
                        Write-Verbose -Message ('Unable to read parent container ID for [{0}]: {1}' -f $Parent.InstanceId,$_.Exception.Message)
                    }

                    If ($ParentContainer -ne $ContainerId) {
                        Continue
                    }

                    $Serial = ($Parent.InstanceId -split '\\')[-1]
                    $Model  = [string]$DockDevice.FriendlyName
                    $Key    = ('{0}|{1}' -f $Model,$Serial)

                    If (-not $Seen.ContainsKey($Key)) {
                        $Seen[$Key] = $true
                        $Results += [PSCustomObject][ordered]@{
                            Manufacturer = 'Dell'
                            Model        = $Model
                            ServiceTag   = $null
                            SerialNumber = $Serial
                            Firmware     = $null
                            Source       = 'Windows PnP container correlation'
                            InstanceId   = $Parent.InstanceId
                        }
                    }
                }
            }
        } Catch {
            Write-Verbose -Message ('PnP container dock correlation failed: {0}' -f $_.Exception.Message)
        }
    }

    Return @($Results)
}

Function Get-PrinterInventory {
    <#
        .SYNOPSIS
        Collects detailed information about real printers installed on the local computer.

        .DESCRIPTION
        Collects detailed local printer inventory using Win32_Printer, Win32_PrinterDriver,
        Win32_TCPIPPrinterPort, and Windows PnP data where available.

        Both physically attached printers and network printers are included.

        Printer connections are classified as USB, DOT4, Parallel, Serial, TCP/IP, WSD,
        Network Share, Network, or Other.

        TCP/IP printers include configured address, TCP port, RAW/LPR protocol, LPR queue,
        and SNMP configuration where available.

        Locally attached PnP printers are correlated to their Windows device hierarchy when
        possible to identify the physical manufacturer, model, device identifier, and
        USB-reported serial number.

        Printer drivers are correlated to Win32_PrinterDriver. Vendor-owned driver files are
        preferred when determining driver version so that a Microsoft rendering component such
        as unidrv.dll is not incorrectly reported as the printer manufacturer's driver version.

        Common software/virtual printers including Microsoft, Adobe, OneNote, Fax, XPS,
        Print to PDF, and similar queues are excluded.

        .OUTPUTS
        PSCustomObject

        .EXAMPLE
        Get-PrinterInventory

        Returns all real printers configured on the local computer.

        .EXAMPLE
        Get-PrinterInventory -Verbose

        Returns printer inventory and displays verbose information about optional driver,
        port, and PnP correlation failures.

        .NOTES
        Author       : James Stephens
        Target       : Windows PowerShell 5.1
        Function     : Printer hardware and queue inventory
    #>
    [CmdletBinding()]
    Param ()

    Begin {
        #region Functions
        Function Get-PrinterStatusName {
            <#
                .SYNOPSIS
                Converts PrinterStatus to readable text.

                .DESCRIPTION
                Converts a numeric Win32_Printer PrinterStatus value into a readable status.

                .PARAMETER Value
                Numeric Win32_Printer PrinterStatus value.

                .OUTPUTS
                String

                .EXAMPLE
                Get-PrinterStatusName -Value 3

                Returns Idle.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Numeric Win32_Printer PrinterStatus value.')]
                [int]$Value
            )

            Switch ($Value) {
                1 {'Other'}
                2 {'Unknown'}
                3 {'Idle'}
                4 {'Printing'}
                5 {'Warming Up'}
                6 {'Stopped Printing'}
                7 {'Offline'}
                Default {('Status {0}' -f $Value)}
            }
        }

        Function Get-ExtendedPrinterStatusName {
            <#
                .SYNOPSIS
                Converts ExtendedPrinterStatus to readable text.

                .DESCRIPTION
                Converts a numeric Win32_Printer ExtendedPrinterStatus value into a
                readable status.

                .PARAMETER Value
                Numeric Win32_Printer ExtendedPrinterStatus value.

                .OUTPUTS
                String

                .EXAMPLE
                Get-ExtendedPrinterStatusName -Value 7

                Returns Offline.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Numeric Win32_Printer ExtendedPrinterStatus value.')]
                [int]$Value
            )

            Switch ($Value) {
                1  {'Other'}
                2  {'Unknown'}
                3  {'Idle'}
                4  {'Printing'}
                5  {'Warming Up'}
                6  {'Stopped Printing'}
                7  {'Offline'}
                8  {'Paused'}
                9  {'Error'}
                10 {'Busy'}
                11 {'Not Available'}
                12 {'Waiting'}
                13 {'Processing'}
                14 {'Initialization'}
                15 {'Power Save'}
                16 {'Pending Deletion'}
                17 {'I/O Active'}
                18 {'Manual Feed'}
                Default {('Status {0}' -f $Value)}
            }
        }

        Function Get-PrinterErrorStateName {
            <#
                .SYNOPSIS
                Converts a printer error-state value to readable text.

                .DESCRIPTION
                Converts Win32_Printer DetectedErrorState or ExtendedDetectedErrorState
                values into readable descriptions.

                .PARAMETER Value
                Numeric printer error-state value.

                .OUTPUTS
                String

                .EXAMPLE
                Get-PrinterErrorStateName -Value 8

                Returns Jammed.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Numeric detected printer error-state value.')]
                [int]$Value
            )

            Switch ($Value) {
                0  {'Unknown'}
                1  {'Other'}
                2  {'No Error'}
                3  {'Low Paper'}
                4  {'No Paper'}
                5  {'Low Toner'}
                6  {'No Toner'}
                7  {'Door Open'}
                8  {'Jammed'}
                9  {'Offline'}
                10 {'Service Requested'}
                11 {'Output Bin Full'}
                12 {'Paper Problem'}
                13 {'Cannot Print Page'}
                14 {'User Intervention Required'}
                15 {'Out of Memory'}
                Default {('ErrorState {0}' -f $Value)}
            }
        }

        Function Get-PrinterConnectionType {
            <#
                .SYNOPSIS
                Determines the connection type for an installed printer.

                .DESCRIPTION
                Classifies a printer using its configured port, PnP identifier,
                network flag, and known TCP/IP printer-port inventory.

                .PARAMETER Printer
                Win32_Printer instance to classify.

                .PARAMETER TcpPorts
                Win32_TCPIPPrinterPort instances available on the local computer.

                .OUTPUTS
                String

                .EXAMPLE
                Get-PrinterConnectionType -Printer $Printer -TcpPorts $TcpPorts

                Returns USB, TCP/IP, WSD, Network Share, or another recognized type.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Win32_Printer instance to classify.')]
                [object]$Printer,

                [Parameter(Mandatory, HelpMessage = 'Collection of Win32_TCPIPPrinterPort instances used to identify TCP/IP printer ports.')]
                [AllowEmptyCollection()]
                [object[]]$TcpPorts
            )

            $PortName    = [string]$Printer.PortName
            $PNPDeviceID = [string]$Printer.PNPDeviceID

            If ($PNPDeviceID -match '^(?i)USBPRINT\\|USB\\') {
                Return 'USB'
            }

            If ($TcpPorts | Where-Object {$_.Name -eq $PortName} | Select-Object -First 1) {
                Return 'TCP/IP'
            }

            Switch -Regex ($PortName) {
                '^(?i)USB\d+$'                {Return 'USB'}
                '^(?i)DOT4'                   {Return 'DOT4'}
                '^(?i)LPT\d*:?$'              {Return 'Parallel'}
                '^(?i)COM\d*:?$'              {Return 'Serial'}
                '^(?i)WSD-'                   {Return 'WSD'}
                '^(?i)IP_'                    {Return 'TCP/IP'}
                '^(?i)\d{1,3}(\.\d{1,3}){3}$' {Return 'TCP/IP'}
                '^\\\\[^\\]+\\[^\\]+'         {Return 'Network Share'}
            }

            If ([string]$Printer.Name -match '^\\\\[^\\]+\\[^\\]+') {
                Return 'Network Share'
            }

            If ($Printer.Network) {
                Return 'Network'
            }

            Return 'Other'
        }

        Function Get-PrinterQueueType {
            <#
                .SYNOPSIS
                Converts a printer connection type into a high-level queue classification.

                .DESCRIPTION
                Classifies a printer as locally attached, network TCP/IP, network WSD,
                network share, network, or other.

                .PARAMETER ConnectionType
                Connection type returned by Get-PrinterConnectionType.

                .OUTPUTS
                String

                .EXAMPLE
                Get-PrinterQueueType -ConnectionType 'TCP/IP'

                Returns Network TCP/IP.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Printer connection type to classify.')]
                [string]$ConnectionType
            )

            Switch ($ConnectionType) {
                'USB'           {'Local Physical'}
                'DOT4'          {'Local Physical'}
                'Parallel'      {'Local Physical'}
                'Serial'        {'Local Physical'}
                'TCP/IP'        {'Network TCP/IP'}
                'WSD'           {'Network WSD'}
                'Network Share' {'Network Share'}
                'Network'       {'Network'}
                Default         {'Other'}
            }
        }

        Function Get-PnpPrinterIdentity {
            <#
                .SYNOPSIS
                Retrieves physical PnP identity for a printer.

                .DESCRIPTION
                Correlates a printer PnP instance to Windows PnP information.

                When Get-PnpDeviceProperty is available, the device hierarchy is followed toward
                its physical USB parent. A USB descriptor serial is returned when Windows exposes
                a serial-bearing USB parent instance.

                .PARAMETER PNPDeviceID
                PnP device identifier associated with the printer.

                .OUTPUTS
                PSCustomObject

                .EXAMPLE
                Get-PnpPrinterIdentity -PNPDeviceID 'USBPRINT\HP...'

                Returns manufacturer, model, serial, device ID, and physical USB parent where found.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Printer PnP device identifier to correlate with Windows PnP inventory.')]
                [string]$PNPDeviceID
            )

            $Manufacturer = $null
            $Model        = $null
            $SerialNumber = $null
            $BusName      = $null
            $DeviceID     = $PNPDeviceID
            $UsbParentID  = $null

            Try {
                $EscapedPNPDeviceID = $PNPDeviceID.Replace('\','\\').Replace("'","''")
                $PnPEntity = Get-CimInstance -ClassName Win32_PnPEntity -Filter "DeviceID='$EscapedPNPDeviceID'" @script:EA1 | Select-Object -First 1

                If ($PnPEntity) {
                    $Manufacturer = ([string]$PnPEntity.Manufacturer).Trim()
                    $Model        = ([string]$PnPEntity.Name).Trim()
                    $DeviceID     = [string]$PnPEntity.DeviceID
                }
            } Catch {
                Write-Verbose -Message ('Win32_PnPEntity correlation failed for "{0}": {1}' -f $PNPDeviceID,$_.Exception.Message)
            }

            If (Get-Command -Name Get-PnpDeviceProperty @script:EA0) {
                Try {
                    $BusName = (Get-PnpDeviceProperty -InstanceId $PNPDeviceID -KeyName DEVPKEY_Device_BusReportedDeviceDesc @script:EA1).Data
                } Catch {
                    Write-Verbose -Message ('Bus-reported printer description unavailable for "{0}": {1}' -f $PNPDeviceID,$_.Exception.Message)
                }

                $CurrentID = $PNPDeviceID

                For ($i = 0; $i -lt 8 -and $CurrentID; $i++) {
                    If ($CurrentID -match '^(?i)USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\([^&\\]+)$') {
                        $SerialNumber = $Matches[1]
                        $UsbParentID  = $CurrentID
                        Break
                    }

                    Try {
                        $ParentID = (Get-PnpDeviceProperty -InstanceId $CurrentID -KeyName DEVPKEY_Device_Parent @script:EA1).Data
                    } Catch {
                        Write-Verbose -Message ('Unable to obtain PnP parent for "{0}": {1}' -f $CurrentID,$_.Exception.Message)
                        Break
                    }

                    If ([string]::IsNullOrWhiteSpace([string]$ParentID) -or $ParentID -eq $CurrentID) {
                        Break
                    }

                    $CurrentID = [string]$ParentID
                }

                If ($UsbParentID) {
                    Try {
                        $ParentBusName = (Get-PnpDeviceProperty -InstanceId $UsbParentID -KeyName DEVPKEY_Device_BusReportedDeviceDesc @script:EA1).Data
                        If ($ParentBusName) {
                            $BusName = $ParentBusName
                        }
                    } Catch {
                        Write-Verbose -Message ('Unable to read bus-reported description from USB parent "{0}": {1}' -f $UsbParentID,$_.Exception.Message)
                    }
                }
            }

            [PSCustomObject][ordered]@{
                Manufacturer = $Manufacturer
                Model        = If ($BusName) {[string]$BusName} Else {$Model}
                SerialNumber = $SerialNumber
                DeviceID     = $DeviceID
                UsbParentID  = $UsbParentID
            }
        }

        Function Get-PrinterDriverInventory {
            <#
                .SYNOPSIS
                Resolves printer driver inventory information.

                .DESCRIPTION
                Correlates a Win32_Printer DriverName to Win32_PrinterDriver and determines
                the most meaningful vendor driver file and version.

                Vendor-owned configuration, data, and dependent files are checked before the
                generic DriverPath so Microsoft rendering components such as unidrv.dll do not
                incorrectly become the reported vendor driver version.

                .PARAMETER Printer
                Win32_Printer instance whose driver should be resolved.

                .PARAMETER Drivers
                Collection of Win32_PrinterDriver instances.

                .OUTPUTS
                PSCustomObject

                .EXAMPLE
                Get-PrinterDriverInventory -Printer $Printer -Drivers $Drivers

                Returns driver file, version, vendor, type, platform, and monitor information.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Win32_Printer instance whose driver information should be resolved.')]
                [object]$Printer,

                [Parameter(Mandatory, HelpMessage = 'Collection of Win32_PrinterDriver instances available on the computer.')]
                [AllowEmptyCollection()]
                [object[]]$Drivers
            )

            $Driver = $Drivers | Where-Object {
                $_.Name -like "*$($Printer.DriverName)*"
            } | Select-Object -First 1

            If (-not $Driver) {
                Return [PSCustomObject][ordered]@{
                    Name        = $Printer.DriverName
                    Vendor      = $null
                    Version     = $null
                    File        = $null
                    Type        = $null
                    Platform    = $null
                    MonitorName = $null
                    ConfigFile  = $null
                    DataFile    = $null
                    DriverPath  = $null
                }
            }

            $DriverFile    = $null
            $DriverVersion = $null
            $DriverVendor  = $null

            $DriverCandidates = @(
                $Driver.ConfigFile
                $Driver.DataFile
                @($Driver.DependentFiles)
                $Driver.DriverPath
            ) | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_) -and
                (Test-Path -LiteralPath $_)
            } | Select-Object -Unique

            ForEach ($DriverCandidate in $DriverCandidates) {
                Try {
                    $VersionInfo = (Get-Item -LiteralPath $DriverCandidate @script:EA1).VersionInfo

                    If (
                        $VersionInfo.CompanyName -and
                        $VersionInfo.CompanyName -notmatch '^(?i)Microsoft'
                    ) {
                        $DriverFile    = Split-Path -Path $DriverCandidate -Leaf
                        $DriverVendor  = ([string]$VersionInfo.CompanyName).Trim()
                        $DriverVersion = ([string]$VersionInfo.ProductVersion).Trim()

                        If ([string]::IsNullOrWhiteSpace($DriverVersion)) {
                            $DriverVersion = ([string]$VersionInfo.FileVersion).Trim()
                        }

                        Break
                    }
                } Catch {
                    Write-Verbose -Message ('Unable to inspect printer driver file "{0}": {1}' -f $DriverCandidate,$_.Exception.Message)
                }
            }

            If (-not $DriverFile -and $Driver.DriverPath) {
                $DriverFile = Split-Path -Path $Driver.DriverPath -Leaf

                Try {
                    $VersionInfo   = (Get-Item -LiteralPath $Driver.DriverPath @script:EA1).VersionInfo
                    $DriverVersion = ([string]$VersionInfo.ProductVersion).Trim()
                    $DriverVendor  = ([string]$VersionInfo.CompanyName).Trim()
                } Catch {
                    Write-Verbose -Message ('Unable to read fallback printer driver version from "{0}": {1}' -f $Driver.DriverPath,$_.Exception.Message)
                }
            }

            [PSCustomObject][ordered]@{
                Name        = $Printer.DriverName
                Vendor      = $DriverVendor
                Version     = $DriverVersion
                File        = $DriverFile
                Type        = $Driver.Version
                Platform    = $Driver.SupportedPlatform
                MonitorName = $Driver.MonitorName
                ConfigFile  = $Driver.ConfigFile
                DataFile    = $Driver.DataFile
                DriverPath  = $Driver.DriverPath
            }
        }

        Function Get-NetworkPrinterPortInventory {
            <#
                .SYNOPSIS
                Retrieves configured TCP/IP printer-port details.

                .DESCRIPTION
                Correlates a printer to Win32_TCPIPPrinterPort and returns its configured
                destination, port, protocol, queue, and SNMP settings.

                .PARAMETER Printer
                Win32_Printer instance whose network port should be resolved.

                .PARAMETER TcpPorts
                Collection of Win32_TCPIPPrinterPort instances.

                .OUTPUTS
                PSCustomObject

                .EXAMPLE
                Get-NetworkPrinterPortInventory -Printer $Printer -TcpPorts $TcpPorts

                Returns TCP/IP printer-port configuration when present.
            #>
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory, HelpMessage = 'Win32_Printer instance whose TCP/IP port should be resolved.')]
                [object]$Printer,

                [Parameter(Mandatory, HelpMessage = 'Collection of Win32_TCPIPPrinterPort instances available on the computer.')]
                [AllowEmptyCollection()]
                [object[]]$TcpPorts
            )

            $TcpPort = $TcpPorts | Where-Object {
                $_.Name -eq $Printer.PortName
            } | Select-Object -First 1

            If (-not $TcpPort) {
                Return [PSCustomObject][ordered]@{
                    Address         = $null
                    Port            = $null
                    Protocol        = $null
                    Queue           = $null
                    SNMPEnabled     = $null
                    SNMPCommunity   = $null
                    SNMPDeviceIndex = $null
                }
            }

            $Protocol = Switch ([int]$TcpPort.Protocol) {
                1 {'RAW'}
                2 {'LPR'}
                Default {('Protocol {0}' -f $TcpPort.Protocol)}
            }

            [PSCustomObject][ordered]@{
                Address         = $TcpPort.HostAddress
                Port            = $TcpPort.PortNumber
                Protocol        = $Protocol
                Queue           = $TcpPort.Queue
                SNMPEnabled     = $TcpPort.SNMPEnabled
                SNMPCommunity   = $TcpPort.SNMPCommunity
                SNMPDeviceIndex = $TcpPort.SNMPDevIndex
            }
        }
        #endregion Functions
    }

    Process {
        $Results = @()

        Try {
            $Printers = @(
                Get-CimInstance -ClassName Win32_Printer @script:EA1 | Where-Object {
                    $_.Name       -notmatch '^(?i)(Microsoft|Adobe|OneNote|Fax)' -and
                    $_.DriverName -notmatch '^(?i)(Microsoft|Adobe|OneNote)' -and
                    $_.Name       -notmatch '(?i)XPS|Print to PDF|PDF Writer|PDFCreator'
                }
            )
        } Catch {
            Write-Warning -Message ('Unable to query Win32_Printer: {0}' -f $_.Exception.Message)
            Return
        }

        Try {
            $Drivers = @(Get-CimInstance -ClassName Win32_PrinterDriver @script:EA1)
        } Catch {
            Write-Verbose -Message ('Unable to query Win32_PrinterDriver: {0}' -f $_.Exception.Message)
            $Drivers = @()
        }

        Try {
            $TcpPorts = @(Get-CimInstance -ClassName Win32_TCPIPPrinterPort @script:EA1)
        } Catch {
            Write-Verbose -Message ('Unable to query Win32_TCPIPPrinterPort: {0}' -f $_.Exception.Message)
            $TcpPorts = @()
        }

        ForEach ($Printer in $Printers) {
            $ConnectionType = Get-PrinterConnectionType -Printer $Printer -TcpPorts $TcpPorts
            $QueueType      = Get-PrinterQueueType -ConnectionType $ConnectionType
            $Driver         = Get-PrinterDriverInventory -Printer $Printer -Drivers $Drivers
            $NetworkPort    = Get-NetworkPrinterPortInventory -Printer $Printer -TcpPorts $TcpPorts

            $PnpIdentity = $null

            If (-not [string]::IsNullOrWhiteSpace([string]$Printer.PNPDeviceID)) {
                Try {
                    $PnpIdentity = Get-PnpPrinterIdentity -PNPDeviceID $Printer.PNPDeviceID
                } Catch {
                    Write-Verbose -Message ('PnP printer identity correlation failed for "{0}": {1}' -f $Printer.Name,$_.Exception.Message)
                }
            }

            $RemoteServer = $null
            $RemoteShare  = $null

            $UncValue     = @(
                [string]$Printer.PortName
                [string]$Printer.Name
            ) | Where-Object {
                $_ -match '^\\\\([^\\]+)\\([^\\]+)'
            } | Select-Object -First 1

            If ($UncValue -and $UncValue -match '^\\\\([^\\]+)\\([^\\]+)') {
                $RemoteServer = $Matches[1]
                $RemoteShare  = $Matches[2]
            }

            $PrinterStatus = $null
            If ($null -ne $Printer.PrinterStatus) {
                $PrinterStatus = Get-PrinterStatusName -Value ([int]$Printer.PrinterStatus)
            }

            $ExtendedPrinterStatus = $null
            If ($null -ne $Printer.ExtendedPrinterStatus) {
                $ExtendedPrinterStatus = Get-ExtendedPrinterStatusName -Value ([int]$Printer.ExtendedPrinterStatus)
            }

            $DetectedErrorState = $null
            If ($null -ne $Printer.DetectedErrorState) {
                $DetectedErrorState = Get-PrinterErrorStateName -Value ([int]$Printer.DetectedErrorState)
            }

            $ExtendedDetectedErrorState = $null
            If ($null -ne $Printer.ExtendedDetectedErrorState) {
                $ExtendedDetectedErrorState = Get-PrinterErrorStateName -Value ([int]$Printer.ExtendedDetectedErrorState)
            }

            $Manufacturer = $null
            If ($PnpIdentity -and $PnpIdentity.Manufacturer) {
                $Manufacturer = $PnpIdentity.Manufacturer
            } ElseIf ($Driver.Vendor) {
                $Manufacturer = $Driver.Vendor
            }

            $Model = $null
            If ($PnpIdentity -and $PnpIdentity.Model) {
                $Model = $PnpIdentity.Model
            }

            $Results += [PSCustomObject][ordered]@{
                Name                       = $Printer.Name
                QueueType                  = $QueueType
                Connection                 = $ConnectionType

                Manufacturer               = $Manufacturer
                Model                      = $Model
                SerialNumber               = If ($PnpIdentity) {$PnpIdentity.SerialNumber} Else {$null}

                PortName                   = $Printer.PortName
                PrinterAddress             = $NetworkPort.Address
                PrinterPort                = $NetworkPort.Port
                PrinterProtocol            = $NetworkPort.Protocol
                PrinterQueue               = $NetworkPort.Queue

                RemoteServer               = $RemoteServer
                RemoteShare                = $RemoteShare

                SNMPEnabled                = $NetworkPort.SNMPEnabled
                SNMPCommunity              = $NetworkPort.SNMPCommunity
                SNMPDeviceIndex            = $NetworkPort.SNMPDeviceIndex

                DriverName                 = $Driver.Name
                DriverVendor               = $Driver.Vendor
                DriverVersion              = $Driver.Version
                DriverFile                 = $Driver.File
                DriverType                 = $Driver.Type
                DriverPlatform             = $Driver.Platform
                PrintMonitor               = $Driver.MonitorName

                Status                     = $Printer.Status
                PrinterStatus              = $PrinterStatus
                ExtendedPrinterStatus      = $ExtendedPrinterStatus
                DetectedErrorState         = $DetectedErrorState
                ExtendedDetectedErrorState = $ExtendedDetectedErrorState

                HorizontalResolution       = $Printer.HorizontalResolution
                VerticalResolution         = $Printer.VerticalResolution

                Default                    = $Printer.Default
                Shared                     = $Printer.Shared
                ShareName                  = $Printer.ShareName
                Published                  = $Printer.Published
                SpoolEnabled               = $Printer.SpoolEnabled
                WorkOffline                = $Printer.WorkOffline
                JobCountSinceLastReset     = $Printer.JobCountSinceLastReset

                Location                   = $Printer.Location
                Comment                    = $Printer.Comment

                PNPDeviceID                = $Printer.PNPDeviceID
                DeviceID                   = If ($PnpIdentity) {$PnpIdentity.DeviceID} Else {$null}
                UsbParentID                = If ($PnpIdentity) {$PnpIdentity.UsbParentID} Else {$null}
            }
        }

        Return @($Results | Sort-Object -Property QueueType, Name)
    }
}

Function Get-SystemResponsibilityInventory {
    <#
        .SYNOPSIS
        Inventories what a physical computer is responsible for, plus its security and readiness posture.

        .DESCRIPTION
        Collects local workstation or server information into a structured PSCustomObject.
        Supports Windows 11 and Windows Server with Windows PowerShell 5.1.
        Self-contained: uses only what Windows itself provides (inbox cmdlets, CIM/WMI providers,
        the registry, configuration files, .NET Framework classes and Win32 APIs compiled with
        Add-Type). It never depends on optional management modules (RSAT ActiveDirectory,
        DnsServer, DhcpServer, FailoverClusters, WebAdministration) or third-party tools.
        Role-specific queries run only when the role's service is present.

        Failures in individual categories are recorded in CollectionErrors and never stop the
        rest of the collection. Unsupported or unrequested categories are $null.

        Two derived collections drive the report:
          - Roles   : what the machine does (DC, DNS, DHCP, Hyper-V, file/print, IIS, SQL, ...).
          - Posture : readiness checks (pending reboot, Secure Boot, TPM, BitLocker, firewall,
                      time source, uptime, elevation, collection gaps), each with a status of
                      OK, Warning, Critical or Neutral.

        The function writes no formatted screen output, files or email. Sensitive material such
        as product keys, passwords and BitLocker recovery keys is deliberately excluded.

        .PARAMETER IncludeLogs
        Includes recent System and Application critical/error events.

        .PARAMETER LogCount
        Maximum number of events read per event log. Defaults to 100.

        .PARAMETER IncludeShareACL
        Includes share and root-folder NTFS permissions for nonadministrative SMB shares.

        .PARAMETER IncludeUpdates
        Includes installed hotfix records returned by Get-HotFix.

        .PARAMETER IncludeSoftware
        Includes installed software from machine-wide uninstall registry entries.

        .PARAMETER IncludeTasks
        Includes local scheduled task definitions and state. Non-Microsoft tasks are enriched
        with run-as account, last run time and last result.

        .PARAMETER IncludeCapabilities
        Includes installed Windows capabilities on workstations. This query can take 10-30
        seconds, so it is off unless requested.

        .EXAMPLE
        $R = Get-SystemResponsibilityInventory -IncludeLogs -IncludeSoftware -IncludeTasks -IncludeUpdates -IncludeShareACL

        .OUTPUTS
        System.Management.Automation.PSCustomObject

        .NOTES
        Requires Windows PowerShell 5.1. Elevation is strongly recommended; without it TPM,
        BitLocker, Secure Boot, optional features and some role data are reported as unknown.
        Queries the local computer only. Does not change system configuration.
    #>
    [CmdletBinding()]
    Param (
        [switch]$IncludeLogs,

        [ValidateRange(1,1000)]
        [int]$LogCount = 100,

        [switch]$IncludeShareACL,

        [switch]$IncludeUpdates,

        [switch]$IncludeSoftware,

        [switch]$IncludeTasks,

        [switch]$IncludeCapabilities
    )

    #region Collection Helpers
    $CollectionErrors = New-Object -TypeName 'System.Collections.Generic.List[object]'
    <#
        LESSON 1: Scriptblocks as private helper functions
        $Name = { Param (...) ... } stores code in a variable, and & $Name arg1 arg2 runs it. The
        helpers below ($AddError, $Collect, $Available, $Prop, $Plural) work like small functions
        but stay private to this function: they cannot collide with command names elsewhere, and
        because they are values they can be passed to other code. $Collect receives a scriptblock
        as its $Action parameter and runs it.
    #>
    $CollectedAt      = Get-Date

    $AddError      = {
        <#
            LESSON 2: What a scriptblock can change in its caller
            & runs a scriptblock in a child scope. It can READ the caller's variables, but
            assigning to one ($Count = 5) creates a local copy that disappears when the scriptblock
            ends. Calling a METHOD on the caller's object is different: $CollectionErrors.Add(...)
            changes the one shared List, so the entry is still there afterwards. That is why errors
            are added to a List rather than collected with $Errors += $Item.
        #>
        Param ([string]$Category,[object]$ErrorRecord)

        $Message = If ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception.Message } Else { [string]$ErrorRecord }
        $Type    = If ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception.GetType().FullName } Else { $null }

        $CollectionErrors.Add(
            [pscustomobject][ordered]@{
                Category = $Category
                Error    = $Message
                Type     = $Type
            }
        )

        Write-Verbose -Message ('{0}: {1}' -f $Category,$Message)
    }

    $Collect       = {
        <#
            LESSON 3: Record the error and carry on
            An inventory should report what it can. Every category runs through $Collect: if the
            scriptblock fails, the error is recorded under that category name, $Collect returns $null,
            and collection continues. The script's 'Stop' preference turns every error into a
            terminating one, so this single Try/Catch catches them all. The recorded errors become the
            report's Collection Gaps table.
        #>
        Param ([string]$Category,[scriptblock]$Action)

        Try {
            & $Action
        } Catch {
            & $AddError $Category $_
            $null
        }
    }

    $Available     = {
        <#
            LESSON 4: Check for a feature, not an OS version
            Get-Command returns nothing, without an error, when a command does not exist. Casting the
            result to [bool] gives $true or $false. Asking "is Get-Tpm available?" is more reliable
            than guessing from the Windows version, because roles, editions and installed modules all
            affect which commands exist.
        #>
        Param ([string]$Command)
        [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
    }

    $ServiceExists = {
        Param ([string]$Service)

        [bool](Get-Service -Name $Service -ErrorAction SilentlyContinue)
    }

    <#
        LESSON 5: Reading a property that might not exist
        Under Set-StrictMode, reading a missing property throws. PSObject.Properties['Name']
        returns $null instead, so $Prop can test first and read second. Hashtable keys are not
        properties, so dictionaries are checked separately with Contains.
    #>
    $Prop          = {
        Param ([object]$Object,[string]$Name)

        If ($null -eq $Object) {
            Return $null
        }

        If ($Object -is [System.Collections.IDictionary]) {
            If ($Object.Contains($Name)) {
                Return $Object[$Name]
            }
            Return $null
        }

        $Property = $Object.PSObject.Properties[$Name]
        If ($Property) {
            Return $Property.Value
        }

        Return $null
    }

    $ToGB          = {
        Param ([object]$Bytes)

        If ($null -eq $Bytes -or [string]$Bytes -eq '') {
            Return $null
        }

        [math]::Round(([double]$Bytes / 1GB),1)
    }

    $Plural        = {
        Param ([int]$Count,[string]$Singular,[string]$PluralForm)

        If (-not $PluralForm) {
            $PluralForm = If ($Singular -match '(s|x|ch|sh)$') {
                $Singular + 'es'
            } ElseIf ($Singular -match '[^aeiou]y$') {
                $Singular.Substring(0,$Singular.Length-1) + 'ies'
            } Else {
                $Singular + 's'
            }
        }

        '{0} {1}' -f $Count,$(If ($Count -eq 1) { $Singular } Else { $PluralForm })
    }

    <#
        LESSON 6: Is this session elevated?
        With UAC, an administrator's normal session runs with a filtered token that is NOT in the
        Administrators role. IsInRole(Administrator) returns $true only in an elevated ("Run as
        administrator") session. The report uses this to explain why some checks show Unknown.
    #>
    $IsElevated    = $false
    Try {
        $Principal  = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
        $IsElevated = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } Catch {
        & $AddError 'Elevation' $_
    }
    #endregion

    #region Operating System and Hardware Identity
    $OS = & $Collect 'OperatingSystem' {
        Get-CimInstance -ClassName Win32_OperatingSystem @script:EA1
    }

    If (-not $OS) {
        Throw 'Cannot identify the local operating system.'
    }

    $Computer  = & $Collect 'ComputerSystem' {
        Get-CimInstance -ClassName Win32_ComputerSystem @script:EA1
    }

    $BIOS      = & $Collect 'BIOS' {
        Get-CimInstance -ClassName Win32_BIOS @script:EA1
    }

    $Enclosure = & $Collect 'Chassis' {
        @(Get-CimInstance -ClassName Win32_SystemEnclosure @script:EA1 | Select-Object -Property Manufacturer,SerialNumber,SMBIOSAssetTag,ChassisTypes,LockPresent)
    }

    $Board     = & $Collect 'Baseboard' {
        @(Get-CimInstance -ClassName Win32_BaseBoard @script:EA1 | Select-Object -Property Manufacturer,Product,SerialNumber,Version)
    }

    $CPU       = & $Collect 'Processors' {
        @(Get-CimInstance -ClassName Win32_Processor @script:EA1 | Select-Object -Property DeviceID,Name,Manufacturer,SocketDesignation,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,ProcessorId)
    }

    $DIMMs     = & $Collect 'MemoryModules' {
        @(Get-CimInstance -ClassName Win32_PhysicalMemory @script:EA1 | Select-Object -Property BankLabel,DeviceLocator,Manufacturer,PartNumber,SerialNumber,Capacity,Speed,ConfiguredClockSpeed,SMBIOSMemoryType,FormFactor)
    }

    <#
        LESSON 7: Switch produces a value
        Like If, Switch outputs whatever the matching branch outputs, so it can be assigned
        directly. Default runs when nothing else matches. Win32_OperatingSystem.ProductType is 1
        for a workstation, 2 for a domain controller and 3 for a server.
    #>
    $OSType    = Switch ([int]$OS.ProductType) {
        1       { 'Workstation' }
        2       { 'Domain Controller' }
        3       { 'Server' }
        Default { 'Unknown' }
    }

    $BootTime  = $OS.LastBootUpTime
    $UptimeHrs = If ($BootTime) { [math]::Round(((Get-Date) - $BootTime).TotalHours,1) } Else { $null }

    $System    = [pscustomobject][ordered]@{
        Hostname                 = $env:COMPUTERNAME
        OSType                   = $OSType
        Caption                  = $OS.Caption
        Version                  = $OS.Version
        Build                    = $OS.BuildNumber
        Architecture             = $OS.OSArchitecture
        InstallDate              = $OS.InstallDate
        LastBootUpTime           = $BootTime
        UptimeHours              = $UptimeHrs
        Manufacturer             = & $Prop $Computer 'Manufacturer'
        Model                    = & $Prop $Computer 'Model'
        Domain                   = & $Prop $Computer 'Domain'
        PartOfDomain             = & $Prop $Computer 'PartOfDomain'
        TotalPhysicalMemoryBytes = & $Prop $Computer 'TotalPhysicalMemory'
        BIOSSerialNumber         = & $Prop $BIOS 'SerialNumber'
        BIOSVersion              = (@(& $Prop $BIOS 'SMBIOSBIOSVersion') -join '; ')
        BIOSReleaseDate          = & $Prop $BIOS 'ReleaseDate'
        BIOSManufacturer         = & $Prop $BIOS 'Manufacturer'
        Elevated                 = $IsElevated
    }
    #endregion

    #region Storage and Volumes
    $PhysicalDisks = If (& $Available 'Get-PhysicalDisk') {
        & $Collect 'PhysicalDisks' {
            <#
                LESSON 8: Calculated properties
                @{ N = 'Name'; E = { ... } } in Select-Object creates a property whose value is
                computed while selecting: the E (Expression) scriptblock runs once per object,
                with $_ as that object, and the result is stored. [string]$_.MediaType turns an
                enum into readable text; without it, ConvertTo-Json writes the enum's number.
                Compare the ScriptProperty in Register-PSDiscoveryProtocol, which recomputes its
                value every time it is read.
            #>
            @(
                Get-PhysicalDisk @script:EA1 | Select-Object -Property FriendlyName, SerialNumber, UniqueId, @{
                    N = 'MediaType'
                    E = {[string]$_.MediaType}
                }, @{
                    N = 'BusType'
                    E = {[string]$_.BusType}
                }, @{
                    N = 'StorageType'
                    E = {
                        If ([string]$_.BusType -eq 'iSCSI') {
                            'Remote iSCSI'
                        } ElseIf ([string]$_.BusType -eq 'RAID') {
                            'RAID Logical Disk'
                        } Else {
                            'Other'
                        }
                    }
                }, Size, @{
                    N = 'HealthStatus'
                    E = {[string]$_.HealthStatus}
                }, @{
                    N = 'OperationalStatus'
                    E = {@($_.OperationalStatus) -join ', '}
                }, FirmwareVersion, PhysicalLocation
            )
        }
    } Else {
        $null
    }

    $DiskDrives    = & $Collect 'DiskDrives' {
        @(Get-CimInstance -ClassName Win32_DiskDrive @script:EA1 | Select-Object -Property Index,Model,SerialNumber,InterfaceType,MediaType,Size,PNPDeviceID,Status)
    }

    $Disks         = If (& $Available 'Get-Disk') {
        & $Collect 'Disks' {
            @(
                Get-Disk @script:EA1 | Select-Object -Property Number, FriendlyName, SerialNumber, @{
                    N = 'PartitionStyle'
                    E = {[string]$_.PartitionStyle}
                }, @{
                    N = 'BusType'
                    E = {[string]$_.BusType}
                }, Size, IsBoot, IsSystem, IsOffline, IsReadOnly, @{
                    N = 'HealthStatus'
                    E = {[string]$_.HealthStatus}
                }, @{
                    N = 'OperationalStatus'
                    E = {@($_.OperationalStatus) -join ', '}
                }
            )
        }
    } Else {
        $null
    }

    $Partitions    = If (& $Available 'Get-Partition') {
        & $Collect 'Partitions' {
            @(Get-Partition @script:EA1 | Select-Object -Property DiskNumber,PartitionNumber,DriveLetter,Type,Size,IsBoot,IsSystem,IsActive)
        }
    } Else {
        $null
    }

    $Volumes       = If (& $Available 'Get-Volume') {
        & $Collect 'Volumes' {
            @(
                Get-Volume @script:EA1 | Select-Object -Property DriveLetter, FileSystemLabel, FileSystem, @{
                    N = 'DriveType'
                    E = {[string]$_.DriveType}
                }, Size, SizeRemaining, @{
                    N = 'FreePercent'
                    E = {If ($_.Size) {[math]::Round(100*$_.SizeRemaining/$_.Size,1)} Else {$null}}
                }, @{
                    N = 'HealthStatus'
                    E = {[string]$_.HealthStatus}
                }, @{
                    N = 'OperationalStatus'
                    E = {@($_.OperationalStatus) -join ', '}
                }, Path
            )
        }
    } Else {
        $null
    }

    $StoragePools  = If (& $Available 'Get-StoragePool') {
        & $Collect 'StoragePools' {
            @(
                Get-StoragePool @script:EA1 | Where-Object {
                    -not $_.IsPrimordial
                } | Select-Object -Property FriendlyName, @{
                    N = 'HealthStatus'
                    E = {[string]$_.HealthStatus}
                }, @{
                    N = 'OperationalStatus'
                    E = {@($_.OperationalStatus) -join ', '}
                }, Size, AllocatedSize, IsReadOnly
            )
        }
    } Else {
        $null
    }

    $VirtualDisks  = If (& $Available 'Get-VirtualDisk') {
        & $Collect 'VirtualDisks' {
            @(
                Get-VirtualDisk @script:EA1 | Select-Object -Property FriendlyName, ResiliencySettingName, @{
                    N = 'ProvisioningType'
                    E = {[string]$_.ProvisioningType}
                }, Size, FootprintOnPool, @{
                    N = 'HealthStatus'
                    E = {[string]$_.HealthStatus}
                }, @{
                    N = 'OperationalStatus'
                    E = {@($_.OperationalStatus) -join ', '}
                }
            )
        }
    } Else {
        $null
    }
    #endregion

    #region Network and Device Drivers
    $NICs            = If (& $Available 'Get-NetAdapter') {
        & $Collect 'NetworkAdapters' {
            @(
                Get-NetAdapter @script:EA1 | Select-Object -Property Name, InterfaceDescription, InterfaceIndex, @{
                    N = 'MacAddress'
                    E = {([string]$_.MacAddress).Replace('-',':')}
                }, Status, LinkSpeed, DriverInformation, DriverVersion, DriverDate, HardwareInterface, Virtual
            )
        }
    } Else {
        $null
    }

    $IPAddresses     = If (& $Available 'Get-NetIPAddress') {
        & $Collect 'IPAddresses' {
            @(
                Get-NetIPAddress @script:EA1 | Select-Object -Property InterfaceAlias, InterfaceIndex, @{
                    N = 'AddressFamily'
                    E = {[string]$_.AddressFamily}
                }, IPAddress, PrefixLength, @{
                    N = 'PrefixOrigin'
                    E = {[string]$_.PrefixOrigin}
                }, @{
                    N = 'SuffixOrigin'
                    E = {[string]$_.SuffixOrigin}
                }, @{
                    N = 'AddressState'
                    E = {[string]$_.AddressState}
                }
            )
        }
    } Else {
        $null
    }

    $IPConfiguration = If (& $Available 'Get-NetIPConfiguration') {
        & $Collect 'IPConfiguration' {
            @(
                Get-NetIPConfiguration -Detailed @script:EA0 | ForEach-Object {
                    $Config = $_
                    [pscustomobject][ordered]@{
                        InterfaceAlias = $Config.InterfaceAlias
                        InterfaceIndex = $Config.InterfaceIndex
                        IPv4Address    = (@(& $Prop $Config 'IPv4Address' | ForEach-Object { & $Prop $_ 'IPAddress' }) -join '; ')
                        IPv4Gateway    = (@(& $Prop $Config 'IPv4DefaultGateway' | ForEach-Object { & $Prop $_ 'NextHop' }) -join '; ')
                        DNSServer      = (@(& $Prop $Config 'DNSServer' | ForEach-Object { & $Prop $_ 'ServerAddresses' }) -join '; ')
                        NetProfile     = (@(& $Prop $Config 'NetProfile' | ForEach-Object { & $Prop $_ 'Name' }) -join '; ')
                    }
                }
            )
        }
    } Else {
        $null
    }

    $NetVLAN         = If (& $Available 'Get-NetAdapterAdvancedProperty') {
        & $Collect 'AdapterVLANProperties' {
            @(
                Get-NetAdapterAdvancedProperty @script:EA1 | Where-Object {
                    $_.RegistryKeyword -match 'Vlan|Priority' -or
                    $_.DisplayName -match 'VLAN|Priority'
                } | Select-Object -Property Name,DisplayName,DisplayValue,RegistryKeyword,@{
                    N = 'RegistryValue'
                    E = {@($_.RegistryValue) -join ', '}
                }
            )
        }
    } Else {
        $null
    }

    $PnPDevices      = If (& $Available 'Get-PnpDevice') {
        & $Collect 'PnPDevices' {
            @(
                Get-PnpDevice -PresentOnly @script:EA1 | Where-Object {
                    $_.Class -in 'Net','SCSIAdapter','HDC','DiskDrive','Display','System'
                } | Select-Object -Property Class,FriendlyName,Status,InstanceId
            )
        }
    } Else {
        $null
    }
    #endregion

    #region Security, Power and Reboot Readiness
    $TPM           = If (& $Available 'Get-Tpm') {
        & $Collect 'TPM' {
            Get-Tpm @script:EA1 | Select-Object -Property TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,ManufacturerIdTxt,ManufacturerVersion
        }
    } Else {
        $null
    }

    <#
        LESSON 9: Several Catch blocks, most specific first
        A Try can have several Catch blocks. PowerShell picks the FIRST one whose exception type
        matches, so specific types go before the plain Catch. Here, a legacy-BIOS machine and a
        non-elevated session each get a clear answer instead of an error. Some cmdlets wrap the
        original exception, so the plain Catch also checks the message text.
    #>
    $SecureBoot    = $null
    If (& $Available 'Confirm-SecureBootUEFI') {
        Try {
            $SecureBoot = If (Confirm-SecureBootUEFI @script:EA1) { 'Enabled' } Else { 'Disabled' }
        } Catch [System.PlatformNotSupportedException] {
            $SecureBoot = 'Not supported (legacy BIOS)'
        } Catch [System.UnauthorizedAccessException] {
            $SecureBoot = 'Unknown (requires elevation)'
        } Catch {
            If ($_.Exception.Message -match '(?i)not supported') {
                $SecureBoot = 'Not supported (legacy BIOS)'
            } Else {
                $SecureBoot = 'Unknown'
                & $AddError 'SecureBoot' $_
            }
        }
    }

    $BitLocker     = If (& $Available 'Get-BitLockerVolume') {
        & $Collect 'BitLocker' {
            @(
                Get-BitLockerVolume @script:EA1 | Select-Object -Property MountPoint, @{
                    N = 'VolumeType'
                    E = {[string]$_.VolumeType}
                }, @{
                    N = 'VolumeStatus'
                    E = {[string]$_.VolumeStatus}
                }, @{
                    N = 'ProtectionStatus'
                    E = {[string]$_.ProtectionStatus}
                }, EncryptionPercentage, @{
                    N = 'EncryptionMethod'
                    E = {[string]$_.EncryptionMethod}
                }, AutoUnlockEnabled
            )
        }
    } Else {
        $null
    }

    $Firewall      = If (& $Available 'Get-NetFirewallProfile') {
        & $Collect 'FirewallProfiles' {
            @(
                Get-NetFirewallProfile @script:EA1 | Select-Object -Property Name, @{
                    N = 'Enabled'
                    E = {[string]$_.Enabled}
                }, @{
                    N = 'DefaultInboundAction'
                    E = {[string]$_.DefaultInboundAction}
                }, @{
                    N = 'DefaultOutboundAction'
                    E = {[string]$_.DefaultOutboundAction}
                }, @{
                    N = 'LogAllowed'
                    E = {[string]$_.LogAllowed}
                }, @{
                    N = 'LogBlocked'
                    E = {[string]$_.LogBlocked}
                }, LogFileName
            )
        }
    } Else {
        $null
    }

    $Power         = & $Collect 'PowerSupply' {
        @(Get-CimInstance -ClassName Win32_Battery @script:EA1 | Select-Object -Property Name,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,DesignVoltage)
    }

    $TimeService   = & $Collect 'WindowsTime' {
        $Svc = Get-Service -Name W32Time @script:EA1

        # Native stderr plus a script-wide 'Stop' preference turns w32tm warnings into terminating errors.
        $ErrorActionPreference = 'Continue'
        <#
            LESSON 10: Preference variables are scoped, and native programs write to stderr
            In Windows PowerShell 5.1, 2>&1 turns each line a native program writes to stderr into
            an error record, and under the script's 'Stop' preference the first one ends the
            command. Setting $ErrorActionPreference = 'Continue' here affects only this scriptblock
            and anything it calls; the rest of the script keeps 'Stop'. 2>&1 merges stderr into
            normal output, and [string]$_ turns each line back into text.
        #>
        $StatusLines = @(& w32tm.exe /query /status 2>&1 | ForEach-Object { [string]$_ })

        $Source   = $null
        $LastSync = $null
        $Stratum  = $null
        ForEach ($Line in $StatusLines) {
            If ($Line -match '^\s*Source:\s*(.+?)\s*$')                    { $Source   = $Matches[1] }
            If ($Line -match '^\s*Last Successful Sync Time:\s*(.+?)\s*$') { $LastSync = $Matches[1] }
            If ($Line -match '^\s*Stratum:\s*(\d+)')                       { $Stratum  = [int]$Matches[1] }
        }

        [pscustomobject][ordered]@{
            Status        = [string]$Svc.Status
            StartType     = [string]$Svc.StartType
            Source        = $Source
            LastSync      = $LastSync
            Stratum       = $Stratum
            Configuration = ($StatusLines -join '; ')
        }
    }

    $PendingReboot = & $Collect 'PendingReboot' {
        $CBS     = Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $WU      = Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $SM      = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' @script:EA0
        $Renames = [bool](& $Prop $SM 'PendingFileRenameOperations')

        $ActiveName  = & $Prop (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' @script:EA0) 'ComputerName'
        $PendingName = & $Prop (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' @script:EA0) 'ComputerName'
        $Rename      = [bool]($ActiveName -and $PendingName -and $ActiveName -ne $PendingName)

        <#
            LESSON 11: Building an array from conditions
            Each If inside @( ) outputs its string only when the condition is true, and an If
            whose condition is false outputs nothing. The result holds exactly the reasons that
            apply: no empty array to start with and no += needed.
        #>
        $Reasons = @(
            If ($CBS)     { 'Component servicing' }
            If ($WU)      { 'Windows Update' }
            If ($Renames) { 'Pending file rename' }
            If ($Rename)  { 'Computer rename' }
        )

        [pscustomobject][ordered]@{
            CBS               = $CBS
            WindowsUpdate     = $WU
            PendingFileRename = $Renames
            ComputerRename    = $Rename
            Any               = [bool]$Reasons.Count
            Reasons           = $Reasons
        }
    }
    #endregion

    #region Services, Software, Local Principals and Shares
    <#
        LESSON 12: Cache work you would otherwise repeat
        Hundreds of services share a few executables; dozens run inside svchost.exe alone. Reading
        each file's version information once and storing it in a hashtable keyed by path avoids
        repeating the same disk read. Hashtable keys are case-insensitive by default, which
        matches how Windows treats paths.
        Service paths come in several forms: quoted ("C:\Program Files\App\app.exe" -k), unquoted
        with arguments, with environment variables (%SystemRoot%), or with kernel prefixes
        (\??\ and \SystemRoot\). The regexes and replacements below normalize each form to a
        plain file path.
    #>
    $VendorCache = @{}

    $GetVendor   = {
        Param ([string]$PathName)

        If ([string]::IsNullOrWhiteSpace($PathName)) {
            Return $null
        }

        $Exe = If ($PathName -match '^\s*"([^"]+)"') {
            $Matches[1]
        } ElseIf ($PathName -match '^\s*(.+?\.(?:exe|sys|dll))(?:\s|$)') {
            $Matches[1]
        } Else {
            $PathName.Trim()
        }

        $Exe = [Environment]::ExpandEnvironmentVariables($Exe)
        $Exe = $Exe -replace '^\\\?\?\\',''
        $Exe = $Exe -replace '^(?i)\\SystemRoot\\',($env:SystemRoot + '\')

        If ($VendorCache.ContainsKey($Exe)) {
            Return $VendorCache[$Exe]
        }

        $Company = $null
        Try {
            If (Test-Path -LiteralPath $Exe -PathType Leaf) {
                $Company = (Get-Item -LiteralPath $Exe -Force @script:EA1).VersionInfo.CompanyName
            }
        } Catch {
            Write-Verbose -Message ('Unable to read version information for {0}: {1}' -f $Exe,$_.Exception.Message)
        }

        $Result = [pscustomobject]@{
            Path    = $Exe
            Company = If ([string]::IsNullOrWhiteSpace($Company)) { $null } Else { $Company.Trim() }
        }

        $VendorCache[$Exe] = $Result
        $Result
    }

    $Services    = & $Collect 'Services' {
        @(
            Get-CimInstance -ClassName Win32_Service @script:EA1 | ForEach-Object {
                $Vendor      = & $GetVendor $_.PathName
                $Company     = & $Prop $Vendor 'Company'
                $UnderSystem = [bool]((& $Prop $Vendor 'Path') -like ($env:SystemRoot + '\*'))
                $IsMicrosoft = [bool]($Company -match '^(?i)Microsoft') -or (-not $Company -and $UnderSystem)
                $ExitCode    = & $Prop $_ 'ExitCode'
                $TriggerKey  = 'HKLM:\SYSTEM\CurrentControlSet\Services\{0}\TriggerInfo' -f $_.Name
                $IsTrigger   = [bool](Test-Path -LiteralPath $TriggerKey @script:EA0)

                ### Automatic services that ran and exited cleanly (exit code 0), or that start on a
                ### trigger, are stopped by design. Only the rest count as stopped unexpectedly.
                $Unexpected  = [bool](
                    $_.StartMode -eq 'Auto' -and
                    $_.State -ne 'Running' -and
                    -not $IsTrigger -and
                    $null -ne $ExitCode -and
                    [long]$ExitCode -ne 0
                )

                [pscustomobject][ordered]@{
                    Name                = $_.Name
                    DisplayName         = $_.DisplayName
                    State               = $_.State
                    StartMode           = $_.StartMode
                    DelayedAutoStart    = & $Prop $_ 'DelayedAutoStart'
                    TriggerStart        = $IsTrigger
                    ExitCode            = $ExitCode
                    StoppedUnexpectedly = $Unexpected
                    StartName           = $_.StartName
                    Vendor              = $Company
                    IsMicrosoft         = $IsMicrosoft
                    PathName            = $_.PathName
                }
            } | Sort-Object -Property DisplayName
        )
    }

    $Tasks       = If ($IncludeTasks -and (& $Available 'Get-ScheduledTask')) {
        & $Collect 'ScheduledTasks' {
            @(
                Get-ScheduledTask @script:EA1 | ForEach-Object {
                    $Task        = $_
                    $Author      = [string](& $Prop $Task 'Author')
                    $IsMicrosoft = [bool](
                        $Task.TaskPath -like '\Microsoft\*' -or
                        $Author -match '^(?i)(Microsoft|\$\(@%SystemRoot%)' -or
                        $Task.TaskName -match '^(Optimize Start Menu Cache Files-S-1-5-|User_Feed_Synchronization-\{|CreateExplorerShellUnelevatedTask$|OneDrive )'
                    )
                    $LastRun     = $null
                    $LastResult  = $null
                    $NextRun     = $null

                    If (-not $IsMicrosoft) {
                        Try {
                            $Info       = Get-ScheduledTaskInfo -InputObject $Task @script:EA1
                            $LastRun    = If ($Info.LastRunTime -and $Info.LastRunTime.Year -gt 2000) { $Info.LastRunTime } Else { $null }
                            $NextRun    = If ($Info.NextRunTime -and $Info.NextRunTime.Year -gt 2000) { $Info.NextRunTime } Else { $null }
                            $LastResult = '0x{0:X8}' -f [uint32]$Info.LastTaskResult
                        } Catch {
                            Write-Verbose -Message ('Scheduled task info {0}: {1}' -f $Task.TaskName,$_.Exception.Message)
                        }
                    }

                    [pscustomobject][ordered]@{
                        TaskName       = $Task.TaskName
                        TaskPath       = $Task.TaskPath
                        Author         = $Author
                        State          = [string]$Task.State
                        RunAs          = & $Prop (& $Prop $Task 'Principal') 'UserId'
                        Execute        = (@($Task.Actions | ForEach-Object { & $Prop $_ 'Execute' }) -join '; ')
                        Arguments      = (@($Task.Actions | ForEach-Object { & $Prop $_ 'Arguments' }) -join '; ')
                        LastRunTime    = $LastRun
                        LastTaskResult = $LastResult
                        NextRunTime    = $NextRun
                        IsMicrosoft    = $IsMicrosoft
                    }
                }
            )
        }
    } Else {
        $null
    }

    $Software    = If ($IncludeSoftware) {
        & $Collect 'InstalledSoftware' {
            <#
                LESSON 13: 64-bit Windows has two software registries
                32-bit programs register under WOW6432Node on 64-bit Windows, so both keys must be
                read. Get-ItemProperty accepts several paths at once, and the * wildcard returns
                every subkey. Entries marked SystemComponent are hidden from Programs and Features,
                and entries with a ParentKeyName are updates to another product, so both are
                skipped. ParseExact with InvariantCulture reads the yyyyMMdd dates the same way on
                every regional setting.
            #>
            $Paths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )

            @(
                Get-ItemProperty -Path $Paths @script:EA0 | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string](& $Prop $_ 'DisplayName')) -and
                    -not (& $Prop $_ 'SystemComponent') -and
                    -not (& $Prop $_ 'ParentKeyName')
                } | ForEach-Object {
                    $Raw         = [string](& $Prop $_ 'InstallDate')
                    $InstallDate = $null
                    If ($Raw -match '^\d{8}$') {
                        Try {
                            $InstallDate = [datetime]::ParseExact($Raw,'yyyyMMdd',[cultureinfo]::InvariantCulture).ToString('yyyy-MM-dd')
                        } Catch {
                            $InstallDate = $Raw
                        }
                    }

                    [pscustomobject][ordered]@{
                        DisplayName    = ([string](& $Prop $_ 'DisplayName')).Trim()
                        DisplayVersion = & $Prop $_ 'DisplayVersion'
                        Publisher      = & $Prop $_ 'Publisher'
                        InstallDate    = $InstallDate
                    }
                } | Sort-Object -Property DisplayName,DisplayVersion -Unique
            )
        }
    } Else {
        $null
    }

    $LocalUsers  = If ($OSType -ne 'Domain Controller' -and (& $Available 'Get-LocalUser')) {
        & $Collect 'LocalUsers' {
            @(Get-LocalUser @script:EA1 | Select-Object -Property Name,Enabled,Description,LastLogon,PasswordRequired,PasswordLastSet)
        }
    } Else {
        $null
    }

    $LocalGroups = If ($OSType -ne 'Domain Controller' -and (& $Available 'Get-LocalGroup')) {
        & $Collect 'LocalGroups' {
            @(
                Get-LocalGroup @script:EA1 | Select-Object -Property Name, Description, @{
                    N = 'SID'
                    E = {[string]$_.SID}
                }
            )
        }
    } Else {
        $null
    }

    $LocalAdmins = If ($OSType -ne 'Domain Controller') {
        & $Collect 'LocalAdministrators' {
            $Members = $null

            If (& $Available 'Get-LocalGroupMember') {
                Try {
                    $Members = @(
                        Get-LocalGroupMember -SID 'S-1-5-32-544' @script:EA1 | ForEach-Object {
                            [pscustomobject][ordered]@{
                                Name        = $_.Name
                                ObjectClass = [string]$_.ObjectClass
                                Source      = [string]$_.PrincipalSource
                            }
                        }
                    )
                } Catch {
                    # Get-LocalGroupMember fails on orphaned SIDs; fall back to the WinNT provider below.
                    Write-Verbose -Message ('Get-LocalGroupMember failed, using WinNT provider: {0}' -f $_.Exception.Message)
                }
            }

            <#
                LESSON 14: Plan B, and why groups are found by SID
                Get-LocalGroupMember fails when the group contains an orphaned SID, such as a
                deleted domain account, so the WinNT ADSI provider is used as a fallback.
                The Administrators group is found by its well-known SID S-1-5-32-544, never by
                name: on non-English Windows the group is named differently (Administradores,
                Administrateurs). Translate() returns the local name for building the ADSI path.
                InvokeMember reads properties from the COM objects ADSI returns.
            #>
            If ($null -eq $Members) {
                $GroupName = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
                $Group     = [ADSI]('WinNT://{0}/{1},group' -f $env:COMPUTERNAME,$GroupName)
                $Members   = @(
                    $Group.Invoke('Members') | ForEach-Object {
                        $Path  = [string]$_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null)
                        $Class = [string]$_.GetType().InvokeMember('Class','GetProperty',$null,$_,$null)

                        [pscustomobject][ordered]@{
                            Name        = ($Path -replace '^WinNT://','') -replace '/','\'
                            ObjectClass = $Class
                            Source      = 'WinNT'
                        }
                    }
                )
            }

            @($Members | Sort-Object -Property Name)
        }
    } Else {
        $null
    }

    $Shares      = If (& $Available 'Get-SmbShare') {
        & $Collect 'FileShares' {
            @(
                Get-SmbShare @script:EA1 | Where-Object {
                    $_.Name -notmatch '\$$'
                } | ForEach-Object {
                    $Share    = $_
                    $ShareACL = $null
                    $NTFSACL  = $null

                    If ($IncludeShareACL) {
                        Try {
                            $ShareACL = @(
                                Get-SmbShareAccess -Name $Share.Name @script:EA1 | Select-Object -Property AccountName,@{
                                    N = 'AccessControlType'
                                    E = {[string]$_.AccessControlType}
                                },@{
                                    N = 'AccessRight'
                                    E = {[string]$_.AccessRight}
                                }
                            )
                        } Catch {
                            & $AddError 'ShareACL' ('{0}: {1}' -f $Share.Name,$_.Exception.Message)
                        }

                        If ($Share.Path -and (Test-Path -LiteralPath $Share.Path @script:EA0)) {
                            Try {
                                $NTFSACL = @(
                                    (Get-Acl -LiteralPath $Share.Path @script:EA1).Access | Select-Object -Property @{
                                        N = 'IdentityReference'
                                        E = {[string]$_.IdentityReference}
                                    },@{
                                        N = 'FileSystemRights'
                                        E = {[string]$_.FileSystemRights}
                                    },@{
                                        N = 'AccessControlType'
                                        E = {[string]$_.AccessControlType}
                                    },IsInherited
                                )
                            } Catch {
                                & $AddError 'NTFSACL' ('{0}: {1}' -f $Share.Path,$_.Exception.Message)
                            }
                        }
                    }

                    [pscustomobject][ordered]@{
                        Name        = $Share.Name
                        Path        = $Share.Path
                        Description = $Share.Description
                        ShareType   = [string]$Share.ShareType
                        IsSystem    = [bool]($Share.Name -in 'NETLOGON','SYSVOL','print$','CertEnroll')
                        ShareACL    = $ShareACL
                        NTFSACL     = $NTFSACL
                    }
                }
            )
        }
    } Else {
        $null
    }

    $SharedPrinters = & $Collect 'SharedPrinters' {
        @(Get-CimInstance -ClassName Win32_Printer -Filter 'Shared=True' @script:EA1 | Select-Object -Property Name,ShareName,DriverName,PortName,Location)
    }
    #endregion

    #region Windows Features and Installed Roles
    $Features         = $null
    $OptionalFeatures = $null
    $Capabilities     = $null

    If ($OSType -ne 'Workstation' -and (& $Available 'Get-WindowsFeature')) {
        $Features = & $Collect 'WindowsFeatures' {
            @(
                Get-WindowsFeature @script:EA1 | Where-Object Installed | Select-Object -Property Name, DisplayName, @{
                    N = 'FeatureType'
                    E = {[string]$_.FeatureType}
                }, Depth, Path
            )
        }
    } Else {
        If (& $Available 'Get-WindowsOptionalFeature') {
            $OptionalFeatures = & $Collect 'OptionalFeatures' {
                @(
                    Get-WindowsOptionalFeature -Online @script:EA1 | Where-Object {[string]$_.State -eq 'Enabled'} | Select-Object -Property FeatureName, @{
                        N = 'State'
                        E = {[string]$_.State}
                    }
                )
            }
        }

        If ($IncludeCapabilities -and (& $Available 'Get-WindowsCapability')) {
            $Capabilities = & $Collect 'WindowsCapabilities' {
                @(
                    Get-WindowsCapability -Online @script:EA1 | Where-Object {[string]$_.State -eq 'Installed'} | Select-Object -Property Name, @{
                        N = 'State'
                        E = {[string]$_.State}
                    }
                )
            }
        }
    }

    $HasFeature = {
        Param ([string]$Name)
        [bool](@($Features | Where-Object {$_ -and $_.Name -eq $Name}).Count)
    }

    $HyperV     = If ((& $Available 'Get-VMHost') -and (& $Available 'Get-VM') -and (& $ServiceExists 'vmms')) {
        & $Collect 'HyperV' {
            $VMHost = Get-VMHost @script:EA1

            [pscustomobject][ordered]@{
                Host     = [pscustomobject][ordered]@{
                    ComputerName                   = $VMHost.ComputerName
                    VirtualHardDiskPath            = $VMHost.VirtualHardDiskPath
                    VirtualMachinePath             = $VMHost.VirtualMachinePath
                    LogicalProcessorCount          = $VMHost.LogicalProcessorCount
                    MemoryCapacityGB               = & $ToGB (& $Prop $VMHost 'MemoryCapacity')
                    VirtualMachineMigrationEnabled = $VMHost.VirtualMachineMigrationEnabled
                }
                VMs      = @(
                    Get-VM @script:EA1 | Sort-Object -Property Name | ForEach-Object {
                        $VM     = $_
                        $Uptime = $null
                        If ($VM.Uptime -and $VM.Uptime.TotalSeconds -gt 0) {
                            $Uptime = '{0}d {1:00}:{2:00}' -f $VM.Uptime.Days,$VM.Uptime.Hours,$VM.Uptime.Minutes
                        }

                        [pscustomobject][ordered]@{
                            Name                 = $VM.Name
                            State                = [string]$VM.State
                            Generation           = $VM.Generation
                            Version              = $VM.Version
                            ProcessorCount       = $VM.ProcessorCount
                            MemoryStartupGB      = & $ToGB $VM.MemoryStartup
                            MemoryAssignedGB     = & $ToGB $VM.MemoryAssigned
                            DynamicMemory        = $VM.DynamicMemoryEnabled
                            Uptime               = $Uptime
                            AutomaticStartAction = [string]$VM.AutomaticStartAction
                            Checkpoints          = @(Get-VMSnapshot -VM $VM @script:EA0).Count
                            ReplicationState     = [string](& $Prop $VM 'ReplicationState')
                            Path                 = $VM.Path
                        }
                    }
                )
                Switches = @(
                    Get-VMSwitch @script:EA1 | Select-Object -Property Name, @{
                        N = 'SwitchType'
                        E = {[string]$_.SwitchType}
                    }, NetAdapterInterfaceDescription, AllowManagementOS
                )
            }
        }
    } Else {
        $null
    }

    ### DNS: the MicrosoftDNS WMI provider is installed with the DNS Server role itself, so this does
    ### not depend on the optional DnsServer PowerShell module.
    $DNS        = If (& $ServiceExists 'DNS') {
        & $Collect 'DNS' {
            $Namespace = 'root\MicrosoftDNS'

            $ZoneTypes = @{
                0 = 'Cache'
                1 = 'Primary'
                2 = 'Secondary'
                3 = 'Stub'
                4 = 'Forwarder'
            }

            $Updates   = @{
                0 = 'None'
                1 = 'Nonsecure and secure'
                2 = 'Secure only'
            }

            $Zones = @(
                Get-CimInstance -Namespace $Namespace -ClassName MicrosoftDNS_Zone @script:EA1 | Where-Object {
                    -not (& $Prop $_ 'AutoCreated') -and $_.Name -ne 'TrustAnchors'
                } | Sort-Object -Property Name
            )

            $Server = Get-CimInstance -Namespace $Namespace -ClassName MicrosoftDNS_Server @script:EA0 | Select-Object -First 1

            [pscustomobject][ordered]@{
                Zones      = @(
                    ForEach ($Zone in $Zones) {
                        $Count = $null
                        Try {
                            $Filter = "ContainerName='{0}'" -f ([string]$Zone.Name -replace "'","''")
                            $Count  = @(Get-CimInstance -Namespace $Namespace -ClassName MicrosoftDNS_ResourceRecord -Filter $Filter -KeyOnly @script:EA1).Count
                        } Catch {
                            & $AddError 'DNSRecordCount' ('{0}: {1}' -f $Zone.Name,$_.Exception.Message)
                        }

                        $Type   = & $Prop $Zone 'ZoneType'
                        $Update = & $Prop $Zone 'AllowUpdate'

                        [pscustomobject][ordered]@{
                            ZoneName            = $Zone.Name
                            ZoneType            = If ($null -ne $Type -and $ZoneTypes.ContainsKey([int]$Type)) { $ZoneTypes[[int]$Type] } Else { [string]$Type }
                            IsDsIntegrated      = [bool](& $Prop $Zone 'DsIntegrated')
                            IsReverseLookupZone = [bool](& $Prop $Zone 'Reverse')
                            DynamicUpdate       = If ($null -ne $Update -and $Updates.ContainsKey([int]$Update)) { $Updates[[int]$Update] } Else { [string]$Update }
                            Records             = $Count
                        }
                    }
                )
                Forwarders = @(& $Prop $Server 'Forwarders' | Where-Object { $_ } | ForEach-Object { [string]$_ })
            }
        }
    } Else {
        $null
    }

    ### DHCP: the DHCP Server management API (dhcpsapi.dll) ships with the DHCP Server role, so this
    ### does not depend on the optional DhcpServer PowerShell module.
    $DHCP       = If (& $ServiceExists 'DHCPServer') {
        & $Collect 'DHCP' {
            If (-not ('HardwareInventory.DhcpNative' -as [type])) {
                Add-Type -TypeDefinition $script:DhcpNativeSource -Language CSharp @script:EA1
            }

            @(
                [HardwareInventory.DhcpNative]::GetScopes() | ForEach-Object {
                    $Total = If ($_.InUse -ge 0 -and $_.Free -ge 0) {
                        $_.InUse + $_.Free
                    } Else {
                        0
                    }

                    [pscustomobject][ordered]@{
                        ScopeId      = $_.ScopeId
                        Name         = $_.Name
                        Description  = $_.Comment
                        State        = $_.State
                        StartRange   = $_.StartRange
                        EndRange     = $_.EndRange
                        SubnetMask   = $_.SubnetMask
                        InUse        = If ($_.InUse -ge 0) { $_.InUse } Else { $null }
                        Free         = If ($_.Free -ge 0) { $_.Free } Else { $null }
                        PercentInUse = If ($Total -gt 0) { [math]::Round(100 * $_.InUse / $Total,1) } Else { $null }
                    }
                } | Sort-Object -Property { [version]$_.ScopeId }
            )
        }
    } Else {
        $null
    }

    ### Active Directory: System.DirectoryServices.ActiveDirectory is part of the .NET Framework, so
    ### this does not depend on the optional RSAT ActiveDirectory module.
    $AD         = If ($OSType -eq 'Domain Controller') {
        & $Collect 'ActiveDirectory' {
            <#
                LESSON 15: Active Directory without the ActiveDirectory module
                The RSAT ActiveDirectory module is optional even on domain controllers, but the
                .NET Framework always includes System.DirectoryServices.ActiveDirectory. A
                DirectoryContext names the server to talk to, and GetDomainController returns an
                object exposing the site, FSMO roles and replication neighbors. It holds network
                connections, so it is disposed in Finally.
            #>
            $ContextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer
            $Context     = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList $ContextType,$env:COMPUTERNAME
            $DC          = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($Context)

            $RoleNames   = @{
                SchemaRole         = 'Schema Master'
                NamingRole         = 'Domain Naming Master'
                PdcRole            = 'PDC Emulator'
                RidRole            = 'RID Master'
                InfrastructureRole = 'Infrastructure Master'
            }

            Try {
                $IsReadOnly = $null
                Try {
                    $RootDse  = [ADSI]('LDAP://{0}/RootDSE' -f $env:COMPUTERNAME)
                    $NtdsPath = [string]$RootDse.Properties['dsServiceName'].Value
                    $Ntds     = [ADSI]('LDAP://{0}/{1}' -f $env:COMPUTERNAME,$NtdsPath)
                    $Ntds.RefreshCache([string[]]@('msDS-isRODC'))
                    $IsReadOnly = [bool]$Ntds.Properties['msDS-isRODC'].Value
                } Catch {
                    & $AddError 'ADReadOnlyFlag' $_
                }

                $Partners = @(
                    Try {
                        $DC.GetAllReplicationNeighbors() | ForEach-Object {
                            $Source = [string]$_.SourceServer
                            [pscustomobject][ordered]@{
                                Partner                        = If ($Source) { $Source.Split('.')[0] } Else { [string]$_.SourceInvocationId }
                                Partition                      = $_.PartitionName
                                Transport                      = [string]$_.TransportType
                                LastReplicationSuccess         = If ($_.LastSuccessfulSync -gt [datetime]'1990-01-01') { $_.LastSuccessfulSync } Else { $null }
                                LastReplicationAttempt         = If ($_.LastAttemptedSync -gt [datetime]'1990-01-01') { $_.LastAttemptedSync } Else { $null }
                                LastReplicationResult          = [int]$_.LastSyncResult
                                LastReplicationMessage         = $_.LastSyncMessage
                                ConsecutiveReplicationFailures = [int]$_.ConsecutiveFailureCount
                            }
                        }
                    } Catch {
                        & $AddError 'ADReplication' $_
                    }
                )

                [pscustomobject][ordered]@{
                    Domain              = $DC.Domain.Name
                    Forest              = $DC.Forest.Name
                    Site                = $DC.SiteName
                    IsGlobalCatalog     = $DC.IsGlobalCatalog()
                    IsReadOnly          = $IsReadOnly
                    FSMORoles           = @(
                        $DC.Roles | ForEach-Object {
                            $RoleName = [string]$_
                            If ($RoleNames.ContainsKey($RoleName)) {
                                $RoleNames[$RoleName]
                            } Else {
                                $RoleName
                            }
                        }
                    )
                    ReplicationPartners = $Partners
                }
            } Finally {
                $DC.Dispose()
            }
        }
    } Else {
        $null
    }

    ### IIS: read straight from applicationHost.config, which exists whenever IIS is installed, so this
    ### does not depend on the optional WebAdministration module.
    $IIS        = If (& $ServiceExists 'W3SVC') {
        & $Collect 'IIS' {
            $System32 = If ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
                'Sysnative'
            } Else {
                'System32'
            }
            $Config   = Join-Path -Path $env:SystemRoot -ChildPath ('{0}\inetsrv\config\applicationHost.config' -f $System32)

            If (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
                Throw ('IIS configuration not found at {0}.' -f $Config)
            }

            <#
                LESSON 16: Reading XML without the module that usually wraps it
                IIS keeps its whole configuration in applicationHost.config. SelectNodes takes an
                XPath query such as '/configuration/system.applicationHost/sites/site' and returns
                every match. HasAttribute and GetAttribute read attributes without failing when
                one is absent. Dot access ($Xml.configuration...) would throw under StrictMode for
                a missing element. 'Sysnative' lets 32-bit PowerShell reach the real System32
                folder instead of being redirected to SysWOW64.
            #>
            $Xml = New-Object -TypeName System.Xml.XmlDocument
            $Xml.Load($Config)

            $Attr = {
                Param ($Node,[string]$Name,[string]$Default)

                If ($Node -and $Node.HasAttribute($Name)) {
                    Return $Node.GetAttribute($Name)
                }

                Return $Default
            }

            $PoolDefaults = $Xml.SelectSingleNode('/configuration/system.applicationHost/applicationPools/applicationPoolDefaults')

            [pscustomobject][ordered]@{
                Sites    = @(
                    ForEach ($Site in @($Xml.SelectNodes('/configuration/system.applicationHost/sites/site'))) {
                        $Root     = $Site.SelectSingleNode("application[@path='/']/virtualDirectory[@path='/']")
                        $RootApp  = $Site.SelectSingleNode("application[@path='/']")
                        $Bindings = @(
                            ForEach ($Binding in @($Site.SelectNodes('bindings/binding'))) {
                                '{0} {1}' -f (& $Attr $Binding 'protocol' ''),(& $Attr $Binding 'bindingInformation' '')
                            }
                        )

                        [pscustomobject][ordered]@{
                            Name            = & $Attr $Site 'name' ''
                            Id              = & $Attr $Site 'id' ''
                            AutoStart       = (& $Attr $Site 'serverAutoStart' 'true') -ne 'false'
                            Bindings        = $Bindings -join '; '
                            PhysicalPath    = [Environment]::ExpandEnvironmentVariables((& $Attr $Root 'physicalPath' ''))
                            ApplicationPool = & $Attr $RootApp 'applicationPool' ''
                        }
                    }
                )
                AppPools = @(
                    ForEach ($Pool in @($Xml.SelectNodes('/configuration/system.applicationHost/applicationPools/add'))) {
                        [pscustomobject][ordered]@{
                            Name                  = & $Attr $Pool 'name' ''
                            AutoStart             = (& $Attr $Pool 'autoStart' (& $Attr $PoolDefaults 'autoStart' 'true')) -ne 'false'
                            ManagedRuntimeVersion = $(
                                $Runtime = & $Attr $Pool 'managedRuntimeVersion' (& $Attr $PoolDefaults 'managedRuntimeVersion' 'v4.0')
                                If ([string]::IsNullOrEmpty($Runtime)) {
                                    'No managed code'
                                } Else {
                                    $Runtime
                                }
                            )
                            ManagedPipelineMode   = & $Attr $Pool 'managedPipelineMode' (& $Attr $PoolDefaults 'managedPipelineMode' 'Integrated')
                        }
                    }
                )
                Service  = [string](Get-Service -Name W3SVC @script:EA1).Status
            }
        }
    } Else {
        $null
    }

    $RRAS       = If (& $ServiceExists 'RemoteAccess') {
        & $Collect 'RRAS' {
            $Svc = Get-Service -Name RemoteAccess @script:EA1
            If ([string]$Svc.StartType -ne 'Disabled' -or [string]$Svc.Status -eq 'Running') {
                [pscustomobject][ordered]@{
                    Name      = $Svc.Name
                    Status    = [string]$Svc.Status
                    StartType = [string]$Svc.StartType
                }
            }
        }
    } Else {
        $null
    }

    ### Failover clustering: the MSCluster WMI provider is installed with the Failover Clustering
    ### feature itself, so this does not depend on the optional FailoverClusters module.
    $Clustering = If (& $ServiceExists 'ClusSvc') {
        & $Collect 'Clustering' {
            $Namespace   = 'root\MSCluster'

            <#
                LESSON 17: Turning numeric codes into words, and why the cast matters
                WMI reports states as numbers, and hashtables translate them into readable text.
                Hashtable keys are type-sensitive: the key 1 written here is an [int], so a lookup
                with [uint32]1 (how WMI often returns numbers) or with the string '1' finds
                NOTHING. $Map casts with [int]$Value before looking up, and falls back to the raw
                value for codes the table does not list.
            #>
            $NodeStates  = @{
                -1 = 'Unknown'
                0 = 'Up'
                1 = 'Down'
                2 = 'Paused'
                3 = 'Joining'
            }

            $GroupStates = @{
                -1 = 'Unknown'
                0 = 'Online'
                1 = 'Offline'
                2 = 'Failed'
                3 = 'Partial online'
                4 = 'Pending'
            }

            $NetStates   = @{
                -1 = 'Unknown'
                0 = 'Unavailable'
                1 = 'Down'
                2 = 'Partitioned'
                3 = 'Up'
            }

            $NetRoles    = @{
                0 = 'None'
                1 = 'Cluster only'
                2 = 'Client only'
                3 = 'Cluster and client'
            }

            $GroupTypes  = @{
                1   = 'Cluster'
                2   = 'Available Storage'
                100 = 'Temporary'
                101 = 'Cluster Shared Volume'
                102 = 'Storage Pool'
                103 = 'File Server'
                104 = 'Print Server'
                105 = 'DHCP Server'
                106 = 'DTC'
                107 = 'MSMQ'
                110 = 'Generic Application'
                111 = 'Generic Service'
                112 = 'Generic Script'
                114 = 'Virtual Machine'
                117 = 'Scale-Out File Server'
                122 = 'Storage Replica'
            }

            $Map = {
                Param ([hashtable]$Table,$Value)

                If ($null -eq $Value) {
                    Return $null
                }

                If ($Table.ContainsKey([int]$Value)) {
                    Return $Table[[int]$Value]
                }

                Return [string]$Value
            }

            $Cluster = Get-CimInstance -Namespace $Namespace -ClassName MSCluster_Cluster @script:EA1 | Select-Object -First 1

            [pscustomobject][ordered]@{
                Cluster  = [pscustomobject][ordered]@{
                    Name       = & $Prop $Cluster 'Name'
                    Domain     = & $Prop $Cluster 'Fqdn'
                    QuorumType = & $Prop $Cluster 'QuorumType'
                }
                Nodes    = @(
                    Get-CimInstance -Namespace $Namespace -ClassName MSCluster_Node @script:EA1 | ForEach-Object {
                        [pscustomobject][ordered]@{
                            Name       = $_.Name
                            State      = & $Map $NodeStates (& $Prop $_ 'State')
                            NodeWeight = & $Prop $_ 'NodeWeight'
                        }
                    } | Sort-Object -Property Name
                )
                Roles    = @(
                    Get-CimInstance -Namespace $Namespace -ClassName MSCluster_ResourceGroup @script:EA1 | ForEach-Object {
                        [pscustomobject][ordered]@{
                            Name      = $_.Name
                            State     = & $Map $GroupStates (& $Prop $_ 'State')
                            OwnerNode = & $Prop $_ 'OwnerNode'
                            GroupType = & $Map $GroupTypes (& $Prop $_ 'GroupType')
                        }
                    } | Sort-Object -Property Name
                )
                Networks = @(
                    Get-CimInstance -Namespace $Namespace -ClassName MSCluster_Network @script:EA1 | ForEach-Object {
                        [pscustomobject][ordered]@{
                            Name        = $_.Name
                            Address     = & $Prop $_ 'Address'
                            AddressMask = & $Prop $_ 'AddressMask'
                            Role        = & $Map $NetRoles (& $Prop $_ 'Role')
                            State       = & $Map $NetStates (& $Prop $_ 'State')
                        }
                    }
                )
            }
        }
    } Else {
        $null
    }

    $CA         = If (& $ServiceExists 'CertSvc') {
        & $Collect 'CertificateAuthority' {
            $ConfigKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
            $Active    = & $Prop (Get-ItemProperty -Path $ConfigKey @script:EA0) 'Active'
            $CAType    = If ($Active) { & $Prop (Get-ItemProperty -Path (Join-Path -Path $ConfigKey -ChildPath $Active) @script:EA0) 'CAType' } Else { $null }

            [pscustomobject][ordered]@{
                Name    = $Active
                Type    = Switch ($CAType) {
                    0       { 'Enterprise Root' }
                    1       { 'Enterprise Subordinate' }
                    3       { 'Standalone Root' }
                    4       { 'Standalone Subordinate' }
                    Default { $null }
                }
                Service = [string](Get-Service -Name CertSvc @script:EA1).Status
            }
        }
    } Else {
        $null
    }

    $SQL        = & $Collect 'SQLServer' {
        @(
            Get-Service @script:EA0 | Where-Object {
                $_.Name -match '^(MSSQLSERVER|MSSQL\$.+)$'
            } | ForEach-Object {
                [pscustomobject][ordered]@{
                    Instance  = If ($_.Name -eq 'MSSQLSERVER') { 'MSSQLSERVER (default)' } Else { $_.Name.Substring(6) }
                    Service   = $_.Name
                    Status    = [string]$_.Status
                    StartType = [string]$_.StartType
                }
            }
        )
    }
    #endregion

    #region Optional Updates and Event Logs
    $Updates = If ($IncludeUpdates -and (& $Available 'Get-HotFix')) {
        & $Collect 'HotFixes' {
            @(
                Get-HotFix @script:EA1 | ForEach-Object {
                    $HotFix      = $_
                    $InstalledOn = $null
                    Try {
                        $InstalledOn = $HotFix.InstalledOn
                    } Catch {
                        Write-Verbose -Message ('Unreadable InstalledOn for {0}' -f $HotFix.HotFixID)
                    }

                    [pscustomobject][ordered]@{
                        HotFixID    = $HotFix.HotFixID
                        Description = $HotFix.Description
                        InstalledBy = $HotFix.InstalledBy
                        InstalledOn = $InstalledOn
                    }
                } | Sort-Object -Property InstalledOn -Descending
            )
        }
    } Else {
        $null
    }

    $Logs    = If ($IncludeLogs) {
        & $Collect 'EventLogs' {
            $Result = [ordered]@{}

            ForEach ($LogName in 'System','Application') {
                Try {
                    $Result[$LogName] = @(
                        Get-WinEvent -FilterHashtable @{
                            LogName   = $LogName
                            Level     = 1,2
                            StartTime = (Get-Date).AddDays(-30)
                        } -MaxEvents $LogCount @script:EA1 | Select-Object -Property TimeCreated, Id, LevelDisplayName, ProviderName, @{
                            N = 'Message'
                            E = {
                                $Text = [string]$_.Message
                                If ($Text.Length -gt 600) { $Text.Substring(0,600) + '...' } Else { $Text }
                            }
                        }
                    )
                } Catch {
                    If ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') {
                        $Result[$LogName] = @()
                    } Else {
                        & $AddError ('EventLog-{0}' -f $LogName) $_
                        $Result[$LogName] = $null
                    }
                }
            }

            $Result['ReadLimit'] = $LogCount

            [pscustomobject]$Result
        }
    } Else {
        $null
    }
    #endregion

    #region SMB1
    $SMB1 = & $Collect 'SMB1' {
        $ServerEnabled = $null
        If (& $Available 'Get-SmbServerConfiguration') {
            $ServerEnabled = [bool](Get-SmbServerConfiguration @script:EA1).EnableSMB1Protocol
        }

        $FeatureInstalled = [bool](
            @($Features | Where-Object { $_ -and $_.Name -in 'FS-SMB1','FS-SMB1-SERVER' }).Count -or
            @($OptionalFeatures | Where-Object { $_ -and $_.FeatureName -in 'SMB1Protocol','SMB1Protocol-Server' }).Count
        )

        [pscustomobject][ordered]@{
            ServerProtocolEnabled = $ServerEnabled
            FeatureInstalled      = $FeatureInstalled
        }
    }
    #endregion

    #region Derived Roles
    <#
        LESSON 18: Collect raw data first, then draw conclusions from it
        Everything above gathers facts. Roles and Posture interpret them ("this is a DHCP server,
        and one scope is 93% full"), so the rules live in one place and are easy to change.
        Generic.List[object] grows in place as items are added, whereas $Array += $Item copies
        the whole array every time. ToArray() converts the list once, at the end.
    #>
    $Roles   = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $AddRole = {
        Param ([string]$Role,[string]$Detail,[string]$Status = 'OK')
        $Roles.Add(
            [pscustomobject][ordered]@{
                Role   = $Role
                Detail = $Detail
                Status = $Status
            }
        )
    }

    If ($AD) {
        $Failures = @($AD.ReplicationPartners | Where-Object { $_ -and $_.ConsecutiveReplicationFailures -gt 0 }).Count
        $Parts    = @(
            ('Site {0}' -f $AD.Site)
            If ($AD.IsGlobalCatalog) { 'Global Catalog' }
            If ($AD.IsReadOnly)      { 'Read-only' }
            If (@($AD.FSMORoles).Count) { 'FSMO: {0}' -f (@($AD.FSMORoles) -join ', ') }
            If ($Failures)           { '{0} failing' -f (& $Plural $Failures 'replication partner') }
        )
        & $AddRole 'Domain controller' ($Parts -join ' | ') $(If ($Failures) { 'Warning' } Else { 'OK' })
    } ElseIf ($OSType -eq 'Domain Controller') {
        & $AddRole 'Domain controller' 'AD module unavailable; details not collected' 'Neutral'
    }

    If ($HyperV) {
        $Running = @($HyperV.VMs | Where-Object { $_.State -eq 'Running' }).Count
        & $AddRole 'Hyper-V host' ('{0}, {1} running | {2}' -f (& $Plural @($HyperV.VMs).Count 'VM'),$Running,(& $Plural @($HyperV.Switches).Count 'virtual switch'))
    }

    If ($Clustering -and $Clustering.Cluster) {
        $Down   = @($Clustering.Nodes | Where-Object { $_.State -ne 'Up' }).Count
        $Detail = '{0} | {1}, {2}' -f $Clustering.Cluster.Name,(& $Plural @($Clustering.Nodes).Count 'node'),(& $Plural @($Clustering.Roles).Count 'role')
        If ($Down) { $Detail += ' | {0} not up' -f (& $Plural $Down 'node') }
        & $AddRole 'Failover cluster node' $Detail $(If ($Down) { 'Warning' } Else { 'OK' })
    }

    If (@($SQL).Count) {
        $Stopped = @($SQL | Where-Object { $_.Status -ne 'Running' -and $_.StartType -eq 'Automatic' }).Count
        & $AddRole 'SQL Server' ((@($SQL | ForEach-Object { '{0} ({1})' -f $_.Instance,$_.Status }) -join ', ')) $(If ($Stopped) { 'Warning' } Else { 'OK' })
    }

    If ($CA) {
        & $AddRole 'Certificate authority' ((@($CA.Name,$CA.Type) | Where-Object { $_ }) -join ' | ') $(If ($CA.Service -ne 'Running') { 'Warning' } Else { 'OK' })
    }

    If ($IIS) {
        $AutoStart = @($IIS.Sites | Where-Object { $_.AutoStart }).Count
        & $AddRole 'Web server (IIS)' ('{0}, {1} set to auto-start | {2} | Service {3}' -f (& $Plural @($IIS.Sites).Count 'site'),$AutoStart,(& $Plural @($IIS.AppPools).Count 'app pool'),$IIS.Service) $(If ($IIS.Service -ne 'Running') { 'Warning' } Else { 'OK' })
    }

    $UserShares = @($Shares | Where-Object { $_ -and -not $_.IsSystem })
    If ($UserShares.Count) {
        & $AddRole 'File server' ('{0}: {1}' -f (& $Plural $UserShares.Count 'share'),((@($UserShares | Select-Object -First 4 -ExpandProperty Name) -join ', ') + $(If ($UserShares.Count -gt 4) { ', ...' } Else { '' })))
    }

    If (@($SharedPrinters).Count) {
        & $AddRole 'Print server' (& $Plural @($SharedPrinters).Count 'shared printer')
    }

    If ($DNS) {
        $Primary = @($DNS.Zones | Where-Object { $_.ZoneType -eq 'Primary' }).Count
        & $AddRole 'DNS server' ('{0}, {1} primary' -f (& $Plural @($DNS.Zones).Count 'zone'),$Primary)
    }

    If ($DHCP) {
        $Active = @($DHCP | Where-Object { $_.State -eq 'Active' }).Count
        $Full   = @($DHCP | Where-Object { $null -ne $_.PercentInUse -and $_.PercentInUse -ge 90 }).Count
        $Detail = '{0}, {1} active' -f (& $Plural @($DHCP).Count 'scope'),$Active
        If ($Full) { $Detail += ' | {0} at 90%+ in use' -f (& $Plural $Full 'scope') }
        & $AddRole 'DHCP server' $Detail $(If ($Full) { 'Warning' } Else { 'OK' })
    }

    If ($RRAS) {
        & $AddRole 'Remote access (RRAS)' ('Service {0}' -f $RRAS.Status)
    }

    $FeatureRoles = [ordered]@{
        'RDS-RD-Server'      = 'Remote Desktop Session Host'
        'RDS-Licensing'      = 'Remote Desktop Licensing'
        'UpdateServices'     = 'WSUS'
        'WDS'                = 'Windows Deployment Services'
        'NPAS'               = 'Network Policy Server'
        'FS-DFS-Namespace'   = 'DFS Namespaces'
        'FS-DFS-Replication' = 'DFS Replication'
    }

    ForEach ($Key in $FeatureRoles.Keys) {
        If (& $HasFeature $Key) {
            & $AddRole $FeatureRoles[$Key] 'Installed role or feature'
        }
    }

    If ($Roles.Count -eq 0) {
        $Detail = If ($OSType -eq 'Workstation') {
            'No server roles; general-purpose workstation'
        } Else {
            'No recognised server roles detected'
        }
        & $AddRole ('{0}' -f $(If ($OSType -eq 'Workstation') { 'Workstation' } Else { 'Member server' })) $Detail 'Neutral'
    }
    #endregion

    #region Derived Posture
    $Posture   = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $AddCheck  = {
        Param ([string]$Check,[string]$Value,[string]$Status)

        $Posture.Add(
            [pscustomobject][ordered]@{
                Check  = $Check
                Value  = $Value
                Status = $Status
            }
        )
    }
    $IsServer  = $OSType -ne 'Workstation'
    $Unknown   = If ($IsElevated) { 'Unknown' } Else { 'Unknown (run elevated)' }

    If ($PendingReboot) {
        If ($PendingReboot.Any) {
            & $AddCheck 'Pending reboot' ('Yes: {0}' -f (@($PendingReboot.Reasons) -join ', ')) 'Warning'
        } Else {
            & $AddCheck 'Pending reboot' 'No' 'OK'
        }
    }

    If ($null -ne $UptimeHrs) {
        $Days = [math]::Floor($UptimeHrs / 24)
        & $AddCheck 'Uptime' (& $Plural $Days 'day') $(If ($Days -ge 60) { 'Warning' } Else { 'OK' })
    }

    If ($SecureBoot) {
        $Status = Switch -Regex ($SecureBoot) {
            '^Enabled'  { 'OK' }
            '^Disabled' { 'Warning' }
            '^Not supp' { 'Warning' }
            Default     { 'Neutral' }
        }
        & $AddCheck 'Secure Boot' $SecureBoot $Status
    }

    If ($TPM) {
        If (-not $TPM.TpmPresent) {
            & $AddCheck 'TPM' 'Not present' $(If ($IsServer) { 'Neutral' } Else { 'Warning' })
        } ElseIf ($TPM.TpmReady) {
            $Maker = (@($TPM.ManufacturerIdTxt,$TPM.ManufacturerVersion) | Where-Object { $_ }) -join ' '
            & $AddCheck 'TPM' ('Ready{0}' -f $(If ($Maker) { (' ({0})' -f $Maker) } Else { '' })) 'OK'
        } Else {
            & $AddCheck 'TPM' 'Present, not ready' 'Warning'
        }
    } Else {
        & $AddCheck 'TPM' $Unknown 'Neutral'
    }

    $OSVolume = @($BitLocker | Where-Object { $_ -and $_.VolumeType -eq 'OperatingSystem' }) | Select-Object -First 1
    If ($OSVolume) {
        If ($OSVolume.ProtectionStatus -eq 'On') {
            & $AddCheck 'BitLocker (OS drive)' ('On, {0}% encrypted' -f $OSVolume.EncryptionPercentage) 'OK'
        } Else {
            & $AddCheck 'BitLocker (OS drive)' ('Off ({0})' -f $OSVolume.VolumeStatus) $(If ($IsServer) { 'Neutral' } Else { 'Warning' })
        }
    } ElseIf (-not $IsServer) {
        & $AddCheck 'BitLocker (OS drive)' $Unknown 'Neutral'
    }

    $FixedVolumes = @(
        $Volumes | Where-Object {
            $null -ne $_ -and
            $_.DriveType -eq 'Fixed' -and
            $_.DriveLetter -and
            $_.Size -gt 0
        }
    )

    If ($FixedVolumes.Count) {
        $LowVolumes = @($FixedVolumes | Where-Object { $_.FreePercent -lt 10 } | Sort-Object -Property FreePercent)

        If ($LowVolumes.Count) {
            $LowText = @(
                $LowVolumes | ForEach-Object {
                    '{0}: {1}% free ({2} GB)' -f $_.DriveLetter,$_.FreePercent,[math]::Round(([double]$_.SizeRemaining / 1GB),1)
                }
            ) -join ', '

            & $AddCheck 'Disk space' $LowText $(If ($LowVolumes[0].FreePercent -lt 5) { 'Critical' } Else { 'Warning' })
        } Else {
            $Lowest = $FixedVolumes | Sort-Object -Property FreePercent | Select-Object -First 1
            & $AddCheck 'Disk space' ('Lowest {0}: {1}% free' -f $Lowest.DriveLetter,$Lowest.FreePercent) 'OK'
        }
    }

    If ($SMB1) {
        If ($SMB1.ServerProtocolEnabled) {
            & $AddCheck 'SMB1' 'Enabled' 'Warning'
        } ElseIf ($SMB1.FeatureInstalled) {
            & $AddCheck 'SMB1' 'Installed; server protocol off' 'Warning'
        } Else {
            & $AddCheck 'SMB1' 'Not installed' 'OK'
        }
    }

    $UserShares = @($Shares | Where-Object { $null -ne $_ -and -not $_.IsSystem })
    If ($UserShares.Count -and $IncludeShareACL) {
        $OpenShares = @(
            ForEach ($Share in $UserShares) {
                $Open = @(
                    $Share.ShareACL | Where-Object {
                        $null -ne $_ -and
                        $_.AccountName -eq 'Everyone' -and
                        $_.AccessControlType -eq 'Allow' -and
                        $_.AccessRight -in 'Full','Change'
                    }
                )

                If ($Open.Count) {
                    '{0} (Everyone: {1})' -f $Share.Name,$Open[0].AccessRight
                }
            }
        )

        If ($OpenShares.Count) {
            & $AddCheck 'Shares writable by Everyone' ($OpenShares -join ', ') 'Warning'
        } Else {
            & $AddCheck 'Shares writable by Everyone' 'None' 'OK'
        }
    }

    If (@($Firewall).Count) {
        $Off = @($Firewall | Where-Object { $_ -and $_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
        If ($Off.Count) {
            & $AddCheck 'Windows Firewall' ('Off: {0}' -f ($Off -join ', ')) 'Warning'
        } Else {
            & $AddCheck 'Windows Firewall' 'All profiles on' 'OK'
        }
    }

    If ($TimeService) {
        $Source = $TimeService.Source
        If ([string]::IsNullOrWhiteSpace($Source)) {
            & $AddCheck 'Time source' ('Service {0}; source {1}' -f $TimeService.Status,$Unknown.ToLower()) 'Neutral'
        } ElseIf ($Source -match '(?i)Local CMOS Clock|Free-running') {
            & $AddCheck 'Time source' $Source 'Warning'
        } Else {
            & $AddCheck 'Time source' $Source 'OK'
        }
    }

    If ($null -ne $LocalAdmins) {
        & $AddCheck 'Local administrators' (& $Plural @($LocalAdmins).Count 'member') 'Neutral'
    }

    If ($Logs) {
        $Since  = (Get-Date).AddDays(-7)
        $Capped = [bool](@($Logs.System).Count -ge $LogCount -or @($Logs.Application).Count -ge $LogCount)
        $Recent = @(
            @($Logs.System) + @($Logs.Application) | Where-Object { $_ -and $_.TimeCreated -ge $Since }
        ).Count

        $RecentText = & $Plural $Recent 'critical or error event'
        If ($Capped) {
            ### The read limit was reached, so the real number is at least this many.
            $RecentText = $RecentText -replace '^(\d+)','$1+'
        }

        & $AddCheck 'Errors, last 7 days' $RecentText $(If ($Recent -ge 25) { 'Warning' } Else { 'Neutral' })
    }

    & $AddCheck 'Run as administrator' $(If ($IsElevated) { 'Yes' } Else { 'No; some checks are incomplete' }) $(If ($IsElevated) { 'OK' } Else { 'Warning' })

    If ($CollectionErrors.Count) {
        & $AddCheck 'Collection gaps' ('{0} could not be read' -f (& $Plural $CollectionErrors.Count 'category')) 'Warning'
    }
    #endregion

    #region Structured Result
    <#
        LESSON 19: Return one structured object
        The function writes nothing to the screen, files or email. It returns one object, and the
        HTML report, console view and JSON file all read that same object. [ordered] keeps the
        properties in a predictable order in the JSON file. @( ) keeps list properties as arrays,
        so ConvertTo-Json writes ["x"] even when there is only one item; without it, a single item
        would be written as a plain value and the file's shape would change between machines.
    #>
    [pscustomobject][ordered]@{
        Hostname              = $env:COMPUTERNAME
        CollectedAt           = $CollectedAt
        Roles                 = @($Roles.ToArray())
        Posture               = @($Posture.ToArray())
        System                = $System
        Chassis               = $Enclosure
        Baseboard             = $Board
        Processors            = $CPU
        MemoryModules         = $DIMMs
        PhysicalDisks         = $PhysicalDisks
        DiskDrives            = $DiskDrives
        Disks                 = $Disks
        Partitions            = $Partitions
        Volumes               = $Volumes
        StoragePools          = $StoragePools
        VirtualDisks          = $VirtualDisks
        NetworkAdapters       = $NICs
        IPAddresses           = $IPAddresses
        IPConfiguration       = $IPConfiguration
        AdapterVLANProperties = $NetVLAN
        PnPDevices            = $PnPDevices
        TPM                   = $TPM
        SecureBoot            = $SecureBoot
        BitLocker             = $BitLocker
        FirewallProfiles      = $Firewall
        Battery               = $Power
        WindowsTime           = $TimeService
        PendingReboot         = $PendingReboot
        Services              = $Services
        ScheduledTasks        = $Tasks
        InstalledSoftware     = $Software
        LocalUsers            = $LocalUsers
        LocalGroups           = $LocalGroups
        LocalAdministrators   = $LocalAdmins
        FileShares            = $Shares
        SMB1                  = $SMB1
        SharedPrinters        = $SharedPrinters
        WindowsFeatures       = $Features
        OptionalFeatures      = $OptionalFeatures
        WindowsCapabilities   = $Capabilities
        HyperV                = $HyperV
        DNS                   = $DNS
        DHCP                  = $DHCP
        ActiveDirectory       = $AD
        IIS                   = $IIS
        RRAS                  = $RRAS
        Clustering            = $Clustering
        CertificateAuthority  = $CA
        SQLServer             = $SQL
        HotFixes              = $Updates
        EventLogs             = $Logs
        CollectionErrors      = @($CollectionErrors.ToArray())
    }
    #endregion
} ### Lessons

Function Register-PSDiscoveryProtocol {
    <#
        .SYNOPSIS
        Defines the embedded CDP/LLDP discovery functions in the caller's scope.

        .DESCRIPTION
        Contains a self-contained copy of the discovery-protocol capture and parsing logic: the
        DiscoveryProtocolPacket class, Invoke-DiscoveryProtocolCapture, Get-DiscoveryProtocolData,
        ConvertFrom-CDPPacket, ConvertFrom-LLDPPacket and Export-Pcap. Capture uses the inbox
        NetEventPacketCapture provider; no external module or executable is required.

        The functions are defined inside this function's scope, so it must be dot-sourced for them
        to remain available to the caller.

        .EXAMPLE
        . Register-PSDiscoveryProtocol
        $Packets = Invoke-DiscoveryProtocolCapture -Type LLDP -Duration 35

        .OUTPUTS
        None
    #>
    #region classes
    <#
        LESSON 1: A function whose job is to define other functions
        Everything below defines things; nothing runs until it is called. Functions and classes
        defined inside a function belong to that function's scope and disappear when it returns.
        Calling Register-PSDiscoveryProtocol normally would define everything and then throw it
        away. Dot-sourcing it (. Register-PSDiscoveryProtocol) runs it in the CALLER's scope, so
        the definitions stay.
    #>
    <#
        DiscoveryProtocolPacket wraps one captured Ethernet frame from the NetEventPacketCapture ETL
        file and adds script properties that identify CDP (SNAP type 0x2000) and LLDP (EtherType
        0x88CC) frames and expose the sender's MAC address. Comment-based help is not supported on
        PowerShell classes, so the class is documented here.
    #>
    class DiscoveryProtocolPacket {
        <#
            LESSON 2: Classes and constructors
            A class declares typed properties ([string]$MachineName, [byte[]]$Fragment); PowerShell
            converts values to those types when they are assigned. A method with the class's own
            name is a constructor: it runs when an object is created, and $this refers to the new
            object. Because this constructor takes one [PSCustomObject], PowerShell can convert
            event objects into packets in a single step: $Events -as [DiscoveryProtocolPacket[]]
            (Lesson 10).
        #>
        [string]$MachineName
        [datetime]$TimeCreated
        [int]$FragmentSize
        [byte[]]$Fragment
        [int]$MiniportIfIndex
        [string]$Connection
        [string]$Interface

        DiscoveryProtocolPacket([PSCustomObject]$WinEvent) {
            $this.MachineName     = $WinEvent.MachineName
            $this.TimeCreated     = $WinEvent.TimeCreated
            $this.FragmentSize    = $WinEvent.FragmentSize
            $this.Fragment        = $WinEvent.Fragment
            $this.MiniportIfIndex = $WinEvent.MiniportIfIndex
            $this.Connection      = $WinEvent.Connection
            $this.Interface       = $WinEvent.Interface

            <#
                LESSON 3: A property whose value is computed by a scriptblock
                Add-Member -MemberType ScriptProperty attaches a property whose value is a
                scriptblock. PowerShell runs it every time the property is READ, with $this as the
                object, so the result always reflects the current Fragment bytes. Compare
                Add-Member -NotePropertyName (used in Get-DiscoveryProtocolData), which stores a
                fixed value once, and a Select-Object calculated property, which runs once while
                selecting.
                Byte order: $this.Fragment[21..20] lists bytes 21 then 20, a reversed range.
                Network packets store numbers big-endian, and BitConverter reads little-endian on
                Windows, so reversing the two bytes makes 0x88CC (LLDP) read correctly.
            #>
            Add-Member -InputObject $this -MemberType ScriptProperty -Name IsDiscoveryProtocolPacket -Value {
                If (
                    [UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0) -or
                    [UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)
                ) {
                    Return [bool]$true
                } Else {
                    Return [bool]$false
                }
            }

            Add-Member -InputObject $this -MemberType ScriptProperty -Name DiscoveryProtocolType -Value {
                If ([UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0)) {
                    Return [string]'CDP'
                } ElseIf ([UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)) {
                    Return [string]'LLDP'
                } Else {
                    Return [string]::Empty
                }
            }

            Add-Member -InputObject $this -MemberType ScriptProperty -Name SourceAddress -Value {
                [PhysicalAddress]::new($this.Fragment[6..11]).ToString()
            }
        }
    }
    #endregion

    Function Invoke-DiscoveryProtocolCapture {
        <#
            .SYNOPSIS
            Capture CDP or LLDP packets on local or remote computers

            .DESCRIPTION
            Capture discovery protocol packets on local or remote computers. This function will start a packet capture and save the
            captured packets in a temporary ETL file. The first qualifying discovery protocol packet per interface is returned.

            Cisco devices will by default send CDP announcements every 60 seconds. Default interval for LLDP packets is 30 seconds.

            Requires elevation (Run as Administrator) for local capture.
            WinRM and PowerShell remoting must be enabled on target computer for remote capture.

            .PARAMETER ComputerName
            Specifies one or more computers on which to capture packets. Defaults to $env:COMPUTERNAME.

            If specified, remote capture is assumed and therefore WinRM must be enabled on target.

            .PARAMETER Duration
            Specifies the duration for which the discovery protocol packets are captured, in seconds.

            If Type is LLDP, Duration defaults to 32. If Type is CDP or omitted, Duration defaults to 62.

            .PARAMETER Type
            Specifies what type of packet to capture, CDP or LLDP. If omitted, both types will be captured,
            but only the first one will be returned.

            If Type is LLDP, Duration defaults to 32. If Type is CDP or omitted, Duration defaults to 62.

            .PARAMETER NoCleanup
            If specified, the ETL file will not be deleted from %TEMP%.

            .PARAMETER Credential
            Use this with remote capture if current user do not have administrative privileges on the target computer.

            .OUTPUTS
            DiscoveryProtocolPacket

            .EXAMPLE
            PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type CDP -Duration 60
            PS C:\> Get-DiscoveryProtocolData -Packet $Packet

            Port      : FastEthernet0/1
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 10
            Computer  : COMPUTER1
            Type      : CDP

            .EXAMPLE
            PS C:\> Invoke-DiscoveryProtocolCapture -Computer COMPUTER1 | Get-DiscoveryProtocolData

            Port      : FastEthernet0/1
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 10
            Computer  : COMPUTER1
            Type      : CDP

            .EXAMPLE
            PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Get-DiscoveryProtocolData

            Port      : FastEthernet0/1
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 10
            Computer  : COMPUTER1
            Type      : CDP

            Port      : FastEthernet0/2
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 20
            Computer  : COMPUTER2
            Type      : CDP
        #>
        [CmdletBinding(DefaultParameterSetName = 'LocalCapture')]
        [OutputType('DiscoveryProtocolPacket')]
        [Alias('Capture-CDPPacket', 'Capture-LLDPPacket')]
        Param (
            [Parameter(ParameterSetName = 'RemoteCapture', Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
            [Alias('CN', 'Computer')]
            [String[]]$ComputerName = $env:COMPUTERNAME,

            [Parameter(ParameterSetName = 'LocalCapture', Position = 0)]
            [Parameter(ParameterSetName = 'RemoteCapture', Position = 1)]
            [Int16]$Duration = $(If ($Type -eq 'LLDP') { 32 } Else { 62 }),

            [Parameter(ParameterSetName = 'LocalCapture', Position = 1)]
            [Parameter(ParameterSetName = 'RemoteCapture', Position = 2)]
            [ValidateSet('CDP', 'LLDP')]
            [String]$Type,

            [Parameter(ParameterSetName = 'RemoteCapture')]
            [ValidateNotNull()]
            [System.Management.Automation.Credential()]
            [PSCredential]$Credential = [pscredential]::Empty,

            [Parameter()]
            [switch]$NoCleanup
        )

        <#
            LESSON 4: Begin, Process and End
            A function that accepts pipeline input (ValueFromPipeline on -ComputerName) runs in
            three parts. Begin runs once, before the first input: here it checks elevation. Process
            runs once per item piped in, with that item bound to the parameter. End runs once, after
            the last item. Without these blocks, the function would see only the LAST piped item.
            Parameter sets: -ComputerName exists only in the RemoteCapture set, so a call without
            it uses LocalCapture (the DefaultParameterSetName). Position numbers differ between the
            sets, so the same positional argument binds to the right parameter in either mode.
        #>

        Begin {
            If ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
                $Identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
                $Principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $Identity
                If (-not $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                    Throw 'Invoke-DiscoveryProtocolCapture requires elevation. Please run PowerShell as administrator.'
                }
            }

            <#
                LESSON 5: Keeping old command names working
                [Alias('Capture-CDPPacket','Capture-LLDPPacket')] lets the old names still run
                this function. $MyInvocation.InvocationName is the name the caller actually typed,
                while $MyInvocation.MyCommand is the function's real name. When they differ, the
                caller used an old alias: the function picks the protocol from that name and warns
                that the alias is deprecated. This is a gentle way to rename a command without
                breaking existing scripts.
            #>
            If ($MyInvocation.InvocationName -ne $MyInvocation.MyCommand) {
                If ($MyInvocation.InvocationName -eq 'Capture-CDPPacket')  { $Type = 'CDP' }
                If ($MyInvocation.InvocationName -eq 'Capture-LLDPPacket') { $Type = 'LLDP' }
                $Warning = '{0} has been deprecated, please use {1}' -f $MyInvocation.InvocationName, $MyInvocation.MyCommand
                Write-Warning -Message $Warning
            }
        }
        Process {
            ForEach ($Computer in $ComputerName) {
                Write-Verbose -Message ('ParameterSetName: {0}' -f $PSCmdlet.ParameterSetName)
                Write-Verbose -Message ('TargetComputer: {0}' -f $Computer)

                <#
                    LESSON 6: Optional parameters by splatting an empty hashtable
                    The same commands run locally and remotely. For a local capture, $CimSession
                    and $PSSession are EMPTY hashtables, and splatting an empty hashtable passes
                    nothing. For a remote capture they contain CimSession = <session>, so every
                    command (Get-NetAdapter @CimSession, Invoke-Command @PSSession) targets the
                    remote computer. One code path serves both cases with no If around each command.
                #>
                If ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
                    $CimSession = @{}
                    $PSSession  = @{}
                } Else {
                    $PSCredential = @{}
                    If ($PSBoundParameters.ContainsKey('Credential')) {
                        $PSCredential.Add('Credential', $Credential)
                    }

                    Try {
                        $CimSession = @{CimSession = New-CimSession -ComputerName $Computer @script:EA1 @PSCredential}
                    } Catch [Microsoft.Management.Infrastructure.CimException] {
                        If ($_.CategoryInfo.Category -eq 'PermissionDenied') {
                            Write-Warning -Message ('Access Denied on {0}. You can try to connect using -Credential.' -f $Computer)
                        } ElseIf ($_.CategoryInfo.Category -eq 'ConnectionError') {
                            Write-Warning -Message ('Unable to create CimSession. Please make sure WinRM and PSRemoting is enabled on {0}.' -f $Computer)
                        } Else {
                            Write-Warning -Message $_.Exception.Message
                        }
                        Continue
                    } Catch {
                        Write-Warning -Message $_.Exception.Message
                        Continue
                    }

                    Try {
                        $PSSession = @{Session = New-PSSession -ComputerName $Computer @script:EA1 @PSCredential}
                    } Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                        If ($_.Exception.ErrorCode -eq 5) {
                            Write-Warning -Message ('Access Denied on {0}. You can try to connect using -Credential.' -f $Computer)
                        } ElseIf ($_.Exception.ErrorCode -eq -2144108526) {
                            Write-Warning -Message ('Unable to create CimSession. Please make sure WinRM and PSRemoting is enabled on {0}.' -f $Computer)
                        } Else {
                            Write-Warning -Message $_.Exception.Message
                        }
                        Continue
                    } Catch {
                        Write-Warning -Message $_.Exception.Message
                        Continue
                    }
                }

                $ETLFilePath = Invoke-Command @PSSession -ScriptBlock {
                    $TempFile = New-TemporaryFile
                    $ETLFile  = Rename-Item -Path $TempFile.FullName -NewName $TempFile.FullName.Replace('.tmp', '.etl') -PassThru
                    $ETLFile.FullName
                }

                Write-Verbose -Message ('ETLFilePath: {0}' -f $ETLFilePath)

                $Adapters = Get-NetAdapter @CimSession | Where-Object {
                    $_.Status -eq 'Up' -and 
                    $_.InterfaceType -eq 6
                } | Select-Object -Property Name, MacAddress, InterfaceDescription, InterfaceIndex

                If ($Adapters) {
                    <#
                        LESSON 7: Member enumeration and the .ForEach() method
                        $Adapters.MacAddress reads MacAddress from EVERY adapter in the array and
                        returns them all; this is member enumeration. .ForEach({ ... }) runs the
                        scriptblock for each element and is faster than piping to ForEach-Object.
                        [PhysicalAddress]::Parse() accepts MAC text in several formats, so the
                        comparison later is format-independent.
                        The session name includes a GUID (globally unique identifier) so it can
                        never collide with another capture session on the machine.
                    #>
                    $MACAddresses = $Adapters.MacAddress.ForEach({ [PhysicalAddress]::Parse($_).ToString() })
                    $SessionName  = 'Discovery-{0}' -f [guid]::NewGuid().ToString('N')

                    Try {
                        $null = New-NetEventSession -Name $SessionName -LocalFilePath $ETLFilePath -CaptureMode SaveToFile @CimSession @script:EA1
                    } Catch [Microsoft.Management.Infrastructure.CimException] {
                        If ($_.Exception.NativeErrorCode -eq 'AlreadyExists') {
                            $Message = 'Another NetEventSession already exists. Run Invoke-DiscoveryProtocolCapture with -Force switch to remove existing NetEventSessions.'
                            Write-Warning -Message $Message
                        } Else {
                            Write-Warning -Message $_.Exception.Message
                        }
                        Continue
                    }

                    <#
                        LESSON 8: Filter at the source, and a Switch branch with several values
                        CDP and LLDP frames are sent to fixed multicast MAC addresses. Passing only
                        those addresses to the capture provider means Windows records just the
                        discovery frames, not all network traffic. A Switch branch can output
                        several values, so 'LLDP' produces three addresses, and $LinkLayerAddress
                        becomes an array.
                    #>
                    $LinkLayerAddress = Switch ($Type) {
                        'CDP'   { '01-00-0c-cc-cc-cc' }
                        'LLDP'  { '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                        Default { '01-00-0c-cc-cc-cc', '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                    }

                    $PacketCaptureParams = @{
                        SessionName      = $SessionName
                        TruncationLength = 0
                        CaptureType      = 'Physical'
                        LinkLayerAddress = $LinkLayerAddress
                    }

                    Try {
                        $null = Add-NetEventPacketCaptureProvider @PacketCaptureParams @CimSession

                        ForEach ($Adapter in $Adapters) {
                            $null = Add-NetEventNetworkAdapter -Name $Adapter.Name -PromiscuousMode $True @CimSession
                        }

                        Start-NetEventSession -Name $SessionName @CimSession

                        $Seconds = $Duration
                        $End     = (Get-Date).AddSeconds($Seconds)
                        While ($End -gt (Get-Date)) {
                            $SecondsLeft = $End.Subtract((Get-Date)).TotalSeconds
                            $Percent     = ($Seconds - $SecondsLeft) / $Seconds * 100
                            Write-Progress -Activity 'Discovery Protocol Packet Capture' -Status (
                                'Capturing on {0}...' -f $Computer
                            ) -SecondsRemaining $SecondsLeft -PercentComplete $Percent
                            [System.Threading.Thread]::Sleep(500)
                        }

                        Stop-NetEventSession -Name $SessionName @CimSession

                        $Events = Invoke-Command @PSSession -ScriptBlock {
                            Param ($ETLFilePath)

                            Try {
                                $Events = Get-WinEvent -Path $ETLFilePath -Oldest -FilterXPath '*[System[EventID=1001]]' -ErrorAction Stop
                            } Catch {
                                If ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                                    Write-Warning -Message $_.Exception.Message
                                }
                            }

                            [string[]]$XpathQueries = @(
                                "Event/EventData/Data[@Name='FragmentSize']"
                                "Event/EventData/Data[@Name='Fragment']"
                                "Event/EventData/Data[@Name='MiniportIfIndex']"
                            )

                            $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($XpathQueries)

                            ForEach ($WinEvent in $Events) {
                                $EventData = $WinEvent | Select-Object -Property MachineName, TimeCreated
                                $EventData | Add-Member -NotePropertyName FragmentSize -NotePropertyValue $null
                                $EventData | Add-Member -NotePropertyName Fragment -NotePropertyValue $null
                                $EventData | Add-Member -NotePropertyName MiniportIfIndex -NotePropertyValue $null
                                $EventData.FragmentSize, $EventData.Fragment, $EventData.MiniportIfIndex = $WinEvent.GetPropertyValues($PropertySelector)

                                $Adapter = @(Get-NetAdapter).Where({ $_.InterfaceIndex -eq $EventData.MiniportIfIndex })
                                $EventData | Add-Member -NotePropertyName Connection -NotePropertyValue $Adapter.Name
                                $EventData | Add-Member -NotePropertyName Interface -NotePropertyValue $Adapter.InterfaceDescription
                                $EventData
                            }
                        } -ArgumentList $ETLFilePath

                        <#
                            LESSON 9: Convert a whole array with -as
                            -as [DiscoveryProtocolPacket[]] converts every event using the class
                            constructor from Lesson 2. Unlike a [Type] cast, -as returns $null
                            instead of throwing when conversion is impossible. The filter keeps real
                            discovery frames that were not sent by this computer.
                            Group-Object -Property MiniportIfIndex groups the packets by network
                            adapter, and Select-Object -First 1 keeps one packet per adapter.
                        #>
                        $FoundPackets = $Events -as [DiscoveryProtocolPacket[]] | Where-Object {
                            $_.IsDiscoveryProtocolPacket -and 
                            $_.SourceAddress -notin $MACAddresses
                        } | Group-Object -Property MiniportIfIndex | ForEach-Object {
                            $_.Group | Select-Object -First 1
                        }

                    } Finally {
                        <#
                            LESSON 10: Clean up resources that outlive your script
                            A NetEventSession is not a PowerShell object that vanishes when the
                            script ends. It is a Windows capture session that keeps running, and it
                            leaves the adapters in promiscuous mode, until someone stops it. Finally
                            guarantees it is stopped and removed even if the capture fails or the
                            user presses Ctrl+C. The temporary ETL file is deleted here as well.
                        #>
                        $Session = Get-NetEventSession -Name $SessionName @CimSession @script:EA0
                        If ($Session) {
                            If ($Session.SessionStatus -eq 'Running') {
                                Stop-NetEventSession -Name $SessionName @CimSession @script:EA0
                            }
                            Remove-NetEventSession -Name $SessionName @CimSession @script:EA0
                        }

                        If (-not $NoCleanup) {
                            Invoke-Command @PSSession -ScriptBlock {
                                Param($Path)
                                Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
                            } -ArgumentList $ETLFilePath
                        }
                    }

                    If ($FoundPackets) {
                        $FoundPackets
                    } Else {
                        Write-Verbose -Message ('No discovery protocol packets captured on {0} in {1} seconds.' -f $Computer, $Seconds)
                    }
                } Else {
                    Write-Warning -Message ('Unable to find a connected wired adapter on {0}.' -f $Computer)
                    Return
                }
            }
        }
        End {}
    }

    Function Get-DiscoveryProtocolData {
        <#
            .SYNOPSIS
            Parse CDP or LLDP packets captured by Invoke-DiscoveryProtocolCapture

            .DESCRIPTION
            Gets computername, type and packet details from a DiscoveryProtocolPacket.

            Calls ConvertFrom-CDPPacket or ConvertFrom-LLDPPacket to extract packet details
            from a byte array.

            .PARAMETER Packet
            Specifies an object of type DiscoveryProtocolPacket.

            .EXAMPLE
            PS C:\> $Packet = Invoke-DiscoveryProtocolCapture
            PS C:\> Get-DiscoveryProtocolData -Packet $Packet

            Port      : FastEthernet0/1
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 10
            Computer  : COMPUTER1
            Type      : CDP

            .EXAMPLE
            PS C:\> Invoke-DiscoveryProtocolCapture -Computer COMPUTER1 | Get-DiscoveryProtocolData

            Port      : FastEthernet0/1
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 10
            Computer  : COMPUTER1
            Type      : CDP

            .EXAMPLE
            PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Get-DiscoveryProtocolData

            Port      : FastEthernet0/1
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 10
            Computer  : COMPUTER1
            Type      : CDP

            Port      : FastEthernet0/2
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 20
            Computer  : COMPUTER2
            Type      : CDP
        #>
        [CmdletBinding()]
        [Alias('Parse-CDPPacket', 'Parse-LLDPPacket')]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Provide the DiscoveryProtocolPacket objects to decode.', ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
            [DiscoveryProtocolPacket[]]
            $Packet
        )

        Begin {
            If ($MyInvocation.InvocationName -ne $MyInvocation.MyCommand) {
                $Warning = '{0} has been deprecated, please use {1}' -f $MyInvocation.InvocationName, $MyInvocation.MyCommand
                Write-Warning -Message $Warning
            }
        }
        Process {
            ForEach ($Item in $Packet) {
                Switch ($Item.DiscoveryProtocolType) {
                    'CDP'   { $PacketData = ConvertFrom-CDPPacket -Packet $Item.Fragment }
                    'LLDP'  { $PacketData = ConvertFrom-LLDPPacket -Packet $Item.Fragment }
                    Default { Throw 'No valid CDP or LLDP found in $Packet' }
                }

                $PacketData | Add-Member -NotePropertyName Computer -NotePropertyValue $Item.MachineName
                $PacketData | Add-Member -NotePropertyName Connection -NotePropertyValue $Item.Connection
                $PacketData | Add-Member -NotePropertyName Interface -NotePropertyValue $Item.Interface
                $PacketData | Add-Member -NotePropertyName Type -NotePropertyValue $Item.DiscoveryProtocolType
                $PacketData
            }
        }
        End {}
    }

    Function ConvertFrom-CDPPacket {
        <#
            .SYNOPSIS
            Parse CDP packet.

            .DESCRIPTION
            Parse CDP packet to get port, device, model, ipaddress and vlan.

            This function is used by Get-DiscoveryProtocolData to parse the
            Fragment property of a DiscoveryProtocolPacket object.

            .PARAMETER Packet
            Raw CDP packet as byte array.

            This function is used by Get-DiscoveryProtocolData to parse the
            Fragment property of a DiscoveryProtocolPacket object.

            .EXAMPLE
            PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type CDP
            PS C:\> ConvertFrom-CDPPacket -Packet $Packet.Fragment

            Port      : FastEthernet0/1
            Device    : SWITCH1.domain.example
            Model     : cisco WS-C2960-48TT-L
            IPAddress : 192.0.2.10
            VLAN      : 10
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Raw CDP packet as byte array', Position = 0)]
            [byte[]]$Packet
        )

        $DASH        = '----------------------------------------------------------------'

        <#
            LESSON 11: Reading binary data in sequence
            A MemoryStream presents a byte array as a stream, and a BinaryReader reads it in order:
            each ReadBytes(n) returns the next n bytes and moves forward, so there is no offset
            arithmetic. CDP is big-endian, so two-byte numbers are read as ReadBytes(2)[1..0]
            (reversed) before BitConverter converts them. [PhysicalAddress] turns six bytes into a
            MAC address. (, $Packet) is the unary comma again: the byte array is passed as ONE
            constructor argument.
        #>
        $Stream      = New-Object -TypeName System.IO.MemoryStream -ArgumentList (, $Packet)
        $Reader      = New-Object -TypeName System.IO.BinaryReader -ArgumentList $Stream

        $Destination = [PhysicalAddress]$Reader.ReadBytes(6)
        $Source      = [PhysicalAddress]$Reader.ReadBytes(6)
        $Length      = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)

        $null        = $Reader.ReadBytes(6)

        $CDP         = [System.BitConverter]::ToString($Reader.ReadBytes(2))
        $Version     = $Reader.ReadByte()
        $TimeToLive  = $Reader.ReadByte()

        $null        = $Reader.ReadBytes(2)

        $Tlv         = @{
            0x0001 = 'Device'
            0x0002 = 'IPAddress'
            0x0003 = 'Port'
            0x0006 = 'Model'
            0x000A = 'VLAN'
            0x0016 = 'Management'
        }

        $TypeString  = 0x0001, 0x003, 0x006
        $TypeAddress = 0x0002, 0x0016
        $TypeInt     = 0x000A

        $IPv4        = 0xCC
        $IPv6        = 0xAAAA0300000086DD

        $Properties  = @{}

        Write-Verbose -Message ('Destination    : {0}' -f $Destination)
        Write-Verbose -Message ('Source         : {0}' -f $Source)
        Write-Verbose -Message ('Length         : {0}' -f $Length)
        Write-Verbose -Message ('Protocol ID    : {0}' -f $CDP)
        Write-Verbose -Message ('CDP Version    : {0}' -f $Version)
        Write-Verbose -Message ('Time To Live   : {0} seconds' -f $TimeToLive)
        Write-Verbose -Message $DASH

        ### PeekChar is for reading text, so check the stream position when reading bytes.
        While ($Stream.Position -lt $Stream.Length) {
            $TlvType   = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)
            $TlvLength = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)

            Switch ($TlvType) {
                { $_ -in $TypeString } {
                    $String = $Reader.ReadChars($TlvLength - 4) -join ''
                    $Properties.Add($Tlv.Item([int]$TlvType), $String)
                }

                { $_ -in $TypeAddress } {
                    $NumberOfAddresses = [System.BitConverter]::ToUInt32($Reader.ReadBytes(4)[3..0], 0)
                    $Addresses         = New-Object -TypeName System.Collections.Generic.List[String]

                    If ($NumberOfAddresses -gt 0) {
                        1..$NumberOfAddresses | ForEach-Object {
                            $ProtocolType   = $Reader.ReadByte()
                            $ProtocolLength = $Reader.ReadByte()

                            If ($ProtocolLength -eq 1) {
                                $Protocol = $Reader.ReadByte()
                            } Else {
                                $Protocol = [System.BitConverter]::ToInt64($Reader.ReadBytes(8)[7..0], 0)
                            }

                            $AddressLength = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)
                            $AddressBytes = $Reader.ReadBytes($AddressLength)

                            If (
                                ($ProtocolType -eq 0x01 -and $Protocol -eq $IPv4) -or 
                                ($ProtocolType -eq 0x02 -and $Protocol -eq $IPv6)
                            ) {
                                $IPAddress = [ipaddress]::new($AddressBytes).IPAddressToString
                                $Addresses.Add($IPAddress)
                            } Else {
                                $ProtocolBytes = [System.BitConverter]::GetBytes($Protocol)[7..0]
                                $ProtocolHex   = [System.BitConverter]::ToString($ProtocolBytes)
                                $AddressHex    = [System.BitConverter]::ToString($AddressBytes)

                                Write-Verbose -Message ('TlvType        : {0}' -f $TlvType)
                                Write-Verbose -Message ('TlvLength      : {0}' -f $TlvLength)
                                Write-Verbose -Message ('ProtocolType   : {0}' -f $ProtocolType)
                                Write-Verbose -Message ('ProtocolLength : {0}' -f $ProtocolLength)
                                Write-Verbose -Message ('ProtocolHex    : {0}' -f $ProtocolHex)
                                Write-Verbose -Message ('AddressLength  : {0}' -f $AddressLength)
                                Write-Verbose -Message ('AddressHex     : {0}' -f $AddressHex)
                                Write-Verbose -Message $DASH
                            }
                        }
                    } Else {
                        Write-Verbose -Message ('TlvType        : {0}' -f $TlvType)
                        Write-Verbose -Message ('TlvLength      : {0}' -f $TlvLength)
                        Write-Verbose -Message ('NumOfAddresses : {0}' -f $NumberOfAddresses)
                        Write-Verbose -Message $DASH
                    }

                    If ($Addresses.Count -gt 0) {
                        $Properties.Add($Tlv.Item([int]$TlvType), $Addresses)
                    }
                }

                $TypeInt {
                    $NativeVlan = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)
                    $Properties.Add($Tlv.Item([int]$TlvType), $NativeVlan)
                }

                default {
                    $Bytes = $Reader.ReadBytes($TlvLength - 4)
                    $Chars = $Bytes -as [System.Char[]]
                    $Hex   = [System.BitConverter]::ToString($Bytes)
                    $Ascii = $Chars -join ''

                    Write-Verbose -Message ('TlvType        : {0}' -f $TlvType)
                    Write-Verbose -Message ('TlvLength      : {0}' -f $TlvLength)
                    Write-Verbose -Message ('Hex            : {0}' -f $Hex)
                    Write-Verbose -Message ('Ascii          : {0}' -f $Ascii)
                    Write-Verbose -Message $DASH
                }
            }
        }

        $Reader.Dispose()

        New-Object -TypeName PSObject -Property $Properties
    }

    Function ConvertFrom-LLDPPacket {
        <#
            .SYNOPSIS
            Parse LLDP packet.

            .DESCRIPTION
            Parse LLDP packet to get port, description, device, model, ipaddress and vlan.

            .PARAMETER Packet
            Raw LLDP packet as byte array.

            This function is used by Get-DiscoveryProtocolData to parse the
            Fragment property of a DiscoveryProtocolPacket object.

            .EXAMPLE
            PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type LLDP
            PS C:\> ConvertFrom-LLDPPacket -Packet $Packet.Fragment

            Model       : WS-C2960-48TT-L
            Description : HR Workstation
            VLAN        : 10
            Port        : Fa0/1
            Device      : SWITCH1.domain.example
            IPAddress   : 192.0.2.10

        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Raw LLDP packet as byte array', Position = 0)]
            [byte[]]$Packet
        )

        Begin {
            $TlvType = @{
                EndOfLLDPDU          = 0
                ChassisId            = 1
                PortId               = 2
                TimeToLive           = 3
                PortDescription      = 4
                SystemName           = 5
                SystemDescription    = 6
                ManagementAddress    = 8
                OrganizationSpecific = 127
            }

            $DASH    = '----------------------------------------------------------------'
        }

        Process {
            $Destination = [PhysicalAddress]::new($Packet[0..5])
            $Source      = [PhysicalAddress]::new($Packet[6..11])
            $EtherType   = [BitConverter]::ToString($Packet[12..13])

            Write-Verbose -Message ('Destination    : {0}' -f $Destination)
            Write-Verbose -Message ('Source         : {0}' -f $Source)
            Write-Verbose -Message ('EtherType      : {0}' -f $EtherType)
            Write-Verbose -Message $DASH

            <#
                LESSON 12: Type-Length-Value records and fields smaller than a byte
                An LLDP frame is a 14-byte Ethernet header followed by records, each holding a
                Type, a Length and a Value. The header of each record is 2 bytes (16 bits): the
                first 7 bits are the type and the last 9 bits are the length.
                  $Packet[$Offset] -shr 1  shifts the first byte right by one bit, leaving the
                                           7-bit type.
                  ... -band 0x01FF         keeps the low 9 bits of the 2-byte value: the length.
                After reading a record, $Offset += $Length jumps to the next one. Type 0
                (EndOfLLDPDU) ends the frame.
            #>
            $Offset = 14
            $Mask   = 0x01FF
            $Hash   = @{}

            While ($Offset -lt $Packet.Length) {
                $Type    = $Packet[$Offset] -shr 1
                $Length  = [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0) -band $Mask
                $Offset += 2

                Switch ($Type) {
                    $TlvType.ChassisId {
                        $Subtype = $Packet[($Offset)]

                        If ($SubType -in (1, 2, 3, 6, 7)) {
                            $Hash.Add(
                                'ChassisId', [System.Text.Encoding]::ASCII.GetString(
                                    $Packet[($Offset + 1)..($Offset + $Length - 1)]
                                )
                            )
                        }

                        If ($Subtype -eq 5) {
                            $AddressFamily = $Packet[($Offset + 1)]
                            If ($AddressFamily -in 1, 2) {
                                $Hash.Add('ChassisId', [IPAddress]::new($Packet[($Offset + 2)..($Offset + $Length - 1)]))
                            } Else {
                                $Bytes = $Packet[($Offset + 2)..($Offset + $Length - 1)]
                                $Hex   = [System.BitConverter]::ToString($Bytes)
                                $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                                Write-Verbose -Message ('TlvType        : {0}' -f $Type)
                                Write-Verbose -Message ('TlvLength      : {0}' -f $Length)
                                write-Verbose -Message ('SubType        : {0}' -f $Subtype)
                                Write-Verbose -Message ('AddressFamily  : {0}' -f $AddressFamily)
                                Write-Verbose -Message ('Hex            : {0}' -f $Hex)
                                Write-Verbose -Message ('Ascii          : {0}' -f $Ascii)
                                Write-Verbose -Message $DASH
                            }
                        }

                        If ($Subtype -eq 4) {
                            $Hash.Add('ChassisId', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                        }

                        $Offset += $Length
                        Break
                    }

                    $TlvType.PortId {
                        $Subtype = $Packet[($Offset)]

                        If ($SubType -in (1, 2, 5, 6, 7)) {
                            $Hash.Add('Port', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                        }

                        If ($Subtype -eq 4) {
                            $AddressFamily = $Packet[($Offset + 1)]
                            If ($AddressFamily -in 1, 2) {
                                $Hash.Add('Port', [IPAddress]::new($Packet[($Offset + 2)..($Offset + $Length - 1)]))
                            } Else {
                                $Bytes = $Packet[($Offset + 2)..($Offset + $Length - 1)]
                                $Hex   = [System.BitConverter]::ToString($Bytes)
                                $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                                Write-Verbose -Message ('TlvType        : {0}' -f $Type)
                                Write-Verbose -Message ('TlvLength      : {0}' -f $Length)
                                write-Verbose -Message ('SubType        : {0}' -f $Subtype)
                                Write-Verbose -Message ('AddressFamily  : {0}' -f $AddressFamily)
                                Write-Verbose -Message ('Hex            : {0}' -f $Hex)
                                Write-Verbose -Message ('Ascii          : {0}' -f $Ascii)
                                Write-Verbose -Message $DASH
                            }
                        }

                        If ($Subtype -eq 3) {
                            $Hash.Add('Port', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                        }

                        $Offset += $Length
                        Break
                    }

                    $TlvType.TimeToLive {
                        $Hash.Add('TimeToLive', [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0))
                        $Offset += $Length
                        Break
                    }

                    $TlvType.PortDescription {
                        $Hash.Add('PortDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                        $Offset += $Length
                        Break
                    }

                    $TlvType.SystemName {
                        $Hash.Add('Device', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                        $Offset += $Length
                        Break
                    }

                    $TlvType.SystemDescription {
                        $Hash.Add('SystemDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                        $Offset += $Length
                        Break
                    }

                    $TlvType.ManagementAddress {
                        $AddrLen = $Packet[($Offset)]
                        $Subtype = $Packet[($Offset + 1)]

                        If (-not $Hash.ContainsKey('IPAddress') -and $Subtype -in 1, 2) {
                            $Addresses = New-Object -TypeName System.Collections.Generic.List[String]
                            $Hash.Add('IPAddress', $Addresses)
                        }

                        If ($Subtype -in 1, 2) {
                            $Addresses.Add(([ipaddress][byte[]]$Packet[($Offset + 2)..($Offset + $AddrLen)]).IPAddressToString)
                        } Else {
                            $Bytes = $Packet[($Offset + 2)..($Offset + $AddrLen)]
                            $Hex   = [System.BitConverter]::ToString($Bytes)
                            $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                            Write-Verbose -Message ('TlvType        : {0}' -f $Type)
                            Write-Verbose -Message ('TlvLength      : {0}' -f $Length)
                            Write-Verbose -Message ('AddressLength  : {0}' -f $AddrLen)
                            write-Verbose -Message ('SubType        : {0}' -f $Subtype)
                            Write-Verbose -Message ('Hex            : {0}' -f $Hex)
                            Write-Verbose -Message ('Ascii          : {0}' -f $Ascii)
                            Write-Verbose -Message $DASH
                        }

                        $Offset += $Length
                        Break
                    }

                    $TlvType.OrganizationSpecific {
                        $OUI     = [System.BitConverter]::ToString($Packet[($Offset)..($Offset + 2)])
                        $Subtype = $Packet[($Offset + 3)]

                        If ($OUI -eq '00-12-BB' -and $Subtype -eq 10) {
                            $Hash.Add('Model', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 4)..($Offset + $Length - 1)]))
                        }

                        If ($OUI -eq '00-80-C2' -and $Subtype -eq 1) {
                            $Hash.Add('VLAN', [BitConverter]::ToUInt16($Packet[($Offset + 5)..($Offset + 4)], 0))
                        }

                        If ($OUI -eq '00-80-C2' -and $Subtype -eq 9) {
                            $ETSMask = [uint16]0x000F
                            $Pri0To3 = [BitConverter]::ToUInt16($Packet[($Offset + 6)..($Offset + 5)], 0)
                            $Pri4To7 = [BitConverter]::ToUInt16($Packet[($Offset + 8)..($Offset + 7)], 0)

                            $ETS     = [PSCustomObject]@{
                                <#
                                    LESSON 13: Testing a single bit flag
                                    1 -shl 7 is 128 (binary 10000000), a value with only the top bit
                                    set. -band keeps just that bit of the byte, and -ne 0 turns the
                                    result into $true or $false. One byte can hold eight yes/no
                                    flags this way.
                                #>
                                Willing                  = ($Packet[($Offset + 4)] -band (1 -shl 7)) -ne 0
                                PriorityAssignmentTable  = @(
                                    [PSCustomObject]@{
                                        Priority     = 0
                                        TrafficClass = ($Pri0To3 -shr 12) -band $ETSMask
                                    }
                                    [PSCustomObject]@{
                                        Priority     = 1
                                        TrafficClass = ($Pri0To3 -shr 8) -band $ETSMask
                                    }
                                    [PSCustomObject]@{
                                        Priority     = 2
                                        TrafficClass = ($Pri0To3 -shr 4) -band $ETSMask
                                    }
                                    [PSCustomObject]@{
                                        Priority     = 3
                                        TrafficClass = $Pri0To3 -band $ETSMask
                                    }
                                    [PSCustomObject]@{
                                        Priority     = 4
                                        TrafficClass = ($Pri4To7 -shr 12) -band $ETSMask
                                    }
                                    [PSCustomObject]@{
                                        Priority     = 5
                                        TrafficClass = ($Pri4To7 -shr 8) -band $ETSMask
                                    }
                                    [PSCustomObject]@{
                                        Priority     = 6
                                        TrafficClass = ($Pri4To7 -shr 4) -band $ETSMask
                                    }
                                    [PSCustomObject]@{
                                        Priority     = 7
                                        TrafficClass = $Pri4To7 -band $ETSMask
                                    }
                                )
                                BandwidthAssignmentTable = @(
                                    [PSCustomObject]@{
                                        Priority  = 0
                                        Bandwidth = $Packet[($Offset + 9)]
                                    }
                                    [PSCustomObject]@{
                                        Priority  = 1
                                        Bandwidth = $Packet[($Offset + 10)]
                                    }
                                    [PSCustomObject]@{
                                        Priority  = 2
                                        Bandwidth = $Packet[($Offset + 11)]
                                    }
                                    [PSCustomObject]@{
                                        Priority  = 3
                                        Bandwidth = $Packet[($Offset + 12)]
                                    }
                                    [PSCustomObject]@{
                                        Priority  = 4
                                        Bandwidth = $Packet[($Offset + 13)]
                                    }
                                    [PSCustomObject]@{
                                        Priority  = 5
                                        Bandwidth = $Packet[($Offset + 14)]
                                    }
                                    [PSCustomObject]@{
                                        Priority  = 6
                                        Bandwidth = $Packet[($Offset + 15)]
                                    }
                                    [PSCustomObject]@{
                                        Priority  = 7
                                        Bandwidth = $Packet[($Offset + 16)]
                                    }
                                )
                            }

                            If (-not ($Hash.ContainsKey('DCBX'))) {
                                $Hash.Add(
                                    'DCBX', [PSCustomObject]@{
                                        IEEE = [PSCustomObject]@{}
                                    }
                                )
                            }

                            $Hash.DCBX.IEEE | Add-Member -NotePropertyName ETS -NotePropertyValue $ETS
                        }

                        If ($OUI -eq '00-80-C2' -and $Subtype -eq 11) {
                            $PFC = [PSCustomObject]@{
                                Willing     = ($Packet[($Offset + 4)] -band (1 -shl 7)) -ne 0
                                FlowControl = 0..7 | ForEach-Object {
                                    [PSCustomObject]@{
                                        Priority = $_
                                        Enabled  = ($Packet[($Offset + 5)] -band (1 -shl $_)) -ne 0
                                    }
                                }
                            }

                            If (-not ($Hash.ContainsKey('DCBX'))) {
                                $Hash.Add(
                                    'DCBX', [PSCustomObject]@{
                                        IEEE = [PSCustomObject]@{}
                                    }
                                )
                            }

                            $Hash.DCBX.IEEE | Add-Member -NotePropertyName PFC -NotePropertyValue $PFC
                        }

                        If ($OUI -eq '00-1B-21' -and $Subtype -eq 2) {
                            If (-not ($Hash.ContainsKey('DCBX'))) {
                                $Hash.Add(
                                    'DCBX', [PSCustomObject]@{
                                        CEE = [PSCustomObject]@{}
                                    }
                                )
                            }

                            $DCBXTLVBuffer = $Packet[($Offset + 4)..($Offset + $Length - 1)]
                            $DCBXTLVOffset = 0

                            While ($DCBXTLVOffset -lt $DCBXTLVBuffer.Length) {
                                $DCBXTLVType    = $DCBXTLVBuffer[($DCBXTLVOffset)] -shr 1
                                $DCBXTLVLength  = [BitConverter]::ToUInt16($DCBXTLVBuffer[($DCBXTLVOffset + 1)..$DCBXTLVOffset], 0) -band $Mask
                                $DCBXTLVOffset += 2

                                Write-Verbose -Message ('DCBXTLVType    : {0}' -f $DCBXTLVType)
                                Write-Verbose -Message ('DCBXTLVLength  : {0}' -f $DCBXTLVLength)

                                If ($DCBXTLVType -eq 2) {
                                    $ETSMask = [uint16]0x000F
                                    $Pri0To3 = [BitConverter]::ToUInt16($DCBXTLVBuffer[($DCBXTLVOffset + 5)..($DCBXTLVOffset + 4)], 0)
                                    $Pri4To7 = [BitConverter]::ToUInt16($DCBXTLVBuffer[($DCBXTLVOffset + 7)..($DCBXTLVOffset + 6)], 0)

                                    $ETS     = [PSCustomObject]@{
                                        Enabled                 = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 7)) -ne 0
                                        Willing                 = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 6)) -ne 0
                                        PriorityAssignmentTable = @(
                                            [PSCustomObject]@{
                                                Priority     = 0
                                                TrafficClass = ($Pri0To3 -shr 12) -band $ETSMask
                                            }
                                            [PSCustomObject]@{
                                                Priority     = 1
                                                TrafficClass = ($Pri0To3 -shr 8) -band $ETSMask
                                            }
                                            [PSCustomObject]@{
                                                Priority     = 2
                                                TrafficClass = ($Pri0To3 -shr 4) -band $ETSMask
                                            }
                                            [PSCustomObject]@{
                                                Priority     = 3
                                                TrafficClass = $Pri0To3 -band $ETSMask
                                            }
                                            [PSCustomObject]@{
                                                Priority     = 4
                                                TrafficClass = ($Pri4To7 -shr 12) -band $ETSMask
                                            }
                                            [PSCustomObject]@{
                                                Priority     = 5
                                                TrafficClass = ($Pri4To7 -shr 8) -band $ETSMask
                                            }
                                            [PSCustomObject]@{
                                                Priority     = 6
                                                TrafficClass = ($Pri4To7 -shr 4) -band $ETSMask
                                            }
                                            [PSCustomObject]@{
                                                Priority     = 7
                                                TrafficClass = $Pri4To7 -band $ETSMask
                                            }
                                        )
                                        BandwidthAssignmentTable = @(
                                            [PSCustomObject]@{
                                                Priority  = 0
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 8)]
                                            }
                                            [PSCustomObject]@{
                                                Priority  = 1
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 9)]
                                            }
                                            [PSCustomObject]@{
                                                Priority  = 2
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 10)]
                                            }
                                            [PSCustomObject]@{
                                                Priority  = 3
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 11)]
                                            }
                                            [PSCustomObject]@{
                                                Priority  = 4
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 12)]
                                            }
                                            [PSCustomObject]@{
                                                Priority  = 5
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 13)]
                                            }
                                            [PSCustomObject]@{
                                                Priority  = 6
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 14)]
                                            }
                                            [PSCustomObject]@{
                                                Priority  = 7
                                                Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 15)]
                                            }
                                        )
                                    }

                                    $Hash.DCBX.CEE | Add-Member -NotePropertyName ETS -NotePropertyValue $ETS
                                }

                                If ($DCBXTLVType -eq 3) {
                                    $PFC = [PSCustomObject]@{
                                        Enabled     = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 7)) -ne 0
                                        Willing     = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 6)) -ne 0
                                        FlowControl = 0..7 | ForEach-Object {
                                            [PSCustomObject]@{
                                                Priority = $_
                                                Enabled = ($DCBXTLVBuffer[($DCBXTLVOffset + 4)] -band (1 -shl $_)) -ne 0
                                            }
                                        }
                                    }

                                    $Hash.DCBX.CEE | Add-Member -NotePropertyName PFC -NotePropertyValue $PFC
                                }

                                $DCBXTLVOffset += $DCBXTLVLength
                            }
                        }

                        $Bytes = $Packet[($Offset + 4)..($Offset + $Length - 1)]
                        $Hex   = [System.BitConverter]::ToString($Bytes)
                        $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                        Write-Verbose -Message ('TlvType        : {0}' -f $Type)
                        Write-Verbose -Message ('TlvLength      : {0}' -f $Length)
                        Write-Verbose -Message ('OUI            : {0}' -f $OUI)
                        write-Verbose -Message ('SubType        : {0}' -f $SubType)
                        Write-Verbose -Message ('Hex            : {0}' -f $Hex)
                        Write-Verbose -Message ('Ascii          : {0}' -f $Ascii)
                        Write-Verbose -Message $DASH

                        $Offset += $Length
                        Break
                    }

                    $TlvType.EndOfLLDPDU {
                        Write-Verbose -Message 'TlvName        : End Of LLDPDU'
                        Write-Verbose -Message ('TlvType        : {0}' -f $Type)
                        Write-Verbose -Message ('TlvLength      : {0}' -f $Length)
                        Write-Verbose -Message $DASH
                    }

                    default {
                        $Bytes = $Packet[$Offset..($Offset + $Length - 1)]
                        $Hex   = [System.BitConverter]::ToString($Bytes)
                        $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                        Write-Verbose -Message ('TlvType        : {0}' -f $Type)
                        Write-Verbose -Message ('TlvLength      : {0}' -f $Length)
                        Write-Verbose -Message ('Hex            : {0}' -f $Hex)
                        Write-Verbose -Message ('Ascii          : {0}' -f $Ascii)
                        Write-Verbose -Message $DASH

                        $Offset += $Length
                        Break
                    }
                }
            }
            [PSCustomObject]$Hash
        }
        End {}
    }

    Function Export-Pcap {
        <#
            .SYNOPSIS
            Export packets to pcap

            .DESCRIPTION
            Export packets, captured using Invoke-DiscoveryProtocolCapture, to pcap format.

            .PARAMETER Packet
            Specifies one or more objects of type DiscoveryProtocolPacket.

            .PARAMETER Bytes
            Raw Ethernet frame bytes to export instead of DiscoveryProtocolPacket objects.

            .PARAMETER DateTime
            Timestamp written for the frame supplied through -Bytes. Defaults to the current time.

            .PARAMETER Path
            Relative or absolute path to pcap file.

            .PARAMETER Invoke
            If Invoke is set, exported file is opened in the program associated with pcap files.

            .EXAMPLE
            PS C:\> $Packet = Invoke-DiscoveryProtocolCapture
            PS C:\> Export-Pcap -Packet $Packet -Path C:\Windows\Temp\captures.pcap -Invoke

            Export captured packet to C:\Windows\Temp\captures.pcap and open file in
            the program associated with pcap files.

            .EXAMPLE
            PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Export-Pcap -Path captures.pcap

            Export captured packets to captures.pcap in current directory. Export-Pcap supports input from pipeline.
        #>
        [CmdletBinding(DefaultParameterSetName = 'DiscoveryProtocolPacket')]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Provide one or more DiscoveryProtocolPacket objects to export.', ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'DiscoveryProtocolPacket')]
            [DiscoveryProtocolPacket[]]$Packet,

            [Parameter(Mandatory, HelpMessage = 'Provide the raw Ethernet frame bytes to export.', ParameterSetName = 'BytesAndDateTime')]
            [byte[]]$Bytes,

            [Parameter(ParameterSetName = 'BytesAndDateTime')]
            [datetime]$DateTime = (Get-Date),

            [Parameter(Mandatory, HelpMessage = 'Specify the .pcap file to write.')]
            [ValidateScript(
                {
                    If ([System.IO.Path]::IsPathRooted($_)) { $AbsolutePath = $_ } Else { $AbsolutePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_) }
                    If (-not(Test-Path -Path (Split-Path -Path $AbsolutePath -Parent))) { Throw 'Folder does not exist' }
                    If ($_ -notmatch '\.pcap$') { Throw 'Extension must be pcap' }
                    Return $true
                }
            )]
            [System.IO.FileInfo]$Path,

            [switch]$Invoke
        )

        Begin {
            <#
                LESSON 14: Writing a binary file format
                A .pcap file starts with a 24-byte header: a magic number that identifies the
                format, version numbers, the maximum packet length and the link type (1 means
                Ethernet). Each packet then gets a 16-byte record header (timestamp and length)
                followed by its bytes. The typed variables ([uint32], [uint16]) matter because
                BinaryWriter.Write writes exactly as many bytes as the value's type: 4 for
                [uint32] and 2 for [uint16].
                Everything is written to a MemoryStream in memory and saved once in End, so a
                failure midway never leaves a half-written file.
                The [ValidateScript()] on -Path rejects a bad path before the function runs: the
                folder must exist and the extension must be .pcap. Throwing inside ValidateScript
                shows that message to the caller.
            #>
            [uint32]$magicNumber  = '0xa1b2c3d4'
            [uint16]$versionMajor = 2
            [uint16]$versionMinor = 4
            [int]$thisZone        = 0
            [uint32]$sigFigs      = 0
            [uint32]$snapLen      = 65536
            [uint32]$network      = 1

            $stream = New-Object -TypeName System.IO.MemoryStream
            $writer = New-Object -TypeName System.IO.BinaryWriter -ArgumentList $stream

            $writer.Write($magicNumber)
            $writer.Write($versionMajor)
            $writer.Write($versionMinor)
            $writer.Write($thisZone)
            $writer.Write($sigFigs)
            $writer.Write($snapLen)
            $writer.Write($network)
        }
        Process {
            Switch ($PSCmdlet.ParameterSetName) {
                'DiscoveryProtocolPacket' {
                    ForEach ($item in $Packet) {
                        [uint32]$tsSec   = ([DateTimeOffset]$item.TimeCreated).ToUnixTimeSeconds()
                        [uint32]$tsUsec  = $item.TimeCreated.Millisecond
                        [uint32]$inclLen = $item.FragmentSize
                        [uint32]$origLen = $inclLen

                        $writer.Write($tsSec)
                        $writer.Write($tsUsec)
                        $writer.Write($inclLen)
                        $writer.Write($origLen)
                        $writer.Write($item.Fragment)
                    }
                }
                'BytesAndDateTime' {
                    [uint32]$tsSec   = ([DateTimeOffset]$DateTime).ToUnixTimeSeconds()
                    [uint32]$tsUsec  = $DateTime.Millisecond
                    [uint32]$inclLen = $Bytes.Length
                    [uint32]$origLen = $inclLen

                    $writer.Write($tsSec)
                    $writer.Write($tsUsec)
                    $writer.Write($inclLen)
                    $writer.Write($origLen)
                    $writer.Write($Bytes)
                }
            }
        }
        End {
            $bytes = $stream.ToArray()

            $stream.Dispose()
            $writer.Dispose()

            If (-not([System.IO.Path]::IsPathRooted($Path))) {
                $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
            }

            <#
                LESSON 15: Saving bytes, then opening the file with its associated program
                [System.IO.File]::WriteAllBytes writes the whole array in one call. It needs a full
                path; .NET does not know PowerShell's current location, which is why -Path is
                resolved to an absolute path first. Invoke-Item opens a file the same way
                double-clicking does, so -Invoke launches Wireshark or whichever program is
                registered for .pcap files.
            #>
            [System.IO.File]::WriteAllBytes($Path, $bytes)

            If ($Invoke) {
                Invoke-Item -Path $Path
            }
        }
    }
} ### Lessons

Function Get-ADSiteSubnetInventory {
    <#
        .SYNOPSIS
        Returns the Active Directory subnet objects for the local site, or for all sites.

        .DESCRIPTION
        Determines the computer's AD site with System.DirectoryServices.ActiveDirectory, then reads
        the subnet objects under CN=Subnets,CN=Sites in the configuration partition with ADSI. No
        RSAT module or external executable is used.

        Each record is classified from its subnet and description:
          IsServers     : description contains the word Servers.
          IsPQE         : description contains the word PQE.
          IsLegacy      : description contains the word Legacy.
          IsReplacement : a 10.X.50.0 subnet that is not marked Legacy.

        .PARAMETER Site
        AD site name to report. Defaults to the computer's own site.

        .PARAMETER AllSites
        Returns subnets for every site instead of a single site.

        .EXAMPLE
        Get-ADSiteSubnetInventory

        Returns the subnets assigned to this computer's AD site.

        .EXAMPLE
        Get-ADSiteSubnetInventory -AllSites | Where-Object IsLegacy

        Returns every subnet in the forest whose description marks it as Legacy.

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [string]$Site,

        [Parameter()]
        [switch]$AllSites
    )

    If (-not $Site -and -not $AllSites) {
        Try {
            <#
                LESSON 1: Ask .NET, not a command-line tool
                An earlier version ran nltest /dsgetsite and read its text output. That breaks on
                a non-English Windows, where the text is translated, and depends on an external
                program. GetComputerSite() returns the same answer as an object on any language.
                On a computer that is not joined to a domain it throws, which the Catch turns into
                a verbose message, and the clear error below explains the outcome.
            #>
            $Site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
        } Catch {
            Write-Verbose -Message ('Unable to determine the computer AD site: {0}' -f $_.Exception.Message)
        }
    }

    If (-not $Site -and -not $AllSites) {
        Throw 'Unable to determine the local Active Directory site.'
    }

    <#
        LESSON 2: Finding where AD keeps site information, without hard-coding it
        [ADSI] is a type accelerator: a short name PowerShell provides for
        System.DirectoryServices.DirectoryEntry. RootDSE is a special entry every domain
        controller offers, describing the directory itself. Its configurationNamingContext is the
        path of the configuration partition (CN=Configuration,DC=mycompany,DC=com), where sites and
        subnets are stored for the whole forest. Reading it from RootDSE means the same code works
        in any domain.
        The next line builds the search location inside double quotes, so $Config is expanded into
        the path string. Single quotes would keep the literal text "$Config".
    #>
    $Root   = [ADSI]'LDAP://RootDSE'
    $Config = [string]$Root.configurationNamingContext
    $Base   = [ADSI]"LDAP://CN=Subnets,CN=Sites,$Config"
    $S      = New-Object -TypeName DirectoryServices.DirectorySearcher -ArgumentList ($Base)

    <#
        LESSON 3: Searching Active Directory with DirectorySearcher
        The filter uses LDAP syntax: (attribute=value) in parentheses, combined with & (and) or |
        (or), for example (&(objectClass=subnet)(description=*Legacy*)).
        PageSize matters: without it, a search stops silently after 1000 results. With PageSize
        set, results arrive in pages of that size and the search returns ALL matches.
        PropertiesToLoad requests only the attributes needed, instead of every attribute of every
        object.
    #>
    $S.Filter   = '(objectClass=subnet)'
    $S.PageSize = 1000

    <#
        LESSON 4: Methods that return values, inside a pipeline too
        PropertiesToLoad.Add returns the index of the new entry, just like ArrayList.Add in
        Get-NativeSubnetDiscovery. Inside ForEach-Object that number would become output of this
        whole function and appear among the results, so $null = discards it.
    #>
    'cn','description','siteObject' | ForEach-Object {
        $null = $S.PropertiesToLoad.Add($_)
    }

    Try {
        $Results = $S.FindAll()

        @(
            ForEach ($R in $Results) {
                <#
                    LESSON 5: Directory attributes are lists, and may be missing
                    An AD attribute can hold several values, so each result property is a
                    collection, even when it holds one value: [0] takes the first. An attribute
                    with no value is simply absent from the result, so Contains() checks first and
                    avoids an error. Attribute names come back in lowercase ('siteobject'), which
                    is why the lookups use lowercase names.
                #>
                $Subnet      = If ($R.Properties.Contains('cn')) { [string]$R.Properties['cn'][0] } Else { $null }
                $Description = If ($R.Properties.Contains('description')) { [string]$R.Properties['description'][0] } Else { $null }
                $SiteDN      = If ($R.Properties.Contains('siteobject')) { [string]$R.Properties['siteobject'][0] } Else { $null }

                <#
                    LESSON 6: Pulling one part out of a distinguished name
                    A subnet links to its site by distinguished name (DN), the object's full path
                    read from left to right: CN=MagnaWinnipeg,CN=Sites,CN=Configuration,DC=...
                    ^CN=([^,]+) captures everything after the first CN= up to the first comma,
                    which is the site's name. [^,]+ means "one or more characters that are not a
                    comma".
                #>
                $SiteName    = If ($SiteDN -match '^CN=([^,]+),CN=Sites,') { $Matches[1] } Else { $null }

                <#
                    LESSON 7: Skip an item with Continue, and where filtering happens
                    Continue jumps straight to the next result; the code below it runs only for
                    subnets in the requested site. Here ALL subnets are downloaded and filtered in
                    PowerShell. An LDAP filter on siteObject could ask the domain controller to
                    filter instead. With a few hundred subnets the difference is negligible, and
                    downloading everything keeps -AllSites trivial. On large data, filter at the
                    source, as in Lesson 2 of Get-LastInteractiveLogonUser.
                #>
                If (-not $AllSites -and $SiteName -ne $Site) {
                    Continue
                }

                <#
                    LESSON 8: Assigning several variables at once
                    -split returns an array, and a list of variables on the left receives its
                    elements in order: '10.25.15.0/24' gives $Network = '10.25.15.0' and
                    $Prefix = '24'. This has worked since PowerShell 1.0 (see
                    about_Assignment_Operators). With more elements than variables, the LAST
                    variable receives all the remaining elements as an array. With fewer, the
                    extra variables are $null, which is why PrefixLength checks If ($Prefix).
                #>
                $Network,$Prefix = $Subnet -split '/'

                [PSCustomObject]@{
                    Site          = $SiteName
                    Subnet        = $Subnet
                    Network       = $Network
                    PrefixLength  = If ($Prefix) { [int]$Prefix } Else { $null }
                    Description   = $Description
                    <#
                        LESSON 9: Match whole words with \b
                        \b is a word boundary: the position between a letter or digit and anything
                        else, such as a space, a parenthesis or the end of the text. \bLegacy\b
                        matches 'Philadelphia Legacy' and 'Calgary, AB (Legacy)' but not
                        'NonLegacyNet'. -match already ignores case, so (?i) only makes that
                        explicit.
                        These flags turn free-text descriptions into yes/no facts the rest of the
                        script can filter on, such as Where-Object IsLegacy.
                    #>
                    IsServers     = [bool]($Description -match '(?i)\bServers\b')
                    IsPQE         = [bool]($Description -match '(?i)\bPQE\b')
                    IsLegacy      = [bool]($Description -match '(?i)\bLegacy\b')
                    IsReplacement = [bool]($Subnet -match '^10\.\d{1,3}\.50\.' -and $Description -notmatch '(?i)\bLegacy\b')
                }
            }
        )
    } Finally {
        <#
            LESSON 10: Some results must be disposed explicitly
            The collection FindAll() returns holds unmanaged memory that .NET's garbage collector
            cannot fully release on its own. Microsoft's documentation tells you to call Dispose().
            A script that searches repeatedly without disposing slowly leaks memory. The searcher
            is disposed too.
        #>
        If ($Results) {
            $Results.Dispose()
        }
        $S.Dispose()

        If ($Base) {
            $Base.Dispose()
        }

        If ($Root) {
            $Root.Dispose()
        }
    }
} ### Lessons
#endregion Inventory Functions

#region Dell/Hyper-V Network Inventory
Function Get-HyperVNetworkInventory {
    <#
        .SYNOPSIS
        Generates a detailed inventory of Hyper-V host physical NICs, physical switch connections, iSCSI storage paths, virtual switches, and VM guest adapters.

        .DESCRIPTION
        Get-HyperVNetworkInventory retrieves hardware, operating system, physical network adapter, Hyper-V virtual switch, iSCSI storage path, physical switch LLDP neighbor, and guest VM network adapter information from the local Hyper-V host.

        Physical host adapters are correlated with:
        - Hyper-V external virtual switches.
        - Active iSCSI connections and sessions.
        - The local source IP and physical interface selected by Windows for each iSCSI target.
        - Physical network switch and switch port information discovered passively through LLDP using NetEventSession.

        Guest IPv4 addresses are obtained from Hyper-V Integration Services when available, with DNS used as a fallback.

        When NewSN is specified, the final octet of each discovered IPv4 address is appended to the supplied three-octet subnet prefix to provide a proposed replacement address.

        .PARAMETER Out
        Specifies the output format.

        Screen displays formatted host adapter, physical switch, iSCSI storage path, and VM guest tables.

        CSV returns comma-separated inventory records suitable for redirection or Out-File.

        .PARAMETER LLDPCaptureSeconds
        Number of seconds to passively capture LLDP advertisements with NetEventSession.

        The default is 35 seconds. Set this parameter to 0 to disable NetEventSession LLDP discovery.

        Existing NetEventSession captures are not stopped. If NetEventSession cannot start a new capture, switch discovery is skipped.

        .PARAMETER iDRAC
        Object returned by Get-iDRACInventory. Used to recognise the iDRAC pass-through adapter and
        the iDRAC management address among the host's network data.

        .PARAMETER SiteSubnets
        Records returned by Get-ADSiteSubnetInventory. When omitted, the function queries Active
        Directory for the local site's subnets itself.

        .INPUTS
        None.

        .OUTPUTS
        System.String

        When Out is CSV, returns CSV-formatted strings representing host physical adapters and VM guest adapters.

        .EXAMPLE
        PS C:\> Get-HyperVNetworkInventory

        Displays the complete local Hyper-V network inventory.

        .EXAMPLE
        PS C:\> Get-HyperVNetworkInventory -NewSN '10.203.50'

        Displays the inventory and calculates replacement addresses in the 10.203.50.0/24 subnet.

        .EXAMPLE
        PS C:\> Get-HyperVNetworkInventory -Out CSV -NewSN '10.203.50' | Out-File -FilePath 'C:\down\HyperV-NetworkInventory.csv' -Encoding UTF8

        Exports the complete inventory to CSV.

        .EXAMPLE
        PS C:\> Get-HyperVNetworkInventory -LLDPCaptureSeconds 0

        Runs the inventory without performing passive LLDP discovery.

        .NOTES
        Author: James Stephens
        Requires: Windows PowerShell 5.1+, Hyper-V Module, Administrator privileges.
    #>

    [CmdletBinding()]
    Param (
        [Parameter()]
        [ValidateSet('Screen', 'CSV', 'Object')]
        [string]$Out = 'Object',

        [Parameter()]
        [ValidateRange(0,300)]
        [int]$LLDPCaptureSeconds = 35,

        [Parameter()]
        [object]$iDRAC,

        [object[]]$SiteSubnets
    )

    #region Runtime Variables
    $ipLookup             = @{}
    $lldpLookup           = @{}
    $vSwitchMap           = @{}
    $vmStateLookup        = @{}
    $iSCSILookup          = @{}

    $allRecords           = [System.Collections.Generic.List[object]]::new()
    $iSCSIPathRecords     = [System.Collections.Generic.List[object]]::new()
    $lldpRecords          = [System.Collections.Generic.List[object]]::new()

    $IL0 = @{InformationLevel = 'Quiet'}

    $Gy  = @{ForegroundColor = 'Gray'}
    $Ma  = @{ForegroundColor = 'Magenta'}
    $Cy  = @{ForegroundColor = 'Cyan'}
    $Gr  = @{ForegroundColor = 'Green'}
    $DY  = @{ForegroundColor = 'DarkYellow'}
    $DC  = @{ForegroundColor = 'DarkCyan'}
    $Ye  = @{ForegroundColor = 'Yellow'}

    $lldpCaptureStatus    = 'Not Attempted'
    $vSwitchAccess        = $true
    #endregion

    #region Get New Subnet
    Try {
        If (-not $SiteSubnets.Count) {
            $SiteSubnets = @(Get-ADSiteSubnetInventory @script:EA1)
        }

        If (-not $SiteSubnets.Count) {
            Throw 'No AD subnet objects were assigned to the local AD site.'
        }

        $Site = $SiteSubnets[0].Site

        $ServerSubnets = @(
            $SiteSubnets | Where-Object {
                $_.IsServers -and
                -not $_.IsPQE -and
                $_.IsReplacement
            }
        )

        If ($ServerSubnets.Count -eq 0) {
            Throw ("No Servers subnet matching 10.X.50.X was found for AD site '{0}'." -f $Site)
        }

        If ($ServerSubnets.Count -gt 1) {
            Throw ("Multiple Servers subnets were found for AD site '{0}': {1}" -f $Site,($ServerSubnets.Subnet -join ', '))
        }

        $ServerSubnet = $ServerSubnets[0]
        $NewSN        = ($ServerSubnet.Network -replace '\.\d+$','')

        Write-Host ('AD Site: {0} | Servers Subnet: {1} | New IP Prefix: {2}' -f $Site,$ServerSubnet.Subnet,$NewSN) @Gy
    } Catch {
        Throw ('Unable to determine the replacement server subnet from Active Directory Sites and Services: {0}' -f $_.Exception.Message)
    }
    #endregion

    #region Prerequisite Validation
    If (-not (Get-Command -Name Get-VM @script:EA0)) {
        Throw 'The Hyper-V PowerShell module is not available on this computer.'
    }

    If (-not (Get-Command -Name Get-NetAdapter @script:EA0)) {
        Throw 'The NetAdapter PowerShell module is not available on this computer.'
    }
    #endregion

    #region Hardware, Host & OS Detection
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $os   = Get-CimInstance -ClassName Win32_OperatingSystem

    $isPhysical       = $cs.Model -notmatch 'Virtual|VMware|VirtualBox|KVM|HVM'
    $hostType         = If ($isPhysical) { 'Physical' } Else { 'Virtual' }
    $hostManufacturer = $cs.Manufacturer
    $hostModel        = $cs.Model
    $hostSerial       = $bios.SerialNumber
    $osVersion        = ('{0} ({1} Build {2})' -f $os.Caption, $os.Version, $os.BuildNumber)
    #endregion

    #region Data Caching & Indexing
    ### Cache valid local IPv4 addresses by interface
    Get-NetIPAddress -AddressFamily IPv4 @script:EA0 | Where-Object {
        $_.IPAddress -notlike '169.254.*' -and 
        $_.IPAddress -ne '127.0.0.1' -and 
        -not $_.SkipAsSource
    } | Group-Object -Property InterfaceIndex | ForEach-Object {
        $ipLookup[[int]$_.Name] = @($_.Group | Sort-Object -Property IPAddress | Select-Object -ExpandProperty IPAddress)
    }

    ### Cache physical host adapters only
    $allAdapters = @(Get-NetAdapter -Physical | Sort-Object -Property Name)

    ### Cache Hyper-V vSwitch mappings
    Try {
        $vSwitches = @(Get-VMSwitch @script:EA1)
        ForEach ($vSwitch in $vSwitches) {
            ForEach ($description in @($vSwitch.NetAdapterInterfaceDescriptions | Where-Object {$_})) {
                If ($vSwitchMap.ContainsKey($description)) {
                    $vSwitchMap[$description] = (@($vSwitchMap[$description]) + $vSwitch.Name | Select-Object -Unique) -join '; '
                } Else {
                    $vSwitchMap[$description] = $vSwitch.Name
                }
            }
        }
    } Catch {
        $vSwitchAccess = $false
        Write-Warning -Message ('Unable to enumerate Hyper-V virtual switches: {0}' -f $_.Exception.Message)
    }

    ### Cache VM power states
    Try {
        Get-VM @EA1 | ForEach-Object {
            $vmStateLookup[$_.Name] = $_.State.ToString()
        }
    } Catch {
        Write-Warning -Message ('Unable to enumerate Hyper-V virtual machines: {0}' -f $_.Exception.Message)
    }
    #endregion

    #region iSCSI Storage Discovery
    $iSCSILookup      = @{}
    $iSCSIPathRecords = [System.Collections.Generic.List[object]]::new()

    If (
        (Get-Command -Name Get-IscsiConnection @script:EA0) -and 
        (Get-Command -Name Get-IscsiSession @script:EA0) -and 
        (Get-Command -Name Find-NetRoute @script:EA0)
    ) {
        $iSCSIConnections = @(Get-IscsiConnection @script:EA0)
        $iSCSISessions    = @(Get-IscsiSession @script:EA0)
        $iSCSITargets     = @(Get-IscsiTarget @script:EA0)
        $iSCSIPortals     = @(Get-IscsiTargetPortal @script:EA0)

        $iSCSIConnections | Group-Object -Property TargetAddress,TargetPortNumber | ForEach-Object {
            $ConnectionGroup = @($_.Group)
            $Connection      = $ConnectionGroup | Select-Object -First 1
            $RouteObjects    = @(Find-NetRoute -RemoteIPAddress $Connection.TargetAddress @script:EA0)

            $LocalAddress    = $RouteObjects | Where-Object {
                $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress'
            } | Select-Object -First 1

            $Route           = $RouteObjects | Where-Object {
                $_.CimClass.CimClassName -eq 'MSFT_NetRoute'
            } | Select-Object -First 1

            If (-not $LocalAddress) {
                Write-Verbose -Message ('No route/interface found for iSCSI target {0}:{1}.' -f $Connection.TargetAddress,$Connection.TargetPortNumber)

                Return
            }

            $InterfaceIndex = [int]$LocalAddress.InterfaceIndex
            $NIC = Get-NetAdapter -InterfaceIndex $InterfaceIndex @script:EA0

            ### Generate traffic so the directly-connected target is present in the neighbor cache
            $null = Test-NetConnection -ComputerName $Connection.TargetAddress -Port $Connection.TargetPortNumber @IL0 @script:EA0

            $Neighbor = Get-NetNeighbor -IPAddress $Connection.TargetAddress -AddressFamily IPv4 -InterfaceIndex $InterfaceIndex @EA0 | Where-Object {
                $_.State -notin 'Unreachable','Incomplete'
            } | Select-Object -First 1

            $TargetMACType = If (
                $Neighbor -and 
                $Route -and 
                $Route.NextHop -eq '0.0.0.0'
            ) {
                'Direct Target'
            } ElseIf ($Neighbor) {
                'Gateway'
            } Else {
                $script:NA
            }

            ### Try the explicit connection-to-session association first
            $SessionLookup = @{}
            ForEach ($CurrentConnection in $ConnectionGroup) {
                $ConnectionSessions = @(Get-IscsiSession -IscsiConnection $CurrentConnection @EA0)
                ForEach ($Session in $ConnectionSessions) {
                    $SessionKey = If ($Session.SessionIdentifier) {
                        $Session.SessionIdentifier
                    } Else {
                        $Session.TargetNodeAddress
                    }

                    If ($SessionKey -and -not $SessionLookup.ContainsKey($SessionKey)) {
                        $SessionLookup[$SessionKey] = $Session
                    }
                }
            }

            ### Server/version fallback: preserve established sessions even if association lookup returns nothing
            $Sessions = @($SessionLookup.Values)
            If (-not $Sessions.Count) {
                $Sessions = @($iSCSISessions | Where-Object {$_.IsConnected})
            }

            $TargetIQNs        = @($Sessions | Where-Object {$_.TargetNodeAddress} | Select-Object -ExpandProperty TargetNodeAddress -Unique)
            $ConnectedTargets  = @($iSCSITargets | Where-Object {$_.IsConnected})
            If (-not $TargetIQNs.Count -and $ConnectedTargets.Count) {
                $TargetIQNs = @($ConnectedTargets | Select-Object -ExpandProperty NodeAddress -Unique)
            }

            $StorageConnected  = If ($Sessions.Count) {
                [bool](@($Sessions | Where-Object {$_.IsConnected}).Count)
            } Else {
                $false
            }

            $StoragePersistent = If ($Sessions.Count) {
                (@($Sessions | Select-Object -ExpandProperty IsPersistent -Unique) -join '; ')
            } Else {
                $script:NA
            }

            $MultipathValues   = @()
            ForEach ($Session in $Sessions) {
                If ($Session.PSObject.Properties['IsMultipathEnabled']) {
                    $MultipathValues += $Session.IsMultipathEnabled
                }
            }

            $StorageMultipath  = If ($MultipathValues.Count) {
                (@($MultipathValues | Select-Object -Unique) -join '; ')
            } Else {
                $script:NA
            }

            $PortalNames       = @($iSCSIPortals | Where-Object {$_.TargetPortalAddress} | Select-Object -ExpandProperty TargetPortalAddress -Unique)

            $PathRecord        = [PSCustomObject]@{
                InterfaceIndex   = $InterfaceIndex
                InterfaceAlias   = $LocalAddress.InterfaceAlias
                LocalIPAddress   = $LocalAddress.IPAddress
                LocalMACAddress  = If ($NIC.MacAddress) { $NIC.MacAddress -replace '-', ':' } Else { $script:NA }
                TargetAddress    = $Connection.TargetAddress
                TargetMACAddress = If ($Neighbor.LinkLayerAddress) { $Neighbor.LinkLayerAddress -replace '-', ':' } Else { $script:NA }
                TargetMACType    = $TargetMACType
                NeighborState    = If ($Neighbor) { $Neighbor.State } Else { $script:NA }
                TargetPort       = $Connection.TargetPortNumber
                TargetPortal     = If ($PortalNames.Count) { $PortalNames -join '; ' } Else { $script:NA }
                RoutePrefix      = If ($Route) { $Route.DestinationPrefix } Else { $script:NA }
                NextHop          = If ($Route) { $Route.NextHop } Else { $script:NA }
                Connected        = $StorageConnected
                Persistent       = $StoragePersistent
                Multipath        = $StorageMultipath
                TargetIQN        = If ($TargetIQNs.Count) { $TargetIQNs -join '; ' } Else { $script:NA }
                SessionCount     = $Sessions.Count
                ConnectionCount  = $ConnectionGroup.Count
            }
            $iSCSIPathRecords.Add($PathRecord)

            If (-not $iSCSILookup.ContainsKey($InterfaceIndex)) {
                $iSCSILookup[$InterfaceIndex] = [System.Collections.Generic.List[object]]::new()
            }
            $iSCSILookup[$InterfaceIndex].Add($PathRecord)

            ### The route-selected local address is authoritative for this storage path.
            ### Add it to the host IP lookup if normal Get-NetIPAddress enumeration missed it.
            If (-not $ipLookup.ContainsKey($InterfaceIndex)) {
                $ipLookup[$InterfaceIndex] = @($LocalAddress.IPAddress)
            } ElseIf ($ipLookup[$InterfaceIndex] -notcontains $LocalAddress.IPAddress) {
                $ipLookup[$InterfaceIndex] = @($ipLookup[$InterfaceIndex]) + $LocalAddress.IPAddress
            }
        }
    } Else {
        Write-Verbose -Message 'iSCSI cmdlets or Find-NetRoute are unavailable. iSCSI storage discovery was skipped.'
    }
    #endregion

    #region Direct NAS / Storage Peer Discovery
    $StoragePeerLookup = @{}
    ForEach ($adapter in $allAdapters) {
        $adapterInterfaceIndex = [int]$adapter.InterfaceIndex
        $LocalIPs              = @($ipLookup[$adapterInterfaceIndex])
        ForEach ($LocalIP in $LocalIPs) {
            $IPAddressObject = Get-NetIPAddress -InterfaceIndex $adapterInterfaceIndex -AddressFamily IPv4 @script:EA0 | Where-Object {
                $_.IPAddress -eq $LocalIP
            } | Select-Object -First 1

            If (-not $IPAddressObject) {
                Continue
            }

            ### Dedicated /30 networks have only one possible remote host.
            If ($IPAddressObject.PrefixLength -eq 30) {
                $Octets      = $LocalIP -split '\.'
                $HostOctet   = [int]$Octets[3]
                $NetworkBase = $HostOctet -band 252

                $PeerCandidates = @(
                    ('{0}.{1}.{2}.{3}' -f $Octets[0],$Octets[1],$Octets[2],($NetworkBase + 1)), ('{0}.{1}.{2}.{3}' -f $Octets[0],$Octets[1],$Octets[2],($NetworkBase + 2))
                ) | Where-Object {
                    $_ -ne $LocalIP
                }

                ForEach ($PeerIP in $PeerCandidates) {
                    If (-not (Test-Connection -ComputerName $PeerIP -Count 1 -Quiet @script:EA0)) {
                        Continue
                    }

                    $SMB   = Test-NetConnection -ComputerName $PeerIP -Port 445 @IL0 @script:EA0
                    $ISCSI = Test-NetConnection -ComputerName $PeerIP -Port 3260 @IL0 @script:EA0
                    $HTTPS = Test-NetConnection -ComputerName $PeerIP -Port 443 @IL0 @script:EA0
                    $HTTP  = Test-NetConnection -ComputerName $PeerIP -Port 80 @IL0 @script:EA0

                    $Neighbor = Get-NetNeighbor -InterfaceIndex $adapterInterfaceIndex -IPAddress $PeerIP -AddressFamily IPv4 @script:EA0 | Where-Object {
                        $_.State -notin 'Unreachable','Incomplete'
                    } | Select-Object -First 1

                    $StoragePeerLookup[$adapterInterfaceIndex] = [PSCustomObject]@{
                        InterfaceIndex  = $adapterInterfaceIndex
                        AdapterName     = $adapter.Name
                        LocalIPAddress  = $LocalIP
                        LocalMACAddress = If ($adapter.MacAddress) { $adapter.MacAddress -replace '-', ':' } Else { $script:NA }
                        PeerIPAddress   = $PeerIP
                        PeerMACAddress  = If ($Neighbor.LinkLayerAddress) { $Neighbor.LinkLayerAddress -replace '-', ':' } Else { $script:NA }
                        NeighborState   = If ($Neighbor) { $Neighbor.State } Else { $script:NA }
                        SMB             = [bool]$SMB
                        ISCSI           = [bool]$ISCSI
                        HTTPS           = [bool]$HTTPS
                        HTTP            = [bool]$HTTP
                    }
                }
            }
        }
    }
    #endregion

    #region Passive LLDP Discovery Using NetEventSession
    If ($LLDPCaptureSeconds -gt 0) {
        Try {
            If (-not (Get-Command Invoke-DiscoveryProtocolCapture @script:EA0) -or -not (Get-Command Get-DiscoveryProtocolData @script:EA0)) {
                . Register-PSDiscoveryProtocol
            }

            If (-not (Get-Command Invoke-DiscoveryProtocolCapture @script:EA0) -or -not (Get-Command Get-DiscoveryProtocolData @script:EA0)) {
                Throw 'Discovery protocol functions failed to register.'
            }

            Write-Verbose -Message ('Starting NetEventSession LLDP capture for {0} seconds.' -f $LLDPCaptureSeconds)

            $lldpCaptureStatus = 'Capture Started'
            $DecodeErrors      = 0
            $Packets           = @(Invoke-DiscoveryProtocolCapture -Type LLDP -Duration $LLDPCaptureSeconds @script:EA1)
            $lldpCaptureStatus = 'LLDP Not Seen'

            ForEach ($Packet in $Packets) {
                Try {
                    $PhysicalAdapter    = $allAdapters | Where-Object { $_.InterfaceIndex -eq $Packet.MiniportIfIndex } | Select-Object -First 1

                    If (-not $PhysicalAdapter) {
                        Continue
                    }

                    $Data               = Get-DiscoveryProtocolData -Packet $Packet @script:EA1

                    $PhysicalSwitch     = If ($Data.Device) {
                        [string]$Data.Device
                    } ElseIf ($Data.ChassisId) {
                        [string]$Data.ChassisId
                    } Else {
                        $script:NA
                    }

                    $PhysicalSwitchPort = If ($Data.Port) {
                        [string]$Data.Port
                    } ElseIf ($Data.PortDescription) {
                        [string]$Data.PortDescription
                    } Else {
                        $script:NA
                    }

                    $NeighborRecord     = [PSCustomObject]@{
                        ComponentId          = $script:NA
                        AdapterName          = $PhysicalAdapter.Name
                        InterfaceDescription = $PhysicalAdapter.InterfaceDescription
                        InterfaceIndex       = $PhysicalAdapter.InterfaceIndex
                        MACAddress           = If ($PhysicalAdapter.MacAddress) { $PhysicalAdapter.MacAddress -replace '-', ':' } Else { $script:NA }
                        PhysicalSwitch       = $PhysicalSwitch
                        PhysicalSwitchPort   = $PhysicalSwitchPort
                        SwitchChassisID      = If ($Data.ChassisId) { [string]$Data.ChassisId } Else { $script:NA }
                        LLDPVLAN             = If ($null -ne $Data.VLAN -and "$($Data.VLAN)" -ne '') { [string]$Data.VLAN } Else { $script:NA }
                        DiscoverySource      = 'LLDP/NetEventSession'
                    }

                    $lldpLookup[$PhysicalAdapter.InterfaceDescription] = $NeighborRecord
                } Catch {
                    $DecodeErrors++
                    Write-Verbose -Message ('LLDP packet decoding failed: {0}' -f $_.Exception.Message)
                }
            }

            ForEach ($Neighbor in @($lldpLookup.Values)) {
                $lldpRecords.Add($Neighbor)
            }

            If ($lldpLookup.Count) {
                $lldpCaptureStatus = 'LLDP/NetEventSession'
            } ElseIf ($DecodeErrors) {
                $lldpCaptureStatus = 'LLDP Decode Error'
            }
        } Catch {
            $lldpCaptureStatus = 'NetEventSession Error'
            Write-Verbose -Message ('LLDP discovery failed: {0}' -f $_.Exception.Message)
        }
    } Else {
        $lldpCaptureStatus = 'Disabled'
    }
    #endregion

    #region Helper Functions
    $GetNewIP = {
        Param (
            [string]$CurrentIP, 
            [string]$Subnet
        )

        If (-not $Subnet -or -not $CurrentIP -or $CurrentIP -eq 'N/A') {
            Return ''
        }

        $NewAddresses = @()
        ForEach ($Address in ($CurrentIP -split ';')) {
            $Address = $Address.Trim()
            If ($Address -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
                $LastOctet     = ($Address -split '\.')[-1]
                $NewAddresses += ('{0}.{1}' -f $Subnet,$LastOctet)
            }
        }

        Return ($NewAddresses -join '; ')
    }
    #endregion

    #region Build Unified Data Array
    ### Host Physical Adapters
    ForEach ($adapter in $allAdapters) {
        $adapterInterfaceIndex = [int]$adapter.InterfaceIndex

        $ip  = If ($ipLookup.ContainsKey($adapterInterfaceIndex)) {
            $ipLookup[$adapterInterfaceIndex] -join '; '
        } Else {
            $script:NA
        }

        $vSw = If (-not $vSwitchAccess) {
            'Unknown'
        } ElseIf ($vSwitchMap.ContainsKey($adapter.InterfaceDescription)) {
            $vSwitchMap[$adapter.InterfaceDescription]
        } Else {
            'None'
        }

        $mac = If ($adapter.MacAddress) {
            $adapter.MacAddress -replace '-', ':'
        } Else {
            $script:NA
        }

        ### Resolve any iSCSI paths using this physical NIC
        $iSCSIPaths = @()
        If ($iSCSILookup.ContainsKey($adapterInterfaceIndex)) {
            $iSCSIPaths = @($iSCSILookup[$adapterInterfaceIndex] | ForEach-Object {$_})
        }

        ### Resolve any directly-connected NAS/storage peer using this physical NIC
        $StoragePeer = If ($StoragePeerLookup.ContainsKey($adapterInterfaceIndex)) {
            $StoragePeerLookup[$adapterInterfaceIndex]
        } Else {
            $null
        }

        ### Resolve physical switch neighbor
        $LLDPNeighbor = If ($lldpLookup.ContainsKey($adapter.InterfaceDescription)) {
            $lldpLookup[$adapter.InterfaceDescription]
        } Else {
            $null
        }

        ### Determine configured and active network roles
        $configuredRole = If ($adapter.Name -match '(?i)iSCSI|SAN|NAS|Storage') {
            'Storage/iSCSI'
        } Else {
            $script:NA
        }

        $activeRole     = If ($vSw -ne 'None' -and $vSw -ne 'Unknown' -and $iSCSIPaths.Count) {
            'Hyper-V; iSCSI'
        } ElseIf ($vSw -ne 'None' -and $vSw -ne 'Unknown') {
            'Hyper-V'
        } ElseIf ($iSCSIPaths.Count) {
            'iSCSI'
        } ElseIf ($StoragePeer -and $StoragePeer.SMB) {
            'NAS/SMB'
        } ElseIf ($StoragePeer -and $StoragePeer.ISCSI) {
            'iSCSI'
        } ElseIf ($StoragePeer) {
            'Storage'
        } Else {
            'None'
        }

        ### Do not propose production subnet renumbering for storage interfaces
        If ($configuredRole -eq 'Storage/iSCSI') {
            $calculatedNewIP = ''
        } Else {
            $calculatedNewIP = & $GetNewIP -CurrentIP $ip -Subnet $NewSN
        }

        $storageTargetAddress = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.TargetAddress | Sort-Object -Unique) -join '; '
        } Else {
            $script:NA
        }

        $storageTargetPort    = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.TargetPort | Sort-Object -Unique) -join '; '
        } Else {
            $script:NA
        }

        $storageTargetPortal  = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.TargetPortal | Where-Object {$_ -and $_ -ne 'N/A'} | Sort-Object -Unique) -join '; '
        } Else {
            $script:NA
        }

        If (-not $storageTargetPortal) {
            $storageTargetPortal = 'N/A'
        }

        $storageTargetIQN     = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.TargetIQN | Where-Object {$_ -and $_ -ne 'N/A'} | Sort-Object -Unique) -join '; '
        } Else {
            $script:NA
        }

        If (-not $storageTargetIQN) {
            $storageTargetIQN = $script:NA
        }

        $storageConnected       = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.Connected | Sort-Object -Unique) -join '; '
        } Else {
            $script:NA
        }

        $storagePersistent      = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.Persistent | Sort-Object -Unique) -join '; '
        } Else {
            $script:NA
        }

        $storageMultipath       = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.Multipath | Sort-Object -Unique) -join '; '
        } Else {
            $script:NA
        }

        $storageSessionCount    = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.SessionCount | Measure-Object -Sum).Sum
        } Else {
            $script:NA
        }

        $storageConnectionCount = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.ConnectionCount | Measure-Object -Sum).Sum
        } Else {
            $script:NA
        }

        $physicalSwitch         = If ($LLDPNeighbor)     {
            $LLDPNeighbor.PhysicalSwitch
        } Else {
            $script:NA
        }

        $physicalSwitchPort     = If ($LLDPNeighbor)     {
            $LLDPNeighbor.PhysicalSwitchPort
        } Else {
            $script:NA
        }

        $switchChassisID        = If ($LLDPNeighbor)     {
            $LLDPNeighbor.SwitchChassisID
        } Else {
            $script:NA
        }

        $lldpVLAN = If ($LLDPNeighbor) {
            $LLDPNeighbor.LLDPVLAN
        } Else {
            $script:NA
        }

        $switchDiscovery = If ($LLDPNeighbor) {
            $LLDPNeighbor.DiscoverySource
        } ElseIf ($adapter.Status -ne 'Up') {
            $script:NA
        } ElseIf ($lldpCaptureStatus -eq 'LLDP/NetEventSession') {
            'LLDP Not Seen'
        } Else {
            $lldpCaptureStatus
        }

        $storageLocalMAC = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.LocalMACAddress | Where-Object {$_ -and $_ -ne $script:NA} | Sort-Object -Unique) -join '; '
        } ElseIf ($StoragePeer) {
            $StoragePeer.LocalMACAddress
        } Else {
            $script:NA
        }

        $storagePeerIP = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.TargetAddress | Sort-Object -Unique) -join '; '
        } ElseIf ($StoragePeer) {
            $StoragePeer.PeerIPAddress
        } Else {
            $script:NA
        }

        $storagePeerMAC = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.TargetMACAddress | Where-Object {$_ -and $_ -ne $script:NA} | Sort-Object -Unique) -join '; '
        } ElseIf ($StoragePeer) {
            $StoragePeer.PeerMACAddress
        } Else {
            $script:NA
        }

        $storageNeighborState = If ($iSCSIPaths.Count) {
            ($iSCSIPaths.NeighborState | Where-Object {$_ -and $_ -ne $script:NA} | Sort-Object -Unique) -join '; '
        } ElseIf ($StoragePeer) {
            $StoragePeer.NeighborState
        } Else {
            $script:NA
        }

        $isIDRACNDIS = $adapter.InterfaceDescription -match 'Remote NDIS|iDRAC'

        $allRecords.Add(
            [PSCustomObject]@{
                HostName               = $env:COMPUTERNAME
                HostFormFactor         = $hostType
                Manufacturer           = $hostManufacturer
                Model                  = $hostModel
                SerialNumber           = $hostSerial
                OSVersion              = $osVersion
                AdapterType            = 'Host Physical'
                VMName                 = If ($isIDRACNDIS -and $iDRAC -and $iDRAC.DNSName) { ($iDRAC.DNSName -split '\.')[0] } Else { $script:NA }
                AdapterName            = $adapter.Name
                InterfaceDescription   = $adapter.InterfaceDescription
                InterfaceIndex         = $adapterInterfaceIndex
                vSwitch                = $vSw
                MACAddress             = $mac
                MacAddressType         = 'Static (Hardware)'
                CurrentIPAddress       = $ip
                IPFrom                 = If ($ip -ne $script:NA) { 'LOCAL' } Else { $script:NA }
                NewIPAddress           = $calculatedNewIP
                ConfiguredRole         = $configuredRole
                ActiveRole             = $activeRole
                PhysicalSwitch         = $physicalSwitch
                PhysicalSwitchPort     = $physicalSwitchPort
                SwitchChassisID        = $switchChassisID
                LLDPVLAN               = $lldpVLAN
                SwitchDiscovery        = $switchDiscovery
                iDRACDNSName           = If ($isIDRACNDIS -and $iDRAC) { $iDRAC.DNSName } Else { $script:NA }
                iDRACManagementIP      = If ($isIDRACNDIS -and $iDRAC) { $iDRAC.ManagementIPAddress } Else { $script:NA }
                iDRACManagementMAC     = If ($isIDRACNDIS -and $iDRAC) { $iDRAC.ManagementMACAddress } Else { $script:NA }
                iDRACNewIPAddress      = If ($isIDRACNDIS -and $iDRAC) { & $GetNewIP -CurrentIP $iDRAC.ManagementIPAddress -Subnet $NewSN} Else { $script:NA }
                iDRACInternalIP        = If ($isIDRACNDIS -and $iDRAC) { $iDRAC.InternalBMCIPAddress } Else { $script:NA }
                iDRACInternalMAC       = If ($isIDRACNDIS -and $iDRAC) { $iDRAC.InternalBMCMACAddress } Else { $script:NA }
                iDRACMACConfirmed      = If ($isIDRACNDIS -and $iDRAC) { $iDRAC.ManagementMACConfirmed } Else { $script:NA }
                StorageProtocol        = If ($iSCSIPaths.Count) { 'iSCSI' } ElseIf ($StoragePeer -and $StoragePeer.SMB) { 'SMB' } ElseIf ($StoragePeer -and $StoragePeer.ISCSI) { 'iSCSI' } ElseIf ($StoragePeer) { 'Storage' } Else { $script:NA }
                StorageLocalMAC        = $storageLocalMAC
                StoragePeerIP          = $storagePeerIP
                StoragePeerMAC         = $storagePeerMAC
                StorageNeighborState   = $storageNeighborState
                StorageSMB             = If ($StoragePeer) { $StoragePeer.SMB } Else { $script:NA }
                StorageISCSI           = If ($iSCSIPaths.Count) { $true } ElseIf ($StoragePeer) { $StoragePeer.ISCSI } Else { $script:NA }
                StorageHTTPS           = If ($StoragePeer) { $StoragePeer.HTTPS } Else { $script:NA }
                StorageHTTP            = If ($StoragePeer) { $StoragePeer.HTTP } Else { $script:NA }
                StorageTargetPortal    = $storageTargetPortal
                StorageTargetAddress   = $storageTargetAddress
                StorageTargetPort      = $storageTargetPort
                StorageTargetIQN       = $storageTargetIQN
                StorageConnected       = $storageConnected
                StoragePersistent      = $storagePersistent
                StorageMultipath       = $storageMultipath
                StorageSessionCount    = $storageSessionCount
                StorageConnectionCount = $storageConnectionCount
                Status                 = $adapter.Status
            }
        )
    }

    ### Hyper-V VM Guest Adapters
    $vmAdapters = @(Get-VMNetworkAdapter -VMName * @EA0)
    ForEach ($vmNic in $vmAdapters) {
        ### Resolve the physical host adapter backing this VM's vSwitch
        $PhysicalUplinks = @(
            $allRecords | Where-Object {
                $_.AdapterType -eq 'Host Physical' -and 
                $_.vSwitch -ne 'None' -and 
                $_.vSwitch -ne 'Unknown' -and 
                (@($_.vSwitch -split '; ') -contains $vmNic.SwitchName)
            }
        )

        $PhysicalUplink  = $PhysicalUplinks | Select-Object -First 1

        $macFormatted    = If ($vmNic.MacAddress) {
            $vmNic.MacAddress -replace '(?<=\G[0-9A-Fa-f]{2})(?=[0-9A-Fa-f]{2})', ':'
        } Else {
            $script:NA
        }

        $vmState         = If ($vmStateLookup.ContainsKey($vmNic.VMName)) {
            $vmStateLookup[$vmNic.VMName]
        } Else {
            'Unknown'
        }

        $localIPs        = @(
            $vmNic.IPAddresses | Where-Object {
                $_ -match '^(?:\d{1,3}\.){3}\d{1,3}$' -and 
                $_ -notlike '169.254.*' -and 
                $_ -ne '127.0.0.1'
            } | Sort-Object -Unique
        )

        $resolvedIP      = $script:NA
        $ipSource        = $script:NA

        If ($localIPs.Count) {
            $resolvedIP = $localIPs -join '; '
            $ipSource   = 'HYPER-V'
        } Else {
            Try {
                $dnsResult = @(
                    Resolve-DnsName -Name $vmNic.VMName -Type A @EA1 | Where-Object {
                        $_.Type -eq 'A'
                    } | Select-Object -ExpandProperty IPAddress -Unique
                )

                If ($dnsResult.Count) {
                    $resolvedIP = $dnsResult -join '; '
                    $ipSource   = 'DNS'
                }
            } Catch {
                Write-Verbose -Message ('Unable to resolve {0} through DNS: {1}' -f $vmNic.VMName,$_.Exception.Message)
            }
        }

        $macType = If (-not $vmNic.MacAddress) {
            $script:NA
        } ElseIf ($vmNic.PSObject.Properties['DynamicMacAddressEnabled']) {
            If ($vmNic.DynamicMacAddressEnabled) {
                'Dynamic'
            } Else {
                'Static'
            }
        } ElseIf ($vmNic.PSObject.Properties['DynamicMacAddress']) {
            If ($vmNic.DynamicMacAddress) {
                'Dynamic'
            } Else {
                'Static'
            }
        } Else {
            $script:UN
        }

        $calculatedNewIP = & $GetNewIP -CurrentIP $resolvedIP -Subnet $NewSN

        $allRecords.Add(
            [PSCustomObject]@{
                HostName               = $env:COMPUTERNAME
                HostFormFactor         = $hostType
                Manufacturer           = $hostManufacturer
                Model                  = $hostModel
                SerialNumber           = $hostSerial
                OSVersion              = $osVersion
                AdapterType            = 'VM Guest'
                VMName                 = $vmNic.VMName
                AdapterName            = If ($PhysicalUplink) { $PhysicalUplink.AdapterName } Else { $vmNic.Name }
                InterfaceDescription   = If ($PhysicalUplink) { $PhysicalUplink.InterfaceDescription } Else { $script:NA }
                InterfaceIndex         = If ($PhysicalUplink) { $PhysicalUplink.InterfaceIndex } Else { $script:NA }
                vSwitch                = If ($vmNic.SwitchName) { $vmNic.SwitchName } Else { $script:NA }
                MACAddress             = $macFormatted
                MacAddressType         = $macType
                CurrentIPAddress       = $resolvedIP
                IPFrom                 = $ipSource
                NewIPAddress           = $calculatedNewIP
                ConfiguredRole         = $script:NA
                ActiveRole             = If ($PhysicalUplink) { 'VM Guest; Hyper-V' } Else { 'VM Guest' }
                PhysicalSwitch         = If ($PhysicalUplink) { $PhysicalUplink.PhysicalSwitch } Else { $script:NA }
                PhysicalSwitchPort     = If ($PhysicalUplink) { $PhysicalUplink.PhysicalSwitchPort } Else { $script:NA }
                SwitchChassisID        = If ($PhysicalUplink) { $PhysicalUplink.SwitchChassisID } Else { $script:NA }
                LLDPVLAN               = If ($PhysicalUplink) { $PhysicalUplink.LLDPVLAN } Else { $script:NA }
                SwitchDiscovery        = If ($PhysicalUplink) { $PhysicalUplink.SwitchDiscovery } Else { $script:NA }
                StorageLocalMAC        = $script:NA
                StoragePeerIP          = $script:NA
                StoragePeerMAC         = $script:NA
                StorageNeighborState   = $script:NA
                StorageSMB             = $script:NA
                StorageISCSI           = $script:NA
                StorageHTTPS           = $script:NA
                StorageHTTP            = $script:NA
                StorageTargetPortal    = $script:NA
                StorageTargetAddress   = $script:NA
                StorageTargetPort      = $script:NA
                StorageTargetIQN       = $script:NA
                StorageConnected       = $script:NA
                StoragePersistent      = $script:NA
                StorageMultipath       = $script:NA
                StorageSessionCount    = $script:NA
                StorageConnectionCount = $script:NA
                Status                 = $vmState
            }
        )
    }
    #endregion

    #region iDRAC / Out-of-Band Management
    If ($iDRAC -and $iDRAC.Detected) {
        $iDRACNewIP = & $GetNewIP -CurrentIP $iDRAC.ManagementIPAddress -Subnet $NewSN

        $allRecords.Add(
            [PSCustomObject]@{
                HostName               = $env:COMPUTERNAME
                HostFormFactor         = $hostType
                Manufacturer           = $hostManufacturer
                Model                  = $hostModel
                SerialNumber           = $iDRAC.ServiceTag
                OSVersion              = $osVersion
                AdapterType            = 'iDRAC'
                VMName                 = If ($iDRAC.DNSName) { ($iDRAC.DNSName -split '\.')[0] } Else { $script:NA }
                AdapterName            = 'iDRAC Dedicated Management'
                InterfaceDescription   = $iDRAC.Product
                InterfaceIndex         = $iDRAC.ManagementInterfaceIndex
                vSwitch                = $script:NA
                MACAddress             = $iDRAC.ManagementMACAddress
                MacAddressType         = 'Physical'
                CurrentIPAddress       = $iDRAC.ManagementIPAddress
                IPFrom                 = 'DNS + Redfish MAC Correlation'
                NewIPAddress           = $iDRACNewIP
                ConfiguredRole         = 'Out-of-Band Management'
                ActiveRole             = 'iDRAC'
                PhysicalSwitch         = $script:NA
                PhysicalSwitchPort     = $script:NA
                SwitchChassisID        = $script:NA
                LLDPVLAN               = $script:NA
                SwitchDiscovery        = $script:NA
                StorageProtocol        = $script:NA
                StorageLocalMAC        = $script:NA
                StoragePeerIP          = $script:NA
                StoragePeerMAC         = $script:NA
                StorageNeighborState   = $iDRAC.ManagementNeighborState
                StorageSMB             = $script:NA
                StorageISCSI           = $script:NA
                StorageHTTPS           = $iDRAC.PassthroughReachable
                StorageHTTP            = $script:NA
                StorageTargetPortal    = $script:NA
                StorageTargetAddress   = $script:NA
                StorageTargetPort      = $script:NA
                StorageTargetIQN       = $script:NA
                StorageConnected       = $script:NA
                StoragePersistent      = $script:NA
                StorageMultipath       = $script:NA
                StorageSessionCount    = $script:NA
                StorageConnectionCount = $script:NA
                Status                 = If ($iDRAC.ManagementMACConfirmed) { 'Confirmed' } Else { 'Detected' }
            }
        )
    }
    #endregion iDRAC / Out-of-Band Management

    #region Output Handling
    $RequiredCSVProperties = @('HostName', 'AdapterType', 'AdapterName', 'MACAddress', 'Status')

    $csvProperties         = @()
    $AllPropertyNames      = @($allRecords | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique)

    $csvProperties = @(
        $AllPropertyNames | Where-Object {
            $PropertyName = $_

            If ($RequiredCSVProperties -contains $PropertyName) {
                Return $true
            }

            @(
                $allRecords | Where-Object {
                    $P = $_.PSObject.Properties[$PropertyName]
                    If ($P) {
                        $Value = [string]$P.Value
                        $Value.Trim() -and $Value.Trim() -ne $script:NA
                    }
                }
            ).Count -gt 0
        }
    )

    $Result = [PSCustomObject][ordered]@{
        CollectedAt        = Get-Date
        ADSite             = $Site
        ServersSubnet      = $ServerSubnet.Subnet
        ServersDescription = $ServerSubnet.Description
        ReplacementPrefix  = $NewSN
        LLDPCaptureStatus  = $lldpCaptureStatus
        Records            = @($allRecords)
        ISCSIPaths         = @($iSCSIPathRecords)
        LLDPNeighbors      = @($lldpRecords)
    }

    If ($Out -eq 'Object') {
        Return $Result
    }

    If ($Out -eq 'CSV')    {
        If ($allRecords.Count -eq 0) {
            Return @()
        }

        Return $allRecords | Select-Object -Property $csvProperties | ConvertTo-Csv @script:eCSV1
    }

    Write-Host "`n================ HOST: $env:COMPUTERNAME ================" @Ma
    Write-Host ('OS: {0}' -f $osVersion) @Gy
    Write-Host ('Hardware: {0} {1} | Form: {2} | Serial/Tag: {3}' -f $hostManufacturer, $hostModel, $hostType, $hostSerial) @Gy

    Write-Host "`n=== Host Physical Adapters ===" @Cy
    $PA = @{
        Property = 'HostName', 'AdapterName', 'InterfaceIndex', 'MACAddress', 'CurrentIPAddress', 'NewIPAddress', 'vSwitch', 'ConfiguredRole', 'ActiveRole', 'Status'
        Autosize = $true
    }

    $allRecords | Where-Object {
        $_.AdapterType -eq 'Host Physical'
    } | Format-Table @PA

    Write-Host "`n=== Physical Switch / Port Discovery ===" @Gr
    $PS = @{
        Property = 'AdapterName', 'MACAddress', 'Status', 'PhysicalSwitch', 'PhysicalSwitchPort', 'LLDPVLAN', 'SwitchChassisID', 'SwitchDiscovery'
        Autosize = $true
    }

    $allRecords | Where-Object {
        $_.AdapterType -eq 'Host Physical'
    } | Format-Table @PS

    $StorageNICRecords = @(
        $allRecords | Where-Object {
            $_.AdapterType -eq 'Host Physical' -and 
            ($_.ConfiguredRole -eq 'Storage/iSCSI' -or $_.ActiveRole -match 'iSCSI|NAS|Storage')
        }
    )

    If ($StorageNICRecords.Count) {
        Write-Host "`n=== NAS / Storage NICs ===" @DY
        $TN = @{
            Property = 'AdapterName', 'CurrentIPAddress', 'MACAddress', 'ConfiguredRole', 'ActiveRole', 'StorageProtocol', 'StoragePeerIP', 'StoragePeerMAC', 'StorageNeighborState', 'StorageSMB', 'StorageISCSI', 'StorageHTTPS', 'StorageHTTP', 'Status'
            Autosize = $true
        }
        $StorageNICRecords | Format-Table @TN
    }

    If ($iSCSIPathRecords.Count) {
        Write-Host "`n=== iSCSI / NAS Storage Connections ===" @DC
        $NC = @{Property = 'InterfaceAlias', 'InterfaceIndex', 'LocalIPAddress', 'TargetPortal', 'TargetAddress', 'TargetPort', 'RoutePrefix', 'NextHop', 'Connected', 'Persistent', 'Multipath', 'SessionCount', 'ConnectionCount', 'TargetIQN'}
        $iSCSIPathRecords | Format-List @NC
    }

    Write-Host "`n=== VM Guest Adapters ===" @Ye
    $GA = @{
        Property = 'VMName', 'AdapterName', 'vSwitch', 'MACAddress', 'MacAddressType', 'CurrentIPAddress', 'IPFrom', 'NewIPAddress', 'Status'
        Autosize = $true
    }

    $allRecords | Where-Object {
        $_.AdapterType -eq 'VM Guest'
    } | Format-Table @GA
    #endregion
}

Function Get-iDRACInventory {
    <#
        .SYNOPSIS
        Discovers local Dell iDRAC management information from Windows.

        .DESCRIPTION
        Get-iDRACInventory attempts to discover and correlate Dell iDRAC management information
        from the local Windows operating system without requiring RACADM or iDRAC credentials.

        The function detects the Dell Remote NDIS / OS-to-iDRAC pass-through adapter, determines
        the Windows-side and iDRAC-side internal link-local addresses, and tests HTTPS connectivity
        to the local iDRAC Redfish service.

        When the unauthenticated Redfish ServiceRoot is available, the function retrieves the Dell
        service tag, Redfish version, product information, and the authoritative iDRAC management
        MAC address.

        The function also attempts to resolve common iDRAC DNS naming conventions based on the local
        computer name and correlates the resolved management IP address with the Windows neighbor
        cache. When the neighbor MAC matches the Redfish-reported management MAC, the management
        address is marked as confirmed.

        All MAC addresses returned by the function are normalized to colon-delimited uppercase
        notation.

        .OUTPUTS
        System.Management.Automation.PSCustomObject

        Returns an object containing the following properties:

        Detected
            Indicates whether a Dell iDRAC was positively identified through the local Redfish
            ServiceRoot.

        Product
            Product name reported by Redfish.

        Vendor
            Vendor reported by Redfish.

        ServiceTag
            Dell service tag reported by Redfish.

        RedfishVersion
            Redfish protocol version reported by the iDRAC ServiceRoot.

        DNSName
            Resolved iDRAC DNS name, when found.

        ManagementIPAddress
            Routable iDRAC management IPv4 address resolved through DNS.

        ManagementMACAddress
            Dedicated iDRAC management MAC address reported by Redfish.

        ManagementMACSource
            Source used to determine the management MAC address.

        ManagementMACConfirmed
            Indicates whether the Redfish management MAC matches the MAC learned for the resolved
            management IP address through the Windows neighbor cache.

        ManagementLearnedVia
            Windows interface through which the routable iDRAC neighbor was learned.

        ManagementInterfaceIndex
            Interface index associated with the routable iDRAC neighbor entry.

        ManagementNeighborState
            Current Windows neighbor-cache state for the routable iDRAC management address.

        InternalHostIPAddress
            Windows-side IPv4 address of the OS-to-iDRAC Remote NDIS connection.

        InternalHostMACAddress
            Windows-side MAC address of the OS-to-iDRAC Remote NDIS connection.

        InternalBMCIPAddress
            iDRAC-side IPv4 address of the internal OS-to-iDRAC connection.

        InternalBMCMACAddress
            iDRAC-side MAC address of the internal OS-to-iDRAC connection.

        PassthroughAdapter
            Windows adapter name used for OS-to-iDRAC communication.

        PassthroughInterfaceIndex
            Windows interface index of the OS-to-iDRAC adapter.

        PassthroughReachable
            Indicates whether HTTPS on the internal iDRAC address is reachable.

        .EXAMPLE
        PS C:\> Get-iDRACInventory

        Discovers iDRAC information for the local Dell server and returns a structured object.

        .EXAMPLE
        PS C:\> $iDRAC = Get-iDRACInventory
        PS C:\> $iDRAC | Format-List

        Stores the discovered iDRAC information and displays all returned properties.

        .NOTES
        Requires Windows PowerShell 5.1 or later.

        Dell OS-to-iDRAC pass-through must be available for local Redfish discovery.

        The local Redfish ServiceRoot is queried with an embedded .NET HTTPS client that accepts the
        iDRAC's self-signed certificate for that single request only. No external executable is used.

        Deeper Redfish resources normally require iDRAC authentication; this function intentionally
        uses only information available from the unauthenticated ServiceRoot and local Windows
        network discovery.
    #>
    [CmdletBinding()]
    Param ()

    $IDRAC = [ordered]@{
        Detected                  = $false
        Product                   = $null
        Vendor                    = $null
        ServiceTag                = $null
        RedfishVersion            = $null
        DNSName                   = $null
        ManagementIPAddress       = $null
        ManagementMACAddress      = $null
        ManagementMACSource       = $null
        ManagementMACConfirmed    = $false
        ManagementLearnedVia      = $null
        ManagementInterfaceIndex  = $null
        ManagementNeighborState   = $null
        InternalHostIPAddress     = $null
        InternalHostMACAddress    = $null
        InternalBMCIPAddress      = $null
        InternalBMCMACAddress     = $null
        PassthroughAdapter        = $null
        PassthroughInterfaceIndex = $null
        PassthroughReachable      = $false
    }

    $NDIS = Get-NetAdapter -IncludeHidden @script:EA0 | Where-Object {
        $_.InterfaceDescription -match 'Remote NDIS|iDRAC'
    } | Select-Object -First 1

    If ($NDIS) {
        $NDISIP = Get-NetIPAddress -InterfaceIndex $NDIS.IfIndex -AddressFamily IPv4 @script:EA0 | Where-Object {
            $_.IPAddress -like '169.254.*'
        } | Select-Object -First 1

        If ($NDISIP) {
            $IDRAC.PassthroughAdapter        = $NDIS.Name
            $IDRAC.PassthroughInterfaceIndex = $NDIS.IfIndex
            $IDRAC.InternalHostIPAddress     = $NDISIP.IPAddress
            $IDRAC.InternalHostMACAddress    = $NDIS.MacAddress.Replace('-',':')
            $IDRAC.InternalBMCIPAddress      = (($NDISIP.IPAddress -split '\.')[0..2] -join '.') + '.1'

            $IDRAC.PassthroughReachable      = Test-NetConnection -ComputerName $IDRAC.InternalBMCIPAddress -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
            If ($IDRAC.PassthroughReachable) {
                $Neighbor = Get-NetNeighbor -InterfaceIndex $NDIS.IfIndex -IPAddress $IDRAC.InternalBMCIPAddress @script:EA0 | Where-Object {
                    $_.State -ne 'Unreachable' -and
                    $_.LinkLayerAddress -and
                    $_.LinkLayerAddress -ne '00-00-00-00-00-00'
                } | Select-Object -First 1

                If ($Neighbor) {
                    $IDRAC.InternalBMCMACAddress = $Neighbor.LinkLayerAddress.Replace('-',':')
                }

                Try {
                    If (-not ('HardwareInventory.LocalHttps' -as [type])) {
                        Add-Type -TypeDefinition $script:LocalHttpsSource -Language CSharp -IgnoreWarnings -WarningAction SilentlyContinue @script:EA1
                    }

                    $RootJson = [HardwareInventory.LocalHttps]::Get(('https://{0}/redfish/v1/' -f $IDRAC.InternalBMCIPAddress),5000)

                    If ($RootJson) {
                        $Root    = $RootJson | ConvertFrom-Json
                        $RootGet = {
                            Param ($Object,[string[]]$Path)

                            ForEach ($Name in $Path) {
                                If ($null -eq $Object -or -not $Object.PSObject.Properties[$Name]) {
                                    Return $null
                                }

                                $Object = $Object.$Name
                            }

                            Return $Object
                        }

                        If ((& $RootGet $Root 'Product') -match 'Integrated Dell Remote Access Controller') {
                            $IDRAC.Detected       = $true
                            $IDRAC.Product        = & $RootGet $Root 'Product'
                            $IDRAC.Vendor         = & $RootGet $Root 'Vendor'
                            $IDRAC.RedfishVersion = & $RootGet $Root 'RedfishVersion'
                            $IDRAC.ServiceTag     = & $RootGet $Root 'ServiceIdentification'

                            $ManagerMAC = & $RootGet $Root 'Oem','Dell','ManagerMACAddress'
                            If ($ManagerMAC) {
                                $IDRAC.ManagementMACAddress = ([string]$ManagerMAC).ToUpper()
                                $IDRAC.ManagementMACSource  = 'Redfish ServiceRoot'
                            }
                        }
                    }
                } Catch {
                    Write-Verbose -Message ('Unable to query local iDRAC Redfish ServiceRoot: {0}' -f $_.Exception.Message)
                }
            }
        }
    }

    $ComputerName = $env:COMPUTERNAME

    ForEach ($Name in @("$ComputerName-idrac","$ComputerName`idrac","idrac-$ComputerName")) {
        Try {
            $DNS = Resolve-DnsName -Name $Name -Type A @script:EA1 | Where-Object {
                $_.Type -eq 'A'
            } | Select-Object -First 1

            If ($DNS) {
                $IDRAC.DNSName             = $DNS.Name
                $IDRAC.ManagementIPAddress = $DNS.IPAddress

                Break
            }
        } Catch {
            Write-Verbose -Message ('Unable to resolve iDRAC DNS candidate {0}: {1}' -f $Name,$_.Exception.Message)
        }
    }

    If ($IDRAC.ManagementIPAddress) {
        $null = Test-Connection -ComputerName $IDRAC.ManagementIPAddress -Count 1 -Quiet @script:EA0

        $Neighbor = Get-NetNeighbor -IPAddress $IDRAC.ManagementIPAddress @script:EA0 | Where-Object {
            $_.State -ne 'Unreachable' -and
            $_.LinkLayerAddress -and
            $_.LinkLayerAddress -ne '00-00-00-00-00-00'
        } | Select-Object -First 1

        If ($Neighbor) {
            $IDRAC.ManagementLearnedVia     = $Neighbor.InterfaceAlias
            $IDRAC.ManagementInterfaceIndex = $Neighbor.ifIndex
            $IDRAC.ManagementNeighborState  = [string]$Neighbor.State

            If (
                $IDRAC.ManagementMACAddress -and 
                (($Neighbor.LinkLayerAddress -replace '-',':').ToUpper() -eq $IDRAC.ManagementMACAddress)
            ) {
                $IDRAC.ManagementMACConfirmed = $true
            }
        }
    }

    Return [PSCustomObject]$IDRAC
}

Function ConvertTo-HardwareInventoryCsvRows {
    <#
        .SYNOPSIS
        Flattens the complete local hardware inventory into lossless long-form CSV records.

        .DESCRIPTION
        Flattens the inventory into one row per item (computer, CPU, memory module, disk, volume,
        adapter, monitor, printer, dock and so on) with a consistent column set, for the hardware CSV
        report.

        .PARAMETER Inventory
        Complete hardware inventory object.

        .EXAMPLE
        ConvertTo-HardwareInventoryCsvRows -Inventory $Inventory | Export-Csv -LiteralPath .\Hardware.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,HelpMessage='Inventory')]
        [object]$Inventory
    )

    $Rows   = @()

    $Common = @{
        ComputerName = $Inventory.Computer.ComputerName
        Manufacturer = $Inventory.Computer.Manufacturer
        Model        = $Inventory.Computer.Model
        ServiceTag   = $Inventory.Computer.ServiceTag
    }

    $Rows += [PSCustomObject][ordered]@{
        ComputerName   = $Common.ComputerName
        RecordType     = 'Computer'
        Name           = $Inventory.Computer.ComputerName
        Manufacturer   = $Common.Manufacturer
        Model          = $Common.Model
        SerialNumber   = $Common.ServiceTag
        Status         = $Inventory.Computer.ComputerType
        Detail1        = $Inventory.Computer.OS
        Detail2        = ('{0} / {1}' -f $Inventory.Computer.Version,$Inventory.Computer.OSBuild)
        Detail3        = $Inventory.Computer.Chassis
        IPAddress      = $null
        MACAddress     = $null
        InterfaceIndex = $null
        Capacity       = $null
        Location       = $null
    }

    If ($Inventory.iDRAC -and $Inventory.iDRAC.Detected) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'iDRAC'
            Name           = $Inventory.iDRAC.DNSName
            Manufacturer   = $Inventory.iDRAC.Vendor
            Model          = $Inventory.iDRAC.Product
            SerialNumber   = $Inventory.iDRAC.ServiceTag
            Status         = If ($Inventory.iDRAC.ManagementMACConfirmed) {'Confirmed'} Else {'Detected'}
            Detail1        = ('Redfish {0}' -f $Inventory.iDRAC.RedfishVersion)
            Detail2        = ('BMC {0} / Host {1}' -f $Inventory.iDRAC.InternalBMCIPAddress,$Inventory.iDRAC.InternalHostIPAddress)
            Detail3        = ('Learned via {0}' -f $Inventory.iDRAC.ManagementLearnedVia)
            IPAddress      = $Inventory.iDRAC.ManagementIPAddress
            MACAddress     = $Inventory.iDRAC.ManagementMACAddress
            InterfaceIndex = $Inventory.iDRAC.ManagementInterfaceIndex
            Capacity       = $null
            Location       = 'Out-of-Band Management'
        }
    }

    ForEach ($Processor in @($Inventory.CPU)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'CPU'
            Name           = $Processor.Name
            Manufacturer   = $Processor.Manufacturer
            Model          = $Processor.Name
            SerialNumber   = $null
            Status         = $null
            Detail1        = ('{0} cores / {1} logical' -f $Processor.Cores,$Processor.LogicalProcessors)
            Detail2        = ('{0} MHz' -f $Processor.MaxClockMHz)
            Detail3        = $null
            IPAddress      = $null
            MACAddress     = $null
            InterfaceIndex = $null
            Capacity       = $null
            Location       = $Processor.Socket
        }
    }

    ForEach ($Memory in @($Inventory.Memory.Modules)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'Memory'
            Name           = $Memory.PartNumber
            Manufacturer   = $Memory.Manufacturer
            Model          = $Memory.Type
            SerialNumber   = $Memory.SerialNumber
            Status         = $Memory.Status
            Detail1        = ('{0} MHz' -f $Memory.SpeedMHz)
            Detail2        = $Memory.FormFactor
            Detail3        = $null
            IPAddress      = $null
            MACAddress     = $null
            InterfaceIndex = $null
            Capacity       = $Memory.Capacity
            Location       = $Memory.Locator
        }
    }

    ForEach ($Disk in @($Inventory.Storage.Disks)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'Disk'
            Name           = $Disk.Model
            Manufacturer   = $Disk.Manufacturer
            Model          = $Disk.Model
            SerialNumber   = $Disk.SerialNumber
            Status         = $Disk.HealthStatus
            Detail1        = $Disk.MediaType
            Detail2        = $Disk.BusType
            Detail3        = $Disk.FirmwareRevision
            IPAddress      = $null
            MACAddress     = $null
            InterfaceIndex = $Disk.Index
            Capacity       = $Disk.Size
            Location       = $Disk.DeviceID
        }
    }

    ForEach ($Volume in @($Inventory.Storage.Volumes)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'Volume'
            Name           = $Volume.Drive
            Manufacturer   = $null
            Model          = $Volume.FileSystem
            SerialNumber   = $Volume.VolumeSerialNumber
            Status         = ('{0}% Free' -f $Volume.FreePercent)
            Detail1        = $Volume.Label
            Detail2        = ('Free {0}' -f $Volume.Free)
            Detail3        = $null
            IPAddress      = $null
            MACAddress     = $null
            InterfaceIndex = $null
            Capacity       = $Volume.Size
            Location       = $Volume.Drive
        }
    }

    ForEach ($Adapter in @($Inventory.NetworkAdapters)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'NetworkAdapter'
            Name           = $Adapter.Name
            Manufacturer   = $Adapter.Manufacturer
            Model          = $Adapter.Type
            SerialNumber   = $null
            Status         = $Adapter.ConnectionStatus
            Detail1        = $Adapter.DefaultGateway
            Detail2        = $Adapter.DNSServers
            Detail3        = $(If ($null -ne $Adapter.DHCPEnabled) { 'DHCP={0}' -f $Adapter.DHCPEnabled })
            IPAddress      = $Adapter.IPv4Address
            MACAddress     = $Adapter.MACAddress
            InterfaceIndex = $Adapter.InterfaceIndex
            Capacity       = $(If ($Adapter.LinkGbps) { '{0} Gbps' -f $Adapter.LinkGbps })
            Location       = $Adapter.Connection
        }
    }

    ForEach ($Display in @($Inventory.DisplayAdapters)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'DisplayAdapter'
            Name           = $Display.Name
            Manufacturer   = $null
            Model          = $Display.Name
            SerialNumber   = $null
            Status         = $Display.Status
            Detail1        = $Display.DriverVersion
            Detail2        = $Display.VideoMode
            Detail3        = $null
            IPAddress      = $null
            MACAddress     = $null
            InterfaceIndex = $null
            Capacity       = $Display.AdapterMemory
            Location       = $null
        }
    }

    ForEach ($Monitor in @($Inventory.Monitors)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'Monitor'
            Name           = $Monitor.Model
            Manufacturer   = $Monitor.Manufacturer
            Model          = $Monitor.Model
            SerialNumber   = $Monitor.SerialNumber
            Status         = If ($Monitor.Active) {'Active'} Else {'Inactive'}
            Detail1        = $Monitor.CurrentResolution
            Detail2        = $Monitor.NativeResolution
            Detail3        = $Monitor.Connection
            IPAddress      = $null
            MACAddress     = $null
            InterfaceIndex = $null
            Capacity       = $null
            Location       = $null
        }
    }

    ForEach ($Printer in @($Inventory.Printers)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'Printer'
            Name           = $Printer.Name
            Manufacturer   = $Printer.Manufacturer
            Model          = $Printer.DriverName
            SerialNumber   = $null
            Status         = $Printer.Status
            Detail1        = $Printer.PortName
            Detail2        = $Printer.DriverName
            Detail3        = $null
            IPAddress      = $Printer.IPAddress
            MACAddress     = $null
            InterfaceIndex = $null
            Capacity       = $null
            Location       = $Printer.Location
        }
    }

    ForEach ($Dock in @($Inventory.DellDocks)) {
        $Rows += [PSCustomObject][ordered]@{
            ComputerName   = $Common.ComputerName
            RecordType     = 'Dock'
            Name           = $Dock.Model
            Manufacturer   = 'Dell'
            Model          = $Dock.Model
            SerialNumber   = $Dock.SerialNumber
            Status         = $Dock.Status
            Detail1        = $Dock.Source
            Detail2        = $null
            Detail3        = $null
            IPAddress      = $null
            MACAddress     = $null
            InterfaceIndex = $null
            Capacity       = $null
            Location       = $null
        }
    }

    Return $Rows
}

Function Export-HyperVNetworkInventoryCsv {
    <#
        .SYNOPSIS
        Exports Hyper-V host and guest network records while retaining useful populated columns.

        .DESCRIPTION
        Writes the Hyper-V host and VM network records (adapters, vSwitches, current and replacement
        IP addresses, LLDP switch ports and storage paths) to a CSV file.

        .PARAMETER HyperVNetwork
        Object returned by Get-HyperVNetworkInventory.

        .PARAMETER Path
        Full path of the CSV file to write.

        .EXAMPLE
        Export-HyperVNetworkInventoryCsv -HyperVNetwork $Inventory.HyperVNetwork -Path .\HyperVNetwork.csv
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the object returned by Get-HyperVNetworkInventory.')]
        [object]$HyperVNetwork,

        [Parameter(Mandatory, HelpMessage = 'Specify the full path of the Hyper-V network CSV file to write.')]
        [string]$Path
    )

    $Records = @($HyperVNetwork.Records)
    If ($Records.Count -eq 0) {
        'HostName,AdapterType,AdapterName,MACAddress,Status' | Set-Content -LiteralPath $Path -Encoding UTF8
        Return
    }

    $Required = @('HostName','AdapterType','AdapterName','MACAddress','Status')

    $AllPropertyNames = @($Records | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique)

    $Properties = @(
        $AllPropertyNames | Where-Object {
            $PropertyName = $_

            If ($Required -contains $PropertyName) {
                Return $true
            }

            @(
                $Records | Where-Object {
                    $P = $_.PSObject.Properties[$PropertyName]
                    If ($P) {
                        $Value = [string]$P.Value
                        $Value.Trim() -and $Value.Trim() -ne $script:NA
                    }
                }
            ).Count -gt 0
        }
    )

    $Records | Select-Object -Property $Properties | Export-Csv -LiteralPath $Path @script:eCSV2
}
#endregion Dell/Hyper-V Network Inventory

#region Presentation Functions
Function Format-HardwareInventoryTableHeader {
    <#
        .SYNOPSIS
        Splits run-together property names in HTML table headers into readable words.

        .DESCRIPTION
        ConvertTo-Html uses property names such as ManagementNeighborState as column headers.
        A header cannot wrap inside a single word, so a table with many such headers forces the
        whole report wider than its 1040 px layout. This function inserts spaces at word and
        acronym boundaries inside <th> elements only, so headers wrap and read naturally:
        CurrentIPAddress becomes "Current IP Address" and MaxClockMHz becomes "Max Clock MHz".
        A single leading lowercase letter stays attached, so vSwitch and iSCSI are unchanged.

        The HTML tables show the columns that matter for review; the CSV and JSON reports keep
        every column.

        .PARAMETER Fragment
        HTML fragment produced by ConvertTo-Html -Fragment.

        .EXAMPLE
        Format-HardwareInventoryTableHeader -Fragment '<table><tr><th>MACAddress</th></tr></table>'

        Returns <table><tr><th>MAC Address</th></tr></table>.

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    <#
        LESSON 1: [OutputType()] documents, it does not enforce
        [OutputType([string])] tells Get-Help, tab completion and readers what the function
        returns. PowerShell does not check it: a function declaring [string] could still output
        a number. Keep it accurate by hand.
    #>
    [OutputType([string])]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the HTML fragment whose table headers should be made readable.')]
        <#
            LESSON 2: Mandatory parameters reject empty values unless you allow them
            A Mandatory [string] parameter refuses an empty string '' and fails the call. A table
            with no visible columns produces an empty fragment, which is still valid input here.
            [AllowEmptyString()] permits '' while still requiring the parameter. [AllowNull()] and
            [AllowEmptyCollection()] work the same way for $null and empty arrays.
        #>
        [AllowEmptyString()]
        [string]$Fragment
    )

    <#
        LESSON 3: Letting a scriptblock decide each replacement
        -replace substitutes the same text for every match. [regex]::Replace can instead call a
        scriptblock once per match, a "match evaluator", and use whatever it returns. $Match is
        the current match; $Match.Groups[1] is the text captured by the first ( ) in the pattern,
        which is the header text between <th> and </th>. Only that text is changed; the rest of
        the HTML passes through untouched.
    #>
    $Evaluator = {
        Param ($Match)

        <#
            LESSON 4: Matching a POSITION instead of characters
            Lookarounds check the text around a position without consuming it. (?<=x) means "x
            comes just before here" and (?=y) means "y comes just after here". This pattern
            matches no characters at all, only positions between characters, so replacing the
            match with ' ' INSERTS a space and removes nothing.
            Rule 1: (?<=[a-z]{2}|[0-9])(?=[A-Z]) means two lowercase letters or a digit, then an
                    uppercase letter. 'CurrentIPAddress' becomes 'Current IPAddress', and
                    'IPv4Address' becomes 'IPv4 Address'.
            Rule 2: (?<=[A-Z]{2})(?=[A-Z][a-z]) means two capitals, then a capital followed by a
                    lowercase letter. This is where an acronym ends and a word begins:
                    'IPAddress' becomes 'IP Address', and 'MACAddress' becomes 'MAC Address'.
            Requiring TWO lowercase letters in Rule 1 keeps 'vSwitch' and 'iSCSI' intact. A
            simpler pattern, (?=[A-Z]) alone, turns 'MACAddress' into 'M A C Address'.
        #>
        <#
            LESSON 5: Why -creplace and not -replace
            PowerShell operators ignore case by default, so with -replace, [a-z] and [A-Z] BOTH
            match every letter. With -replace this exact pattern turns 'CurrentIPAddress' into
            'Cu r r e n t I P A d d r e s s'. The c in -creplace, like -cmatch and -ceq, makes the
            comparison case-sensitive, which this pattern depends on.
        #>
        $Text = $Match.Groups[1].Value -creplace '(?<=[a-z]{2}|[0-9])(?=[A-Z])|(?<=[A-Z]{2})(?=[A-Z][a-z])',' '

        <#
            LESSON 6: Stop at the right place: [^<]* rather than .*
            .* is greedy: it matches as much as it can. On '<th>A</th><th>B</th>', the pattern
            '<th>(.*)</th>' captures 'A</th><th>B', spanning both headers. [^<]* means "any
            characters except <", so each match stops at its own closing tag and every header is
            handled separately. A lazy .*? would also work. And because the pattern starts with
            <th>, data cells (<td>) are never changed.
        #>
        <#
            EXERCISE: Predict the output, then check it in the console
            Run each line and compare the result with your prediction:
              'LLDPCaptureStatus' -creplace '(?<=[a-z]{2}|[0-9])(?=[A-Z])|(?<=[A-Z]{2})(?=[A-Z][a-z])',' '
              'VMGuestAdapters'   -creplace '(?<=[a-z]{2}|[0-9])(?=[A-Z])|(?<=[A-Z]{2})(?=[A-Z][a-z])',' '
              'iSCSIPaths'        -creplace '(?<=[a-z]{2}|[0-9])(?=[A-Z])|(?<=[A-Z]{2})(?=[A-Z][a-z])',' '
            Then try the same three with -replace and explain the difference using Lesson 5.
            Challenge: which header could these rules still split badly? (Hint: 'eTag' or 'iPhone'.)
        #>
        Return ('<th>{0}</th>' -f $Text)
    }

    Return [regex]::Replace($Fragment,'<th>([^<]*)</th>',$Evaluator)
} ### Lessons

Function Convert-ObjectToHtmlTable {
    <#
        .SYNOPSIS
        Converts objects to a full-width HTML inventory table and removes empty columns.

        .DESCRIPTION
        Converts objects into the standard hardware inventory table. Requested properties are
        evaluated across the complete input collection and any property that is blank for every
        row is omitted. False and numeric zero are retained as meaningful values.

        .PARAMETER Title
        Section heading displayed above the table.

        .PARAMETER InputObject
        Objects to render.

        .PARAMETER Property
        Ordered properties to evaluate and display.

        .PARAMETER IconKey
        Embedded section icon asset key.

        .EXAMPLE
        Convert-ObjectToHtmlTable -Title 'Battery' -IconKey 'Battery' -InputObject $Inventory.Battery -Property Name, Status

        Returns a report section with a heading and a table containing only non-empty columns.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the title to display above the HTML table.')]
        [string]$Title,

        [Parameter()]
        [object[]]$InputObject,

        [Parameter()]
        [string[]]$Property,

        [Parameter(Mandatory, HelpMessage = 'Specify the embedded section icon asset key.')]
        [string]$IconKey
    )

    $Rows = @($InputObject | Where-Object {$null -ne $_})
    If ($Rows.Count -eq 0) {
        Return ''
    }

    If (-not $Property -or $Property.Count -eq 0) {
        $Property = @(
            $Rows[0].PSObject.Properties | Where-Object {
                $_.MemberType -in 'NoteProperty','Property','AliasProperty','ScriptProperty'
            } | Select-Object -ExpandProperty Name
        )
    }

    $VisibleProperties = @(
        ForEach ($PropertyName in $Property) {
            $HasValue = $false
            ForEach ($Row in $Rows) {
                $Value = $null
                If ($Row.PSObject.Properties.Name -contains $PropertyName) {
                    $Value = $Row.$PropertyName
                }

                If ($null -eq $Value) {
                    Continue
                }

                If ($Value -is [string]) {
                    If (-not [string]::IsNullOrWhiteSpace($Value)) {
                        $HasValue = $true
                        Break
                    }
                    Continue
                }

                If ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
                    If (@($Value).Count -gt 0) {
                        $HasValue = $true
                        Break
                    }
                    Continue
                }

                $HasValue = $true
                Break
            }

            If ($HasValue) {
                $PropertyName
            }
        }
    )

    If ($VisibleProperties.Count -eq 0) {
        Return ''
    }

    $Fragment = @($Rows | Select-Object -Property $VisibleProperties | ConvertTo-Html -Fragment) -join [Environment]::NewLine
    $Fragment = Format-HardwareInventoryTableHeader -Fragment $Fragment
    $Fragment = $Fragment -replace '<table>', '<table class="data-table" width="100%" cellpadding="0" cellspacing="0" border="0">'
    $Heading  = New-HardwareInventorySectionTitle -Title $Title -IconKey $IconKey

    Return @"
<div class="section">
$Heading
$Fragment
</div>
"@
}

Function Convert-ObjectToHtmlTableFragment {
    <#
        .SYNOPSIS
        Converts objects to an HTML table fragment while removing empty columns.

        .DESCRIPTION
        Evaluates requested properties across the complete input collection and removes
        any property that is null or blank for every row. False and numeric zero are
        retained as meaningful values.

        Returns only the HTML table fragment without a report section heading or wrapper.

        .PARAMETER InputObject
        Objects to render.

        .PARAMETER Property
        Ordered properties to evaluate and display.

        .EXAMPLE
        Convert-ObjectToHtmlTableFragment -InputObject $PowerSupplies -Property Name,Status,Presence

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,HelpMessage='Provide the objects to render as an HTML table fragment.')]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter()]
        [string[]]$Property
    )

    $Rows = @($InputObject | Where-Object {$null -ne $_})

    If ($Rows.Count -eq 0) {
        Return ''
    }

    If (-not $Property -or $Property.Count -eq 0) {
        $Property = @(
            $Rows[0].PSObject.Properties | Where-Object {
                $_.MemberType -in 'NoteProperty','Property','AliasProperty','ScriptProperty'
            } | Select-Object -ExpandProperty Name
        )
    }

    $VisibleProperties = @(
        ForEach ($PropertyName in $Property) {
            $HasValue = $false
            ForEach ($Row in $Rows) {
                $Value = $null
                If ($Row.PSObject.Properties.Name -contains $PropertyName) {
                    $Value = $Row.$PropertyName
                }

                If ($null -eq $Value) {
                    Continue
                }

                If ($Value -is [string]) {
                    If (-not [string]::IsNullOrWhiteSpace($Value)) {
                        $HasValue = $true

                        Break
                    }

                    Continue
                }

                If ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
                    If (@($Value).Count -gt 0) {
                        $HasValue = $true

                        Break
                    }

                    Continue
                }

                $HasValue = $true

                Break
            }

            If ($HasValue) {
                $PropertyName
            }
        }
    )

    If ($VisibleProperties.Count -eq 0) {
        Return ''
    }

    $Fragment = @($Rows | Select-Object -Property $VisibleProperties | ConvertTo-Html -Fragment) -join [Environment]::NewLine
    $Fragment = Format-HardwareInventoryTableHeader -Fragment $Fragment

    Return ($Fragment -replace '<table>', '<table class="data-table" width="100%" cellpadding="0" cellspacing="0" border="0">')
}

Function Convert-VolumesToHtmlTable {
    <#
        .SYNOPSIS
        Converts volume inventory into an HTML table with free-space charts.

        .DESCRIPTION
        Renders fixed-volume information using the standard hardware inventory table
        format and adds a small color-coded free-space donut chart to each volume.

        Columns that contain no values across the complete volume collection are omitted.

        Free-space chart thresholds are:
        - 20 percent or greater: green
        - 10 through less than 20 percent: yellow
        - Less than 10 percent: red

        .PARAMETER InputObject
        Volume inventory objects returned by Get-DiskInventory.

        .EXAMPLE
        Convert-VolumesToHtmlTable -InputObject $Inventory.Storage.Volumes

        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the volume inventory objects to render.')]
        [AllowEmptyCollection()]
        [object[]]$InputObject
    )

    $Rows = @($InputObject | Where-Object { $null -ne $_ })

    If ($Rows.Count -eq 0) {
        Return ''
    }

    $Columns = @(
        [PSCustomObject]@{
            Name  = 'Drive'
            Label = 'Drive'
        }
        [PSCustomObject]@{
            Name  = 'Label'
            Label = 'Label'
        }
        [PSCustomObject]@{
            Name  = 'FileSystem'
            Label = 'File System'
        }
        [PSCustomObject]@{
            Name  = 'Size'
            Label = 'Size'
        }
        [PSCustomObject]@{
            Name  = 'Free'
            Label = 'Free'
        }
        [PSCustomObject]@{
            Name  = 'FreePercent'
            Label = 'Free %'
        }
        [PSCustomObject]@{
            Name  = 'Usage'
            Label = 'Free Space'
        }
    )

    $VisibleColumns = @(
        ForEach ($Column in $Columns) {
            If ($Column.Name -eq 'Usage') {
                If (@($Rows | Where-Object {$null -ne $_.FreePercent}).Count -gt 0) {
                    $Column
                }

                Continue
            }

            $HasValue = $false
            ForEach ($Row in $Rows) {
                $Value = $null
                If ($Row.PSObject.Properties.Name -contains $Column.Name) {
                    $Value = $Row.($Column.Name)
                }

                If ($null -eq $Value) {
                    Continue
                }

                If ($Value -is [string]) {
                    If (-not [string]::IsNullOrWhiteSpace($Value)) {
                        $HasValue = $true

                        Break
                    }

                    Continue
                }
                $HasValue = $true

                Break
            }

            If ($HasValue) {
                $Column
            }
        }
    )

    If ($VisibleColumns.Count -eq 0) {
        Return ''
    }

    $HeaderCells = @(
        ForEach ($Column in $VisibleColumns) {
            '<th>{0}</th>' -f [Net.WebUtility]::HtmlEncode([string]$Column.Label)
        }
    )

    $HtmlRows    = @()
    ForEach ($Row in $Rows) {
        $Cells = @()
        ForEach ($Column in $VisibleColumns) {
            If ($Column.Name -eq 'Usage') {
                $Chart = ''
                If ($null -ne $Row.FreePercent) {
                    $Chart = Get-VolumeFreeSpaceChartHtml -FreePercent ([double]$Row.FreePercent)
                }
                $Cells += '<td class="volume-chart-cell">{0}</td>' -f $Chart

                Continue
            }

            $Value = $null
            If ($Row.PSObject.Properties.Name -contains $Column.Name) {
                $Value = $Row.($Column.Name)
            }

            If ($Column.Name -eq 'FreePercent' -and $null -ne $Value) {
                $Value = '{0:0.0}%' -f [double]$Value
            }

            $Cells += '<td>{0}</td>' -f [Net.WebUtility]::HtmlEncode([string]$Value)
        }
        $HtmlRows += '<tr>{0}</tr>' -f ($Cells -join '')
    }
    $Heading = New-HardwareInventorySectionTitle -Title 'Volumes' -IconKey 'Volume'

    Return @"
<div class="section">
$Heading
<table class="data-table" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr>$($HeaderCells -join '')</tr>
$($HtmlRows -join [Environment]::NewLine)
</table>
</div>
"@
}

Function New-HardwareInventoryHtml {
    <#
        .SYNOPSIS
        Builds the modern self-contained hardware inventory HTML report.

        .DESCRIPTION
        Creates a bounded-width, Outlook-friendly report using table-based layout and fixed-size
        embedded PNG assets. The report contains no JavaScript, remote images, web fonts, forms,
        iframes, or external style resources.

        Section icons are 20x20 PNGs. Summary icons are 28x28 PNGs. The header logo is a
        pre-sized 104x91 PNG. The platform icon automatically selects Laptop, Workstation, or
        Server from the collected operating system and chassis information.

        .PARAMETER Inventory
        Complete hardware inventory object produced by the inventory script.

        .EXAMPLE
        $Html = New-HardwareInventoryHtml -Inventory $Inventory
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the complete hardware inventory object to render as HTML.')]
        [object]$Inventory
    )

    #region Helper Functions
    Function ConvertTo-HtmlValue {
        <#
            .SYNOPSIS
            HTML-encodes a report value.

            .DESCRIPTION
            Returns an empty string for $null; otherwise converts the value to a string and HTML-encodes
            it so collected text can never inject markup into the report.

            .PARAMETER Value
            Value to encode.

            .EXAMPLE
            ConvertTo-HtmlValue -Value 'R&D <Lab>'

            Returns R&amp;D &lt;Lab&gt;.
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Specify the value to HTML-encode.')]
            [AllowNull()]
            [object]$Value
        )

        If ($null -eq $Value) {
            Return ''
        }

        Return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }

    Function New-HtmlPropertyRows {
        <#
            .SYNOPSIS
            Creates two-pair property rows for the computer detail table.

            .DESCRIPTION
            Renders label/value pairs as rows of the key/value table, two pairs per row. A pair with no
            value is dropped; when only one pair in a row has a value it spans the full row. When the
            second label is Service Tag, the Dell Support link is appended to its value.

            .PARAMETER Rows
            Property-pair objects containing Label1, Value1, Label2, and Value2.

            .PARAMETER DellSupportHtml
            Pre-built Dell Support hyperlink HTML.

            .EXAMPLE
            New-HtmlPropertyRows -Rows @([PSCustomObject]@{ Label1 = 'Model'; Value1 = 'R430'; Label2 = 'Service Tag'; Value2 = 'ABC1234' })
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Provide property-pair objects to render.')]
            [object[]]$Rows,

            [Parameter()]
            [string]$DellSupportHtml
        )

        $HtmlRows = @()

        ForEach ($Row in $Rows) {
            $HasValue1 = -not [string]::IsNullOrWhiteSpace([string]$Row.Value1)
            $HasValue2 = -not [string]::IsNullOrWhiteSpace([string]$Row.Value2)

            If (-not $HasValue1 -and -not $HasValue2) {
                Continue
            }

            $Label1 = ConvertTo-HtmlValue -Value $Row.Label1
            $Value1 = ConvertTo-HtmlValue -Value $Row.Value1
            $Label2 = ConvertTo-HtmlValue -Value $Row.Label2
            $Value2 = ConvertTo-HtmlValue -Value $Row.Value2

            If ($Row.Label2 -eq 'Service Tag' -and $HasValue2 -and $DellSupportHtml) {
                $Value2 = '{0}&nbsp;&nbsp;{1}' -f $Value2,$DellSupportHtml
            }

            If ($HasValue1 -and $HasValue2) {
                $HtmlRows += '<tr><td class="kv-label" width="18%">{0}</td><td class="kv-value" width="32%">{1}</td><td class="kv-label" width="18%">{2}</td><td class="kv-value" width="32%">{3}</td></tr>' -f $Label1,$Value1,$Label2,$Value2
            } ElseIf ($HasValue1) {
                $HtmlRows += '<tr><td class="kv-label" width="18%">{0}</td><td class="kv-value" colspan="3">{1}</td></tr>' -f $Label1,$Value1
            } Else {
                $HtmlRows += '<tr><td class="kv-label" width="18%">{0}</td><td class="kv-value" colspan="3">{1}</td></tr>' -f $Label2,$Value2
            }
        }

        Return ($HtmlRows -join [Environment]::NewLine)
    }

    Function New-RecordSection {
        <#
            .SYNOPSIS
            Wraps one or more record cards in an icon section.

            .DESCRIPTION
            Combines pre-built record cards (one per adapter, printer or dock) under a single section
            heading. Returns an empty string when there are no cards.

            .PARAMETER Title
            Section title.

            .PARAMETER IconKey
            Embedded section icon key.

            .PARAMETER Cards
            HTML record cards.

            .EXAMPLE
            New-RecordSection -Title 'Printers' -IconKey 'Printer' -Cards $Cards
        #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory, HelpMessage = 'Specify the section title.')]
            [string]$Title,

            [Parameter(Mandatory, HelpMessage = 'Specify the embedded section icon key.')]
            [string]$IconKey,

            [Parameter(Mandatory, HelpMessage = 'Provide the HTML record cards.')]
            [string[]]$Cards
        )

        If (@($Cards).Count -eq 0) {
            Return ''
        }

        $Heading = New-HardwareInventorySectionTitle -Title $Title -IconKey $IconKey

        Return '<div class="section">{0}{1}</div>' -f $Heading,($Cards -join [Environment]::NewLine)
    }

    #endregion Helper Functions

    $PlatformIconKey        = Get-HardwareInventoryPlatformIconKey -Computer $Inventory.Computer
    $PlatformSummaryIconKey = '{0}Summary' -f $PlatformIconKey
    $LogoHtml               = Get-HardwareInventoryImageHtml -Key 'Logo' -Alt 'MyCompany' -CssClass 'header-logo'

    $DellSupportHtml = $null
    If ($Inventory.Computer.DellSupportUrl) {
        $DellUrl         = [System.Net.WebUtility]::HtmlEncode([string]$Inventory.Computer.DellSupportUrl)
        $DellSupportHtml = '<a class="support-link" href="{0}" target="_blank" rel="noopener noreferrer">Dell Support</a>' -f $DellUrl
    }

    $PlatformText = [string]$Inventory.Computer.ComputerType
    If (-not [string]::IsNullOrWhiteSpace([string]$Inventory.Computer.VirtualType)) {
        $PlatformText = '{0} - {1}' -f $PlatformText,$Inventory.Computer.VirtualType
    }

    $PropertyRows     = @(
        [PSCustomObject]@{
            Label1 = 'Computer Name'
            Value1 = $Inventory.Computer.ComputerName
            Label2 = 'Current User'
            Value2 = $Inventory.Computer.CurrentUser
        }
        [PSCustomObject]@{
            Label1 = 'Manufacturer'
            Value1 = $Inventory.Computer.Manufacturer
            Label2 = 'Model'
            Value2 = $Inventory.Computer.Model
        }
        [PSCustomObject]@{
            Label1 = 'System Family'
            Value1 = $Inventory.Computer.SystemFamily
            Label2 = 'Chassis'
            Value2 = $Inventory.Computer.Chassis
        }
        [PSCustomObject]@{
            Label1 = 'Platform'
            Value1 = $PlatformText
            Label2 = 'Service Tag'
            Value2 = $Inventory.Computer.ServiceTag
        }
        [PSCustomObject]@{
            Label1 = 'Operating System'
            Value1 = $Inventory.Computer.OS
            Label2 = 'Version / Build'
            Value2 = ('{0} / {1}' -f $Inventory.Computer.Version,$Inventory.Computer.OSBuild)
        }
        [PSCustomObject]@{
            Label1 = 'Architecture'
            Value1 = $Inventory.Computer.Architecture
            Label2 = 'BIOS Version'
            Value2 = $Inventory.Computer.BIOSVersion
        }
        [PSCustomObject]@{
            Label1 = 'Installed On'
            Value1 = $Inventory.Computer.InstalledOn
            Label2 = 'BIOS Release'
            Value2 = $Inventory.Computer.BIOSReleaseDate
        }
        [PSCustomObject]@{
            Label1 = 'Last Boot'
            Value1 = $Inventory.Computer.LastBootTime
            Label2 = 'Uptime'
            Value2 = $Inventory.Computer.Uptime
        }
        [PSCustomObject]@{
            Label1 = 'Last Update'
            Value1 = $Inventory.Computer.LastUpdateDateTime
            Label2 = 'Collected'
            Value2 = $Inventory.Computer.CollectedAt
        }
    )

    $PropertyRowsHtml = New-HtmlPropertyRows -Rows $PropertyRows -DellSupportHtml $DellSupportHtml

    $LastUpdateHtml = ''
    If (-not [string]::IsNullOrWhiteSpace([string]$Inventory.Computer.LastUpdateTitle)) {
        $LastUpdateTitle = ConvertTo-HtmlValue -Value $Inventory.Computer.LastUpdateTitle
        $LastUpdateHtml  = '<tr><td class="kv-label">Last Update Title</td><td class="kv-value" colspan="3">{0}</td></tr>' -f $LastUpdateTitle
    }

    $MemoryTitle = 'Memory - {0} Total | {1} populated' -f $Inventory.Memory.Total,$Inventory.Memory.InstalledModuleCount
    If ($Inventory.Memory.ReportedLocationCount -gt 0) {
        $MemoryTitle += ' / {0} reported' -f $Inventory.Memory.ReportedLocationCount
    }

    If ($Inventory.Memory.EmptyLocationCount -gt 0)    {
        $MemoryTitle += ' | {0} empty' -f $Inventory.Memory.EmptyLocationCount
    }

    If ($Inventory.Memory.MaxCapacity) {
        $MemoryTitle += ' | Max {0}' -f $Inventory.Memory.MaxCapacity
    }

    $CpuTitle = 'Processor'
    If ($Inventory.CPUTopology) {
        $CpuTitle += ' - {0} populated' -f $Inventory.CPUTopology.InstalledSocketCount
        If ($null -ne $Inventory.CPUTopology.ReportedSocketCount) {
            $CpuTitle += ' / {0} reported sockets' -f $Inventory.CPUTopology.ReportedSocketCount
        }

        If ($null -ne $Inventory.CPUTopology.EmptySocketCount -and $Inventory.CPUTopology.EmptySocketCount -gt 0) {
            $CpuTitle += ' | {0} empty' -f $Inventory.CPUTopology.EmptySocketCount
        }

        $CpuTitle += ' | {0} cores / {1} logical' -f $Inventory.CPUTopology.TotalCores,$Inventory.CPUTopology.TotalLogicalProcessors
    }

    $Sections  = @()
    $Sections += Convert-ObjectToHtmlTable -Title $CpuTitle -IconKey 'CPU' -InputObject $Inventory.CPU -Property Socket, Name, Manufacturer, Cores, LogicalProcessors, MaxClockMHz, CurrentClockMHz, Virtualization
    $Sections += Convert-ObjectToHtmlTable -Title $MemoryTitle -IconKey 'Memory' -InputObject $Inventory.Memory.Slots -Property Slot, Status, Bank, Locator, Capacity, Type, FormFactor, TypeDetail, SpeedMHz, ConfiguredMHz, Manufacturer, PartNumber, SerialNumber
    $Sections += Convert-ObjectToHtmlTable -Title 'OS-Visible Disks' -IconKey 'Disk' -InputObject @($Inventory.Storage.Disks | Sort-Object -Property Index) -Property Index, Model, SerialNumber, Size, Interface, MediaType, BusType, HealthStatus, OperationalStatus, FirmwareRevision
    $Sections += Convert-VolumesToHtmlTable -InputObject $Inventory.Storage.Volumes

    #region Servers
    If ($Inventory.ServerHardware -and $Inventory.ServerHardware.Available) {
        $ServerHardware = $Inventory.ServerHardware
        If ($ServerHardware.Health) {
            $HealthRows  = @()
            $HealthRows += [PSCustomObject]@{
                Component = 'Overall'
                Status    = $ServerHardware.Health.Status
            }

            ForEach ($Component in @($ServerHardware.Health.Components)) {
                If ($Component -and -not [string]::IsNullOrWhiteSpace([string]$Component.Component)) {
                    $HealthRows += [PSCustomObject]@{
                        Component = $Component.Component
                        Status    = $Component.Status
                    }
                }
            }

            If ($ServerHardware.Power -and -not ($HealthRows.Component -contains 'Power')) {
                $HealthRows += [PSCustomObject]@{
                    Component = 'Power'
                    Status    = $ServerHardware.Power.Status
                }
            }

            If ($ServerHardware.Cooling -and -not ($HealthRows.Component -contains 'Cooling')) {
                $HealthRows += [PSCustomObject]@{
                    Component = 'Cooling'
                    Status    = $ServerHardware.Cooling.Status
                }
            }

            If ($ServerHardware.Temperatures -and -not ($HealthRows.Component -contains 'Temperatures')) {
                $HealthRows += [PSCustomObject]@{
                    Component = 'Temperatures'
                    Status    = $ServerHardware.Temperatures.Status
                }
            }

            ### Rendered as status tiles rather than a <ul>: Outlook rewrites list bullets as literal
            ### "*" characters, and tiles match the Readiness and Security panel.
            $HealthTiles = @(
                ForEach ($HealthRow in $HealthRows) {
                    $StatusText = ([string]$HealthRow.Status).Trim()
                    If ([string]::IsNullOrWhiteSpace($StatusText)) {
                        Continue
                    }

                    If ($StatusText -match '^(?i)ok$') {
                        $StatusText = 'OK'
                    }

                    $TileStatus = Switch -Regex ($StatusText) {
                        '^(?i)(OK|Healthy|Ready|Online|Full)$'                  { 'OK' }
                        '^(?i)(Warning|Degraded|Non-Critical|Partial)$'        { 'Warning' }
                        '^(?i)(Critical|Failed|Failure|Offline|Lost|Non-Recoverable)$' { 'Critical' }
                        Default                                                 { 'Neutral' }
                    }

                    [PSCustomObject]@{
                        Check  = ([string]$HealthRow.Component).Trim()
                        Value  = $StatusText
                        Status = $TileStatus
                    }
                }
            )

            If ($HealthTiles.Count -gt 0) {
                $Sections += New-ResponsibilityTileGridHtml -Title 'Server Hardware Health' -IconKey 'Server' -Items $HealthTiles -Mode Posture -PerRow 4
            }
        }

        If ($ServerHardware.Management) {
            $Management    = $ServerHardware.Management
            $ManagementUrl = $null
            If (-not [string]::IsNullOrWhiteSpace([string]$Management.HttpsUrl)) {
                $EncodedManagementUrl = ConvertTo-HtmlValue -Value $Management.HttpsUrl
                $ManagementUrl        = '<a class="support-link" href="{0}" target="_blank" rel="noopener noreferrer">{0}</a>' -f $EncodedManagementUrl
            }

            $ManagementRows = @(
                [PSCustomObject]@{
                    Label1 = 'Controller'
                    Value1 = $Management.Product
                    Label2 = 'IPv4 Address'
                    Value2 = $Management.IPv4Address
                }
                [PSCustomObject]@{
                    Label1 = 'Firmware'
                    Value1 = $Management.Firmware
                    Label2 = 'Lifecycle Controller'
                    Value2 = $Management.LifecycleController
                }
                [PSCustomObject]@{
                    Label1 = 'Source'
                    Value1 = $Management.Source
                    Label2 = $null
                    Value2 = $null
                }
            )
            $ManagementRowsHtml = New-HtmlPropertyRows -Rows $ManagementRows
            If ($ManagementUrl) {
                $ManagementRowsHtml += '<tr><td class="kv-label" width="18%">Management URL</td><td class="kv-value" colspan="3">{0}</td></tr>' -f $ManagementUrl
            }
            $ManagementHeading = New-HardwareInventorySectionTitle -Title 'Out-of-Band Management' -IconKey 'Network'
            $Sections += '<div class="section">{0}<table class="kv-table" width="100%" cellpadding="0" cellspacing="0" border="0">{1}</table></div>' -f $ManagementHeading,$ManagementRowsHtml
        }

        If ($ServerHardware.Power) {
            $Power = $ServerHardware.Power

            $CurrentWatts = $null
            $PeakWatts    = $null
            $Headroom     = $null
            $Cumulative   = $null

            If ($Power.Consumption) {
                If ($null -ne $Power.Consumption.CurrentWatts)           {
                    $CurrentWatts = '{0:N0} W' -f [double]$Power.Consumption.CurrentWatts
                }

                If ($null -ne $Power.Consumption.PeakWatts)              {
                    $PeakWatts    = '{0:N0} W' -f [double]$Power.Consumption.PeakWatts
                }

                If ($null -ne $Power.Consumption.InstantaneousHeadroomW) {
                    $Headroom     = '{0:N0} W' -f [double]$Power.Consumption.InstantaneousHeadroomW
                }

                If ($null -ne $Power.Consumption.CumulativeKWh)          {
                    $Cumulative   = '{0:N3} kWh' -f [double]$Power.Consumption.CumulativeKWh
                }
            }

            $PowerRows = @(
                [PSCustomObject]@{
                    Label1 = 'Status'
                    Value1 = $Power.Status
                    Label2 = 'Redundancy'
                    Value2 = $Power.Redundancy
                }
                [PSCustomObject]@{
                    Label1 = 'Power Supplies'
                    Value1 = If ($Power.SupplyCount -gt 0) { '{0} ({1} healthy)' -f $Power.SupplyCount,$Power.HealthyCount } Else { $null }
                    Label2 = 'Current Draw'
                    Value2 = $CurrentWatts
                }
                [PSCustomObject]@{
                    Label1 = 'Headroom'
                    Value1 = $Headroom
                    Label2 = 'Peak Draw'
                    Value2 = $PeakWatts
                }
                [PSCustomObject]@{
                    Label1 = 'Energy Recorded'
                    Value1 = $Cumulative
                    Label2 = 'Source'
                    Value2 = $Power.Source
                }
            )

            $PowerRowsHtml = New-HtmlPropertyRows -Rows $PowerRows
            $PowerHeading  = New-HardwareInventorySectionTitle -Title 'Power' -IconKey 'Battery'
            $PowerHtml     = '<div class="section">{0}<table class="kv-table" width="100%" cellpadding="0" cellspacing="0" border="0">{1}</table>' -f $PowerHeading,$PowerRowsHtml
            If (@($Power.Supplies).Count -gt 0) {
                $PowerSupplyTable = @(
                    $Power.Supplies | Select-Object -Property Name, Status, Presence, @{
                        Name       = 'Rated Input'
                        Expression = {
                            If ($null -ne $_.InputRatedWatts) {
                                '{0:N0} W' -f [double]$_.InputRatedWatts
                            }
                        }
                    }, @{
                        Name       = 'Max Output'
                        Expression = {
                            If ($null -ne $_.MaximumOutputWatts) {
                                '{0:N0} W' -f [double]$_.MaximumOutputWatts
                            }
                        }
                    }
                )

                $PowerSupplyFragment = Convert-ObjectToHtmlTableFragment -InputObject $PowerSupplyTable
                $PowerSupplyFragment = $PowerSupplyFragment -replace '<table>', '<table class="data-table" width="100%" cellpadding="0" cellspacing="0" border="0">'
                $PowerHtml          += $PowerSupplyFragment
            }
            $PowerHtml += '</div>'
            $Sections  += $PowerHtml
        }

        If ($ServerHardware.Cooling) {
            $Cooling    = $ServerHardware.Cooling
            $FanRPM     = @($Cooling.Fans | Where-Object {$null -ne $_.RPM} | Select-Object -ExpandProperty RPM)
            $SpeedRange = $null
            If ($FanRPM.Count -gt 0) {
                $MinimumRPM = ($FanRPM | Measure-Object -Minimum).Minimum
                $MaximumRPM = ($FanRPM | Measure-Object -Maximum).Maximum
                $SpeedRange = '{0:N0} - {1:N0} RPM' -f $MinimumRPM,$MaximumRPM
            }

            $CoolingRows = @(
                [PSCustomObject]@{
                    Label1 = 'Status'
                    Value1 = $Cooling.Status
                    Label2 = 'Redundancy'
                    Value2 = $Cooling.Redundancy
                }
                [PSCustomObject]@{
                    Label1 = 'Fans'
                    Value1 = If ($Cooling.FanCount -gt 0) { '{0} ({1} healthy)' -f $Cooling.FanCount,$Cooling.HealthyCount } Else { $null }
                    Label2 = 'Speed Range'
                    Value2 = $SpeedRange
                }
                [PSCustomObject]@{
                    Label1 = 'Source'
                    Value1 = $Cooling.Source
                    Label2 = $null
                    Value2 = $null
                }
            )

            $CoolingRowsHtml = New-HtmlPropertyRows -Rows $CoolingRows
            $CoolingHeading  = New-HardwareInventorySectionTitle -Title 'Cooling' -IconKey 'Server'
            $CoolingHtml     = '<div class="section">{0}<table class="kv-table" width="100%" cellpadding="0" cellspacing="0" border="0">{1}</table>' -f $CoolingHeading,$CoolingRowsHtml
            $AbnormalFans    = @($Cooling.Fans | Where-Object { $_.Status -notmatch '^(?i)OK$' })
            If ($AbnormalFans.Count -gt 0) {
                $AbnormalFanTable = @(
                    $AbnormalFans | Select-Object -Property Name, Status, @{
                        Name       = 'RPM'
                        Expression = {$_.RPM}
                    }, WarningMinimum, CriticalMinimum
                )

                $AbnormalFanFragment = Convert-ObjectToHtmlTableFragment -InputObject $AbnormalFanTable
                $AbnormalFanFragment = $AbnormalFanFragment -replace '<table>', '<table class="data-table" width="100%" cellpadding="0" cellspacing="0" border="0">'
                $CoolingHtml        += $AbnormalFanFragment
            }
            $CoolingHtml += '</div>'
            $Sections    += $CoolingHtml
        }

        If ($ServerHardware.Temperatures -and @($ServerHardware.Temperatures.Sensors).Count -gt 0) {
            $TemperatureRows = @(
                $ServerHardware.Temperatures.Sensors | Select-Object -Property Name, Status, @{
                    Name       = 'Temperature'
                    Expression = {
                        If ($null -ne $_.Celsius) {
                            '{0:N1} C' -f [double]$_.Celsius
                        }
                    }
                }, @{
                    Name       = 'Warning Maximum'
                    Expression = {
                        If ($null -ne $_.WarningMaximumC) {
                            '{0:N1} C' -f [double]$_.WarningMaximumC
                        }
                    }
                }, @{
                    Name       = 'Critical Maximum'
                    Expression = {
                        If ($null -ne $_.CriticalMaximumC) {
                            '{0:N1} C' -f [double]$_.CriticalMaximumC
                        }
                    }
                }
            )

            $Sections += Convert-ObjectToHtmlTable -Title 'Temperatures' -InputObject $TemperatureRows -Property @(
                'Name',
                'Status',
                'Temperature',
                'Warning Maximum',
                'Critical Maximum'
            ) -IconKey 'Server'
        }

        If ($ServerHardware.Storage) {
            If (@($ServerHardware.Storage.Controllers).Count -gt 0) {
                $Sections += Convert-ObjectToHtmlTable -Title 'RAID Controllers' -InputObject $ServerHardware.Storage.Controllers -Property @(
                    'ID',
                    'Name',
                    'Status',
                    'State',
                    'Slot',
                    'Firmware',
                    'Driver',
                    'StorportDriver',
                    'Mode',
                    'CacheMemory',
                    'PatrolReadMode',
                    'PatrolReadState'
                ) -IconKey 'Disk'
            }

            If (@($ServerHardware.Storage.VirtualDisks).Count -gt 0) {
                $Sections += Convert-ObjectToHtmlTable -Title 'RAID Virtual Disks' -InputObject $ServerHardware.Storage.VirtualDisks -Property @(
                    'ID',
                    'Name',
                    'Status',
                    'State',
                    'RaidLevel',
                    'Size',
                    'WindowsDisk',
                    'BusProtocol',
                    'MediaType',
                    'ReadPolicy',
                    'WritePolicy',
                    'StripeSize'
                ) -IconKey 'Disk'
            }

            If (@($ServerHardware.Storage.PhysicalDisks).Count -gt 0) {
                $PhysicalDiskRows = @($ServerHardware.Storage.PhysicalDisks | Select-Object -Property ID, Status, State, MediaType, BusProtocol, Model, SerialNumber, Capacity, HotSpare, Firmware, NegotiatedSpeed, CapableSpeed, FailurePredicted, Certified)
                $Sections += Convert-ObjectToHtmlTable -Title 'RAID Physical Disks' -InputObject $PhysicalDiskRows -Property @(
                    'ID',
                    'Status',
                    'State',
                    'MediaType',
                    'BusProtocol',
                    'Model',
                    'SerialNumber',
                    'Capacity',
                    'HotSpare',
                    'Firmware',
                    'NegotiatedSpeed',
                    'CapableSpeed',
                    'FailurePredicted',
                    'Certified'
                ) -IconKey 'Disk'
            }

            If (@($ServerHardware.Storage.Enclosures).Count -gt 0) {
                $Sections += Convert-ObjectToHtmlTable -Title 'Storage Enclosures' -InputObject $ServerHardware.Storage.Enclosures -Property @(
                    'ID',
                    'Name',
                    'Status',
                    'State',
                    'Connector',
                    'Firmware',
                    'SASAddress'
                ) -IconKey 'Disk'
            }
        }

        If (@($ServerHardware.Firmware).Count -gt 0) {
            $FirmwareRows = @(
                $ServerHardware.Firmware | Where-Object {
                    $_.Name -notmatch '(?i)^Microsoft Windows|^Server Administrator$'
                } | Select-Object -Property Name, Version, Source
            )
            If ($FirmwareRows.Count -gt 0) {
                $Sections += Convert-ObjectToHtmlTable -Title 'Server Firmware' -InputObject $FirmwareRows -Property @(
                    'Name',
                    'Version',
                    'Source'
                ) -IconKey 'Server'
            }
        }
    }
    #endregion Servers


    $Sections += Convert-ObjectToHtmlTable -Title 'Display Adapters' -IconKey 'Display' -InputObject $Inventory.DisplayAdapters -Property Name, AdapterMemory, DriverVersion, VideoMode, Status
    $Sections += Convert-ObjectToHtmlTable -Title 'Battery' -IconKey 'Battery' -InputObject $Inventory.Battery -Property Name, Status, EstimatedChargePercent, EstimatedRunTimeMinutes, DesignVoltageMv
    $Sections += Convert-ObjectToHtmlTable -Title 'Monitors' -IconKey 'Monitor' -InputObject (Get-HardwareInventoryDisplayMonitor -Inventory $Inventory) -Property Manufacturer, Model, SerialNumber, Connection, CurrentResolution, NativeResolution, RefreshRateHz, Primary, ProductCode, Active

    If (@($Inventory.NetworkAdapters).Count) {
        $Cards = @()

        ForEach ($Adapter in @($Inventory.NetworkAdapters)) {
            $Name = ConvertTo-HtmlValue -Value $Adapter.Name
            $Link = $null
            If ($null -ne $Adapter.LinkGbps -and "$($Adapter.LinkGbps)" -ne '') {
                $Link = '{0} Gbps' -f $Adapter.LinkGbps
            }

            $AdapterRows = @(
                [PSCustomObject]@{
                    Label1 = 'Type'
                    Value1 = $Adapter.Type
                    Label2 = 'Status'
                    Value2 = $Adapter.ConnectionStatus
                }
                [PSCustomObject]@{
                    Label1 = 'Connection'
                    Value1 = $Adapter.Connection
                    Label2 = 'Link'
                    Value2 = $Link
                }
                [PSCustomObject]@{
                    Label1 = 'MAC'
                    Value1 = $Adapter.MACAddress
                    Label2 = 'IPv4'
                    Value2 = $Adapter.IPv4Address
                }
                [PSCustomObject]@{
                    Label1 = 'Gateway'
                    Value1 = $Adapter.DefaultGateway
                    Label2 = 'DHCP'
                    Value2 = $Adapter.DHCPEnabled
                }
                [PSCustomObject]@{
                    Label1 = 'DHCP Server'
                    Value1 = $Adapter.DHCPServer
                    Label2 = 'DNS'
                    Value2 = $Adapter.DNSServers
                }
            )

            $AdapterRowsHtml = New-HtmlPropertyRows -Rows $AdapterRows

            $Cards += '<table class="record-card" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="record-title" colspan="4">{0}</td></tr>{1}</table>' -f $Name,$AdapterRowsHtml
        }

        $Sections += New-RecordSection -Title 'Physical Network Adapters' -IconKey 'Network' -Cards $Cards
    }

    If ($Inventory.iDRAC -and $Inventory.iDRAC.Detected) {
        $iDRAC = $Inventory.iDRAC

        $iDRACRows = @(
            [PSCustomObject]@{
                Label1 = 'Controller'
                Value1 = $iDRAC.Product
                Label2 = 'Service Tag'
                Value2 = $iDRAC.ServiceTag
            }
            [PSCustomObject]@{
                Label1 = 'DNS Name'
                Value1 = $iDRAC.DNSName
                Label2 = 'Management IP'
                Value2 = $iDRAC.ManagementIPAddress
            }
            [PSCustomObject]@{
                Label1 = 'Management MAC'
                Value1 = $iDRAC.ManagementMACAddress
                Label2 = 'MAC Confirmed'
                Value2 = $iDRAC.ManagementMACConfirmed
            }
            [PSCustomObject]@{
                Label1 = 'Learned Via'
                Value1 = $iDRAC.ManagementLearnedVia
                Label2 = 'Neighbor State'
                Value2 = $iDRAC.ManagementNeighborState
            }
            [PSCustomObject]@{
                Label1 = 'Redfish Version'
                Value1 = $iDRAC.RedfishVersion
                Label2 = 'Pass-through Reachable'
                Value2 = $iDRAC.PassthroughReachable
            }
            [PSCustomObject]@{
                Label1 = 'Pass-through Adapter'
                Value1 = $iDRAC.PassthroughAdapter
                Label2 = 'Internal Host IP'
                Value2 = $iDRAC.InternalHostIPAddress
            }
            [PSCustomObject]@{
                Label1 = 'Internal Host MAC'
                Value1 = $iDRAC.InternalHostMACAddress
                Label2 = 'Internal BMC IP'
                Value2 = $iDRAC.InternalBMCIPAddress
            }
            [PSCustomObject]@{
                Label1 = 'Internal BMC MAC'
                Value1 = $iDRAC.InternalBMCMACAddress
                Label2 = $null
                Value2 = $null
            }
        )

        $iDRACHeading = New-HardwareInventorySectionTitle -Title 'iDRAC / BMC Inventory' -IconKey 'Network'
        $Sections    += '<div class="section">{0}<table class="kv-table" width="100%" cellpadding="0" cellspacing="0" border="0">{1}</table></div>' -f $iDRACHeading,(New-HtmlPropertyRows -Rows $iDRACRows)
    }

    If ($Inventory.HyperVNetwork) {
        $HV         = $Inventory.HyperVNetwork
        $HVRecords  = @($HV.Records)
        $HVPhysical = @($HVRecords | Where-Object {$_.AdapterType -eq 'Host Physical'})
        $HVGuests   = @($HVRecords | Where-Object {$_.AdapterType -eq 'VM Guest'})

        $HVSummary = [PSCustomObject][ordered]@{
            ADSite            = $HV.ADSite
            ServersSubnet     = $HV.ServersSubnet
            ReplacementPrefix = $HV.ReplacementPrefix
            LLDPCaptureStatus = $HV.LLDPCaptureStatus
            PhysicalAdapters  = $HVPhysical.Count
            VMGuestAdapters   = $HVGuests.Count
            ISCSIPaths        = @($HV.ISCSIPaths).Count
        }
        $Sections += Convert-ObjectToHtmlTable -Title 'Hyper-V Network Discovery Summary' -IconKey 'Network' -InputObject @($HVSummary) -Property ADSite, ServersSubnet, ReplacementPrefix, LLDPCaptureStatus, PhysicalAdapters, VMGuestAdapters, ISCSIPaths

        If ($HVPhysical.Count) {
            ### Display projection: switch and port share one column and the discovery source is
            ### shortened, so MAC and IP addresses are not broken across lines. The CSV keeps every field.
            $UplinkRows = @(
                $HVPhysical | ForEach-Object {
                    $SwitchName = [string]$_.PhysicalSwitch
                    $SwitchPort = [string]$_.PhysicalSwitchPort

                    [PSCustomObject][ordered]@{
                        AdapterName      = $_.AdapterName
                        MACAddress       = $_.MACAddress
                        CurrentIPAddress = $_.CurrentIPAddress
                        NewIPAddress     = $_.NewIPAddress
                        vSwitch          = $_.vSwitch
                        ActiveRole       = $_.ActiveRole
                        SwitchPort       = If ($SwitchName -and $SwitchName -ne 'N/A') { ('{0} {1}' -f $SwitchName,$SwitchPort).Trim() } Else { 'N/A' }
                        Discovery        = ([string]$_.SwitchDiscovery) -replace '^LLDP/NetEventSession$','LLDP' -replace '^LLDP Not Seen$','Not seen'
                        StoragePeerIP    = $_.StoragePeerIP
                        Status           = $_.Status
                    }
                }
            )

            $Sections += Convert-ObjectToHtmlTable -Title 'Hyper-V Host Network / Physical Uplinks' -IconKey 'Network' -InputObject $UplinkRows -Property AdapterName, MACAddress, CurrentIPAddress, NewIPAddress, vSwitch, ActiveRole, SwitchPort, Discovery, StoragePeerIP, Status
        }

        If ($HVGuests.Count) {
            $Sections += Convert-ObjectToHtmlTable -Title 'Hyper-V VM Network Mapping' -IconKey 'Network' -InputObject $HVGuests -Property VMName, MACAddress, CurrentIPAddress, IPFrom, NewIPAddress, vSwitch, PhysicalSwitch, PhysicalSwitchPort, Status
        }

        If (@($HV.ISCSIPaths).Count) {
            $Sections += Convert-ObjectToHtmlTable -Title 'iSCSI Storage Paths' -IconKey 'Disk' -InputObject @($HV.ISCSIPaths) -Property InterfaceAlias, LocalIPAddress, TargetAddress, RoutePrefix, Connected, Persistent, SessionCount, TargetIQN
        }
    }

    If ($Inventory.SubnetDiscovery) {
        $SD = $Inventory.SubnetDiscovery
        $Sections += Convert-ObjectToHtmlTable -Title ('Native Subnet Discovery - {0} | {1} devices found | {2}/{3} scanned' -f $SD.Subnet,$SD.Found,$SD.Scanned,$SD.Total) -IconKey 'Network' -InputObject @($SD.Devices) -Property IPAddress,HostName,MACAddress,MACSource,PhysicalSwitch,PhysicalSwitchPort,Ping,Discovery,OpenPorts
    }

    If (@($Inventory.Printers).Count) {
        $Cards = @()
        ForEach ($Printer in @($Inventory.Printers)) {
            $Name       = ConvertTo-HtmlValue -Value $Printer.Name
            $DeviceText = @($Printer.Manufacturer, $Printer.Model) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            $DeviceText = $DeviceText -join ' - '

            $Endpoint   = $null
            If (-not [string]::IsNullOrWhiteSpace([string]$Printer.PrinterAddress)) {
                $Endpoint = [string]$Printer.PrinterAddress
                If ($null -ne $Printer.PrinterPort -and "$($Printer.PrinterPort)" -ne '') {
                    $Endpoint = '{0}:{1}' -f $Endpoint,$Printer.PrinterPort
                }

                If (-not [string]::IsNullOrWhiteSpace([string]$Printer.PrinterProtocol)) {
                    $Endpoint = '{0} ({1})' -f $Endpoint,$Printer.PrinterProtocol
                }
            }

            $PrinterRows = @(
                [PSCustomObject]@{
                    Label1 = 'Queue'
                    Value1 = $Printer.QueueType
                    Label2 = 'Connection'
                    Value2 = $Printer.Connection
                }
                [PSCustomObject]@{
                    Label1 = 'Device'
                    Value1 = $DeviceText
                    Label2 = 'Serial'
                    Value2 = $Printer.SerialNumber
                }
                [PSCustomObject]@{
                    Label1 = 'Endpoint'
                    Value1 = $Endpoint
                    Label2 = 'Location'
                    Value2 = $Printer.Location
                }
                [PSCustomObject]@{
                    Label1 = 'Driver'
                    Value1 = $Printer.DriverName
                    Label2 = 'Version'
                    Value2 = $Printer.DriverVersion
                }
                [PSCustomObject]@{
                    Label1 = 'Printer Status'
                    Value1 = $Printer.PrinterStatus
                    Label2 = 'Error State'
                    Value2 = $Printer.DetectedErrorState
                }
            )

            $PrinterRowsHtml = New-HtmlPropertyRows -Rows $PrinterRows

            $Cards += '<table class="record-card" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="record-title" colspan="4">{0}</td></tr>{1}</table>' -f $Name,$PrinterRowsHtml
        }

        $Sections += New-RecordSection -Title 'Printers' -IconKey 'Printer' -Cards $Cards
    }

    If (@($Inventory.DellDocks).Count) {
        $Cards = @()

        ForEach ($Dock in @($Inventory.DellDocks)) {
            $DockModel = ConvertTo-HtmlValue -Value $Dock.Model

            $DockRows  = @(
                [PSCustomObject]@{
                    Label1 = 'Service Tag'
                    Value1 = $Dock.ServiceTag
                    Label2 = 'Serial Number'
                    Value2 = $Dock.SerialNumber
                }
                [PSCustomObject]@{
                    Label1 = 'Firmware'
                    Value1 = $Dock.Firmware
                    Label2 = 'Discovery Source'
                    Value2 = $Dock.Source
                }
            )

            $DockRowsHtml = New-HtmlPropertyRows -Rows $DockRows

            $Cards += '<table class="record-card" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td class="record-title" colspan="4">{0}</td></tr>{1}</table>' -f $DockModel,$DockRowsHtml
        }

        $Sections += New-RecordSection -Title 'Dell Docks' -IconKey 'Dock' -Cards $Cards
    }

    $TotalPhysicalStorageBytes = [uint64]0
    If ($Inventory.Storage -and @($Inventory.Storage.Disks).Count -gt 0) {
        $TotalPhysicalStorageBytes = [uint64](($Inventory.Storage.Disks | Measure-Object -Property SizeBytes -Sum).Sum)
    }

    $TotalPhysicalStorage = If ($TotalPhysicalStorageBytes -gt 0) {
        Optimize-HumanReadable -Size $TotalPhysicalStorageBytes
    } Else {
        $null
    }

    $ComputerName    = ConvertTo-HtmlValue -Value $Inventory.Computer.ComputerName
    $Model           = ConvertTo-HtmlValue -Value $Inventory.Computer.Model
    $OSSummary       = ConvertTo-HtmlValue -Value ('{0} {1}' -f $Inventory.Computer.OS,$Inventory.Computer.Version)
    $MemoryTotal     = ConvertTo-HtmlValue -Value $Inventory.Memory.Total
    $StorageTotal    = ConvertTo-HtmlValue -Value $TotalPhysicalStorage
    $Generated       = ConvertTo-HtmlValue -Value $Inventory.Metadata.CollectedAt
    $ScriptVer       = ConvertTo-HtmlValue -Value $Inventory.Metadata.ScriptVersion
    $PowerShell      = ConvertTo-HtmlValue -Value $Inventory.Metadata.PowerShellVersion

    $ResponsibilityHtml = New-ResponsibilityHtml -Responsibility $(If ($Inventory.PSObject.Properties['Responsibility']) { $Inventory.Responsibility } Else { $null })
    $Sections          += @($ResponsibilityHtml.Sections)
    $RoleSummary        = If ($ResponsibilityHtml.PrimaryRole) { ConvertTo-HtmlValue -Value $ResponsibilityHtml.PrimaryRole } Else { $null }
    $RoleIcon           = Get-HardwareInventoryImageHtml -Key 'RolesSummary' -Alt '' -CssClass 'summary-icon'
    $SummaryWidth       = If ($RoleSummary) { '20%' } Else { '25%' }
    $RoleSummaryCell    = If ($RoleSummary) { '<td class="summary-cell" width="20%"><table cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td class="summary-icon-cell">{0}</td><td><div class="summary-label">Role</div><div class="summary-value">{1}</div></td></tr></table></td>' -f $RoleIcon,$RoleSummary } Else { '' }

    $ComputerHeading = New-HardwareInventorySectionTitle -Title 'Computer and Operating System' -IconKey $PlatformIconKey
    $ModelIcon       = Get-HardwareInventoryImageHtml -Key $PlatformSummaryIconKey -Alt '' -CssClass 'summary-icon'
    $OSIcon          = Get-HardwareInventoryImageHtml -Key 'WindowsSummary' -Alt '' -CssClass 'summary-icon'
    $MemoryIcon      = Get-HardwareInventoryImageHtml -Key 'MemorySummary' -Alt '' -CssClass 'summary-icon'
    $StorageIcon     = Get-HardwareInventoryImageHtml -Key 'DiskSummary' -Alt '' -CssClass 'summary-icon'

    $Css = @'
<style type="text/css">
body { margin:0; padding:0; background:#eef2f6; color:#1f2937; font-family:"Segoe UI",Arial,sans-serif; font-size:13px; line-height:1.4; }
table { border-collapse:collapse; }
.report-shell { width:100%; background:#eef2f6; }
.report-container { width:100%; max-width:1040px; background:#ffffff; }
.header { background:#17365d; color:#ffffff; padding:20px 26px; }
.title { margin:0; font-size:25px; line-height:1.15; font-weight:600; color:#ffffff; }
.subtitle { margin-top:5px; font-size:13px; color:#dbe7f5; }
.meta { margin-top:8px; font-size:11px; color:#c8d8eb; }
.header-logo { display:block; width:104px; height:91px; border:0; margin-left:auto; }
.summary { width:100%; table-layout:fixed; background:#f7f9fc; border-bottom:1px solid #dbe3ec; }
.summary-cell { padding:13px 14px; border-right:1px solid #dbe3ec; vertical-align:middle; }
.summary-icon-cell { width:38px; padding-right:9px; vertical-align:middle; }
.summary-icon { display:block; width:28px; height:28px; border:0; }
.summary-label { color:#667085; font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.3px; }
.summary-value { color:#172b4d; font-size:14px; font-weight:600; margin-top:2px; word-break:break-word; }
.content { padding:18px 22px 26px 22px; }
.section { width:100%; margin:0 0 16px 0; }
.section-heading { width:100%; background:#e8f1fa; border:1px solid #cfdceb; }
.section-icon-cell { width:30px; padding:6px 0 6px 9px; vertical-align:middle; }
.section-icon { display:block; width:20px; height:20px; border:0; }
.section-title-text { color:#17365d; font-size:14px; line-height:20px; font-weight:700; padding:6px 9px 6px 4px; vertical-align:middle; }
.data-table { width:100% !important; border:1px solid #dbe3ec; table-layout:auto; margin:0; }
.data-table th { background:#f2f5f8; color:#344054; border:1px solid #dbe3ec; padding:7px 8px; font-size:11px; font-weight:700; text-align:left; vertical-align:top; }
.data-table td { color:#344054; border:1px solid #e3e8ef; padding:7px 8px; font-size:11px; text-align:left; vertical-align:top; word-break:normal; overflow-wrap:break-word; }
.resp-table td { word-break:break-word; overflow-wrap:anywhere; }
.data-table tr:nth-child(even) td { background:#fbfcfd; }
.volume-chart-cell { width:42px; text-align:center !important; vertical-align:middle !important; white-space:nowrap; }
.volume-space-chart { display:block; width:28px; height:28px; border:0; margin:0 auto; }
.kv-table { width:100%; border:1px solid #dbe3ec; }
.kv-label { background:#f5f7fa; color:#475467; border:1px solid #e3e8ef; padding:7px 8px; font-size:11px; font-weight:700; vertical-align:top; }
.kv-value { color:#344054; border:1px solid #e3e8ef; padding:7px 9px; font-size:11px; vertical-align:top; word-break:break-word; overflow-wrap:anywhere; }
.record-card { width:100%; border:1px solid #dbe3ec; margin:0 0 9px 0; }
.record-title { background:#edf3f9; color:#17365d; border:1px solid #dbe3ec; padding:7px 9px; font-size:12px; font-weight:700; }
.health-list { margin:0; padding:9px 14px 9px 32px; border:1px solid #dbe3ec; border-top:0; background:#ffffff; }
.health-list li { margin:3px 0; padding:0; color:#344054; font-size:11px; line-height:1.45; }
.health-component { color:#475467; font-weight:700; }
.health-ok { color:#067647; font-weight:700; }
.health-warning { color:#b54708; font-weight:700; }
.health-critical { color:#b42318; font-weight:700; }
.health-neutral { color:#475467; font-weight:700; }
.support-link { color:#0563c1; font-weight:600; text-decoration:none; }
.resp-role { color:#17365d; font-size:13px; font-weight:700; line-height:1.3; }
.resp-detail { color:#475467; font-size:11px; line-height:1.45; margin-top:3px; }
.resp-check { color:#667085; font-size:11px; line-height:1.3; }
.resp-value { font-size:13px; font-weight:700; line-height:1.3; margin-top:3px; word-break:break-word; }
.resp-note { color:#667085; font-size:10px; line-height:1.4; padding:6px 2px 0 2px; }
.footer { color:#667085; font-size:10px; border-top:1px solid #e3e8ef; padding:11px 22px 16px 22px; }
a { color:#0563c1; }
@media only screen and (max-width:720px) {
    .content { padding:12px; }
    .header { padding:16px; }
    .summary-cell { display:block; width:auto !important; border-right:0; border-bottom:1px solid #dbe3ec; }
    .resp-tile { display:block !important; width:auto !important; margin-top:8px; }
    .resp-gutter, .resp-empty, .resp-gap { display:none !important; }
}
</style>
'@

    Return @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
$Css
</head>
<body>
<table class="report-shell" width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td align="center" style="padding:18px 10px;">
<table class="report-container" width="1040" cellpadding="0" cellspacing="0" border="0" role="presentation" style="width:100%;max-width:1040px;">
<tr><td class="header"><table width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td valign="middle"><div class="title">Hardware and Responsibility Inventory</div><div class="subtitle">$ComputerName &nbsp;&bull;&nbsp; $Model</div><div class="meta">Generated $Generated &nbsp;&bull;&nbsp; Script $ScriptVer &nbsp;&bull;&nbsp; Windows PowerShell $PowerShell</div></td><td width="130" align="right" valign="middle">$LogoHtml</td></tr></table></td></tr>
<tr><td><table class="summary" width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation"><tr>
<td class="summary-cell" width="$SummaryWidth"><table cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td class="summary-icon-cell">$ModelIcon</td><td><div class="summary-label">Model</div><div class="summary-value">$Model</div></td></tr></table></td>
<td class="summary-cell" width="$SummaryWidth"><table cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td class="summary-icon-cell">$OSIcon</td><td><div class="summary-label">Operating System</div><div class="summary-value">$OSSummary</div></td></tr></table></td>
<td class="summary-cell" width="$SummaryWidth"><table cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td class="summary-icon-cell">$MemoryIcon</td><td><div class="summary-label">Memory</div><div class="summary-value">$MemoryTotal</div></td></tr></table></td>
<td class="summary-cell" width="$SummaryWidth"><table cellpadding="0" cellspacing="0" border="0" role="presentation"><tr><td class="summary-icon-cell">$StorageIcon</td><td><div class="summary-label">OS-Visible Storage</div><div class="summary-value">$StorageTotal</div></td></tr></table></td>
$RoleSummaryCell
</tr></table></td></tr>
<tr><td class="content">
<div class="section">$ComputerHeading<table class="kv-table" width="100%" cellpadding="0" cellspacing="0" border="0">$PropertyRowsHtml$LastUpdateHtml</table></div>
$($ResponsibilityHtml.Overview)
$($Sections -join [Environment]::NewLine)
</td></tr>
<tr><td class="footer">Generated locally by the hardware inventory script. All report images are fixed-size embedded PNG assets; no remote images, tracking pixels, scripts, forms, web fonts, or external style resources are included.</td></tr>
</table></td></tr></table>
</body>
</html>
"@
}

Function Get-HardwareInventoryDisplayMonitor {
    <#
        .SYNOPSIS
        Returns the monitors worth showing in the report and console.

        .DESCRIPTION
        On servers, the BMC virtual console (for example the iDRAC virtual KVM) appears to Windows
        as a monitor with an "Other" connection type, a generic manufacturer and a placeholder
        serial number. It is not a physical display, so it is omitted from the HTML report and the
        console view. The JSON report still contains every monitor Windows reported.

        .PARAMETER Inventory
        Complete hardware inventory object.

        .EXAMPLE
        Get-HardwareInventoryDisplayMonitor -Inventory $Inventory

        .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the complete hardware inventory object.')]
        [object]$Inventory
    )

    $IsServer = [string]$Inventory.Computer.ComputerType -match '(?i)Server'

    @(
        $Inventory.Monitors | Where-Object {
            $null -ne $_ -and -not ($IsServer -and [string]$_.Connection -eq 'Other')
        }
    )
}

Function Show-HardwareInventory {
    ### Lesson 0: This block is the function's help. Run Get-Help Show-HardwareInventory -Full to see it.
    <#
        .SYNOPSIS
        Displays hardware inventory in the PowerShell console.

        .DESCRIPTION
        Formats the complete inventory into concise console sections. Optional sections are shown
        only when matching hardware is present.

        .PARAMETER Inventory
        Complete inventory object to display.

        .EXAMPLE
        Show-HardwareInventory -Inventory $Inventory
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Provide the complete hardware inventory object to display.')]
        [object]$Inventory
    )

    ### Hint - to cut down on repeated duplicate efforts, I'll usually splat them like this.
    $Cy = @{ForegroundColor = 'Cyan'}

    #region - Quick Notes
    ### Lesson 1: Lookup variables
    ### A hashtable ($CN.ST) or an array ($PM[0]) can hold values you type often. Array indexes
    ### start at 0, so $PM[0] is 'Model'. A negative index counts back from the end, so $PM[-1] is
    ### the last element, 'SerialNumber', the same element as $PM[2]. This is NOT splatting (see
    ### Lesson 3). Use lookup variables sparingly: 'SerialNumber' is easier to read than $PM[-1],
    ### and repeating a string costs nothing
    $CN = @{
        NM = 'Name'
        ST = 'Status'
    }

    $PM = @('Model','ID','SerialNumber')

    ### Lesson 2: Two ways to write an array
    ### Inside @( ), items can be separated by commas or by line breaks. The lists below use line
    ### breaks; commas are required only when several items share one line, as in $PM above.
    $OSVDisks = @(
        'Index'
        $PM[0]
        $PM[-1]
        'Size'
        'Interface'
        'MediaType'
        'BusType'
        'HealthStatus'
        'OperationalStatus'
    )

    ### Lesson 3: Splatting
    ### Splatting passes a hashtable of parameter names and values to a command, using @ in
    ### place of $:  Format-Table @MemSplat  is the same as  Format-Table -Property Slot, ...
    ### Only a plain variable can be splatted. @FTSplat.MEM is not valid syntax, and
    ### @($FTSplat.MEM) is the array subexpression operator, not a splat: it passes the whole
    ### hashtable to -Property and the command fails. Copy the inner hashtable into a variable
    ### first, then splat that variable.
    ###
    ### Compare $OSVDisks with $MemSplat: $OSVDisks is an array holding the VALUE of one parameter,
    ### so it is passed with $ (Format-Table -Property $OSVDisks). $MemSplat is a hashtable of
    ### parameter NAMES and values, so it is passed with @ (Format-Table @MemSplat).
    $FTSplat = @{
        Comp = @{
            Property = @(
                'ComputerName'
                'CurrentUser'
                'ComputerType'
                'VirtualType'
                'Manufacturer'
                $PM[0]
                'Chassis'
                'ServiceTag'
                'OS'
                'Version'
                'OSBuild'
                'Architecture'
                'InstalledOn'
                'LastBootTime'
                'Uptime'
                'LastUpdateDateTime'
                'LastUpdateTitle'
                'BIOSVersion'
            )
        }
        MEM  = @{
            Property = @(
                'Slot'
                $CN.ST
                'Bank'
                'Locator'
                'Capacity'
                'Type'
                'FormFactor'
                'SpeedMHz'
                'ConfiguredMHz'
                'Manufacturer'
                'PartNumber'
                $PM[-1]
            )
        }
    }

    $CompSplat = $FTSplat.Comp
    $MemSplat  = $FTSplat.MEM

    ### Lesson 4: Default parameter values, scoped to this function
    ### $PSDefaultParameterValues supplies a parameter automatically whenever a matching command
    ### runs; keys are 'CommandName:ParameterName' and accept wildcards. Assigning a NEW
    ### hashtable creates a variable local to this function, so the default applies here and in
    ### anything this function calls, then disappears when it returns. Changing a key on the
    ### existing table ($PSDefaultParameterValues['Format-Table:AutoSize'] = $true) would modify
    ### the caller's session and outlive the script. To keep defaults the caller already has,
    ### start from a copy: $PSDefaultParameterValues = $PSDefaultParameterValues.Clone()
    $PSDefaultParameterValues = @{
        'Format-Table:AutoSize' = $true
    }
    #endregion - Quick Notes


    Write-Host ''
    Write-Host '=== COMPUTER / OS ===' @Cy

    ### Lesson 5: Format-Table and Format-List are for display only
    ### They turn objects into formatting instructions for the console. Anything piped after them
    ### (Export-Csv, Where-Object, Sort-Object) receives those instructions, not your data, so a
    ### Format cmdlet always goes last in a pipeline: sort first, then format, as in
    ### Sort-Object -Property Index | Format-Table. Keep the real objects for anything else.
    $Inventory.Computer | Format-List @CompSplat

    ### Lesson 6: Counting safely with @( )
    ### A property can hold nothing ($null), one object, or many. Only arrays reliably have
    ### .Count, and under Set-StrictMode, reading .Count on a single object throws in Windows
    ### PowerShell 5.1. Wrapping the value in @( ) always produces an array: @($null).Count is 0,
    ### one object gives 1, many give their number. A count of 0 is treated as $false by If, so
    ### If (@($Inventory.CPU).Count) means "if there is at least one CPU".
    If (@($Inventory.CPU).Count) {
        $CpuTitle = '=== CPU'
        If ($Inventory.CPUTopology) {
            $CpuTitle += ' ({0} POPULATED' -f $Inventory.CPUTopology.InstalledSocketCount
            If ($null -ne $Inventory.CPUTopology.ReportedSocketCount) {
                $CpuTitle += ' / {0} REPORTED SOCKETS' -f $Inventory.CPUTopology.ReportedSocketCount
            }

            ### Lesson 7: Put $null on the left of a comparison
            ### When the left side is an array, -eq and -ne filter the array instead of answering yes or
            ### no: @(1,$null,2) -ne $null returns 1 and 2, not $true. $null -ne $Value always returns a
            ### single $true or $false, whatever $Value holds.
            If ($null -ne $Inventory.CPUTopology.EmptySocketCount -and $Inventory.CPUTopology.EmptySocketCount -gt 0) {
                $CpuTitle += ' | {0} EMPTY' -f $Inventory.CPUTopology.EmptySocketCount
            }

            $CpuTitle += ' | {0} CORES / {1} LOGICAL' -f $Inventory.CPUTopology.TotalCores,$Inventory.CPUTopology.TotalLogicalProcessors
            $CpuTitle += ')'
        }
        $CpuTitle += ' ==='

        ### Lesson 8: Write-Host versus output
        ### Write-Host writes straight to the console and never enters the pipeline, which suits
        ### headings like '=== CPU ==='. Data should be output (written to the pipeline) so a caller
        ### can capture, filter or save it. This function is display-only by design; a function
        ### that returns data should not use Write-Host for that data.
        Write-Host $CpuTitle @Cy
        $Inventory.CPU | Format-Table -Property Socket, $CN.NM, Cores, LogicalProcessors, MaxClockMHz
    }

    If ($Inventory.Memory -and @($Inventory.Memory.Slots).Count) {
        $MemoryTitle  = '=== MEMORY ({0} TOTAL | {1} POPULATED' -f $Inventory.Memory.Total,$Inventory.Memory.InstalledModuleCount
        If ($Inventory.Memory.ReportedLocationCount -gt 0) { $MemoryTitle += ' / {0} REPORTED LOCATIONS' -f $Inventory.Memory.ReportedLocationCount }
        If ($Inventory.Memory.EmptyLocationCount -gt 0)    { $MemoryTitle += ' | {0} EMPTY' -f $Inventory.Memory.EmptyLocationCount }
        If ($Inventory.Memory.MaxCapacity)                 { $MemoryTitle += ' | MAX {0}' -f $Inventory.Memory.MaxCapacity }
        $MemoryTitle += ') ==='

        Write-Host $MemoryTitle @Cy
        $Inventory.Memory.Slots | Format-Table @MemSplat
    }

    If (@($Inventory.Storage.Disks).Count) {
        Write-Host '=== OS-VISIBLE DISKS ===' @Cy
        $Inventory.Storage.Disks | Sort-Object -Property Index | Format-Table -Property $OSVDisks
    }

    If ($Inventory.ServerHardware -and $Inventory.ServerHardware.Available) {
        $ServerHardware = $Inventory.ServerHardware
        If ($ServerHardware.Health) {
            Write-Host '=== SERVER HARDWARE HEALTH ===' @Cy

            ### Lesson 9: Building an object for display
            ### [PSCustomObject]@{ } turns a hashtable into an object with properties. [ordered] keeps the
            ### properties in the order written; a plain hashtable has no guaranteed order. Building a
            ### small object like this is often simpler than formatting each value by hand.
            [PSCustomObject][ordered]@{
                Overall      = $ServerHardware.Health.Status
                ### Lesson 10: If can produce a value
                ### Power = If ($A) { $A.Status } Else { $null } assigns whatever the chosen branch outputs.
                ### The trap: a one-element array returned this way is unwrapped into a single object. Wrap
                ### the whole If in @( ) when the result must stay an array: $List = @(If ($A) { $Items }).
                Power        = If ($ServerHardware.Power) {$ServerHardware.Power.Status} Else {$null}
                Cooling      = If ($ServerHardware.Cooling) {$ServerHardware.Cooling.Status} Else {$null}
                Temperatures = If ($ServerHardware.Temperatures) {$ServerHardware.Temperatures.Status} Else {$null}
            } | Format-List
        }

        If ($ServerHardware.Management) {
            Write-Host '=== OUT-OF-BAND MANAGEMENT ===' @Cy
            $ServerHardware.Management | Format-List -Property Product, IPv4Address, HttpsUrl, Firmware, LifecycleController, Source
        }

        If ($ServerHardware.Power) {
            Write-Host '=== POWER ===' @Cy
            [PSCustomObject][ordered]@{
                Status                 = $ServerHardware.Power.Status
                Redundancy             = $ServerHardware.Power.Redundancy
                SupplyCount            = $ServerHardware.Power.SupplyCount
                HealthyCount           = $ServerHardware.Power.HealthyCount
                CurrentWatts           = If ($ServerHardware.Power.Consumption) {$ServerHardware.Power.Consumption.CurrentWatts} Else {$null}
                InstantaneousHeadroomW = If ($ServerHardware.Power.Consumption) {$ServerHardware.Power.Consumption.InstantaneousHeadroomW} Else {$null}
                PeakWatts              = If ($ServerHardware.Power.Consumption) {$ServerHardware.Power.Consumption.PeakWatts} Else {$null}
                CumulativeKWh          = If ($ServerHardware.Power.Consumption) {$ServerHardware.Power.Consumption.CumulativeKWh} Else {$null}
                Source                 = $ServerHardware.Power.Source
            } | Format-List

            If (@($ServerHardware.Power.Supplies).Count -gt 0) {
                $ServerHardware.Power.Supplies | Format-Table -Property $CN.NM, $CN.ST, Presence, InputRatedWatts, MaximumOutputWatts
            }
        }

        If ($ServerHardware.Cooling) {
            Write-Host '=== COOLING ===' @Cy
            [PSCustomObject][ordered]@{
                Status       = $ServerHardware.Cooling.Status
                Redundancy   = $ServerHardware.Cooling.Redundancy
                FanCount     = $ServerHardware.Cooling.FanCount
                HealthyCount = $ServerHardware.Cooling.HealthyCount
                Source       = $ServerHardware.Cooling.Source
            } | Format-List
            $ServerHardware.Cooling.Fans | Format-Table -Property $CN.NM, $CN.ST, RPM, WarningMinimum, CriticalMinimum
        }

        If ($ServerHardware.Temperatures -and @($ServerHardware.Temperatures.Sensors).Count -gt 0) {
            Write-Host '=== TEMPERATURES ===' @Cy
            $ServerHardware.Temperatures.Sensors | Format-Table -Property $CN.NM, $CN.ST, Celsius, WarningMaximumC, CriticalMaximumC
        }

        If ($ServerHardware.Storage) {
            If (@($ServerHardware.Storage.Controllers).Count -gt 0) {
                Write-Host '=== RAID CONTROLLERS ===' @Cy
                $ServerHardware.Storage.Controllers | Format-Table -Property $PM[1], $CN.NM, $CN.ST, State, Slot, Firmware, Driver, Mode, CacheMemory
            }

            If (@($ServerHardware.Storage.VirtualDisks).Count -gt 0) {
                Write-Host '=== RAID VIRTUAL DISKS ===' @Cy
                $ServerHardware.Storage.VirtualDisks | Format-Table -Property $PM[1], $CN.NM, $CN.ST, State, RaidLevel, Size, WindowsDisk, BusProtocol, MediaType
            }

            If (@($ServerHardware.Storage.PhysicalDisks).Count -gt 0) {
                Write-Host '=== RAID PHYSICAL DISKS ===' @Cy
                $ServerHardware.Storage.PhysicalDisks | Format-Table -Property $PM[1], $CN.ST, State, MediaType, BusProtocol, $PM[0], $PM[-1], Capacity, HotSpare, Firmware
            }

            If (@($ServerHardware.Storage.Enclosures).Count -gt 0) {
                Write-Host '=== STORAGE ENCLOSURES ===' @Cy
                $ServerHardware.Storage.Enclosures | Format-Table -Property $PM[1], $CN.NM, $CN.ST, State, Connector, Firmware, SASAddress
            }
        }

        If (@($ServerHardware.Firmware).Count -gt 0) {
            Write-Host '=== SERVER FIRMWARE ===' @Cy
            $ServerHardware.Firmware | Where-Object {
                ### Lesson 11: -match uses regular expressions
                ### -match is already case-insensitive (use -cmatch for case-sensitive), so (?i) is not needed.
                ### In 'A|B', each side is a separate pattern with its own anchors: '^Microsoft Windows' skips
                ### anything starting with that text, while '^Server Administrator$' skips only that exact name.
                $_.Name -notmatch '^Microsoft Windows|^Server Administrator$'
            } | Format-Table -Property $CN.NM, Version, Source
        }
    }


    If (@($Inventory.Storage.Volumes).Count) {
        Write-Host '=== VOLUMES ===' @Cy
        $Inventory.Storage.Volumes | Format-Table -Property Drive, Label, FileSystem, Size, Free, FreePercent
    }

    If (@($Inventory.Storage.Layout).Count) {
        Write-Host '=== DISK LAYOUT ===' @Cy
        $Inventory.Storage.Layout | Format-Table -Property DiskIndex, Partition, PartitionSize, Drive, Label, FileSystem, VolumeSize, Free, FreePercent
    }

    If (@($Inventory.DisplayAdapters).Count) {
        Write-Host '=== DISPLAY ADAPTERS ===' @Cy
        $Inventory.DisplayAdapters | Format-Table -Property $CN.NM, AdapterMemory, DriverVersion, VideoMode, $CN.ST
    }

    If (@($Inventory.Battery).Count) {
        Write-Host '=== BATTERY ===' @Cy
        $Inventory.Battery | Format-Table -Property $CN.NM, $CN.ST, EstimatedChargePercent, EstimatedRunTimeMinutes
    }

    If (@($Inventory.NetworkAdapters).Count) {
        Write-Host '=== PHYSICAL NETWORK ADAPTERS ===' @Cy
        $NetAdap = @{
            Property = @(
                'Type'
                $CN.NM
                'MACAddress'
                'LinkGbps'
                'Enabled'
                'ConnectionStatus'
                'IPv4Address',
                'DefaultGateway'
                'DHCPEnabled'
            )
            ### Lesson 4 already sets AutoSize for every Format-Table in this function. Without
            ### that default, you could add it to this splat instead:
            #AutoSize = $true
        }
        $Inventory.NetworkAdapters | Format-Table @NetAdap
    }

    $DisplayMonitors = @(Get-HardwareInventoryDisplayMonitor -Inventory $Inventory)
    If ($DisplayMonitors.Count) {
        Write-Host '=== MONITORS ===' @Cy
        $FTMonitors = @{
            Property = @(
                'Manufacturer'
                $PM[0]
                $PM[-1]
                'Connection'
                'CurrentResolution'
                'NativeResolution'
                'RefreshRateHz'
                'Primary'
                'ProductCode'
                'Active'
            )
        }
        $DisplayMonitors | Format-Table @FTMonitors
    }

    If (@($Inventory.Printers).Count) {
        Write-Host '=== PRINTERS ===' @Cy
        $PRN = @{
            Property = @(
                $CN.NM, 
                'QueueType', 
                'Connection', 
                'Manufacturer', 
                $PM[0], 
                'SerialNumber', 
                'PrinterAddress', 
                'DriverName', 
                'DriverVersion', 
                'PrinterStatus', 
                'Location'
            )
        }
        $Inventory.Printers | Format-Table @PRN
    }

    If (@($Inventory.DellDocks).Count) {
        Write-Host '=== DELL DOCKS ===' @Cy
        $Inventory.DellDocks | Format-Table -Property Manufacturer, $PM[0], ServiceTag, SerialNumber, Firmware, Source
    }

    $Responsibility = If ($Inventory.PSObject.Properties['Responsibility']) { $Inventory.Responsibility } Else { $null }
    If ($Responsibility) {
        Write-Host '=== SYSTEM RESPONSIBILITIES ===' @Cy
        $Responsibility.Roles | Format-Table -Property Role, $CN.ST, Detail -Wrap

        Write-Host '=== READINESS AND SECURITY ===' @Cy
        $Responsibility.Posture | Format-Table -Property Check, $CN.ST, Value -Wrap

        ### Lesson 12: Continuing a long line without backticks
        ### A line ending in an operator (-and, -or), a pipe (|), a comma or an opening bracket
        ### continues on the next line automatically. That is safer than a backtick, which silently
        ### stops working if a space follows it.
        $ThirdPartyStopped = @(
            $Responsibility.Services | Where-Object {
                $null -ne $_ -and
                -not $_.IsMicrosoft -and
                $_.PSObject.Properties['StoppedUnexpectedly'] -and
                $_.StoppedUnexpectedly
            }
        )

        If ($ThirdPartyStopped.Count) {
            Write-Host '=== THIRD-PARTY SERVICES STOPPED WITH AN ERROR ===' @Cy
            $ThirdPartyStopped | Format-Table -Property DisplayName, $CN.NM, State, ExitCode, StartName, Vendor
        }

        If (@($Responsibility.CollectionErrors).Count) {
            Write-Host '=== COLLECTION GAPS ===' @Cy
            $Responsibility.CollectionErrors | Format-Table -Property Category, Error -Wrap
        }
    }
}

Function Send-HardwareInventoryEmail {
    <#
        .SYNOPSIS
        Sends the hardware inventory report with all embedded images as inline CID resources.

        .DESCRIPTION
        Sends the report through System.Net.Mail.SmtpClient for Windows PowerShell 5.1. Every
        Base64 PNG used by the standalone HTML is converted to a Content-ID linked resource before
        transmission. The email therefore contains no remote image references and does not rely on
        Outlook supporting data URI images.

        .PARAMETER EmailConfig
        Hashtable containing To, From, SmtpServer, SmtpPort, and UseSsl.

        .PARAMETER Credential
        Optional SMTP credential.

        .PARAMETER Subject
        Email subject.

        .PARAMETER HtmlBody
        HTML generated by New-HardwareInventoryHtml.

        .PARAMETER Attachments
        Optional file paths to attach.

        .EXAMPLE
        Send-HardwareInventoryEmail -EmailConfig $EmailConfig -Credential $SmtpCredential -Subject $Subject -HtmlBody $Html -Attachments $Attachments
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the hashtable containing To, From, SmtpServer, SmtpPort, and UseSsl settings.')]
        [hashtable]$EmailConfig,

        [Parameter()]
        [System.Management.Automation.Credential()]
        [pscredential]$Credential,

        [Parameter(Mandatory, HelpMessage = 'Specify the email subject.')]
        [string]$Subject,

        [Parameter(Mandatory, HelpMessage = 'Specify the HTML email body.')]
        [string]$HtmlBody,

        [Parameter()]
        [string[]]$Attachments
    )

    <#
        LESSON 1: Why .NET classes instead of Send-MailMessage
        Send-MailMessage can send HTML and attachments, but it cannot attach images that the HTML
        displays INLINE. The report needs exactly that, so this function builds the message itself
        with System.Net.Mail, the same classes Send-MailMessage uses internally. Microsoft now marks
        Send-MailMessage as obsolete, which is another reason to understand the classes underneath.
        Each variable is set to $null before the Try so Finally can safely test and dispose
        whatever was actually created (see Lesson 4 of Get-VolumeFreeSpaceChartHtml).
    #>
    $Message       = $null
    $Client        = $null
    $AlternateView = $null

    <#
        LESSON 2: Lists typed to what they hold, and tracking objects for later cleanup
        List[System.IO.MemoryStream] accepts only MemoryStream objects, so adding anything else
        fails immediately instead of causing a confusing error later. Every stream and image
        resource created below is added to one of these lists so Finally can dispose all of them,
        however many images the report uses.
    #>
    $Streams       = New-Object -TypeName System.Collections.Generic.List[System.IO.MemoryStream]
    $Resources     = New-Object -TypeName System.Collections.Generic.List[System.Net.Mail.LinkedResource]

    Try {
        $Message = New-Object -TypeName System.Net.Mail.MailMessage
        $Client  = New-Object -TypeName System.Net.Mail.SmtpClient -ArgumentList ($EmailConfig.SmtpServer,[int]$EmailConfig.SmtpPort)

        $Message.From = New-Object -TypeName System.Net.Mail.MailAddress -ArgumentList ($EmailConfig.From)

        <#
            LESSON 3: Accept either separator, and drop empty entries
            -split takes a regular expression, and [,;] is a character class meaning "a comma OR a
            semicolon", so 'a@x.com; b@x.com' and 'a@x.com,b@x.com' both work. A trailing separator
            leaves an empty entry, which the Where-Object filter removes. Trim() strips the spaces
            around each address. MailAddress and To.Add check each address's format and throw on
            invalid input, which the Catch below reports.
        #>
        ForEach ($Address in ($EmailConfig.To -split '[,;]' | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})) {
            $null = $Message.To.Add($Address.Trim())
        }

        $Message.Subject         = $Subject

        <#
            LESSON 4: Declare the encoding for anything outside plain English
            Without UTF-8, characters such as é, ü or a non-breaking space can arrive as question
            marks or garbled text. The subject and the body each carry their own encoding setting.
        #>
        $Message.SubjectEncoding = [System.Text.Encoding]::UTF8
        $Message.BodyEncoding    = [System.Text.Encoding]::UTF8
        $Message.IsBodyHtml      = $true

        $EmailHtml     = $HtmlBody
        $UsedAssetKeys = @()

        <#
            LESSON 5: Turning embedded images into email attachments the HTML can display
            The standalone HTML file embeds every image as a data URI (src="data:image/png;base64,...").
            Outlook for Windows does not display data URI images, so for email each one is replaced
            with src="cid:HardwareInventory_<Key>", which refers to an image attached to the same
            message by its Content-ID.
            .Contains() and .Replace() are .NET string methods: they match text LITERALLY and are
            case-sensitive. -replace would treat the Base64 text as a regular expression, and
            Base64 contains +, which regex treats as "one or more" of the previous character, so
            the match would fail. Use the string methods whenever the search text is data rather
            than a pattern.
            Several asset keys share identical image data. The first key replaces every copy of
            that data, so the later keys find nothing and add no duplicate attachment.
        #>
        ForEach ($AssetKey in $script:HardwareInventoryImageAssets.Keys) {
            $Asset   = $script:HardwareInventoryImageAssets[$AssetKey]
            $DataUri = 'data:{0};base64,{1}' -f $Asset.MimeType,$Asset.Base64

            If ($EmailHtml.Contains($DataUri)) {
                $Cid       = 'HardwareInventory_{0}' -f $AssetKey
                $EmailHtml = $EmailHtml.Replace($DataUri,('cid:{0}' -f $Cid))

                $UsedAssetKeys += $AssetKey
            }
        }

        <#
            LESSON 6: How an HTML email carries its own images
            An AlternateView is one version of the message body, here the HTML version. Images
            added to its LinkedResources travel inside the message next to the HTML, each labeled
            with its ContentId. A mail client shows them inline wherever the HTML says
            cid:<ContentId>, rather than listing them as attachments, and no remote image is ever
            loaded.
        #>
        $AlternateView = [System.Net.Mail.AlternateView]::CreateAlternateViewFromString(
            $EmailHtml,[System.Text.Encoding]::UTF8,'text/html'
        )

        ForEach ($AssetKey in $UsedAssetKeys) {
            $Asset    = $script:HardwareInventoryImageAssets[$AssetKey]
            $Bytes    = [Convert]::FromBase64String($Asset.Base64)

            <#
                LESSON 7: Some objects must stay open until much later
                A LinkedResource does not copy the image when it is created; it reads the stream
                when the message is SENT. Disposing the stream inside this loop would leave the
                resource pointing at a closed stream, and Send() would fail. That is why each
                stream goes into $Streams and is disposed in Finally, after sending. (,$Bytes)
                passes the byte array as ONE constructor argument, as in earlier lessons.
            #>
            $Stream   = New-Object -TypeName System.IO.MemoryStream -ArgumentList (,$Bytes)
            $Resource = New-Object -TypeName System.Net.Mail.LinkedResource -ArgumentList ($Stream,$Asset.MimeType)

            $Resource.ContentId        = 'HardwareInventory_{0}' -f $AssetKey
            $Resource.TransferEncoding = [System.Net.Mime.TransferEncoding]::Base64

            $null     = $Streams.Add($Stream)
            $null     = $Resources.Add($Resource)
            $null     = $AlternateView.LinkedResources.Add($Resource)
        }

        $null = $Message.AlternateViews.Add($AlternateView)

        ForEach ($Path in @($Attachments)) {
            If ($Path -and (Test-Path -LiteralPath $Path)) {
                $null = $Message.Attachments.Add((New-Object -TypeName System.Net.Mail.Attachment -ArgumentList ($Path)))
            } ElseIf ($Path) {
                Write-Warning -Message ('Attachment not found and skipped: {0}' -f $Path)
            }
        }

        <#
            LESSON 8: Adding one option to a set of flags
            SecurityProtocol is a flags value: each protocol is one bit. -bor (bitwise OR) turns
            the TLS 1.2 bit on and leaves the others as they were. Assigning Tls12 directly would
            REPLACE the whole set and could break other connections in the same session that need
            a different protocol.
        #>
        ### Azure Communication Services requires TLS 1.2; older .NET defaults may offer only TLS 1.0.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        <#
            LESSON 9: What EnableSsl means for SmtpClient
            SmtpClient supports only STARTTLS: it connects in plain text, normally on port 587, and
            then upgrades the connection to TLS before signing in. It does NOT support "implicit"
            TLS on port 465, where encryption starts immediately. Pointing it at port 465 hangs or
            fails, a common surprise. Azure Communication Services uses 587 with STARTTLS.
        #>
        $Client.EnableSsl = [bool]$EmailConfig.UseSsl

        <#
            LESSON 10: Handing a PowerShell credential to a .NET class
            .NET networking classes do not accept a PSCredential. GetNetworkCredential() converts it
            into the NetworkCredential type that SmtpClient expects. UseDefaultCredentials = $false
            ensures the client uses the supplied account rather than the signed-in Windows user.
        #>
        If ($Credential) {
            $Client.UseDefaultCredentials = $false
            $Client.Credentials           = $Credential.GetNetworkCredential()
        }

        $Client.Send($Message)
    } Catch {
        <#
            LESSON 11: Rethrow with context
            An error such as "Failure sending mail" says nothing about which step was involved.
            Throwing a new message that names the operation, and includes the original message,
            tells the caller exactly what failed. An earlier version used Write-Error followed by
            Throw: under the script's 'Stop' preference the Write-Error itself ended the function,
            so the Throw never ran and the clearer message was lost.
        #>
        Throw ('Unable to send hardware inventory email: {0}' -f $_.Exception.Message)
    } Finally {
        <#
            LESSON 12: Dispose the message, the connection, then anything left over
            Disposing the MailMessage also disposes its views, linked images and attachments, and
            closes file handles on the attached CSV and JSON reports, so they can be deleted or
            moved afterwards. Disposing the SmtpClient closes the network connection. The tracked
            resources and streams are then disposed explicitly. Disposing an object twice is
            harmless, and each call has its own Try/Catch so one failure cannot stop the rest.
        #>
        If ($Message) { $Message.Dispose() }
        If ($Client)  { $Client.Dispose() }

        ForEach ($Resource in $Resources) {
            Try {
                $Resource.Dispose()
            } Catch {
                Write-Verbose -Message ('Unable to dispose linked image resource: {0}' -f $_.Exception.Message)
            }
        }
        ForEach ($Stream in $Streams) {
            Try {
                $Stream.Dispose()
            } Catch {
                Write-Verbose -Message ('Unable to dispose linked image stream: {0}' -f $_.Exception.Message)
            }
        }
    }
} ### Lessons

#region System Responsibility Presentation
Function ConvertTo-ResponsibilityHtmlText {
    <#
        .SYNOPSIS
        Formats and HTML-encodes one report value.

        .DESCRIPTION
        Dates render as yyyy-MM-dd HH:mm, booleans as Yes/No, collections as a comma-separated
        list, and long text is truncated to MaxLength characters.

        .PARAMETER Value
        Value to format.

        .PARAMETER MaxLength
        Optional maximum number of characters before truncation.

        .EXAMPLE
        ConvertTo-ResponsibilityHtmlText -Value (Get-Date) -MaxLength 20

        Returns the date as yyyy-MM-dd HH:mm, HTML-encoded.
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [AllowNull()]
        [object]$Value,

        [Parameter()]
        [int]$MaxLength = 0
    )

    If ($null -eq $Value) {
        Return ''
    }

    $Text = If ($Value -is [datetime]) {
        $Value.ToString('yyyy-MM-dd HH:mm')
    } ElseIf ($Value -is [bool]) {
        If ($Value) { 'Yes' } Else { 'No' }
    } ElseIf ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        (@($Value | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) -join ', ')
    } Else {
        [string]$Value
    }

    $Text = ($Text -replace '\s+',' ').Trim()

    If ($MaxLength -gt 0 -and $Text.Length -gt $MaxLength) {
        $Text = $Text.Substring(0,$MaxLength).TrimEnd() + '...'
    }

    Return [System.Net.WebUtility]::HtmlEncode($Text)
}

Function Get-ResponsibilityStatusColor {
    <#
        .SYNOPSIS
        Returns the accent colour for a status name.

        .DESCRIPTION
        Maps the report's status vocabulary to its accent colours: OK is green, Warning is amber,
        Critical is red, Role is the report navy, and anything else is a neutral grey.

        .PARAMETER Status
        OK, Warning, Critical, Neutral or Role.

        .EXAMPLE
        Get-ResponsibilityStatusColor -Status 'Warning'

        Returns #b54708.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter()]
        [AllowEmptyString()]
        [string]$Status
    )

    Switch -Regex ($Status) {
        '^(?i)OK$'       { Return '#067647' }
        '^(?i)Warning$'  { Return '#b54708' }
        '^(?i)Critical$' { Return '#b42318' }
        '^(?i)Role$'     { Return '#17365d' }
        Default          { Return '#98a2b3' }
    }
}

Function Get-ResponsibilityCellStatus {
    <#
        .SYNOPSIS
        Infers a status from a common state value such as Running, Stopped or a task result code.

        .DESCRIPTION
        Used for table cells that carry a state but no explicit status. Running, Started, Up,
        Online, Active, Enabled and OK map to OK; task result 0x00000000 maps to OK and the
        "not yet run" codes to Neutral; any other hexadecimal result code maps to Warning; Failed,
        Down, Offline and similar map to Critical. Everything else is Neutral.

        .PARAMETER Value
        Displayed state value.

        .EXAMPLE
        Get-ResponsibilityCellStatus -Value 'Running'

        Returns OK.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    $Text = [string]$Value

    Switch -Regex ($Text) {
        '^(?i)(Running|Started|Up|Online|Active|Enabled|OK|Healthy|Ready|On)$' { Return 'OK' }
        '^0x00000000$'                                                         { Return 'OK' }
        '^0x0004130[0-5]$'                                                     { Return 'Neutral' }
        '^0x[0-9A-F]{8}$'                                                      { Return 'Warning' }
        '^(?i)(Degraded|Paused|Warning|Inactive|Partial)$'                     { Return 'Warning' }
        '^(?i)(Failed|Down|Error|Critical|Offline|Lost)$'                      { Return 'Critical' }
        Default                                                                { Return 'Neutral' }
    }
}

Function New-ResponsibilityTableHtml {
    <#
        .SYNOPSIS
        Renders rows as a report section table with optional status colouring and a row limit.

        .DESCRIPTION
        Columns is an ordered dictionary of header text to a property name or scriptblock.
        Columns listed in StatusColumns are coloured by status. A row can override the inferred
        status of a column by carrying a property named <PropertyName>Status.
        Columns that are blank for every row are dropped.

        .PARAMETER Title
        Section heading.

        .PARAMETER IconKey
        Embedded section icon key.

        .PARAMETER Rows
        Objects to render.

        .PARAMETER Columns
        Ordered dictionary of header text to property name or scriptblock.

        .PARAMETER StatusColumns
        Header names whose cells are status-coloured.

        .PARAMETER MaxRows
        Maximum rows to render; 0 renders all.

        .PARAMETER MaxCellLength
        Maximum characters per cell; 0 disables truncation.

        .PARAMETER NoWrapColumns
        Header names whose cells must not wrap, such as dates and result codes.

        .PARAMETER Note
        Optional note shown under the table.

        .EXAMPLE
        New-ResponsibilityTableHtml -Title 'SQL Server Instances' -IconKey 'Services' -Rows $SQL -Columns ([ordered]@{ 'Instance' = 'Instance'; 'Status' = 'Status' }) -StatusColumns 'Status'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the section title.')]
        [string]$Title,

        [Parameter(Mandatory, HelpMessage = 'Specify the embedded section icon key.')]
        [string]$IconKey,

        [Parameter()]
        [object[]]$Rows,

        [Parameter(Mandatory, HelpMessage = 'Specify the ordered column map.')]
        [System.Collections.Specialized.OrderedDictionary]$Columns,

        [Parameter()]
        [string[]]$StatusColumns = @(),

        [Parameter()]
        [int]$MaxRows = 0,

        [Parameter()]
        [int]$MaxCellLength = 160,

        [Parameter()]
        [string[]]$NoWrapColumns = @(),

        [Parameter()]
        [string]$Note
    )

    <#
        LESSON 1: Filter out $null first, and return something the caller can always use
        A collector that failed passes $null, and @($null) is a one-element array, so its .Count
        is 1, not 0. Filtering with Where-Object { $null -ne $_ } inside @( ) gives a true count.
        Returning an empty string rather than $null means the caller can add the result to the
        report without checking it first.
    #>
    $AllRows = @($Rows | Where-Object { $null -ne $_ })
    If ($AllRows.Count -eq 0) {
        Return ''
    }

    <#
        LESSON 2: An If statement unwraps a one-element array
        When an If statement's output is assigned to a variable, a one-element array comes out as
        a single object. Windows PowerShell 5.1 under StrictMode then throws on $Shown.Count. This
        was a real bug: any table with exactly one row, such as a server with one SQL instance,
        stopped the whole report. Wrapping the whole If in @( ) keeps the result an array however
        many rows there are.
    #>
    $Shown    = @(
        If ($MaxRows -gt 0 -and $AllRows.Count -gt $MaxRows) {
            $AllRows | Select-Object -First $MaxRows
        } Else {
            $AllRows
        }
    )

    ### Worker Scriptblock
    <#
        LESSON 3: A column defined by a property name OR by a scriptblock
        Each column in the -Columns map is either a property name ('Name') or a scriptblock
        ({ Param ($Row) ... }). $GetValue checks which one it received with -is [scriptblock]: a
        scriptblock is run with the row as its argument, and a name is looked up with
        PSObject.Properties, which is safe under StrictMode.
        This is the third way a value can be code, alongside a ScriptProperty, which runs every
        time it is read, and a calculated property, which runs once while selecting. Here the
        code that RECEIVES the scriptblock decides when to run it.
    #>
    $GetValue = {
        Param ($Row,$Selector)

        If ($Selector -is [scriptblock]) {
            Return (& $Selector $Row)
        }

        $Property = $Row.PSObject.Properties[[string]$Selector]
        If ($Property) {
            Return $Property.Value
        }

        Return $null
    }

    <#
        LESSON 4: [ordered] keeps the columns in order, and what the leading comma is for
        A plain hashtable does not keep keys in the order they were added; [ordered]@{} does, so
        each row's cells stay in column order.
        ,$Map is the unary comma: it wraps $Map in a one-element array so the pipeline cannot
        unroll it. That matters for ARRAYS: without the comma, two 2-item arrays would come out
        as four separate items. A dictionary is not unrolled by the pipeline, so here the comma is
        only a safeguard. The code would also work without it, and testing shows both give two
        rows.
    #>
    $Cells    = @(
        ForEach ($Row in $Shown) {
            $Map = [ordered]@{}
            ForEach ($Header in $Columns.Keys) {
                $Map[$Header] = & $GetValue $Row $Columns[$Header]
            }
            ,$Map
        }
    )

    <#
        LESSON 5: Break, and the ForEach-Object trap
        A column is shown only if at least one row has a value in it. For each column, the inner
        loop checks rows until it finds a value, outputs the column name, and Break stops that
        inner loop; the outer loop then moves on to the next column. Break in nested ForEach
        STATEMENTS exits only the innermost one.
        Warning: Break inside ForEach-Object (the pipeline cmdlet) does NOT mean "skip the rest
        of this item". With no enclosing loop it stops the ENTIRE script. Use a ForEach
        statement when you need Break or Continue.
    #>
    $Visible  = @(
        ForEach ($Header in $Columns.Keys) {
            ForEach ($Map in $Cells) {
                $Value = $Map[$Header]
                If ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace((ConvertTo-ResponsibilityHtmlText -Value $Value))) {
                    $Header
                    Break
                }
            }
        }
    )

    If ($Visible.Count -eq 0) {
        Return ''
    }

    <#
        LESSON 6: Build large text with StringBuilder
        .NET strings cannot be changed: $Html += '<td>...</td>' creates a brand-new string and
        copies everything built so far, every time. For a table with thousands of cells the
        copying grows enormously. StringBuilder appends into a growing buffer, and ToString()
        produces the final string once. Append() returns the builder itself, to allow
        $sb.Append('a').Append('b'), so $null = discards that return value, as in Lesson 2 of
        Get-NativeSubnetDiscovery.
    #>
    $Builder = New-Object -TypeName System.Text.StringBuilder
    $null    = $Builder.Append('<table class="data-table resp-table" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>')
    <#
        LESSON 7: Encode anything you did not write yourself
        Service names, share descriptions and event messages come from the machine being
        inventoried, so any of them could contain < > & or quotes. HtmlEncode turns those into
        &lt; &gt; &amp; so they display as text and can never inject HTML into the report.
        Headers and notes are encoded here; cell values are encoded by
        ConvertTo-ResponsibilityHtmlText. The colored <span> is added AFTER encoding, so only
        markup this function wrote itself is ever live HTML.
    #>
    ForEach ($Header in $Visible) {
        $null = $Builder.AppendFormat('<th>{0}</th>',[System.Net.WebUtility]::HtmlEncode($Header))
    }
    $null = $Builder.Append('</tr>')

    <#
        LESSON 8: A For loop when two arrays line up by position
        $Shown holds the original rows and $Cells holds the computed values for those same rows,
        in the same order. A For loop with an index $I reads both: $Shown[$I] and $Cells[$I] always
        belong to the same row. ForEach gives only the current item, not its position.
    #>
    For ($I = 0; $I -lt $Shown.Count; $I++) {
        $Row  = $Shown[$I]
        $Map  = $Cells[$I]
        $null = $Builder.Append('<tr>')

        ForEach ($Header in $Visible) {
            $Text = ConvertTo-ResponsibilityHtmlText -Value $Map[$Header] -MaxLength $MaxCellLength

            If ($StatusColumns -contains $Header -and $Text) {
                $Selector = $Columns[$Header]

                <#
                    LESSON 9: A naming convention as a feature
                    Normally a cell's color is guessed from its text: 'Running' shows green. A row
                    can override that guess by carrying a property named <Column>Status. A State
                    column, for example, checks for StateStatus. The Third-Party Services table uses
                    this so that a stopped service which exited cleanly stays grey, while one that
                    crashed shows amber. -isnot [scriptblock] skips the check for computed columns,
                    which have no property name to build from.
                #>
                $Override = If ($Selector -isnot [scriptblock]) {
                    $Row.PSObject.Properties[('{0}Status' -f $Selector)]
                } Else {
                    $null
                }

                $Status   = If ($Override) {
                    [string]$Override.Value
                } Else {
                    Get-ResponsibilityCellStatus -Value $Map[$Header]
                }

                If ($Status -ne 'Neutral') {
                    $Text = '<span style="color:{0};font-weight:700;">{1}</span>' -f (Get-ResponsibilityStatusColor -Status $Status),$Text
                }
            }

            If ($NoWrapColumns -contains $Header) {
                $null = $Builder.AppendFormat('<td style="white-space:nowrap;">{0}</td>',$Text)
            } Else {
                $null = $Builder.AppendFormat('<td>{0}</td>',$Text)
            }
        }

        $null = $Builder.Append('</tr>')
    }

    $null = $Builder.Append('</table>')

    <#
        LESSON 10: When += on an array is perfectly fine
        Lesson 6 warned about copying with +=. That cost matters only for large or frequently
        grown collections. $Notes holds at most two short strings, so @() with += is the clearest
        choice here. Choose the simple tool unless size or speed actually matters.
    #>
    $Notes = @()
    If ($Shown.Count -lt $AllRows.Count) {
        $Notes += 'Showing {0} of {1}. The complete list is in the JSON report.' -f $Shown.Count,$AllRows.Count
    }
    If (-not [string]::IsNullOrWhiteSpace($Note)) {
        $Notes += $Note
    }
    If ($Notes.Count) {
        $null = $Builder.AppendFormat('<div class="resp-note">{0}</div>',[System.Net.WebUtility]::HtmlEncode(($Notes -join ' ')))
    }

    $Heading = New-HardwareInventorySectionTitle -Title $Title -IconKey $IconKey

    Return '<div class="section">{0}{1}</div>' -f $Heading,$Builder.ToString()
} ### Lessons

Function New-ResponsibilityKeyValueHtml {
    <#
        .SYNOPSIS
        Renders label/value pairs as a two-pairs-per-row key/value section.

        .DESCRIPTION
        Used for single-record sections such as the domain controller and certificate authority.
        Values are formatted with ConvertTo-ResponsibilityHtmlText, blank values are skipped, and the
        section is omitted entirely when nothing has a value.

        .PARAMETER Title
        Section heading.

        .PARAMETER IconKey
        Embedded section icon key.

        .PARAMETER Pairs
        Ordered dictionary of label to value. Blank values are skipped.

        .EXAMPLE
        New-ResponsibilityKeyValueHtml -Title 'Certificate Authority' -IconKey 'Shield' -Pairs ([ordered]@{ 'CA name' = $CA.Name; 'Service' = $CA.Service })
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the section title.')]
        [string]$Title,

        [Parameter(Mandatory, HelpMessage = 'Specify the embedded section icon key.')]
        [string]$IconKey,

        [Parameter(Mandatory, HelpMessage = 'Specify the ordered label/value pairs.')]
        [System.Collections.Specialized.OrderedDictionary]$Pairs
    )

    $Items = @(
        ForEach ($Label in $Pairs.Keys) {
            $Text = ConvertTo-ResponsibilityHtmlText -Value $Pairs[$Label]
            If (-not [string]::IsNullOrWhiteSpace($Text)) {
                [pscustomobject]@{
                    Label = [System.Net.WebUtility]::HtmlEncode($Label)
                    Value = $Text
                }
            }
        }
    )

    If ($Items.Count -eq 0) {
        Return ''
    }

    $Rows = @(
        For ($I = 0; $I -lt $Items.Count; $I += 2) {
            If ($I + 1 -lt $Items.Count) {
                '<tr><td class="kv-label" width="18%">{0}</td><td class="kv-value" width="32%">{1}</td><td class="kv-label" width="18%">{2}</td><td class="kv-value" width="32%">{3}</td></tr>' -f $Items[$I].Label,$Items[$I].Value,$Items[$I+1].Label,$Items[$I+1].Value
            } Else {
                '<tr><td class="kv-label" width="18%">{0}</td><td class="kv-value" colspan="3">{1}</td></tr>' -f $Items[$I].Label,$Items[$I].Value
            }
        }
    )

    $Heading = New-HardwareInventorySectionTitle -Title $Title -IconKey $IconKey

    Return '<div class="section">{0}<table class="kv-table" width="100%" cellpadding="0" cellspacing="0" border="0">{1}</table></div>' -f $Heading,($Rows -join '')
}

Function New-ResponsibilityTileGridHtml {
    <#
        .SYNOPSIS
        Renders an Outlook-safe grid of status tiles.

        .DESCRIPTION
        Role tiles show the role name with a detail line. Posture tiles show a small check label
        above a status-coloured value. Every tile carries a status-coloured left accent bar.

        .PARAMETER Title
        Section heading.

        .PARAMETER IconKey
        Embedded section icon key.

        .PARAMETER Items
        Objects with Role/Detail/Status (roles) or Check/Value/Status (posture) properties.

        .PARAMETER Mode
        Role or Posture.

        .PARAMETER PerRow
        Tiles per row.

        .EXAMPLE
        New-ResponsibilityTileGridHtml -Title 'Readiness and Security' -IconKey 'Shield' -Items $Posture -Mode Posture -PerRow 4
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the section title.')]
        [string]$Title,

        [Parameter(Mandatory, HelpMessage = 'Specify the embedded section icon key.')]
        [string]$IconKey,

        [Parameter()]
        [object[]]$Items,

        [Parameter(Mandatory, HelpMessage = 'Specify Role or Posture.')]
        [ValidateSet('Role','Posture')]
        [string]$Mode,

        [Parameter()]
        [ValidateRange(1,6)]
        [int]$PerRow = 3
    )

    $List = @($Items | Where-Object { $null -ne $_ })
    If ($List.Count -eq 0) {
        Return ''
    }

    ### Tiles are cells of one table row so every tile in a row shares the tallest tile's height.
    ### Narrow spacer cells and spacer rows provide the gutters (Outlook ignores border-spacing).
    $Gutter  = 8
    $Width   = [math]::Floor((100 - $PerRow) / $PerRow)
    $Columns = ($PerRow * 2) - 1
    $Builder = New-Object -TypeName System.Text.StringBuilder
    $null    = $Builder.Append('<table class="resp-grid" width="100%" cellpadding="0" cellspacing="0" border="0" role="presentation">')

    For ($I = 0; $I -lt $List.Count; $I += $PerRow) {
        $null = $Builder.AppendFormat('<tr class="resp-gap"><td colspan="{0}" height="{1}" style="height:{1}px;font-size:0;line-height:0;">&nbsp;</td></tr><tr>',$Columns,$Gutter)

        For ($J = 0; $J -lt $PerRow; $J++) {
            If ($J -gt 0) {
                $null = $Builder.AppendFormat('<td class="resp-gutter" width="{0}" style="width:{0}px;font-size:0;line-height:0;">&nbsp;</td>',$Gutter)
            }

            If ($I + $J -ge $List.Count) {
                $null = $Builder.AppendFormat('<td class="resp-empty" width="{0}%">&nbsp;</td>',$Width)
                Continue
            }

            $Item   = $List[$I + $J]
            $Status = [string]$Item.Status

            If ($Mode -eq 'Role') {
                $Accent = If ($Status -in 'OK','') {
                    Get-ResponsibilityStatusColor -Status 'Role'
                } Else {
                    Get-ResponsibilityStatusColor -Status $Status
                }
                $Inner  = '<div class="resp-role">{0}</div><div class="resp-detail">{1}</div>' -f (ConvertTo-ResponsibilityHtmlText -Value $Item.Role),(ConvertTo-ResponsibilityHtmlText -Value $Item.Detail -MaxLength 140)
            } Else {
                $Accent = Get-ResponsibilityStatusColor -Status $Status
                $Value  = If ($Status -eq 'Neutral') { '#344054' } Else { $Accent }
                $Inner  = '<div class="resp-check">{0}</div><div class="resp-value" style="color:{1};">{2}</div>' -f (ConvertTo-ResponsibilityHtmlText -Value $Item.Check),$Value,(ConvertTo-ResponsibilityHtmlText -Value $Item.Value -MaxLength 90)
            }

            $null = $Builder.AppendFormat(
                '<td class="resp-tile" width="{0}%" valign="top" style="background:#f7f9fc;border:1px solid #dbe3ec;border-left:4px solid {1};padding:10px 12px;">{2}</td>',
                $Width,$Accent,$Inner
            )
        }

        $null = $Builder.Append('</tr>')
    }

    $null    = $Builder.Append('</table>')
    $Heading = New-HardwareInventorySectionTitle -Title $Title -IconKey $IconKey

    Return '<div class="section">{0}{1}</div>' -f $Heading,$Builder.ToString()
}

Function New-ResponsibilityHtml {
    <#
        .SYNOPSIS
        Builds the System Responsibility parts of the HTML report.

        .DESCRIPTION
        Returns an object with:
          Overview    : the roles and readiness tile grids, placed directly under the computer
                        and operating system section.
          Sections    : the detailed role, service, task, share, software and event tables,
                        appended after the hardware sections.
          PrimaryRole : a short label for the report's summary bar.

        Lists that can be long are capped in the email; the JSON report always holds everything.

        .PARAMETER Responsibility
        Object returned by Get-SystemResponsibilityInventory.

        .EXAMPLE
        $ResponsibilityHtml = New-ResponsibilityHtml -Responsibility $Inventory.Responsibility
        $ResponsibilityHtml.Overview
    #>
    [CmdletBinding()]
    Param (
        [Parameter()]
        [AllowNull()]
        [object]$Responsibility
    )

    #region Preparation
    $Empty = [pscustomobject]@{
        Overview    = ''
        Sections    = @()
        PrimaryRole = $null
    }

    If (-not $Responsibility) {
        Return $Empty
    }

    $R = $Responsibility
    $P = {
        Param ($Object,[string]$Name)

        If ($null -eq $Object) {
            Return $null
        }

        $Property = $Object.PSObject.Properties[$Name]
        If ($Property) {
            Return $Property.Value
        }

        Return $null
    }

    #region Overview
    $Roles     = @(& $P $R 'Roles')
    $Roles     = @($Roles | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Role'] })

    $Posture   = @(& $P $R 'Posture')
    $Posture   = @($Posture | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Check'] })

    $Overview  = New-ResponsibilityTileGridHtml -Title 'System Responsibilities' -IconKey 'Roles' -Items $Roles -Mode Role -PerRow 3
    $Overview += New-ResponsibilityTileGridHtml -Title 'Readiness and Security' -IconKey 'Shield' -Items $Posture -Mode Posture -PerRow 4

    $Primary = $null
    If ($Roles.Count) {
        $Primary = [string]$Roles[0].Role
        If ($Roles.Count -gt 1) {
            $Primary = '{0} +{1}' -f $Primary,($Roles.Count - 1)
        }
    }
    #endregion Overview

    $Sections = New-Object -TypeName 'System.Collections.Generic.List[string]'

    ### Worker scriptblock
    $Add      = {
        Param ([string]$Html)
        If (-not [string]::IsNullOrWhiteSpace($Html)) {
            $Sections.Add($Html)
        }
    }
    #endregion Preparation

    #region Roles and Features
    $Features = @(& $P $R 'WindowsFeatures')
    $Features = @($Features | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Name'] })
    If ($Features.Count) {
        $RoleRows    = @($Features | Where-Object { $_.FeatureType -in 'Role','Role Service' })
        $TopLevel    = @($Features | Where-Object { $_.FeatureType -eq 'Feature' -and $_.Depth -le 1 } | ForEach-Object { $_.DisplayName })
        $FeatureNote = If ($TopLevel.Count) { 'Installed features: {0}.' -f ($TopLevel -join ', ') } Else { $null }

        $Columns     = [ordered]@{
            'Role or role service' = {
                Param ($Row)
                If ($Row.FeatureType -eq 'Role Service') {
                    '- ' + $Row.DisplayName
                } Else {
                    $Row.DisplayName
                }
            }
            'Type'                 = 'FeatureType'
            'Feature name'         = 'Name'
        }

        If ($RoleRows.Count) {
            & $Add (New-ResponsibilityTableHtml -Title 'Installed Server Roles' -IconKey 'Roles' -Rows $RoleRows -Columns $Columns -MaxCellLength 0 -Note $FeatureNote)
        } ElseIf ($FeatureNote) {
            & $Add (New-ResponsibilityKeyValueHtml -Title 'Installed Server Features' -IconKey 'Roles' -Pairs ([ordered]@{ 'Features' = ($TopLevel -join ', ') }))
        }
    }
    #endregion Roles and Features

    #region Active Directory
    $AD = & $P $R 'ActiveDirectory'
    If ($AD) {
        & $Add (
            New-ResponsibilityKeyValueHtml -Title 'Domain Controller' -IconKey 'Roles' -Pairs (
                [ordered]@{
                    'Domain'          = $AD.Domain
                    'Forest'          = $AD.Forest
                    'Site'            = $AD.Site
                    'Global catalog'  = $AD.IsGlobalCatalog
                    'Read-only'       = $AD.IsReadOnly
                    'FSMO roles'      = $(If (@($AD.FSMORoles).Count) { @($AD.FSMORoles) } Else { 'None' })
                }
            )
        )

        $Replication = @(
            & $P $AD 'ReplicationPartners' | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Partner'] } | ForEach-Object {
                $Failures = [int](& $P $_ 'ConsecutiveReplicationFailures')
                $Result   = & $P $_ 'LastReplicationResult'
                [pscustomobject]@{
                    Partner        = $_.Partner
                    Partition      = & $P $_ 'Partition'
                    LastSuccess    = & $P $_ 'LastReplicationSuccess'
                    Result         = If ([int]$Result -eq 0) { 'OK' } Else { 'Error {0}' -f $Result }
                    ResultStatus   = If ([int]$Result -eq 0) { 'OK' } Else { 'Critical' }
                    Failures       = $Failures
                    FailuresStatus = If ($Failures -gt 0) { 'Warning' } Else { 'OK' }
                }
            }
        )

        & $Add (
            New-ResponsibilityTableHtml -Title 'AD Replication Partners' -IconKey 'Network' -Rows $Replication -Columns (
                [ordered]@{
                    'Partner'             = 'Partner'
                    'Partition'           = 'Partition'
                    'Last success'        = 'LastSuccess'
                    'Last result'         = 'Result'
                    'Consecutive failures'= 'Failures'
                }
            ) -StatusColumns 'Last result','Consecutive failures' -NoWrapColumns 'Last success' -MaxCellLength 0
        )
    }
    #endregion Active Directory

    #region DNS and DHCP
    $DNS  = & $P $R 'DNS'
    If ($DNS) {
        $Forwarders = @($DNS.Forwarders | Where-Object { $_ })
        & $Add (
            New-ResponsibilityTableHtml -Title 'DNS Zones' -IconKey 'Web' -Rows @($DNS.Zones) -Columns (
                [ordered]@{
                    'Zone'           = 'ZoneName'
                    'Type'           = 'ZoneType'
                    'AD integrated'  = 'IsDsIntegrated'
                    'Reverse lookup' = 'IsReverseLookupZone'
                    'Dynamic update' = 'DynamicUpdate'
                    'Records'        = 'Records'
                }
            ) -MaxRows 40 -Note $(
                If ($Forwarders.Count) {
                    'Forwarders: {0}.' -f ($Forwarders -join ', ')
                } Else {
                    $null
                }
            )
        )
    }

    $DHCP = @(& $P $R 'DHCP')
    $DHCP = @($DHCP | Where-Object { $null -ne $_ -and $_.PSObject.Properties['ScopeId'] })
    If ($DHCP.Count) {
        $DHCPRows = @(
            $DHCP | ForEach-Object {
                $Use   = & $P $_ 'PercentInUse'
                $InUse = & $P $_ 'InUse'
                $Free  = & $P $_ 'Free'
                $Start = & $P $_ 'StartRange'
                $End   = & $P $_ 'EndRange'

                [pscustomobject]@{
                    Scope       = $_.ScopeId
                    Name        = & $P $_ 'Name'
                    State       = & $P $_ 'State'
                    Range       = If ($Start -or $End) { '{0} - {1}' -f $Start,$End } Else { $null }
                    Mask        = & $P $_ 'SubnetMask'
                    Description = & $P $_ 'Description'
                    InUse       = If ($null -ne $Use) { '{0}% ({1} of {2})' -f $Use,$InUse,([int]$InUse + [int]$Free) } Else { $null }
                    InUseStatus = If ($null -eq $Use) { 'Neutral' } ElseIf ($Use -ge 90) { 'Critical' } ElseIf ($Use -ge 75) { 'Warning' } Else { 'OK' }
                }
            }
        )

        & $Add (
            New-ResponsibilityTableHtml -Title 'DHCP Scopes' -IconKey 'Network' -Rows $DHCPRows -Columns (
                [ordered]@{
                    'Scope'       = 'Scope'
                    'Name'        = 'Name'
                    'State'       = 'State'
                    'Range'       = 'Range'
                    'Mask'        = 'Mask'
                    'Description' = 'Description'
                    'In use'      = 'InUse'
                }
            ) -StatusColumns 'State','In use'
        )
    }
    #endregion DNS and DHCP

    #region Hyper-V and Clustering
    $HyperV  = & $P $R 'HyperV'
    If ($HyperV -and @($HyperV.VMs).Count) {
        $HostNote = $null
        If ($HyperV.Host) {
            $HostNote = 'Host capacity: {0} logical processors, {1} GB memory. Default VM path: {2}.' -f $HyperV.Host.LogicalProcessorCount,$HyperV.Host.MemoryCapacityGB,$HyperV.Host.VirtualMachinePath
        }

        & $Add (
            New-ResponsibilityTableHtml -Title 'Hyper-V Virtual Machines' -IconKey 'VM' -Rows @($HyperV.VMs) -Columns (
                [ordered]@{
                    'VM'             = 'Name'
                    'State'          = 'State'
                    'Gen'            = 'Generation'
                    'Version'        = 'Version'
                    'vCPU'           = 'ProcessorCount'
                    'Startup GB'     = 'MemoryStartupGB'
                    'Assigned GB'    = {
                        Param ($Row)
                        If ($Row.State -eq 'Running') {
                            $Row.MemoryAssignedGB
                        } Else {
                            $null
                        }
                    }
                    'Dynamic memory' = 'DynamicMemory'
                    'Uptime'         = 'Uptime'
                    'Auto start'     = 'AutomaticStartAction'
                    'Checkpoints'    = {
                        Param ($Row)
                        If ($Row.Checkpoints -gt 0) {
                            $Row.Checkpoints
                        } Else {
                            $null
                        }
                    }
                    'Replication'    = {
                        Param ($Row)
                        If ($Row.ReplicationState -and $Row.ReplicationState -ne 'Disabled') {
                            $Row.ReplicationState
                        } Else {
                            $null
                        }
                    }
                }
            ) -StatusColumns 'State' -Note $HostNote
        )
    }

    $Cluster = & $P $R 'Clustering'
    If ($Cluster -and $Cluster.Cluster) {
        $ClusterRows = @(
            @(
                & $P $Cluster 'Nodes' | Where-Object {
                    $null -ne $_ -and 
                    $_.PSObject.Properties['Name']
                } | ForEach-Object {
                    $Weight = & $P $_ 'NodeWeight'

                    [pscustomobject]@{
                        Kind   = 'Node'
                        Name   = $_.Name
                        State  = & $P $_ 'State'
                        Owner  = $null
                        Detail = If ($null -ne $Weight) { 'Vote weight {0}' -f $Weight } Else { $null }
                    }
                }
            ) + @(
                & $P $Cluster 'Roles' | Where-Object {
                    $null -ne $_ -and 
                    $_.PSObject.Properties['Name']
                } | ForEach-Object {
                    [pscustomobject]@{
                        Kind   = 'Role'
                        Name   = $_.Name
                        State  = & $P $_ 'State'
                        Owner  = & $P $_ 'OwnerNode'
                        Detail = & $P $_ 'GroupType'
                    }
                }
            ) | Where-Object { $_ }
        )

        & $Add (
            New-ResponsibilityTableHtml -Title (
                'Failover Cluster - {0}' -f $Cluster.Cluster.Name
            ) -IconKey 'Server' -Rows $ClusterRows -Columns (
                [ordered]@{
                    'Item'   = 'Kind'
                    'Name'   = 'Name'
                    'State'  = 'State'
                    'Owner'  = 'Owner'
                    'Detail' = 'Detail'
                }
            ) -StatusColumns 'State'
        )
    }
    #endregion Hyper-V and Clustering

    #region IIS, CA, SQL
    $IIS = & $P $R 'IIS'
    If ($IIS) {
        $PoolNote = If (@($IIS.AppPools).Count) {
            'Application pools: {0}. Read from applicationHost.config.' -f (@($IIS.AppPools | ForEach-Object { '{0} ({1}, {2})' -f $_.Name,$_.ManagedRuntimeVersion,$_.ManagedPipelineMode }) -join ', ')
        } Else {
            'Read from applicationHost.config.'
        }

        & $Add (
            New-ResponsibilityTableHtml -Title 'IIS Websites' -IconKey 'Web' -Rows @($IIS.Sites) -Columns (
                [ordered]@{
                    'Site'             = 'Name'
                    'ID'               = 'Id'
                    'Auto start'       = 'AutoStart'
                    'Bindings'         = 'Bindings'
                    'Physical path'    = 'PhysicalPath'
                    'Application pool' = 'ApplicationPool'
                }
            ) -MaxCellLength 220 -Note $PoolNote
        )
    }

    $CA  = & $P $R 'CertificateAuthority'
    If ($CA) {
        & $Add (
            New-ResponsibilityKeyValueHtml -Title 'Certificate Authority' -IconKey 'Shield' -Pairs (
                [ordered]@{
                    'CA name' = $CA.Name
                    'CA type' = $CA.Type
                    'Service' = $CA.Service
                }
            )
        )
    }

    $SQL = @(& $P $R 'SQLServer')
    $SQL = @($SQL | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Instance'] })
    If ($SQL.Count) {
        $SQL = @(
            $SQL | ForEach-Object {
                [pscustomobject]@{
                    Instance     = $_.Instance
                    Service      = $_.Service
                    Status       = $_.Status
                    StatusStatus = If ($_.Status -eq 'Running') { 'OK' } ElseIf ($_.StartType -eq 'Automatic') { 'Warning' } Else { 'Neutral' }
                    StartType    = $_.StartType
                }
            }
        )

        & $Add (
            New-ResponsibilityTableHtml -Title 'SQL Server Instances' -IconKey 'Services' -Rows $SQL -Columns (
                [ordered]@{
                    'Instance'   = 'Instance'
                    'Service'    = 'Service'
                    'Status'     = 'Status'
                    'Start type' = 'StartType'
                }
            ) -StatusColumns 'Status'
        )
    }
    #endregion IIS, CA, SQL

    #region Shares, Printers, Administrators
    $Shares = @(& $P $R 'FileShares' | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Name'] -and -not (& $P $_ 'IsSystem') })
    If ($Shares.Count) {
        $ShareRows = @(
            $Shares | ForEach-Object {
                [pscustomobject]@{
                    Name        = $_.Name
                    Path        = $_.Path
                    Description = $_.Description
                    Access      = If (@($_.ShareACL).Count) {
                        (
                            @(
                                $_.ShareACL | ForEach-Object {
                                    '{0}: {1}{2}' -f $_.AccountName,$_.AccessRight,$(If ($_.AccessControlType -eq 'Deny') { ' (deny)' } Else { '' })
                                }
                            ) -join '; '
                        )
                    } Else {
                        $null
                    }
                }
            }
        )

        & $Add (
            New-ResponsibilityTableHtml -Title 'File Shares' -IconKey 'Share' -Rows $ShareRows -Columns (
                [ordered]@{
                    'Share'        = 'Name'
                    'Path'         = 'Path'
                    'Description'  = 'Description'
                    'Share access' = 'Access'
                }
            ) -MaxRows 50 -MaxCellLength 240
        )
    }

    $SharedPrinters = @(& $P $R 'SharedPrinters')
    $SharedPrinters = @($SharedPrinters | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Name'] })
    If ($SharedPrinters.Count) {
        & $Add (
            New-ResponsibilityTableHtml -Title 'Shared Printers' -IconKey 'Printer' -Rows $SharedPrinters -Columns (
                [ordered]@{
                    'Printer'  = 'Name'
                    'Share'    = 'ShareName'
                    'Driver'   = 'DriverName'
                    'Port'     = 'PortName'
                    'Location' = 'Location'
                }
            ) -MaxRows 50
        )
    }

    $Admins = @(& $P $R 'LocalAdministrators')
    $Admins = @($Admins | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Name'] })
    If ($Admins.Count) {
        & $Add (
            New-ResponsibilityTableHtml -Title 'Local Administrators' -IconKey 'Users' -Rows $Admins -Columns (
                [ordered]@{
                    'Member' = 'Name'
                    'Type'   = 'ObjectClass'
                    'Source' = 'Source'
                }
            )
        )
    }
    #endregion Shares, Printers, Administrators

    #region Third-Party Services and Tasks
    $Services = @(& $P $R 'Services' | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Name'] -and -not (& $P $_ 'IsMicrosoft') })
    If ($Services.Count) {
        $ServiceRows = @(
            $Services | ForEach-Object {
                $State      = [string]$_.State
                $Unexpected = [bool](& $P $_ 'StoppedUnexpectedly')

                [pscustomobject]@{
                    DisplayName = $_.DisplayName
                    Name        = $_.Name
                    State       = If ($Unexpected) { '{0} (exit code {1})' -f $State,(& $P $_ 'ExitCode') } Else { $State }
                    StateStatus = If ($State -eq 'Running') { 'OK' } ElseIf ($Unexpected) { 'Warning' } Else { 'Neutral' }
                    StartMode   = $_.StartMode
                    RunAs       = $_.StartName
                    Vendor      = $_.Vendor
                    Order       = If ($Unexpected) { 0 } ElseIf ($_.StartMode -eq 'Auto') { 1 } Else { 2 }
                }
            } | Sort-Object -Property Order,DisplayName
        )

        & $Add (
            New-ResponsibilityTableHtml -Title 'Third-Party Services' -IconKey 'Services' -Rows $ServiceRows -Columns (
                [ordered]@{
                    'Service'    = 'DisplayName'
                    'Name'       = 'Name'
                    'State'      = 'State'
                    'Start mode' = 'StartMode'
                    'Run as'     = 'RunAs'
                    'Vendor'     = 'Vendor'
                }
            ) -StatusColumns 'State' -MaxRows 60 -Note 'Automatic services that stopped with an error are listed first. Services that exited cleanly or start on a trigger are not flagged.'
        )
    }

    $Tasks = @(& $P $R 'ScheduledTasks' | Where-Object { $null -ne $_ -and $_.PSObject.Properties['TaskName'] -and -not (& $P $_ 'IsMicrosoft') })
    If ($Tasks.Count) {
        $TaskRows = @(
            $Tasks | ForEach-Object {
                [pscustomobject]@{
                    TaskName    = $_.TaskName
                    TaskPath    = $_.TaskPath
                    State       = $_.State
                    StateStatus = If ($_.State -eq 'Disabled') { 'Neutral' } Else { Get-ResponsibilityCellStatus -Value $_.State }
                    RunAs       = $_.RunAs
                    Action      = (@($_.Execute,$_.Arguments) | Where-Object { $_ }) -join ' '
                    LastRun     = $_.LastRunTime
                    LastResult  = $_.LastTaskResult
                    NextRun     = $_.NextRunTime
                }
            } | Sort-Object -Property TaskPath,TaskName
        )

        & $Add (
            New-ResponsibilityTableHtml -Title 'Third-Party Scheduled Tasks' -IconKey 'Tasks' -Rows $TaskRows -Columns (
                [ordered]@{
                    'Task'        = 'TaskName'
                    'Folder'      = 'TaskPath'
                    'State'       = 'State'
                    'Run as'      = 'RunAs'
                    'Action'      = 'Action'
                    'Last run'    = 'LastRun'
                    'Last result' = 'LastResult'
                    'Next run'    = 'NextRun'
                }
            ) -StatusColumns 'State','Last result' -NoWrapColumns 'Last run','Last result','Next run' -MaxRows 40 -MaxCellLength 140
        )
    }
    #endregion Third-Party Services and Tasks

    #region Events and Updates
    $Logs = & $P $R 'EventLogs'
    If ($Logs) {
        $Events = @(
            ForEach ($LogName in 'System','Application') {
                ForEach ($LogEvent in @(& $P $Logs $LogName)) {
                    If ($LogEvent) {
                        [pscustomobject]@{
                            Log      = $LogName
                            Source   = $LogEvent.ProviderName
                            Id       = $LogEvent.Id
                            Level    = $LogEvent.LevelDisplayName
                            Time     = $LogEvent.TimeCreated
                            Message  = (([string]$LogEvent.Message) -split "`r?`n")[0]
                        }
                    }
                }
            }
        )

        ### A log that returned exactly the read limit was truncated; its counts are lower bounds.
        $ReadLimit  = & $P $Logs 'ReadLimit'
        $CappedLogs = @(
            ForEach ($LogName in 'System','Application') {
                If ($ReadLimit -and @(& $P $Logs $LogName | Where-Object { $_ }).Count -ge [int]$ReadLimit) {
                    $LogName
                }
            }
        )

        If ($Events.Count) {
            $Grouped = @(
                $Events | Group-Object -Property Log,Source,Id | ForEach-Object {
                    $Latest = $_.Group | Sort-Object -Property Time -Descending | Select-Object -First 1
                    [pscustomobject]@{
                        Log         = $Latest.Log
                        Source      = $Latest.Source
                        Id          = $Latest.Id
                        Level       = $Latest.Level
                        LevelStatus = If ($Latest.Level -match '(?i)Critical') { 'Critical' } Else { 'Warning' }
                        Count       = $_.Count
                        CountText   = If ($CappedLogs -contains $Latest.Log) { '{0}+' -f $_.Count } Else { [string]$_.Count }
                        LastSeen    = $Latest.Time
                        Message     = $Latest.Message
                    }
                } | Sort-Object -Property @{
                    Expression = 'Count'
                    Descending = $true
                }, @{
                    Expression = 'LastSeen'
                    Descending = $true
                }
            )

            & $Add (
                New-ResponsibilityTableHtml -Title 'Recent Critical and Error Events (30 days)' -IconKey 'Events' -Rows $Grouped -Columns (
                    [ordered]@{
                        'Log'       = 'Log'
                        'Source'    = 'Source'
                        'Event ID'  = 'Id'
                        'Level'     = 'Level'
                        'Count'     = 'CountText'
                        'Last seen' = 'LastSeen'
                        'Message'   = 'Message'
                    }
                ) -StatusColumns 'Level' -NoWrapColumns 'Last seen' -MaxRows 15 -MaxCellLength 180 -Note $(
                    If ($CappedLogs.Count) {
                        'Grouped by log, source and event ID. The {0} log reached the {1}-event read limit, so its counts marked + are minimums.' -f ($CappedLogs -join ' and '),$ReadLimit
                    } Else {
                        'Grouped by log, source and event ID.'
                    }
                )
            )
        }
    }

    $HotFixes = @(& $P $R 'HotFixes' | Where-Object { $null -ne $_ -and $_.PSObject.Properties['HotFixID'] })
    If ($HotFixes.Count) {
        & $Add (
            New-ResponsibilityTableHtml -Title 'Most Recent Updates' -IconKey 'Shield' -Rows $HotFixes -Columns (
                [ordered]@{
                    'Update'       = 'HotFixID'
                    'Description'  = 'Description'
                    'Installed on' = {
                        Param ($Row)
                        If ($Row.InstalledOn -is [datetime]) {
                            $Row.InstalledOn.ToString('yyyy-MM-dd')
                        } Else {
                            $Row.InstalledOn
                        }
                    }
                    'Installed by' = 'InstalledBy'
                }
            ) -NoWrapColumns 'Installed on' -MaxRows 10
        )
    }

    $Software = @(
        & $P $R 'InstalledSoftware' | Where-Object {
            $null -ne $_ -and 
            $_.PSObject.Properties['DisplayName'] -and 
            $_.DisplayName -notmatch '^(?i)(Microsoft Visual C\+\+ \d{4}.*Redistributable|Update for |Security Update for |Hotfix for )'
        }
    )

    If ($Software.Count) {
        & $Add (
            New-ResponsibilityTableHtml -Title ('Installed Software ({0})' -f $Software.Count) -IconKey 'Software' -Rows $Software -Columns (
                [ordered]@{
                    'Name'      = 'DisplayName'
                    'Version'   = 'DisplayVersion'
                    'Publisher' = 'Publisher'
                    'Installed' = 'InstallDate'
                }
            ) -MaxRows 150 -Note 'Visual C++ redistributables and individual updates are omitted here.'
        )
    }
    #endregion Events and Updates

    #region Collection Gaps
    $Gaps = @(& $P $R 'CollectionErrors' | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Category'] })
    If ($Gaps.Count) {
        & $Add (
            New-ResponsibilityTableHtml -Title 'Collection Gaps' -IconKey 'Events' -Rows $Gaps -Columns (
                [ordered]@{
                    'Category'        = {
                        Param ($Row)
                        [string]$Row.Category -creplace '(?<=[a-z])(?=[A-Z])',' '
                    }
                    'What went wrong' = 'Error'
                }
            ) -MaxCellLength 220 -Note 'These categories could not be read. Running the script elevated resolves most access-related gaps.'
        )
    }
    #endregion Collection Gaps

    Return [pscustomobject]@{
        Overview    = $Overview
        Sections    = @($Sections.ToArray())
        PrimaryRole = $Primary
    }
}
#endregion System Responsibility Presentation
#endregion Presentation Functions

#region Native Subnet Discovery v7
Function Get-NativeSubnetDiscovery {
    <#
        .SYNOPSIS
        Scans IPv4 subnets assigned to the local AD site and correlates MAC and switch ports.

        .DESCRIPTION
        Uses AD Sites and Services site subnets, parallel ICMP/TCP probing, local neighbor
        cache, Hyper-V/LLDP uplinks and optional SNMP bridge forwarding tables.
        Remote switch port lookup uses embedded .NET SNMP v2c and an authorized community.
        A learned uplink or trunk is not necessarily the endpoint's physical access port.

        .PARAMETER HyperVNetwork
        Object returned by Get-HyperVNetworkInventory. Used to attach local host and VM MAC addresses
        and LLDP switch ports to discovered addresses.

        .PARAMETER SiteSubnets
        Records returned by Get-ADSiteSubnetInventory for the local AD site.

        .PARAMETER SNMPCommunity
        Optional SNMP v2c read-only community. Omit to skip switch-side FDB queries.

        .PARAMETER Switches
        Optional additional switch DNS names or IP addresses to query via SNMP.

        .PARAMETER Throttle
        Maximum number of addresses probed in parallel.

        .PARAMETER PingTimeout
        ICMP echo timeout per address, in milliseconds.

        .PARAMETER PortTimeout
        Time allowed for TCP connection attempts per address, in milliseconds.

        .PARAMETER MaxSeconds
        Overall time budget for the scan. When it is reached, no new addresses are started and the
        summary marks the affected subnets as timed out.

        .PARAMETER MaxAddresses
        Maximum total usable addresses across all site subnets (default 65536).

        .EXAMPLE
        Get-NativeSubnetDiscovery -SiteSubnets @(Get-ADSiteSubnetInventory | Where-Object IsLegacy) -Throttle 100 -MaxSeconds 300

        .NOTES
        Requires Windows PowerShell 5.1. Scans all provided site CIDRs subject to
        MaxAddresses and MaxSeconds. No MAC or switch port is inferred across routers.
    #>
    [CmdletBinding()]
    Param (
        [object]$HyperVNetwork,

        [object[]]$SiteSubnets,

        [int]$Throttle = 100,

        [int]$PingTimeout = 2000,

        [int]$PortTimeout = 1000,

        [int]$MaxSeconds = 300,

        [int]$MaxAddresses = 1000000,

        [string]$SNMPCommunity,

        [string[]]$Switches = @()
    )

    #region Runtime Variables
    $Ports      = @(21,22,23,25,53,80,81,88,111,135,139,161,389,443,445,515,548,623,636,902,989,990,1433,1521,2000,2001,2049,2375,2376,3000,3260,3268)
    $Ports     += @(3269,3306,3389,4786,5000,5001,5060,5432,5900,5985,5986,7001,7443,8000,8008,8080,8081,8443,8880,8888,9000,9090,9100,9443,9440,10000)

    $Interfaces = @(
        Get-NetIPAddress -AddressFamily IPv4 @script:EA1 | Where-Object {
            $_.IPAddress -notmatch '^(127|169\.254)\.' -and 
            $_.AddressState -eq 'Preferred'
        }
    )

    <#
        LESSON 1: Was a parameter supplied, or just empty?
        $PSBoundParameters holds only the parameters the caller actually passed. ContainsKey
        tells "not supplied at all" apart from "supplied, but empty". Testing
        If (-not $SiteSubnets.Count) cannot: both cases look the same. This was a real bug in
        an earlier version. An empty list of Legacy subnets was treated as "not supplied", and
        the function went on to scan every subnet in the AD site.
    #>
    If (-not $PSBoundParameters.ContainsKey('SiteSubnets')) {
        $SiteSubnets = @(Get-ADSiteSubnetInventory @script:EA1)
    }

    If (-not @($SiteSubnets).Count) {
        Throw 'No site subnets were supplied to scan.'
    }

    $Site = @($SiteSubnets | Where-Object {$_.Site} | Select-Object -ExpandProperty Site -Unique)
    If ($Site.Count -ne 1) {
        Throw ('Expected one AD site, found: {0}' -f ($Site -join ', '))
    }

    $Candidates = New-Object -TypeName System.Collections.ArrayList
    #endregion Runtime Variables

    #region Subnet Selection
    $Seen = @{}
    ForEach ($S in $SiteSubnets) {
        $CIDR = [string]$S.Subnet
        If ($CIDR -notmatch '^((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})$') {
            Write-Warning -Message ('Skipping non-IPv4 subnet: {0}' -f $CIDR)
            Continue
        }

        <#
            LESSON 2: The $Matches automatic variable
            When -match or -notmatch tests a single string and the pattern matches, PowerShell
            fills $Matches: $Matches[0] is the whole match, and $Matches[1], [2], ... are the
            capture groups in ( ). Here group 1 is the address and group 2 is the prefix length.
            A failed match does NOT clear $Matches; it keeps the previous result. That is why the
            code checks -notmatch and Continues first: $Matches is read only after a successful
            match.
        #>
        $Prefix = [int]$Matches[2]
        If ($Prefix -lt 1 -or $Prefix -gt 32) {
            Write-Warning -Message ('Skipping invalid prefix: {0}' -f $CIDR)
            Continue
        }

        Try {
            $Bytes = [ipaddress]::Parse($Matches[1]).GetAddressBytes()
            If ($Bytes.Count -ne 4) {
                Continue
            }

            <#
                LESSON 3: IPv4 addresses are 32-bit numbers
                GetAddressBytes() returns the four octets in network order (10.6.1.0 gives 10, 6,
                1, 0). BitConverter reads the first byte as the least significant one on Windows,
                so the bytes are reversed before converting them to a [uint32].
                The subnet mask is all 32 bits set, shifted left by (32 - prefix): a /24 leaves
                24 ones followed by 8 zeros. The shift happens in 64 bits so nothing overflows,
                and -band 4294967295 keeps only the low 32 bits.
                Address -band Mask gives the network address: the host bits are cleared. That
                one operation answers "which subnet is this address in?" throughout the function.
            #>
            [array]::Reverse($Bytes)

            $N        = [BitConverter]::ToUInt32($Bytes,0)
            $Mask     = [uint32]([uint64]4294967295 -shl (32-$Prefix) -band [uint64]4294967295)
            $Network  = [uint32]($N -band $Mask)
            $NetBytes = [BitConverter]::GetBytes($Network)
            [array]::Reverse($NetBytes)

            <#
                LESSON 4: Passing an array as ONE argument
                New-Object -ArgumentList expects an array of constructor arguments. Passing the
                byte array directly would spread its four bytes into four separate arguments, and
                no IPAddress constructor takes four bytes. The unary comma in (,$NetBytes) wraps
                the array inside a one-element array, so the constructor receives a single byte[].
            #>
            $CIDR     = '{0}/{1}' -f (New-Object -TypeName Net.IPAddress -ArgumentList (,$NetBytes)).ToString(),$Prefix
            If ($Seen.ContainsKey($CIDR)) {
                Continue
            }

            $Seen[$CIDR] = $true

            $Total    = If ($Prefix -eq 32) { 1 } ElseIf ($Prefix -eq 31) { 2 } Else { [long]([math]::Pow(2,32-$Prefix)-2) }

            $Local    = @(
                $Interfaces | Where-Object {
                    $B = [ipaddress]::Parse($_.IPAddress).GetAddressBytes()
                    [array]::Reverse($B)
                    (([BitConverter]::ToUInt32($B,0) -band $Mask) -eq $Network)
                } | Select-Object -First 1
            )

            <#
                LESSON 5: Methods that return values pollute function output
                ArrayList.Add returns the index of the item it added. In PowerShell, any value
                that is not captured becomes part of the function's output, so a bare
                $Candidates.Add($x) would mix numbers into the results. $null = discards the
                value. [void] does the same, and both are much faster than | Out-Null in Windows
                PowerShell 5.1. System.Collections.Generic.List[object] avoids the issue: its
                Add method returns nothing.
            #>
            $null = $Candidates.Add(
                [pscustomobject]@{
                    Subnet      = $CIDR
                    Network     = $Network
                    Prefix      = $Prefix
                    Mask        = $Mask
                    Total       = $Total
                    Interface   = If ($Local.Count) { $Local[0].InterfaceAlias } Else { 'Routed' }
                    Local       = [bool]$Local.Count
                    Description = $S.Description
                }
            )
        } Catch {
            Write-Warning -Message ('Skipping invalid site subnet {0}: {1}' -f $CIDR,$_.Exception.Message)
        }
    }

    If (-not $Candidates.Count) {
        Throw ('No valid IPv4 subnets found for AD site {0}.' -f $Site[0])
    }
    #endregion Subnet Selection

    #region Skip subnets that sit inside a larger candidate (for example 10.6.1.0/24 inside 10.6.0.0/16).
    <#
        LESSON 6: Is one subnet inside another?
        Subnet C is inside subnet P when P has a shorter prefix (it is larger) and C's network
        address, masked with P's mask, equals P's network address. Lesson 4's -band operation is
        reused here. Removing nested subnets prevents scanning the same addresses twice. In
        Irving, 10.6.1.0/24 and 10.6.2.0/23 sit inside 10.6.0.0/16.
    #>
    $Candidates = @(
        ForEach ($C in $Candidates) {
            $Parent = @(
                $Candidates | Where-Object {
                    $_.Prefix -lt $C.Prefix -and 
                    ([uint32]($C.Network -band $_.Mask)) -eq $_.Network
                }
            ) | Select-Object -First 1

            If ($Parent) {
                Write-Verbose -Message ('Skipping {0}; it is inside {1}.' -f $C.Subnet,$Parent.Subnet)
            } Else {
                $C
            }
        }
    )
    #endregion

    #region Subnet Discovery & Iteration
    $Addresses = [long]0
    ForEach ($C in $Candidates) {
        $Addresses += $C.Total
    }

    If ($Addresses -gt $MaxAddresses) {
        Throw ('Site {0} has {1} scan addresses, exceeding MaxAddresses {2}. Increase -MaxAddresses explicitly if authorized.' -f $Site[0],$Addresses,$MaxAddresses)
    }

    <#
        LESSON 7: Sorting on more than one key, each in its own direction
        -Property takes a list. A plain name sorts ascending; a hashtable with Expression and
        Descending sets the direction for that key alone. Here Local is sorted descending, so
        $true comes first and directly connected subnets are scanned before routed ones; ties
        are then sorted by Subnet, ascending.
    #>
    $Candidates = @(
        $Candidates | Sort-Object -Property @{
            Expression = 'Local'
            Descending = $true
        }, Subnet
    )

    #region Helper scriptblock
    $Worker     = {
        Param ($IP,$Ports,$PingTimeout,$PortTimeout)

        $PingOK = $false
        $Open   = New-Object -TypeName 'System.Collections.Generic.List[int]'
        $P      = $null

        Try {
            $P      = New-Object -TypeName Net.NetworkInformation.Ping
            $PingOK = ($P.Send($IP,$PingTimeout).Status -eq 'Success')
        } Catch {
            Write-Verbose -Message ('ICMP probe failed for {0}: {1}' -f $IP,$_.Exception.Message)
        } Finally {
            If ($P) {
                $P.Dispose()
            }
        }

        <#
            LESSON 8: Many TCP connections at once
            Testing 58 ports one after another with a 1-second timeout could take 58 seconds per
            address. ConnectAsync starts each connection attempt and returns immediately with a
            Task object. The loop below checks every Task's IsCompleted until all have finished
            or PortTimeout has passed, so one address takes about PortTimeout in total, however
            many ports are tested. A port is open when its Task ran to completion and the client
            reports Connected. Disposing an unfinished client abandons that attempt.
        #>
        $Pending = New-Object -TypeName System.Collections.ArrayList

        ForEach ($Port in $Ports) {
            $Client = New-Object -TypeName Net.Sockets.TcpClient
            Try {
                $Task = $Client.ConnectAsync($IP,[int]$Port)
                $null = $Pending.Add(
                    [pscustomobject]@{
                        Port   = $Port
                        Client = $Client
                        Task   = $Task
                    }
                )
            } Catch {
                Write-Verbose -Message ('TCP probe initialization failed for {0}:{1}: {2}' -f $IP,$Port,$_.Exception.Message)
                $Client.Dispose()
            }
        }

        $Watch = [Diagnostics.Stopwatch]::StartNew()
        While ($Pending.Count -and $Watch.ElapsedMilliseconds -lt $PortTimeout){
            For ($J=$Pending.Count-1; $J -ge 0; $J--) {
                $Item = $Pending[$J]
                If ($Item.Task.IsCompleted) {
                    If (
                        $Item.Task.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion -and 
                        $Item.Client.Connected
                    ) {
                        $Open.Add([int]$Item.Port)
                    }
                    $Item.Client.Dispose()
                    $Pending.RemoveAt($J)
                }
            }

            If ($Pending.Count) {
                [Threading.Thread]::Sleep(10)
            }
        }

        ForEach ($Item in $Pending) {
            $Item.Client.Dispose()
        }

        If ($PingOK -or $Open.Count) {
            [pscustomobject]@{
                IPAddress = $IP
                Ping      = $PingOK
                OpenPorts = (($Open | Sort-Object) -join ',')
                Discovery = If ($PingOK -and $Open.Count) { 'ICMP + TCP' } ElseIf ($PingOK) { 'ICMP' } Else { 'TCP' }
            }
        }
    }
    #endregion Helper scriptblock

    <#
        LESSON 9: Parallel work in Windows PowerShell 5.1 with a runspace pool
        Windows PowerShell 5.1 has no ForEach-Object -Parallel (that arrived in PowerShell 7),
        and Start-Job launches a separate powershell.exe process for every job, which is far too
        slow for thousands of addresses. A runspace pool keeps up to $Throttle PowerShell
        instances on threads inside THIS process.
        The pattern:
          1. CreateRunspacePool(1,$Throttle), then Open().
          2. For each work item: [PowerShell]::Create(), attach it to the pool, add the script
             and its arguments, then BeginInvoke(). BeginInvoke returns at once with a handle.
          3. Check each handle's IsCompleted. EndInvoke(handle) returns the output and re-raises
             any error the worker hit.
          4. Dispose each PowerShell instance, then Close() and Dispose() the pool.
        The outer While loop keeps at most $Throttle workers active: it starts new ones only as
        running ones finish.
    #>
    $Pool = [RunspaceFactory]::CreateRunspacePool(1,$Throttle)
    $Pool.Open()

    $Active    = New-Object -TypeName System.Collections.ArrayList
    $Found     = New-Object -TypeName System.Collections.ArrayList
    $Summaries = New-Object -TypeName System.Collections.ArrayList
    $Completed = 0
    $Started   = 0
    $TimedOut  = $false
    $Clock     = [Diagnostics.Stopwatch]::StartNew()

    Try {
        ForEach ($C in $Candidates) {
            $SubnetStart     = $Clock.Elapsed
            $SubnetCompleted = 0
            $SubnetFound     = 0
            $Next            = [uint64]$C.Network + $(If ($C.Prefix -ge 31) { 0 } Else { 1 })
            $End             = $Next + [uint64]$C.Total - 1

            While ($SubnetCompleted -lt $C.Total) {
                While (
                    $Active.Count -lt $Throttle -and 
                    $Next -le $End -and 
                    $Clock.Elapsed.TotalSeconds -lt $MaxSeconds
                ) {
                    $Bytes = [BitConverter]::GetBytes([uint32]$Next)
                    [array]::Reverse($Bytes)

                    $IP = (New-Object -TypeName Net.IPAddress -ArgumentList (,$Bytes)).ToString()
                    $PS = [PowerShell]::Create()
                    $PS.RunspacePool = $Pool

                    <#
                        LESSON 10: A runspace sees nothing of this script
                        Each runspace has its own variables and functions. $script:EA1, the
                        script's functions and $ErrorActionPreference do not exist inside it.
                        That is why $Worker uses only .NET classes and the values passed in.
                        AddArgument values bind to the worker's Param block in order: $IP,
                        $Ports, $PingTimeout, $PortTimeout.
                        $Worker.ToString() sends the script as TEXT. A scriptblock remembers the
                        runspace it was created in, and invoking it directly elsewhere can route
                        execution back to that original runspace and serialize the work. Text
                        is compiled fresh inside each worker's own runspace.
                    #>
                    $null   = $PS.AddScript($Worker.ToString()).AddArgument($IP).AddArgument($Ports).AddArgument($PingTimeout).AddArgument($PortTimeout)
                    $Handle = $PS.BeginInvoke()
                    $null   = $Active.Add(
                        [pscustomobject]@{
                            PS     = $PS
                            Handle = $Handle
                            Subnet = $C.Subnet
                        }
                    )

                    $Next++
                    $Started++
                }

                <#
                    LESSON 11: Remove items while looping by counting backwards
                    RemoveAt($I) shifts every later item down one place. Looping forwards, the
                    item after a removed one would slide into the current index and be skipped.
                    Counting down from the last index means removals only move items that have
                    already been checked. The $Pending loop in $Worker uses the same technique.
                #>
                For ($I=$Active.Count-1; $I -ge 0; $I--) {
                    $Job = $Active[$I]
                    If ($Job.Handle.IsCompleted) {
                        Try {
                            ForEach ($Result in @($Job.PS.EndInvoke($Job.Handle))) {
                                If ($Result) {
                                    $Result | Add-Member -NotePropertyName Subnet -NotePropertyValue $Job.Subnet
                                    $null = $Found.Add($Result)
                                    $SubnetFound++
                                }
                            }
                        } Catch {
                            Write-Verbose -Message ('Subnet worker failed: {0}' -f $_.Exception.Message)
                        } Finally {
                            <#
                                LESSON 12: Finally always runs
                                A Finally block runs when the Try block succeeds, throws an error, exits with Break,
                                or is cancelled with Ctrl+C. Cleanup belongs here: stopping and disposing workers and
                                closing the pool. Without it, a cancelled scan would leave up to $Throttle threads
                                running in the session. Each cleanup step has its own Try/Catch, so one failure
                                cannot prevent the remaining steps.
                            #>
                            $Job.PS.Dispose()
                            $Active.RemoveAt($I)
                            $Completed++
                            $SubnetCompleted++
                        }
                    }
                }

                Write-Progress -Activity (
                    'Native Subnet Discovery - {0}' -f $Site[0]
                ) -Status (
                    '{0} | {1}/{2} | Found {3} | Overall {4}/{5} | {6:mm\:ss}' -f $C.Subnet,$SubnetCompleted,$C.Total,$SubnetFound,$Completed,$Addresses,$Clock.Elapsed
                ) -PercentComplete (
                    [math]::Min(100,100*$Completed/$Addresses)
                )

                If ($Clock.Elapsed.TotalSeconds -ge $MaxSeconds) {
                    $TimedOut = $true
                    Break
                }

                If ($Active.Count) {
                    [Threading.Thread]::Sleep(50)
                }
            }

            $null = $Summaries.Add(
                [pscustomobject]@{
                    Subnet      = $C.Subnet
                    Interface   = $C.Interface
                    Local       = $C.Local
                    Description = $C.Description
                    Total       = $C.Total
                    Scanned     = $SubnetCompleted
                    Found       = $SubnetFound
                    TimedOut    = ($SubnetCompleted -lt $C.Total)
                    Elapsed     = ($Clock.Elapsed-$SubnetStart).ToString()
                }
            )

            If ($TimedOut) {
                Break
            }
        }
    } Finally {
        Write-Progress -Activity ('Native Subnet Discovery - {0}' -f $Site[0]) -Completed

        ForEach ($Job in $Active) {
            Try {
                $Job.PS.Stop()
            } Catch {
                Write-Verbose -Message ('Unable to stop subnet worker: {0}' -f $_.Exception.Message)
            }

            Try {
                $Job.PS.Dispose()
            } Catch {
                Write-Verbose -Message ('Unable to dispose subnet worker: {0}' -f $_.Exception.Message)
            }
        }

        $Pool.Close()
        $Pool.Dispose()
        $Clock.Stop()
    }
    #endregion Discovery & Iteration

    #region Subnet document/store findings
    $HostByIP = @{}
    $VMByIP   = @{}
    If ($HyperVNetwork) {
        ForEach ($H in @($HyperVNetwork.Records | Where-Object {$_.AdapterType -eq 'Host Physical'})) {
            <#
                LESSON 13: Matching whole IP addresses with lookarounds
                (?<!\d) means "not preceded by a digit" and (?!\d) means "not followed by a
                digit". Both are zero-width: they check the characters around the match without
                consuming any. Without them, the pattern could match 0.25.15.14 inside
                110.25.15.141. [regex]::Matches returns every match in the string, which handles
                adapters with several addresses.
            #>
            ForEach ($M in [regex]::Matches([string]$H.CurrentIPAddress,'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')) {
                $HostByIP[$M.Value] = $H
            }
        }

        ForEach ($G in @($HyperVNetwork.Records | Where-Object {$_.AdapterType -eq 'VM Guest'})) {
            ForEach ($M in [regex]::Matches([string]$G.CurrentIPAddress,'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')) {
                If (-not $VMByIP.ContainsKey($M.Value)) {
                    $VMByIP[$M.Value] = $G
                }
            }
        }

        ForEach ($I in $Interfaces) {
            If (-not $HostByIP.ContainsKey($I.IPAddress)) {
                $H = $HyperVNetwork.Records | Where-Object {
                    $_.AdapterType -eq 'Host Physical' -and 
                    $_.InterfaceIndex -eq $I.InterfaceIndex
                } | Select-Object -First 1

                If ($H) {
                    $HostByIP[$I.IPAddress] = $H
                }
            }
        }
    }

    $Neighbor = @{}
    Try {
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object {
            If (
                $_.LinkLayerAddress -and 
                $_.LinkLayerAddress -notmatch '^(00[:-]00|FF[:-]FF)'
            ) {
                $Neighbor[$_.IPAddress] = $_.LinkLayerAddress
            }
        }
    } Catch {
        Write-Verbose -Message ('Unable to read IPv4 neighbor cache: {0}' -f $_.Exception.Message)
    }

    $Rows = @(
        <#
            LESSON 14: Sorting IP addresses correctly
            Strings sort character by character, so '10.0.0.10' comes before '10.0.0.2'. Casting
            to [version] compares each dot-separated part as a number. An IPv4 address has
            exactly four parts, like a version number, so the trick sorts addresses correctly.
            -Unique then drops duplicates of the sort key.
        #>
        $Found | Sort-Object -Property {[version]$_.IPAddress} -Unique | ForEach-Object {
            $D    = $_
            $Name = $null
            Try {
                $Name = [Net.Dns]::GetHostEntry($D.IPAddress).HostName
            } Catch {
                Write-Verbose -Message ('Reverse DNS failed for {0}: {1}' -f $D.IPAddress,$_.Exception.Message)
            }

            $VM          = $VMByIP[$D.IPAddress]
            $HostAdapter = $HostByIP[$D.IPAddress]
            $MAC         = $Neighbor[$D.IPAddress]
            $MACSource   = If ($MAC) { 'Neighbor Cache' } Else { $null }

            If ($HostAdapter -and $HostAdapter.MACAddress -and $HostAdapter.MACAddress -ne 'N/A') {
                $MAC       = $HostAdapter.MACAddress
                $MACSource = 'Local Host Adapter'
            } ElseIf (-not $MAC -and $VM -and $VM.MACAddress -and $VM.MACAddress -ne 'N/A') {
                $MAC       = $VM.MACAddress
                $MACSource = 'Hyper-V Guest'
            }

            If ($MAC) {
                $MAC = ([string]$MAC).Replace('-',':').ToUpperInvariant()
            }

            $vSwitch = $null
            $Port    = $null
            $Source  = $null
            $VLAN    = $null

            If ($HostAdapter -and $HostAdapter.PhysicalSwitch -and $HostAdapter.PhysicalSwitch -ne 'N/A') {
                $vSwitch = $HostAdapter.PhysicalSwitch
                $Port    = $HostAdapter.PhysicalSwitchPort
                $Source  = $HostAdapter.SwitchDiscovery
                $VLAN    = If ($HostAdapter.PSObject.Properties['LLDPVLAN']) { $HostAdapter.LLDPVLAN } Else { $null }
            } ElseIf ($VM -and $VM.PhysicalSwitch -and $VM.PhysicalSwitch -ne 'N/A') {
                $vSwitch = $VM.PhysicalSwitch
                $Port    = $VM.PhysicalSwitchPort
                $Source  = 'Hyper-V Uplink Mapping (not endpoint port)'
                $VLAN    = If ($VM.PSObject.Properties['LLDPVLAN']) { $VM.LLDPVLAN } Else { $null }
            }

            [pscustomobject][ordered]@{
                Subnet             = $D.Subnet
                IPAddress          = $D.IPAddress
                HostName           = $Name
                MACAddress         = $MAC
                MACSource          = $MACSource
                PhysicalSwitch     = $vSwitch
                PhysicalSwitchPort = $Port
                LLDPVLAN           = $VLAN
                SwitchDiscovery    = $Source
                Ping               = $D.Ping
                Discovery          = $D.Discovery
                OpenPorts          = $D.OpenPorts
            }
        }
    )
    #endregion Subnet document/store findings

    #region - Optional native SNMP v2c forwarding-table discovery (no external executables/modules).
    $FDBStatus = 'Disabled'
    If ($SNMPCommunity) {
        $FDBStatus = 'Attempted'
        <#
            LESSON 15: Load a compiled type only once
            'Name' -as [type] returns the type when it is already loaded and $null when it is
            not, without raising an error. Add-Type cannot redefine a type that is already
            loaded, and .NET cannot unload one until the PowerShell session ends, so running the
            script twice in one console would fail without this check.
        #>
        If (-not ('NativeSnmpWalk' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;
public static class NativeSnmpWalk {
    static byte[] Len(int n) { if(n<128)return new byte[]{(byte)n}; if(n<256)return new byte[]{129,(byte)n};return new byte[]{130,(byte)(n>>8),(byte)n}; }
    static byte[] T(int tag,byte[] b) { var r=new List<byte>();r.Add((byte)tag);r.AddRange(Len(b.Length));r.AddRange(b);return r.ToArray(); }
    static byte[] Join(params byte[][] a) { var r=new List<byte>();foreach(var b in a)r.AddRange(b);return r.ToArray(); }
    static byte[] Int(int n) { return T(2,new byte[]{(byte)(n>>24),(byte)(n>>16),(byte)(n>>8),(byte)n}); }
    static byte[] Oid(string s) { var a=s.Split('.');var b=new List<byte>();b.Add((byte)(int.Parse(a[0])*40+int.Parse(a[1])));for(int i=2;i<a.Length;i++){uint v=uint.Parse(a[i]);var z=new List<byte>();z.Add((byte)(v&127));v>>=7;while(v>0){z.Insert(0,(byte)((v&127)|128));v>>=7;}b.AddRange(z);}return T(6,b.ToArray()); }
    static int Size(byte[] b,ref int p) { int n=b[p++];if(n<128)return n;int k=n&127;n=0;for(int i=0;i<k;i++)n=(n<<8)|b[p++];return n; }
    static byte[] Read(byte[] b,ref int p,out int tag) {tag=b[p++];int n=Size(b,ref p);if(n<0||p+n>b.Length)throw new Exception("Invalid SNMP BER");var v=new byte[n];Array.Copy(b,p,v,0,n);p+=n;return v;}
    static string DecodeOid(byte[] b) {var a=new List<uint>();if(b.Length==0)return "";a.Add((uint)Math.Min(2,b[0]/40));a.Add((uint)(b[0]-40*a[0]));uint n=0;for(int i=1;i<b.Length;i++){n=(n<<7)|(uint)(b[i]&127);if((b[i]&128)==0){a.Add(n);n=0;}}return string.Join(".",a);}
    static string Value(int tag,byte[] b) {if(tag==4)return Encoding.ASCII.GetString(b);if(tag==6)return DecodeOid(b);if(tag==2||tag==65||tag==66||tag==67){long n=0;foreach(byte v in b)n=(n<<8)|v;return n.ToString();}return BitConverter.ToString(b);}
    public static Dictionary<string,string> Walk(string host,string community,string root,int timeout,int limit) {
        var result=new Dictionary<string,string>();var address=Dns.GetHostAddresses(host);IPAddress ip=null;foreach(var a in address)if(a.AddressFamily==AddressFamily.InterNetwork){ip=a;break;}if(ip==null)throw new Exception("No IPv4 address for switch");
        using(var udp=new UdpClient(AddressFamily.InterNetwork)) {udp.Client.ReceiveTimeout=timeout;udp.Client.SendTimeout=timeout;udp.Connect(ip,161);string cursor=root;
            for(int i=0;i<limit;i++) {var varbind=T(48,Join(Oid(cursor),T(5,new byte[0])));var pdu=T(161,Join(Int(i+1),Int(0),Int(0),T(48,varbind)));var packet=T(48,Join(Int(1),T(4,Encoding.ASCII.GetBytes(community)),pdu));udp.Send(packet,packet.Length);var remote=new IPEndPoint(IPAddress.Any,0);var response=udp.Receive(ref remote);
                int pos=0,tag;var outer=Read(response,ref pos,out tag);pos=0;Read(outer,ref pos,out tag);Read(outer,ref pos,out tag);var rpdu=Read(outer,ref pos,out tag);pos=0;Read(rpdu,ref pos,out tag);var err=Read(rpdu,ref pos,out tag);long code=0;foreach(byte x in err)code=(code<<8)|x;if(code!=0)break;Read(rpdu,ref pos,out tag);var binds=Read(rpdu,ref pos,out tag);pos=0;var binding=Read(binds,ref pos,out tag);pos=0;var name=DecodeOid(Read(binding,ref pos,out tag));var value=Read(binding,ref pos,out tag);if(!(name==root||name.StartsWith(root+"."))||name==cursor||tag==130||tag==129||tag==128)break;result[name]=Value(tag,value);cursor=name;
            }
        }return result;
    }
}
'@ @script:EA1
        }

        $SwitchNames = @($Switches) + @(
            $HyperVNetwork.Records | Where-Object {
                $_.PhysicalSwitch -and 
                $_.PhysicalSwitch -ne 'N/A'
            } | Select-Object -ExpandProperty PhysicalSwitch
        )

        $SwitchNames = @($SwitchNames | Where-Object {$_} | Sort-Object -Unique)
        $Matched     = 0

        ForEach ($SwitchName in $SwitchNames) {
            Try {
                $Fdb     = [NativeSnmpWalk]::Walk($SwitchName,$SNMPCommunity,'1.3.6.1.2.1.17.4.3.1.2',2000,8192)
                $Bridge  = [NativeSnmpWalk]::Walk($SwitchName,$SNMPCommunity,'1.3.6.1.2.1.17.1.4.1.2',2000,1024)
                $IfNames = [NativeSnmpWalk]::Walk($SwitchName,$SNMPCommunity,'1.3.6.1.2.1.31.1.1.1.1',2000,2048)
                $FDBMap  = @{}

                ForEach ($Entry in $Fdb.GetEnumerator()) {
                    $Suffix = $Entry.Key.Substring('1.3.6.1.2.1.17.4.3.1.2.'.Length)
                    $Octets = @($Suffix -split '\.')
                    If ($Octets.Count -ne 6) {
                        Continue
                    }

                    $MAC       = (@($Octets | ForEach-Object {'{0:X2}' -f [int]$_}) -join ':')
                    $BridgeOID = '1.3.6.1.2.1.17.1.4.1.2.{0}' -f $Entry.Value
                    If (-not $Bridge.ContainsKey($BridgeOID)) {
                        Continue
                    }

                    $NameOID = '1.3.6.1.2.1.31.1.1.1.1.{0}' -f $Bridge[$BridgeOID]
                    If ($IfNames.ContainsKey($NameOID)) {
                        $FDBMap[$MAC] = $IfNames[$NameOID]
                    }
                }

                ForEach ($D in $Rows) {
                    If ($D.MACAddress -and $FDBMap.ContainsKey($D.MACAddress) -and -not $D.SwitchDiscovery) {
                        $D.PhysicalSwitch     = $SwitchName
                        $D.PhysicalSwitchPort = $FDBMap[$D.MACAddress]
                        $D.SwitchDiscovery    = 'SNMP FDB (learned port; may be uplink/trunk)'
                        $Matched++
                    }
                }
            } Catch {
                Write-Verbose -Message ('SNMP FDB query failed for {0}: {1}' -f $SwitchName,$_.Exception.Message)
            }
        }
        $FDBStatus = 'Attempted; matched {0} devices' -f $Matched
    }
    #endregion - Optional native SNMP v2c forwarding-table discovery (no external executables/modules).

    [pscustomobject]@{
        Site      = $Site[0]
        Subnet    = If ($Candidates.Count -eq 1) { $Candidates[0].Subnet } Else { 'Multiple' }
        Interface = If ($Candidates.Count -eq 1) { $Candidates[0].Interface } Else { 'Multiple' }
        VMVotes   = $null
        Total     = $Addresses
        Scanned   = $Completed
        Found     = $Rows.Count
        TimedOut  = $TimedOut
        Elapsed   = $Clock.Elapsed.ToString()
        Subnets   = @($Summaries)
        FDBStatus = $FDBStatus
        Devices   = $Rows
    }
} ### Lessons
#endregion Native Subnet Discovery v7

#region Collector Guard
Function Invoke-InventoryCollector {
    <#
        .SYNOPSIS
        Runs one optional inventory collector without letting its failure stop the script.

        .DESCRIPTION
        The script runs with $ErrorActionPreference set to Stop, so an unexpected error in any
        collector would otherwise end the run before reports are written. Optional collectors
        (display adapters, battery, network adapters, monitors, printers, Dell docks) run through
        this function: a failure is reported as a warning and the collector returns nothing, so
        its report section is simply omitted.

        .PARAMETER Name
        Display name used in the warning message.

        .PARAMETER ScriptBlock
        Script block that runs the collector.

        .EXAMPLE
        $Printers = @(Invoke-InventoryCollector -Name 'Printers' -ScriptBlock { Get-PrinterInventory })

        .OUTPUTS
        Whatever the collector returns, or nothing when it fails.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, HelpMessage = 'Specify the collector display name used in warnings.')]
        [string]$Name,

        [Parameter(Mandatory, HelpMessage = 'Specify the script block that runs the collector.')]
        [scriptblock]$ScriptBlock
    )

    Try {
        & $ScriptBlock
    } Catch {
        Write-Warning -Message ('{0} inventory could not be collected: {1}' -f $Name,$_.Exception.Message)
    }
}
#endregion Collector Guard

#region Collect Inventory
#region Basic Collection
$Computer    = Get-ComputerInventory
$CPU         = @(Get-CpuInventory)
$CPUTopology = Get-CpuTopology -Processors $CPU
$Memory      = Get-MemoryInventory
$Storage     = Get-DiskInventory
#endregion Basic Collection

#region Dell specific
$DellServer = $null
If ($Computer.Manufacturer -match '(?i)Dell' -and $Computer.OS -match '(?i)Windows Server') {
    Try {
        $DellServer = Get-DellServerInventory
    } Catch {
        Write-Verbose -Message ('Unable to collect Dell server enrichment: {0}' -f $_.Exception.Message)
    }
}
#endregion Dell specific

#region Gather iDRAC
$iDRAC = $null
If ($Computer.Manufacturer -match '(?i)Dell') {
    Try {
        $iDRAC = Get-iDRACInventory
    } Catch {
        Write-Verbose -Message ('Unable to collect iDRAC inventory: {0}' -f $_.Exception.Message)
    }
}
#endregion Gather iDRAC

#region Gather AD Site Subnets
$SiteSubnets = @()
Try {
    $SiteSubnets = @(Get-ADSiteSubnetInventory @script:EA1)
} Catch {
    Write-Warning -Message ('Unable to collect AD site subnets: {0}' -f $_.Exception.Message)
}
#endregion Gather AD Site Subnets

#region Gather Hyper-V
$HyperVNetwork = $null
$HyperVCommand = Get-Command -Name Get-VM @script:EA0
If ($HyperVCommand) {
    Try {
        $HyperVNetwork = Get-HyperVNetworkInventory -Out Object -LLDPCaptureSeconds $LLDPCaptureSeconds -iDRAC $iDRAC -SiteSubnets $SiteSubnets
    } Catch {
        Write-Warning -Message ('Unable to collect Hyper-V network inventory: {0}' -f $_.Exception.Message)
    }
} Else {
    Write-Verbose -Message 'Hyper-V Get-VM cmdlet was not found; Hyper-V network inventory will not be collected.'
}
#endregion Gather Hyper-V

#region System Responsibility
$Responsibility = $null
If (-not $SkipResponsibilityInventory) {
    Try {
        Write-Progress -Activity 'Hardware inventory' -Status 'Collecting system responsibilities, services, software and security posture'
        $Responsibility = Get-SystemResponsibilityInventory -IncludeLogs -IncludeSoftware -IncludeTasks -IncludeUpdates -IncludeShareACL
    } Catch {
        Write-Warning -Message ('Unable to collect system responsibility inventory: {0}' -f $_.Exception.Message)
    } Finally {
        Write-Progress -Activity 'Hardware inventory' -Completed
    }
}
#endregion System Responsibility

#region Legacy Subnet Discovery
$SubnetDiscovery = $null
$LegacySubnets   = @($SiteSubnets | Where-Object { $_ -and $_.IsLegacy })
If ($ScanNativeSubnet -and $LegacySubnets.Count -eq 0) {
    Write-Host 'Native subnet discovery skipped: no Legacy subnets are assigned to this AD site.' -ForegroundColor DarkYellow
} ElseIf ($ScanNativeSubnet) {
    Try {
        $SubnetDiscovery = Get-NativeSubnetDiscovery -HyperVNetwork $HyperVNetwork -SiteSubnets $LegacySubnets -Throttle $SubnetScanThrottle -PingTimeout $SubnetPingTimeout -PortTimeout $SubnetPortTimeout -MaxSeconds $SubnetScanMaxSeconds
    } Catch {
        Write-Warning -Message ('Native subnet discovery failed: {0}' -f $_.Exception.Message)
    }
}
#endregion Legacy Subnet Discovery

$Inventory = [PSCustomObject][ordered]@{
    Metadata        = [PSCustomObject][ordered]@{
        ScriptVersion     = $ScriptVersion
        PowerShellVersion = [string]$PSVersionTable.PSVersion
        CollectedAt       = Get-Date
    }
    Computer        = $Computer
    ServerHardware  = $DellServer
    iDRAC           = $iDRAC
    CPU             = $CPU
    CPUTopology     = $CPUTopology
    Memory          = $Memory
    Storage         = $Storage
    DisplayAdapters = @(Invoke-InventoryCollector -Name 'DisplayAdapters' -ScriptBlock { Get-DisplayAdapterInventory })
    Battery         = @(Invoke-InventoryCollector -Name 'Battery' -ScriptBlock { Get-BatteryInventory })
    NetworkAdapters = @(Invoke-InventoryCollector -Name 'NetworkAdapters' -ScriptBlock { Get-PhysicalNetworkInventory })
    Monitors        = @(Invoke-InventoryCollector -Name 'Monitors' -ScriptBlock { Get-MonitorInventory })
    Printers        = @(Invoke-InventoryCollector -Name 'Printers' -ScriptBlock { Get-PrinterInventory })
    DellDocks       = @(Invoke-InventoryCollector -Name 'DellDocks' -ScriptBlock { Get-DellDockInventory })
    HyperVNetwork   = $HyperVNetwork
    SubnetDiscovery = $SubnetDiscovery
    Responsibility  = $Responsibility
}
#endregion Collect Inventory

#region Report Files
If (-not (Test-Path -LiteralPath $OutputDirectory)) {
    $null = (New-Item -Path $OutputDirectory -ItemType Directory -Force)
}

$Timestamp       = Get-Date -Format 'yyyyMMdd-HHmmss'
$BaseName        = ('HardwareInventory-{0}-{1}' -f $Computer.ComputerName,$Timestamp)
$HtmlPath        = Join-Path -Path $OutputDirectory -ChildPath ('{0}.html' -f $BaseName)
$JsonPath        = Join-Path -Path $OutputDirectory -ChildPath ('{0}.json' -f $BaseName)
$HardwareCsvPath = Join-Path -Path $OutputDirectory -ChildPath ('{0}.csv' -f $BaseName)
$HyperVCsvPath   = Join-Path -Path $OutputDirectory -ChildPath ('HyperVNetworkInventory-{0}-{1}.csv' -f $Computer.ComputerName,$Timestamp)
$SubnetCsvPath   = Join-Path -Path $OutputDirectory -ChildPath ('SubnetDiscovery-{0}-{1}.csv' -f $Computer.ComputerName,$Timestamp)
$Html            = New-HardwareInventoryHtml -Inventory $Inventory

[IO.File]::WriteAllText($HtmlPath,$Html,(New-Object -TypeName System.Text.UTF8Encoding -ArgumentList ($false)))
$Inventory | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $JsonPath -Encoding UTF8

ConvertTo-HardwareInventoryCsvRows -Inventory $Inventory | Export-Csv -LiteralPath $HardwareCsvPath @script:eCSV2

If ($Inventory.HyperVNetwork) {
    Export-HyperVNetworkInventoryCsv -HyperVNetwork $Inventory.HyperVNetwork -Path $HyperVCsvPath
} Else {
    [PSCustomObject][ordered]@{
        HostName    = $Computer.ComputerName
        AdapterType = 'Hyper-V Discovery'
        AdapterName = $null
        MACAddress  = $null
        Status      = 'Hyper-V network inventory was not collected'
    } | Export-Csv -LiteralPath $HyperVCsvPath @script:eCSV2
}

If ($Inventory.SubnetDiscovery) {
    $Inventory.SubnetDiscovery.Devices | Export-Csv -LiteralPath $SubnetCsvPath @script:eCSV2
}

Show-HardwareInventory -Inventory $Inventory

#region OutScreen
$Gr = @{ForegroundColor = 'Green'}
Write-Host ''
Write-Host ('HTML report: {0}' -f $HtmlPath) @Gr
Write-Host ('JSON report: {0}' -f $JsonPath) @Gr
Write-Host ('Hardware CSV: {0}' -f $HardwareCsvPath) @Gr
If ($Inventory.SubnetDiscovery) {
    Write-Host ('Subnet CSV: {0} | {1} devices on {2}' -f $SubnetCsvPath,$Inventory.SubnetDiscovery.Found,$Inventory.SubnetDiscovery.Subnet) @Gr
}

If ($Inventory.HyperVNetwork)   {
    Write-Host ('Hyper-V CSV: {0}' -f $HyperVCsvPath) @Gr
    Write-Host (
        'Hyper-V network: AD Site {0} | Servers Subnet {1} | Replacement Prefix {2} | LLDP {3}' -f $Inventory.HyperVNetwork.ADSite,
            $Inventory.HyperVNetwork.ServersSubnet,
            $Inventory.HyperVNetwork.ReplacementPrefix,
            $Inventory.HyperVNetwork.LLDPCaptureStatus
    ) @Gr
}
#endregion OutScreen
#endregion Report Files

#region Email
If ($SendEmail) {
    $Missing = @()
    If ([string]::IsNullOrWhiteSpace($EmailConfig.To))         { $Missing += 'To' }
    If ([string]::IsNullOrWhiteSpace($EmailConfig.From))       { $Missing += 'From' }
    If ([string]::IsNullOrWhiteSpace($EmailConfig.SmtpServer)) { $Missing += 'SmtpServer' }
    If ([string]::IsNullOrWhiteSpace($EmailConfig.UserName))   { $Missing += 'UserName' }

    If ($Missing.Count -gt 0) {
        Throw ('-SendEmail requires: {0}.' -f ($Missing -join ', '))
    }

    $SmtpPasswordPlainText = Convert-PasswordCipher -Decrypt -CipherText $EncryptedSmtpPassword -Keyword $Keyword
    Try {
        $SmtpCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList (
            $EmailConfig.UserName,(ConvertTo-SecureString -String $SmtpPasswordPlainText -AsPlainText -Force)
        )
    } Finally {
        $SmtpPasswordPlainText = $null
    }

    $Attachments = @()
    If (-not $NoAttachments) {
        ForEach ($Path in @($HtmlPath,$JsonPath,$HardwareCsvPath,$HyperVCsvPath,$SubnetCsvPath)) {
            If ($Path -and (Test-Path -LiteralPath $Path)) {
                $Attachments += $Path
            }
        }
    }

    $Subject     = '{0} - {1} - {2}' -f $EmailSubjectPrefix,$Computer.ComputerName,$Computer.Model
    $MailSplat   = @{
        EmailConfig = $EmailConfig
        Credential  = $SmtpCredential
        Subject     = $Subject
        HtmlBody    = $Html
        Attachments = $Attachments
    }

    Send-HardwareInventoryEmail @MailSplat

    Write-Host ('Email sent to {0}' -f $EmailConfig.To) @Gr
}
#endregion Email

#region cleanup
Remove-Variable -Name Keyword, SACredential, SmtpCredential, SmtpPasswordPlainText @script:EA0
#endregion cleanup
