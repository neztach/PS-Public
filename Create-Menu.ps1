Function Create-Menu {
    [CmdletBinding()]
    Param (
        [string]$Title,
        $MenuItems,
        [string]$TitleColor,
        [string]$LineColor,
        [string]$MenuItemColor
    )
    Clear-Host 
    [string]$Title   = "$Title" 
    $TitleCount      = $Title.Length 
    $LongestMenuItem = ($MenuItems | Measure-Object -Maximum -Property Length).Maximum 
    If ($TitleCount -lt $LongestMenuItem) {
        $reference = $LongestMenuItem
    } Else {
        $reference = $TitleCount
    }
    $reference                          = $reference + 10 
    $Line                               = '═' * $reference 
    $TotalLineCount                     = $Line.Length 
    $RemaniningCountForTitleLine        = $reference - $TitleCount 
    $RemaniningCountForTitleLineForEach = $RemaniningCountForTitleLine / 2 
    $RemaniningCountForTitleLineForEach = [math]::Round($RemaniningCountForTitleLineForEach) 
    $LineForTitleLine                   = "`0" * $RemaniningCountForTitleLineForEach 
    $Tab                                = "`t" 
    Write-Host '╔'   -NoNewline -ForegroundColor $LineColor
    Write-Host $Line -NoNewline -ForegroundColor $LineColor
    Write-Host '╗'              -ForegroundColor $LineColor 
    If ($RemaniningCountForTitleLine % 2 -eq 1) { 
        $RemaniningCountForTitleLineForEach = $RemaniningCountForTitleLineForEach - 1 
        $LineForTitleLine2                  = "`0" * $RemaniningCountForTitleLineForEach 
        Write-Host '║'                -NoNewline -ForegroundColor $LineColor
        Write-Host $LineForTitleLine  -NoNewline -ForegroundColor $LineColor
        Write-Host $Title             -NoNewline -ForegroundColor $TitleColor
        Write-Host $LineForTitleLine2 -NoNewline -ForegroundColor $LineColor
        Write-Host '║'                           -ForegroundColor $LineColor
    } Else { 
        Write-Host '║'               -NoNewline -ForegroundColor $LineColor
        Write-Host $LineForTitleLine -NoNewline -ForegroundColor $LineColor
        Write-Host $Title            -NoNewline -ForegroundColor $TitleColor
        Write-Host $LineForTitleLine -NoNewline -ForegroundColor $LineColor
        Write-Host '║'                          -ForegroundColor $LineColor 
    }
    Write-Host '╠'   -NoNewline -ForegroundColor $LineColor
    Write-Host $Line -NoNewline -ForegroundColor $LineColor
    Write-Host '╣'              -ForegroundColor $LineColor
    $i = 1
    ForEach ($menuItem in $MenuItems) { 
        $number                    = $i++ 
        $RemainingCountForItemLine = $TotalLineCount - $menuItem.Length - 9 
        $LineForItems              = "`0" * $RemainingCountForItemLine 
        Write-Host '║'           -NoNewline -ForegroundColor $LineColor
        Write-Host $Tab          -NoNewline
        Write-Host $number"."    -NoNewline -ForegroundColor $MenuItemColor
        Write-Host $menuItem     -NoNewline -ForegroundColor $MenuItemColor
        Write-Host $LineForItems -NoNewline -ForegroundColor $LineColor
        Write-Host '║'                      -ForegroundColor $LineColor 
    }
    Write-Host '╚'   -NoNewline -ForegroundColor $LineColor
    Write-Host $Line -NoNewline -ForegroundColor $LineColor
    Write-Host '╝'              -ForegroundColor $LineColor 
} 

# Use splating to pass the most items of the CreateMenu Function

$MenuParams = @{
    Title         = 'Service Desk Task - Reports AD' 
    TitleColor    = 'Red' 
    LineColor     = 'Cyan'
    MenuItemColor = 'Yellow'
}

# I didn't success to pass all parameters in a splat
CreateMenu @MenuParams -MenuItems  'User Memberhip groups', `
    'Group Members', `
    'Users Groups members from a file', `
    'User accounts in a specific OU', `
    'Disabled Users Accounts', `
    'User Accounts with expired password', `
    'User Accounts with password expiring in x days',
'All User Accounts',
'Quit'
<#
The result is like this ... in color
╔════════════════════════════════════════════════════════╗
║             Service Desk Task - Reports AD             ║
╠════════════════════════════════════════════════════════╣
║       1.User Memberhip groups                          ║
║       2.Group Members                                  ║
║       3.Users Groups members from a file               ║
║       4.User accounts in a specific OU                 ║
║       5.Disabled Users Accounts                        ║
║       6.User Accounts with expired password            ║
║       7.User Accounts with password expiring in x days ║
║       8.All User Accounts                              ║
║       9.Quit                                           ║
╚════════════════════════════════════════════════════════╝
#>


# then, use it in a script like this : 
CreateMenu @MenuParams -MenuItems  'User Memberhip groups', 'Group Members', 'Groups members from a file', 'User accounts in a specific OU', 'Disabled Users Accounts', 'User Accounts with expired password', 'User Accounts with password expiring in x days', 'All User Accounts', 'Quit'
$selection = Read-Host -Prompt 'Please make a selection'
Switch ($selection) {
    '1' {
        'You chose option #1' # Insert your code : simple cmdlet, or calling a function 
    } '2' {
        'You chose option #2' # Insert your code : simple cmdlet, or calling a function 
    } '3' {
        'You chose option #3' # Insert your code : simple cmdlet, or calling a function 
    } 'q' {
        return
    }
}
