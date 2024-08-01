Function Show-Menu {
    <#
        .SYNOPSIS
        Shows an interactive menu to the user and returns the chosen item or item index.

        .DESCRIPTION
        Shows an interactive menu on supporting console hosts. The user can interactively
        select one (or more, in case of -MultiSelect) items. The cmdlet returns the items
        itself, or its indices (in case of -ReturnIndex). 

        The interactive menu is controllable by hotkeys:
            - Arrow up/down: Focus menu item.
            - Enter: Select menu item.
            - Page up/down: Go one page up or down - if the menu is larger then the screen.
            - Home/end: Go to the top or bottom of the menu.
            - Spacebar: If in multi-select mode (MultiSelect parameter), toggle item choice.

        Not all console hosts support the interactive menu (PowerShell ISE is a well-known
        host which doesn't support it). The console host needs to support the ReadKey method.
        The default PowerShell console host does this. 

        .PARAMETER  MenuItems
        Array of objects or strings containing menu items. Must contain at least one item.
        Must not contain $null. 

        The items are converted to a string for display by the MenuItemFormatter parameter, which
        does by default a ".ToString()" of the underlying object. It is best for this string 
        to fit on a single line.

        The array of menu items may also contain unselectable separators, which can be used
        to visually distinct menu items. You can call Get-MenuSeparator to get a separator object,
        and add that to the menu item array.

        .PARAMETER  ReturnIndex
        Instead of returning the object(s) that has/have been chosen, return the index/indices
        of the object(s) that have been chosen.

        .PARAMETER  MultiSelect
        Allow the user to select multiple items instead of a single item.

        .PARAMETER  ItemFocusColor
        The console color used for focusing the active item. This by default green,
        which looks good on both default PowerShell-blue and black consoles.

        .PARAMETER  MenuItemFormatter
        A function/scriptblock which accepts a menu item (from the MenuItems parameter)
        and returns a string suitable for display. This function will be called many times,
        for each menu item once.

        This parameter is optional and by default executes a ".ToString()" on the object.
        If you control the objects that you pass in MenuItems, then you want to probably
        override the ToString() method. If you don't control the objects, then this parameter
        is very useful.

        .PARAMETER InitialSelection
        Set initial selections if multi-select mode. This is an array of indecies.

        .PARAMETER Callback
        A function/scriptblock which is called every 10 milliseconds while the menu is shown

        .INPUTS
        None. You cannot pipe objects to Show-Menu.

        .OUTPUTS
        Array of chosen menu items or (if the -ReturnIndex parameter is given) the indices.

        .LINK
        https://github.com/Sebazzz/PSMenu
        https://github.com/chrisseroka/ps-menu

        .EXAMPLE
        Show-Menu @("option 1", "option 2", "option 3")

        .EXAMPLE 
        Show-Menu -MenuItems $(Get-NetAdapter) -MenuItemFormatter { $Args | Select -Exp Name }

        .EXAMPLE 
        Show-Menu @("Option A", "Option B", $(Get-MenuSeparator), "Quit")
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, Position = 0)]
        [Array]$MenuItems,
        [Switch]$ReturnIndex, 
        [Switch]$MultiSelect, 
        [ConsoleColor]$ItemFocusColor = [ConsoleColor]::Green,
        [ScriptBlock]$MenuItemFormatter = { Param($M) Format-MenuItemDefault $M },
        [Array]$InitialSelection = @(),
        [ScriptBlock]$Callback = $null
    )

    Begin {
        $Separator = [PSCustomObject]@{
            __MarkSeparator = [Guid]::NewGuid()
        }

        Function Get-MenuSeparator() {
            <#
                .SYNOPSIS 
                Returns a separator for the Show-Menu Cmdlet. The separator is not selectable by the user and
                allows a visual distinction of multiple menuitems.
                .EXAMPLE
                $MenuItems = @("Option A", "Option B", $(Get-MenuSeparator), "Quit")
                Show-Menu $MenuItems
            #>
            [CmdletBinding()]
            Param()

            # Internally we will check this parameter by-reference
            Return $Separator
        }

        Function Test-MenuSeparator([Parameter(Mandatory)]$MenuItem) {
            $Separator = Get-MenuSeparator

            # Separator is a singleton and we compare it by reference
            Return [Object]::ReferenceEquals($Separator, $MenuItem)
        }

        Function Format-MenuItem(
            [Parameter(Mandatory)]$MenuItem, 
            [Switch]$MultiSelect, 
            [Parameter(Mandatory)][bool]$IsItemSelected, 
            [Parameter(Mandatory)][bool]$IsItemFocused
        ) {
            $SelectionPrefix = '    '
            $FocusPrefix     = '  '
            $ItemText        = ' -------------------------- '

            If ($(Test-MenuSeparator $MenuItem) -ne $true) {
                If ($MultiSelect) { $SelectionPrefix = If ($IsItemSelected) { '[x] ' } Else { '[ ] ' } }
                $FocusPrefix = If ($IsItemFocused) { '> ' } Else { '  ' }
                $ItemText    = $MenuItem.ToString()
            }

            $WindowWidth = (Get-Host).UI.RawUI.WindowSize.Width
            $Text        = "{0}{1}{2}" -f $FocusPrefix, $SelectionPrefix, $ItemText
            If ($WindowWidth - ($Text.Length + 2) -gt 0) { $Text = $Text.PadRight($WindowWidth - ($Text.Length + 2), ' ') }
            Return $Text
        }

        Function Format-MenuItemDefault($MenuItem) {
            Return $MenuItem.ToString()
        }

        Function Get-ConsoleHeight() {
            Return (Get-Host).UI.RawUI.WindowSize.Height - 2
        }

        Function Test-HostSupported() {
            $Whitelist = @("ConsoleHost","Visual Studio Code Host")
            If ($Whitelist -inotcontains $Host.Name) {
                Throw "This host is $($Host.Name) and does not support an interactive menu."
            }
        }

        #region Test-Input
        # Ref: https://docs.microsoft.com/en-us/windows/desktop/inputdev/virtual-key-codes
        $KeyConstants = [PSCustomObject]@{
            VK_RETURN   = 0x0D;
            VK_ESCAPE   = 0x1B;
            VK_UP       = 0x26;
            VK_DOWN     = 0x28;
            VK_SPACE    = 0x20;
            VK_PAGEUP   = 0x21; # Actually VK_PRIOR
            VK_PAGEDOWN = 0x22; # Actually VK_NEXT
            VK_END      = 0x23;
            VK_HOME     = 0x24;
        }

        Function Test-KeyEnter($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_RETURN
        }

        Function Test-KeyEscape($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_ESCAPE
        }

        Function Test-KeyUp($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_UP
        }

        Function Test-KeyDown($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_DOWN
        }

        Function Test-KeySpace($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_SPACE
        }

        Function Test-KeyPageDown($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_PAGEDOWN
        }

        Function Test-KeyPageUp($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_PAGEUP
        }

        Function Test-KeyEnd($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_END
        }

        Function Test-KeyHome($VKeyCode) {
            Return $VKeyCode -eq $KeyConstants.VK_HOME
        }
        #endregion Test-Input

        Function Test-MenuItemArray([Array]$MenuItems) {
            ForEach ($MenuItem in $MenuItems) {
                $IsSeparator = Test-MenuSeparator $MenuItem
                If ($IsSeparator -eq $false) { Return }
            }
            Throw 'The -MenuItems option only contains non-selectable menu-items (like separators)'
        }

        Function Get-CalculatedPageIndexNumber(
            [Parameter(Mandatory, Position = 0)][Array]$MenuItems, 
            [Parameter(Position = 1)][int]$MenuPosition, 
            [Switch]$TopIndex, 
            [Switch]$ItemCount, 
            [Switch]$BottomIndex
        ) {
            $WindowHeight   = Get-ConsoleHeight
            $TopIndexNumber = 0;
            $MenuItemCount  = $MenuItems.Count
            If ($MenuItemCount -gt $WindowHeight) {
                $MenuItemCount = $WindowHeight;
                If ($MenuPosition -gt $MenuItemCount) {
                    $TopIndexNumber = $MenuPosition - $MenuItemCount;
                }
            }

            If ($TopIndex) {
                Return $TopIndexNumber
            }

            If ($ItemCount) {
                Return $MenuItemCount
            }

            If ($BottomIndex) {
                Return $TopIndexNumber + [Math]::Min($MenuItemCount, $WindowHeight) - 1
            }

            Throw 'Invalid option combination'
        }

        Function Get-WrappedPosition(
            [Array]$MenuItems, 
            [int]$Position, 
            [int]$PositionOffset
        ) {
            # Wrap position
            If ($Position -lt 0) { $Position = $MenuItems.Count - 1 }

            If ($Position -ge $MenuItems.Count) { $Position = 0 }

            # Ensure to skip separators
            While (Test-MenuSeparator $($MenuItems[$Position])) {
                $Position += $PositionOffset
                $Position  = Get-WrappedPosition $MenuItems $Position $PositionOffset
            }

            Return $Position
        }

        Function Write-MenuItem(
            [Parameter(Mandatory)][String]$MenuItem, 
            [Switch]$IsFocused, 
            [ConsoleColor]$FocusColor
        ) {
            If ($IsFocused) {
                Write-Host $MenuItem -ForegroundColor $FocusColor
            } Else {
                Write-Host $MenuItem
            }
        }

        Function Write-Menu {
            Param (
                [Parameter(Mandatory)]
                [Array]$MenuItems, 
                [Parameter(Mandatory)]
                [Int]$MenuPosition,
                [Parameter()]
                [Array]$CurrentSelection, 
                [Parameter(Mandatory)]
                [ConsoleColor]$ItemFocusColor,
                [Parameter(Mandatory)]
                [ScriptBlock]$MenuItemFormatter,
                [Switch]$MultiSelect
            )
    
            $CurrentIndex  = Get-CalculatedPageIndexNumber -MenuItems $MenuItems -MenuPosition $MenuPosition -TopIndex
            $MenuItemCount = Get-CalculatedPageIndexNumber -MenuItems $MenuItems -MenuPosition $MenuPosition -ItemCount
            $ConsoleWidth  = [Console]::BufferWidth
            $MenuHeight    = 0

            For ($i = 0; $i -le $MenuItemCount; $i++) {
                If ($null -eq $MenuItems[$CurrentIndex]) {
                    Continue
                }

                $RenderMenuItem = $MenuItems[$CurrentIndex]
                $MenuItemStr    = If (Test-MenuSeparator $RenderMenuItem) { $RenderMenuItem } Else { & $MenuItemFormatter $RenderMenuItem }
                If (!$MenuItemStr) {
                    Throw "'MenuItemFormatter' returned an empty string for item #$CurrentIndex"
                }

                $IsItemSelected = $CurrentSelection -contains $CurrentIndex
                $IsItemFocused  = $CurrentIndex -eq $MenuPosition

                $DisplayText = Format-MenuItem -MenuItem $MenuItemStr -MultiSelect:$MultiSelect -IsItemSelected:$IsItemSelected -IsItemFocused:$IsItemFocused
                Write-MenuItem -MenuItem $DisplayText -IsFocused:$IsItemFocused -FocusColor $ItemFocusColor
                $MenuHeight += [Math]::Max([Math]::Ceiling($DisplayText.Length / $ConsoleWidth), 1)

                $CurrentIndex++;
            }

            $MenuHeight
        }

        Function Get-PositionWithVKey(
            [Array]$MenuItems, 
            [int]$Position, 
            $VKeyCode
        ) {
            $MinPosition  = 0
            $MaxPosition  = $MenuItems.Count - 1
            $WindowHeight = Get-ConsoleHeight

            Set-Variable -Name NewPosition -Option AllScope -Value $Position

            Function Reset-InvalidPosition([Parameter(Mandatory)][int] $PositionOffset) {
                <#
                    .SYNOPSIS
                    Updates the position until we aren't on a separator
                #>
                $NewPosition = Get-WrappedPosition $MenuItems $NewPosition $PositionOffset
            }

            If (Test-KeyUp $VKeyCode) { 
                $NewPosition--
                Reset-InvalidPosition -PositionOffset -1
            }

            If (Test-KeyDown $VKeyCode) {
                $NewPosition++
                Reset-InvalidPosition -PositionOffset 1
            }

            If (Test-KeyPageDown $VKeyCode) {
                $NewPosition = [Math]::Min($MaxPosition, $NewPosition + $WindowHeight)
                Reset-InvalidPosition -PositionOffset -1
            }

            If (Test-KeyEnd $VKeyCode) {
                $NewPosition = $MenuItems.Count - 1
                Reset-InvalidPosition -PositionOffset 1
            }

            If (Test-KeyPageUp $VKeyCode) {
                $NewPosition = [Math]::Max($MinPosition, $NewPosition - $WindowHeight)
                Reset-InvalidPosition -PositionOffset -1
            }

            If (Test-KeyHome $VKeyCode) {
                $NewPosition = $MinPosition
                Reset-InvalidPosition -PositionOffset -1
            }
            Return $NewPosition
        }

        Function Read-VKey() {
            $CurrentHost = Get-Host
            $ErrMsg      = "Current host '$CurrentHost' does not support operation 'ReadKey'"

            Try {
                # Issues with reading up and down arrow keys
                # - https://github.com/PowerShell/PowerShell/issues/16443
                # - https://github.com/dotnet/runtime/issues/63387
                # - https://github.com/PowerShell/PowerShell/issues/16606
                If ($IsLinux -or $IsMacOS) {
                    ## A bug with Linux and Mac where arrow keys are return in 2 chars.  First is esc follow by A,B,C,D
                    $key1 = $CurrentHost.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    If ($key1.VirtualKeyCode -eq 0x1B) {
                        ## Found that we got an esc chair so we need to grab one more char
                        $key2 = $CurrentHost.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

                        ## We just care about up and down arrow mapping here for now.
                        If ($key2.VirtualKeyCode -eq 0x41) {
                            # VK_UP = 0x26 up-arrow
                            $key1.VirtualKeyCode = 0x26
                        }
                        If ($key2.VirtualKeyCode -eq 0x42) {
                            # VK_DOWN = 0x28 down-arrow
                            $key1.VirtualKeyCode = 0x28
                        }
                    }
                    Return $key1
                }
                Return $CurrentHost.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            } Catch [System.NotSupportedException] {
                Write-Error -Exception $_.Exception -Message $ErrMsg
            } Catch [System.NotImplementedException] {
                Write-Error -Exception $_.Exception -Message $ErrMsg
            }
        }

        Function Toggle-Selection {
            Param ($Position, [Array]$CurrentSelection)
            If ($CurrentSelection -contains $Position) { 
                $result = $CurrentSelection | Where-Object { $_ -ne $Position }
            } Else {
                $CurrentSelection += $Position
                $result            = $CurrentSelection
            }
            Return $Result
        }
    }
    Process {
        Test-HostSupported
        Test-MenuItemArray -MenuItems $MenuItems

        # Current pressed virtual key code
        $VKeyCode = 0

        # Initialize valid position
        $Position = Get-WrappedPosition $MenuItems -Position 0 -PositionOffset 1

        $CurrentSelection = $InitialSelection

        Try {
            [System.Console]::CursorVisible = $False # Prevents cursor flickering

            # Body
            $WriteMenu  = {
                ([ref]$MenuHeight).Value = Write-Menu -MenuItems $MenuItems `
                    -MenuPosition $Position `
                    -MultiSelect:$MultiSelect `
                    -CurrentSelection:$CurrentSelection `
                    -ItemFocusColor $ItemFocusColor `
                    -MenuItemFormatter $MenuItemFormatter
            }
            $MenuHeight = 0

            & $WriteMenu
            $NeedRendering = $false

            While ($True) {
                If (Test-KeyEscape $VKeyCode) { Return $null }
                If (Test-KeyEnter $VKeyCode)  { Break }

                # While there are 
                Do {
                    # Read key when callback and available key, or no callback at all
                    $VKeyCode = $null
                    If ($null -eq $Callback -or [Console]::KeyAvailable) {
                        $CurrentPress = Read-VKey
                        $VKeyCode     = $CurrentPress.VirtualKeyCode
                    }

                    If (Test-KeySpace $VKeyCode) { $CurrentSelection = Toggle-Selection $Position $CurrentSelection }

                    $Position = Get-PositionWithVKey -MenuItems $MenuItems -Position $Position -VKeyCode $VKeyCode

                    If (!$(Test-KeyEscape $VKeyCode)) {
                        [System.Console]::SetCursorPosition(0, [Math]::Max(0, [Console]::CursorTop - $MenuHeight))
                        $NeedRendering = $true
                    }
                } While ($null -eq $Callback -and [Console]::KeyAvailable);

                If ($NeedRendering) {
                    & $WriteMenu
                    $NeedRendering = $false
                }

                If ($Callback) {
                    & $Callback
                    Start-Sleep -Milliseconds 10
                }
            }
        } Finally {
            [System.Console]::CursorVisible = $true
        }

        If ($ReturnIndex -eq $false -and $null -ne $Position) {
            If ($MultiSelect) {
                If ($null -ne $CurrentSelection) { Return $MenuItems[$CurrentSelection] }
            } Else {
                Return $MenuItems[$Position]
            }
        } Else {
            If ($MultiSelect) {
                Return $CurrentSelection
            } Else {
                Return $Position
            }
        }
    }
}
