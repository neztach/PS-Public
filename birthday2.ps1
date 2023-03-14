Function birthday2 {
    Param (
        [Parameter(Mandatory=$true,Position=0)][String]$date,
        [switch]$gui
    )
    $TempDate    = $date.split('/')
    $CurrentDate = Get-Date -Date (Get-Date).Date
    $StartDate   = (Get-Date -Month $TempDate[1] -Day $TempDate[0] -Year $TempDate[2])
    $DateDiff    = $CurrentDate - $StartDate

    $Years = $Months = $Days = 0
    $D     = $DateDiff.Days
    $CY    = $CurrentDate.Year
    $CM    = $CurrentDate.Month
    $SM    = $StartDate.Month

    While ($D -ge 366) {
        If (
            ($CurrentDate.Month -gt 2) -and 
            (([datetime]::IsLeapYear($CurrentDate.Year)) -eq $TRUE)
        ) {
            $DIY = 366
        } ElseIf (
            (([datetime]::IsLeapYear(($CY - $Years)) -eq $TRUE)) -and 
            (($Years -ne 0) -XOR 
                (($Years -eq 0) -and ($CM -eq 2))
            )
        ) {
            $DIY = 366
        } Else {
            $DIY = 365
        }
        $D     = $D - $DIY
        $Years = $Years + 1
    }

    $DTA = 0
    While ($D -ge 31) {
        $DTA = Switch ($SM) {
            12 {31}
            11 {30}
            10 {31}
            9  {30}
            8  {31}
            7  {31}
            6  {30}
            5  {31}
            4  {30}
            3  {31}
            2  {29}
            1  {31}
        }

        If (([datetime]::IsLeapYear(($CY - $Years)) -eq $TRUE) -and 
            ($SM -eq 2)
        ){
            $DTA = $DTA + 1
        }

        If ($SM -lt 12){$SM = $SM + 1} Else {$SM = 1}

        $D      = $D - $DTA
        $Months = $Months + 1	
    }

    $num    = @{ForegroundColor = 'Green'}
    $Days   = $D
    $tDays  = '{0:N0}' -f $DateDiff.Days
    $tWeeks = '{0:N0}' -f [int](($DateDiff.Days) / 7)
    $out    = ("You have been alive for {0} years {1} months and {2} days. `n`nYou are currently on your {3}th day`n...or roughly your {4}th week." -f $Years, $Months, $Days, ($tDays), ($tWeeks))
    If ($gui){
        [System.Windows.MessageBox]::Show($out)
    } Else {
        $out -split ' ' | Foreach-Object {
            If ($_ -match '([0-9])'){
                Write-Host ('{0} ' -f $_) -NoNewLine @num
            } Else {
                Write-Host ('{0} ' -f $_) -NoNewLine
            }
        }
    }
}

$s1 = Read-Host -Prompt "Enter your birth date (dd/MM/yyyy)"
birthday2 $s1 -gui
