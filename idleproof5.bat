@echo off

set "seconds=%~1"
if "%seconds%"=="" set "seconds=0"

rem Extract and execute PowerShell portion from this file
start /b "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
  "$argSec=%seconds%; " ^
  "$ps = (Get-Content '%~f0' -Raw) -replace '(?s)^.*###POWERSHELL_START###\r?\n','' -replace '\r?\n###POWERSHELL_END###.*$',''; " ^
  "$ps = $ps -replace 'SECONDS_PARAM',$argSec; " ^
  "Invoke-Expression $ps"

exit /b

###POWERSHELL_START###
[int]$Seconds = SECONDS_PARAM

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

try { $wshell = New-Object -ComObject Wscript.Shell } catch { $wshell = $null }
function SendAntiIdleKeys {
  if($wshell) {
    try {
      $wshell.SendKeys(' ')
      $wshell.SendKeys('{BACKSPACE}')
    } catch {}
  }
}

$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        WindowStyle="None"
        ResizeMode="NoResize"
        AllowsTransparency="True"
        Background="Transparent"
        Topmost="True"
        ShowInTaskbar="False"
        Width="540" Height="110"
        WindowStartupLocation="CenterScreen">
  <Border x:Name="Root"
          CornerRadius="16"
          Background="#FF0B0B0B"
          BorderBrush="#FF2A2A2A"
          BorderThickness="1"
          Padding="14">
    <Grid>
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="10"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>

      <DockPanel Grid.Row="0" LastChildFill="False">
        <TextBlock x:Name="TimeText"
                   FontFamily="Consolas"
                   FontSize="28"
                   Foreground="#FFEDEDED"
                   Text="00:00:00"
                   DockPanel.Dock="Left"/>
        <TextBlock x:Name="HintText"
                   FontFamily="Segoe UI"
                   FontSize="12"
                   Foreground="#FF9A9A9A"
                   Text="drag to move - focus lost = close"
                   Margin="12,10,0,0"
                   DockPanel.Dock="Right"/>
      </DockPanel>

      <Border Grid.Row="2"
              CornerRadius="12"
              Background="#FF000000"
              BorderBrush="#FF1F1F1F"
              BorderThickness="1"
              Padding="10,6">
        <Grid Height="44" VerticalAlignment="Center">
          <UniformGrid x:Name="LedGrid" Rows="1" HorizontalAlignment="Stretch" VerticalAlignment="Center"/>
        </Grid>
      </Border>
    </Grid>
  </Border>
</Window>
'@

$xml = New-Object System.Xml.XmlDocument
$xml.LoadXml($xaml)
$reader = New-Object System.Xml.XmlNodeReader $xml
$win = [System.Windows.Markup.XamlReader]::Load($reader)

$root     = $win.FindName('Root')
$timeText = $win.FindName('TimeText')
$hintText = $win.FindName('HintText')
$ledGrid  = $win.FindName('LedGrid')

$root.Add_MouseLeftButtonDown({ try { $win.DragMove() } catch {} })

$allowDeactivateAt = [DateTime]::UtcNow.AddMilliseconds(400)
$win.Add_Deactivated({ if([DateTime]::UtcNow -ge $allowDeactivateAt){ $win.Close() } })

$win.Topmost = $true
$win.Add_Loaded({
  $win.WindowState = 'Normal'
  $null = $win.Activate()
  $null = $win.Focus()
  $win.Topmost = $false
  $win.Topmost = $true
})

$ledCount = 32
$ledGrid.Columns = $ledCount

$gap = 2
$outerH = 30
$coreH  = 10
$cornerOuter = 6
$cornerCore  = 4

$offOuter = [System.Windows.Media.Color]::FromRgb(12, 0, 0)
$offCore  = [System.Windows.Media.Color]::FromRgb(3, 0, 0)

$outerBrushes = New-Object System.Collections.Generic.List[System.Windows.Media.SolidColorBrush]
$coreBrushes  = New-Object System.Collections.Generic.List[System.Windows.Media.SolidColorBrush]

for($i=0; $i -lt $ledCount; $i++){

  $cell = New-Object System.Windows.Controls.Grid
  $cell.Margin = New-Object System.Windows.Thickness($gap,0,$gap,0)
  $cell.VerticalAlignment = 'Center'

  $outer = New-Object System.Windows.Shapes.Rectangle
  $outer.Height  = $outerH
  $outer.RadiusX = $cornerOuter
  $outer.RadiusY = $cornerOuter
  $outer.VerticalAlignment = 'Center'
  $outer.HorizontalAlignment = 'Stretch'
  $outer.Opacity = 1.0

  $ob = New-Object System.Windows.Media.SolidColorBrush($offOuter)
  $outer.Fill = $ob
  $outerBrushes.Add($ob) | Out-Null

  $core = New-Object System.Windows.Shapes.Rectangle
  $core.Height  = $coreH
  $core.RadiusX = $cornerCore
  $core.RadiusY = $cornerCore
  $core.VerticalAlignment = 'Center'
  $core.HorizontalAlignment = 'Stretch'
  $core.Margin = New-Object System.Windows.Thickness(3,0,3,0)

  $cb = New-Object System.Windows.Media.SolidColorBrush($offCore)
  $core.Fill = $cb
  $coreBrushes.Add($cb) | Out-Null

  $sheen = New-Object System.Windows.Shapes.Rectangle
  $sheen.Height = [Math]::Max(4, [Math]::Floor($outerH * 0.22))
  $sheen.RadiusX = $cornerOuter
  $sheen.RadiusY = $cornerOuter
  $sheen.VerticalAlignment = 'Top'
  $sheen.HorizontalAlignment = 'Stretch'
  $sheen.Margin = New-Object System.Windows.Thickness(2,2,2,0)
  $sheen.Opacity = 0.20
  $sheen.Fill = New-Object System.Windows.Media.SolidColorBrush([System.Windows.Media.Color]::FromRgb(255,255,255))

  $null = $cell.Children.Add($outer)
  $null = $cell.Children.Add($core)
  $null = $cell.Children.Add($sheen)

  $null = $ledGrid.Children.Add($cell)
}

function Clamp01([double]$x){ [Math]::Max(0.0, [Math]::Min(1.0, $x)) }

function OuterColor([double]$a){
  $a = Clamp01 $a
  $r = [byte](12 + 235*$a)
  $g = [byte](0  +  45*$a)
  [System.Windows.Media.Color]::FromRgb($r,$g,0)
}

function CoreColor([double]$a){
  $a = Clamp01 $a
  $r = [byte](10 + 245*$a)
  $g = [byte](0  +  85*$a)
  [System.Windows.Media.Color]::FromRgb($r,$g,0)
}

$sw = [Diagnostics.Stopwatch]::StartNew()

$tail   = 6.0
$gamma  = 1.8
$period = 2.93

function PingPong01([double]$t01){
  if($t01 -lt 0.5){ return ($t01*2.0) }
  else { return (2.0 - $t01*2.0) }
}

$script:keystrokeCount = 0
$script:lastKeystrokeTime = 0
$renderHandler = $null
$renderHandler = [EventHandler]{
  try {
    $currentTime = $sw.Elapsed.TotalSeconds
    if($currentTime - $script:lastKeystrokeTime -ge 5) {
      SendAntiIdleKeys
      $script:keystrokeCount++
      $script:lastKeystrokeTime = $currentTime
      $hintText.Text = "Keystrokes: $($script:keystrokeCount) (last at $([int]$currentTime)s)"
    }

    if($Seconds -gt 0 -and $sw.Elapsed.TotalSeconds -ge $Seconds){
      [System.Windows.Media.CompositionTarget]::remove_Rendering($renderHandler)
      $win.Close()
      return
    }

    $t = $sw.Elapsed
    $timeText.Text = ('{0:D2}:{1:D2}:{2:D2}' -f $t.Hours,$t.Minutes,$t.Seconds)

    $phase = ($t.TotalSeconds % $period) / $period
    $p = PingPong01 $phase
    $pos = $p * ($ledCount - 1)

    for($i=0; $i -lt $ledCount; $i++){
      $d = [Math]::Abs($i - $pos)

      if($d -gt $tail){
        $outerBrushes[$i].Color = $offOuter
        $coreBrushes[$i].Color  = $offCore
      } else {
        $a = [Math]::Pow(1.0 - ($d / $tail), $gamma)

        $outerBrushes[$i].Color = (OuterColor ($a * 0.85))
        $coreBrushes[$i].Color  = (CoreColor  ($a * 1.00))
      }
    }

  } catch {
    [System.Windows.Media.CompositionTarget]::remove_Rendering($renderHandler)
    $hintText.Text = ('ERROR: ' + $_.Exception.Message)
  }
}

[System.Windows.Media.CompositionTarget]::add_Rendering($renderHandler)

$null = $win.ShowDialog()
###POWERSHELL_END###
