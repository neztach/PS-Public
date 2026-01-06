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
  <Grid>
    <Border x:Name="Root"
            CornerRadius="16"
            BorderBrush="#FF2A2A2A"
            BorderThickness="1"
            Padding="14">
      <Border.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#DD0F0F0F" Offset="0.0"/>
          <GradientStop Color="#DD080808" Offset="0.5"/>
          <GradientStop Color="#DD0B0B0B" Offset="1.0"/>
        </LinearGradientBrush>
      </Border.Background>
      <Border.Effect>
        <DropShadowEffect Color="#AA000000" BlurRadius="20" ShadowDepth="0" Opacity="0.8"/>
      </Border.Effect>
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

    <Border CornerRadius="16" IsHitTestVisible="False" Margin="1">
      <Border.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
          <GradientStop Color="#33FFFFFF" Offset="0.0"/>
          <GradientStop Color="#00FFFFFF" Offset="0.3"/>
          <GradientStop Color="#00FFFFFF" Offset="0.7"/>
          <GradientStop Color="#11000000" Offset="1.0"/>
        </LinearGradientBrush>
      </Border.Background>
    </Border>
  </Grid>
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
  $outer.Opacity = 0.95

  $ob = New-Object System.Windows.Media.SolidColorBrush($offOuter)
  $outer.Fill = $ob
  $outer.Effect = New-Object System.Windows.Media.Effects.BlurEffect
  $outer.Effect.Radius = 3
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
  $core.Effect = New-Object System.Windows.Media.Effects.DropShadowEffect
  $core.Effect.Color = [System.Windows.Media.Color]::FromRgb(255, 0, 0)
  $core.Effect.BlurRadius = 8
  $core.Effect.ShadowDepth = 0
  $core.Effect.Opacity = 0.8
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
  $aBoosted = [Math]::Pow($a, 0.7)
  $r = [byte](8 + 247*$aBoosted)
  $g = [byte](0  +  35*$aBoosted)
  [System.Windows.Media.Color]::FromRgb($r,$g,0)
}

function CoreColor([double]$a){
  $a = Clamp01 $a
  $aBoosted = [Math]::Pow($a, 0.6)
  $r = [byte](5 + 250*$aBoosted)
  $g = [byte](0  +  50*$aBoosted)
  [System.Windows.Media.Color]::FromRgb($r,$g,0)
}

$sw = [Diagnostics.Stopwatch]::StartNew()

$tail   = 10.0
$gamma  = 2.2
$period = 2.5

$script:lastPos = 0
$script:direction = 1
$script:ledIntensity = New-Object double[] $ledCount
for($i=0; $i -lt $ledCount; $i++){ $script:ledIntensity[$i] = 0.0 }

function PingPong01([double]$t01){
  if($t01 -lt 0.5){ return ($t01*2.0) }
  else { return (2.0 - $t01*2.0) }
}

$script:keystrokeCount = 0
$script:lastKeystrokeTime = 0
$script:pulseTime = -999

function PulseBorder {
  $script:pulseTime = $sw.Elapsed.TotalSeconds
  $root.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(255, 140, 0))
}

$renderHandler = $null
$renderHandler = [EventHandler]{
  try {
    $currentTime = $sw.Elapsed.TotalSeconds

    if($currentTime - $script:lastKeystrokeTime -ge 5) {
      SendAntiIdleKeys
      $script:keystrokeCount++
      $script:lastKeystrokeTime = $currentTime
      $hintText.Text = "Keystrokes: $($script:keystrokeCount) (last at $([int]$currentTime)s)"
      PulseBorder
    }

    $timeSincePulse = $currentTime - $script:pulseTime
    if($timeSincePulse -lt 0.5) {
      $fadeOut = 1.0 - ($timeSincePulse / 0.5)
      $redVal = [Math]::Max(42, [Math]::Min(255, 255 * $fadeOut))
      $orangeVal = [Math]::Max(42, [Math]::Min(255, 140 * $fadeOut))
      $root.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb([byte]$redVal, [byte]$orangeVal, 42))
    } elseif($timeSincePulse -ge 0.5 -and $timeSincePulse -lt 0.51) {
      $root.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromRgb(42, 42, 42))
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

    if($pos -gt $script:lastPos){ $script:direction = 1 }
    elseif($pos -lt $script:lastPos){ $script:direction = -1 }
    $script:lastPos = $pos

    for($i=0; $i -lt $ledCount; $i++){
      $script:ledIntensity[$i] *= 0.82
    }

    $leadIdx = [Math]::Round($pos)
    if($leadIdx -ge 0 -and $leadIdx -lt $ledCount) {
      $script:ledIntensity[$leadIdx] = 1.0
    }

    $trailStart = $leadIdx - $script:direction
    for($t=0; $t -lt 5; $t++){
      $trailIdx = $trailStart - ($t * $script:direction)
      if($trailIdx -ge 0 -and $trailIdx -lt $ledCount) {
        $trailIntensity = [Math]::Pow(1.0 - ($t / 5.0), 2.0) * 0.90
        if($trailIntensity -gt $script:ledIntensity[$trailIdx]) {
          $script:ledIntensity[$trailIdx] = $trailIntensity
        }
      }
    }

    for($i=0; $i -lt $ledCount; $i++){
      $intensity = $script:ledIntensity[$i]
      if($intensity -gt 0.02) {
        $outerBrushes[$i].Color = (OuterColor ($intensity * 0.75))
        $coreBrushes[$i].Color  = (CoreColor  ($intensity * 0.90))
      } else {
        $outerBrushes[$i].Color = $offOuter
        $coreBrushes[$i].Color  = $offCore
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
