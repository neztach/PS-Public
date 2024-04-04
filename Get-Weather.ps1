<#
.SYNOPSIS
	Lists the weather report
.DESCRIPTION
	This PowerShell script lists the hourly weather report in a nice table.
.PARAMETER Location
	Specifies the location to use (determined automatically per default)
.EXAMPLE
	PS> ./list-weather.ps1
	TODAY   🌡°C  ☂️mm  💧  💨km/h ☀️UV  ☁️  👁km  at Munich,Bayern
	0°°   -2°   0.0   93%   ↗ 6   1    21%  10  🌙 clear
	...
#>

Param (
    [string]$Location = "",
    [switch]$today
) # empty means determine automatically

Function GetDescription {
    Param ([string]$text)
	    Switch ($text.trim()) {
	    "Blizzard"			                            { return "❄️ blizzard ⚠️" }
	    "Blowing snow"			                        { return "❄️ blowing snow ⚠️" }
	    "Clear"				                            { return "🌙 clear" }
	    "Cloudy"			                            { return "☁️ cloudy" }
	    "Fog"				                            { return "🌫  fog" }
	    "Freezing fog"			                        { return "🌫  freezing fog" }
	    "Heavy snow"			                        { return "❄️ heavy snow ⚠️" }
	    "Light drizzle"			                        { return "💧 light drizzle" }
	    "Light freezing rain"		                    { return "💧 light freezing rain ⚠️" }
	    "Light rain"			                        { return "💧 light rain" }
	    "Light rain shower"		                        { return "💧 light rain shower" }
	    "Light sleet"			                        { return "❄️ light sleet" }
	    "Light sleet showers"		                    { return "❄️ light sleet showers" }
	    "Light snow"			                        { return "❄️ light snow" }
	    "Light snow showers"		                    { return "❄️ light snow showers" }
	    "Moderate or heavy freezing rain"               { return "💧 moderate or heavy freezing rain ⚠️" }
	    "Moderate or heavy sleet"	                    { return "❄️ moderate or heavy sleet ⚠️" }
	    "Moderate or heavy rain shower"                 { return "💧 moderate or heavy rain shower ⚠️" }
	    "Moderate or heavy snow showers"                { return "❄️ moderate or heavy snow showers ⚠️" }
	    "Moderate or heavy snow in area with thunder"   { return "❄️ moderate or heavy snow with thunder ⚠️" }
	    "Moderate rain"			                        { return "💧 moderate rain" }
	    "Moderate rain at times"	                    { return "💧 moderate rain at times" }
	    "Moderate snow"			                        { return "❄️ moderate snow" }
	    "Mist"				                            { return "🌫  misty" }
	    "Overcast"			                            { return "☁️ overcast" }
	    "Partly cloudy"			                        { return "⛅️ partly cloudy" }
	    "Patchy heavy snow"		                        { return "❄️ patchy heavy snow ⚠️" }
	    "Patchy light drizzle"     	                    { return "💧 patchy light drizzle" }
	    "Patchy light rain"     	                    { return "💧 patchy light rain" }
	    "Patchy light rain with thunder"                { return "💧 patchy light rain with thunder" }
	    "Patchy light snow"		                        { return "❄️ patchy light snow" }
	    "Patchy moderate snow"		                    { return "❄️ patchy moderate snow" }
	    "Patchy rain possible"  	                    { return "💧 patchy rain possible" }
	    "Patchy rain nearby"		                    { return "💧 patchy rain nearby" }
	    "Patchy sleet nearby"		                    { return "❄️ patchy sleet nearby" }
	    "Patchy snow possible"  	                    { return "❄️ patchy snow possible" }
	    "Sunny"				                            { return "☀️ sunny" }
	    "Thundery outbreaks possible"	                { return "⚡️ thundery outbreaks possible" }
	    default				                            { return "$Text" }
	}
}

Function GetWindDir     {
    Param ([string]$Text)
	Switch($Text) {
	    "NW"	{ return "↘" }
	    "NNW"	{ return "↓" }
	    "N"	    { return "↓" }
	    "NNE"	{ return "↓" }
	    "NE"	{ return "↙" }
	    "ENE"	{ return "←" }
	    "E"	    { return "←" }
	    "ESE"	{ return "←" }
	    "SE"	{ return "↖" }
	    "SSE"	{ return "↑" }
	    "S"	    { return "↑" }
	    "SSW"	{ return "↑" }
	    "SW"	{ return "↗" }
	    "WSW"	{ return "→" }
	    "W"	    { return "→" }
	    "WNW"	{ return "→" }
	    default { return "$Text" }
	}
}

Function Convert-Hours([int]$c) {
    $toReturn = $c.ToString("0000")
    return $toReturn
}

Try {
    $Gr       = @{ForegroundColor = 'Green'}
	Write-Progress "Loading weather data from http://wttr.in ..."
	$Weather  = (
        Invoke-WebRequest -URI http://wttr.in/${Location}?format=j1 -userAgent "curl" -useBasicParsing
    ).Content | ConvertFrom-Json
	Write-Progress -completed "."
	$Area     = $Weather.nearest_area.areaName.value
	$Region   = $Weather.nearest_area.region.value
	#$Country  = $Weather.nearest_area.country.value	
	[int]$Day = 0

    If ($today) {
        #$Array = $Weather.weather.hourly | Select-Object -First 8 | Select-Object *,@{n='datetime';e={[datetime]::ParseExact(((Convert-Hours $_.time) -replace '(.+)(.{2})$', '$1:$2'), 'HH:mm', $null)}}
	    ForEach ($Hourly in ($Weather.weather.hourly | Select-Object -First 8)) {
		    $Hour      = $Hourly.time / 100
		    $Temp      = $(($Hourly.tempF.toString()).PadLeft(3))
		    $Precip    = $Hourly.precipInches
		    $Humidity  = $(($Hourly.humidity.toString()).PadLeft(3))
		    $WindSpeed = $(($Hourly.windspeedMiles.toString()).PadLeft(2))
		    $WindDir   = GetWindDir $Hourly.winddir16Point
		    $UV        = $Hourly.uvIndex
		    $Clouds    = $(($Hourly.cloudcover.toString()).PadLeft(3))
		    $Visib     = $(($Hourly.visibilityMiles.toString()).PadLeft(2))
		    $Desc      = GetDescription $Hourly.weatherDesc.value
		    If ($Hour -eq 0) {
			    If ($Day -eq 0) {
				    Write-Host "TODAY  🌡 °F  ☂️ in   💧    💨 mph  ☀️ UV    ☁️   👁  mi  at $Area, $Region" @Gr
			    }
			    $Day++
		    }
		    "$(($Hour.toString()).PadLeft(2))°°  $Temp°    $Precip   $Humidity%   $($WindDir)  $WindSpeed    $UV     $Clouds%   $Visib     $Desc"
	    }
    } Else {
	    ForEach ($Hourly in $Weather.weather.hourly) {
		    $Hour      = $Hourly.time / 100
		    $Temp      = $(($Hourly.tempF.toString()).PadLeft(3))
		    $Precip    = $Hourly.precipInches
		    $Humidity  = $(($Hourly.humidity.toString()).PadLeft(3))
		    #$Pressure  = $Hourly.pressure
		    $WindSpeed = $(($Hourly.windspeedMiles.toString()).PadLeft(2))
		    $WindDir   = GetWindDir $Hourly.winddir16Point
		    $UV        = $Hourly.uvIndex
		    $Clouds    = $(($Hourly.cloudcover.toString()).PadLeft(3))
		    $Visib     = $(($Hourly.visibilityMiles.toString()).PadLeft(2))
		    $Desc      = GetDescription $Hourly.weatherDesc.value
		    If ($Hour -eq 0) {
			    If ($Day -eq 0) {
				    Write-Host "TODAY  🌡 °F  ☂️ in   💧    💨 mph  ☀️ UV    ☁️   👁  mi  at $Area, $Region" @Gr
			    } ElseIf ($Day -eq 1) {
				    $Date = (Get-Date).AddDays(1)
				    [string]$Weekday = $Date.DayOfWeek
				    Write-Host "$($Weekday.toUpper())" @Gr
			    } Else {
				    $Date = (Get-Date).AddDays(2)
				    [string]$Weekday = $Date.DayOfWeek
				    Write-Host "$($Weekday.toUpper())" @Gr
			    }
			    $Day++
		    }
		    "$(($Hour.toString()).PadLeft(2))°°  $Temp°    $Precip   $Humidity%   $($WindDir) $WindSpeed    $UV     $Clouds%   $Visib     $Desc"
	    }
    }
	exit 0 # success
} Catch {
	"⚠️ Error in line $($_.InvocationInfo.ScriptLineNumber): $($Error[0])"
	exit 1
}
