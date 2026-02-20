Function Write-Color {
    <#
        .SYNOPSIS
        A lightweight version of PSWriteColor for multi-colored single lines.
        .EXAMPLE
        Write-Color -Text "Blood: ", "Lethal" -Color White, Red
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true,HelpMessage='Text(s)', Position=0)]
        [string[]]$Text,

        [Parameter(Mandatory=$false, Position=1)]
        [ConsoleColor[]]$Color = 'White',

        [Switch]$NoNewLine
    )

    For ($i = 0; $i -lt $Text.Count; $i++) {
        ### If there are more text segments than colors, it loops back to the first color
        $CurrentColor = $Color[$i % $Color.Count]
        
        Write-Host -Object $Text[$i] -ForegroundColor $CurrentColor -NoNewline
    }

    If (-not $NoNewLine) { Write-Host '' }
}

Function Get-WeightTranslation {
    <#
        .SYNOPSIS
        Translates modern and historical mass units into a standardized Imperial output.
        .DESCRIPTION
        Accepts Kilograms or Stone and calculates the equivalent in Pounds and Metric.
        1 Stone = 14 Lbs.
        1 Kg    = 2.20462 Lbs.
    #>
    Param (
        [Parameter(ParameterSetName = 'Metric')]
        [double]$Kilograms,

        [Parameter(ParameterSetName = 'Historical')]
        [double]$Stone
    )

    $totalLbs = 0

    If ($PSCmdlet.ParameterSetName -eq 'Metric') {
        $totalLbs = $Kilograms * 2.20462
    } Else {
        $totalLbs = $Stone * 14
    }

    ### Internal math for the breakdown
    $outStone = [Math]::Floor($totalLbs / 14)
    $outLbs   = [Math]::Round($totalLbs % 14, 2)
    $outKg    = [Math]::Round(($totalLbs / 2.20462), 2)

    Write-Host "`n--- Mass Standardization Report ---" -ForegroundColor Gray
    Write-Color 'Standardized Lbs: ', ([Math]::Round($totalLbs, 2)), ' lbs' -C White, Yellow, White
    Write-Color 'Stone Breakdown : ', $outStone, ' st ', $outLbs, ' lbs' -C White, Cyan, White, Cyan, White
    Write-Color 'Metric Equiv    : ', $outKg, ' kg' -C White, Green, White

    ### Return an object for use in other functions
    return [PSCustomObject]@{
        TotalLbs = [Math]::Round($totalLbs, 2)
        TotalKg  = $outKg
        Stone    = $outStone
        RemLbs   = $outLbs
    }
}

Function Get-MetricConversionModern {
    <#
        .SYNOPSIS
        Converts Imperial units to Metric for use in Modern functions.
        .DESCRIPTION
        Translates Pounds to Kilograms, Fahrenheit to Celsius, and Inches to Centimeters.
    #>
    $val = 0

    Write-Host "`n--- Unit Conversion Utility ---" -ForegroundColor Gray
    Write-Host '1. Weight (Lbs to Kg)'
    Write-Host '2. Temperature (F to C)'
    Write-Host '3. Length (Inches to Cm)'
    
    $choice = Read-Host -Prompt 'Select conversion type (1-3)'

    Switch ($choice) {
        '1' {
            $lbs = Read-Host -Prompt 'Enter weight in lbs'
            If ([double]::TryParse($lbs, [ref]$val)) {
                $kg = [Math]::Round(($val / 2.20462), 2)
                Write-Color -Text 'Result: ', (('{0} kg' -f $kg)) -Color White, Cyan
            }
        }
        '2' {
            $f = Read-Host -Prompt 'Enter temp in Fahrenheit'
            If ([double]::TryParse($f, [ref]$val)) {
                $c = [Math]::Round((($val - 32) * (5/9)), 2)
                Write-Color -Text 'Result: ', (('{0} °C' -f $c)) -Color White, Cyan
            }
        }
        '3' {
            $in = Read-Host -Prompt 'Enter length in inches'
            If ([double]::TryParse($in, [ref]$val)) {
                $cm = [Math]::Round(($val * 2.54), 2)
                Write-Color -Text 'Result: ', (('{0} cm' -f $cm)) -Color White, Cyan
            }
        }
        Default { Write-Error -Message 'Invalid Selection.' }
    }
}

Function Get-OfficialDropLength {
    <#
        .SYNOPSIS
        Calculates the drop length based on the 1913 Official Table of Drops Formula
        .DESCRIPTION
        Samuel Haughton, M.D., F.R.S.
        Haughton's formula for the "long drop" based on the equivalence with the energy 
        of 1 ton falling through 1 foot: 
        "Divide the weight of the patient in pounds into 2240 and the quotient will give the 
        length of the long drop in feet" - being a reference to the length of rope. 

        Haughton's ruminations on the subject included calculations of the method and force 
        needed to hang the unfaithful handmaids of Penelope who dallied with the suitors in 
        Homer's The Odyssey.

        The official executioner for Ireland for about 20 years after 1868 was an ex-cobbler 
        called Marwood.
        Marwood is credited with the practice of putting the knot of the noose just under the 
        left ear and he maintained that jerking the head sharply to the right was more effectual 
        to the killing than the length of the drop.

        How the match works:
        1. Energy Constant: The "Official Table of Drops" (1913 revision) was 
           designed to provide a constant terminal energy of 1,000 foot-pounds.
        2. The Calculation: If a person weighs 150 lbs, the math is 1000 / 150 = 6.66 feet.
        3. Conversion: The script takes the decimal remainder (.66) and multiplies 
           it by 12 to provide the "inches" portion of the output (e.g. 6' 8").
        .LINK
        https://en.wikipedia.org/wiki/Official_Table_of_Drops
    #>
    ### Initialize the variable for weight
    $weight = 0

    ### Prompt user for weight
    $weightString = Read-Host -Prompt 'Enter weight in lbs'

    ### Validate input is a number
    If ([double]::TryParse($weightString, [ref]$weight)) {
        If ($weight -le 0) {
            Write-Error -Message 'Weight must be greater than zero.'
            return
        }

        ### Formula: Drop (ft) = Energy  (1000 ft-lbs) / Weight (lbs)
        $totalFeet = 1000 / $weightString

        ### Calculate Feet and Inches
        $feet      = [Math]::Floor($totalFeet)
        $rawInches = ($totalFeet - $feet) * 12
        
        ### Rounding logic for nearest half-inch:
        ### (Value * 2) -> Round -> / 2
        $inches = [Math]::Round($rawInches * 2, [MidpointRounding]::AwayFromZero) / 2

        ### Logic to handle rollover (e.g. if 11.2 inches rounds up to 12 inches)
        If ($inches -eq 12) {
            $feet  += 1
            $inches = 0
        }

        ### Output Formatting
        Write-Host "`n--- Calculation Results ----" -ForegroundColor Gray
        Write-Color -Text 'Input Weight   : ', ([string]$weight + ' lbs') -Color Magenta, Cyan
        Write-Color -Text 'Calculated Drop: ', $feet, ' feet ', $inches, ' inches ', '(', ([string]$feet + "' " + [string]$inches + '"'), ')' -NoNewLine -Color Magenta, Cyan, Yellow, Cyan, Yellow, Gray, Yellow, Gray
    } Else {
        Write-Error -Message 'Invalid input.  Please enter a numerical value for weight.'
    }
}

Function Get-OfficialDropLengthModern {
    <#
        .SYNOPSIS
        Calculates the drop length based on modern judicial tables (Metric).
    #>
    $weightKg  = 0
    $weightStr = Read-Host -Prompt 'Enter subject weight (kg)'

    If ([double]::TryParse($weightStr, [ref]$weightKg)) {
        If ($weightKg -le 0) {
            Write-Error -Message 'Weight must be greater than zero.'
            return
        }

        ### Convert Kg to Lbs for the energy formula
        $weightLbs   = $weightKg * 2.20462

        ### Modern Energy Constant: 850 ft-lbs
        $totalFeet   = 850 / $weightLbs

        ### Convert to Centimeters and Total Inches
        $totalCm     = [Math]::Round(($totalFeet * 30.48), 1)
        $totalInches = [Math]::Round(($totalFeet * 12), 2)

        ### Breakdown for Imperial Reference
        $feet        = [Math]::Floor($totalFeet)
        $inches      = [Math]::Round(($totalInches - ($feet * 12)), 1)

        Write-Host "`n--- Modern Judicial Drop Calculation ---" -ForegroundColor Gray
        Write-Color 'Input Weight   : ', ("$weightKg kg "), '(', ([Math]::Round($weightLbs, 2)), ' lbs)' -C Magenta, Cyan, Gray, Yellow, Gray
        
        Write-Color 'Calculated Drop: ', ("$totalCm cm") -C Magenta, Yellow
        
        ### Using the totalInches variable for a more detailed Imperial reference
        Write-Color 'Imperial Ref   : ', ("$feet' $inches`" "), '(', ("$totalInches total inches"), ')' -C Gray, Yellow, Gray, Cyan, Gray
        
        Write-Host "Protocol: 850 ft-lb Energy Constant | Metric Precision" -ForegroundColor DarkGray
    } Else {
        Write-Error -Message 'Invalid input. Please enter a numerical value for weight in kg.'
    }
}

Function Get-CasperDecompositionRatio {
    <#
        .SYNOPSIS
        Calculates equivalent decomposition stages based on Casper's Dictum.
        .DESCRIPTION
        Johann Ludwig Casper (1796-1864) posited that the rate of decomposition 
        follows a ratio of 1:2:8 based on the medium of exposure.

        His "Dictum" is a classic forensic rule of thumb regarding how long a body 
        takes to reach a certain stage of decomposition based on the medium it is 
        in (Air vs. Water vs. Earth).

        The Math: 
        1 week in open air = 2 weeks in water = 8 weeks buried in earth.
    #>
    Param (
        [Parameter(Mandatory,HelpMessage='Weeks exposed to air')]
        [ValidateRange(1, 52)]
        [int]$WeeksInAir
    )

    $waterWeeks = $WeeksInAir * 2
    $earthWeeks = $WeeksInAir * 8

    Write-Color -Text "`n--- Casper's Dictum: Decomposition Parity ---", 'If a body has been in open air for ', ('{0} weeks' -f $WeeksInAir) -Color Gray, White, Yellow
    Write-Color -Text "`nIt would reach the same stage in:", '  • Water : ', ('{0} weeks' -f $waterWeeks), '  • Earth : ', ('{0} weeks' -f $earthWeeks) -Color White, White, Cyan, White, Green
}

Function Get-TimeOfDeath {
    <#
        .SYNOPSIS
        Estimates hours since death using Glaister's Equation (Algor Mortis).
        .DESCRIPTION
        The formula assumes the body loses roughly 1.5 degrees Fahrenheit per hour 
        under standard conditions.

        Glaister's Equation (Time of Death)
        This is a historical formula used to estimate the "Post-Mortem Interval" (PMI) based on the cooling 
        of the body (Algor Mortis). While modern forensics uses more complex models (like the Henssge Nomogram), 
        Glaister's is the "classic" scriptable version.

        The Math:
                            98.4 - Rectal Temperature​​
        Hours since death = -------------------------​
                                    1.5
    #>
    $temp       = 0
    $tempString = Read-Host -Prompt 'Enter body core temperature (Fahrenheit)'
    
    If ([double]::TryParse($tempString, [ref]$temp)) {
        $averageBodyTemp = 98.4
        
        If ($temp -gt $averageBodyTemp) {
            Write-Warning -Message 'Temperature is above average living body heat. Subject may be feverish or still alive.'
            return
        }

        $hoursSinceDeath = ($averageBodyTemp - $temp) / 1.5
        $hours           = [Math]::Floor($hoursSinceDeath)
        $minutes         = [Math]::Round(($hoursSinceDeath - $hours) * 60)

        Write-Host "`n--- Algor Mortis Estimate ---" -ForegroundColor Gray
        Write-Color -Text 'Estimated PMI: ', ('{0} hours, {1} minutes' -f $hours, $minutes) -Color White, Red
        Write-Host 'Note: Ambient temperature and body mass may vary results.' -ForegroundColor DarkGray
    } Else {
        Write-Error -Message 'Please enter a valid numerical temperature.'
    }
}

Function Get-TimeOfDeathModern {
    <#
        .SYNOPSIS
        Modern Post-Mortem Interval (PMI) estimation using Celsius and Corrective Factors.
        .DESCRIPTION
        Replaces Glaister's Equation with a modern simplified cooling model.
        Standard body temp: 37.2°C. 
        Corrective Factors (Cf): 1.0 (Naked), 1.5 (Clothed), 0.5 (In Water).
    #>
    $temp    = 0
    $amb     = 0
    $tempStr = Read-Host -Prompt 'Enter body core temperature (Celsius)'
    $ambStr  = Read-Host -Prompt 'Enter ambient temperature (Celsius)'
    $weight  = Read-Host -Prompt 'Enter body weight (kg)'
    
    If ([double]::TryParse($tempStr, [ref]$temp) -and [double]::TryParse($ambStr, [ref]$amb)) {
        $standardTemp = 37.2
        $cf = 1.5 # Default for clothed body
        
        ### Simplified Henssge-style logic: Cooling is slower for heavier bodies
        ### PMI = ((37.2 - Temp) / (1.5 * Cf)) * (Weight / 70)^0.625
        $tempDiff = $standardTemp - $temp
        $massFactor = [Math]::Pow(($weight / 70), 0.625)
        $hoursSinceDeath = ($tempDiff / (1.5 * $cf)) * $massFactor
        
        $hours   = [Math]::Floor($hoursSinceDeath)
        $minutes = [Math]::Round(($hoursSinceDeath - $hours) * 60)

        Write-Host "`n--- Modern Algor Mortis Estimate ---" -ForegroundColor Gray
        Write-Color -Text 'Estimated PMI: ', (('{0} hours, {1} minutes' -f $hours, $minutes)) -Color White, Red
        Write-Host 'Model: Sigmoid Cooling (Cf 1.5) | Metric Standard' -ForegroundColor DarkGray
    }
}

Function Get-BurnSeverity {
    <#
        .SYNOPSIS
        Calculates Total Body Surface Area (TBSA) using the Rule of Nines.
        .DESCRIPTION
        The Rule of Nines (Burn Severity)
        Used by emergency victorian-era medicine (and still used today) to quickly calculate the 
        percentage of the body affected by burns. It divides the body into sections of 9%.
    #>
    Write-Host '--- Burn Area Calculator ---' -ForegroundColor Red
    $head       = [int](Read-Host -Prompt 'Head & Neck (1 for yes, 0 for no)') * 9
    $torsoFront = [int](Read-Host -Prompt 'Torso Front (%) [0, 9, or 18]')
    $arms       = [int](Read-Host -Prompt 'Number of arms affected') * 9
    $legs       = [int](Read-Host -Prompt 'Number of legs affected') * 18

    $total      = $head + $torsoFront + $arms + $legs

    Write-Host "`nTotal Body Surface Area Affected: " -NoNewLine
    Write-Host ('{0}%' -f $total) -ForegroundColor Yellow -BackgroundColor Black
}

Function Get-BurnSeverityModern {
    <#
        .SYNOPSIS
        Calculates TBSA using Lund-Browder age-adjusted logic.
    #>
    $age = [int](Read-Host -Prompt 'Enter subject age')
    
    ### Age-adjusted Head % (Approximate)
    If ($age -le 1) {
        $headVal = 19
    } ElseIf ($age -le 5) {
        $headVal = 15
    } ElseIf ($age -le 10) {
        $headVal = 11
    } Else {
        $headVal = 9
    }

    $isHead = [int](Read-Host -Prompt 'Head affected? (1 for yes, 0 for no)')
    $arms   = [int](Read-Host -Prompt 'Number of arms affected') * 7
    $legs   = [int](Read-Host -Prompt 'Number of legs affected') * 9.5
    $torso  = [int](Read-Host -Prompt 'Torso % (Front=13, Back=13)')

    $total = ($isHead * $headVal) + $arms + $legs + $torso

    Write-Host "`n--- Modern TBSA Assessment (Lund-Browder) ---" -ForegroundColor Gray
    Write-Color -Text 'Total Surface Area: ', (('{0} %' -f $total)) -Color White, Yellow
    Write-Host ('Age-adjusted Head Value: {0}%' -f $headVal) -ForegroundColor DarkGray
}

Function Get-KineticLethality {
    <#
        .SYNOPSIS
        Calculates if a projectile meets the historical 58 ft-lb lethality threshold.
        .DESCRIPTION
        The Lethal Striking Energy (Early Ballistics)
        In the 19th century, military surgeons and engineers debated the "Minimum Lethal Energy" required to 
        disable an opponent. A common historical benchmark (often attributed to Russian or Prussian military studies) 
        was that 58 foot-pounds of kinetic energy was sufficient to perforate human skin and bone.

        The Math: KE = 1/2 ​* mass * velocity^2
        Simplified for Imperial units:
                  Weight in grains * Velocity^2
        Energy = -----------------------------
                           450, 436
    #>
    $grains      = 0
    $velocity    = 0
    $grainString = Read-Host -Prompt 'Enter projectile weight (grains)'
    $velString   = Read-Host -Prompt 'Enter velocity (feet per second)'

    If ([double]::TryParse($grainString, [ref]$grains) -and [double]::TryParse($velString, [ref]$velocity)) {
        
        ### PEMDAS: Exponents first, then Multiplication, then Division
        ### Energy = (Grains * (Velocity^2)) / 450436
        $vSquared = [Math]::Pow($velocity, 2)
        $energy   = ($grains * $vSquared) / 450436
        
        $roundedEnergy = [Math]::Round($energy, 2)

        Write-Host "`n--- Ballistic Energy Report ---" -ForegroundColor Gray
        Write-Color -Text 'Kinetic Energy: ', (('{0} ft-lbs' -f $roundedEnergy)) -Color White, Yellow

        If ($energy -ge 58) {
            Write-Color -Text 'Status: ', 'LETHAL' -Color White, Red
            Write-Host 'Exceeds the 19th-century military threshold for bone penetration.' -ForegroundColor DarkGray
        } Else {
            Write-Color -Text 'Status: ', 'NON-LETHAL' -Color White, Green
            Write-Host 'Likely to cause contusion only.' -ForegroundColor DarkGray
        }
    }
}

Function Get-ExsanguinationLimit {
    <#
        .SYNOPSIS
        Estimates blood volume and thresholds for hemorrhagic shock.
        .DESCRIPTION
        The Exsanguination Threshold (Shock)
        This function calculates the volume of blood loss required to enter different stages of hemorrhagic shock. 
        It is based on the medical "Rule of Thumb" that the average human has approximately 70ml of blood per kilogram of body weight.

        The Math: 
         * Stage II (Anxiety/Tachycardia): 15-30% loss.
         Stage IV (Lethal/Exsanguination): >40% loss.
    #>
    $lbs       = 0
    $weightLbs = Read-Host -Prompt 'Enter subject weight (lbs)'
    
    If ([double]::TryParse($weightLbs, [ref]$lbs)) {
        $kg            = $lbs / 2.20462
        $totalVolumeML = $kg * 70 # Average 70ml per kg
        $totalLiters   = [Math]::Round($totalVolumeML / 1000, 2)
        
        $class4Loss    = [Math]::Round($totalVolumeML * 0.40, 0)

        Write-Host "`n--- Hematological Capacity ---" -ForegroundColor Gray
        Write-Color -Text 'Total Estimated Blood Volume: ', ('{0} Liters' -f $totalLiters) -Color White, Cyan
        
        Write-Color -Text 'Critical Loss Threshold (40%): ', ('{0} mL' -f $class4Loss) -Color White, Red
        Write-Host 'Loss of this volume typically results in irreversible shock.' -ForegroundColor DarkGray
    }
}

Function Get-ExsanguinationLimitModern {
    <#
        .SYNOPSIS
        Modern Hemorrhagic Shock assessment.
    #>
    $kg    = 0
    $kgStr = Read-Host -Prompt 'Enter subject weight (kg)'
    $sex   = Read-Host -Prompt 'Subject Sex (M/F)'
    
    If ([double]::TryParse($kgStr, [ref]$kg)) {
        $ratio = If ($sex -eq 'F') { 65 } Else { 75 }
        $totalVolML = $kg * $ratio
        
        ### Modern Shock Class IV is 40%+ loss
        $lethalVol = $totalVolML * 0.40

        Write-Host "`n--- Modern Hematological Report ---" -ForegroundColor Gray
        Write-Color -Text 'Subject Sex         : ', $sex -Color White, Cyan
        Write-Color -Text 'Est. Blood Volume   : ', (('{0} mL' -f $totalVolML)) -Color White, Cyan
        Write-Color -Text 'Lethal Loss (Class IV): ', (('{0} mL' -f $lethalVol)) -Color White, Red
        Write-Host 'Note: Modern Protocol suggests 1:1:1 Transfusion of Plasma:Platelets:RBCs.' -ForegroundColor DarkGray
    }
}

Function Get-SurvivalWindow {
    <#
        .SYNOPSIS
        Calculates the "Rule of Threes" timeline for human expiration.
        .DESCRIPTION
        The "Rule of Threes" (Survival Decay)
        This is a classic survivalist/macabre calculation used to determine the window of opportunity for rescue. 
        It tracks the countdown to expiration based on the deprivation of basic needs.
        The Rules: 3 Minutes (Air), 3 Hours (Shelter/Warmth), 3 Days (Water), 3 Weeks (Food).
    #>
    Param (
        [Parameter(Mandatory=$true,HelpMessage='Deprivation Type')]
        [ValidateSet('Air', 'Shelter', 'Water', 'Food')]
        [string]$DeprivationType
    )

    $now = Get-Date
    Write-Host "`n--- Survival Expiration Estimate ---" -ForegroundColor Gray
    Write-Host 'Subject deprived of: ' -NoNewLine
    Write-Host $DeprivationType -ForegroundColor Magenta

    Switch ($DeprivationType) {
        'Air'     {
            $expiry = $now.AddMinutes(3)
            $desc   = 'Anoxia / Brain Death'
        }
        'Shelter' {
            $expiry = $now.AddHours(3)
            $desc   = 'Hypothermia in extreme conditions'
        }
        'Water'   {
            $expiry = $now.AddDays(3)
            $desc   = 'Critical Dehydration / Organ Failure'
        }
        'Food'    {
            $expiry = $now.AddDays(21)
            $desc   = 'Starvation / Inanition'
        }
    }

    Write-Color -Text 'Estimated Point of No Return: ', $expiry.ToString('f') -Color White, Red
    Write-Host ('Expected Cause: {0}' -f $desc) -ForegroundColor DarkGray
}

Function Get-LethalDosage {
    <#
        .SYNOPSIS
        Calculates the amount of a substance required for an LD50 (50% lethality).
        .DESCRIPTION
        Data based on oral LD50 (Rat) as a proxy for human toxicity.
        Note: Individual sensitivity varies wildly.

        For this to work in PowerShell, we need to calculate the dosage based on the subject's body mass (mg/kg).
        The Toxicity Estimator (LD50)
        This function includes a small "apothecary" of historical and modern toxins. 
        It calculates the specific milligram dosage required to reach a lethal threshold based on the user's weight.
    #>
    $toxins = @{
        'Cyanide'    = 5.0    # mg/kg
        'Arsenic'    = 13.0   # mg/kg
        'Strychnine' = 2.0    # mg/kg
        'Nicotine'   = 50.0   # mg/kg
        'Caffeine'   = 192.0  # mg/kg
        'Ricinine'   = 0.02   # mg/kg (Extremely potent)
    }

    $lbs       = 0
    $weightLbs = Read-Host -Prompt 'Enter subject weight (lbs)'
    
    If ([double]::TryParse($weightLbs, [ref]$lbs)) {
        $kg = $lbs / 2.20462
        
        Write-Host "`n--- Toxicology Report: LD50 Thresholds ---" -ForegroundColor Gray
        Write-Color -Text 'Subject Mass: ', ([Math]::Round($kg, 2)), ' kg' -Color White, White, Cyan
        Write-Host '------------------------------------------' -ForegroundColor Gray

        ForEach ($toxin in $toxins.Keys) {
            $mgRequired = $kg * $toxins[$toxin]
            
            ### Format output for alignment
            $name = $toxin.PadRight(12)
            Write-Color -Text ('{0} : ' -f $name), ([Math]::Round($mgRequired, 4)), ' mg' -Color Magenta, Yellow, White
        }
        Write-Host "`nDisclaimer: For educational/fictional purposes only." -ForegroundColor DarkGray
    }
}

Function Get-LethalDosageModern {
    <#
        .SYNOPSIS
        Calculates lethal thresholds using modern toxicology benchmarks.
    #>
    $kg     = 0

    $toxins = @{
        'Fentanyl (IV)'   = 0.03   # mg/kg
        'Ricinine (Inh)'  = 0.005  # mg/kg
        'Cyanide (Oral)'  = 1.5    # mg/kg (More precise than Victorian 5.0)
        'Nicotine (IV)'   = 0.8    # mg/kg
    }

    $kgStr = Read-Host -Prompt 'Enter subject mass (kg)'
    
    If ([double]::TryParse($kgStr, [ref]$kg)) {
        Write-Host "`n--- 21st Century Toxicology Report ---" -ForegroundColor Gray
        Write-Host '------------------------------------------' -ForegroundColor Gray

        ForEach ($key in $toxins.Keys) {
            $mgReq = $kg * $toxins[$key]
            $name = $key.PadRight(18)
            Write-Color -Text (('{0} : ' -f $name)), ([Math]::Round($mgReq, 4)), ' mg' -Color Magenta, Yellow, White
        }
        Write-Host "`nReference: Registry of Toxic Effects of Chemical Substances (RTECS)" -ForegroundColor DarkGray
    }
}

Function Get-ToxinResidual {
    <#
        .SYNOPSIS
        Calculates the remaining toxin in a system based on biological half-life.
        .DESCRIPTION
        The Thallium "Trial" (Cumulative Decay)
        Thallium, often called "The Poisoner's Poison," is notorious because it mimics potassium and stays in the body for 
        a long time. This function calculates the biological half-life to see how much toxin remains after a certain number of days.

                                    t/h
        The Math: N(t) = N  * (0.5)^
                          0
        Where N  is the initial dose, t is time, and h is the half-life (approx. 3 days for Thallium).
               0
    #>
    Param (
        [Parameter(Mandatory=$true,HelpMessage='Initial Dose (mg)')]
        [double]$InitialDoseMg,
        [Parameter(Mandatory=$true,HelpMessage='Days Elapsed')]
        [int]$DaysElapsed
    )

    $halfLife  = 3 ### Average biological half-life of Thallium in days
    $remaining = $InitialDoseMg * [Math]::Pow(0.5, ($DaysElapsed / $halfLife))

    Write-Host "`n--- Residual Toxin Analysis ---" -ForegroundColor Gray
    Write-Color -Text ('After {0} days, the system retains: ' -f $DaysElapsed), ([Math]::Round($remaining, 3)), ' mg' -Color White, Red, White
}

Function Get-WaterIntoxication {
    <#
        .SYNOPSIS
        Calculates the volume of water intake that could be fatal.
        .DESCRIPTION
        The "Death by Water" (Hyponatremia)
        Even the most benign substance is toxic in the right dose. This calculates the LD50 for water (approx. 90ml/kg), which causes fatal salt imbalance.
    #>
    $lbs       = 0
    $weightLbs = Read-Host -Prompt 'Enter subject weight (lbs)'
    
    If ([double]::TryParse($weightLbs, [ref]$lbs)) {
        $kg           = $lbs / 2.20462
        $lethalLiters = ($kg * 90) / 1000

        Write-Host "`n--- Aqueous Toxicity ---" -ForegroundColor Gray
        Write-Color -Text 'Lethal Water Threshold: ', ([Math]::Round($lethalLiters, 2)), ' Liters' -Color White, Cyan, White
        Write-Host "Even the 'Elixir of Life' has a limit." -ForegroundColor DarkGray
    }
}

# Get-LivorMortisStatus (Post-Mortem Lividity)

# Livor mortis (lividity) is the settling of blood in the lower portion of the body. Forensic surgeons used this to determine if a body had been moved after death.

# The Math: Lividity typically begins at 2 hours, becomes "fixed" (permanent) at 8-12 hours, and disappears if the body is significantly decomposed.
Function Get-LivorMortisStatus {
    <#
        .SYNOPSIS
        Evaluates the fixity of lividity based on time since death.
        .DESCRIPTION
        Livor Mortis (Lividity)
        Used by 19th-century coroners to determine if a body was moved. 
        Blood settles due to gravity; if the "stains" do not shift when 
        the body is turned, the lividity is "fixed."
    #>
    Param (
        [Parameter(Mandatory=$true,HelpMessage='Hours Since Death')]
        [ValidateRange(0, 72)]
        [int]$HoursSinceDeath
    )

    Write-Host "`n--- Forensic Lividity Assessment ---" -ForegroundColor Gray

    If ($HoursSinceDeath -lt 2) {
        $status = 'Absent'
        $desc   = 'Blood has not yet begun to settle.'
        $color  = 'Cyan'
    } ElseIf ($HoursSinceDeath -ge 2 -and $HoursSinceDeath -lt 8) {
        $status = 'Evident / Non-Fixed'
        $desc   = 'Staining is visible but will shift if the body is moved.'
        $color  = 'Yellow'
    } ElseIf ($HoursSinceDeath -ge 8 -and $HoursSinceDeath -lt 36) {
        $status = 'Fixed'
        $desc   = 'Staining is permanent. Moving the body will not shift the marks.'
        $color  = 'Red'
    } Else {
        $status = 'Fading'
        $desc   = 'Decomposition (putrefaction) is obscuring the lividity.'
        $color  = 'DarkGray'
    }

    Write-Color -Text 'Time Elapsed: ', (('{0} hours' -f $HoursSinceDeath)) -Color White, Yellow
    Write-Color -Text 'Status      : ', $status -Color White, $color
    Write-Host ('Clinical Note: {0}' -f $desc) -ForegroundColor DarkGray
}

# Get-BuryingPoint (The Resurrectionist's Math)

# During the era of Burke and Hare, "resurrectionists" (body snatchers) had to calculate the volume of earth to be moved to reach a coffin. A standard Victorian grave was "six feet under."

# The Math: Volume = Length * Width * Depth.
# We will calculate the weight of the soil to be moved, assuming standard loose earth is ~76 lbs per cubic foot.
Function Get-BuryingPoint {
    <#
        .SYNOPSIS
        Calculates the volume and weight of earth required to reach a standard coffin.
        .DESCRIPTION
        Historical "Resurrectionist" Math.
        Calculates the labor required to exhume a standard plot (approx. 7ft x 2.5ft x 6ft).
    #>
    $length       = 7
    $width        = 2.5
    $depth        = 6
    $earthDensity = 76 ### lbs per cubic foot

    $volume = $length * $width * $depth
    $weight = $volume * $earthDensity
    $tons   = $weight / 2240 ### Long Ton (Victorian Standard)

    Write-Host "`n--- Excavation Requirements (The Resurrectionist) ---" -ForegroundColor Gray
    Write-Color -Text 'Total Earth Volume : ', (('{0} cubic feet' -f $volume)) -Color White, Cyan
    Write-Color -Text 'Estimated Weight   : ', ([Math]::Round($weight, 2)), ' lbs ', '(', ([Math]::Round($tons, 2)), ' long tons)' -Color White, Yellow, White, Gray, Yellow, Gray
    Write-Host "Note: Labor requires approximately 4 hours for a single 'nightman'." -ForegroundColor DarkGray
}

# Get-PhossyJawRisk (Industrial Toxicity)

# Victorian match-stick girls suffered from "Phossy Jaw," caused by white phosphorus. This function calculates the cumulative exposure risk based on a 19th-century work week.

# The Math: Exposure threshold was roughly 5mg/day of vaporized phosphorus.
Function Get-PhossyJawRisk {
    <#
        .SYNOPSIS
        Estimates the timeline for necrotic bone decay in match-factory workers.
    #>
    $years       = 0
    $yearsString = Read-Host -Prompt 'Enter years of employment in match factory'
    
    If ([double]::TryParse($yearsString, [ref]$years)) {
        ### Cumulative exposure logic
        $daysWorked = $years * 312 # 6 days a week, 52 weeks
        $totalMg    = $daysWorked * 5 # Average daily exposure in mg

        Write-Host "`n--- Occupational Toxicology Report ---" -ForegroundColor Gray
        Write-Color -Text 'Total Exposure: ', (('{0} mg of White Phosphorus' -f $totalMg)) -Color White, Yellow

        If ($years -ge 5) {
            Write-Color -Text 'Risk Level    : ', 'CRITICAL (Necrosis Likely)' -Color White, Red
            Write-Host 'Subject likely presents with abscesses and mandibular decay.' -ForegroundColor DarkGray
        } ElseIf ($years -ge 2) {
            Write-Color -Text 'Risk Level    : ', 'ELEVATED' -Color White, Yellow
            Write-Host 'Initial symptoms of glowing breath and toothache expected.' -ForegroundColor DarkGray
        } Else {
            Write-Color -Text 'Risk Level    : ', 'LOW' -Color White, Green
            Write-Host 'Short-term exposure; minor respiratory irritation possible.' -ForegroundColor DarkGray
        }
    }
}
