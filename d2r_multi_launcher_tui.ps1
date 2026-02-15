# D2R interactive launcher (arrow keys + Enter)

$script:Root = $PSScriptRoot
$script:D2rExe = Join-Path $script:Root 'D2R.exe'
$script:HandleExe = Join-Path $script:Root 'handle64.exe'
$script:OfficialLauncherExe = Join-Path $script:Root 'Diablo II Resurrected Launcher.exe'
$script:HandlesDumpFile = Join-Path $script:Root 'd2r_handles.txt'
$script:ModsConfigFile = Join-Path $script:Root 'mods_config.txt'

function Ensure-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        return
    }

    $quotedScriptPath = '"' + $PSCommandPath + '"'
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File $quotedScriptPath"

    Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -ErrorAction Stop | Out-Null
    exit
}

function Assert-Prerequisites {
    param(
        [string[]]$AdditionalFiles = @()
    )

    $required = @('D2R.exe', 'handle64.exe') + $AdditionalFiles
    $missing = @()

    foreach ($name in ($required | Select-Object -Unique)) {
        $path = Join-Path $script:Root $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $missing += $name
        }
    }

    if ($missing.Count -gt 0) {
        throw "Missing required files: $($missing -join ', ')"
    }
}

function Show-Menu {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string[]]$Items,

        [string]$Prompt = 'Use Up/Down arrows, then press Enter',

        [int]$InitialIndex = 0,

        [switch]$AllowBack
    )

    if ($Items.Count -eq 0) {
        throw 'Menu items cannot be empty.'
    }

    $selected = 0
    if ($InitialIndex -ge 0 -and $InitialIndex -lt $Items.Count) {
        $selected = $InitialIndex
    }

    while ($true) {
        Clear-Host
        Write-Host $Title -ForegroundColor Cyan
        Write-Host ''

        for ($i = 0; $i -lt $Items.Count; $i++) {
            if ($i -eq $selected) {
                Write-Host "> $($Items[$i])" -ForegroundColor Yellow
            } else {
                Write-Host "  $($Items[$i])"
            }
        }

        Write-Host ''
        if ($AllowBack) {
            Write-Host ($Prompt + ' | Esc/Backspace: back') -ForegroundColor DarkGray
        } else {
            Write-Host $Prompt -ForegroundColor DarkGray
        }

        try {
            $key = [Console]::ReadKey($true)
        } catch {
            throw 'Interactive console with keyboard input is required.'
        }

        switch ($key.Key) {
            ([ConsoleKey]::UpArrow) {
                if ($selected -gt 0) {
                    $selected--
                } else {
                    $selected = $Items.Count - 1
                }
            }
            ([ConsoleKey]::DownArrow) {
                if ($selected -lt ($Items.Count - 1)) {
                    $selected++
                } else {
                    $selected = 0
                }
            }
            ([ConsoleKey]::Enter) {
                return $selected
            }
            ([ConsoleKey]::Escape) {
                if ($AllowBack) {
                    return -1
                }
            }
            ([ConsoleKey]::Backspace) {
                if ($AllowBack) {
                    return -1
                }
            }
            default { }
        }
    }
}

function Show-StatusAndWait {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [string[]]$Lines = @()
    )

    Clear-Host
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ''

    foreach ($line in $Lines) {
        Write-Host $line
    }

    Write-Host ''
    Write-Host 'Press Enter to return to main menu' -ForegroundColor DarkGray

    while ($true) {
        try {
            $key = [Console]::ReadKey($true)
        } catch {
            break
        }

        if ($key.Key -eq [ConsoleKey]::Enter) {
            break
        }
    }
}

function Get-AccountsFromFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    Assert-Prerequisites -AdditionalFiles @($FileName)

    $fullPath = Join-Path $script:Root $FileName
    $accounts = @()
    $lineNumber = 0

    foreach ($rawLine in (Get-Content -LiteralPath $fullPath -Encoding UTF8)) {
        $lineNumber++
        $line = $rawLine.Trim()

        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }

        $parts = $line -split ';'
        if ($parts.Count -lt 2) {
            Write-Warning "$FileName line $lineNumber has bad format; skipped."
            continue
        }

        $email = $parts[0].Trim()
        $password = $parts[1].Trim()

        if ([string]::IsNullOrWhiteSpace($email) -or [string]::IsNullOrWhiteSpace($password)) {
            Write-Warning "$FileName line $lineNumber missing email or password; skipped."
            continue
        }

        $displayName = $email
        if ($parts.Count -ge 3 -and -not [string]::IsNullOrWhiteSpace($parts[2])) {
            $displayName = $parts[2].Trim()
        }

        $modFlag = ''
        if ($parts.Count -ge 4 -and -not [string]::IsNullOrWhiteSpace($parts[3])) {
            $modFlag = $parts[3].Trim().ToLowerInvariant()
        }

        $accounts += [PSCustomObject]@{
            Email       = $email
            Password    = $password
            DisplayName = $displayName
            ModFlag     = $modFlag
        }
    }

    if ($accounts.Count -eq 0) {
        throw "$FileName has no valid accounts."
    }

    return ,$accounts
}

function Close-D2RHandle {
    Assert-Prerequisites

    & $script:HandleExe -accepteula -a -p D2R.exe > $script:HandlesDumpFile

    $procIdPopulated = ''
    $handleIdPopulated = ''
    $closedCount = 0

    foreach ($line in (Get-Content -LiteralPath $script:HandlesDumpFile -ErrorAction SilentlyContinue)) {
        $procMatch = [regex]::Match($line, '^D2R\.exe pid\: (?<pid>.+) ')
        if ($procMatch.Success) {
            $procIdPopulated = $procMatch.Groups['pid'].Value
        }

        $handleMatch = [regex]::Match($line, '^(?<handle>.+): Event.*DiabloII Check For Other Instances')
        if ($handleMatch.Success) {
            $handleIdPopulated = $handleMatch.Groups['handle'].Value
        }

        if (-not [string]::IsNullOrWhiteSpace($handleIdPopulated) -and -not [string]::IsNullOrWhiteSpace($procIdPopulated)) {
            & $script:HandleExe -p $procIdPopulated -c $handleIdPopulated -y | Out-Null
            $closedCount++
            $handleIdPopulated = ''
        }
    }

    return $closedCount
}

function Resolve-Region {
    $regionOptions = @(
        [PSCustomObject]@{ Label = 'Asia (kr)'; Value = 'kr' }
        [PSCustomObject]@{ Label = 'North America (us)'; Value = 'us' }
        [PSCustomObject]@{ Label = 'Europe (eu)'; Value = 'eu' }
    )

    $choice = Show-Menu -Title 'Select region' -Items ($regionOptions | ForEach-Object { $_.Label }) -AllowBack
    if ($choice -lt 0) {
        return $null
    }
    return $regionOptions[$choice].Value
}

function Resolve-SingleModSelection {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$ModDefinitions
    )

    $modOptions = @(
        $ModDefinitions | ForEach-Object {
            [PSCustomObject]@{
                Label = $_.Label
                Name  = $_.Name
                Key   = $_.Key
                Mod   = if ($_.Name -eq 'none') { '' } else { $_.Name }
                Extra = $_.Args
            }
        }
    )

    $choice = Show-Menu -Title 'Select mod' -Items ($modOptions | ForEach-Object { $_.Label }) -AllowBack -InitialIndex 0
    if ($choice -lt 0) {
        return $null
    }
    return $modOptions[$choice]
}

function Get-ModDefinitions {
    $definitions = New-Object System.Collections.Generic.List[object]
    $seen = @{}

    if (Test-Path -LiteralPath $script:ModsConfigFile -PathType Leaf) {
        foreach ($rawLine in (Get-Content -LiteralPath $script:ModsConfigFile -Encoding UTF8)) {
            $line = $rawLine.Trim()
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
                continue
            }

            $parts = $line -split '\|', 2
            $name = $parts[0].Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }

            if ($name -notmatch '^[a-z0-9_-]+$') {
                continue
            }

            $args = @()
            if ($parts.Count -ge 2 -and -not [string]::IsNullOrWhiteSpace($parts[1])) {
                $args = ($parts[1].Trim() -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            }

            if ($name -eq 'none') {
                $args = @()
            }

            $argsText = $args -join ' '
            $key = "$name|$argsText"
            if ($seen.ContainsKey($key)) {
                continue
            }

            $label = $name
            if ($args.Count -gt 0) {
                $label = "$label ($argsText)"
            }

            $definitions.Add([PSCustomObject]@{
                Name     = $name
                Args     = $args
                ArgsText = $argsText
                Key      = $key
                Label    = $label
            })
            $seen[$key] = $true
        }
    }

    if (-not ($definitions | Where-Object { $_.Name -eq 'none' } | Select-Object -First 1)) {
        $definitions.Add([PSCustomObject]@{
            Name     = 'none'
            Args     = @()
            ArgsText = ''
            Key      = 'none|'
            Label    = 'none'
        })
    }

    return ,$definitions.ToArray()
}

function Resolve-ModDefinitionFromFlag {
    param(
        [AllowNull()]
        [string]$ModFlag,

        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$ModDefinitions
    )

    if ($ModDefinitions.Count -eq 0) {
        throw 'No mod definitions available.'
    }

    $fallbackDef = $ModDefinitions | Where-Object { $_.Name -eq 'none' } | Select-Object -First 1
    if ($null -eq $fallbackDef) {
        $fallbackDef = $ModDefinitions[0]
    }

    $normalized = ''
    if (-not [string]::IsNullOrWhiteSpace($ModFlag)) {
        $normalized = $ModFlag.Trim().ToLowerInvariant()
    }

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $fallbackDef
    }

    $nameToken = $normalized
    $argsText = ''
    if ($normalized.Contains('|')) {
        $parts = $normalized -split '\|', 2
        $nameToken = $parts[0].Trim()
        if ($parts.Count -ge 2 -and -not [string]::IsNullOrWhiteSpace($parts[1])) {
            $argsText = (($parts[1].Trim() -split '\s+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
        }
    }

    switch ($nameToken) {
        'csh2' { $nameToken = 'csh' }
        'nohd' { $nameToken = 'cshnohd' }
        '' { $nameToken = 'none' }
    }

    if ($nameToken -eq 'none') {
        $argsText = ''
    }

    $fullKey = "$nameToken|$argsText"
    $exactDef = $ModDefinitions | Where-Object { $_.Key -eq $fullKey } | Select-Object -First 1
    if ($null -ne $exactDef) {
        return $exactDef
    }

    $byNameDef = $ModDefinitions | Where-Object { $_.Name -eq $nameToken } | Select-Object -First 1
    if ($null -ne $byNameDef) {
        return $byNameDef
    }

    return $fallbackDef
}

function Resolve-BatchSelectionsInOneScreen {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Accounts,

        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$ModDefinitions
    )

    if ($Accounts.Count -eq 0) {
        throw 'No accounts available for batch selection.'
    }

    $modOptions = @($ModDefinitions)
    $modOptionKeys = @($modOptions | ForEach-Object { $_.Key })
    $modIndexes = New-Object int[] $Accounts.Count

    for ($i = 0; $i -lt $Accounts.Count; $i++) {
        $currentDef = Resolve-ModDefinitionFromFlag -ModFlag $Accounts[$i].ModFlag -ModDefinitions $modOptions
        $currentIndex = [Array]::IndexOf($modOptionKeys, $currentDef.Key)
        if ($currentIndex -lt 0) {
            $currentIndex = 0
        }
        $modIndexes[$i] = $currentIndex
    }

    $row = 0
    while ($true) {
        Clear-Host
        Write-Host 'Batch mod editor (all accounts on one screen)' -ForegroundColor Cyan
        Write-Host ''

        for ($i = 0; $i -lt $Accounts.Count; $i++) {
            $account = $Accounts[$i]
            $modDef = $modOptions[$modIndexes[$i]]
            $modDisplay = $modDef.Label
            $line = "[$($i + 1)] $($account.DisplayName) <$($account.Email)>  ->  $modDisplay"
            if ($i -eq $row) {
                Write-Host "> $line" -ForegroundColor Yellow
            } else {
                Write-Host "  $line"
            }
        }

        Write-Host ''
        Write-Host 'Up/Down: select account | Left/Right: change mod | Enter: confirm and launch | Esc/Backspace: back' -ForegroundColor DarkGray

        try {
            $key = [Console]::ReadKey($true)
        } catch {
            throw 'Interactive console with keyboard input is required.'
        }

        switch ($key.Key) {
            ([ConsoleKey]::UpArrow) {
                if ($row -gt 0) { $row-- } else { $row = $Accounts.Count - 1 }
            }
            ([ConsoleKey]::DownArrow) {
                if ($row -lt ($Accounts.Count - 1)) { $row++ } else { $row = 0 }
            }
            ([ConsoleKey]::LeftArrow) {
                if ($modIndexes[$row] -gt 0) { $modIndexes[$row]-- } else { $modIndexes[$row] = $modOptions.Count - 1 }
            }
            ([ConsoleKey]::RightArrow) {
                if ($modIndexes[$row] -lt ($modOptions.Count - 1)) { $modIndexes[$row]++ } else { $modIndexes[$row] = 0 }
            }
            ([ConsoleKey]::Enter) {
                $selections = @()
                for ($j = 0; $j -lt $Accounts.Count; $j++) {
                    $selectedDef = $modOptions[$modIndexes[$j]]
                    $selections += [PSCustomObject]@{
                        Account      = $Accounts[$j]
                        Skip         = $false
                        EffectiveMod = $selectedDef.Key
                        PersistMod   = $selectedDef.Key
                    }
                }
                return ,$selections
            }
            ([ConsoleKey]::Escape) {
                return $null
            }
            ([ConsoleKey]::Backspace) {
                return $null
            }
            default { }
        }
    }
}

function Show-BatchSelectionPreview {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Selections,

        [Parameter(Mandatory = $true)]
        [string]$Region,

        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$ModDefinitions
    )

    Clear-Host
    Write-Host 'Batch launch plan' -ForegroundColor Cyan
    Write-Host "Region: $Region"
    Write-Host ''

    for ($i = 0; $i -lt $Selections.Count; $i++) {
        $selection = $Selections[$i]
        $modDef = Resolve-ModDefinitionFromFlag -ModFlag $selection.EffectiveMod -ModDefinitions $ModDefinitions
        $modDisplay = $modDef.Label
        Write-Host ("[{0}] {1} -> {2}" -f ($i + 1), $selection.Account.DisplayName, $modDisplay)
    }

    Write-Host ''
    Write-Host 'Press Enter to start launch | Esc/Backspace: back' -ForegroundColor DarkGray

    while ($true) {
        try {
            $key = [Console]::ReadKey($true)
        } catch {
            return $false
        }

        if ($key.Key -eq [ConsoleKey]::Enter) {
            return $true
        }

        if ($key.Key -eq [ConsoleKey]::Escape -or $key.Key -eq [ConsoleKey]::Backspace) {
            return $false
        }
    }
}

function Save-AccountsModFlags {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$Selections
    )

    Assert-Prerequisites -AdditionalFiles @($FileName)

    $path = Join-Path $script:Root $FileName
    $tempPath = "$path.tmp"
    $rawLines = Get-Content -LiteralPath $path -Encoding UTF8
    $outputLines = New-Object System.Collections.Generic.List[string]
    $selectionIndex = 0

    foreach ($rawLine in $rawLines) {
        $line = $rawLine.Trim()

        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            $outputLines.Add($rawLine)
            continue
        }

        $parts = $rawLine -split ';'
        if ($parts.Count -lt 2) {
            $outputLines.Add($rawLine)
            continue
        }

        $email = $parts[0].Trim()
        $password = $parts[1].Trim()
        if ([string]::IsNullOrWhiteSpace($email) -or [string]::IsNullOrWhiteSpace($password)) {
            $outputLines.Add($rawLine)
            continue
        }

        if ($selectionIndex -ge $Selections.Count) {
            throw 'Account selection count mismatch while writing accounts.txt.'
        }

        $selection = $Selections[$selectionIndex]
        $selectionIndex++

        if ($null -eq $selection.PersistMod) {
            $outputLines.Add($rawLine)
            continue
        }

        $col1 = if ($parts.Count -ge 1) { $parts[0] } else { $selection.Account.Email }
        $col2 = if ($parts.Count -ge 2) { $parts[1] } else { $selection.Account.Password }
        $col3 = if ($parts.Count -ge 3) { $parts[2] } else { $selection.Account.DisplayName }
        $newLine = @($col1, $col2, $col3, $selection.PersistMod) -join ';'
        $outputLines.Add($newLine)
    }

    if ($selectionIndex -ne $Selections.Count) {
        throw 'Account selection count mismatch after writing accounts.txt.'
    }

    try {
        Set-Content -LiteralPath $tempPath -Value $outputLines.ToArray() -Encoding UTF8
        Move-Item -LiteralPath $tempPath -Destination $path -Force
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Resolve-BatchMod {
    param(
        [string]$ModFlag,

        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$ModDefinitions
    )

    $definition = Resolve-ModDefinitionFromFlag -ModFlag $ModFlag -ModDefinitions $ModDefinitions
    if ($definition.Name -eq 'none') {
        return [PSCustomObject]@{ Mod = ''; Extra = @(); Warning = $null }
    }

    return [PSCustomObject]@{ Mod = $definition.Name; Extra = $definition.Args; Warning = $null }
}

function Start-D2RClient {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Email,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $true)]
        [string]$Region,

        [string]$Mod = '',

        [string[]]$ExtraArgs = @()
    )

    Assert-Prerequisites

    $args = @(
        '-username', $Email
        '-password', $Password
        '-address', "$Region.actual.battle.net"
    )

    if (-not [string]::IsNullOrWhiteSpace($Mod)) {
        $args += @('-mod', $Mod)
    }

    if ($ExtraArgs.Count -gt 0) {
        $args += $ExtraArgs
    }

    & $script:D2rExe @args
}

function Invoke-SingleClientFlow {
    try {
        $accounts = Get-AccountsFromFile -FileName 'accounts.txt'
        $modDefinitions = Get-ModDefinitions
        $region = $null
        $modSelection = $null
        $step = 'region'
        $lastResult = ''

        while ($true) {
            switch ($step) {
                'region' {
                    $region = Resolve-Region
                    if ($null -eq $region) {
                        return
                    }
                    $step = 'mod'
                }
                'mod' {
                    $modSelection = Resolve-SingleModSelection -ModDefinitions $modDefinitions
                    if ($null -eq $modSelection) {
                        $step = 'region'
                        continue
                    }
                    $step = 'account'
                }
                'account' {
                    $accountItems = $accounts | ForEach-Object { "$($_.DisplayName) <$($_.Email)>" }
                    $modDisplay = $modSelection.Name
                    $title = "Select account (region=$region, mod=$modDisplay)"
                    if (-not [string]::IsNullOrWhiteSpace($lastResult)) {
                        $title = "$title`n$lastResult"
                    }

                    $accountIndex = Show-Menu -Title $title -Items $accountItems -AllowBack
                    if ($accountIndex -lt 0) {
                        $step = 'mod'
                        continue
                    }

                    $account = $accounts[$accountIndex]

                    try {
                        $closedHandles = Close-D2RHandle
                        Start-D2RClient -Email $account.Email -Password $account.Password -Region $region -Mod $modSelection.Mod -ExtraArgs $modSelection.Extra
                        $lastResult = "Last launch: $($account.DisplayName) (handles closed: $closedHandles)"
                    } catch {
                        $lastResult = "Last launch failed: $($_.Exception.Message)"
                    }
                }
            }
        }
    } catch {
        Show-StatusAndWait -Title 'Single client flow failed' -Lines @($_.Exception.Message)
    }
}

function Invoke-MultiClientFlow {
    try {
        $accounts = Get-AccountsFromFile -FileName 'accounts.txt'
        $modDefinitions = Get-ModDefinitions
        while ($true) {
            $region = Resolve-Region
            if ($null -eq $region) {
                return
            }

            while ($true) {
                $selections = Resolve-BatchSelectionsInOneScreen -Accounts $accounts -ModDefinitions $modDefinitions
                if ($null -eq $selections) {
                    break
                }

                $confirmed = Show-BatchSelectionPreview -Selections $selections -Region $region -ModDefinitions $modDefinitions
                if (-not $confirmed) {
                    continue
                }

                Save-AccountsModFlags -FileName 'accounts.txt' -Selections $selections

                $resultLines = New-Object System.Collections.Generic.List[string]
                $resultLines.Add('Source file: accounts.txt')
                $resultLines.Add("Region: $region")
                $resultLines.Add('Applied per-account mod mapping from batch editor.')
                $resultLines.Add("Account count: $($accounts.Count)")
                $resultLines.Add('')

                $index = 0
                foreach ($selection in $selections) {
                    $index++
                    $account = $selection.Account

                    $resolved = Resolve-BatchMod -ModFlag $selection.EffectiveMod -ModDefinitions $modDefinitions
                    $resultLines.Add("[$index/$($selections.Count)] Launching $($account.DisplayName)")

                    try {
                        $closedHandles = Close-D2RHandle
                        Start-D2RClient -Email $account.Email -Password $account.Password -Region $region -Mod $resolved.Mod -ExtraArgs $resolved.Extra

                        $modDisplay = if ([string]::IsNullOrWhiteSpace($resolved.Mod)) { 'none' } else { $resolved.Mod }
                        $resultLines.Add("  Success: mod=$modDisplay, closed_handles=$closedHandles")

                        if ($resolved.Warning) {
                            $resultLines.Add("  Warning: $($resolved.Warning)")
                        }
                    } catch {
                        $resultLines.Add("  Failed: $($_.Exception.Message)")
                    }

                    Start-Sleep -Seconds 5
                }

                Show-StatusAndWait -Title 'Batch flow complete' -Lines $resultLines.ToArray()
                return
            }
        }
    } catch {
        Show-StatusAndWait -Title 'Batch flow failed' -Lines @($_.Exception.Message)
    }
}

function Invoke-OfficialLauncher {
    try {
        Assert-Prerequisites -AdditionalFiles @('Diablo II Resurrected Launcher.exe')
        & $script:OfficialLauncherExe
        Show-StatusAndWait -Title 'Official launcher started' -Lines @('Launch command sent.')
    } catch {
        Show-StatusAndWait -Title 'Official launcher failed' -Lines @($_.Exception.Message)
    }
}

function Start-Tui {
    Ensure-Admin
    Assert-Prerequisites
    try {
        $Host.UI.RawUI.WindowTitle = 'D2R Multi Launcher'
    } catch {
        # Ignore non-interactive hosts that do not support setting window title.
    }

    while ($true) {
        $mainItems = @(
            'Single client launch'
            'Batch multi-client launch'
            'Start official launcher'
            'Exit'
        )

        $selection = Show-Menu -Title 'D2R Multi Launcher' -Items $mainItems

        switch ($selection) {
            0 { Invoke-SingleClientFlow }
            1 { Invoke-MultiClientFlow }
            2 { Invoke-OfficialLauncher }
            3 {
                Clear-Host
                return
            }
            default { }
        }
    }
}

try {
    Start-Tui
} catch {
    Clear-Host
    Write-Host 'Unable to start TUI.' -ForegroundColor Red
    Write-Host $_.Exception.Message
    Write-Host 'Run this script in an interactive PowerShell console.'
    Read-Host 'Press Enter to close'
    exit 1
}
