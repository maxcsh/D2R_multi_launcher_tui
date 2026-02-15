# D2R interactive launcher (arrow keys + Enter)

$script:Root = $PSScriptRoot
$script:D2rExe = Join-Path $script:Root 'D2R.exe'
$script:HandleExe = Join-Path $script:Root 'handle64.exe'
$script:OfficialLauncherExe = Join-Path $script:Root 'Diablo II Resurrected Launcher.exe'
$script:HandlesDumpFile = Join-Path $script:Root 'd2r_handles.txt'
$script:ModsConfigFile = Join-Path $script:Root 'mods_config.txt'
$script:SettingsFile = Join-Path $script:Root 'settings.txt'
$script:WindowApiInitialized = $false
$script:RenameWindowTitleEnabled = $true

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

function Convert-ToBooleanSetting {
    param(
        [string]$RawValue,
        [bool]$Default = $true
    )

    if ([string]::IsNullOrWhiteSpace($RawValue)) {
        return $Default
    }

    switch ($RawValue.Trim().ToLowerInvariant()) {
        '1' { return $true }
        'true' { return $true }
        'on' { return $true }
        'yes' { return $true }
        'y' { return $true }
        '0' { return $false }
        'false' { return $false }
        'off' { return $false }
        'no' { return $false }
        'n' { return $false }
        default { return $Default }
    }
}

function Get-LauncherSettings {
    $settings = [ordered]@{
        rename_window_title = $true
    }

    if (-not (Test-Path -LiteralPath $script:SettingsFile -PathType Leaf)) {
        return [PSCustomObject]$settings
    }

    foreach ($rawLine in (Get-Content -LiteralPath $script:SettingsFile -Encoding UTF8)) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }

        $parts = $line -split '=', 2
        if ($parts.Count -lt 2) {
            continue
        }

        $key = $parts[0].Trim().ToLowerInvariant()
        $value = $parts[1].Trim()

        switch ($key) {
            'rename_window_title' {
                $settings.rename_window_title = Convert-ToBooleanSetting -RawValue $value -Default $settings.rename_window_title
            }
            default { }
        }
    }

    return [PSCustomObject]$settings
}

function Save-LauncherSettings {
    param(
        [bool]$RenameWindowTitleEnabled
    )

    $flag = if ($RenameWindowTitleEnabled) { 'true' } else { 'false' }
    $lines = @(
        '# D2R multi launcher settings'
        "rename_window_title=$flag"
    )

    Set-Content -LiteralPath $script:SettingsFile -Value $lines -Encoding UTF8
}

function Initialize-WindowApi {
    if ($script:WindowApiInitialized) {
        return
    }

    if ("D2RWindowApi" -as [type]) {
        $script:WindowApiInitialized = $true
        return
    }

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class D2RWindowApi {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetWindowText(IntPtr hWnd, string lpString);
}
"@

    $script:WindowApiInitialized = $true
}

function Get-D2RPidsSnapshot {
    return @(
        Get-Process -Name 'D2R' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id
    )
}

function Get-D2RWindowTitleText {
    param(
        [string]$DisplayName,
        [string]$Region
    )

    $safeName = $DisplayName
    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = 'Unknown'
    }
    $safeName = ($safeName -replace '[\r\n]+', ' ').Trim()

    $safeRegion = $Region
    if ([string]::IsNullOrWhiteSpace($safeRegion)) {
        $safeRegion = '-'
    }
    $safeRegion = ($safeRegion -replace '[\r\n]+', ' ').Trim().ToLowerInvariant()

    return "D2R: $safeName [$safeRegion]"
}

function Wait-NewD2RWindowTarget {
    param(
        [int[]]$BeforePids = @(),
        [int]$PreferredPid = 0,
        [int]$TimeoutMs = 15000,
        [int]$PollIntervalMs = 250
    )

    $beforeSet = @{}
    foreach ($existingPid in $BeforePids) {
        $beforeSet[$existingPid] = $true
    }

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.ElapsedMilliseconds -lt $TimeoutMs) {
        $processes = @(Get-Process -Name 'D2R' -ErrorAction SilentlyContinue)
        $candidates = New-Object System.Collections.Generic.List[object]

        if ($PreferredPid -gt 0) {
            $preferred = $processes | Where-Object { $_.Id -eq $PreferredPid } | Select-Object -First 1
            if ($null -ne $preferred) {
                $candidates.Add($preferred)
            }
        }

        foreach ($process in $processes) {
            if ($PreferredPid -gt 0 -and $process.Id -eq $PreferredPid) {
                continue
            }
            if (-not $beforeSet.ContainsKey($process.Id)) {
                $candidates.Add($process)
            }
        }

        foreach ($candidate in $candidates) {
            try {
                $candidate.Refresh()
                $windowHandle = $candidate.MainWindowHandle
            } catch {
                continue
            }

            if ($windowHandle -ne [IntPtr]::Zero) {
                return [PSCustomObject]@{
                    Pid    = $candidate.Id
                    Handle = $windowHandle
                }
            }
        }

        Start-Sleep -Milliseconds $PollIntervalMs
    }

    return $null
}

function Set-D2RWindowTitleForLaunch {
    param(
        [int[]]$BeforePids = @(),
        [int]$LaunchedPid = 0,
        [string]$DisplayName,
        [string]$Region,
        [int]$TimeoutMs = 15000
    )

    $windowTitle = Get-D2RWindowTitleText -DisplayName $DisplayName -Region $Region
    $target = Wait-NewD2RWindowTarget -BeforePids $BeforePids -PreferredPid $LaunchedPid -TimeoutMs $TimeoutMs

    if ($null -eq $target) {
        return [PSCustomObject]@{
            Success     = $false
            Warning     = "Could not find D2R window within $TimeoutMs ms."
            WindowTitle = $windowTitle
            WindowPid   = $null
        }
    }

    try {
        Initialize-WindowApi
        $renamed = [D2RWindowApi]::SetWindowText($target.Handle, $windowTitle)
    } catch {
        return [PSCustomObject]@{
            Success     = $false
            Warning     = "Failed to set window title: $($_.Exception.Message)"
            WindowTitle = $windowTitle
            WindowPid   = $target.Pid
        }
    }

    if (-not $renamed) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        return [PSCustomObject]@{
            Success     = $false
            Warning     = "SetWindowText returned false (Win32Error=$lastError)."
            WindowTitle = $windowTitle
            WindowPid   = $target.Pid
        }
    }

    return [PSCustomObject]@{
        Success     = $true
        Warning     = $null
        WindowTitle = $windowTitle
        WindowPid   = $target.Pid
    }
}

function Show-Menu {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]$Items,

        [string]$Prompt = 'Use Up/Down arrows, then press Enter',

        [int]$InitialIndex = 0,

        [switch]$AllowBack
    )

    if ($Items.Count -eq 0) {
        throw 'Menu items cannot be empty.'
    }

    $selectable = @()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        if (-not [string]::IsNullOrWhiteSpace($Items[$i])) {
            $selectable += $i
        }
    }

    if ($selectable.Count -eq 0) {
        throw 'Menu has no selectable items.'
    }

    $selected = $selectable[0]
    if ($InitialIndex -ge 0 -and $InitialIndex -lt $Items.Count -and -not [string]::IsNullOrWhiteSpace($Items[$InitialIndex])) {
        $selected = $InitialIndex
    }

    while ($true) {
        Clear-Host
        Write-Host $Title -ForegroundColor Cyan
        Write-Host ''

        for ($i = 0; $i -lt $Items.Count; $i++) {
            if ([string]::IsNullOrWhiteSpace($Items[$i])) {
                Write-Host ''
                continue
            }
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
                do {
                    if ($selected -gt 0) {
                        $selected--
                    } else {
                        $selected = $Items.Count - 1
                    }
                } while ([string]::IsNullOrWhiteSpace($Items[$selected]))
            }
            ([ConsoleKey]::DownArrow) {
                do {
                    if ($selected -lt ($Items.Count - 1)) {
                        $selected++
                    } else {
                        $selected = 0
                    }
                } while ([string]::IsNullOrWhiteSpace($Items[$selected]))
            }
            ([ConsoleKey]::Enter) {
                if (-not [string]::IsNullOrWhiteSpace($Items[$selected])) {
                    return $selected
                }
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

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

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

    $beforePids = Get-D2RPidsSnapshot
    $startedProcess = Start-Process -FilePath $script:D2rExe -ArgumentList $args -PassThru
    if (-not $script:RenameWindowTitleEnabled) {
        return [PSCustomObject]@{
            ProcessId            = $startedProcess.Id
            WindowTitle          = $null
            WindowRenameSuccess  = $false
            WindowRenameWarning  = 'Window title rename is disabled by settings.'
            WindowRenamedForPid  = $null
            WindowRenameSkipped  = $true
        }
    }

    $windowTitleResult = Set-D2RWindowTitleForLaunch -BeforePids $beforePids -LaunchedPid $startedProcess.Id -DisplayName $DisplayName -Region $Region

    return [PSCustomObject]@{
        ProcessId            = $startedProcess.Id
        WindowTitle          = $windowTitleResult.WindowTitle
        WindowRenameSuccess  = $windowTitleResult.Success
        WindowRenameWarning  = $windowTitleResult.Warning
        WindowRenamedForPid  = $windowTitleResult.WindowPid
        WindowRenameSkipped  = $false
    }
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
                        $launchResult = Start-D2RClient -Email $account.Email -Password $account.Password -Region $region -DisplayName $account.DisplayName -Mod $modSelection.Mod -ExtraArgs $modSelection.Extra
                        $titleState = if ($launchResult.WindowRenameSkipped) { 'disabled' } elseif ($launchResult.WindowRenameSuccess) { 'ok' } else { 'warning' }
                        $lastResult = "Last launch: $($account.DisplayName) (handles closed: $closedHandles, title=$titleState)"
                        if (-not $launchResult.WindowRenameSkipped -and $launchResult.WindowRenameWarning) {
                            $lastResult = "$lastResult | $($launchResult.WindowRenameWarning)"
                        }
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
                $renameState = if ($script:RenameWindowTitleEnabled) { 'ON' } else { 'OFF' }
                $resultLines.Add("Window rename: $renameState")
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
                        $launchResult = Start-D2RClient -Email $account.Email -Password $account.Password -Region $region -DisplayName $account.DisplayName -Mod $resolved.Mod -ExtraArgs $resolved.Extra

                        $modDisplay = if ([string]::IsNullOrWhiteSpace($resolved.Mod)) { 'none' } else { $resolved.Mod }
                        $titleSet = if ($launchResult.WindowRenameSkipped) { 'disabled' } elseif ($launchResult.WindowRenameSuccess) { 'true' } else { 'false' }
                        $resultLines.Add("  Success: mod=$modDisplay, closed_handles=$closedHandles, window_title_set=$titleSet")

                        if ($resolved.Warning) {
                            $resultLines.Add("  Warning: $($resolved.Warning)")
                        }
                        if (-not $launchResult.WindowRenameSkipped -and $launchResult.WindowRenameWarning) {
                            $resultLines.Add("  Warning: $($launchResult.WindowRenameWarning)")
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
    $settingsWarning = $null
    try {
        $settings = Get-LauncherSettings
        $script:RenameWindowTitleEnabled = [bool]$settings.rename_window_title
    } catch {
        $script:RenameWindowTitleEnabled = $true
        $settingsWarning = "Failed to load settings.txt; using defaults. $($_.Exception.Message)"
    }

    try {
        $Host.UI.RawUI.WindowTitle = 'D2R Multi Launcher'
    } catch {
        # Ignore non-interactive hosts that do not support setting window title.
    }

    if ($settingsWarning) {
        Show-StatusAndWait -Title 'Settings warning' -Lines @($settingsWarning)
    }

    while ($true) {
        $renameState = if ($script:RenameWindowTitleEnabled) { 'ON' } else { 'OFF' }
        $mainItems = @(
            "Rename Window Title: $renameState"
            ' '
            'Single client launch'
            'Batch multi-client launch'
            'Start official launcher'
            'Exit'
        )

        $selection = Show-Menu -Title 'D2R Multi Launcher' -Items $mainItems -InitialIndex 2

        switch ($selection) {
            0 {
                $previousValue = $script:RenameWindowTitleEnabled
                $script:RenameWindowTitleEnabled = -not $script:RenameWindowTitleEnabled
                try {
                    Save-LauncherSettings -RenameWindowTitleEnabled $script:RenameWindowTitleEnabled
                } catch {
                    $script:RenameWindowTitleEnabled = $previousValue
                    Show-StatusAndWait -Title 'Settings save failed' -Lines @($_.Exception.Message)
                }
            }
            2 { Invoke-SingleClientFlow }
            3 { Invoke-MultiClientFlow }
            4 { Invoke-OfficialLauncher }
            5 {
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
