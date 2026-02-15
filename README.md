# D2R Multi Launcher TUI

Keyboard-only launcher workflow for Diablo II: Resurrected.

## Features
- Single account launch loop (stay on account list after each launch)
- Batch launch with one-screen per-account mod editing
- Arrow key and Enter based TUI
- Esc/Backspace to go back
- External mod definitions from `mods_config.txt`

## Requirements
- Windows
- Windows PowerShell 5.1 or newer
- Administrator privileges (script auto-elevates)
- `D2R.exe` and `handle64.exe` in the same folder as `d2r_multi_launcher_tui.ps1` (Game root)

## Placement (Important)
This launcher script resolves paths from its own folder (`$PSScriptRoot`).

Recommended layout:
1. Put these files in your Diablo II: Resurrected install folder (same folder as `D2R.exe`):
   - `d2r_multi_launcher_tui.ps1`
   - `run_d2r_multi_launcher_tui.cmd`
   - `accounts.txt`
   - `mods_config.txt`
   - `settings.txt`
2. Keep README/example files anywhere you like.

If `d2r_multi_launcher_tui.ps1` is not in the same folder as `D2R.exe` and `handle64.exe`, launch will fail.

## Download `handle64.exe`
1. Open Microsoft Sysinternals Handle page:
   - `https://learn.microsoft.com/sysinternals/downloads/handle`
2. Download `Handle.zip`
3. Extract the zip
4. Copy `handle64.exe` into this project folder (same folder as `d2r_multi_launcher_tui.ps1`)

## Files
- `d2r_multi_launcher_tui.ps1`: main launcher script
- `run_d2r_multi_launcher_tui.cmd`: convenience launcher
- `accounts.txt`: account data (do not commit)
- `mods_config.txt`: mod definitions (`mod|args`)
- `settings.txt`: launcher settings (`key=value`)

## Quick Start (From Zero to Launch)
1. Prepare folder location:
   - Place runtime files in your D2R game folder (same folder as `D2R.exe`).
2. Prepare config files:
   - Copy `accounts.example.txt` -> `accounts.txt`
   - Copy `mods_config.example.txt` -> `mods_config.txt`
   - Copy `settings.example.txt` -> `settings.txt`
3. Edit `accounts.txt` with your account data.
4. Edit `mods_config.txt` with your mod options and optional args.
5. Launch:
   - `run_d2r_multi_launcher_tui.cmd`, or
   - `powershell -NoProfile -ExecutionPolicy Bypass -File .\d2r_multi_launcher_tui.ps1`

Expected result:
- You should see the TUI menu and can navigate with arrow keys + Enter.

## Config Format

### `accounts.txt`
One account per line:

`email;password;display_name;mod(optional)`

Example:

`user@example.com;your_password;MyCharacter;yourmod|-ns`

### `mods_config.txt`
One mod per line:

`mod_name|extra_args`

Examples:
- `yourmod|`
- `yourmod|-ns`
- `none|`

Notes:
- `none` means launch without `-mod`
- If `mods_config.txt` is missing, only `none` is available
- Mod dedupe uses `name+args` as identity:
  - `yourmod|` and `yourmod|-ns` are treated as different options

### `settings.txt`
Launcher settings in `key=value` format.

Example:
- `rename_window_title=true`

Notes:
- `rename_window_title=true` by default
- You can toggle this in main menu: `Rename Window Title: ON/OFF`

## Key Bindings
- `Up/Down`: move selection
- `Left/Right`: change mod in batch editor
- `Enter`: confirm
- `Esc` / `Backspace`: back
- Main menu includes `Rename Window Title: ON/OFF` (saved to `settings.txt`)

## Main Menu Behavior
- `Rename Window Title: ON/OFF` is shown on the first line.
- A separator blank line is shown between rename toggle and launch actions.
- Default selected item remains `Single client launch`.

## Troubleshooting
- `Missing required files: D2R.exe`:
  - Move script/runtime files to the D2R install folder (same folder as `D2R.exe`).
- `Missing required files: handle64.exe`:
  - Download from Sysinternals Handle page and place `handle64.exe` next to the script.
- UAC prompt appears then closes:
  - Run from a normal interactive PowerShell/Command Prompt, not a restricted terminal host.
- `Interactive console with keyboard input is required.`:
  - Use Windows Terminal / PowerShell console directly (not non-interactive runners).
- Accounts not loaded or skipped:
  - Check `accounts.txt` format: `email;password;display_name;mod(optional)`.
- Cannot save title toggle setting:
  - Ensure launcher folder is writable and `settings.txt` is not read-only.

## Security Notes
- `accounts.txt` contains plaintext credentials. Never commit it.
- Review `.gitignore` before pushing.
- Accounts used by this launcher must **not** have Blizzard Authenticator (2FA) enabled.

## Disclaimer
- Unofficial project, not affiliated with Blizzard.
- Use at your own risk.
- You are responsible for following game terms and local regulations.
