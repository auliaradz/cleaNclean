<p align="center">
  <img src="assets/logo.svg" alt="cleaNclean Logo" width="140" height="140" />
</p>

<h1 align="center">cleaNclean v.1.0.0</h1>

<p align="center">
  <strong>Windows System Uninstaller, Orphaned Leftover &amp; Sandbox/GPU Hook Cleaner</strong><br/>
  A fast, native <strong>C# / .NET 8 (WPF)</strong> desktop utility with a <em>Revo Uninstaller</em>-inspired high-density interface to uninstall Windows programs, sweep orphaned leftovers, repair broken AppContainer Sandbox ACLs, and clean orphaned Vulkan/GPU overlay hooks.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v.1.0.0-2563EB?style=flat-square" alt="Version v.1.0.0" />
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20(x64)-0284C7?style=flat-square" alt="Platform Windows" />
  <img src="https://img.shields.io/badge/.NET-8.0%20WPF-7C3AED?style=flat-square" alt=".NET 8 WPF" />
  <img src="https://img.shields.io/badge/language-English%20%7C%20Bahasa%20Indonesia-059669?style=flat-square" alt="Bilingual UI" />
  <img src="https://img.shields.io/badge/license-MIT-F59E0B?style=flat-square" alt="License MIT" />
</p>

---

## 🌟 Key Features

### 1. 📦 Uninstaller & Windows Apps Manager
- **Desktop Uninstaller (`64-bit` & `32-bit`):** Enumerates all installed programs from `HKLM\SOFTWARE\...\Uninstall`, `HKLM\SOFTWARE\WOW6432Node\...\Uninstall`, and `HKCU\Software\...\Uninstall` with real `.exe`/`DisplayIcon` icon extraction, estimated size, version, architecture (`64-bit` / `32-bit`), install date (`dd/MM/yyyy HH.mm.ss`), publisher, and install path.
- **Windows Apps Manager (`AppX` / `MSIX`):** Lists installed Microsoft Store / UWP packages with display name, publisher, and logo extraction from `AppxManifest.xml`.
- **Automated *Uninstall + Scan Leftovers* Workflow:** Launches the application's built-in uninstaller (or `Remove-AppxPackage` for Store apps), waits for completion, and **automatically triggers Leftover Scanner** to sweep any remaining files, folders, and Registry keys.
- **Right-Click Context Menu:**
  - `🗑️ Uninstall + Scan Leftovers`
  - `🔍 Scan Leftovers Only (Without Uninstall)`
  - `📂 Open Install Location`
  - `🔑 Open Registry Key (Regedit)` *(jumps directly to the exact key in `regedit.exe`)*
  - `🌐 Search Online (Google)`
  - `📋 Copy Uninstall String`

---

### 2. 🧹 Orphaned Leftover Scanner & Cleaner
Detects remnants of uninstalled applications using a **Multi-Drive Deep Indexer**, *CamelCase/Acronym* token boundary matching, and a built-in *System Whitelist* to keep active applications safe:
- **`AppData`, `ProgramData` & `Program Files` Folders:** Scans `%APPDATA%` (`Roaming`), `%LOCALAPPDATA%` (`Local` & `LocalLow`), `%PROGRAMDATA%`, and orphaned folders in `Program Files` / `Program Files (x86)`.
- **Windows Registry (`HKCU` & `HKLM`):** Scans orphaned vendor/application keys in `HKCU\Software`, `HKLM\SOFTWARE`, and `HKLM\SOFTWARE\WOW6432Node`.
- **Broken Shortcuts (`.lnk`):** Scans Desktop (`User` & `Public`), Start Menu, and Startup folders for shortcuts whose target `.exe` is missing as well as uninstalled **UWP / Microsoft Store (`WindowsApps`)** shortcuts via binary `UTF-16LE` & `ASCII` inspection.
- **Task Scheduler & Startup Entries:** Scans `C:\Windows\System32\Tasks` XML definitions and Registry `Run` entries pointing to missing executables.
- **Instant Checkbox Filtering & Single Select-All Toggle:** Filter findings live by category (`AppData / Folder`, `Registry`, `Shortcut`, `Task & Startup`) with a safe default-unchecked `Select All` toggle.

---

### 3. 🛡️ Orphaned Sandbox & Graphics Hook Cleaner
A universal diagnostic and repair module supporting both `Scan()` (*Dry-Run*) and `Clean()`:

1. **Orphaned AppContainer SID & Sandbox ACL Sanitizer**
   - Scans directory Access Control Lists (ACLs) across `%LOCALAPPDATA%`, `%LOCALAPPDATA%\Programs`, and `%APPDATA%`.
   - Identifies orphaned specific AppContainer SIDs (`S-1-15-2-<8-subauthorities>`) that no longer exist in `HKCU\...\AppContainer\Mappings\<SID>` or `%LOCALAPPDATA%\Packages`.
   - **Mandatory Whitelist:** Strictly protects universal capability SIDs `S-1-15-2-1` (`ALL APPLICATION PACKAGES`) and `S-1-15-2-2` (`ALL RESTRICTED APPLICATION PACKAGES`).
   - **Sandbox Auto-Heal (`*S-1-15-2-1`):** Automatically injects `ReadAndExecute (OI)(CI)(RX)` permissions for `ALL APPLICATION PACKAGES` on application directories with broken sandbox ACLs to prevent Chromium/Electron/WebView2 GPU Sandbox crashes (`STATUS_BREAKPOINT`).

2. **Orphaned Vulkan & GPU Overlay Hook Cleaner**
   - Scans `ImplicitLayers` and `ExplicitLayers` under `HKLM\SOFTWARE\Khronos\Vulkan`, `HKLM\SOFTWARE\WOW6432Node\Khronos\Vulkan`, and `HKCU\SOFTWARE\Khronos\Vulkan`.
   - Verifies whether the layer `.json` manifest exists on disk, parses `layer.library_path` to verify the `.dll` binary exists, and detects orphaned `C:\ProgramData\*hook*` folders whose parent app has been uninstalled.
   - Supports two actions per finding: **`Remove`** (delete Registry entry & orphaned hook directory) or **`Disable`** (set `DWORD = 1` to disable layer injection without deleting).

3. **Broken App Launcher & Proxy Shortcut Validator**
   - Validates shortcuts across Desktop, Start Menu, and Taskbar Pinned (`%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar`).
   - **Squirrel / Stub Launcher Validator:** Verifies that stub launchers in `%LOCALAPPDATA%\<Vendor>\<App>` still contain valid `app-*` version folders and readable `*S-1-15-2-1` permissions.
   - **Browser PWA Proxy Validator (`chrome_proxy.exe` / `msedge_proxy.exe`):** Inspects `--app-id=<id>` arguments and checks whether the corresponding Web App is still installed in the browser's `User Data` profiles.

---

## 🌐 Bilingual Interface (English & Bahasa Indonesia)
- **English** is the default language on startup.
- Click **`🌐 Language: EN ▾`** on the Top Ribbon Toolbar at any time to switch instantaneously between **🇺🇸 English (Default)** and **🇮🇩 Bahasa Indonesia** without restarting the application.

---

## 🔒 Safety, Backups & Audit Logs

- **Send to Recycle Bin (Safe by Default):** File, folder, and broken shortcut removals are sent to the **Windows Recycle Bin** by default so they can be restored if needed.
- **Automatic Registry Backup (`.reg`):** Before deleting any leftover Registry key or Vulkan layer entry, `cleaNclean` automatically exports a `.reg` backup to `%LOCALAPPDATA%\cleaNclean\Backups\`.
- **Automatic SDDL ACL Backup & Audit Log:** Before modifying any directory ACL in the Sandbox module, the original SDDL string is backed up to `%LOCALAPPDATA%\cleaNclean\Logs\acl_sddl_backups.jsonl` alongside a detailed execution log in `sandbox_hook_cleaner.log`.
- **One-Click UAC Elevation:** Displays current privilege status (`Mode: Standard User` vs `Mode: Administrator`) with a one-click **Admin Mode** button to relaunch elevated when cleaning system-wide (`HKLM` / `ProgramData`) targets.

---

## 📥 Download & Running Releases

Pre-packaged archives can be downloaded from the [**GitHub Releases**](../../releases) page (or generated locally in `./dist/`):

| Package | Description | Requirement |
| :--- | :--- | :--- |
| **`cleaNclean-v1.0.0-win-x64-standalone.zip`** | Self-contained single-file `cleaNclean.exe` (includes .NET 8 runtime inside the executable) | Windows 10 / 11 (x64) — **No .NET installation required** |
| **`cleaNclean-v1.0.0-win-x64-lightweight.zip`** | Lightweight single-file `cleaNclean.exe` | Windows 10 / 11 (x64) + [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) |

---

## 🛠️ Building from Source

### Prerequisites
- **OS:** Windows 10 or Windows 11 (x64)
- **SDK:** [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (`net8.0-windows`)

### 1. Build & Run in Release Mode
```powershell
dotnet build .\cleaNclean.csproj -c Release
Start-Process .\bin\Release\net8.0-windows\cleaNclean.exe
```

### 2. Build GitHub Release Packages (`.\dist\`)
Run the release packaging script to generate both the **Standalone** and **Lightweight** `.zip` archives plus `SHA256SUMS.txt`:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_release.ps1
```

### 3. Regenerate Multi-Resolution Icon (`assets/logo.svg` → `assets/app.ico`)
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\convert_svg_to_ico.ps1
```

### 4. Command-Line (CLI) Automation Flags
- `--self-test`: Runs an automated end-to-end integration test across all leftover scanners and Sandbox/Vulkan Hook cleaners using safe temporary dummy fixtures.
- `--dump-scan "<output.txt>"`: Runs a headless automatic leftover scan and writes findings to a text file.
- `--scan-sandbox-json "<output.json>"`: Runs a headless Dry-Run scan of the Sandbox & Graphics Hook module and exports structured JSON findings.

---

## 📄 License

Licensed under the [MIT License](LICENSE).
