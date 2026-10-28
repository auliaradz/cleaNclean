# Changelog — cleaNclean

All notable changes to **cleaNclean** are documented in this file.

---

## [v.1.0.0] - 2026-10-28

### 🎉 Initial Public Release (`v.1.0.0`)

#### 📦 Uninstaller & Windows Apps Manager
- **Revo-Style High-Density UI:** Top Ribbon Toolbar, real-time Search & Filter bar, sortable high-density DataGrid with native `.exe`/`DisplayIcon` icon extraction, docked **Description Panel**, and 3-panel **Classic Bottom Status Bar**.
- **Desktop Uninstaller (`64-bit` & `32-bit`):** Enumerates all installed applications across `HKLM` (`64-bit` & `WOW6432Node`) and `HKCU`, runs built-in uninstallers, and automatically triggers post-uninstall **Leftover Scanning**.
- **Windows Apps (`AppX` / `MSIX`):** Lists Microsoft Store & UWP packages with `AppxManifest.xml` display name/publisher resolution and one-click `Remove-AppxPackage` + leftover scan.

#### 🧹 Orphaned Leftover Scanner & Cleaner
- **Multi-Drive Deep Indexer:** Cross-references installed programs, UWP packages, running processes, Windows Services, and Steam/Epic/GOG libraries across all fixed drives (`C:\`, `D:\`, etc.) to prevent false positives.
- **4 Core Scanners:**
  1. `AppData / Folder` (`%APPDATA%`, `%LOCALAPPDATA%`, `LocalLow`, `%PROGRAMDATA%`, `Program Files`, `Program Files (x86)`)
  2. `Registry` (`HKCU\Software`, `HKLM\SOFTWARE`, `WOW6432Node`)
  3. `Broken Shortcuts` (`.lnk` & `.url` across Desktop, Public Desktop, Start Menu, and Startup — including binary `UTF-16LE` inspection for uninstalled UWP / `WindowsApps` shortcuts)
  4. `Task Scheduler & Startup` (`C:\Windows\System32\Tasks` XML & Registry `Run` entries)

#### 🛡️ Orphaned Sandbox & Graphics Hook Cleaner
- **Sub-Module 1 — AppContainer SID & Sandbox ACL Sanitizer:** Detects orphaned `S-1-15-2-*` SIDs in directory ACLs, strictly protects `S-1-15-2-1` (`ALL APPLICATION PACKAGES`) and `S-1-15-2-2`, and injects `*S-1-15-2-1` Read & Execute permissions (`Auto-Heal`) to prevent Chromium/Electron/WebView2 GPU Sandbox crashes (`STATUS_BREAKPOINT`).
- **Sub-Module 2 — Vulkan & GPU Overlay Hook Cleaner:** Scans `ImplicitLayers` and `ExplicitLayers` in `HKLM`/`HKCU` for missing `.json` or `.dll` files and orphaned `C:\ProgramData\*hook*` directories, with `Remove` and `Disable` (`DWORD = 1`) modes.
- **Sub-Module 3 — Broken Launcher & PWA Proxy Validator:** Validates Squirrel `Update.exe --processStart` stub launchers and Chromium/Edge PWA proxy shortcuts (`--app-id=...`).

#### 🔒 Safety, Backup & Localization
- **Bilingual UI (English Default + Bahasa Indonesia):** Instant live language switching via the `🌐 Language: EN ▾` Ribbon button.
- **Safe by Default:** Sends deleted files/folders to the **Windows Recycle Bin**, exports `.reg` backups before Registry deletion, and records original SDDL ACL strings (`acl_sddl_backups.jsonl`) before permission repairs.
