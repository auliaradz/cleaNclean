using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace cleaNclean.Services;

public enum AppLanguage
{
    English,
    Indonesian
}

public class LocalizationManager : INotifyPropertyChanged
{
    public static LocalizationManager Instance { get; } = new();

    private AppLanguage _currentLanguage = AppLanguage.English; // Default is English
    public AppLanguage CurrentLanguage
    {
        get => _currentLanguage;
        set
        {
            if (_currentLanguage == value) return;
            _currentLanguage = value;
            OnPropertyChanged(string.Empty); // Notify all bound properties
            LanguageChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public bool IsEnglish => CurrentLanguage == AppLanguage.English;
    public event EventHandler? LanguageChanged;

    // --- Top Ribbon Toolbar ---
    public string RibbonUninstaller => IsEnglish ? "Uninstaller" : "Uninstaller";
    public string TipUninstaller => IsEnglish
        ? "List all installed desktop applications on Windows (Win32 / 64-bit / 32-bit)"
        : "Daftar seluruh aplikasi desktop yang terinstal di Windows (Win32 / 64-bit / 32-bit)";

    public string RibbonWindowsApps => IsEnglish ? "Windows Apps" : "Windows Apps";
    public string TipWindowsApps => IsEnglish
        ? "List installed UWP / Microsoft Store packages (AppX / MSIX)"
        : "Daftar paket aplikasi UWP / Microsoft Store (AppX / MSIX)";

    public string RibbonLeftoverScanner => IsEnglish ? "Leftover Scanner" : "Leftover Scanner";
    public string TipLeftoverScanner => IsEnglish
        ? "Scan & clean orphaned leftovers (AppData, ProgramData, Registry, Shortcuts, Task Scheduler)"
        : "Pemindai & Pembersih Orphaned Leftover (AppData, ProgramData, Registry, Shortcut, Task Scheduler)";

    public string RibbonSandboxHooks => IsEnglish ? "Sandbox & Hooks" : "Sandbox & Hooks";
    public string TipSandboxHooks => IsEnglish
        ? "Orphaned AppContainer SID, Sandbox ACL Auto-Heal, Vulkan Overlay Hook & Broken Launcher Cleaner"
        : "Orphaned AppContainer SID, Sandbox ACL Auto-Heal, Vulkan Overlay Hook & Broken Launcher Cleaner";

    public string RibbonUninstall => IsEnglish ? "Uninstall" : "Uninstall";
    public string TipUninstallAction => IsEnglish
        ? "Run the selected application's uninstaller and automatically scan for its leftovers"
        : "Jalankan uninstaller bawaan aplikasi terpilih lalu otomatis pindai sisa Leftover-nya";

    public string RibbonScanLeftovers => IsEnglish ? "Scan Leftovers" : "Scan Leftovers";
    public string TipScanAction => IsEnglish
        ? "Scan leftovers for the selected app (or run Automatic / Dry-Run Scan on the active tab)"
        : "Pindai Leftover aplikasi terpilih (atau jalankan Scan Otomatis / Dry-Run Scan pada tab aktif)";

    public string RibbonCleanSelected => IsEnglish ? "Clean Selected" : "Clean Selected";
    public string TipCleanAction => IsEnglish
        ? "Clean or repair all checked items in the Leftover Scanner or Sandbox & Hooks tab"
        : "Bersihkan / Perbaiki seluruh item yang dicentang pada tab Leftover Scanner atau Sandbox & Hooks";

    public string RibbonRefresh => IsEnglish ? "Refresh" : "Refresh";
    public string TipRefresh => IsEnglish
        ? "Reload / Rescan the active tab"
        : "Muat ulang / Pindai ulang daftar pada tab yang sedang aktif";

    public string RibbonBackupsLogs => IsEnglish ? "Backups & Logs ▾" : "Backups & Logs ▾";
    public string TipBackups => IsEnglish
        ? "Open Registry Backup folder (.reg), Audit Log & SDDL Backup folder, or export JSON report"
        : "Buka folder Backup Registry (.reg), folder Log Audit & Backup SDDL, atau ekspor laporan JSON";

    public string MenuOpenRegBackup => IsEnglish ? "📂 Open Registry Backup Folder (.reg)" : "📂 Buka Folder Backup Registry (.reg)";
    public string MenuOpenAuditLogs => IsEnglish ? "📋 Open Audit Log & SDDL Backup Folder" : "📋 Buka Folder Log Audit & Backup SDDL";
    public string MenuExportJson => IsEnglish ? "📄 Export Sandbox & Hook Report (.json)" : "📄 Ekspor Laporan Sandbox & Hook (.json)";

    public string RibbonLanguageLabel => IsEnglish ? "Language: EN ▾" : "Bahasa: ID ▾";
    public string TipLanguage => IsEnglish ? "Switch application language (English / Bahasa Indonesia)" : "Ubah bahasa aplikasi (English / Bahasa Indonesia)";
    public string TipAdmin => IsEnglish ? "Click to restart cleaNclean as Administrator (UAC Elevated)" : "Klik untuk memulai ulang cleaNclean sebagai Administrator (UAC Elevated)";

    // --- Search & Filter Bar ---
    public string QuickFilterTooltip => IsEnglish ? "Type to filter the table instantly" : "Ketik untuk memfilter tabel secara instan";
    public string ClearFilterTooltip => IsEnglish ? "Clear filter text" : "Bersihkan teks filter";
    public string SearchByLabel => IsEnglish ? "Search by:" : "Cari berdasarkan:";
    public string FilterByLabel => IsEnglish ? "Filter by:" : "Filter:";
    public string ChkAppData => IsEnglish ? "AppData / Folder" : "AppData / Folder";
    public string ChkRegistry => IsEnglish ? "Registry" : "Registry";
    public string ChkShortcut => IsEnglish ? "Shortcut" : "Shortcut";
    public string ChkTaskStartup => IsEnglish ? "Task & Startup" : "Task & Startup";
    public string ManualSearchLabel => IsEnglish ? "Manual Search:" : "Cari Manual:";
    public string ManualSearchTooltip => IsEnglish ? "Type an uninstalled app name and press Enter" : "Ketik nama aplikasi yang sudah dihapus lalu tekan Enter";
    public string ManualSearchButton => IsEnglish ? "Search" : "Cari";
    public string SelectAllLabel => IsEnglish ? "Select All" : "Pilih Semua";
    public string SelectAllTooltip => IsEnglish
        ? "Check to select all visible items; uncheck to deselect all"
        : "Centang untuk memilih semua item yang tampil; hilangkan centang untuk melepas semua pilihan";

    public string ChkAppContainerAcl => IsEnglish ? "AppContainer ACL" : "AppContainer ACL";
    public string ChkVulkanHooks => IsEnglish ? "Vulkan Hooks" : "Vulkan Hooks";
    public string ChkLauncherPwa => IsEnglish ? "Launcher & PWA" : "Launcher & PWA";

    // --- Context Menus ---
    public string CtxUninstallAndScan => IsEnglish ? "🗑️ Uninstall + Scan Leftovers" : "🗑️ Uninstall + Scan Leftovers";
    public string CtxUninstallAppxAndScan => IsEnglish ? "🗑️ Uninstall AppX + Scan Leftovers" : "🗑️ Uninstall AppX + Scan Leftovers";
    public string CtxScanLeftoversOnly => IsEnglish ? "🔍 Scan Leftovers Only (Without Uninstall)" : "🔍 Scan Leftovers Only (Tanpa Uninstall)";
    public string CtxOpenInstallLocation => IsEnglish ? "📂 Open Install Location" : "📂 Buka Lokasi Instalasi";
    public string CtxOpenPackageLocation => IsEnglish ? "📂 Open Package Location" : "📂 Buka Lokasi Paket";
    public string CtxOpenRegistryKey => IsEnglish ? "🔑 Open Registry Key (Regedit)" : "🔑 Buka Kunci Registry (Regedit)";
    public string CtxSearchOnline => IsEnglish ? "🌐 Search Online (Google)" : "🌐 Cari Online (Google)";
    public string CtxCopyUninstallString => IsEnglish ? "📋 Copy Uninstall String" : "📋 Salin Uninstall String";

    public string CtxOpenExplorer => IsEnglish ? "📂 Open Location in File Explorer" : "📂 Buka Lokasi di File Explorer";
    public string CtxCopyPath => IsEnglish ? "📋 Copy Path / Registry Key" : "📋 Salin Path / Registry Key";
    public string CtxAddWhitelist => IsEnglish ? "🛡️ Exclude (Add to Whitelist)" : "🛡️ Kecualikan (Tambah ke Whitelist)";

    // --- Empty States ---
    public string EmptyLeftoverTitle => IsEnglish ? "No Leftover Scan Data Yet" : "Belum Ada Data Pemindaian Leftover";
    public string EmptyLeftoverSub => IsEnglish
        ? "Click 'Scan Leftovers' on the top toolbar to scan for remnants of uninstalled applications."
        : "Klik tombol 'Scan Leftovers' di toolbar atas untuk memindai seluruh sisa aplikasi yang telah dihapus.";

    public string EmptySandboxTitle => IsEnglish ? "No Sandbox & GPU Hook Dry-Run Results Yet" : "Belum Ada Hasil Dry-Run Scan Sandbox & GPU Hooks";
    public string EmptySandboxSub => IsEnglish
        ? "Click 'Scan Leftovers' or 'Refresh' on the top toolbar to scan AppContainer SIDs, Vulkan Hooks & Launchers."
        : "Klik tombol 'Scan Leftovers' atau 'Refresh' di toolbar atas untuk memindai AppContainer SID, Vulkan Hooks & Launcher.";

    // --- Description Panel & Status Bar ---
    public string ChkRecycleBin => IsEnglish ? "Send to Recycle Bin (Safe)" : "Kirim ke Recycle Bin (Aman)";
    public string ChkBackupRegSddl => IsEnglish ? "Backup Registry (.reg) & SDDL" : "Backup Registry (.reg) & SDDL";
    public string ToggleDescriptionTooltip => IsEnglish ? "Show / Hide Description Panel" : "Tampilkan / Sembunyikan Description Panel";
    public string CancelProcessButton => IsEnglish ? "Cancel" : "Batalkan Proses";
    public string StatusBarAdminTooltip => IsEnglish ? "Click to restart cleaNclean as Administrator (UAC Elevated)" : "Klik untuk memulai ulang cleaNclean sebagai Administrator (UAC Elevated)";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
