using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using cleaNclean.Models;
using cleaNclean.Modules.SandboxAndHooks.Models;
using cleaNclean.Modules.SandboxAndHooks.Services;
using cleaNclean.Services;

namespace cleaNclean.ViewModels;

public class MainViewModel : INotifyPropertyChanged
{
    private readonly LeftoverScanOrchestrator _orchestrator = new();
    private readonly LeftoverCleanerService _cleanerService = new();
    private readonly SandboxAndHookOrchestrator _sandboxHookOrchestrator;
    private readonly InstalledProgramsEnumerator _programsEnumerator = new();
    private CancellationTokenSource? _scanCts;
    private bool _windowsAppsLoadedOnce;

    // 1. Installed Win32/64-bit Programs (Uninstaller Tab)
    public ObservableCollection<InstalledProgramItem> InstalledPrograms { get; } = [];
    public ICollectionView FilteredProgramsView { get; }

    // 2. Windows Store / UWP Apps (Windows Apps Tab)
    public ObservableCollection<InstalledProgramItem> WindowsStoreApps { get; } = [];
    public ICollectionView FilteredWindowsAppsView { get; }

    // 3. Orphaned Leftover Items (Leftover Scanner Tab)
    public ObservableCollection<LeftoverItem> AllItems { get; } = [];
    public ICollectionView FilteredItemsView { get; }

    // 4. Orphaned Sandbox & Graphics Hook Findings (Sandbox & Hooks Tab)
    public ObservableCollection<DiagnosticFinding> SandboxHookFindings { get; } = [];
    public ICollectionView FilteredSandboxHookView { get; }

    public LocalizationManager Loc => LocalizationManager.Instance;

    public bool IsAdmin => SecurityAuditLogger.IsRunningAsAdministrator();
    public string AdminStatusBadge => IsAdmin
        ? "🛡️ Mode: Administrator"
        : (Loc.IsEnglish ? "⚠️ Mode: Standard User" : "⚠️ Mode: Pengguna Standar");
    public string AdminToolbarLabel => IsAdmin
        ? (Loc.IsEnglish ? "Admin (Active)" : "Admin (Aktif)")
        : "Admin Mode";

    public void SetLanguage(AppLanguage lang)
    {
        Loc.CurrentLanguage = lang;
    }

    // Active Module Tab: "UNINSTALLER", "WINDOWS_APPS", "LEFTOVER", "SANDBOX_HOOKS"
    private string _activeModuleTab = "UNINSTALLER";
    public string ActiveModuleTab
    {
        get => _activeModuleTab;
        set
        {
            if (_activeModuleTab == value) return;
            _activeModuleTab = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(UninstallerViewVisibility));
            OnPropertyChanged(nameof(WindowsAppsViewVisibility));
            OnPropertyChanged(nameof(LeftoverViewVisibility));
            OnPropertyChanged(nameof(SandboxHooksViewVisibility));
            OnPropertyChanged(nameof(ProgramSearchComboVisibility));
            OnPropertyChanged(nameof(LeftoverFilterBarVisibility));
            OnPropertyChanged(nameof(SandboxFilterBarVisibility));
            OnPropertyChanged(nameof(CleanerActionBarVisibility));
            OnPropertyChanged(nameof(CleanerActionButtonText));
            OnPropertyChanged(nameof(CanUninstallSelected));
            OnPropertyChanged(nameof(CanCleanSelected));
            OnPropertyChanged(nameof(StatusBarLeftCountText));
            RefreshDescriptionPanel();
        }
    }

    public Visibility UninstallerViewVisibility => ActiveModuleTab == "UNINSTALLER" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WindowsAppsViewVisibility => ActiveModuleTab == "WINDOWS_APPS" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility LeftoverViewVisibility => ActiveModuleTab == "LEFTOVER" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility SandboxHooksViewVisibility => ActiveModuleTab == "SANDBOX_HOOKS" ? Visibility.Visible : Visibility.Collapsed;

    public Visibility ProgramSearchComboVisibility => ActiveModuleTab is "UNINSTALLER" or "WINDOWS_APPS" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility LeftoverFilterBarVisibility => ActiveModuleTab == "LEFTOVER" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility SandboxFilterBarVisibility => ActiveModuleTab == "SANDBOX_HOOKS" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility CleanerActionBarVisibility => ActiveModuleTab is "LEFTOVER" or "SANDBOX_HOOKS" ? Visibility.Visible : Visibility.Collapsed;
    public string CleanerActionButtonText => ActiveModuleTab == "SANDBOX_HOOKS"
        ? (Loc.IsEnglish ? $"⚡ Execute Clean() ({SelectedSandboxHooksCount})" : $"⚡ Eksekusi Clean() ({SelectedSandboxHooksCount})")
        : (Loc.IsEnglish ? $"🗑️ Clean Selected ({SelectedCount})" : $"🗑️ Bersihkan Terpilih ({SelectedCount})");

    public Visibility LeftoverEmptyVisibility => TotalCount == 0 ? Visibility.Visible : Visibility.Collapsed;
    public Visibility SandboxEmptyVisibility => TotalSandboxHooksCount == 0 ? Visibility.Visible : Visibility.Collapsed;

    private bool _isDescriptionPanelVisible = true;
    public bool IsDescriptionPanelVisible
    {
        get => _isDescriptionPanelVisible;
        set
        {
            _isDescriptionPanelVisible = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(DescriptionPanelBodyVisibility));
            OnPropertyChanged(nameof(DescriptionToggleGlyph));
        }
    }

    public Visibility DescriptionPanelBodyVisibility => IsDescriptionPanelVisible ? Visibility.Visible : Visibility.Collapsed;
    public string DescriptionToggleGlyph => IsDescriptionPanelVisible ? "▾" : "▴";

    private InstalledProgramItem? _selectedProgram;
    public InstalledProgramItem? SelectedProgram
    {
        get => _selectedProgram;
        set
        {
            _selectedProgram = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanUninstallSelected));
            RefreshDescriptionPanel();
        }
    }

    private LeftoverItem? _selectedLeftover;
    public LeftoverItem? SelectedLeftover
    {
        get => _selectedLeftover;
        set
        {
            _selectedLeftover = value;
            OnPropertyChanged();
            RefreshDescriptionPanel();
        }
    }

    private DiagnosticFinding? _selectedSandboxFinding;
    public DiagnosticFinding? SelectedSandboxFinding
    {
        get => _selectedSandboxFinding;
        set
        {
            _selectedSandboxFinding = value;
            OnPropertyChanged();
            RefreshDescriptionPanel();
        }
    }

    public bool CanUninstallSelected =>
        IsNotBusy &&
        ActiveModuleTab is "UNINSTALLER" or "WINDOWS_APPS" &&
        SelectedProgram != null;

    public bool CanCleanSelected =>
        IsNotBusy &&
        ((ActiveModuleTab == "LEFTOVER" && SelectedCount > 0) ||
         (ActiveModuleTab == "SANDBOX_HOOKS" && SelectedSandboxHooksCount > 0));

    private string _descriptionHeaderTitle = "Description Panel";
    public string DescriptionHeaderTitle
    {
        get => _descriptionHeaderTitle;
        set { _descriptionHeaderTitle = value; OnPropertyChanged(); }
    }

    private string _descriptionPrimaryText =
        "Uninstaller lists all installed programs and components for the current user and all users. Click any row to view the Registry key and UninstallString, or right-click to Uninstall + Scan Leftovers.";
    public string DescriptionPrimaryText
    {
        get => _descriptionPrimaryText;
        set { _descriptionPrimaryText = value; OnPropertyChanged(); }
    }

    private string _descriptionSecondaryText = string.Empty;
    public string DescriptionSecondaryText
    {
        get => _descriptionSecondaryText;
        set
        {
            _descriptionSecondaryText = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(DescriptionSecondaryVisibility));
        }
    }

    public Visibility DescriptionSecondaryVisibility =>
        string.IsNullOrWhiteSpace(DescriptionSecondaryText) ? Visibility.Collapsed : Visibility.Visible;

    private string _programSearchField = "Name";
    public string ProgramSearchField
    {
        get => _programSearchField;
        set
        {
            _programSearchField = value;
            OnPropertyChanged();
            FilteredProgramsView.Refresh();
            FilteredWindowsAppsView.Refresh();
        }
    }

    private string _searchKeyword = string.Empty;
    public string SearchKeyword
    {
        get => _searchKeyword;
        set { _searchKeyword = value; OnPropertyChanged(); }
    }

    private string _filterText = string.Empty;
    public string FilterText
    {
        get => _filterText;
        set
        {
            _filterText = value;
            OnPropertyChanged();
            FilteredProgramsView.Refresh();
            FilteredWindowsAppsView.Refresh();
            FilteredItemsView.Refresh();
            FilteredSandboxHookView.Refresh();
            OnPropertyChanged(nameof(StatusBarLeftCountText));
        }
    }

    private string _selectedCategoryTab = "ALL";
    public string SelectedCategoryTab
    {
        get => _selectedCategoryTab;
        set
        {
            _selectedCategoryTab = value;
            OnPropertyChanged();
            FilteredItemsView.Refresh();
        }
    }

    private string _selectedSandboxFilter = "ALL";
    public string SelectedSandboxFilter
    {
        get => _selectedSandboxFilter;
        set
        {
            _selectedSandboxFilter = value;
            OnPropertyChanged();
            FilteredSandboxHookView.Refresh();
        }
    }

    // Sub-module toggles & live filters for Sandbox & Hook Cleaner
    private bool _scanAppContainerAcl = true;
    public bool ScanAppContainerAcl
    {
        get => _scanAppContainerAcl;
        set
        {
            if (_scanAppContainerAcl == value) return;
            _scanAppContainerAcl = value;
            OnPropertyChanged();
            RefreshSandboxCounters();
        }
    }

    private bool _scanVulkanHooks = true;
    public bool ScanVulkanHooks
    {
        get => _scanVulkanHooks;
        set
        {
            if (_scanVulkanHooks == value) return;
            _scanVulkanHooks = value;
            OnPropertyChanged();
            RefreshSandboxCounters();
        }
    }

    private bool _scanBrokenLaunchers = true;
    public bool ScanBrokenLaunchers
    {
        get => _scanBrokenLaunchers;
        set
        {
            if (_scanBrokenLaunchers == value) return;
            _scanBrokenLaunchers = value;
            OnPropertyChanged();
            RefreshSandboxCounters();
        }
    }

    // Area toggles & live filters for Leftover Scanner
    private bool _scanAppData = true;
    public bool ScanAppData
    {
        get => _scanAppData;
        set
        {
            if (_scanAppData == value) return;
            _scanAppData = value;
            OnPropertyChanged();
            FilteredItemsView.Refresh();
            SyncSelectAllLeftoversState();
            RefreshCounters();
        }
    }

    private bool _scanRegistry = true;
    public bool ScanRegistry
    {
        get => _scanRegistry;
        set
        {
            if (_scanRegistry == value) return;
            _scanRegistry = value;
            OnPropertyChanged();
            FilteredItemsView.Refresh();
            SyncSelectAllLeftoversState();
            RefreshCounters();
        }
    }

    private bool _scanShortcuts = true;
    public bool ScanShortcuts
    {
        get => _scanShortcuts;
        set
        {
            if (_scanShortcuts == value) return;
            _scanShortcuts = value;
            OnPropertyChanged();
            FilteredItemsView.Refresh();
            SyncSelectAllLeftoversState();
            RefreshCounters();
        }
    }

    private bool _scanTasks = true;
    public bool ScanTasks
    {
        get => _scanTasks;
        set
        {
            if (_scanTasks == value) return;
            _scanTasks = value;
            OnPropertyChanged();
            FilteredItemsView.Refresh();
            SyncSelectAllLeftoversState();
            RefreshCounters();
        }
    }

    private bool _isUpdatingSelectAllLeftovers;
    private bool _isAllLeftoversSelected;
    public bool IsAllLeftoversSelected
    {
        get => _isAllLeftoversSelected;
        set
        {
            if (_isAllLeftoversSelected == value) return;
            _isAllLeftoversSelected = value;
            OnPropertyChanged();
            if (!_isUpdatingSelectAllLeftovers)
            {
                SelectAllVisible(value);
            }
        }
    }

    private bool _isUpdatingSelectAllSandbox;
    private bool _isAllSandboxSelected;
    public bool IsAllSandboxSelected
    {
        get => _isAllSandboxSelected;
        set
        {
            if (_isAllSandboxSelected == value) return;
            _isAllSandboxSelected = value;
            OnPropertyChanged();
            if (!_isUpdatingSelectAllSandbox)
            {
                SelectAllSandboxVisible(value);
            }
        }
    }

    private bool _sendToRecycleBin = true;
    public bool SendToRecycleBin
    {
        get => _sendToRecycleBin;
        set { _sendToRecycleBin = value; OnPropertyChanged(); }
    }

    private bool _backupRegistry = true;
    public bool BackupRegistry
    {
        get => _backupRegistry;
        set { _backupRegistry = value; OnPropertyChanged(); }
    }

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            _isBusy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsNotBusy));
            OnPropertyChanged(nameof(CanUninstallSelected));
            OnPropertyChanged(nameof(CanCleanSelected));
        }
    }

    public bool IsNotBusy => !_isBusy;

    private string _statusMessage = "Loading installed applications...";
    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    // Counters for Standard Leftover Scanner (reflects active checkbox filters)
    public int TotalCount => FilteredItemsView?.Cast<LeftoverItem>().Count() ?? AllItems.Count;
    public int AppDataCount => AllItems.Count(i => i.Category == LeftoverCategory.AppDataFolder);
    public int RegistryCount => AllItems.Count(i => i.Category == LeftoverCategory.RegistryKey);
    public int ShortcutCount => AllItems.Count(i => i.Category == LeftoverCategory.BrokenShortcut);
    public int TaskCount => AllItems.Count(i => i.Category == LeftoverCategory.ScheduledTask);
    public int SelectedCount => FilteredItemsView?.Cast<LeftoverItem>().Count(i => i.IsSelected) ?? 0;
    public string SelectedTotalSize => LeftoverItem.FormatBytes(
        FilteredItemsView?.Cast<LeftoverItem>().Where(i => i.IsSelected).Sum(i => i.SizeInBytes) ?? 0,
        LeftoverCategory.AppDataFolder);

    // Counters for Sandbox & Graphics Hook Cleaner (reflects active checkbox filters)
    public int TotalSandboxHooksCount => FilteredSandboxHookView?.Cast<DiagnosticFinding>().Count() ?? SandboxHookFindings.Count;
    public int AppContainerSidCount => SandboxHookFindings.Count(f => f.Category is "OrphanedAppContainerSid" or "SandboxMissingAllAppPackages");
    public int VulkanHookCount => SandboxHookFindings.Count(f => f.Category == "VulkanOverlayHook");
    public int BrokenLauncherCount => SandboxHookFindings.Count(f => f.Category == "BrokenLauncherOrPwaShortcut");
    public int SelectedSandboxHooksCount => FilteredSandboxHookView?.Cast<DiagnosticFinding>().Count(f => f.IsSelected) ?? 0;

    public string StatusBarLeftCountText => ActiveModuleTab switch
    {
        "UNINSTALLER" => Loc.IsEnglish ? $"Installations: {InstalledPrograms.Count}" : $"Instalasi: {InstalledPrograms.Count}",
        "WINDOWS_APPS" => $"Windows Apps: {WindowsStoreApps.Count}",
        "LEFTOVER" => Loc.IsEnglish
            ? $"Leftovers Found: {TotalCount}  |  Selected: {SelectedCount} ({SelectedTotalSize})"
            : $"Leftover Ditemukan: {TotalCount}  |  Terpilih: {SelectedCount} ({SelectedTotalSize})",
        "SANDBOX_HOOKS" => Loc.IsEnglish
            ? $"Findings: {TotalSandboxHooksCount} (ACL: {AppContainerSidCount}, Vulkan: {VulkanHookCount}, Launcher: {BrokenLauncherCount})  |  Selected: {SelectedSandboxHooksCount}"
            : $"Temuan: {TotalSandboxHooksCount} (ACL: {AppContainerSidCount}, Vulkan: {VulkanHookCount}, Launcher: {BrokenLauncherCount})  |  Terpilih: {SelectedSandboxHooksCount}",
        _ => Loc.IsEnglish ? $"Installations: {InstalledPrograms.Count}" : $"Instalasi: {InstalledPrograms.Count}"
    };

    public MainViewModel()
    {
        _sandboxHookOrchestrator = new SandboxAndHookOrchestrator(_orchestrator.Indexer);

        FilteredProgramsView = CollectionViewSource.GetDefaultView(InstalledPrograms);
        FilteredProgramsView.Filter = FilterProgramPredicate;

        FilteredWindowsAppsView = CollectionViewSource.GetDefaultView(WindowsStoreApps);
        FilteredWindowsAppsView.Filter = FilterProgramPredicate;

        FilteredItemsView = CollectionViewSource.GetDefaultView(AllItems);
        FilteredItemsView.Filter = FilterPredicate;

        FilteredSandboxHookView = CollectionViewSource.GetDefaultView(SandboxHookFindings);
        FilteredSandboxHookView.Filter = FilterSandboxHookPredicate;

        Loc.LanguageChanged += OnLanguageChanged;
    }

    private void OnLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(Loc));
        OnPropertyChanged(nameof(AdminStatusBadge));
        OnPropertyChanged(nameof(AdminToolbarLabel));
        OnPropertyChanged(nameof(CleanerActionButtonText));
        OnPropertyChanged(nameof(StatusBarLeftCountText));

        foreach (var item in AllItems)
            item.RefreshLocalization();

        foreach (var finding in SandboxHookFindings)
            finding.RefreshLocalization();

        RefreshDescriptionPanel();
        StatusMessage = Loc.IsEnglish
            ? $"Language changed to English. ({InstalledPrograms.Count} installed programs loaded)"
            : $"Bahasa diubah ke Bahasa Indonesia. ({InstalledPrograms.Count} aplikasi terinstal dimuat)";
    }

    private bool FilterProgramPredicate(object obj)
    {
        if (obj is not InstalledProgramItem prog) return false;
        if (string.IsNullOrWhiteSpace(FilterText)) return true;

        string q = FilterText.Trim();
        return ProgramSearchField switch
        {
            "Name" => prog.Name.Contains(q, StringComparison.OrdinalIgnoreCase),
            "Company" => prog.Company.Contains(q, StringComparison.OrdinalIgnoreCase),
            "Version" => prog.Version.Contains(q, StringComparison.OrdinalIgnoreCase),
            "Comment" => prog.EffectiveComment.Contains(q, StringComparison.OrdinalIgnoreCase),
            _ => prog.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                 prog.Company.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                 prog.Version.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                 prog.EffectiveComment.Contains(q, StringComparison.OrdinalIgnoreCase)
        };
    }

    private bool FilterPredicate(object obj)
    {
        if (obj is not LeftoverItem item) return false;

        bool categoryAllowed = item.Category switch
        {
            LeftoverCategory.AppDataFolder => ScanAppData,
            LeftoverCategory.RegistryKey => ScanRegistry,
            LeftoverCategory.BrokenShortcut => ScanShortcuts,
            LeftoverCategory.ScheduledTask => ScanTasks,
            _ => true
        };
        if (!categoryAllowed) return false;

        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            string f = FilterText.Trim();
            return item.Name.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                   item.Location.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                   item.Reason.Contains(f, StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    private bool FilterSandboxHookPredicate(object obj)
    {
        if (obj is not DiagnosticFinding f) return false;

        bool subModuleAllowed = f.Category switch
        {
            "OrphanedAppContainerSid" or "SandboxMissingAllAppPackages" => ScanAppContainerAcl,
            "VulkanOverlayHook" => ScanVulkanHooks,
            "BrokenLauncherOrPwaShortcut" => ScanBrokenLaunchers,
            _ => true
        };
        if (!subModuleAllowed) return false;

        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            string q = FilterText.Trim();
            return f.Category.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                   f.Target.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                   f.IssueDescription.Contains(q, StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    public void RefreshDescriptionPanel()
    {
        if (ActiveModuleTab is "UNINSTALLER" or "WINDOWS_APPS")
        {
            if (SelectedProgram != null)
            {
                var p = SelectedProgram;
                string sizePart = string.IsNullOrWhiteSpace(p.FormattedSize)
                    ? (Loc.IsEnglish ? "Unknown size" : "Ukuran tidak diketahui")
                    : p.FormattedSize;
                string pubPart = string.IsNullOrWhiteSpace(p.Company) ? "-" : p.Company;
                DescriptionHeaderTitle = $"Description Panel — {p.Name} ({p.ArchitectureType}, {sizePart})";
                DescriptionPrimaryText =
                    $"Publisher: {pubPart}   |   Version: {(string.IsNullOrWhiteSpace(p.Version) ? "-" : p.Version)}   |   Install Date: {(string.IsNullOrWhiteSpace(p.FormattedInstallDate) ? "-" : p.FormattedInstallDate)}   |   Location: {(string.IsNullOrWhiteSpace(p.InstallLocation) ? "-" : p.InstallLocation)}";
                DescriptionSecondaryText =
                    $"Registry Key: {p.RegistryKeyPath}\nUninstall Command: {p.UninstallString}";
            }
            else
            {
                DescriptionHeaderTitle = "Description Panel";
                DescriptionPrimaryText = ActiveModuleTab == "UNINSTALLER"
                    ? (Loc.IsEnglish
                        ? "Uninstaller lists all installed programs and components for the current user and all users. Click any row to view Registry & UninstallString details, or right-click to Uninstall + Scan Leftovers."
                        : "Uninstaller menampilkan seluruh program dan komponen yang terinstal untuk pengguna saat ini maupun seluruh sistem. Klik baris aplikasi untuk melihat detail Registry & UninstallString, atau klik kanan untuk Uninstall + Scan Leftovers.")
                    : (Loc.IsEnglish
                        ? "Windows Apps lists UWP / Microsoft Store packages (AppX/MSIX) registered on your user profile. Select an app and click Uninstall or Scan Leftovers."
                        : "Windows Apps menampilkan paket aplikasi UWP / Microsoft Store (AppX/MSIX) yang terdaftar pada profil Anda. Pilih aplikasi lalu klik Uninstall atau Scan Leftovers.");
                DescriptionSecondaryText = string.Empty;
            }
        }
        else if (ActiveModuleTab == "LEFTOVER")
        {
            if (SelectedLeftover != null)
            {
                var l = SelectedLeftover;
                DescriptionHeaderTitle = $"Description Panel — [{l.CategoryLabel}] {l.Name} ({l.FormattedSize})";
                DescriptionPrimaryText = $"Full Path / Key: {l.Location}";
                DescriptionSecondaryText = Loc.IsEnglish
                    ? $"Detection Reason: {l.Reason}   |   Target Info: {l.TargetInfo}   |   Confidence: {l.ConfidenceLevel}"
                    : $"Alasan Deteksi: {l.Reason}   |   Target Info: {l.TargetInfo}   |   Keyakinan: {l.ConfidenceLevel}";
            }
            else
            {
                DescriptionHeaderTitle = "Description Panel — Leftover Scanner";
                DescriptionPrimaryText = Loc.IsEnglish
                    ? "Leftover Scanner scans orphaned AppData/ProgramData folders, HKCU/HKLM Registry keys, broken shortcuts (.lnk/.url), and Scheduled Tasks from uninstalled apps. Click any row to inspect the full uncropped path."
                    : "Leftover Scanner memindai folder AppData/ProgramData, Registry HKCU/HKLM, Shortcut rusak (.lnk/.url), dan Task Scheduler dari aplikasi yang sudah dihapus. Klik baris item untuk melihat path lengkap yang tidak terpotong.";
                DescriptionSecondaryText = string.Empty;
            }
        }
        else if (ActiveModuleTab == "SANDBOX_HOOKS")
        {
            if (SelectedSandboxFinding != null)
            {
                var f = SelectedSandboxFinding;
                string sddlInfo = f.Metadata.TryGetValue("OriginalSddl", out string? sddl) && !string.IsNullOrWhiteSpace(sddl)
                    ? (Loc.IsEnglish ? $"\nOriginal SDDL ACL: {sddl}" : $"\nSDDL ACL Asli: {sddl}")
                    : string.Empty;
                DescriptionHeaderTitle = $"Description Panel — [{f.CategoryBadge}] Severity: {f.SeverityLabel}";
                DescriptionPrimaryText = $"Full Target: {f.Target}";
                string reqAdminStr = f.RequiresAdmin
                    ? (Loc.IsEnglish ? "Yes (UAC)" : "Ya (UAC)")
                    : (Loc.IsEnglish ? "No" : "Tidak");
                DescriptionSecondaryText = $"Issue: {f.IssueDescription}   |   Recommended Action: {f.RecommendedActionLabel}   |   Requires Admin: {reqAdminStr}{sddlInfo}";
            }
            else
            {
                DescriptionHeaderTitle = "Description Panel — Orphaned Sandbox & Graphics Hook Cleaner";
                DescriptionPrimaryText = Loc.IsEnglish
                    ? "Detects Orphaned AppContainer SIDs (S-1-15-2-*), injects *S-1-15-2-1 Auto-Heal permissions to prevent GPU Sandbox crashes, cleans orphaned Vulkan/Overlay layers, and validates Squirrel & PWA launchers."
                    : "Modul ini mendeteksi Orphaned AppContainer SID (S-1-15-2-*), menyuntikkan izin Auto-Heal *S-1-15-2-1 untuk mencegah crash GPU Sandbox, membersihkan layer Vulkan/Overlay yatim, serta memvalidasi launcher Squirrel & PWA.";
                DescriptionSecondaryText = string.Empty;
            }
        }
    }

    public async Task LoadInstalledProgramsAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        StatusMessage = Loc.IsEnglish
            ? "Loading installed applications from Registry..."
            : "Memuat daftar aplikasi terinstal dari Registry...";

        try
        {
            var list = await _programsEnumerator.GetInstalledProgramsAsync();
            InstalledPrograms.Clear();
            foreach (var item in list)
            {
                InstalledPrograms.Add(item);
            }
            OnPropertyChanged(nameof(StatusBarLeftCountText));
            StatusMessage = Loc.IsEnglish
                ? $"Ready. Found {InstalledPrograms.Count} installed applications."
                : $"Siap. Ditemukan {InstalledPrograms.Count} aplikasi terinstal.";
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.IsEnglish
                ? $"Failed to load installed applications: {ex.Message}"
                : $"Gagal memuat daftar aplikasi: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task LoadWindowsStoreAppsAsync(bool forceReload = false)
    {
        if (IsBusy) return;
        if (_windowsAppsLoadedOnce && !forceReload && WindowsStoreApps.Count > 0)
        {
            OnPropertyChanged(nameof(StatusBarLeftCountText));
            return;
        }

        IsBusy = true;
        StatusMessage = Loc.IsEnglish
            ? "Loading Windows Apps packages (Microsoft Store / UWP)..."
            : "Memuat daftar paket Windows Apps (Microsoft Store / UWP)...";

        try
        {
            var list = await _programsEnumerator.GetWindowsAppsAsync();
            WindowsStoreApps.Clear();
            foreach (var item in list)
            {
                WindowsStoreApps.Add(item);
            }
            _windowsAppsLoadedOnce = true;
            OnPropertyChanged(nameof(StatusBarLeftCountText));
            StatusMessage = Loc.IsEnglish
                ? $"Ready. Found {WindowsStoreApps.Count} Windows Apps packages."
                : $"Siap. Ditemukan {WindowsStoreApps.Count} paket Windows Apps.";
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.IsEnglish
                ? $"Failed to load Windows Apps: {ex.Message}"
                : $"Gagal memuat Windows Apps: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task UninstallSelectedProgramAndScanAsync(InstalledProgramItem? program)
    {
        program ??= SelectedProgram;
        if (program == null || IsBusy) return;

        string confirmBody = Loc.IsEnglish
            ? $"Do you want to run the Uninstaller for:\n\n" +
              $"• Application: {program.Name}\n" +
              $"• Publisher: {(string.IsNullOrWhiteSpace(program.Company) ? "-" : program.Company)}\n" +
              $"• Command: {program.UninstallString}\n\n" +
              $"Once the uninstaller finishes, cleaNclean will automatically scan for all remaining files, folders & Registry leftovers for this application."
            : $"Apakah Anda ingin menjalankan Uninstaller untuk:\n\n" +
              $"• Aplikasi: {program.Name}\n" +
              $"• Publisher: {(string.IsNullOrWhiteSpace(program.Company) ? "-" : program.Company)}\n" +
              $"• Command: {program.UninstallString}\n\n" +
              $"Setelah proses uninstaller selesai, cleaNclean akan otomatis memindai seluruh sisa file/folder & Registry (Leftover) aplikasi ini.";

        var confirm = System.Windows.MessageBox.Show(
            confirmBody,
            "Uninstall + Scan Leftovers — cleaNclean",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes)
            return;

        IsBusy = true;
        StatusMessage = Loc.IsEnglish
            ? $"Running uninstaller for '{program.Name}'... Please follow the application's uninstaller window."
            : $"Menjalankan uninstaller untuk '{program.Name}'... Silakan ikuti jendela uninstaller aplikasi.";

        try
        {
            await InstalledProgramsEnumerator.RunUninstallerProcessAsync(program);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                Loc.IsEnglish
                    ? $"Failed to launch built-in uninstaller for '{program.Name}': {ex.Message}\n\ncleaNclean will still proceed to scan leftovers for this application."
                    : $"Gagal menjalankan uninstaller bawaan '{program.Name}': {ex.Message}\n\ncleaNclean akan tetap melanjutkan ke pemindaian Leftover untuk aplikasi ini.",
                Loc.IsEnglish ? "Uninstaller Warning" : "Peringatan Uninstaller",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
        }

        // Refresh program list after uninstall and jump straight to Leftover Scan for that program
        if (program.IsWindowsApp)
            await LoadWindowsStoreAppsAsync(forceReload: true);
        else
            await LoadInstalledProgramsAsync();

        await ScanLeftoversForProgramOnlyAsync(program);
    }

    public async Task ScanLeftoversForProgramOnlyAsync(InstalledProgramItem? program)
    {
        program ??= SelectedProgram;
        if (program == null || IsBusy) return;

        string cleanKeyword = ExtractSearchKeywordFromProgramName(program.Name, program.InstallLocation);
        SearchKeyword = cleanKeyword;
        ActiveModuleTab = "LEFTOVER";
        await RunManualKeywordScanAsync();
    }

    private static string ExtractSearchKeywordFromProgramName(string displayName, string installLocation)
    {
        if (!string.IsNullOrWhiteSpace(installLocation))
        {
            string folderName = Path.GetFileName(installLocation.TrimEnd('\\', '/'));
            if (!string.IsNullOrWhiteSpace(folderName) &&
                folderName.Length >= 3 &&
                !folderName.Equals("bin", StringComparison.OrdinalIgnoreCase) &&
                !folderName.Equals("app", StringComparison.OrdinalIgnoreCase))
            {
                // Strip trailing version numbers from folder name if any
                string strippedFolder = Regex.Replace(folderName, @"\s+v?\d+(\.\d+)*.*$", "", RegexOptions.IgnoreCase).Trim();
                if (strippedFolder.Length >= 3)
                    return strippedFolder;
            }
        }

        // Strip architecture tags and version numbers from DisplayName (e.g. "7-Zip 26.00 (x64)" -> "7-Zip")
        string cleaned = Regex.Replace(displayName, @"\s*\((?:x64|x86|64-bit|32-bit|User|MSI)\)", "", RegexOptions.IgnoreCase);
        cleaned = Regex.Replace(cleaned, @"\s+v?\d+(\.\d+)+.*$", "", RegexOptions.IgnoreCase);
        cleaned = cleaned.Trim();
        return cleaned.Length >= 2 ? cleaned : displayName.Trim();
    }

    public async Task RunAutomaticScanAsync()
    {
        if (IsBusy) return;

        IsBusy = true;
        _scanCts = new CancellationTokenSource();
        ClearItems();

        var progress = new Progress<string>(msg => StatusMessage = msg);

        try
        {
            var found = await _orchestrator.RunAutomaticOrphanScanAsync(
                true, true, true, true, progress, _scanCts.Token);

            PopulateItems(found);
            StatusMessage = Loc.IsEnglish
                ? $"Automatic Scan completed! Found {TotalCount} orphaned leftovers ({SelectedCount} selected)."
                : $"Scan Otomatis selesai! Ditemukan {TotalCount} leftover aplikasi yatim ({SelectedCount} terpilih).";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = Loc.IsEnglish ? "Scan cancelled by user." : "Pemindaian dibatalkan oleh pengguna.";
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.IsEnglish ? $"Error during scan: {ex.Message}" : $"Terjadi kesalahan saat memindai: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    public async Task RunManualKeywordScanAsync()
    {
        if (IsBusy) return;

        if (string.IsNullOrWhiteSpace(SearchKeyword) || SearchKeyword.Trim().Length < 2)
        {
            System.Windows.MessageBox.Show(
                Loc.IsEnglish
                    ? "Please enter at least 2 characters of an app name or publisher to search."
                    : "Masukkan minimal 2 karakter nama aplikasi atau publisher yang ingin dicari.",
                Loc.IsEnglish ? "cleaNclean - Manual Search" : "cleaNclean - Pencarian Manual",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        IsBusy = true;
        _scanCts = new CancellationTokenSource();
        ClearItems();

        var progress = new Progress<string>(msg => StatusMessage = msg);

        try
        {
            var found = await _orchestrator.RunKeywordScanAsync(
                SearchKeyword.Trim(), true, true, true, true, progress, _scanCts.Token);

            PopulateItems(found);
            StatusMessage = Loc.IsEnglish
                ? $"Search for '{SearchKeyword.Trim()}' completed! Found {TotalCount} matching items ({SelectedCount} selected)."
                : $"Pencarian '{SearchKeyword.Trim()}' selesai! Ditemukan {TotalCount} item terkait ({SelectedCount} terpilih).";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = Loc.IsEnglish ? "Search cancelled." : "Pencarian dibatalkan.";
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.IsEnglish ? $"Error during search: {ex.Message}" : $"Terjadi kesalahan saat mencari: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    public async Task RunSandboxAndHookScanAsync()
    {
        if (IsBusy) return;

        IsBusy = true;
        _scanCts = new CancellationTokenSource();
        ClearSandboxHookFindings();

        var progress = new Progress<string>(msg => StatusMessage = msg);

        try
        {
            var findings = await _sandboxHookOrchestrator.ScanAsync(
                true, true, true, progress, _scanCts.Token);

            foreach (var f in findings)
            {
                f.IsSelected = false;
                f.PropertyChanged += OnFindingPropertyChanged;
                SandboxHookFindings.Add(f);
            }

            RefreshSandboxCounters();
            StatusMessage = Loc.IsEnglish
                ? $"Dry-Run Scan Sandbox & GPU Hooks completed! Showing {TotalSandboxHooksCount} findings (ACL={AppContainerSidCount}, Vulkan={VulkanHookCount}, Launcher/PWA={BrokenLauncherCount})."
                : $"Dry-Run Scan Sandbox & GPU Hooks selesai! Menampilkan {TotalSandboxHooksCount} temuan (ACL={AppContainerSidCount}, Vulkan={VulkanHookCount}, Launcher/PWA={BrokenLauncherCount}).";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = Loc.IsEnglish ? "Sandbox & Hook scan cancelled." : "Pemindaian Sandbox & Hook dibatalkan.";
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.IsEnglish ? $"Failed to scan Sandbox & Hooks: {ex.Message}" : $"Gagal memindai Sandbox & Hook: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    public async Task CleanSelectedSandboxHooksAsync()
    {
        if (IsBusy) return;

        var selected = FilteredSandboxHookView.Cast<DiagnosticFinding>().Where(f => f.IsSelected).ToList();
        if (selected.Count == 0)
        {
            System.Windows.MessageBox.Show(
                "Pilih minimal satu temuan pada tabel Sandbox & GPU Hooks untuk dibersihkan/diperbaiki.",
                "cleaNclean",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        int adminNeededCount = selected.Count(f => f.RequiresAdmin && !IsAdmin);
        if (adminNeededCount > 0)
        {
            var askElevate = System.Windows.MessageBox.Show(
                $"Terdapat {adminNeededCount} item (seperti layer Vulkan di HKLM) yang membutuhkan hak akses Administrator (UAC).\n\n" +
                $"Apakah Anda ingin memulai ulang cleaNclean sebagai Administrator sekarang?",
                "Butuh Akses Administrator (UAC)",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question);

            if (askElevate == MessageBoxResult.Yes)
            {
                if (SecurityAuditLogger.TryRestartAsAdministrator())
                {
                    System.Windows.Application.Current.Shutdown();
                }
                return;
            }
            if (askElevate == MessageBoxResult.Cancel)
                return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"Jalankan Clean() pada {selected.Count} temuan terpilih?\n\n" +
            $"• SDDL ACL asli akan dicadangkan otomatis sebelum modifikasi\n" +
            $"• Log audit lengkap disimpan di: {_sandboxHookOrchestrator.AuditLogger.AuditLogFilePath}",
            "Konfirmasi Orphaned Sandbox & Graphics Hook Cleaner",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
            return;

        IsBusy = true;
        var progress = new Progress<string>(msg => StatusMessage = msg);

        try
        {
            var summary = await _sandboxHookOrchestrator.CleanAsync(selected, SendToRecycleBin, progress);

            foreach (var item in selected)
            {
                if (!item.RequiresAdmin || IsAdmin)
                {
                    item.PropertyChanged -= OnFindingPropertyChanged;
                    SandboxHookFindings.Remove(item);
                }
            }

            RefreshSandboxCounters();
            StatusMessage = $"Selesai: {summary.SuccessCount} berhasil diproses, {summary.FailedCount} gagal, {summary.SkippedRequiresAdminCount} dilewati (butuh Admin).";

            string msg = $"Berhasil mengeksekusi {summary.SuccessCount} tindakan perbaikan/pembersihan!\n\n" +
                         $"File Log Audit:\n{summary.AuditLogPath}";

            if (summary.Errors.Count > 0)
            {
                msg += $"\n\nCatatan/Kendala ({summary.Errors.Count}):\n" + string.Join("\n", summary.Errors.Take(5));
            }

            System.Windows.MessageBox.Show(msg, "Hasil Eksekusi Clean()", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void ExportSandboxReportJson()
    {
        try
        {
            string json = SandboxAndHookOrchestrator.SerializeFindingsToJson(SandboxHookFindings);
            string outPath = Path.Combine(_sandboxHookOrchestrator.AuditLogger.LogDirectory, $"sandbox_hook_scan_{DateTime.Now:yyyyMMdd_HHmmss}.json");
            File.WriteAllText(outPath, json);
            StatusMessage = $"Laporan JSON berhasil diekspor ke: {outPath}";
            Process.Start("explorer.exe", $"/select,\"{outPath}\"");
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Gagal mengekspor JSON: {ex.Message}", "cleaNclean", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public void OpenAuditLogsFolder()
    {
        try
        {
            Directory.CreateDirectory(_sandboxHookOrchestrator.AuditLogger.LogDirectory);
            Process.Start(new ProcessStartInfo
            {
                FileName = _sandboxHookOrchestrator.AuditLogger.LogDirectory,
                UseShellExecute = true
            });
        }
        catch { }
    }

    public void CancelScan()
    {
        _scanCts?.Cancel();
    }

    public async Task CleanSelectedItemsAsync()
    {
        if (IsBusy) return;

        var selected = FilteredItemsView.Cast<LeftoverItem>().Where(i => i.IsSelected).ToList();
        if (selected.Count == 0)
        {
            System.Windows.MessageBox.Show(
                "Pilih (centang) minimal satu item leftover yang ingin dihapus.",
                "cleaNclean",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        string modeInfo = SendToRecycleBin ? "dipindahkan ke Recycle Bin" : "DIHAPUS PERMANEN";
        string regInfo = BackupRegistry ? "Ya (otomatis diekspor ke .reg)" : "Tidak";

        var confirm = System.Windows.MessageBox.Show(
            $"Apakah Anda yakin ingin membersihkan {selected.Count} item leftover terpilih ({SelectedTotalSize})?\n\n" +
            $"• Mode File/Folder: {modeInfo}\n" +
            $"• Backup Registry: {regInfo}",
            "Konfirmasi Pembersihan - cleaNclean",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
            return;

        IsBusy = true;
        var progress = new Progress<string>(msg => StatusMessage = msg);

        try
        {
            var summary = await _cleanerService.CleanItemsAsync(selected, SendToRecycleBin, BackupRegistry, progress);

            foreach (var item in selected)
            {
                bool stillExists = item.Category switch
                {
                    LeftoverCategory.AppDataFolder => Directory.Exists(item.Location),
                    LeftoverCategory.BrokenShortcut => File.Exists(item.Location),
                    _ => false
                };

                if (!stillExists)
                {
                    item.PropertyChanged -= OnItemPropertyChanged;
                    AllItems.Remove(item);
                }
            }

            RefreshCounters();

            string freedText = LeftoverItem.FormatBytes(summary.BytesFreed, LeftoverCategory.AppDataFolder);
            StatusMessage = $"Pembersihan selesai: {summary.SuccessCount} berhasil dihapus ({freedText} dibebaskan), {summary.FailedCount} gagal.";

            string resultMsg = $"Berhasil membersihkan {summary.SuccessCount} item leftover!\nTotal ruang dibebaskan: {freedText}";
            if (summary.FailedCount > 0)
            {
                resultMsg += $"\n\n{summary.FailedCount} item gagal dihapus (mungkin sedang digunakan atau membutuhkan akses Administrator):\n" +
                             string.Join("\n", summary.Errors.Take(5));
            }

            System.Windows.MessageBox.Show(resultMsg, "Hasil Pembersihan - cleaNclean", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void SelectAllVisible(bool isSelected)
    {
        foreach (var obj in FilteredItemsView)
        {
            if (obj is LeftoverItem item)
            {
                item.IsSelected = isSelected;
            }
        }
        RefreshCounters();
    }

    public void SelectAllSandboxVisible(bool isSelected)
    {
        foreach (var obj in FilteredSandboxHookView)
        {
            if (obj is DiagnosticFinding f)
            {
                f.IsSelected = isSelected;
            }
        }
        RefreshSandboxCounters();
    }

    public void AddItemToWhitelist(LeftoverItem? item)
    {
        if (item == null) return;
        _orchestrator.Indexer.AddToUserWhitelist(item.Name);
        _orchestrator.Indexer.AddToUserWhitelist(item.Location);
        item.PropertyChanged -= OnItemPropertyChanged;
        AllItems.Remove(item);
        RefreshCounters();
        StatusMessage = $"'{item.Name}' telah ditambahkan ke daftar pengecualian (Whitelist).";
    }

    public void OpenBackupFolder()
    {
        try
        {
            Directory.CreateDirectory(_cleanerService.BaseBackupDirectory);
            Process.Start(new ProcessStartInfo
            {
                FileName = _cleanerService.BaseBackupDirectory,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Gagal membuka folder backup: {ex.Message}", "cleaNclean", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ClearItems()
    {
        foreach (var item in AllItems)
            item.PropertyChanged -= OnItemPropertyChanged;

        AllItems.Clear();
        RefreshCounters();
    }

    private void ClearSandboxHookFindings()
    {
        foreach (var f in SandboxHookFindings)
            f.PropertyChanged -= OnFindingPropertyChanged;

        SandboxHookFindings.Clear();
        RefreshSandboxCounters();
    }

    private void PopulateItems(IEnumerable<LeftoverItem> items)
    {
        foreach (var item in items)
        {
            item.IsSelected = false;
            item.PropertyChanged += OnItemPropertyChanged;
            AllItems.Add(item);
        }
        RefreshCounters();
    }

    private void SyncSelectAllLeftoversState()
    {
        var visible = FilteredItemsView.Cast<LeftoverItem>().ToList();
        bool allChecked = visible.Count > 0 && visible.All(i => i.IsSelected);
        if (_isAllLeftoversSelected != allChecked)
        {
            _isUpdatingSelectAllLeftovers = true;
            _isAllLeftoversSelected = allChecked;
            OnPropertyChanged(nameof(IsAllLeftoversSelected));
            _isUpdatingSelectAllLeftovers = false;
        }
    }

    private void SyncSelectAllSandboxState()
    {
        var visible = FilteredSandboxHookView.Cast<DiagnosticFinding>().ToList();
        bool allChecked = visible.Count > 0 && visible.All(f => f.IsSelected);
        if (_isAllSandboxSelected != allChecked)
        {
            _isUpdatingSelectAllSandbox = true;
            _isAllSandboxSelected = allChecked;
            OnPropertyChanged(nameof(IsAllSandboxSelected));
            _isUpdatingSelectAllSandbox = false;
        }
    }

    private void OnItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(LeftoverItem.IsSelected))
        {
            SyncSelectAllLeftoversState();
            OnPropertyChanged(nameof(SelectedCount));
            OnPropertyChanged(nameof(SelectedTotalSize));
            OnPropertyChanged(nameof(CanCleanSelected));
            OnPropertyChanged(nameof(CleanerActionButtonText));
            OnPropertyChanged(nameof(StatusBarLeftCountText));
        }
    }

    private void OnFindingPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DiagnosticFinding.IsSelected))
        {
            SyncSelectAllSandboxState();
            OnPropertyChanged(nameof(SelectedSandboxHooksCount));
            OnPropertyChanged(nameof(CanCleanSelected));
            OnPropertyChanged(nameof(CleanerActionButtonText));
            OnPropertyChanged(nameof(StatusBarLeftCountText));
        }
    }

    private void RefreshCounters()
    {
        FilteredItemsView.Refresh();
        SyncSelectAllLeftoversState();
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(AppDataCount));
        OnPropertyChanged(nameof(RegistryCount));
        OnPropertyChanged(nameof(ShortcutCount));
        OnPropertyChanged(nameof(TaskCount));
        OnPropertyChanged(nameof(SelectedCount));
        OnPropertyChanged(nameof(SelectedTotalSize));
        OnPropertyChanged(nameof(LeftoverEmptyVisibility));
        OnPropertyChanged(nameof(CanCleanSelected));
        OnPropertyChanged(nameof(CleanerActionButtonText));
        OnPropertyChanged(nameof(StatusBarLeftCountText));
    }

    private void RefreshSandboxCounters()
    {
        FilteredSandboxHookView.Refresh();
        SyncSelectAllSandboxState();
        OnPropertyChanged(nameof(TotalSandboxHooksCount));
        OnPropertyChanged(nameof(AppContainerSidCount));
        OnPropertyChanged(nameof(VulkanHookCount));
        OnPropertyChanged(nameof(BrokenLauncherCount));
        OnPropertyChanged(nameof(SelectedSandboxHooksCount));
        OnPropertyChanged(nameof(SandboxEmptyVisibility));
        OnPropertyChanged(nameof(CanCleanSelected));
        OnPropertyChanged(nameof(CleanerActionButtonText));
        OnPropertyChanged(nameof(StatusBarLeftCountText));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
