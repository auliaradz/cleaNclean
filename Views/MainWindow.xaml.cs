using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using cleaNclean.Models;
using cleaNclean.Modules.SandboxAndHooks.Services;
using cleaNclean.Services;
using cleaNclean.ViewModels;

namespace cleaNclean.Views;

public partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = ViewModel;
        MenuBackupsDropdown.DataContext = ViewModel;
        MenuLanguageDropdown.DataContext = ViewModel;
        CtxMenuPrograms.DataContext = ViewModel;
        CtxMenuWindowsApps.DataContext = ViewModel;
        CtxMenuLeftovers.DataContext = ViewModel;
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        await ViewModel.LoadInstalledProgramsAsync();
    }

    // ======================================================================
    // TOP RIBBON TOOLBAR: GROUP 1 (VIEW SWITCHERS)
    // ======================================================================

    private void SetActiveRibbonButton(System.Windows.Controls.Button activeBtn)
    {
        var buttons = new[] { BtnRibbonUninstaller, BtnRibbonWindowsApps, BtnRibbonLeftover, BtnRibbonSandbox };
        var activeStyle = (Style)FindResource("RevoToolbarButtonActive");
        var normalStyle = (Style)FindResource("RevoToolbarButton");

        foreach (var btn in buttons)
        {
            btn.Style = ReferenceEquals(btn, activeBtn) ? activeStyle : normalStyle;
        }
    }

    private async void BtnRibbonUninstaller_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.ActiveModuleTab = "UNINSTALLER";
        SetActiveRibbonButton(BtnRibbonUninstaller);
        if (ViewModel.InstalledPrograms.Count == 0)
        {
            await ViewModel.LoadInstalledProgramsAsync();
        }
    }

    private async void BtnRibbonWindowsApps_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.ActiveModuleTab = "WINDOWS_APPS";
        SetActiveRibbonButton(BtnRibbonWindowsApps);
        await ViewModel.LoadWindowsStoreAppsAsync();
    }

    private async void BtnRibbonLeftover_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.ActiveModuleTab = "LEFTOVER";
        SetActiveRibbonButton(BtnRibbonLeftover);
        if (ViewModel.AllItems.Count == 0 && !ViewModel.IsBusy)
        {
            await ViewModel.RunAutomaticScanAsync();
        }
    }

    public void SwitchToLeftoverTabForScreenshot()
    {
        ViewModel.ActiveModuleTab = "LEFTOVER";
        SetActiveRibbonButton(BtnRibbonLeftover);
    }

    public async void SwitchToSandboxHookTab()
    {
        ViewModel.ActiveModuleTab = "SANDBOX_HOOKS";
        SetActiveRibbonButton(BtnRibbonSandbox);
        if (ViewModel.SandboxHookFindings.Count == 0 && !ViewModel.IsBusy)
        {
            await ViewModel.RunSandboxAndHookScanAsync();
        }
    }

    private void BtnRibbonSandbox_Click(object sender, RoutedEventArgs e)
    {
        SwitchToSandboxHookTab();
    }

    // ======================================================================
    // TOP RIBBON TOOLBAR: GROUP 2 (CONTEXTUAL ACTIONS)
    // ======================================================================

    private async void BtnRibbonUninstallAction_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedProgram != null)
        {
            await ViewModel.UninstallSelectedProgramAndScanAsync(ViewModel.SelectedProgram);
            if (ViewModel.ActiveModuleTab == "LEFTOVER")
            {
                SetActiveRibbonButton(BtnRibbonLeftover);
            }
        }
    }

    private async void BtnRibbonScanAction_Click(object sender, RoutedEventArgs e)
    {
        switch (ViewModel.ActiveModuleTab)
        {
            case "UNINSTALLER":
            case "WINDOWS_APPS":
                if (ViewModel.SelectedProgram != null)
                {
                    SetActiveRibbonButton(BtnRibbonLeftover);
                    await ViewModel.ScanLeftoversForProgramOnlyAsync(ViewModel.SelectedProgram);
                }
                else
                {
                    ViewModel.ActiveModuleTab = "LEFTOVER";
                    SetActiveRibbonButton(BtnRibbonLeftover);
                    await ViewModel.RunAutomaticScanAsync();
                }
                break;

            case "LEFTOVER":
                await ViewModel.RunAutomaticScanAsync();
                break;

            case "SANDBOX_HOOKS":
                await ViewModel.RunSandboxAndHookScanAsync();
                break;
        }
    }

    private async void BtnRibbonCleanAction_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.ActiveModuleTab == "LEFTOVER")
        {
            await ViewModel.CleanSelectedItemsAsync();
        }
        else if (ViewModel.ActiveModuleTab == "SANDBOX_HOOKS")
        {
            await ViewModel.CleanSelectedSandboxHooksAsync();
        }
    }

    private async void BtnRibbonRefresh_Click(object sender, RoutedEventArgs e)
    {
        switch (ViewModel.ActiveModuleTab)
        {
            case "UNINSTALLER":
                await ViewModel.LoadInstalledProgramsAsync();
                break;
            case "WINDOWS_APPS":
                await ViewModel.LoadWindowsStoreAppsAsync(forceReload: true);
                break;
            case "LEFTOVER":
                await ViewModel.RunAutomaticScanAsync();
                break;
            case "SANDBOX_HOOKS":
                await ViewModel.RunSandboxAndHookScanAsync();
                break;
        }
    }

    // ======================================================================
    // TOP RIBBON TOOLBAR: GROUP 3 (TOOLS, BACKUPS & ADMIN)
    // ======================================================================

    private void BtnRibbonBackups_Click(object sender, RoutedEventArgs e)
    {
        if (BtnRibbonBackups.ContextMenu != null)
        {
            BtnRibbonBackups.ContextMenu.DataContext = ViewModel;
            BtnRibbonBackups.ContextMenu.PlacementTarget = BtnRibbonBackups;
            BtnRibbonBackups.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            BtnRibbonBackups.ContextMenu.IsOpen = true;
        }
    }

    private void BtnRibbonLanguage_Click(object sender, RoutedEventArgs e)
    {
        if (BtnRibbonLanguage.ContextMenu != null)
        {
            BtnRibbonLanguage.ContextMenu.DataContext = ViewModel;
            BtnRibbonLanguage.ContextMenu.PlacementTarget = BtnRibbonLanguage;
            BtnRibbonLanguage.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            BtnRibbonLanguage.ContextMenu.IsOpen = true;
        }
    }

    private void MenuLangEnglish_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.SetLanguage(AppLanguage.English);
    }

    private void MenuLangIndonesian_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.SetLanguage(AppLanguage.Indonesian);
    }

    private void BtnElevateAdmin_Click(object sender, RoutedEventArgs e)
    {
        PromptOrRestartAsAdmin();
    }

    private void StatusBarAdmin_Click(object sender, MouseButtonEventArgs e)
    {
        PromptOrRestartAsAdmin();
    }

    private static void PromptOrRestartAsAdmin()
    {
        if (SecurityAuditLogger.IsRunningAsAdministrator())
        {
            System.Windows.MessageBox.Show(
                LocalizationManager.Instance.IsEnglish
                    ? "cleaNclean is already running in Administrator mode (UAC Elevated)."
                    : "Aplikasi cleaNclean sudah berjalan dalam mode Administrator (UAC Elevated).",
                "cleaNclean",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        if (SecurityAuditLogger.TryRestartAsAdministrator())
        {
            System.Windows.Application.Current.Shutdown();
        }
    }

    // ======================================================================
    // SEARCH & FILTER BAR HANDLERS
    // ======================================================================

    private void BtnClearQuickFilter_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.FilterText = string.Empty;
    }

    private async void BtnManualSearch_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.RunManualKeywordScanAsync();
    }

    private async void TxtKeywordSearch_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            await ViewModel.RunManualKeywordScanAsync();
        }
    }

    private void BtnCancelScan_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.CancelScan();
    }

    private void BtnSelectAll_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.SelectAllVisible(true);
    }

    private void BtnUnselectAll_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.SelectAllVisible(false);
    }

    private void BtnSelectAllSandbox_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.SelectAllSandboxVisible(true);
    }

    private void BtnUnselectAllSandbox_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.SelectAllSandboxVisible(false);
    }

    // ======================================================================
    // UNINSTALLER / WINDOWS APPS CONTEXT MENU & DOUBLE-CLICK HANDLERS
    // ======================================================================

    private async void GridPrograms_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ViewModel.SelectedProgram != null)
        {
            await ViewModel.UninstallSelectedProgramAndScanAsync(ViewModel.SelectedProgram);
            if (ViewModel.ActiveModuleTab == "LEFTOVER")
            {
                SetActiveRibbonButton(BtnRibbonLeftover);
            }
        }
    }

    private async void MenuProgramUninstallAndScan_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedProgram != null)
        {
            await ViewModel.UninstallSelectedProgramAndScanAsync(ViewModel.SelectedProgram);
            if (ViewModel.ActiveModuleTab == "LEFTOVER")
            {
                SetActiveRibbonButton(BtnRibbonLeftover);
            }
        }
    }

    private async void MenuProgramScanLeftoversOnly_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedProgram != null)
        {
            SetActiveRibbonButton(BtnRibbonLeftover);
            await ViewModel.ScanLeftoversForProgramOnlyAsync(ViewModel.SelectedProgram);
        }
    }

    private void MenuProgramOpenInstallLocation_Click(object sender, RoutedEventArgs e)
    {
        var prog = ViewModel.SelectedProgram;
        if (prog == null) return;

        if (!string.IsNullOrWhiteSpace(prog.InstallLocation) && Directory.Exists(prog.InstallLocation))
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = prog.InstallLocation,
                    UseShellExecute = true
                });
                return;
            }
            catch { }
        }

        System.Windows.MessageBox.Show(
            $"Folder instalasi untuk '{prog.Name}' tidak ditemukan atau tidak tercatat di Registry.",
            "Open Install Location — cleaNclean",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void MenuProgramOpenRegistryKey_Click(object sender, RoutedEventArgs e)
    {
        var prog = ViewModel.SelectedProgram;
        if (prog == null || string.IsNullOrWhiteSpace(prog.RegistryKeyPath)) return;

        InstalledProgramsEnumerator.OpenRegistryKeyInRegedit(prog.RegistryKeyPath);
    }

    private void MenuProgramSearchOnline_Click(object sender, RoutedEventArgs e)
    {
        var prog = ViewModel.SelectedProgram;
        if (prog == null) return;

        try
        {
            string query = Uri.EscapeDataString($"{prog.Name} {prog.Company}".Trim());
            Process.Start(new ProcessStartInfo
            {
                FileName = $"https://www.google.com/search?q={query}",
                UseShellExecute = true
            });
        }
        catch { }
    }

    private void MenuProgramCopyUninstallString_Click(object sender, RoutedEventArgs e)
    {
        var prog = ViewModel.SelectedProgram;
        if (prog == null || string.IsNullOrWhiteSpace(prog.UninstallString)) return;

        System.Windows.Clipboard.SetText(prog.UninstallString);
        ViewModel.StatusMessage = $"UninstallString disalin ke clipboard: {prog.UninstallString}";
    }

    // ======================================================================
    // LEFTOVER SCANNER & SANDBOX HOOK HANDLERS
    // ======================================================================

    private void BtnOpenBackup_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.OpenBackupFolder();
    }

    private void BtnExportSandboxJson_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.ExportSandboxReportJson();
    }

    private void BtnOpenAuditLogs_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.OpenAuditLogsFolder();
    }

    private void MenuOpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (GridLeftovers.SelectedItem is not LeftoverItem item) return;

        try
        {
            if (item.Category == LeftoverCategory.AppDataFolder && Directory.Exists(item.Location))
            {
                Process.Start(new ProcessStartInfo { FileName = item.Location, UseShellExecute = true });
            }
            else if (item.Category == LeftoverCategory.BrokenShortcut && File.Exists(item.Location))
            {
                Process.Start("explorer.exe", $"/select,\"{item.Location}\"");
            }
            else if (item.Category == LeftoverCategory.RegistryKey)
            {
                InstalledProgramsEnumerator.OpenRegistryKeyInRegedit(item.Location);
            }
            else
            {
                System.Windows.MessageBox.Show($"Lokasi: {item.Location}", "Info Lokasi - cleaNclean", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Tidak dapat membuka lokasi: {ex.Message}", "cleaNclean", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void MenuCopyPath_Click(object sender, RoutedEventArgs e)
    {
        if (GridLeftovers.SelectedItem is LeftoverItem item)
        {
            System.Windows.Clipboard.SetText(item.Location);
            ViewModel.StatusMessage = $"Path disalin ke clipboard: {item.Location}";
        }
    }

    private void MenuAddWhitelist_Click(object sender, RoutedEventArgs e)
    {
        if (GridLeftovers.SelectedItem is LeftoverItem item)
        {
            ViewModel.AddItemToWhitelist(item);
        }
    }

    // ======================================================================
    // DESCRIPTION PANEL TOGGLE
    // ======================================================================

    private void BtnToggleDescriptionPanel_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.IsDescriptionPanelVisible = !ViewModel.IsDescriptionPanelVisible;
    }
}
