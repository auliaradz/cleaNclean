using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using cleaNclean.Models;
using cleaNclean.Modules.SandboxAndHooks.Services;
using cleaNclean.Services;
using cleaNclean.Views;
using Microsoft.Win32;

namespace cleaNclean;

public partial class App : System.Windows.Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Length > 0 && e.Args[0].Equals("--self-test", StringComparison.OrdinalIgnoreCase))
        {
            int exitCode = await RunSelfTestAsync();
            Shutdown(exitCode);
            return;
        }

        if (e.Args.Length >= 2 && e.Args[0].Equals("--dump-scan", StringComparison.OrdinalIgnoreCase))
        {
            string outFile = e.Args[1];
            var orch = new LeftoverScanOrchestrator();
            var items = await orch.RunAutomaticOrphanScanAsync(true, true, true, true);
            var lines = items.Select(i => $"{i.Category} | {i.Name} | {i.Location} | {i.FormattedSize}");
            await File.WriteAllLinesAsync(outFile, lines);
            Shutdown(0);
            return;
        }

        if (e.Args.Length >= 2 && e.Args[0].Equals("--scan-sandbox-json", StringComparison.OrdinalIgnoreCase))
        {
            string outFile = e.Args[1];
            var sandboxOrch = new SandboxAndHookOrchestrator();
            var findings = await sandboxOrch.ScanAsync(true, true, true);
            string json = SandboxAndHookOrchestrator.SerializeFindingsToJson(findings);
            await File.WriteAllTextAsync(outFile, json);
            Shutdown(0);
            return;
        }

        if (e.Args.Length >= 2 && e.Args[0].Equals("--screenshot-sandbox", StringComparison.OrdinalIgnoreCase))
        {
            string outPath = e.Args[1];
            var win = new MainWindow();
            MainWindow = win;
            win.Show();
            win.SwitchToSandboxHookTab();
            await win.ViewModel.RunSandboxAndHookScanAsync();
            await Task.Delay(500);
            CaptureWindowToPng(win, outPath);
            Shutdown(0);
            return;
        }

        if (e.Args.Length >= 2 && e.Args[0].Equals("--screenshot", StringComparison.OrdinalIgnoreCase))
        {
            string outPath = e.Args[1];
            var win = new MainWindow();
            MainWindow = win;
            win.Show();
            while (win.ViewModel.IsBusy || win.ViewModel.InstalledPrograms.Count == 0)
            {
                await Task.Delay(200);
            }
            if (win.ViewModel.InstalledPrograms.Count > 2)
            {
                win.ViewModel.SelectedProgram = win.ViewModel.InstalledPrograms[2];
            }
            await Task.Delay(300);
            CaptureWindowToPng(win, outPath);
            Shutdown(0);
            return;
        }

        if (e.Args.Length >= 2 && e.Args[0].Equals("--screenshot-leftover", StringComparison.OrdinalIgnoreCase))
        {
            string outPath = e.Args[1];
            var win = new MainWindow();
            MainWindow = win;
            win.Show();
            while (win.ViewModel.IsBusy)
            {
                await Task.Delay(100);
            }
            win.SwitchToLeftoverTabForScreenshot();
            await win.ViewModel.RunAutomaticScanAsync();
            if (win.ViewModel.AllItems.Count > 0)
            {
                win.ViewModel.SelectedLeftover = win.ViewModel.AllItems[0];
            }
            await Task.Delay(300);
            CaptureWindowToPng(win, outPath);
            Shutdown(0);
            return;
        }

        var mainWin = new MainWindow();
        MainWindow = mainWin;
        mainWin.Show();
    }

    private static async Task<int> RunSelfTestAsync()
    {
        string logFile = Path.Combine(Path.GetTempPath(), "cleaNclean_selftest.log");
        var logs = new List<string>();
        string dummyName = "DummyOrphanedVendorXyz_99";
        string dummyAppDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), dummyName);
        string dummyRegSubKey = $@"Software\{dummyName}";
        string dummyShortcutPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), $"{dummyName}.lnk");

        try
        {
            // 1. Setup dummy leftover artifacts
            Directory.CreateDirectory(dummyAppDataDir);
            await File.WriteAllTextAsync(Path.Combine(dummyAppDataDir, "cache.dat"), new string('X', 4096));

            using (var regKey = Registry.CurrentUser.CreateSubKey(dummyRegSubKey))
            {
                regKey.SetValue("InstallPath", $@"C:\Program Files\{dummyName}\app.exe");
            }

            CreateDummyShortcut(dummyShortcutPath, $@"C:\Program Files\{dummyName}\missing_app.exe");
            logs.Add("[SETUP] Created dummy AppData folder, Registry key, and broken Desktop shortcut.");

            // 2. Run Automatic Orphan Scan
            var orchestrator = new LeftoverScanOrchestrator();
            var autoResults = await orchestrator.RunAutomaticOrphanScanAsync(true, true, true, true);

            bool foundFolderAuto = autoResults.Any(i => i.Category == LeftoverCategory.AppDataFolder && i.Name.Equals(dummyName, StringComparison.OrdinalIgnoreCase));
            bool foundRegAuto = autoResults.Any(i => i.Category == LeftoverCategory.RegistryKey && i.Name.Equals(dummyName, StringComparison.OrdinalIgnoreCase));
            bool foundLnkAuto = autoResults.Any(i => i.Category == LeftoverCategory.BrokenShortcut && i.Name.Contains(dummyName, StringComparison.OrdinalIgnoreCase));

            logs.Add($"[AUTO SCAN] Total found: {autoResults.Count} | DummyFolder={foundFolderAuto}, DummyRegistry={foundRegAuto}, DummyShortcut={foundLnkAuto}");

            // 3. Run Keyword Scan
            var kwResults = await orchestrator.RunKeywordScanAsync(dummyName, true, true, true, false);
            logs.Add($"[KEYWORD SCAN] Found {kwResults.Count} items matching '{dummyName}'.");

            if (!foundFolderAuto || !foundRegAuto || !foundLnkAuto || kwResults.Count < 3)
            {
                logs.Add("[FAIL] One or more dummy leftovers were not detected.");
                await File.WriteAllLinesAsync(logFile, logs);
                return 1;
            }

            // 4. Clean dummy leftovers & verify .reg backup
            var cleaner = new LeftoverCleanerService();
            var summary = await cleaner.CleanItemsAsync(kwResults, sendFilesToRecycleBin: false, backupRegistryBeforeDelete: true);
            logs.Add($"[CLEANUP] Success={summary.SuccessCount}, Failed={summary.FailedCount}, BytesFreed={summary.BytesFreed}, BackupDir={summary.BackupFolderPath}");

            bool folderGone = !Directory.Exists(dummyAppDataDir);
            using var checkReg = Registry.CurrentUser.OpenSubKey(dummyRegSubKey);
            bool regGone = checkReg == null;
            bool lnkGone = !File.Exists(dummyShortcutPath);
            bool backupCreated = Directory.Exists(summary.BackupFolderPath) && Directory.GetFiles(summary.BackupFolderPath, "*.reg").Length > 0;

            logs.Add($"[VERIFY] FolderDeleted={folderGone}, RegDeleted={regGone}, ShortcutDeleted={lnkGone}, RegBackupCreated={backupCreated}");

            // 5. Verify New Module: Orphaned Sandbox & Graphics Hook Cleaner (All 3 Sub-Modules)
            bool sandboxModuleOk = await VerifySandboxAndHookModuleAsync(logs);
            await File.WriteAllLinesAsync(logFile, logs);

            return (folderGone && regGone && lnkGone && backupCreated && sandboxModuleOk) ? 0 : 2;
        }
        catch (Exception ex)
        {
            logs.Add($"[EXCEPTION] {ex}");
            await File.WriteAllLinesAsync(logFile, logs);
            return 3;
        }
        finally
        {
            // Ensure cleanup even if test fails
            try { if (Directory.Exists(dummyAppDataDir)) Directory.Delete(dummyAppDataDir, true); } catch { }
            try { Registry.CurrentUser.DeleteSubKeyTree(dummyRegSubKey, false); } catch { }
            try { if (File.Exists(dummyShortcutPath)) File.Delete(dummyShortcutPath); } catch { }
        }
    }

    private static async Task<bool> VerifySandboxAndHookModuleAsync(List<string> logs)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string testSandboxDir = Path.Combine(localAppData, "DummySandboxTest_cleaNclean");
        string testSquirrelDir = Path.Combine(localAppData, "DummySquirrelStub_cleaNclean");
        string testSquirrelLnk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "DummySquirrel_cleaNclean.lnk");
        string testVulkanJson = Path.Combine(Path.GetTempPath(), "dummy_broken_hook_cleaNclean.json");
        string vulkanRegPath = @"SOFTWARE\Khronos\Vulkan\ImplicitLayers";

        try
        {
            // A. Setup Sub-module 1: Directory with orphaned 8-block AppContainer SID
            Directory.CreateDirectory(testSandboxDir);
            var dirInfo = new DirectoryInfo(testSandboxDir);
            var sec = dirInfo.GetAccessControl();
            var fakeOrphanSid = new System.Security.Principal.SecurityIdentifier("S-1-15-2-99999991-88888882-77777773-66666664-55555555-44444446-33333337");
            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                fakeOrphanSid,
                System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                System.Security.AccessControl.AccessControlType.Allow));
            dirInfo.SetAccessControl(sec);

            // B. Setup Sub-module 2: Vulkan ImplicitLayer JSON with missing library_path DLL
            await File.WriteAllTextAsync(testVulkanJson, """
            {
              "file_format_version": "1.0.0",
              "layer": {
                "name": "VK_LAYER_DUMMY_ORPHAN_HOOK",
                "description": "Dummy Uninstalled Overlay",
                "library_path": ".\\missing_overlay_hook_dll_12345.dll"
              }
            }
            """);
            using (var vkKey = Registry.CurrentUser.CreateSubKey(vulkanRegPath))
            {
                vkKey.SetValue(testVulkanJson, 0, RegistryValueKind.DWord);
            }

            // C. Setup Sub-module 3: Broken Squirrel Stub Launcher shortcut (has Update.exe + empty app-1.0.0 without main exe)
            Directory.CreateDirectory(Path.Combine(testSquirrelDir, "app-1.0.0"));
            await File.WriteAllTextAsync(Path.Combine(testSquirrelDir, "Update.exe"), "MZ-stub");
            await File.WriteAllTextAsync(Path.Combine(testSquirrelDir, "DummyApp.exe"), "MZ-stub");
            CreateDummyShortcut(testSquirrelLnk, Path.Combine(testSquirrelDir, "DummyApp.exe"));

            var orchestrator = new SandboxAndHookOrchestrator();
            var findings = await orchestrator.ScanAsync(true, true, true);

            bool foundOrphanSid = findings.Any(f =>
                f.Category == "OrphanedAppContainerSid" &&
                f.Target.Equals(testSandboxDir, StringComparison.OrdinalIgnoreCase));

            var vulkanFinding = findings.FirstOrDefault(f =>
                f.Category == "VulkanOverlayHook" &&
                f.Target.Contains(testVulkanJson, StringComparison.OrdinalIgnoreCase));

            bool foundBrokenSquirrel = findings.Any(f =>
                f.Category == "BrokenLauncherOrPwaShortcut" &&
                f.Target.Equals(testSquirrelLnk, StringComparison.OrdinalIgnoreCase));

            logs.Add($"[SANDBOX-HOOK SCAN] OrphanSid={foundOrphanSid}, VulkanBrokenDll={vulkanFinding != null}, BrokenSquirrel={foundBrokenSquirrel}");

            if (!foundOrphanSid || vulkanFinding == null || !foundBrokenSquirrel)
                return false;

            // Test Vulkan Disable (DWORD 0 -> 1) first
            vulkanFinding.SelectedAction = cleaNclean.Modules.SandboxAndHooks.Models.RemediationAction.Disable;
            orchestrator.Clean([vulkanFinding]);
            using (var vkKey = Registry.CurrentUser.OpenSubKey(vulkanRegPath))
            {
                int valAfterDisable = (int)(vkKey?.GetValue(testVulkanJson) ?? -1);
                logs.Add($"[VULKAN DISABLE] DWORD after Disable={valAfterDisable}");
                if (valAfterDisable != 1) return false;
            }

            // Now test Remove on all 3 test findings
            vulkanFinding.SelectedAction = cleaNclean.Modules.SandboxAndHooks.Models.RemediationAction.Remove;
            var testItemsToClean = findings.Where(f =>
                f.Target.Equals(testSandboxDir, StringComparison.OrdinalIgnoreCase) ||
                f.Target.Contains(testVulkanJson, StringComparison.OrdinalIgnoreCase) ||
                f.Target.Equals(testSquirrelLnk, StringComparison.OrdinalIgnoreCase)).ToList();

            var cleanSummary = await orchestrator.CleanAsync(testItemsToClean, sendShortcutsToRecycleBin: false);
            logs.Add($"[SANDBOX-HOOK CLEAN] Success={cleanSummary.SuccessCount}, Failed={cleanSummary.FailedCount}");

            return cleanSummary.FailedCount == 0 && cleanSummary.SuccessCount >= 3;
        }
        finally
        {
            try { if (Directory.Exists(testSandboxDir)) Directory.Delete(testSandboxDir, true); } catch { }
            try { if (Directory.Exists(testSquirrelDir)) Directory.Delete(testSquirrelDir, true); } catch { }
            try { if (File.Exists(testSquirrelLnk)) File.Delete(testSquirrelLnk); } catch { }
            try { if (File.Exists(testVulkanJson)) File.Delete(testVulkanJson); } catch { }
            try
            {
                using var vkKey = Registry.CurrentUser.OpenSubKey(vulkanRegPath, writable: true);
                vkKey?.DeleteValue(testVulkanJson, false);
            }
            catch { }
        }
    }

    private static void CreateDummyShortcut(string lnkPath, string targetExePath)
    {
        Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType != null)
        {
            dynamic? shell = Activator.CreateInstance(shellType);
            if (shell != null)
            {
                dynamic shortcut = shell.CreateShortcut(lnkPath);
                shortcut.TargetPath = targetExePath;
                shortcut.Save();
            }
        }
    }

    private static void CaptureWindowToPng(Window window, string outputPath)
    {
        try
        {
            window.UpdateLayout();
            int width = (int)Math.Max(window.ActualWidth, 1320);
            int height = (int)Math.Max(window.ActualHeight, 820);

            var rtb = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
            rtb.Render(window);

            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(rtb));

            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            using var fs = File.Create(outputPath);
            encoder.Save(fs);
        }
        catch { }
    }
}
