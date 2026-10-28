using System.IO;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using cleaNclean.Modules.SandboxAndHooks.Models;
using cleaNclean.Services;

namespace cleaNclean.Modules.SandboxAndHooks.Services;

/// <summary>
/// Sub-Module 3: Broken App Launcher &amp; Proxy Shortcut Validator.
/// Scans Desktop, Start Menu, and Taskbar Pinned shortcuts (.lnk) for:
/// 1. Missing TargetPath on disk
/// 2. Broken Squirrel / Stub Launchers in %LOCALAPPDATA% (missing app-* version folders or missing *S-1-15-2-1 ACL)
/// 3. Broken Browser PWA shortcuts (chrome_proxy.exe / msedge_proxy.exe with --app-id=&lt;id&gt; whose Web App / Extension data is gone)
/// </summary>
public class BrokenLauncherValidator(AppContainerAclSanitizer aclSanitizer, SecurityAuditLogger auditLogger)
{
    private static readonly Regex AppIdArgumentRegex =
        new(@"--app-id=([a-zA-Z0-9_]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ProcessStartArgumentRegex =
        new(@"--processStart\s+(?:""([^""]+)""|([^\s""]+))", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public List<string> GetTargetShortcutDirectories()
    {
        string userDesktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string publicDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
        string userStartMenu = Environment.GetFolderPath(Environment.SpecialFolder.StartMenu);
        string commonStartMenu = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu);
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string taskbarPinned = Path.Combine(roaming, @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar");

        string[] dirs = [userDesktop, publicDesktop, userStartMenu, commonStartMenu, taskbarPinned];
        return dirs
            .Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public List<DiagnosticFinding> Scan(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var findings = new List<DiagnosticFinding>();
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        progress?.Report("Memindai Shortcut Desktop, Start Menu, Taskbar Pinned, Squirrel Stub & PWA Proxy...");

        foreach (var rootDir in GetTargetShortcutDirectories())
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> lnkFiles;
            try
            {
                lnkFiles = Directory.EnumerateFiles(rootDir, "*.lnk", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var lnkPath in lnkFiles)
            {
                ct.ThrowIfCancellationRequested();
                InspectShortcutFile(lnkPath, localAppData, findings);
            }
        }

        return findings;
    }

    private void InspectShortcutFile(string lnkPath, string localAppData, List<DiagnosticFinding> findings)
    {
        var (targetPath, arguments, _) = ReadShortcutProperties(lnkPath);

        // Ignore Windows Installer advertised shortcuts
        if (!string.IsNullOrWhiteSpace(targetPath) &&
            targetPath.Contains(@"\Windows\Installer\", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        // 1. Check if TargetPath (or binary-resolved UWP/WindowsApps/shell target) is missing from disk
        string? effectiveTarget = ShortcutScanner.ResolveShortcutTarget(lnkPath);
        if (string.IsNullOrWhiteSpace(effectiveTarget))
            effectiveTarget = targetPath;

        if (!string.IsNullOrWhiteSpace(effectiveTarget) &&
            IsStandardDrivePath(effectiveTarget) &&
            !File.Exists(effectiveTarget) &&
            !Directory.Exists(effectiveTarget))
        {
            bool isUwpTarget = effectiveTarget.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);
            findings.Add(new DiagnosticFinding
            {
                Category = "BrokenLauncherOrPwaShortcut",
                Target = lnkPath,
                IssueDescription = isUwpTarget
                    ? $"Shortcut UWP/Store rusak: Paket '{Path.GetFileName(effectiveTarget)}' sudah di-uninstall dan tidak ada di '{effectiveTarget}'."
                    : $"Shortcut rusak: Target '{effectiveTarget}' sudah tidak ditemukan di disk.",
                Severity = FindingSeverity.Medium,
                RecommendedAction = RemediationAction.Remove,
                SelectedAction = RemediationAction.Remove,
                AvailableActions = [RemediationAction.Remove],
                RequiresAdmin = IsUnderCommonPath(lnkPath),
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ShortcutPath"] = lnkPath,
                    ["TargetPath"] = effectiveTarget,
                    ["SubType"] = isUwpTarget ? "BrokenUwpShortcut" : "MissingTarget"
                }
            });
            return;
        }

        // 1b. If targetPath is still empty, check for orphaned UWP/AppX PackageFullName in .lnk PropertyStore
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            if (ShortcutScanner.TryGetOrphanedUwpPackageFromLnk(lnkPath, out string? orphanedPkg) &&
                !string.IsNullOrWhiteSpace(orphanedPkg))
            {
                findings.Add(new DiagnosticFinding
                {
                    Category = "BrokenLauncherOrPwaShortcut",
                    Target = lnkPath,
                    IssueDescription = $"Shortcut UWP/Store rusak: Paket AppX '{orphanedPkg}' sudah tidak terinstall di sistem.",
                    Severity = FindingSeverity.Medium,
                    RecommendedAction = RemediationAction.Remove,
                    SelectedAction = RemediationAction.Remove,
                    AvailableActions = [RemediationAction.Remove],
                    RequiresAdmin = IsUnderCommonPath(lnkPath),
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ShortcutPath"] = lnkPath,
                        ["TargetPath"] = orphanedPkg,
                        ["SubType"] = "BrokenUwpShortcut"
                    }
                });
            }
            return;
        }

        // 2. Check for Squirrel / Stub Launcher in %LOCALAPPDATA%
        if (targetPath.StartsWith(localAppData, StringComparison.OrdinalIgnoreCase) &&
            targetPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            InspectSquirrelOrStubLauncher(lnkPath, targetPath, arguments, findings);
        }

        // 3. Check for Broken PWA Shortcut (chrome_proxy.exe / msedge_proxy.exe / brave_proxy.exe with --app-id=<id>)
        if (IsBrowserProxyExecutable(targetPath) && !string.IsNullOrWhiteSpace(arguments))
        {
            InspectBrowserPwaShortcut(lnkPath, targetPath, arguments, localAppData, findings);
        }
    }

    private void InspectSquirrelOrStubLauncher(
        string lnkPath,
        string targetPath,
        string arguments,
        List<DiagnosticFinding> findings)
    {
        string? appDir = Path.GetDirectoryName(targetPath);
        if (string.IsNullOrWhiteSpace(appDir) || !Directory.Exists(appDir))
            return;

        string exeFileName = Path.GetFileName(targetPath);
        bool isUpdateExe = exeFileName.Equals("Update.exe", StringComparison.OrdinalIgnoreCase);
        bool hasUpdateExeSibling = File.Exists(Path.Combine(appDir, "Update.exe"));

        string[] appVersionDirs;
        try
        {
            appVersionDirs = Directory.GetDirectories(appDir, "app-*", SearchOption.TopDirectoryOnly);
        }
        catch
        {
            return;
        }

        // Identify Squirrel/Stub structure: either target is Update.exe, or directory contains Update.exe / app-* subfolders
        if (!isUpdateExe && !hasUpdateExeSibling && appVersionDirs.Length == 0)
            return;

        if (appVersionDirs.Length == 0)
        {
            findings.Add(new DiagnosticFinding
            {
                Category = "BrokenLauncherOrPwaShortcut",
                Target = lnkPath,
                IssueDescription =
                    $"Squirrel/Stub Launcher rusak: Direktori '{appDir}' hanya menyisakan stub '{exeFileName}' tanpa sub-folder versi 'app-*' yang valid.",
                Severity = FindingSeverity.High,
                RecommendedAction = RemediationAction.Remove,
                SelectedAction = RemediationAction.Remove,
                AvailableActions = [RemediationAction.Remove],
                RequiresAdmin = IsUnderCommonPath(lnkPath),
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ShortcutPath"] = lnkPath,
                    ["StubDirectory"] = appDir,
                    ["SubType"] = "BrokenSquirrelNoAppDirs"
                }
            });
            return;
        }

        // Verify that at least one app-* folder contains the target executable (or any main .exe)
        string? expectedProcessExe = null;
        if (isUpdateExe && !string.IsNullOrWhiteSpace(arguments))
        {
            var m = ProcessStartArgumentRegex.Match(arguments);
            if (m.Success)
            {
                expectedProcessExe = !string.IsNullOrWhiteSpace(m.Groups[1].Value) ? m.Groups[1].Value : m.Groups[2].Value;
            }
        }
        else if (!isUpdateExe)
        {
            expectedProcessExe = exeFileName;
        }

        bool hasValidBinaryInAppDir = false;
        string? validAppSubDir = null;

        foreach (var verDir in appVersionDirs.OrderByDescending(d => d))
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(expectedProcessExe))
                {
                    if (File.Exists(Path.Combine(verDir, expectedProcessExe)))
                    {
                        hasValidBinaryInAppDir = true;
                        validAppSubDir = verDir;
                        break;
                    }
                }
                else if (Directory.EnumerateFiles(verDir, "*.exe", SearchOption.TopDirectoryOnly).Any())
                {
                    hasValidBinaryInAppDir = true;
                    validAppSubDir = verDir;
                    break;
                }
            }
            catch { }
        }

        if (!hasValidBinaryInAppDir)
        {
            findings.Add(new DiagnosticFinding
            {
                Category = "BrokenLauncherOrPwaShortcut",
                Target = lnkPath,
                IssueDescription =
                    $"Squirrel/Stub Launcher rusak: Sub-folder 'app-*' di '{appDir}' tidak lagi memiliki file executable utama '{expectedProcessExe ?? "*.exe"}'.",
                Severity = FindingSeverity.High,
                RecommendedAction = RemediationAction.Remove,
                SelectedAction = RemediationAction.Remove,
                AvailableActions = [RemediationAction.Remove],
                RequiresAdmin = IsUnderCommonPath(lnkPath),
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ShortcutPath"] = lnkPath,
                    ["StubDirectory"] = appDir,
                    ["SubType"] = "BrokenSquirrelMissingExe"
                }
            });
            return;
        }

        // Check if the valid app-* folder has ReadAndExecute permission for *S-1-15-2-1 (ALL APPLICATION PACKAGES)
        if (validAppSubDir != null)
        {
            try
            {
                var dirSec = new DirectoryInfo(validAppSubDir).GetAccessControl(AccessControlSections.Access);
                if (!AppContainerAclSanitizer.HasAllApplicationPackagesReadExecute(dirSec))
                {
                    findings.Add(new DiagnosticFinding
                    {
                        Category = "BrokenLauncherOrPwaShortcut",
                        Target = validAppSubDir,
                        IssueDescription =
                            $"Squirrel Launcher '{Path.GetFileName(lnkPath)}' menuju '{validAppSubDir}' kehilangan izin baca '*S-1-15-2-1' (ALL APPLICATION PACKAGES).",
                        Severity = FindingSeverity.High,
                        RecommendedAction = RemediationAction.HealAcl,
                        SelectedAction = RemediationAction.HealAcl,
                        AvailableActions = [RemediationAction.HealAcl, RemediationAction.Remove],
                        RequiresAdmin = false,
                        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["ShortcutPath"] = lnkPath,
                            ["DirectoryPath"] = validAppSubDir,
                            ["SubType"] = "SquirrelMissingSandboxAcl"
                        }
                    });
                }
            }
            catch { }
        }
    }

    private static void InspectBrowserPwaShortcut(
        string lnkPath,
        string targetPath,
        string arguments,
        string localAppData,
        List<DiagnosticFinding> findings)
    {
        var match = AppIdArgumentRegex.Match(arguments);
        if (!match.Success) return;

        string appId = match.Groups[1].Value;
        string? userDataDir = ResolveBrowserUserDataDirectory(targetPath, localAppData);
        if (string.IsNullOrWhiteSpace(userDataDir) || !Directory.Exists(userDataDir))
        {
            findings.Add(new DiagnosticFinding
            {
                Category = "BrokenLauncherOrPwaShortcut",
                Target = lnkPath,
                IssueDescription = $"Broken PWA Shortcut (--app-id={appId}): Direktori User Data browser tidak ditemukan.",
                Severity = FindingSeverity.Medium,
                RecommendedAction = RemediationAction.Remove,
                SelectedAction = RemediationAction.Remove,
                AvailableActions = [RemediationAction.Remove],
                RequiresAdmin = IsUnderCommonPath(lnkPath),
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ShortcutPath"] = lnkPath,
                    ["AppId"] = appId,
                    ["SubType"] = "BrokenPwa"
                }
            });
            return;
        }

        bool pwaExists = CheckPwaInstalledInUserData(userDataDir, appId);
        if (!pwaExists)
        {
            findings.Add(new DiagnosticFinding
            {
                Category = "BrokenLauncherOrPwaShortcut",
                Target = lnkPath,
                IssueDescription =
                    $"Broken PWA Shortcut: Web App / Ekstensi dengan ID '{appId}' sudah dihapus dari profil browser ('{userDataDir}').",
                Severity = FindingSeverity.Medium,
                RecommendedAction = RemediationAction.Remove,
                SelectedAction = RemediationAction.Remove,
                AvailableActions = [RemediationAction.Remove],
                RequiresAdmin = IsUnderCommonPath(lnkPath),
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ShortcutPath"] = lnkPath,
                    ["AppId"] = appId,
                    ["UserDataDir"] = userDataDir,
                    ["SubType"] = "BrokenPwa"
                }
            });
        }
    }

    private static bool CheckPwaInstalledInUserData(string userDataDir, string appId)
    {
        try
        {
            var profileDirs = new List<string>();
            string defaultProfile = Path.Combine(userDataDir, "Default");
            if (Directory.Exists(defaultProfile)) profileDirs.Add(defaultProfile);

            profileDirs.AddRange(Directory.GetDirectories(userDataDir, "Profile *", SearchOption.TopDirectoryOnly));

            foreach (var profile in profileDirs)
            {
                // 1. Check Web Applications\_crx_<appId> or Web Applications\_crx__<appId>
                string webAppsDir = Path.Combine(profile, "Web Applications");
                if (Directory.Exists(webAppsDir))
                {
                    var matchingCrxDirs = Directory.GetDirectories(webAppsDir, $"*{appId}*", SearchOption.AllDirectories);
                    if (matchingCrxDirs.Length > 0)
                        return true;
                }

                // 2. Check Extensions\<appId>
                string extDir = Path.Combine(profile, "Extensions", appId);
                if (Directory.Exists(extDir))
                    return true;
            }
        }
        catch
        {
            return true; // Assume valid if unreadable
        }

        return false;
    }

    private static string? ResolveBrowserUserDataDirectory(string proxyExePath, string localAppData)
    {
        string exeName = Path.GetFileName(proxyExePath);
        if (exeName.Equals("chrome_proxy.exe", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(localAppData, @"Google\Chrome\User Data");
        if (exeName.Equals("msedge_proxy.exe", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(localAppData, @"Microsoft\Edge\User Data");
        if (exeName.Equals("brave_proxy.exe", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(localAppData, @"BraveSoftware\Brave-Browser\User Data");
        if (exeName.Equals("vivaldi_proxy.exe", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(localAppData, @"Vivaldi\User Data");
        return null;
    }

    private static bool IsBrowserProxyExecutable(string targetPath)
    {
        string fileName = Path.GetFileName(targetPath);
        return fileName.Equals("chrome_proxy.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("msedge_proxy.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("brave_proxy.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("vivaldi_proxy.exe", StringComparison.OrdinalIgnoreCase);
    }

    public static (string TargetPath, string Arguments, string WorkingDirectory) ReadShortcutProperties(string lnkPath)
    {
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType != null)
            {
                dynamic? shell = Activator.CreateInstance(shellType);
                if (shell != null)
                {
                    dynamic shortcut = shell.CreateShortcut(lnkPath);
                    string target = Environment.ExpandEnvironmentVariables((shortcut.TargetPath as string) ?? string.Empty);
                    string args = Environment.ExpandEnvironmentVariables((shortcut.Arguments as string) ?? string.Empty);
                    string workDir = Environment.ExpandEnvironmentVariables((shortcut.WorkingDirectory as string) ?? string.Empty);
                    return (target, args, workDir);
                }
            }
        }
        catch { }

        return (string.Empty, string.Empty, string.Empty);
    }

    public void CleanFinding(DiagnosticFinding finding, bool sendToRecycleBin = true)
    {
        if (finding.Category != "BrokenLauncherOrPwaShortcut")
            return;

        string subType = finding.Metadata.GetValueOrDefault("SubType", string.Empty);

        if (finding.SelectedAction == RemediationAction.HealAcl && subType == "SquirrelMissingSandboxAcl")
        {
            string dirPath = finding.Metadata.GetValueOrDefault("DirectoryPath", finding.Target);
            aclSanitizer.HealDirectorySandboxAcl(dirPath);
            return;
        }

        string lnkPath = finding.Metadata.GetValueOrDefault("ShortcutPath", finding.Target);
        if (File.Exists(lnkPath))
        {
            if (sendToRecycleBin)
            {
                Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(
                    lnkPath,
                    Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs,
                    Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
            }
            else
            {
                File.SetAttributes(lnkPath, FileAttributes.Normal);
                File.Delete(lnkPath);
            }

            auditLogger.LogInfo("LauncherValidator", $"Deleted broken shortcut '{lnkPath}' (SubType={subType}).");
        }

        // If it was a broken Squirrel stub directory with no valid app-* binaries, also clean the leftover stub directory
        if (subType is "BrokenSquirrelNoAppDirs" or "BrokenSquirrelMissingExe")
        {
            string stubDir = finding.Metadata.GetValueOrDefault("StubDirectory", string.Empty);
            if (!string.IsNullOrWhiteSpace(stubDir) && Directory.Exists(stubDir))
            {
                try
                {
                    if (sendToRecycleBin)
                    {
                        Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(
                            stubDir,
                            Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs,
                            Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
                    }
                    else
                    {
                        Directory.Delete(stubDir, recursive: true);
                    }
                    auditLogger.LogInfo("LauncherValidator", $"Removed broken Squirrel stub directory '{stubDir}'.");
                }
                catch (Exception ex)
                {
                    auditLogger.LogWarning("LauncherValidator", $"Failed to remove broken Squirrel stub directory '{stubDir}': {ex.Message}");
                }
            }
        }
    }

    private static bool IsStandardDrivePath(string path)
    {
        return path.Length >= 3 &&
               char.IsLetter(path[0]) &&
               path[1] == ':' &&
               (path[2] == '\\' || path[2] == '/');
    }

    private static bool IsUnderCommonPath(string path)
    {
        string commonStartMenu = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu);
        string publicDesktop = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
        return (!string.IsNullOrWhiteSpace(commonStartMenu) && path.StartsWith(commonStartMenu, StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrWhiteSpace(publicDesktop) && path.StartsWith(publicDesktop, StringComparison.OrdinalIgnoreCase));
    }
}
