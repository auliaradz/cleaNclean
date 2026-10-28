using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using cleaNclean.Modules.SandboxAndHooks.Models;
using Microsoft.Win32;

namespace cleaNclean.Modules.SandboxAndHooks.Services;

/// <summary>
/// Sub-Module 1: Orphaned AppContainer SID &amp; Sandbox ACL Sanitizer.
/// Scans %LOCALAPPDATA%, %LOCALAPPDATA%\Programs, and %APPDATA% (plus immediate app directories)
/// for orphaned specific AppContainer SIDs (S-1-15-2-&lt;7+ blocks&gt;) whose registry mappings or package folders
/// no longer exist, and auto-heals missing ALL APPLICATION PACKAGES (S-1-15-2-1) ReadAndExecute (OI)(CI)(RX) permissions.
/// </summary>
public class AppContainerAclSanitizer(SecurityAuditLogger auditLogger)
{
    public const string AllApplicationPackagesSid = "S-1-15-2-1";
    public const string AllRestrictedApplicationPackagesSid = "S-1-15-2-2";

    private const string AppContainerMappingsRegPath =
        @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings";

    // Matches package-specific AppContainer SIDs: S-1-15-2-<7 numeric blocks> (8 numeric blocks total starting from 2)
    // Also matches child AppContainer SIDs with additional blocks, while strictly excluding S-1-15-2-1 and S-1-15-2-2.
    private static readonly Regex SpecificAppContainerSidRegex =
        new(@"^S-1-15-2-(\d+-){6,}\d+$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public List<string> GetTargetDirectoriesToInspect()
    {
        var targets = new List<string>();

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string localPrograms = Path.Combine(localAppData, "Programs");
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string[] rootTargets = [localAppData, localPrograms, roamingAppData];

        foreach (var root in rootTargets)
        {
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
                continue;

            targets.Add(root);

            // Also inspect immediate application subdirectories inside %LOCALAPPDATA%, %LOCALAPPDATA%\Programs, and %APPDATA%
            try
            {
                foreach (var subDir in Directory.GetDirectories(root))
                {
                    try
                    {
                        var attr = File.GetAttributes(subDir);
                        if ((attr & FileAttributes.ReparsePoint) == 0)
                        {
                            targets.Add(subDir);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        return targets.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Dry-Run Scan: Detects orphaned AppContainer SIDs and missing S-1-15-2-1 sandbox permissions without modifying ACLs.
    /// </summary>
    public List<DiagnosticFinding> Scan(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var findings = new List<DiagnosticFinding>();
        string packagesDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages");
        string localAppDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var validSidCache = new Dictionary<string, (bool IsValid, string Reason)>(StringComparer.OrdinalIgnoreCase);
        var directories = GetTargetDirectoriesToInspect();

        progress?.Report("Memindai ACL Sandbox & AppContainer SID pada %LOCALAPPDATA% dan %APPDATA%...");

        foreach (var dirPath in directories)
        {
            ct.ThrowIfCancellationRequested();
            InspectDirectoryAcl(dirPath, localAppDataRoot, packagesDir, validSidCache, findings);
        }

        return findings;
    }

    private void InspectDirectoryAcl(
        string dirPath,
        string localAppDataRoot,
        string packagesDir,
        Dictionary<string, (bool IsValid, string Reason)> validSidCache,
        List<DiagnosticFinding> findings)
    {
        DirectorySecurity security;
        AuthorizationRuleCollection rules;
        try
        {
            var dirInfo = new DirectoryInfo(dirPath);
            security = dirInfo.GetAccessControl(AccessControlSections.Access);
            rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        }
        catch
        {
            // Skip inaccessible system-protected directories
            return;
        }

        bool hasAnyAppContainerSid = false;
        bool hasAllApplicationPackagesRx = false;
        var seenOrphanSidsInDir = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IdentityReference is not SecurityIdentifier sid)
                continue;

            string sidValue = sid.Value;
            if (!sidValue.StartsWith("S-1-15-2-", StringComparison.OrdinalIgnoreCase))
                continue;

            hasAnyAppContainerSid = true;

            // Never flag S-1-15-2-1 (ALL APPLICATION PACKAGES) or S-1-15-2-2 (ALL RESTRICTED APPLICATION PACKAGES) as orphaned
            if (sidValue.Equals(AllApplicationPackagesSid, StringComparison.OrdinalIgnoreCase))
            {
                if (rule.AccessControlType == AccessControlType.Allow &&
                    (rule.FileSystemRights & FileSystemRights.ReadAndExecute) == FileSystemRights.ReadAndExecute)
                {
                    hasAllApplicationPackagesRx = true;
                }
                continue;
            }

            if (sidValue.Equals(AllRestrictedApplicationPackagesSid, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Check specific 8-block (or child) AppContainer SID: S-1-15-2-<blocks>
            if (!SpecificAppContainerSidRegex.IsMatch(sidValue))
                continue;

            // Only remove explicit rules on the directory where they are defined (avoid duplicate findings on inherited children)
            if (rule.IsInherited)
                continue;

            if (!seenOrphanSidsInDir.Add(sidValue))
                continue;

            if (!validSidCache.TryGetValue(sidValue, out var validation))
            {
                validation = ValidateAppContainerSid(sidValue, packagesDir);
                validSidCache[sidValue] = validation;
            }

            if (!validation.IsValid)
            {
                findings.Add(new DiagnosticFinding
                {
                    Category = "OrphanedAppContainerSid",
                    Target = dirPath,
                    IssueDescription = $"Orphaned AppContainer SID ({sidValue}): {validation.Reason}",
                    Severity = FindingSeverity.Medium,
                    RecommendedAction = RemediationAction.Remove,
                    SelectedAction = RemediationAction.Remove,
                    AvailableActions = [RemediationAction.Remove],
                    RequiresAdmin = false,
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Sid"] = sidValue,
                        ["DirectoryPath"] = dirPath,
                        ["ValidationDetail"] = validation.Reason
                    }
                });
            }
        }

        // Auto-Heal Sandbox check:
        // If %LOCALAPPDATA% or a subfolder inside it has S-1-15-2-* entries (or is %LOCALAPPDATA% root itself)
        // but is MISSING ALL APPLICATION PACKAGES (S-1-15-2-1) ReadAndExecute, Chromium/Electron/WebView2 GPU Sandbox will crash (STATUS_BREAKPOINT).
        bool isUnderLocalAppData = dirPath.StartsWith(localAppDataRoot, StringComparison.OrdinalIgnoreCase);
        bool isLocalAppDataRoot = dirPath.Equals(localAppDataRoot, StringComparison.OrdinalIgnoreCase);

        if (isUnderLocalAppData && (hasAnyAppContainerSid || isLocalAppDataRoot) && !hasAllApplicationPackagesRx)
        {
            findings.Add(new DiagnosticFinding
            {
                Category = "SandboxMissingAllAppPackages",
                Target = dirPath,
                IssueDescription =
                    "Direktori memiliki entri AppContainer S-1-15-2-* tetapi kehilangan izin ReadAndExecute (OI)(CI)(RX) untuk 'ALL APPLICATION PACKAGES' (*S-1-15-2-1). Berisiko menyebabkan crash GPU Sandbox (STATUS_BREAKPOINT) pada aplikasi Chromium/Electron/WebView2.",
                Severity = isLocalAppDataRoot ? FindingSeverity.Critical : FindingSeverity.High,
                RecommendedAction = RemediationAction.HealAcl,
                SelectedAction = RemediationAction.HealAcl,
                AvailableActions = [RemediationAction.HealAcl],
                RequiresAdmin = false,
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["DirectoryPath"] = dirPath,
                    ["InjectSid"] = AllApplicationPackagesSid
                }
            });
        }
    }

    /// <summary>
    /// Validates whether an S-1-15-2-* SID still exists in HKCU AppContainer\Mappings and whether its package folder exists.
    /// </summary>
    public static (bool IsValid, string Reason) ValidateAppContainerSid(string sidValue, string packagesRootDir)
    {
        try
        {
            // For child AppContainer SIDs (more than 7 blocks after S-1-15-2-), also check the base 8-block parent SID
            string lookupSid = ExtractBasePackageAppContainerSid(sidValue);

            string regPath = $@"{AppContainerMappingsRegPath}\{lookupSid}";
            using var mappingKey = Registry.CurrentUser.OpenSubKey(regPath);

            if (mappingKey == null)
            {
                return (false, $"Key Registry AppContainer\\Mappings\\{lookupSid} sudah tidak ditemukan");
            }

            string? moniker = mappingKey.GetValue("Moniker")?.ToString();
            if (!string.IsNullOrWhiteSpace(moniker) && Directory.Exists(packagesRootDir))
            {
                string pkgFolder = Path.Combine(packagesRootDir, moniker);
                // Some system AppContainers live in C:\Windows\SystemApps, only flag missing package folder if it's not a Windows system moniker
                if (!Directory.Exists(pkgFolder) &&
                    !moniker.StartsWith("Microsoft.Windows.", StringComparison.OrdinalIgnoreCase) &&
                    !moniker.StartsWith("windows.immersivecontrolpanel", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"Folder paket '{moniker}' sudah tidak ada di %LOCALAPPDATA%\\Packages");
                }
            }

            return (true, "Valid");
        }
        catch (Exception ex)
        {
            return (true, $"Skipped validation due to error: {ex.Message}");
        }
    }

    private static string ExtractBasePackageAppContainerSid(string sidValue)
    {
        // Format: S-1-15-2-<b1>-<b2>-<b3>-<b4>-<b5>-<b6>-<b7>
        var parts = sidValue.Split('-');
        if (parts.Length >= 11)
        {
            return string.Join("-", parts.Take(11));
        }
        return sidValue;
    }

    /// <summary>
    /// Executes ACL sanitization (removing orphaned S-1-15-2-* SIDs) or Auto-Heal (injecting S-1-15-2-1 ReadAndExecute).
    /// Always backs up the original directory SDDL before modifying ACLs.
    /// </summary>
    public void CleanFinding(DiagnosticFinding finding)
    {
        if (finding.Category == "OrphanedAppContainerSid")
        {
            string dirPath = finding.Metadata.GetValueOrDefault("DirectoryPath", finding.Target);
            string sidString = finding.Metadata.GetValueOrDefault("Sid", string.Empty);

            if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath))
                return;

            // Safety guard: never remove S-1-15-2-1 or S-1-15-2-2
            if (sidString.Equals(AllApplicationPackagesSid, StringComparison.OrdinalIgnoreCase) ||
                sidString.Equals(AllRestrictedApplicationPackagesSid, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Whitelisted universal SID '{sidString}' tidak boleh dihapus.");
            }

            var dirInfo = new DirectoryInfo(dirPath);
            DirectorySecurity security = dirInfo.GetAccessControl(AccessControlSections.Access);

            auditLogger.BackupDirectoryAclBeforeModify(dirPath, security, $"Remove Orphaned AppContainer SID {sidString}");

            var sidToRemove = new SecurityIdentifier(sidString);
            security.PurgeAccessRules(sidToRemove);

            // Auto-Heal check during cleanup: if removing/modifying a %LOCALAPPDATA% directory that lacks S-1-15-2-1, ensure S-1-15-2-1 is present
            string localAppDataRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (dirPath.StartsWith(localAppDataRoot, StringComparison.OrdinalIgnoreCase) &&
                !HasAllApplicationPackagesReadExecute(security))
            {
                InjectAllApplicationPackagesRule(security);
                auditLogger.LogInfo("AutoHeal-Sandbox", $"Injected *S-1-15-2-1 (OI)(CI)(RX) onto '{dirPath}' during SID cleanup.");
            }

            dirInfo.SetAccessControl(security);
            auditLogger.LogInfo("ACL-Sanitizer", $"Removed orphaned AppContainer SID '{sidString}' from '{dirPath}'.");
        }
        else if (finding.Category == "SandboxMissingAllAppPackages")
        {
            HealDirectorySandboxAcl(finding.Target);
        }
    }

    public void HealDirectorySandboxAcl(string dirPath)
    {
        if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath))
            return;

        var dirInfo = new DirectoryInfo(dirPath);
        DirectorySecurity security = dirInfo.GetAccessControl(AccessControlSections.Access);

        auditLogger.BackupDirectoryAclBeforeModify(dirPath, security, "Auto-Heal Sandbox (*S-1-15-2-1 ReadAndExecute)");

        InjectAllApplicationPackagesRule(security);
        dirInfo.SetAccessControl(security);

        auditLogger.LogInfo("AutoHeal-Sandbox", $"Successfully injected ALL APPLICATION PACKAGES (*S-1-15-2-1) (OI)(CI)(RX) on '{dirPath}'.");
    }

    public static bool HasAllApplicationPackagesReadExecute(DirectorySecurity security)
    {
        try
        {
            var allAppPkgSid = new SecurityIdentifier(AllApplicationPackagesSid);
            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.IdentityReference.Equals(allAppPkgSid) &&
                    rule.AccessControlType == AccessControlType.Allow &&
                    (rule.FileSystemRights & FileSystemRights.ReadAndExecute) == FileSystemRights.ReadAndExecute)
                {
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    private static void InjectAllApplicationPackagesRule(DirectorySecurity security)
    {
        var allAppPkgSid = new SecurityIdentifier(AllApplicationPackagesSid);
        var rxRule = new FileSystemAccessRule(
            allAppPkgSid,
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);

        security.AddAccessRule(rxRule);
    }
}
