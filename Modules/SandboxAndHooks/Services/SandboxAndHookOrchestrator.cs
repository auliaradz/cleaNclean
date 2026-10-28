using System.IO;
using System.Text.Json;
using cleaNclean.Modules.SandboxAndHooks.Models;
using cleaNclean.Services;

namespace cleaNclean.Modules.SandboxAndHooks.Services;

public class SandboxCleanSummary
{
    public int SuccessCount { get; set; }
    public int FailedCount { get; set; }
    public int SkippedRequiresAdminCount { get; set; }
    public string AuditLogPath { get; set; } = string.Empty;
    public string AclBackupPath { get; set; } = string.Empty;
    public List<string> Errors { get; set; } = [];
}

/// <summary>
/// Unified orchestrator for "Orphaned Sandbox &amp; Graphics Hook Cleaner".
/// Coordinates:
/// 1. AppContainerAclSanitizer (Orphaned S-1-15-2-* SIDs &amp; *S-1-15-2-1 Auto-Heal)
/// 2. VulkanOverlayHookCleaner (Khronos\Vulkan Implicit &amp; Explicit Layers)
/// 3. BrokenLauncherValidator (Desktop/StartMenu/Taskbar .lnk, Squirrel Stub Launchers &amp; Browser PWA Proxies)
/// </summary>
public class SandboxAndHookOrchestrator
{
    public SecurityAuditLogger AuditLogger { get; }
    public InstalledAppsIndexer AppIndexer { get; }
    public AppContainerAclSanitizer AclSanitizer { get; }
    public VulkanOverlayHookCleaner VulkanCleaner { get; }
    public BrokenLauncherValidator LauncherValidator { get; }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public SandboxAndHookOrchestrator(InstalledAppsIndexer? sharedIndexer = null)
    {
        AuditLogger = new SecurityAuditLogger();
        AppIndexer = sharedIndexer ?? new InstalledAppsIndexer();
        AclSanitizer = new AppContainerAclSanitizer(AuditLogger);
        VulkanCleaner = new VulkanOverlayHookCleaner(AppIndexer, AuditLogger);
        LauncherValidator = new BrokenLauncherValidator(AclSanitizer, AuditLogger);
    }

    /// <summary>
    /// Synchronous Dry-Run Scan across all 3 sub-modules.
    /// </summary>
    public List<DiagnosticFinding> Scan(
        bool includeAppContainerAcl = true,
        bool includeVulkanHooks = true,
        bool includeBrokenLaunchers = true,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        AuditLogger.LogInfo("Orchestrator", "Starting Orphaned Sandbox & Graphics Hook Dry-Run Scan...");
        var results = new List<DiagnosticFinding>();

        if (includeAppContainerAcl)
        {
            results.AddRange(AclSanitizer.Scan(progress, ct));
        }

        if (includeVulkanHooks)
        {
            results.AddRange(VulkanCleaner.Scan(progress, ct));
        }

        if (includeBrokenLaunchers)
        {
            results.AddRange(LauncherValidator.Scan(progress, ct));
        }

        AuditLogger.LogInfo("Orchestrator", $"Dry-Run Scan completed. Total findings: {results.Count}");
        return results;
    }

    /// <summary>
    /// Asynchronous Dry-Run Scan across all 3 sub-modules.
    /// </summary>
    public async Task<List<DiagnosticFinding>> ScanAsync(
        bool includeAppContainerAcl = true,
        bool includeVulkanHooks = true,
        bool includeBrokenLaunchers = true,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        if (includeVulkanHooks)
        {
            progress?.Report("Memperbarui indeks aplikasi untuk memvalidasi residu Vulkan Hook...");
            await AppIndexer.BuildIndexAsync(ct);
        }

        return await Task.Run(() => Scan(includeAppContainerAcl, includeVulkanHooks, includeBrokenLaunchers, progress, ct), ct);
    }

    /// <summary>
    /// Serializes scan findings into structured JSON format.
    /// </summary>
    public static string SerializeFindingsToJson(IEnumerable<DiagnosticFinding> findings)
    {
        var exportItems = findings.Select(f => new
        {
            f.Category,
            f.Target,
            f.IssueDescription,
            Severity = f.Severity.ToString(),
            RecommendedAction = f.RecommendedAction.ToString(),
            SelectedAction = f.SelectedAction.ToString(),
            f.RequiresAdmin,
            f.Metadata
        });

        return JsonSerializer.Serialize(exportItems, JsonOptions);
    }

    /// <summary>
    /// Synchronous execution of Clean() on the selected findings.
    /// Performs UAC elevation checks, backs up SDDL / Registry values, and logs all actions.
    /// </summary>
    public SandboxCleanSummary Clean(
        IEnumerable<DiagnosticFinding> findingsToClean,
        bool sendShortcutsToRecycleBin = true,
        IProgress<string>? progress = null)
    {
        var summary = new SandboxCleanSummary
        {
            AuditLogPath = AuditLogger.AuditLogFilePath,
            AclBackupPath = AuditLogger.AclBackupFilePath
        };

        bool isAdmin = SecurityAuditLogger.IsRunningAsAdministrator();
        var list = findingsToClean.ToList();
        int idx = 0;

        AuditLogger.LogInfo("Orchestrator", $"Starting Clean() for {list.Count} findings (IsAdmin={isAdmin})...");

        foreach (var finding in list)
        {
            idx++;
            progress?.Report($"Menjalankan tindakan [{finding.SelectedAction}] ({idx}/{list.Count}): {Path.GetFileName(finding.Target)}...");

            if (finding.RequiresAdmin && !isAdmin)
            {
                summary.SkippedRequiresAdminCount++;
                string msg = $"[Butuh Admin/UAC] {finding.Category}: {finding.Target}";
                summary.Errors.Add(msg);
                AuditLogger.LogWarning("Orchestrator", $"Skipped '{finding.Target}' because Administrator elevation is required.");
                continue;
            }

            try
            {
                switch (finding.Category)
                {
                    case "OrphanedAppContainerSid":
                    case "SandboxMissingAllAppPackages":
                        AclSanitizer.CleanFinding(finding);
                        summary.SuccessCount++;
                        break;

                    case "VulkanOverlayHook":
                        VulkanCleaner.CleanFinding(finding);
                        summary.SuccessCount++;
                        break;

                    case "BrokenLauncherOrPwaShortcut":
                        LauncherValidator.CleanFinding(finding, sendShortcutsToRecycleBin);
                        summary.SuccessCount++;
                        break;

                    default:
                        throw new NotSupportedException($"Kategori temuan tidak dikenali: {finding.Category}");
                }
            }
            catch (Exception ex)
            {
                summary.FailedCount++;
                summary.Errors.Add($"{finding.Category} ({finding.Target}): {ex.Message}");
                AuditLogger.LogError("Orchestrator", $"Failed to clean '{finding.Target}'", ex);
            }
        }

        AuditLogger.LogInfo(
            "Orchestrator",
            $"Clean() finished: Success={summary.SuccessCount}, Failed={summary.FailedCount}, SkippedAdmin={summary.SkippedRequiresAdminCount}");

        return summary;
    }

    public Task<SandboxCleanSummary> CleanAsync(
        IEnumerable<DiagnosticFinding> findingsToClean,
        bool sendShortcutsToRecycleBin = true,
        IProgress<string>? progress = null)
    {
        return Task.Run(() => Clean(findingsToClean, sendShortcutsToRecycleBin, progress));
    }
}
