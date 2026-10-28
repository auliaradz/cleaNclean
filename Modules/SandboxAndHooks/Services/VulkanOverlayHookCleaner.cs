using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using cleaNclean.Modules.SandboxAndHooks.Models;
using cleaNclean.Services;
using Microsoft.Win32;

namespace cleaNclean.Modules.SandboxAndHooks.Services;

/// <summary>
/// Sub-Module 2: Orphaned Vulkan &amp; GPU Overlay Hook Cleaner.
/// Scans HKLM and HKCU Khronos\Vulkan ImplicitLayers and ExplicitLayers for missing .json manifests,
/// missing layer.library_path .dll files, or residual hook directories in ProgramData/AppData left behind
/// after the parent application (e.g. OBS Studio, GOG Galaxy, Epic, RTSS, Steam) was uninstalled.
/// Supports both Remove (delete registry value) and Disable (set DWORD = 1).
/// </summary>
public class VulkanOverlayHookCleaner(InstalledAppsIndexer indexer, SecurityAuditLogger auditLogger)
{
    private static readonly (RegistryKey Hive, string HiveName, string SubKeyPath, bool RequiresAdmin)[] TargetVulkanKeys =
    [
        (Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Khronos\Vulkan\ImplicitLayers", true),
        (Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Khronos\Vulkan\ExplicitLayers", true),
        (Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers", true),
        (Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ExplicitLayers", true),
        (Registry.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Khronos\Vulkan\ImplicitLayers", false),
        (Registry.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\Khronos\Vulkan\ExplicitLayers", false),
        (Registry.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers", false),
        (Registry.CurrentUser, "HKEY_CURRENT_USER", @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ExplicitLayers", false)
    ];

    public List<DiagnosticFinding> Scan(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var findings = new List<DiagnosticFinding>();
        progress?.Report("Memindai Vulkan ImplicitLayers & ExplicitLayers (GPU Overlay Hooks)...");

        foreach (var (hive, hiveName, subKeyPath, requiresAdmin) in TargetVulkanKeys)
        {
            ct.ThrowIfCancellationRequested();
            InspectVulkanLayerKey(hive, hiveName, subKeyPath, requiresAdmin, findings);
        }

        return findings;
    }

    private void InspectVulkanLayerKey(
        RegistryKey hive,
        string hiveName,
        string subKeyPath,
        bool requiresAdmin,
        List<DiagnosticFinding> findings)
    {
        try
        {
            using var key = hive.OpenSubKey(subKeyPath, writable: false);
            if (key == null) return;

            foreach (var jsonManifestPath in key.GetValueNames())
            {
                if (string.IsNullOrWhiteSpace(jsonManifestPath))
                    continue;

                object? rawVal = key.GetValue(jsonManifestPath);
                int currentDword = rawVal is int i ? i : 0;
                string fullRegistryLocation = $@"{hiveName}\{subKeyPath}";
                string cleanJsonPath = Environment.ExpandEnvironmentVariables(jsonManifestPath.Trim('"', ' '));

                // 1. Check if the .json manifest file exists on disk
                if (!File.Exists(cleanJsonPath))
                {
                    findings.Add(CreateVulkanFinding(
                        fullRegistryLocation,
                        jsonManifestPath,
                        cleanJsonPath,
                        libraryDllPath: string.Empty,
                        residualDir: string.Empty,
                        currentDword,
                        requiresAdmin,
                        issue: $"File manifest Vulkan JSON sudah tidak ada di disk: '{cleanJsonPath}'",
                        severity: FindingSeverity.High,
                        recommended: RemediationAction.Remove));
                    continue;
                }

                // 2. Parse the JSON manifest and verify layer.library_path (.dll)
                var (dllPaths, layerName, layerDescription) = ParseVulkanManifest(cleanJsonPath);
                string? missingDll = dllPaths.FirstOrDefault(dll => !File.Exists(dll));

                if (missingDll != null)
                {
                    findings.Add(CreateVulkanFinding(
                        fullRegistryLocation,
                        jsonManifestPath,
                        cleanJsonPath,
                        libraryDllPath: missingDll,
                        residualDir: GetResidualProgramDataFolder(cleanJsonPath),
                        currentDword,
                        requiresAdmin,
                        issue: $"Library DLL Vulkan hook (`layer.library_path`) tidak ditemukan di disk: '{missingDll}'",
                        severity: FindingSeverity.High,
                        recommended: RemediationAction.Remove));
                    continue;
                }

                // 3. Universal Orphaned Parent Application Check (e.g. residual hook folder in ProgramData or AppData whose parent app is uninstalled)
                var (isOrphanedHook, orphanReason, residualFolder) = CheckIfParentApplicationUninstalled(
                    cleanJsonPath, dllPaths.FirstOrDefault() ?? string.Empty, layerName, layerDescription);

                if (isOrphanedHook)
                {
                    findings.Add(CreateVulkanFinding(
                        fullRegistryLocation,
                        jsonManifestPath,
                        cleanJsonPath,
                        libraryDllPath: dllPaths.FirstOrDefault() ?? string.Empty,
                        residualDir: residualFolder,
                        currentDword,
                        requiresAdmin,
                        issue: orphanReason,
                        severity: FindingSeverity.High,
                        recommended: RemediationAction.Remove));
                }
            }
        }
        catch (Exception ex)
        {
            auditLogger.LogWarning("VulkanScanner", $"Failed to inspect '{hiveName}\\{subKeyPath}': {ex.Message}");
        }
    }

    private static DiagnosticFinding CreateVulkanFinding(
        string registryKeyPath,
        string valueName,
        string jsonPath,
        string libraryDllPath,
        string residualDir,
        int currentDword,
        bool requiresAdmin,
        string issue,
        FindingSeverity severity,
        RemediationAction recommended)
    {
        string statusText = currentDword == 0 ? "Aktif (DWORD=0)" : $"Nonaktif (DWORD={currentDword})";
        return new DiagnosticFinding
        {
            Category = "VulkanOverlayHook",
            Target = $@"{registryKeyPath} -> {valueName}",
            IssueDescription = $"{issue} [Status Hook: {statusText}]",
            Severity = severity,
            RecommendedAction = recommended,
            SelectedAction = recommended,
            AvailableActions = [RemediationAction.Remove, RemediationAction.Disable],
            RequiresAdmin = requiresAdmin,
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["RegistryKeyPath"] = registryKeyPath,
                ["ValueName"] = valueName,
                ["JsonPath"] = jsonPath,
                ["LibraryDllPath"] = libraryDllPath,
                ["ResidualDirectory"] = residualDir,
                ["CurrentDword"] = currentDword.ToString()
            }
        };
    }

    /// <summary>
    /// Parses a Khronos Vulkan Layer JSON manifest and resolves any `layer.library_path` or `layers[].library_path` relative to the JSON directory.
    /// </summary>
    public static (List<string> ResolvedDllPaths, string LayerName, string LayerDescription) ParseVulkanManifest(string jsonFilePath)
    {
        var dllPaths = new List<string>();
        string layerName = string.Empty;
        string layerDesc = string.Empty;
        string baseDir = Path.GetDirectoryName(jsonFilePath) ?? string.Empty;

        try
        {
            string jsonText = File.ReadAllText(jsonFilePath);
            using JsonDocument doc = JsonDocument.Parse(jsonText);
            JsonElement root = doc.RootElement;

            if (root.TryGetProperty("layer", out JsonElement singleLayer) && singleLayer.ValueKind == JsonValueKind.Object)
            {
                ExtractLayerElementInfo(singleLayer, baseDir, dllPaths, ref layerName, ref layerDesc);
            }

            if (root.TryGetProperty("layers", out JsonElement multiLayers) && multiLayers.ValueKind == JsonValueKind.Array)
            {
                foreach (var elem in multiLayers.EnumerateArray())
                {
                    if (elem.ValueKind == JsonValueKind.Object)
                    {
                        ExtractLayerElementInfo(elem, baseDir, dllPaths, ref layerName, ref layerDesc);
                    }
                }
            }
        }
        catch
        {
            // Ignore malformed JSON
        }

        return (dllPaths, layerName, layerDesc);
    }

    private static void ExtractLayerElementInfo(
        JsonElement layerObj,
        string baseDir,
        List<string> dllPaths,
        ref string layerName,
        ref string layerDesc)
    {
        if (string.IsNullOrEmpty(layerName) && layerObj.TryGetProperty("name", out JsonElement nameEl))
            layerName = nameEl.GetString() ?? string.Empty;

        if (string.IsNullOrEmpty(layerDesc) && layerObj.TryGetProperty("description", out JsonElement descEl))
            layerDesc = descEl.GetString() ?? string.Empty;

        if (layerObj.TryGetProperty("library_path", out JsonElement libEl))
        {
            string? rawLib = libEl.GetString();
            if (!string.IsNullOrWhiteSpace(rawLib))
            {
                string resolved = ResolveLibraryPath(baseDir, rawLib);
                dllPaths.Add(resolved);
            }
        }
    }

    private static string ResolveLibraryPath(string manifestDir, string libraryPathValue)
    {
        string trimmed = Environment.ExpandEnvironmentVariables(libraryPathValue.Trim());

        // Handle relative paths like ".\obs-vulkan64.dll" or "obs-vulkan64.dll"
        if (!Path.IsPathRooted(trimmed))
        {
            return Path.GetFullPath(Path.Combine(manifestDir, trimmed));
        }

        return trimmed;
    }

    private (bool IsOrphaned, string Reason, string ResidualFolder) CheckIfParentApplicationUninstalled(
        string jsonPath,
        string dllPath,
        string layerName,
        string layerDescription)
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // Skip hardware GPU driver folders in Windows\System32 or DriverStore
        if (jsonPath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
        {
            return (false, string.Empty, string.Empty);
        }

        string? topContainerDir = GetTopFolderUnderRoot(jsonPath, programData)
                               ?? GetTopFolderUnderRoot(jsonPath, localAppData)
                               ?? GetTopFolderUnderRoot(jsonPath, roamingAppData);

        if (string.IsNullOrWhiteSpace(topContainerDir))
        {
            return (false, string.Empty, string.Empty);
        }

        string folderName = Path.GetFileName(topContainerDir);

        // Strip common "-hook", "_hook", "overlay", "vulkan" suffixes to get the true parent app name
        // e.g., "obs-studio-hook" -> "obs-studio", "GOG.com" -> "GOG", "RivaTuner Statistics Server" -> "RivaTuner"
        string parentCandidate = Regex.Replace(folderName, @"([-_\s]*(hook|hooks|overlay|vulkan|layer|capture))+$", "", RegexOptions.IgnoreCase).Trim();
        if (string.IsNullOrWhiteSpace(parentCandidate))
            parentCandidate = folderName;

        // Check if parent candidate or layer description matches any currently installed application
        bool parentInstalled = indexer.IsMatchedWithInstalledApp(parentCandidate) ||
                               indexer.IsMatchedWithInstalledApp(folderName);

        // Also check tokens from layerDescription (e.g., "OBS Studio", "Steam", "Rockstar", "Epic")
        if (!parentInstalled && !string.IsNullOrWhiteSpace(layerDescription))
        {
            string cleanedDesc = Regex.Replace(layerDescription, @"\b(vulkan|layer|implicit|explicit|overlay|hook|capture|graphics|api)\b", "", RegexOptions.IgnoreCase).Trim();
            if (cleanedDesc.Length >= 3 && indexer.IsMatchedWithInstalledApp(cleanedDesc))
            {
                parentInstalled = true;
            }
        }

        if (!parentInstalled)
        {
            return (
                true,
                $"Residu Vulkan Hook yatim di '{topContainerDir}' (Aplikasi induk '{parentCandidate}' sudah di-uninstall tetapi masih menginjeksi file '{Path.GetFileName(dllPath)}')",
                topContainerDir);
        }

        return (false, string.Empty, string.Empty);
    }

    private static string GetResidualProgramDataFolder(string filePath)
    {
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return GetTopFolderUnderRoot(filePath, programData) ?? string.Empty;
    }

    private static string? GetTopFolderUnderRoot(string fullPath, string rootDir)
    {
        if (string.IsNullOrWhiteSpace(rootDir) || !fullPath.StartsWith(rootDir, StringComparison.OrdinalIgnoreCase))
            return null;

        string rel = Path.GetRelativePath(rootDir, fullPath);
        var parts = rel.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
        {
            return Path.Combine(rootDir, parts[0]);
        }
        return null;
    }

    /// <summary>
    /// Cleans or Disables a Vulkan Overlay Hook finding.
    /// - RemediationAction.Remove: Removes the registry property value (and deletes residual hook folder in ProgramData if orphaned).
    /// - RemediationAction.Disable: Sets the registry property DWORD value to 1 to disable hook injection without deleting.
    /// </summary>
    public void CleanFinding(DiagnosticFinding finding)
    {
        if (finding.Category != "VulkanOverlayHook")
            return;

        string regKeyPath = finding.Metadata.GetValueOrDefault("RegistryKeyPath", string.Empty);
        string valueName = finding.Metadata.GetValueOrDefault("ValueName", string.Empty);
        string residualDir = finding.Metadata.GetValueOrDefault("ResidualDirectory", string.Empty);

        if (string.IsNullOrWhiteSpace(regKeyPath) || string.IsNullOrWhiteSpace(valueName))
            throw new InvalidOperationException("Metadata path Registry Vulkan tidak lengkap.");

        bool isHklm = regKeyPath.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase);
        if (isHklm && !SecurityAuditLogger.IsRunningAsAdministrator())
        {
            throw new UnauthorizedAccessException(
                $"Memodifikasi '{regKeyPath}' membutuhkan hak akses Administrator (UAC Elevation). Klik 'Jalankan sebagai Admin' terlebih dahulu.");
        }

        var (hive, subKey) = SplitRegistryKey(regKeyPath);
        if (hive == null)
            throw new InvalidOperationException($"Root Registry tidak dikenali: {regKeyPath}");

        using var key = hive.OpenSubKey(subKey, writable: true)
            ?? throw new UnauthorizedAccessException($"Gagal membuka key Registry '{regKeyPath}' dengan akses tulis.");

        object? prevVal = key.GetValue(valueName);
        RemediationAction action = finding.SelectedAction;

        if (action == RemediationAction.Disable)
        {
            auditLogger.LogRegistryBeforeModify(regKeyPath, valueName, prevVal, "Disable Vulkan Layer (Set DWORD=1)");
            key.SetValue(valueName, 1, RegistryValueKind.DWord);
            auditLogger.LogInfo("VulkanCleaner", $"Disabled Vulkan hook '{valueName}' in '{regKeyPath}' (DWORD set to 1).");
        }
        else
        {
            auditLogger.LogRegistryBeforeModify(regKeyPath, valueName, prevVal, "Remove Vulkan Layer Value");
            key.DeleteValue(valueName, throwOnMissingValue: false);
            auditLogger.LogInfo("VulkanCleaner", $"Removed Vulkan hook registry value '{valueName}' from '{regKeyPath}'.");

            // If there is a confirmed residual hook directory in ProgramData (e.g., C:\ProgramData\obs-studio-hook), remove it too
            if (!string.IsNullOrWhiteSpace(residualDir) &&
                Directory.Exists(residualDir) &&
                residualDir.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(
                        residualDir,
                        Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs,
                        Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
                    auditLogger.LogInfo("VulkanCleaner", $"Moved residual hook directory '{residualDir}' to Recycle Bin.");
                }
                catch (Exception ex)
                {
                    auditLogger.LogWarning("VulkanCleaner", $"Could not remove residual hook folder '{residualDir}': {ex.Message}");
                }
            }
        }
    }

    private static (RegistryKey? Hive, string SubKey) SplitRegistryKey(string fullPath)
    {
        int slash = fullPath.IndexOf('\\');
        if (slash <= 0) return (null, string.Empty);

        string root = fullPath[..slash].ToUpperInvariant();
        string sub = fullPath[(slash + 1)..];

        return root switch
        {
            "HKEY_LOCAL_MACHINE" or "HKLM" => (Registry.LocalMachine, sub),
            "HKEY_CURRENT_USER" or "HKCU" => (Registry.CurrentUser, sub),
            _ => (null, string.Empty)
        };
    }
}
