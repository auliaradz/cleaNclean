using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using cleaNclean.Models;

namespace cleaNclean.Services;

public class ShortcutScanner(InstalledAppsIndexer indexer)
{
    private static readonly Regex UnicodeDrivePathRegex =
        new(@"([a-zA-Z]:\\[^\0""<>|*?\r\n]{3,240})", RegexOptions.Compiled);

    private static readonly Regex AppXPackageFullNameRegex =
        new(@"\b([A-Za-z0-9.\-]+_[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_[a-zA-Z0-9]+__[a-hjkmnp-tv-z0-9]{13})\b", RegexOptions.Compiled);

    public List<string> GetShortcutDirectories()
    {
        var dirs = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        return dirs.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public List<LeftoverItem> ScanBrokenShortcuts(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        progress?.Report("Memindai Shortcut (.lnk & .url) di Desktop, Start Menu & Startup...");

        foreach (var rootDir in GetShortcutDirectories())
        {
            ct.ThrowIfCancellationRequested();
            ScanDirectoryForShortcuts(rootDir, keyword: null, results, ct);
        }

        return results;
    }

    public List<LeftoverItem> ScanByKeyword(string keyword, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        if (string.IsNullOrWhiteSpace(keyword) || keyword.Trim().Length < 2)
            return results;

        string kw = keyword.Trim();
        progress?.Report($"Mencari Shortcut '{kw}' di Desktop & Start Menu...");

        foreach (var rootDir in GetShortcutDirectories())
        {
            ct.ThrowIfCancellationRequested();
            ScanDirectoryForShortcuts(rootDir, kw, results, ct);
        }

        return results;
    }

    private void ScanDirectoryForShortcuts(string rootDir, string? keyword, List<LeftoverItem> results, CancellationToken ct)
    {
        IEnumerable<string> lnkFiles;
        try
        {
            lnkFiles = Directory.EnumerateFiles(rootDir, "*.lnk", SearchOption.AllDirectories);
        }
        catch
        {
            return;
        }

        foreach (var lnkPath in lnkFiles)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string fileName = Path.GetFileNameWithoutExtension(lnkPath);
                string? targetPath = ResolveShortcutTarget(lnkPath);

                if (keyword != null)
                {
                    bool nameMatch = fileName.Contains(keyword, StringComparison.OrdinalIgnoreCase);
                    bool targetMatch = !string.IsNullOrWhiteSpace(targetPath) && targetPath.Contains(keyword, StringComparison.OrdinalIgnoreCase);

                    if (nameMatch || targetMatch)
                    {
                        bool targetMissing = !string.IsNullOrWhiteSpace(targetPath) && !File.Exists(targetPath) && !Directory.Exists(targetPath);
                        var fi = new FileInfo(lnkPath);
                        results.Add(new LeftoverItem
                        {
                            Name = $"{fileName}.lnk",
                            Category = LeftoverCategory.BrokenShortcut,
                            Location = lnkPath,
                            TargetInfo = string.IsNullOrWhiteSpace(targetPath) ? "Shortcut cocok kata kunci" : $"Target: {targetPath}",
                            SizeInBytes = fi.Exists ? fi.Length : 0,
                            ConfidenceLevel = targetMissing ? "Tinggi (Target Hilang)" : "Pencarian Manual",
                            Reason = targetMissing
                                ? $"Target shortcut sudah tidak ada di disk: {targetPath}"
                                : $"Nama atau target shortcut cocok dengan '{keyword}'",
                            LastModified = fi.Exists ? fi.LastWriteTime : null,
                            IsSelected = targetMissing || !indexer.IsMatchedWithInstalledApp(fileName)
                        });
                    }
                }
                else
                {
                    // 1. Standard / Binary-Resolved Target Path Missing on Disk (includes WindowsApps UWP paths!)
                    if (!string.IsNullOrWhiteSpace(targetPath) &&
                        IsStandardDrivePath(targetPath) &&
                        !targetPath.Contains(@"\Windows\Installer\", StringComparison.OrdinalIgnoreCase) &&
                        !File.Exists(targetPath) &&
                        !Directory.Exists(targetPath))
                    {
                        bool isUwpTarget = targetPath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);
                        var fi = new FileInfo(lnkPath);
                        results.Add(new LeftoverItem
                        {
                            Name = $"{fileName}.lnk",
                            Category = LeftoverCategory.BrokenShortcut,
                            Location = lnkPath,
                            TargetInfo = isUwpTarget
                                ? $"Target paket UWP/Store hilang: {targetPath}"
                                : $"Target hilang: {targetPath}",
                            SizeInBytes = fi.Exists ? fi.Length : 0,
                            ConfidenceLevel = isUwpTarget
                                ? "Tinggi (Aplikasi Store/UWP Terhapus)"
                                : "Tinggi (Target .exe Hilang)",
                            Reason = isUwpTarget
                                ? $"Shortcut mengarah ke paket Microsoft Store/AppX '{Path.GetFileName(targetPath)}' yang sudah di-uninstall"
                                : $"File target '{targetPath}' sudah tidak ditemukan di penyimpanan",
                            LastModified = fi.Exists ? fi.LastWriteTime : null
                        });
                        continue;
                    }

                    // 2. Check UWP / AppX PackageFullName embedded in .lnk when no drive path was resolved
                    if (string.IsNullOrWhiteSpace(targetPath) &&
                        TryGetOrphanedUwpPackageFromLnk(lnkPath, out string? orphanedPkgName))
                    {
                        var fi = new FileInfo(lnkPath);
                        results.Add(new LeftoverItem
                        {
                            Name = $"{fileName}.lnk",
                            Category = LeftoverCategory.BrokenShortcut,
                            Location = lnkPath,
                            TargetInfo = $"Target paket AppX/UWP hilang: {orphanedPkgName}",
                            SizeInBytes = fi.Exists ? fi.Length : 0,
                            ConfidenceLevel = "Tinggi (Aplikasi Store/UWP Terhapus)",
                            Reason = $"Paket aplikasi UWP/Microsoft Store '{orphanedPkgName}' sudah tidak terinstall di sistem",
                            LastModified = fi.Exists ? fi.LastWriteTime : null
                        });
                    }
                }
            }
            catch
            {
                // Skip unreadable shortcut
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

    /// <summary>
    /// Resolves the target path of a Windows .lnk shortcut using WScript.Shell COM late binding,
    /// with a UTF-16LE + ASCII binary .lnk parser fallback so UWP/WindowsApps and custom .lnk files resolve accurately.
    /// </summary>
    public static string? ResolveShortcutTarget(string lnkFilePath)
    {
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType != null)
            {
                dynamic? shell = Activator.CreateInstance(shellType);
                if (shell != null)
                {
                    dynamic shortcut = shell.CreateShortcut(lnkFilePath);
                    string? target = shortcut.TargetPath as string;
                    string? args = shortcut.Arguments as string;

                    if (!string.IsNullOrWhiteSpace(target))
                    {
                        string expandedTarget = Environment.ExpandEnvironmentVariables(target);

                        // If target is a Windows shell/host (cmd.exe, powershell.exe, etc.), check Arguments for the real script/binary path
                        if (IsWindowsShellHost(expandedTarget) && !string.IsNullOrWhiteSpace(args))
                        {
                            string expandedArgs = Environment.ExpandEnvironmentVariables(args);
                            var argPathMatch = Regex.Match(
                                expandedArgs,
                                @"([a-zA-Z]:\\[^:*?""<>|'\r\n;]+?\.(?:exe|bat|cmd|ps1|vbs|py|msc|jar))",
                                RegexOptions.IgnoreCase);

                            if (argPathMatch.Success)
                            {
                                return argPathMatch.Groups[1].Value.Trim();
                            }
                        }

                        return expandedTarget;
                    }
                }
            }
        }
        catch
        {
            // Fallback to binary inspection below
        }

        return ParseLnkBinaryFallback(lnkFilePath);
    }

    private static bool IsWindowsShellHost(string targetPath)
    {
        string fileName = Path.GetFileName(targetPath);
        return fileName.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("wscript.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("cscript.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("conhost.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
    }

    public static string? ParseLnkBinaryFallback(string lnkFilePath)
    {
        try
        {
            byte[] bytes = File.ReadAllBytes(lnkFilePath);

            // 1. Inspect UTF-16LE (Encoding.Unicode) PropertyStore & Unicode LinkInfo strings
            //    This catches UWP / Microsoft Store shortcuts pointing to C:\Program Files\WindowsApps\<PackageFullName>
            string unicode = Encoding.Unicode.GetString(bytes);
            foreach (Match m in UnicodeDrivePathRegex.Matches(unicode))
            {
                string candidate = m.Groups[1].Value.Trim();
                if (candidate.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) ||
                    candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    candidate.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                    candidate.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) ||
                    candidate.EndsWith(".msc", StringComparison.OrdinalIgnoreCase))
                {
                    return candidate;
                }
            }

            // 2. Inspect ASCII LinkInfo strings
            string ascii = Encoding.ASCII.GetString(bytes);
            int idx = ascii.IndexOf(@":\", StringComparison.Ordinal);
            if (idx >= 1)
            {
                int start = idx - 1;
                int end = ascii.IndexOf('\0', start);
                if (end > start)
                {
                    string candidate = ascii[start..end];
                    if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                        candidate.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase))
                    {
                        return candidate;
                    }
                }
            }
        }
        catch { }

        return null;
    }

    public static bool TryGetOrphanedUwpPackageFromLnk(string lnkFilePath, out string? orphanedPackageFullName)
    {
        orphanedPackageFullName = null;
        try
        {
            byte[] bytes = File.ReadAllBytes(lnkFilePath);
            string unicode = Encoding.Unicode.GetString(bytes);

            foreach (Match m in AppXPackageFullNameRegex.Matches(unicode))
            {
                string pkgFullName = m.Groups[1].Value;
                // Ignore the StartMenuExperienceHost shell creator stamp
                if (pkgFullName.StartsWith("Microsoft.Windows.StartMenuExperienceHost", StringComparison.OrdinalIgnoreCase) ||
                    pkgFullName.StartsWith("Microsoft.Windows.ShellExperienceHost", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!IsAppXPackageInstalled(pkgFullName))
                {
                    orphanedPackageFullName = pkgFullName;
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    public static bool IsAppXPackageInstalled(string packageFullName)
    {
        try
        {
            string winAppsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps", packageFullName);
            if (Directory.Exists(winAppsDir))
                return true;

            using var repoKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
            if (repoKey != null)
            {
                using var exactSubKey = repoKey.OpenSubKey(packageFullName);
                if (exactSubKey != null)
                    return true;

                // Also check if another version of the same Package Family Name (<Name>_<PublisherId>) is installed
                int firstUnderscore = packageFullName.IndexOf('_');
                int doubleUnderscore = packageFullName.LastIndexOf("__", StringComparison.Ordinal);
                if (firstUnderscore > 0 && doubleUnderscore > firstUnderscore)
                {
                    string pkgPrefix = packageFullName[..(firstUnderscore + 1)];
                    string publisherSuffix = packageFullName[doubleUnderscore..];
                    foreach (var subName in repoKey.GetSubKeyNames())
                    {
                        if (subName.StartsWith(pkgPrefix, StringComparison.OrdinalIgnoreCase) &&
                            subName.EndsWith(publisherSuffix, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        catch { }

        return false;
    }
}
