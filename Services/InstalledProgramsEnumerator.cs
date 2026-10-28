using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Xml.Linq;
using Microsoft.Win32;
using cleaNclean.Models;

namespace cleaNclean.Services;

public class InstalledProgramsEnumerator
{
    private static readonly Regex QuotedOrFirstPathRegex =
        new(@"^(?:""([^""]+)""|([a-zA-Z]:\\[^:*?""<>|\r\n]+?\.(?:exe|ico|dll|msc|msi))|([^\s,""]+))",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MsiGuidRegex =
        new(@"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
            RegexOptions.Compiled);

    private static ImageSource? _defaultAppIcon;
    private static ImageSource? _defaultStoreIcon;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    public Task<List<InstalledProgramItem>> GetInstalledProgramsAsync(CancellationToken ct = default)
    {
        return Task.Run(() => EnumerateWin32Programs(ct), ct);
    }

    public Task<List<InstalledProgramItem>> GetWindowsAppsAsync(CancellationToken ct = default)
    {
        return Task.Run(() => EnumerateWindowsStoreApps(ct), ct);
    }

    private List<InstalledProgramItem> EnumerateWin32Programs(CancellationToken ct)
    {
        var results = new List<InstalledProgramItem>();
        var seenNamesAndLocations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var sources = new (RegistryHive Hive, RegistryView View, string SubKey, string DefaultArch, string HivePrefix)[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "64-bit", @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "32-bit", @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.CurrentUser, RegistryView.Default, @"Software\Microsoft\Windows\CurrentVersion\Uninstall", "64-bit", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall")
        };

        foreach (var src in sources)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(src.Hive, src.View);
                using var uninstallKey = baseKey.OpenSubKey(src.SubKey);
                if (uninstallKey == null) continue;

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var appKey = uninstallKey.OpenSubKey(subKeyName);
                        if (appKey == null) continue;

                        string? displayName = (appKey.GetValue("DisplayName") as string)?.Trim();
                        if (string.IsNullOrWhiteSpace(displayName))
                            continue;

                        bool isSysComponent = appKey.GetValue("SystemComponent") is int sysComp && sysComp == 1;
                        bool isNoRemove = appKey.GetValue("NoRemove") is int noRem && noRem == 1;

                        // Keep notable protected/bundled apps (e.g., Microsoft Edge WebView2, Edge Update, Cortana, etc.)
                        // while filtering out internal MSI sub-components & hotfixes
                        bool isNotableProtectedApp =
                            displayName.Contains("Microsoft Edge", StringComparison.OrdinalIgnoreCase) ||
                            displayName.Contains("WebView2", StringComparison.OrdinalIgnoreCase) ||
                            displayName.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) ||
                            displayName.Contains("Xbox", StringComparison.OrdinalIgnoreCase) ||
                            displayName.Contains("Copilot", StringComparison.OrdinalIgnoreCase) ||
                            displayName.Contains("Teams", StringComparison.OrdinalIgnoreCase);

                        if (isSysComponent && !isNotableProtectedApp)
                            continue;
                        if (!string.IsNullOrWhiteSpace(appKey.GetValue("ParentKeyName") as string))
                            continue;
                        string? releaseType = appKey.GetValue("ReleaseType") as string;
                        if (string.Equals(releaseType, "Security Update", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(releaseType, "Update Rollup", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(releaseType, "Hotfix", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string uninstallString = (appKey.GetValue("UninstallString") as string)?.Trim() ?? string.Empty;
                        string quietUninstall = (appKey.GetValue("QuietUninstallString") as string)?.Trim() ?? string.Empty;
                        string modifyPath = (appKey.GetValue("ModifyPath") as string)?.Trim() ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(uninstallString) &&
                            string.IsNullOrWhiteSpace(quietUninstall) &&
                            string.IsNullOrWhiteSpace(modifyPath))
                            continue;

                        if (string.IsNullOrWhiteSpace(uninstallString))
                            uninstallString = !string.IsNullOrWhiteSpace(quietUninstall) ? quietUninstall : modifyPath;

                        string installLocation = CleanDirectoryPath(appKey.GetValue("InstallLocation") as string);
                        string dedupKey = $"{displayName}|{installLocation}";
                        if (!seenNamesAndLocations.Add(dedupKey))
                            continue;

                        string version = (appKey.GetValue("DisplayVersion") as string)?.Trim() ?? string.Empty;
                        string publisher = (appKey.GetValue("Publisher") as string)?.Trim() ?? string.Empty;
                        string website = (appKey.GetValue("URLInfoAbout") as string)?.Trim()
                                      ?? (appKey.GetValue("HelpLink") as string)?.Trim()
                                      ?? (appKey.GetValue("URLUpdateInfo") as string)?.Trim()
                                      ?? string.Empty;
                        string comments = (appKey.GetValue("Comments") as string)?.Trim() ?? string.Empty;
                        string displayIconRaw = (appKey.GetValue("DisplayIcon") as string)?.Trim() ?? string.Empty;

                        string? iconCandidatePath = ExtractFilePathFromCommand(displayIconRaw);
                        string? uninstallExePath = ExtractFilePathFromCommand(uninstallString);

                        if (string.IsNullOrWhiteSpace(installLocation))
                        {
                            if (!string.IsNullOrWhiteSpace(iconCandidatePath) && File.Exists(iconCandidatePath))
                            {
                                string? dir = Path.GetDirectoryName(iconCandidatePath);
                                if (!string.IsNullOrWhiteSpace(dir) && !IsSystemOrInstallerDirectory(dir))
                                    installLocation = dir;
                            }
                            else if (!string.IsNullOrWhiteSpace(uninstallExePath) && File.Exists(uninstallExePath))
                            {
                                string? dir = Path.GetDirectoryName(uninstallExePath);
                                if (!string.IsNullOrWhiteSpace(dir) && !IsSystemOrInstallerDirectory(dir))
                                    installLocation = dir;
                            }
                        }

                        long sizeInBytes = 0;
                        if (appKey.GetValue("EstimatedSize") is int estKb && estKb > 0)
                        {
                            sizeInBytes = (long)estKb * 1024L;
                        }
                        else if (!string.IsNullOrWhiteSpace(installLocation) && Directory.Exists(installLocation))
                        {
                            sizeInBytes = EstimateDirectorySizeFast(installLocation);
                        }

                        string arch = DetermineArchitecture(src.DefaultArch, installLocation, iconCandidatePath, uninstallExePath);
                        DateTime? installDate = ResolveInstallDate(
                            appKey.GetValue("InstallDate") as string,
                            installLocation,
                            iconCandidatePath,
                            uninstallExePath);

                        ImageSource? icon = ResolveProgramIcon(displayIconRaw, iconCandidatePath, installLocation, uninstallExePath, displayName);

                        results.Add(new InstalledProgramItem
                        {
                            Name = displayName,
                            IconSource = icon,
                            SizeInBytes = sizeInBytes,
                            Version = version,
                            ArchitectureType = arch,
                            InstallDateValue = installDate,
                            Company = publisher,
                            Website = website,
                            Comment = comments,
                            InstallLocation = installLocation,
                            UninstallString = uninstallString,
                            QuietUninstallString = quietUninstall,
                            RegistryKeyPath = $@"{src.HivePrefix}\{subKeyName}",
                            DisplayIconRaw = displayIconRaw,
                            IsWindowsApp = false,
                            IsProtectedApp = isNoRemove || isSysComponent || isNotableProtectedApp,
                            IsSystemComponent = isSysComponent
                        });
                    }
                    catch
                    {
                        // Skip unreadable subkey
                    }
                }
            }
            catch
            {
                // Skip inaccessible hive
            }
        }

        return results.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private List<InstalledProgramItem> EnumerateWindowsStoreApps(CancellationToken ct)
    {
        var results = new List<InstalledProgramItem>();
        var seenPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var repoKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
            if (repoKey == null)
                return results;

            foreach (var pkgFullName in repoKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    // Skip framework/resource split packages
                    if (pkgFullName.Contains("_neutral_split.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.VCLibs.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.NET.Native.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.UI.Xaml.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.WindowsAppRuntime.", StringComparison.OrdinalIgnoreCase) ||
                        pkgFullName.StartsWith("Microsoft.Services.Store.Engagement", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    using var pkgKey = repoKey.OpenSubKey(pkgFullName);
                    if (pkgKey == null) continue;

                    string rootFolder = (pkgKey.GetValue("PackageRootFolder") as string)?.Trim() ?? string.Empty;
                    if (!seenPackages.Add(pkgFullName))
                        continue;

                    // Parse PackageFullName: Name_Version_Arch__PublisherId
                    string[] parts = pkgFullName.Split('_');
                    string rawPkgName = parts.Length > 0 ? parts[0] : pkgFullName;
                    string version = parts.Length > 1 ? parts[1] : string.Empty;
                    string archRaw = parts.Length > 2 ? parts[2] : "x64";
                    string arch = archRaw.Equals("x86", StringComparison.OrdinalIgnoreCase) ? "32-bit" : "64-bit";

                    var (friendlyName, publisher, logoPath) = ReadAppxManifestMetadata(rootFolder, rawPkgName);

                    long sizeBytes = 0;
                    DateTime? installDate = null;
                    if (!string.IsNullOrWhiteSpace(rootFolder) && Directory.Exists(rootFolder))
                    {
                        try
                        {
                            var di = new DirectoryInfo(rootFolder);
                            installDate = di.CreationTime;
                            sizeBytes = EstimateDirectorySizeFast(rootFolder);
                        }
                        catch { }
                    }

                    ImageSource? icon = LoadStoreAppLogo(logoPath, rootFolder) ?? GetDefaultStoreIcon();

                    results.Add(new InstalledProgramItem
                    {
                        Name = friendlyName,
                        IconSource = icon,
                        SizeInBytes = sizeBytes,
                        Version = version,
                        ArchitectureType = arch,
                        InstallDateValue = installDate,
                        Company = publisher,
                        Website = string.Empty,
                        Comment = pkgFullName,
                        InstallLocation = rootFolder,
                        UninstallString = $"Remove-AppxPackage -Package \"{pkgFullName}\"",
                        RegistryKeyPath = $@"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\{pkgFullName}",
                        IsWindowsApp = true,
                        PackageFullName = pkgFullName
                    });
                }
                catch { }
            }
        }
        catch { }

        return results.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static (string DisplayName, string Publisher, string? LogoPath) ReadAppxManifestMetadata(string rootFolder, string fallbackName)
    {
        string displayName = PrettifyPackageName(fallbackName);
        string publisher = string.Empty;
        string? logoRelPath = null;

        if (!string.IsNullOrWhiteSpace(rootFolder))
        {
            string manifestPath = Path.Combine(rootFolder, "AppxManifest.xml");
            if (File.Exists(manifestPath))
            {
                try
                {
                    var doc = XDocument.Load(manifestPath);
                    var props = doc.Root?.Elements().FirstOrDefault(e => e.Name.LocalName == "Properties");
                    if (props != null)
                    {
                        string? dn = props.Elements().FirstOrDefault(e => e.Name.LocalName == "DisplayName")?.Value;
                        if (!string.IsNullOrWhiteSpace(dn) && !dn.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase))
                        {
                            displayName = dn.Trim();
                        }

                        string? pub = props.Elements().FirstOrDefault(e => e.Name.LocalName == "PublisherDisplayName")?.Value;
                        if (!string.IsNullOrWhiteSpace(pub) && !pub.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase))
                        {
                            publisher = pub.Trim();
                        }

                        logoRelPath = props.Elements().FirstOrDefault(e => e.Name.LocalName == "Logo")?.Value;
                    }
                }
                catch { }
            }
        }

        if (string.IsNullOrWhiteSpace(publisher))
        {
            publisher = fallbackName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
                ? "Microsoft Corporation"
                : fallbackName.Split('.')[0];
        }

        return (displayName, publisher, logoRelPath);
    }

    private static string PrettifyPackageName(string rawPkgName)
    {
        string cleaned = rawPkgName;
        if (cleaned.StartsWith("Microsoft.Windows.", StringComparison.OrdinalIgnoreCase))
            cleaned = cleaned["Microsoft.Windows.".Length..];
        else if (cleaned.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase))
            cleaned = cleaned["Microsoft.".Length..];

        cleaned = Regex.Replace(cleaned, @"^[0-9A-F]{6,}\.", "", RegexOptions.IgnoreCase);
        cleaned = Regex.Replace(cleaned, @"([a-z])([A-Z])", "$1 $2");
        return cleaned.Replace('.', ' ').Trim();
    }

    private static ImageSource? LoadStoreAppLogo(string? logoRelPath, string rootFolder)
    {
        if (string.IsNullOrWhiteSpace(rootFolder) || !Directory.Exists(rootFolder))
            return null;

        try
        {
            string? resolvedPng = null;
            if (!string.IsNullOrWhiteSpace(logoRelPath))
            {
                string direct = Path.Combine(rootFolder, logoRelPath);
                if (File.Exists(direct))
                {
                    resolvedPng = direct;
                }
                else
                {
                    string? dir = Path.GetDirectoryName(direct);
                    string baseName = Path.GetFileNameWithoutExtension(direct);
                    if (!string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir))
                    {
                        resolvedPng = Directory.EnumerateFiles(dir, $"{baseName}*.png", SearchOption.TopDirectoryOnly).FirstOrDefault();
                    }
                }
            }

            if (string.IsNullOrWhiteSpace(resolvedPng))
            {
                foreach (var sub in new[] { rootFolder, Path.Combine(rootFolder, "Assets"), Path.Combine(rootFolder, "images") })
                {
                    if (Directory.Exists(sub))
                    {
                        resolvedPng = Directory.EnumerateFiles(sub, "*Logo*.png", SearchOption.TopDirectoryOnly).FirstOrDefault();
                        if (resolvedPng != null) break;
                    }
                }
            }

            if (!string.IsNullOrWhiteSpace(resolvedPng) && File.Exists(resolvedPng))
            {
                var bi = new BitmapImage();
                bi.BeginInit();
                bi.CacheOption = BitmapCacheOption.OnLoad;
                bi.DecodePixelWidth = 24;
                bi.UriSource = new Uri(resolvedPng, UriKind.Absolute);
                bi.EndInit();
                bi.Freeze();
                return bi;
            }
        }
        catch { }

        return null;
    }

    private static ImageSource? ResolveProgramIcon(
        string displayIconRaw,
        string? iconCandidatePath,
        string installLocation,
        string? uninstallExePath,
        string displayName)
    {
        string? bestFile = null;

        if (!string.IsNullOrWhiteSpace(iconCandidatePath) && File.Exists(iconCandidatePath))
        {
            bestFile = iconCandidatePath;
        }
        else if (!string.IsNullOrWhiteSpace(installLocation) && Directory.Exists(installLocation))
        {
            try
            {
                // Look for an .ico or main .exe in InstallLocation
                var exes = Directory.GetFiles(installLocation, "*.exe", SearchOption.TopDirectoryOnly)
                    .Where(f => !Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase) &&
                                !Path.GetFileName(f).Equals("crashpad_handler.exe", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                bestFile = exes.FirstOrDefault(f =>
                               displayName.Contains(Path.GetFileNameWithoutExtension(f), StringComparison.OrdinalIgnoreCase))
                           ?? exes.FirstOrDefault();

                if (bestFile == null)
                {
                    bestFile = Directory.GetFiles(installLocation, "*.ico", SearchOption.TopDirectoryOnly).FirstOrDefault();
                }
            }
            catch { }
        }

        if (bestFile == null &&
            !string.IsNullOrWhiteSpace(uninstallExePath) &&
            File.Exists(uninstallExePath) &&
            !Path.GetFileName(uninstallExePath).Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
        {
            bestFile = uninstallExePath;
        }

        if (!string.IsNullOrWhiteSpace(bestFile) && File.Exists(bestFile))
        {
            try
            {
                using Icon? ico = Icon.ExtractAssociatedIcon(bestFile);
                if (ico != null)
                {
                    var bmp = Imaging.CreateBitmapSourceFromHIcon(
                        ico.Handle,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromWidthAndHeight(20, 20));
                    bmp.Freeze();
                    return bmp;
                }
            }
            catch { }
        }

        return GetDefaultAppIcon();
    }

    private static ImageSource GetDefaultAppIcon()
    {
        if (_defaultAppIcon != null) return _defaultAppIcon;

        try
        {
            string shell32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "imageres.dll");
            if (File.Exists(shell32))
            {
                using Icon? ico = Icon.ExtractAssociatedIcon(shell32);
                if (ico != null)
                {
                    var bmp = Imaging.CreateBitmapSourceFromHIcon(
                        ico.Handle,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromWidthAndHeight(20, 20));
                    bmp.Freeze();
                    _defaultAppIcon = bmp;
                    return bmp;
                }
            }
        }
        catch { }

        var group = new DrawingGroup();
        using (var dc = group.Open())
        {
            dc.DrawRoundedRectangle(
                new SolidColorBrush(System.Windows.Media.Color.FromRgb(59, 130, 246)),
                null,
                new Rect(1, 1, 18, 18),
                3, 3);
            dc.DrawRectangle(System.Windows.Media.Brushes.White, null, new Rect(4, 4, 12, 3));
            dc.DrawRectangle(new SolidColorBrush(System.Windows.Media.Color.FromRgb(219, 234, 254)), null, new Rect(4, 8, 12, 8));
        }
        var di = new DrawingImage(group);
        di.Freeze();
        _defaultAppIcon = di;
        return di;
    }

    private static ImageSource GetDefaultStoreIcon()
    {
        if (_defaultStoreIcon != null) return _defaultStoreIcon;

        var group = new DrawingGroup();
        using (var dc = group.Open())
        {
            dc.DrawRoundedRectangle(
                new SolidColorBrush(System.Windows.Media.Color.FromRgb(14, 165, 233)),
                null,
                new Rect(1, 1, 18, 18),
                3, 3);
            dc.DrawRectangle(System.Windows.Media.Brushes.White, null, new Rect(4, 4, 5, 5));
            dc.DrawRectangle(System.Windows.Media.Brushes.White, null, new Rect(11, 4, 5, 5));
            dc.DrawRectangle(System.Windows.Media.Brushes.White, null, new Rect(4, 11, 5, 5));
            dc.DrawRectangle(System.Windows.Media.Brushes.White, null, new Rect(11, 11, 5, 5));
        }
        var di = new DrawingImage(group);
        di.Freeze();
        _defaultStoreIcon = di;
        return di;
    }

    private static string DetermineArchitecture(
        string defaultArch,
        string installLocation,
        string? iconPath,
        string? uninstallExePath)
    {
        if (installLocation.Contains(@"Program Files (x86)", StringComparison.OrdinalIgnoreCase) ||
            (iconPath != null && iconPath.Contains(@"Program Files (x86)", StringComparison.OrdinalIgnoreCase)) ||
            (uninstallExePath != null && uninstallExePath.Contains(@"Program Files (x86)", StringComparison.OrdinalIgnoreCase)))
        {
            return "32-bit";
        }

        if (installLocation.Contains(@"C:\Program Files\", StringComparison.OrdinalIgnoreCase) ||
            (iconPath != null && iconPath.Contains(@"C:\Program Files\", StringComparison.OrdinalIgnoreCase)))
        {
            return "64-bit";
        }

        string? probeExe = (!string.IsNullOrWhiteSpace(iconPath) && File.Exists(iconPath) && iconPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            ? iconPath
            : (!string.IsNullOrWhiteSpace(uninstallExePath) && File.Exists(uninstallExePath) && uninstallExePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                ? uninstallExePath
                : null;

        if (probeExe != null)
        {
            try
            {
                using var fs = new FileStream(probeExe, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var br = new BinaryReader(fs);
                if (fs.Length > 0x40 && br.ReadUInt16() == 0x5A4D) // MZ
                {
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    int peOffset = br.ReadInt32();
                    if (peOffset > 0 && peOffset + 6 < fs.Length)
                    {
                        fs.Seek(peOffset, SeekOrigin.Begin);
                        if (br.ReadUInt32() == 0x00004550) // PE\0\0
                        {
                            ushort machine = br.ReadUInt16();
                            if (machine is 0x8664 or 0xAA64)
                                return "64-bit";
                            if (machine == 0x014C)
                                return "32-bit";
                        }
                    }
                }
            }
            catch { }
        }

        return defaultArch;
    }

    private static DateTime? ResolveInstallDate(
        string? rawInstallDate,
        string installLocation,
        string? iconPath,
        string? uninstallExePath)
    {
        // Prefer directory / executable timestamp first so we get full dd/MM/yyyy HH.mm.ss like Revo Uninstaller
        if (!string.IsNullOrWhiteSpace(installLocation) && Directory.Exists(installLocation))
        {
            try
            {
                var di = new DirectoryInfo(installLocation);
                if (di.LastWriteTime.Year >= 2000)
                    return di.LastWriteTime;
            }
            catch { }
        }

        if (!string.IsNullOrWhiteSpace(iconPath) && File.Exists(iconPath) && !IsSystemOrInstallerDirectory(Path.GetDirectoryName(iconPath) ?? ""))
        {
            try
            {
                var fi = new FileInfo(iconPath);
                if (fi.LastWriteTime.Year >= 2000)
                    return fi.LastWriteTime;
            }
            catch { }
        }

        if (!string.IsNullOrWhiteSpace(uninstallExePath) && File.Exists(uninstallExePath) && !IsSystemOrInstallerDirectory(Path.GetDirectoryName(uninstallExePath) ?? ""))
        {
            try
            {
                var fi = new FileInfo(uninstallExePath);
                if (fi.LastWriteTime.Year >= 2000)
                    return fi.LastWriteTime;
            }
            catch { }
        }

        if (!string.IsNullOrWhiteSpace(rawInstallDate) &&
            DateTime.TryParseExact(rawInstallDate.Trim(), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsedDate))
        {
            return parsedDate;
        }

        return null;
    }

    private static long EstimateDirectorySizeFast(string dirPath)
    {
        if (IsSystemOrInstallerDirectory(dirPath))
            return 0;

        long total = 0;
        int fileCap = 0;

        try
        {
            var di = new DirectoryInfo(dirPath);
            if (!di.Exists) return 0;

            var opts = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                MaxRecursionDepth = 2,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            foreach (var fi in di.EnumerateFiles("*", opts))
            {
                total += fi.Length;
                if (++fileCap >= 250) break;
            }
        }
        catch { }

        return total;
    }

    private static string CleanDirectoryPath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return string.Empty;

        string cleaned = Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"'));
        return cleaned.TrimEnd('\\', '/');
    }

    private static string? ExtractFilePathFromCommand(string? rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand))
            return null;

        string expanded = Environment.ExpandEnvironmentVariables(rawCommand.Trim());

        // Strip trailing icon index like ",0" or ",-101"
        int commaIdx = expanded.LastIndexOf(',');
        if (commaIdx > 3 && int.TryParse(expanded[(commaIdx + 1)..].Trim(), out _))
        {
            expanded = expanded[..commaIdx].Trim();
        }

        expanded = expanded.Trim('"');
        if (File.Exists(expanded))
            return expanded;

        var m = QuotedOrFirstPathRegex.Match(rawCommand.Trim());
        if (m.Success)
        {
            string candidate = !string.IsNullOrWhiteSpace(m.Groups[1].Value)
                ? m.Groups[1].Value
                : !string.IsNullOrWhiteSpace(m.Groups[2].Value)
                    ? m.Groups[2].Value
                    : m.Groups[3].Value;

            candidate = Environment.ExpandEnvironmentVariables(candidate.Trim().Trim('"'));
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }

    private static bool IsSystemOrInstallerDirectory(string dirPath)
    {
        if (string.IsNullOrWhiteSpace(dirPath)) return true;
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return dirPath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase) ||
               dirPath.Equals(@"C:\Program Files", StringComparison.OrdinalIgnoreCase) ||
               dirPath.Equals(@"C:\Program Files (x86)", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Executes a Multi-Stage Smart &amp; Force Uninstaller capable of removing protected/stubborn applications
    /// such as Microsoft Edge, Edge WebView2, OneDrive, NonRemovable UWP/Store apps, and broken Win32 installers.
    /// </summary>
    public static async Task<bool> RunUninstallerProcessAsync(
        InstalledProgramItem program,
        bool allowForceFallback = true,
        IProgress<string>? progress = null)
    {
        return await Task.Run(async () =>
        {
            bool isEn = LocalizationManager.Instance.IsEnglish;

            // =====================================================================
            // CASE 1: WINDOWS STORE / UWP / SYSTEM APPX PACKAGE (INCLUDING PROTECTED INBOX APPS)
            // =====================================================================
            if (program.IsWindowsApp && !string.IsNullOrWhiteSpace(program.PackageFullName))
            {
                progress?.Report(isEn
                    ? $"Unlocking & removing Windows App package '{program.Name}'..."
                    : $"Membuka kunci & menghapus paket Windows App '{program.Name}'...");

                return await UninstallWindowsStorePackageForcefullyAsync(program.PackageFullName);
            }

            // =====================================================================
            // CASE 2: WIN32 / 64-BIT / STUB INSTALLERS (INCLUDING MICROSOFT EDGE, WEBVIEW2, ONEDRIVE)
            // =====================================================================
            bool isEdgeApp =
                program.Name.Equals("Microsoft Edge", StringComparison.OrdinalIgnoreCase) ||
                program.UninstallString.Contains("--msedge", StringComparison.OrdinalIgnoreCase);

            bool isEdgeWebView =
                program.Name.Contains("Edge WebView2", StringComparison.OrdinalIgnoreCase) ||
                program.UninstallString.Contains("--msedgewebview", StringComparison.OrdinalIgnoreCase);

            bool isOneDrive =
                program.Name.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) ||
                program.UninstallString.Contains("OneDriveSetup.exe", StringComparison.OrdinalIgnoreCase);

            // Step 1: Terminate running processes that lock the application's binaries
            progress?.Report(isEn
                ? $"Stopping active processes & background services for '{program.Name}'..."
                : $"Menghentikan proses aktif & layanan latar belakang untuk '{program.Name}'...");
            TerminateLockingProcesses(program, isEdgeApp, isEdgeWebView, isOneDrive);

            // Step 2: Unlock Registry blocks (NoRemove = 0, EdgeUpdateDev AllowUninstall = 1, DMA Policy)
            UnlockProtectedUninstallRegistry(program, isEdgeApp, isEdgeWebView);

            // Step 3: Build & execute the enhanced native uninstaller command
            string cmd = program.UninstallString.Trim();
            if (string.IsNullOrWhiteSpace(cmd))
                cmd = program.QuietUninstallString.Trim();

            if (!string.IsNullOrWhiteSpace(cmd))
            {
                var (fileName, arguments) = ParseAndEnhanceUninstallCommand(cmd, isEdgeApp, isEdgeWebView);

                // If Microsoft Edge's setup.exe path in Registry points to an older version folder, locate latest setup.exe
                if ((isEdgeApp || isEdgeWebView) && !File.Exists(fileName))
                {
                    string? latestSetup = FindLatestChromiumSetupExe(program.InstallLocation, isEdgeWebView);
                    if (!string.IsNullOrWhiteSpace(latestSetup))
                        fileName = latestSetup;
                }

                if (!string.IsNullOrWhiteSpace(fileName))
                {
                    progress?.Report(isEn
                        ? $"Running uninstaller for '{program.Name}'..."
                        : $"Menjalankan uninstaller untuk '{program.Name}'...");

                    try
                    {
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = fileName,
                            Arguments = arguments,
                            UseShellExecute = true
                        };

                        using var uninstallProc = Process.Start(startInfo);
                        if (uninstallProc != null)
                        {
                            await uninstallProc.WaitForExitAsync();
                        }
                    }
                    catch
                    {
                        // Proceed to post-check & Force Removal fallback below
                    }
                }
            }

            // Step 4: Post-Uninstall Verification & Force Removal Fallback
            // Many protected apps (like Microsoft Edge outside EEA regions) exit setup.exe with code 19 without removing files/Registry.
            bool stillInstalled = IsProgramStillPresent(program, isEdgeApp, isEdgeWebView);
            if (stillInstalled && allowForceFallback)
            {
                progress?.Report(isEn
                    ? $"Native uninstaller was blocked or incomplete. Executing Force Uninstall for '{program.Name}'..."
                    : $"Uninstaller bawaan ditolak/tidak tuntas. Menjalankan Force Uninstall untuk '{program.Name}'...");

                await ExecuteForceUninstallFallbackAsync(program, isEdgeApp, isEdgeWebView, isOneDrive);
            }
            else if (isOneDrive)
            {
                CleanOneDriveExplorerPin();
            }

            return !IsProgramStillPresent(program, isEdgeApp, isEdgeWebView);
        });
    }

    private static (string FileName, string Arguments) ParseAndEnhanceUninstallCommand(
        string cmd,
        bool isEdgeApp,
        bool isEdgeWebView)
    {
        string fileName;
        string arguments = string.Empty;

        if (cmd.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
        {
            var guidMatch = MsiGuidRegex.Match(cmd);
            fileName = "msiexec.exe";
            arguments = guidMatch.Success ? $"/X{guidMatch.Value}" : cmd;
        }
        else if (cmd.StartsWith('"'))
        {
            int endQuote = cmd.IndexOf('"', 1);
            if (endQuote > 1)
            {
                fileName = cmd[1..endQuote];
                arguments = cmd[(endQuote + 1)..].Trim();
            }
            else
            {
                fileName = cmd.Trim('"');
            }
        }
        else
        {
            string? extracted = ExtractFilePathFromCommand(cmd);
            if (!string.IsNullOrWhiteSpace(extracted) && cmd.StartsWith(extracted, StringComparison.OrdinalIgnoreCase))
            {
                fileName = extracted;
                arguments = cmd[extracted.Length..].Trim();
            }
            else
            {
                int firstSpace = cmd.IndexOf(' ');
                if (firstSpace > 0)
                {
                    fileName = cmd[..firstSpace];
                    arguments = cmd[(firstSpace + 1)..].Trim();
                }
                else
                {
                    fileName = cmd;
                }
            }
        }

        fileName = Environment.ExpandEnvironmentVariables(fileName);
        arguments = Environment.ExpandEnvironmentVariables(arguments);

        // Append --force-uninstall for Chromium / Microsoft Edge / WebView2 setup.exe installers
        if ((isEdgeApp || isEdgeWebView || fileName.EndsWith(@"\Installer\setup.exe", StringComparison.OrdinalIgnoreCase)) &&
            !arguments.Contains("--force-uninstall", StringComparison.OrdinalIgnoreCase))
        {
            arguments = $"{arguments} --force-uninstall".Trim();
        }

        return (fileName, arguments);
    }

    private static string? FindLatestChromiumSetupExe(string installLocation, bool isWebView)
    {
        try
        {
            string baseDir = !string.IsNullOrWhiteSpace(installLocation) && Directory.Exists(installLocation)
                ? installLocation
                : Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft",
                    isWebView ? @"EdgeWebView\Application" : @"Edge\Application");

            if (!Directory.Exists(baseDir))
                return null;

            return Directory.EnumerateFiles(baseDir, "setup.exe", SearchOption.AllDirectories)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    private static void TerminateLockingProcesses(
        InstalledProgramItem program,
        bool isEdgeApp,
        bool isEdgeWebView,
        bool isOneDrive)
    {
        var targetProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (isEdgeApp)
        {
            targetProcessNames.Add("msedge");
            targetProcessNames.Add("MicrosoftEdgeUpdate");
            targetProcessNames.Add("identity_helper");
            targetProcessNames.Add("elevation_service");
            targetProcessNames.Add("pwahelper");
        }

        if (isEdgeWebView)
        {
            targetProcessNames.Add("msedgewebview2");
            targetProcessNames.Add("MicrosoftEdgeUpdate");
        }

        if (isOneDrive)
        {
            targetProcessNames.Add("OneDrive");
            targetProcessNames.Add("OneDriveSetup");
            targetProcessNames.Add("FileCoAuth");
        }

        foreach (var procName in targetProcessNames)
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(procName))
                {
                    try { p.Kill(entireProcessTree: true); p.WaitForExit(1500); } catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }

        // Also kill any process running from inside the program's InstallLocation
        if (!string.IsNullOrWhiteSpace(program.InstallLocation) &&
            Directory.Exists(program.InstallLocation) &&
            !IsSystemOrInstallerDirectory(program.InstallLocation))
        {
            try
            {
                int currentPid = Environment.ProcessId;
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        if (p.Id == currentPid) continue;
                        string? mainMod = p.MainModule?.FileName;
                        if (!string.IsNullOrWhiteSpace(mainMod) &&
                            mainMod.StartsWith(program.InstallLocation, StringComparison.OrdinalIgnoreCase))
                        {
                            p.Kill(entireProcessTree: true);
                            p.WaitForExit(1500);
                        }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }
    }

    private static void UnlockProtectedUninstallRegistry(
        InstalledProgramItem program,
        bool isEdgeApp,
        bool isEdgeWebView)
    {
        // 1. Remove NoRemove / NoModify on the program's Uninstall key
        try
        {
            var (hive, view, subKeyPath) = ParseRegistryKeyPath(program.RegistryKeyPath);
            if (subKeyPath != null)
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var appKey = baseKey.OpenSubKey(subKeyPath, writable: true);
                if (appKey != null)
                {
                    appKey.DeleteValue("NoRemove", throwOnMissingValue: false);
                    appKey.DeleteValue("NoModify", throwOnMissingValue: false);
                    appKey.DeleteValue("SystemComponent", throwOnMissingValue: false);
                }
            }
        }
        catch { }

        if (!isEdgeApp && !isEdgeWebView)
            return;

        // 2. Unlock EdgeUpdateDev AllowUninstall = 1 & remove experiment_control_labels
        foreach (var view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using (var devKey = hklm.CreateSubKey(@"SOFTWARE\Microsoft\EdgeUpdateDev", writable: true))
                {
                    devKey?.SetValue("AllowUninstall", 1, RegistryValueKind.DWord);
                }

                // Clear experiment_control_labels that block uninstallation on modern Edge versions
                string[] edgeGuids =
                [
                    "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}", // Microsoft Edge Stable
                    "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"  // Microsoft Edge WebView2
                ];

                foreach (var guid in edgeGuids)
                {
                    using var clientState = hklm.OpenSubKey($@"SOFTWARE\Microsoft\EdgeUpdate\ClientState\{guid}", writable: true);
                    clientState?.DeleteValue("experiment_control_labels", throwOnMissingValue: false);
                    clientState?.SetValue("AllowUninstall", 1, RegistryValueKind.DWord);

                    using var clients = hklm.OpenSubKey($@"SOFTWARE\Microsoft\EdgeUpdate\Clients\{guid}", writable: true);
                    clients?.DeleteValue("NoRemove", throwOnMissingValue: false);
                }

                // Prevent Windows Update from forcibly reinstalling Edge
                using (var edgeUpdateKey = hklm.CreateSubKey(@"SOFTWARE\Microsoft\EdgeUpdate", writable: true))
                {
                    edgeUpdateKey?.SetValue("DoNotUpdateToEdgeWithChromium", 1, RegistryValueKind.DWord);
                }
            }
            catch { }
        }

        // 3. Unlock IntegratedServicesRegionPolicySet.json policy {1d290564-964a-4c1e-823d-278610c84b68} if running as Admin
        try
        {
            string policyFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "IntegratedServicesRegionPolicySet.json");
            if (File.Exists(policyFile))
            {
                RunHiddenCommand("takeown.exe", $"/F \"{policyFile}\" /A");
                RunHiddenCommand("icacls.exe", $"\"{policyFile}\" /grant *S-1-5-32-544:F");

                string json = File.ReadAllText(policyFile);
                // Enable Edge uninstall policy across all regions
                string updated = Regex.Replace(
                    json,
                    @"(""1d290564-964a-4c1e-823d-278610c84b68""[\s\S]{1,350}?""defaultState""\s*:\s*"")disabled("")",
                    "${1}enabled${2}",
                    RegexOptions.IgnoreCase);

                if (!string.Equals(json, updated, StringComparison.Ordinal))
                {
                    File.WriteAllText(policyFile, updated);
                }
            }
        }
        catch { }
    }

    private static bool IsProgramStillPresent(
        InstalledProgramItem program,
        bool isEdgeApp,
        bool isEdgeWebView)
    {
        if (isEdgeApp)
        {
            string edgeExe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                @"Microsoft\Edge\Application\msedge.exe");
            if (File.Exists(edgeExe))
                return true;
        }

        if (isEdgeWebView)
        {
            string webViewDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                @"Microsoft\EdgeWebView\Application");
            if (Directory.Exists(webViewDir) && Directory.EnumerateFiles(webViewDir, "msedgewebview2.exe", SearchOption.AllDirectories).Any())
                return true;
        }

        // Check if Registry Uninstall key still exists
        try
        {
            var (hive, view, subKeyPath) = ParseRegistryKeyPath(program.RegistryKeyPath);
            if (subKeyPath != null)
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var appKey = baseKey.OpenSubKey(subKeyPath);
                if (appKey != null)
                    return true;
            }
        }
        catch { }

        return false;
    }

    private static async Task ExecuteForceUninstallFallbackAsync(
        InstalledProgramItem program,
        bool isEdgeApp,
        bool isEdgeWebView,
        bool isOneDrive)
    {
        // 1. Export Registry Backup (.reg) before forced removal
        BackupUninstallRegistryKey(program.RegistryKeyPath, program.Name);

        // 2. Kill processes again in case setup.exe respawned them
        TerminateLockingProcesses(program, isEdgeApp, isEdgeWebView, isOneDrive);

        // 3. Special complete teardown for Microsoft Edge / EdgeWebView2
        if (isEdgeApp)
        {
            // Stop & delete Edge Updater services
            foreach (var svc in new[] { "edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService" })
            {
                RunHiddenCommand("sc.exe", $"stop \"{svc}\"");
                RunHiddenCommand("sc.exe", $"delete \"{svc}\"");
            }

            // Delete Edge Scheduled Tasks
            RunHiddenCommand("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"Get-ScheduledTask -TaskName 'MicrosoftEdgeUpdate*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue\"");

            // Remove Microsoft Edge AppX / Store stub packages
            await UninstallWindowsStorePackageForcefullyAsync("*MicrosoftEdge*");

            // Force delete Edge directories in Program Files (x86)\Microsoft
            string msRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft");
            string[] edgeDirs = isEdgeWebView
                ? [Path.Combine(msRoot, "EdgeWebView")]
                : [
                    Path.Combine(msRoot, "Edge"),
                    Path.Combine(msRoot, "EdgeCore"),
                    Path.Combine(msRoot, "EdgeUpdate"),
                    Path.Combine(msRoot, "Temp")
                  ];

            foreach (var dir in edgeDirs)
            {
                ForceDeleteDirectoryWithTakeOwn(dir);
            }

            // Clean Edge ClientState & Clients keys so Windows doesn't think Edge is still installed
            foreach (var view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
            {
                try
                {
                    using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    hklm.DeleteSubKeyTree(@"SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}", throwOnMissingSubKey: false);
                    hklm.DeleteSubKeyTree(@"SOFTWARE\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}", throwOnMissingSubKey: false);
                    hklm.DeleteSubKeyTree(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe", throwOnMissingSubKey: false);
                }
                catch { }
            }
        }
        else if (isEdgeWebView)
        {
            string msRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft");
            ForceDeleteDirectoryWithTakeOwn(Path.Combine(msRoot, "EdgeWebView"));

            foreach (var view in new[] { RegistryView.Registry32, RegistryView.Registry64 })
            {
                try
                {
                    using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                    hklm.DeleteSubKeyTree(@"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", throwOnMissingSubKey: false);
                    hklm.DeleteSubKeyTree(@"SOFTWARE\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", throwOnMissingSubKey: false);
                }
                catch { }
            }
        }
        else
        {
            // Generic Force Uninstall for any stubborn Win32 application:
            // Remove its InstallLocation directory (if safe and not a root system directory)
            if (!string.IsNullOrWhiteSpace(program.InstallLocation) &&
                Directory.Exists(program.InstallLocation) &&
                !IsSystemOrInstallerDirectory(program.InstallLocation))
            {
                ForceDeleteDirectoryWithTakeOwn(program.InstallLocation);
            }
        }

        if (isOneDrive)
        {
            CleanOneDriveExplorerPin();
        }

        // 4. Delete the program's Uninstall Registry Key so it is removed from Installed Programs
        DeleteUninstallRegistryKey(program.RegistryKeyPath);
    }

    private static async Task<bool> UninstallWindowsStorePackageForcefullyAsync(string packageNameOrPattern)
    {
        // Unlock InboxApplications in HKLM so NonRemovable / System UWP packages (0x80073CFA) can be removed
        string psScript = $@"
$ErrorActionPreference = 'SilentlyContinue'
$pkgs = Get-AppxPackage -AllUsers | Where-Object {{ $_.PackageFullName -like '{packageNameOrPattern}' -or $_.Name -like '{packageNameOrPattern}' }}
if (-not $pkgs) {{
    $pkgs = Get-AppxPackage | Where-Object {{ $_.PackageFullName -like '{packageNameOrPattern}' -or $_.Name -like '{packageNameOrPattern}' }}
}}
foreach ($p in $pkgs) {{
    $inboxPath = ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\$($p.PackageFullName)""
    if (Test-Path $inboxPath) {{
        Remove-Item -Path $inboxPath -Recurse -Force -ErrorAction SilentlyContinue
    }}
    $deprovPath = ""HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\$($p.PackageFamilyName)""
    New-Item -Path $deprovPath -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-AppxPackage -Package $p.PackageFullName -ErrorAction SilentlyContinue
    Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue
}}
Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {{ $_.PackageName -like '{packageNameOrPattern}' -or $_.DisplayName -like '{packageNameOrPattern}' }} | ForEach-Object {{
    Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null
}}
";

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{psScript.Replace("\"", "\\\"")}\"",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        if (proc != null)
        {
            await proc.WaitForExitAsync();
            return true;
        }
        return false;
    }

    private static void CleanOneDriveExplorerPin()
    {
        try
        {
            using var hkcu = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}", writable: true);
            hkcu?.SetValue("System.IsPinnedToNameSpaceTree", 0, RegistryValueKind.DWord);
        }
        catch { }
    }

    private static void BackupUninstallRegistryKey(string registryKeyPath, string appName)
    {
        if (string.IsNullOrWhiteSpace(registryKeyPath))
            return;

        try
        {
            string backupDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "cleaNclean",
                "Backups");
            Directory.CreateDirectory(backupDir);

            string safeName = Regex.Replace(appName, @"[^\w\-]", "_");
            string outFile = Path.Combine(backupDir, $"UninstallKey_{safeName}_{DateTime.Now:yyyyMMdd_HHmmss}.reg");
            RunHiddenCommand("reg.exe", $"export \"{registryKeyPath}\" \"{outFile}\" /y");
        }
        catch { }
    }

    private static void DeleteUninstallRegistryKey(string registryKeyPath)
    {
        var (hive, view, subKeyPath) = ParseRegistryKeyPath(registryKeyPath);
        if (subKeyPath == null) return;

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            baseKey.DeleteSubKeyTree(subKeyPath, throwOnMissingSubKey: false);
        }
        catch
        {
            // Fallback via reg.exe with explicit 32/64 view
            string regViewFlag = view == RegistryView.Registry32 ? "/reg:32" : "/reg:64";
            RunHiddenCommand("reg.exe", $"delete \"{registryKeyPath}\" /f {regViewFlag}");
        }
    }

    private static (RegistryHive Hive, RegistryView View, string? SubKeyPath) ParseRegistryKeyPath(string registryKeyPath)
    {
        if (string.IsNullOrWhiteSpace(registryKeyPath))
            return (RegistryHive.LocalMachine, RegistryView.Default, null);

        if (registryKeyPath.StartsWith(@"HKLM\SOFTWARE\WOW6432Node\", StringComparison.OrdinalIgnoreCase))
        {
            return (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\" + registryKeyPath[@"HKLM\SOFTWARE\WOW6432Node\".Length..]);
        }
        if (registryKeyPath.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
        {
            return (RegistryHive.LocalMachine, RegistryView.Registry64, registryKeyPath[5..]);
        }
        if (registryKeyPath.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase))
        {
            return (RegistryHive.CurrentUser, RegistryView.Default, registryKeyPath[5..]);
        }

        return (RegistryHive.LocalMachine, RegistryView.Default, null);
    }

    private static void ForceDeleteDirectoryWithTakeOwn(string dirPath)
    {
        if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath) || IsSystemOrInstallerDirectory(dirPath))
            return;

        try
        {
            Directory.Delete(dirPath, recursive: true);
            if (!Directory.Exists(dirPath))
                return;
        }
        catch { }

        // Take ownership & grant Administrators full control if locked by TrustedInstaller / SYSTEM
        RunHiddenCommand("takeown.exe", $"/F \"{dirPath}\" /R /A /D Y");
        RunHiddenCommand("icacls.exe", $"\"{dirPath}\" /grant *S-1-5-32-544:F /T /C /Q");
        RunHiddenCommand("cmd.exe", $"/c rmdir /s /q \"{dirPath}\"");
    }

    private static void RunHiddenCommand(string fileName, string arguments)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
            proc?.WaitForExit(15000);
        }
        catch { }
    }

    /// <summary>
    /// Opens Regedit directly at the specified Registry Key path (just like Revo Uninstaller's "Open Registry Key").
    /// </summary>
    public static void OpenRegistryKeyInRegedit(string registryKeyPath)
    {
        if (string.IsNullOrWhiteSpace(registryKeyPath))
            return;

        string expandedKey = registryKeyPath;
        if (expandedKey.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
            expandedKey = @"HKEY_LOCAL_MACHINE\" + expandedKey[5..];
        else if (expandedKey.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase))
            expandedKey = @"HKEY_CURRENT_USER\" + expandedKey[5..];

        try
        {
            using var regeditKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
            regeditKey?.SetValue("LastKey", @"Computer\" + expandedKey, RegistryValueKind.String);

            Process.Start(new ProcessStartInfo
            {
                FileName = "regedit.exe",
                Arguments = "-m",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Gagal membuka Registry Editor: {ex.Message}", "cleaNclean", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
