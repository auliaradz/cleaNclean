using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using cleaNclean.Models;
using Microsoft.Win32;

namespace cleaNclean.Services;

public class InstalledAppsIndexer
{
    public List<InstalledAppEntry> InstalledApps { get; } = [];
    public HashSet<string> ActiveNormalizedNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ActiveAlphaRoots { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ActiveWords { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ActiveInstallDirectories { get; } = new(StringComparer.OrdinalIgnoreCase);

    // Crucial Windows, System, Runtime, DevTools, and Hardware vendor directories/keys that should never be flagged in automatic orphan mode
    private static readonly HashSet<string> SystemWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Windows", "Microsoft Corporation", "Package Cache", "Packages",
        "Temp", "Tmp", "ConnectedDevicesPlatform", "Comms", "D3DSCache", "Diagnostics",
        "ElevatedDiagnostics", "FontCache", "GDIPFONTCACHEV1.DAT", "History", "IconCache.db",
        "IdentityNexusIntegration", "InputMethod", "Intel", "AMD", "NVIDIA", "NVIDIA Corporation",
        "Realtek", "Dolby", "Synaptics", "ELAN", "ASUS", "Acer", "Lenovo", "HP", "Dell", "MSI",
        "Google", "Mozilla", "Apple", "Apple Computer", "Adobe", "Valve", "Steam",
        "PlaceholderTileLogoFolder", "Publishers", "Programs",
        "Application Data", "Start Menu", "Desktop", "Templates", "Themes", "ToastNotificationManagerCompat",
        "UnrealEngine", "Unreal Engine", "Unity", "CrashDumps", "CrashReportClient", "CrashRpt", "cef_cache", "cache",
        "pip", "npm", "npm-cache", "NuGet", "yarn", "uv", "pypa", "Python", "Go-build",
        "dotnet", "ASP.NET", "GitHub", "Git", "VSCode", "Code", "Cursor", "Antigravity", "Antigravity IDE", "agy", "Gemini",
        "SystemCertificates", "VirtualStore", "WindowsApps", "WinGet",
        "SquirrelTemp", "CEF", "WebView2", "EBWebView", "PeerDistRepub",
        "Classes", "Clients", "Policies", "RegisteredApplications", "WOW6432Node", "Default",
        "Direct3D", "DirectInput", "DirectShow", "DirectSound", "ODBC", "OpenSSH", "Partner",
        "Chronicle", "Chromium", "BraveSoftware", "Opera Software", "Vivaldi",
        "SSH", "Subversion", "TortoiseGit", "JetBrains", "Android", "GoogleCloud", "gcloud", "cloud-code",
        "OEM", "USOPrivate", "USOShared", "SoftwareDistribution", "regid.1991-06.com.microsoft",
        "WindowsHolographicDevices", "Windows Defender", "Windows Security", "Windows NT",
        "OneDrive", "wsl", "fontconfig", "boost_interprocess", "Sentry", "electron",
        "EasyAntiCheat", "BattlEye", "SafeNet Sentinel", "FLEXlm", "shimgen", "chocolatey", "ChocolateyHttpCache",
        "Pub", "R", "CMakeTools", "Visual Studio Setup", "DBG", "DMCache", "Whesvc",
        "MSBuild", "Windows Sidebar", "Windows Mail", "Windows Media Player", "Windows Photo Viewer",
        "Windows Portable Devices", "Reference Assemblies", "ModifiableWindowsApps", "Common Files",
        "Internet Explorer", "Uninstall Information", "IM Providers", "Khronos", "Netscape", "Wine",
        "firebase", "kotlin", "seaborn", "Ultralytics", "create-next-app-nodejs", "nextjs-nodejs"
    };

    // Generic words that should NOT be used alone as a single-word match to prevent false matches
    private static readonly HashSet<string> GenericStopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "application", "applications", "program", "programs", "software", "technologies", "technology",
        "corporation", "company", "international", "enterprise", "solutions", "systems", "system",
        "windows", "microsoft", "desktop", "launcher", "client", "server", "service", "services",
        "manager", "management", "studio", "player", "viewer", "editor", "reader", "writer",
        "helper", "updater", "update", "installer", "install", "uninstall", "uninstaller", "setup",
        "driver", "drivers", "engine", "runtime", "framework", "library", "common", "shared",
        "tools", "tool", "utility", "utilities", "center", "control", "console", "assistant",
        "agent", "daemon", "monitor", "network", "security", "support", "online", "digital",
        "gaming", "games", "game", "interactive", "entertainment", "media", "video", "audio",
        "edition", "version", "release", "stable", "standard", "starter", "express", "community",
        "professional", "ultimate", "premium", "official", "portable", "native", "local", "roaming",
        "package", "packages", "plugin", "plugins", "extension", "extensions", "addon", "addons"
    };

    private static readonly HashSet<string> CustomUserWhitelist = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _whitelistFilePath;

    public InstalledAppsIndexer()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appDir = Path.Combine(appData, "cleaNclean");
        Directory.CreateDirectory(appDir);
        _whitelistFilePath = Path.Combine(appDir, "whitelist.txt");
        LoadUserWhitelist();
    }

    public void AddToUserWhitelist(string itemNameOrPath)
    {
        if (string.IsNullOrWhiteSpace(itemNameOrPath)) return;
        CustomUserWhitelist.Add(itemNameOrPath.Trim());
        CustomUserWhitelist.Add(NormalizeToken(itemNameOrPath));
        try
        {
            File.WriteAllLines(_whitelistFilePath, CustomUserWhitelist);
        }
        catch { }
    }

    private void LoadUserWhitelist()
    {
        try
        {
            if (File.Exists(_whitelistFilePath))
            {
                foreach (var line in File.ReadAllLines(_whitelistFilePath))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        CustomUserWhitelist.Add(line.Trim());
                }
            }
        }
        catch { }
    }

    public Task BuildIndexAsync(CancellationToken cancellationToken = default)
    {
        return Task.Run(() =>
        {
            InstalledApps.Clear();
            ActiveNormalizedNames.Clear();
            ActiveAlphaRoots.Clear();
            ActiveWords.Clear();
            ActiveInstallDirectories.Clear();

            foreach (var item in SystemWhitelist)
            {
                RegisterAppToken(item);
            }

            // 1. Scan Registry Uninstall keys (64-bit, 32-bit, Current User)
            ScanUninstallRegistry(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", cancellationToken);
            ScanUninstallRegistry(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", cancellationToken);
            ScanUninstallRegistry(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", cancellationToken);

            // 2. Scan AppX / MSIX / Windows Store Packages
            ScanAppxPackages(cancellationToken);

            // 3. Scan VALID Shortcuts (.lnk) in Start Menu & Desktop whose target still exists on disk!
            // This catches bundled apps like pgAdmin 4 (inside PostgreSQL), portable apps with shortcuts, etc.
            ScanValidShortcutsForInstalledApps(cancellationToken);

            // 4. Scan Program Files, LocalAppData\Programs, and Game/App folders across ALL fixed drives (C:\, D:\, etc.)
            ScanAllFixedDrivesProgramAndGameDirectories(cancellationToken);

            // 5. Scan currently running processes
            ScanRunningProcesses();
        }, cancellationToken);
    }

    private void ScanUninstallRegistry(RegistryKey root, string subKeyPath, CancellationToken ct)
    {
        try
        {
            using var uninstallKey = root.OpenSubKey(subKeyPath);
            if (uninstallKey == null) return;

            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var appKey = uninstallKey.OpenSubKey(subKeyName);
                    if (appKey == null) continue;

                    string displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                    string publisher = appKey.GetValue("Publisher")?.ToString() ?? string.Empty;
                    string installLocation = appKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                    string uninstallString = appKey.GetValue("UninstallString")?.ToString() ?? string.Empty;
                    string displayIcon = appKey.GetValue("DisplayIcon")?.ToString() ?? string.Empty;

                    if (!subKeyName.StartsWith('{'))
                    {
                        RegisterAppToken(subKeyName);
                    }

                    if (!string.IsNullOrWhiteSpace(displayName))
                        RegisterAppToken(displayName);

                    if (!string.IsNullOrWhiteSpace(publisher))
                        RegisterAppToken(publisher);

                    if (!string.IsNullOrWhiteSpace(installLocation))
                        RegisterInstallPath(installLocation);

                    // Extract existing folder/exe path from DisplayIcon and UninstallString when InstallLocation is empty
                    RegisterPathFromCommandString(displayIcon);
                    RegisterPathFromCommandString(uninstallString);

                    if (!string.IsNullOrWhiteSpace(displayName) || !string.IsNullOrWhiteSpace(publisher))
                    {
                        InstalledApps.Add(new InstalledAppEntry
                        {
                            DisplayName = displayName,
                            Publisher = publisher,
                            InstallLocation = installLocation,
                            UninstallString = uninstallString
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanValidShortcutsForInstalledApps(CancellationToken ct)
    {
        string[] shortcutRoots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)
        ];

        foreach (var root in shortcutRoots)
        {
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root)) continue;

            IEnumerable<string> lnkFiles;
            try
            {
                lnkFiles = Directory.EnumerateFiles(root, "*.lnk", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var lnk in lnkFiles)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string? target = ShortcutScanner.ResolveShortcutTarget(lnk);
                    if (string.IsNullOrWhiteSpace(target)) continue;

                    // If the target executable or directory STILL EXISTS on disk, this shortcut belongs to an active installed app!
                    if (File.Exists(target) || Directory.Exists(target))
                    {
                        string shortcutName = Path.GetFileNameWithoutExtension(lnk);
                        RegisterAppToken(shortcutName);

                        // Also register the Start Menu parent folder name if not "Programs" or "Start Menu"
                        string? parentFolder = Path.GetFileName(Path.GetDirectoryName(lnk));
                        if (!string.IsNullOrWhiteSpace(parentFolder) &&
                            !parentFolder.Equals("Programs", StringComparison.OrdinalIgnoreCase) &&
                            !parentFolder.Equals("Start Menu", StringComparison.OrdinalIgnoreCase) &&
                            !parentFolder.Equals("Desktop", StringComparison.OrdinalIgnoreCase))
                        {
                            RegisterAppToken(parentFolder);
                        }

                        if (File.Exists(target))
                        {
                            string exeName = Path.GetFileNameWithoutExtension(target);
                            RegisterAppToken(exeName);
                            RegisterInstallPath(Path.GetDirectoryName(target) ?? string.Empty);
                            RegisterExeVersionInfo(target);
                        }
                    }
                }
                catch { }
            }
        }
    }

    private void ScanAllFixedDrivesProgramAndGameDirectories(CancellationToken ct)
    {
        var candidateRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs")
        };

        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed))
            {
                string root = drive.RootDirectory.FullName;
                candidateRoots.Add(Path.Combine(root, "Program Files"));
                candidateRoots.Add(Path.Combine(root, "Program Files (x86)"));
                candidateRoots.Add(Path.Combine(root, "Games"));
                candidateRoots.Add(Path.Combine(root, "GOG Games"));
                candidateRoots.Add(Path.Combine(root, "XboxGames"));
                candidateRoots.Add(Path.Combine(root, "SteamLibrary", "steamapps", "common"));
                candidateRoots.Add(Path.Combine(root, "Program Files (x86)", "Steam", "steamapps", "common"));
                candidateRoots.Add(Path.Combine(root, "Program Files", "Epic Games"));
                candidateRoots.Add(Path.Combine(root, "Download"));
            }
        }
        catch { }

        foreach (var baseDir in candidateRoots.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            bool isDownloadFolder = baseDir.EndsWith("Download", StringComparison.OrdinalIgnoreCase);
            ScanProgramDirectoryTree(baseDir, maxDepth: isDownloadFolder ? 1 : 3, ct);
        }
    }

    private void ScanProgramDirectoryTree(string basePath, int maxDepth, CancellationToken ct)
    {
        try
        {
            foreach (var dir1 in Directory.GetDirectories(basePath))
            {
                ct.ThrowIfCancellationRequested();
                string name1 = Path.GetFileName(dir1);

                if (!ContainsExecutablesOrBinaries(dir1))
                    continue;

                ActiveInstallDirectories.Add(dir1);
                RegisterAppToken(name1);
                InspectTopExecutablesForMetadata(dir1);

                if (maxDepth < 2) continue;

                // Level 2 (e.g., C:\Program Files\PostgreSQL\18 or C:\Program Files\Vendor\AppName)
                try
                {
                    foreach (var dir2 in Directory.GetDirectories(dir1))
                    {
                        string name2 = Path.GetFileName(dir2);
                        if (!IsGenericSubfolderName(name2))
                        {
                            RegisterAppToken(name2);
                            InspectTopExecutablesForMetadata(dir2);
                        }

                        if (maxDepth < 3) continue;

                        // Level 3 (e.g., C:\Program Files\PostgreSQL\18\pgAdmin 4)
                        try
                        {
                            foreach (var dir3 in Directory.GetDirectories(dir2))
                            {
                                string name3 = Path.GetFileName(dir3);
                                if (!IsGenericSubfolderName(name3))
                                {
                                    RegisterAppToken(name3);
                                    InspectTopExecutablesForMetadata(dir3);
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void InspectTopExecutablesForMetadata(string dirPath)
    {
        try
        {
            foreach (var exe in Directory.EnumerateFiles(dirPath, "*.exe", SearchOption.TopDirectoryOnly).Take(5))
            {
                string exeName = Path.GetFileNameWithoutExtension(exe);
                if (!exeName.Contains("unins", StringComparison.OrdinalIgnoreCase) &&
                    !exeName.Contains("setup", StringComparison.OrdinalIgnoreCase) &&
                    !exeName.Contains("crash", StringComparison.OrdinalIgnoreCase))
                {
                    RegisterAppToken(exeName);
                    RegisterExeVersionInfo(exe);
                }
            }
        }
        catch { }
    }

    private void RegisterExeVersionInfo(string exePath)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(exePath);
            if (!string.IsNullOrWhiteSpace(info.ProductName))
                RegisterAppToken(info.ProductName);
            if (!string.IsNullOrWhiteSpace(info.CompanyName))
                RegisterAppToken(info.CompanyName);
        }
        catch { }
    }

    private static bool IsGenericSubfolderName(string name)
    {
        return name.Equals("bin", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("lib", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("include", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("share", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("doc", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("docs", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("resources", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("locales", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("plugins", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("data", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("common", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("runtime", StringComparison.OrdinalIgnoreCase) ||
               Regex.IsMatch(name, @"^\d+(\.\d+)*$");
    }

    private void ScanAppxPackages(CancellationToken ct)
    {
        try
        {
            using var appxKey = Registry.CurrentUser.OpenSubKey(@"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
            if (appxKey == null) return;

            foreach (var pkgName in appxKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                var parts = pkgName.Split('_');
                if (parts.Length > 0)
                {
                    RegisterAppToken(parts[0]);
                    foreach (var dotPart in parts[0].Split('.'))
                    {
                        RegisterAppToken(dotPart);
                    }
                }
            }
        }
        catch { }
    }

    private void ScanRunningProcesses()
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(proc.ProcessName))
                        RegisterAppToken(proc.ProcessName);
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch { }
    }

    public static bool ContainsExecutablesOrBinaries(string dirPath)
    {
        try
        {
            return Directory.EnumerateFiles(dirPath, "*.*", SearchOption.AllDirectories)
                .Take(250)
                .Any(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                          f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                          f.EndsWith(".msi", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return true;
        }
    }

    private void RegisterPathFromCommandString(string rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand)) return;

        try
        {
            // Strip icon index like ",0" or arguments
            var match = Regex.Match(rawCommand.Trim(), @"([a-zA-Z]:\\[^:*?""<>|,\r\n]+?\.(?:exe|ico|dll|msi))", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                string filePath = match.Groups[1].Value.Trim();
                if (File.Exists(filePath))
                {
                    string exeName = Path.GetFileNameWithoutExtension(filePath);
                    if (!exeName.Contains("unins", StringComparison.OrdinalIgnoreCase) &&
                        !exeName.Equals("msiexec", StringComparison.OrdinalIgnoreCase))
                    {
                        RegisterAppToken(exeName);
                    }

                    string? dir = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrWhiteSpace(dir))
                        RegisterInstallPath(dir);
                }
            }
        }
        catch { }
    }

    private void RegisterInstallPath(string path)
    {
        try
        {
            string cleanPath = path.Trim('"', ' ', '\'').TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (string.IsNullOrWhiteSpace(cleanPath) || !Directory.Exists(cleanPath)) return;

            ActiveInstallDirectories.Add(cleanPath);

            // Walk up the directory tree up to Program Files / root to register vendor & app folder names
            DirectoryInfo? current = new DirectoryInfo(cleanPath);
            int depth = 0;
            while (current != null && current.Parent != null && depth < 4)
            {
                if (current.Name.Equals("Program Files", StringComparison.OrdinalIgnoreCase) ||
                    current.Name.Equals("Program Files (x86)", StringComparison.OrdinalIgnoreCase) ||
                    current.Name.Equals("Programs", StringComparison.OrdinalIgnoreCase) ||
                    current.Name.Equals("Common Files", StringComparison.OrdinalIgnoreCase) ||
                    current.Name.Equals("common", StringComparison.OrdinalIgnoreCase) ||
                    current.Name.Equals("steamapps", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }

                if (!IsGenericSubfolderName(current.Name))
                {
                    RegisterAppToken(current.Name);
                }

                current = current.Parent;
                depth++;
            }
        }
        catch { }
    }

    private void RegisterAppToken(string rawText)
    {
        if (string.IsNullOrWhiteSpace(rawText)) return;

        string fullNormalized = NormalizeToken(rawText);
        if (fullNormalized.Length >= 2)
        {
            ActiveNormalizedNames.Add(fullNormalized);
        }

        // Also register pure alphabetic root of the full name (e.g., "pgAdmin 4" -> "pgadmin", "WizTree3" -> "wiztree")
        string fullAlphaRoot = NormalizeAlphaOnly(rawText);
        if (fullAlphaRoot.Length >= 3 && !GenericStopWords.Contains(fullAlphaRoot))
        {
            ActiveAlphaRoots.Add(fullAlphaRoot);
        }

        // Strip common suffixes/noise like version numbers, architectures, company suffixes
        string cleaned = StripNoiseAndVersions(rawText);
        string cleanedNorm = NormalizeToken(cleaned);
        if (cleanedNorm.Length >= 2)
        {
            ActiveNormalizedNames.Add(cleanedNorm);
        }

        string cleanedAlpha = NormalizeAlphaOnly(cleaned);
        if (cleanedAlpha.Length >= 3 && !GenericStopWords.Contains(cleanedAlpha))
        {
            ActiveAlphaRoots.Add(cleanedAlpha);
        }

        // Extract individual meaningful words (handling CamelCase, separators, and letter-digit boundaries)
        foreach (var word in ExtractMeaningfulTokens(cleaned))
        {
            ActiveWords.Add(word);
        }
    }

    private static string StripNoiseAndVersions(string input)
    {
        // Strip reverse-domain prefixes/suffixes like com., org., io., .desktop, -updater
        string s = Regex.Replace(input, @"^(com|org|net|io|ai|app)\.", "", RegexOptions.IgnoreCase);
        s = Regex.Replace(s, @"(\.desktop|-updater|_updater|-setup|\.setup|-launcher)$", "", RegexOptions.IgnoreCase);

        // Split Acronym+PascalCase (e.g. "SPSSInc" -> "SPSS Inc") and CamelCase ("DarkSouls" -> "Dark Souls") before stripping suffixes
        s = Regex.Replace(s, @"([A-Z]+)([A-Z][a-z])", "$1 $2");
        s = Regex.Replace(s, @"([a-z])([A-Z])", "$1 $2");

        // Strip version patterns, bitness, corporate suffixes
        s = Regex.Replace(s, @"\b(v?\d+(\.\d+)*|x64|x86|amd64|win64|win32|64-bit|32-bit|inc\.?|corp\.?|corporation|ltd\.?|llc|gmbh|ab|co\.?|ide)\b", " ", RegexOptions.IgnoreCase);
        return s.Trim();
    }

    private static IEnumerable<string> ExtractMeaningfulTokens(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) yield break;

        string s = Regex.Replace(text, @"([A-Z]+)([A-Z][a-z])", "$1 $2");
        string camelSplit = Regex.Replace(s, @"([a-z])([A-Z])", "$1 $2");
        // Insert spaces between letters and numbers (e.g. "Arduino15" -> "Arduino 15", "pgadmin4" -> "pgadmin 4")
        string digitSplit = Regex.Replace(camelSplit, @"([a-zA-Z])(\d)", "$1 $2");

        foreach (Match m in Regex.Matches(digitSplit, @"[A-Za-z]{4,}"))
        {
            string word = m.Value.ToLowerInvariant();
            if (!GenericStopWords.Contains(word))
            {
                yield return word;
            }
        }
    }

    public bool IsWhitelisted(string folderOrKeyName, string fullPath = "")
    {
        if (string.IsNullOrWhiteSpace(folderOrKeyName)) return true;

        if (SystemWhitelist.Contains(folderOrKeyName) ||
            CustomUserWhitelist.Contains(folderOrKeyName) ||
            (!string.IsNullOrEmpty(fullPath) && CustomUserWhitelist.Contains(fullPath)))
        {
            return true;
        }

        if (folderOrKeyName.StartsWith('{') || folderOrKeyName.StartsWith('.'))
            return true;

        string norm = NormalizeToken(folderOrKeyName);
        if (norm.Length < 3) return true;

        if (CustomUserWhitelist.Contains(norm))
            return true;

        return false;
    }

    public bool IsMatchedWithInstalledApp(string candidateName)
    {
        if (IsWhitelisted(candidateName)) return true;

        // 1. Direct normalized alphanumeric match (e.g. "pgAdmin 4" == "pgadmin4")
        string norm = NormalizeToken(candidateName);
        if (ActiveNormalizedNames.Contains(norm))
            return true;

        // 2. Cleaned candidate normalized match (strips com., -updater, version numbers, etc.)
        string cleanedCandidate = StripNoiseAndVersions(candidateName);
        string cleanedNorm = NormalizeToken(cleanedCandidate);
        if (cleanedNorm.Length >= 3 && (ActiveNormalizedNames.Contains(cleanedNorm) || ActiveAlphaRoots.Contains(cleanedNorm)))
            return true;

        // 3. Pure alphabetic root match (e.g. "Arduino15" -> "arduino", "pgadmin4" -> "pgadmin", "WizTree3" -> "wiztree")
        string alphaRoot = NormalizeAlphaOnly(cleanedCandidate);
        if (alphaRoot.Length >= 4 && (ActiveAlphaRoots.Contains(alphaRoot) || ActiveNormalizedNames.Contains(alphaRoot) || ActiveWords.Contains(alphaRoot)))
            return true;

        // 4. Substring containment against active normalized names & alpha roots (for >= 5 chars)
        if (alphaRoot.Length >= 5)
        {
            foreach (var active in ActiveAlphaRoots)
            {
                if (active.Length >= 5 &&
                    (active.Contains(alphaRoot, StringComparison.OrdinalIgnoreCase) ||
                     alphaRoot.Contains(active, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
        }

        // 5. Tokenized word matching (splits dots, hyphens, underscores, CamelCase, and trailing digits)
        foreach (var word in ExtractMeaningfulTokens(cleanedCandidate))
        {
            if (word.Length >= 4 &&
                (ActiveAlphaRoots.Contains(word) ||
                 ActiveNormalizedNames.Contains(word) ||
                 ActiveWords.Contains(word) ||
                 SystemWhitelist.Contains(word)))
            {
                return true;
            }
        }

        return false;
    }

    public static string NormalizeToken(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        return Regex.Replace(input, @"[^a-zA-Z0-9]", "").ToLowerInvariant();
    }

    public static string NormalizeAlphaOnly(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        return Regex.Replace(input, @"[^a-zA-Z]", "").ToLowerInvariant();
    }
}
