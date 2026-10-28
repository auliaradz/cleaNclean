using System.IO;
using cleaNclean.Models;

namespace cleaNclean.Services;

public class AppDataScanner(InstalledAppsIndexer indexer)
{
    public List<string> GetTargetBaseDirectories()
    {
        var dirs = new List<string>();

        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string localLow = Path.Combine(userProfile, "AppData", "LocalLow");

        if (Directory.Exists(local)) dirs.Add(local);
        if (Directory.Exists(roaming)) dirs.Add(roaming);
        if (Directory.Exists(localLow)) dirs.Add(localLow);
        if (Directory.Exists(programData)) dirs.Add(programData);

        return dirs;
    }

    public List<LeftoverItem> ScanOrphanedFolders(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        var baseDirs = GetTargetBaseDirectories();

        foreach (var baseDir in baseDirs)
        {
            ct.ThrowIfCancellationRequested();
            string baseLabel = GetFriendlyRootName(baseDir);
            progress?.Report($"Memindai folder {baseLabel}...");

            string[] topFolders;
            try
            {
                topFolders = Directory.GetDirectories(baseDir);
            }
            catch
            {
                continue;
            }

            foreach (var dirPath in topFolders)
            {
                ct.ThrowIfCancellationRequested();
                string folderName = Path.GetFileName(dirPath);

                // Never scan our own app folder
                if (folderName.Equals("cleaNclean", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (indexer.IsWhitelisted(folderName, dirPath))
                    continue;

                if (indexer.IsMatchedWithInstalledApp(folderName))
                    continue;

                // Check if any immediate subfolder inside this folder matches an installed app (e.g. AppData\Local\Vendor\InstalledApp)
                if (HasAnyMatchedSubdirectory(dirPath))
                    continue;

                // If folder still contains an active executable that is installed as a standalone portable app in AppData, check if it has an active .exe
                bool hasExecutable = ContainsActiveMainExe(dirPath);
                if (hasExecutable)
                    continue;

                long size = CalculateDirectorySizeSafe(dirPath, maxFilesToInspect: 2500);
                DateTime? lastMod = GetLastWriteTimeSafe(dirPath);

                results.Add(new LeftoverItem
                {
                    Name = folderName,
                    Category = LeftoverCategory.AppDataFolder,
                    Location = dirPath,
                    TargetInfo = $"Folder di {baseLabel}",
                    SizeInBytes = size,
                    ConfidenceLevel = "Tinggi (Orphaned)",
                    Reason = $"Tidak ditemukan aplikasi terinstal yang cocok dengan '{folderName}'",
                    LastModified = lastMod
                });
            }
        }

        // Also scan orphaned empty/leftover folders in Program Files & Program Files (x86) that no longer have any .exe/.dll
        ScanOrphanedProgramFilesFolders(results, progress, ct);

        return results;
    }

    private void ScanOrphanedProgramFilesFolders(List<LeftoverItem> results, IProgress<string>? progress, CancellationToken ct)
    {
        string[] pfRoots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        ];

        foreach (var pfRoot in pfRoots)
        {
            if (string.IsNullOrWhiteSpace(pfRoot) || !Directory.Exists(pfRoot)) continue;
            progress?.Report($"Memeriksa sisa folder di {Path.GetFileName(pfRoot)}...");

            try
            {
                foreach (var dirPath in Directory.GetDirectories(pfRoot))
                {
                    ct.ThrowIfCancellationRequested();
                    string folderName = Path.GetFileName(dirPath);

                    if (indexer.IsWhitelisted(folderName, dirPath))
                        continue;

                    // If a folder in Program Files has NO .exe, .dll, or .msi left, and is not matched with an installed app, it's a classic uninstall leftover
                    if (!InstalledAppsIndexer.ContainsExecutablesOrBinaries(dirPath) && !indexer.IsMatchedWithInstalledApp(folderName))
                    {
                        long size = CalculateDirectorySizeSafe(dirPath, maxFilesToInspect: 1500);
                        results.Add(new LeftoverItem
                        {
                            Name = folderName,
                            Category = LeftoverCategory.AppDataFolder,
                            Location = dirPath,
                            TargetInfo = $"Sisa folder instalasi ({Path.GetFileName(pfRoot)}) tanpa file .exe/.dll",
                            SizeInBytes = size,
                            ConfidenceLevel = "Tinggi (Tanpa Binary)",
                            Reason = "Folder di Program Files sudah tidak memiliki executable (.exe/.dll) maupun entri uninstaller",
                            LastModified = GetLastWriteTimeSafe(dirPath)
                        });
                    }
                }
            }
            catch { }
        }
    }

    public List<LeftoverItem> ScanByKeyword(string keyword, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        if (string.IsNullOrWhiteSpace(keyword) || keyword.Trim().Length < 2)
            return results;

        string kw = keyword.Trim();
        string normKw = InstalledAppsIndexer.NormalizeToken(kw);

        var searchRoots = GetTargetBaseDirectories();
        string pf64 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string localPrograms = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");

        if (Directory.Exists(pf64)) searchRoots.Add(pf64);
        if (Directory.Exists(pf86)) searchRoots.Add(pf86);
        if (Directory.Exists(localPrograms)) searchRoots.Add(localPrograms);

        var addedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            string friendlyRoot = GetFriendlyRootName(root);
            progress?.Report($"Mencari '{kw}' di {friendlyRoot}...");

            string[] level1Dirs;
            try
            {
                level1Dirs = Directory.GetDirectories(root);
            }
            catch
            {
                continue;
            }

            foreach (var dir1 in level1Dirs)
            {
                ct.ThrowIfCancellationRequested();
                string name1 = Path.GetFileName(dir1);
                if (name1.Equals("cleaNclean", StringComparison.OrdinalIgnoreCase)) continue;

                if (MatchesKeyword(name1, kw, normKw))
                {
                    if (addedPaths.Add(dir1))
                    {
                        bool isStillInstalled = indexer.IsMatchedWithInstalledApp(name1);
                        results.Add(new LeftoverItem
                        {
                            Name = name1,
                            Category = LeftoverCategory.AppDataFolder,
                            Location = dir1,
                            TargetInfo = friendlyRoot,
                            SizeInBytes = CalculateDirectorySizeSafe(dir1, 2500),
                            ConfidenceLevel = isStillInstalled ? "Perhatian (Mungkin Masih Terinstal)" : "Pencarian Manual",
                            Reason = $"Nama folder cocok dengan kata kunci '{kw}'",
                            LastModified = GetLastWriteTimeSafe(dir1),
                            IsSelected = !isStillInstalled
                        });
                    }
                    continue;
                }

                // Also inspect level-2 subdirectories (e.g., AppData\Local\VendorName\AppName)
                try
                {
                    foreach (var dir2 in Directory.GetDirectories(dir1))
                    {
                        string name2 = Path.GetFileName(dir2);
                        if (MatchesKeyword(name2, kw, normKw) && addedPaths.Add(dir2))
                        {
                            bool isStillInstalled = indexer.IsMatchedWithInstalledApp(name2);
                            results.Add(new LeftoverItem
                            {
                                Name = $"{name1}\\{name2}",
                                Category = LeftoverCategory.AppDataFolder,
                                Location = dir2,
                                TargetInfo = $"{friendlyRoot}\\{name1}",
                                SizeInBytes = CalculateDirectorySizeSafe(dir2, 2500),
                                ConfidenceLevel = isStillInstalled ? "Perhatian (Mungkin Masih Terinstal)" : "Pencarian Manual",
                                Reason = $"Subfolder cocok dengan kata kunci '{kw}'",
                                LastModified = GetLastWriteTimeSafe(dir2),
                                IsSelected = !isStillInstalled
                            });
                        }
                    }
                }
                catch { }
            }
        }

        return results;
    }

    private static bool MatchesKeyword(string candidate, string rawKeyword, string normKeyword)
    {
        if (candidate.Contains(rawKeyword, StringComparison.OrdinalIgnoreCase))
            return true;
        if (normKeyword.Length >= 3)
        {
            string normCand = InstalledAppsIndexer.NormalizeToken(candidate);
            if (normCand.Contains(normKeyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private bool HasAnyMatchedSubdirectory(string dirPath)
    {
        try
        {
            foreach (var subDir in Directory.EnumerateDirectories(dirPath).Take(30))
            {
                string subName = Path.GetFileName(subDir);
                if (subName.Length >= 3 && !IsGenericAppDataSubfolder(subName) && indexer.IsMatchedWithInstalledApp(subName))
                {
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    private static bool IsGenericAppDataSubfolder(string name)
    {
        return name.Equals("Cache", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Caches", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Code Cache", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("GPUCache", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("logs", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("log", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("config", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("data", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("User Data", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Local Storage", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Session Storage", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("blob_storage", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Network", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Temp", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Dictionaries", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Crashpad", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsActiveMainExe(string dirPath)
    {
        try
        {
            // Check top 2 levels for .exe files (excluding uninstallers or updater helpers)
            var topExes = Directory.EnumerateFiles(dirPath, "*.exe", SearchOption.TopDirectoryOnly).ToList();
            if (Directory.Exists(dirPath))
            {
                foreach (var sub in Directory.EnumerateDirectories(dirPath).Take(10))
                {
                    try
                    {
                        topExes.AddRange(Directory.EnumerateFiles(sub, "*.exe", SearchOption.TopDirectoryOnly));
                    }
                    catch { }
                }
            }

            return topExes.Any(exe =>
            {
                string fileName = Path.GetFileNameWithoutExtension(exe);
                return !fileName.Contains("unins", StringComparison.OrdinalIgnoreCase) &&
                       !fileName.Contains("crash", StringComparison.OrdinalIgnoreCase) &&
                       !fileName.Contains("helper", StringComparison.OrdinalIgnoreCase);
            });
        }
        catch
        {
            return false;
        }
    }

    public static long CalculateDirectorySizeSafe(string dirPath, int maxFilesToInspect = 2000)
    {
        long total = 0;
        int count = 0;
        var stack = new Stack<string>();
        stack.Push(dirPath);

        while (stack.Count > 0 && count < maxFilesToInspect)
        {
            string current = stack.Pop();
            try
            {
                foreach (var file in Directory.EnumerateFiles(current))
                {
                    try
                    {
                        total += new FileInfo(file).Length;
                        count++;
                        if (count >= maxFilesToInspect) break;
                    }
                    catch { }
                }

                foreach (var subDir in Directory.EnumerateDirectories(current))
                {
                    try
                    {
                        var attr = File.GetAttributes(subDir);
                        if ((attr & FileAttributes.ReparsePoint) == 0)
                        {
                            stack.Push(subDir);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        return total;
    }

    private static DateTime? GetLastWriteTimeSafe(string path)
    {
        try
        {
            return Directory.GetLastWriteTime(path);
        }
        catch
        {
            return null;
        }
    }

    private static string GetFriendlyRootName(string path)
    {
        if (path.EndsWith(@"AppData\Local", StringComparison.OrdinalIgnoreCase)) return @"AppData\Local";
        if (path.EndsWith(@"AppData\Roaming", StringComparison.OrdinalIgnoreCase)) return @"AppData\Roaming";
        if (path.EndsWith(@"AppData\LocalLow", StringComparison.OrdinalIgnoreCase)) return @"AppData\LocalLow";
        if (path.EndsWith(@"ProgramData", StringComparison.OrdinalIgnoreCase)) return @"ProgramData";
        return path;
    }
}
