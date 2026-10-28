using System.IO;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using cleaNclean.Models;
using Microsoft.Win32;

namespace cleaNclean.Services;

public class TaskSchedulerScanner(InstalledAppsIndexer indexer)
{
    public List<LeftoverItem> ScanOrphanedTasksAndStartup(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();

        progress?.Report("Memindai Windows Task Scheduler & Startup Registry...");
        ScanWindowsTasksFolder(keyword: null, results, ct);
        ScanStartupRegistryEntries(keyword: null, results, ct);

        return results;
    }

    public List<LeftoverItem> ScanByKeyword(string keyword, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        if (string.IsNullOrWhiteSpace(keyword) || keyword.Trim().Length < 2)
            return results;

        string kw = keyword.Trim();
        progress?.Report($"Mencari '{kw}' di Task Scheduler & Startup...");
        ScanWindowsTasksFolder(kw, results, ct);
        ScanStartupRegistryEntries(kw, results, ct);

        return results;
    }

    private void ScanWindowsTasksFolder(string? keyword, List<LeftoverItem> results, CancellationToken ct)
    {
        string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(tasksDir)) return;

        var stack = new Stack<string>();
        stack.Push(tasksDir);

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            string currentDir = stack.Pop();

            // Skip Microsoft system tasks folder in automatic mode
            string relativeDir = Path.GetRelativePath(tasksDir, currentDir);
            if (keyword == null && relativeDir.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase))
                continue;

            try
            {
                foreach (var subDir in Directory.GetDirectories(currentDir))
                {
                    stack.Push(subDir);
                }

                foreach (var taskFile in Directory.GetFiles(currentDir))
                {
                    ct.ThrowIfCancellationRequested();
                    InspectTaskXmlFile(tasksDir, taskFile, keyword, results);
                }
            }
            catch
            {
                // Ignore permission errors on protected system subtrees
            }
        }
    }

    private void InspectTaskXmlFile(string tasksRootDir, string taskFilePath, string? keyword, List<LeftoverItem> results)
    {
        try
        {
            string relativeTaskName = "\\" + Path.GetRelativePath(tasksRootDir, taskFilePath);
            string shortTaskName = Path.GetFileName(taskFilePath);

            XDocument doc = XDocument.Load(taskFilePath);
            XNamespace ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

            var commands = doc.Descendants(ns + "Command").Select(e => e.Value).ToList();
            var args = doc.Descendants(ns + "Arguments").Select(e => e.Value).ToList();

            string firstCommand = commands.FirstOrDefault() ?? string.Empty;
            string firstArgs = args.FirstOrDefault() ?? string.Empty;
            string? resolvedExe = ExtractTargetFilePath(firstCommand, firstArgs);

            if (keyword != null)
            {
                bool matches = relativeTaskName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                               firstCommand.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                               firstArgs.Contains(keyword, StringComparison.OrdinalIgnoreCase);

                if (matches)
                {
                    bool isMissing = !string.IsNullOrWhiteSpace(resolvedExe) && !File.Exists(resolvedExe);
                    results.Add(new LeftoverItem
                    {
                        Name = shortTaskName,
                        Category = LeftoverCategory.ScheduledTask,
                        Location = $"TaskScheduler: {relativeTaskName}",
                        TargetInfo = string.IsNullOrWhiteSpace(resolvedExe) ? firstCommand : $"Command: {resolvedExe}",
                        ConfidenceLevel = isMissing ? "Tinggi (Executable Hilang)" : "Pencarian Manual",
                        Reason = isMissing
                            ? $"Executable Task Scheduler sudah tidak ada: {resolvedExe}"
                            : $"Nama atau command task cocok dengan '{keyword}'",
                        LastModified = File.GetLastWriteTime(taskFilePath),
                        ExtraMetadata = $"TASK|{relativeTaskName}|{taskFilePath}",
                        IsSelected = isMissing || !indexer.IsMatchedWithInstalledApp(shortTaskName)
                    });
                }
            }
            else
            {
                // Automatic Orphaned Check: flag tasks whose target executable on disk is missing
                if (!string.IsNullOrWhiteSpace(resolvedExe) &&
                    IsUserOrProgramPath(resolvedExe) &&
                    !File.Exists(resolvedExe))
                {
                    results.Add(new LeftoverItem
                    {
                        Name = shortTaskName,
                        Category = LeftoverCategory.ScheduledTask,
                        Location = $"TaskScheduler: {relativeTaskName}",
                        TargetInfo = $"Target hilang: {resolvedExe}",
                        ConfidenceLevel = "Tinggi (Executable Hilang)",
                        Reason = $"Task menjadwalkan file '{resolvedExe}' yang sudah dihapus dari komputer",
                        LastModified = File.GetLastWriteTime(taskFilePath),
                        ExtraMetadata = $"TASK|{relativeTaskName}|{taskFilePath}"
                    });
                }
            }
        }
        catch
        {
            // Ignore non-XML or inaccessible task files
        }
    }

    private void ScanStartupRegistryEntries(string? keyword, List<LeftoverItem> results, CancellationToken ct)
    {
        (RegistryKey Root, string RootName, string SubPath)[] runKeys =
        [
            (Registry.CurrentUser, "HKEY_CURRENT_USER", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        ];

        foreach (var (root, rootName, subPath) in runKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = root.OpenSubKey(subPath);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    if (string.IsNullOrWhiteSpace(valueName)) continue;
                    string rawCmd = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(rawCmd)) continue;

                    string? exePath = ExtractTargetFilePath(rawCmd, string.Empty);

                    if (keyword != null)
                    {
                        if (valueName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                            rawCmd.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            bool missing = !string.IsNullOrWhiteSpace(exePath) && !File.Exists(exePath);
                            results.Add(new LeftoverItem
                            {
                                Name = $"[Startup] {valueName}",
                                Category = LeftoverCategory.ScheduledTask,
                                Location = $@"{rootName}\{subPath} -> {valueName}",
                                TargetInfo = rawCmd,
                                ConfidenceLevel = missing ? "Tinggi (Target Hilang)" : "Pencarian Manual",
                                Reason = missing
                                    ? $"Entri Startup menunjuk ke file yang sudah dihapus: {exePath}"
                                    : $"Entri Startup cocok dengan '{keyword}'",
                                ExtraMetadata = $@"RUNVALUE|{rootName}\{subPath}|{valueName}",
                                IsSelected = missing || !indexer.IsMatchedWithInstalledApp(valueName)
                            });
                        }
                    }
                    else
                    {
                        if (!string.IsNullOrWhiteSpace(exePath) &&
                            IsUserOrProgramPath(exePath) &&
                            !File.Exists(exePath))
                        {
                            results.Add(new LeftoverItem
                            {
                                Name = $"[Startup] {valueName}",
                                Category = LeftoverCategory.ScheduledTask,
                                Location = $@"{rootName}\{subPath} -> {valueName}",
                                TargetInfo = $"Target hilang: {exePath}",
                                ConfidenceLevel = "Tinggi (Startup Target Hilang)",
                                Reason = $"Program startup '{exePath}' sudah tidak ada di disk",
                                ExtraMetadata = $@"RUNVALUE|{rootName}\{subPath}|{valueName}"
                            });
                        }
                    }
                }
            }
            catch { }
        }
    }

    private static string? ExtractTargetFilePath(string command, string arguments)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;

        string expandedCmd = Environment.ExpandEnvironmentVariables(command.Trim());

        // If command is quoted: "C:\Path\App.exe" --arg
        var quoteMatch = Regex.Match(expandedCmd, @"^""([^""]+)""");
        if (quoteMatch.Success)
        {
            string candidate = quoteMatch.Groups[1].Value;
            if (IsStandardDrivePath(candidate))
                return candidate;
        }

        // If command ends with .exe or contains .exe before arguments
        var exeMatch = Regex.Match(expandedCmd, @"^([a-zA-Z]:\\[^:*?""<>|\r\n]+?\.(?:exe|bat|cmd|vbs|ps1))\b", RegexOptions.IgnoreCase);
        if (exeMatch.Success)
        {
            return exeMatch.Groups[1].Value;
        }

        // Check if command is cmd.exe / powershell / rundll32 and the actual target path is inside arguments
        if (!string.IsNullOrWhiteSpace(arguments))
        {
            string expandedArgs = Environment.ExpandEnvironmentVariables(arguments);
            var argExeMatch = Regex.Match(expandedArgs, @"([a-zA-Z]:\\[^:*?""<>|\r\n""]+?\.(?:exe|bat|cmd|vbs|ps1))", RegexOptions.IgnoreCase);
            if (argExeMatch.Success)
            {
                return argExeMatch.Groups[1].Value;
            }
        }

        if (IsStandardDrivePath(expandedCmd))
            return expandedCmd;

        return null;
    }

    private static bool IsStandardDrivePath(string path)
    {
        return path.Length >= 3 &&
               char.IsLetter(path[0]) &&
               path[1] == ':' &&
               (path[2] == '\\' || path[2] == '/');
    }

    private static bool IsUserOrProgramPath(string path)
    {
        if (!IsStandardDrivePath(path)) return false;
        // Do not flag core Windows\System32 binaries as orphaned apps
        if (path.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }
}
