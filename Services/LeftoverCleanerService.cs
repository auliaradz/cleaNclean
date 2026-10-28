using System.Diagnostics;
using System.IO;
using cleaNclean.Models;
using Microsoft.VisualBasic.FileIO;
using Microsoft.Win32;

namespace cleaNclean.Services;

public class CleanupResultSummary
{
    public int SuccessCount { get; set; }
    public int FailedCount { get; set; }
    public long BytesFreed { get; set; }
    public string BackupFolderPath { get; set; } = string.Empty;
    public List<string> Errors { get; } = [];
}

public class LeftoverCleanerService
{
    public string BaseBackupDirectory { get; }

    public LeftoverCleanerService()
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        BaseBackupDirectory = Path.Combine(localAppData, "cleaNclean", "Backups");
        Directory.CreateDirectory(BaseBackupDirectory);
    }

    public Task<CleanupResultSummary> CleanItemsAsync(
        IEnumerable<LeftoverItem> itemsToClean,
        bool sendFilesToRecycleBin,
        bool backupRegistryBeforeDelete,
        IProgress<string>? progress = null)
    {
        return Task.Run(() =>
        {
            var summary = new CleanupResultSummary();
            string sessionBackupDir = Path.Combine(BaseBackupDirectory, DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            summary.BackupFolderPath = sessionBackupDir;

            var list = itemsToClean.ToList();
            int index = 0;

            foreach (var item in list)
            {
                index++;
                progress?.Report($"Membersihkan ({index}/{list.Count}): {item.Name}...");

                try
                {
                    switch (item.Category)
                    {
                        case LeftoverCategory.AppDataFolder:
                            CleanFolderItem(item.Location, sendFilesToRecycleBin);
                            summary.SuccessCount++;
                            summary.BytesFreed += item.SizeInBytes;
                            break;

                        case LeftoverCategory.BrokenShortcut:
                            CleanFileItem(item.Location, sendFilesToRecycleBin);
                            summary.SuccessCount++;
                            summary.BytesFreed += item.SizeInBytes;
                            break;

                        case LeftoverCategory.RegistryKey:
                            if (backupRegistryBeforeDelete)
                            {
                                Directory.CreateDirectory(sessionBackupDir);
                                ExportRegistryKeyBackup(item.Location, item.Name, sessionBackupDir);
                            }
                            DeleteRegistryKeyTree(item.Location);
                            summary.SuccessCount++;
                            break;

                        case LeftoverCategory.ScheduledTask:
                            CleanScheduledTaskOrStartupItem(item, backupRegistryBeforeDelete, sessionBackupDir);
                            summary.SuccessCount++;
                            break;
                    }
                }
                catch (Exception ex)
                {
                    summary.FailedCount++;
                    summary.Errors.Add($"{item.Name} ({item.Location}): {ex.Message}");
                }
            }

            return summary;
        });
    }

    private static void CleanFolderItem(string dirPath, bool sendToRecycleBin)
    {
        if (!Directory.Exists(dirPath)) return;

        if (sendToRecycleBin)
        {
            FileSystem.DeleteDirectory(dirPath, UIOption.OnlyErrorDialogs, RecycleOption.SendToRecycleBin);
        }
        else
        {
            ClearReadOnlyAttributes(dirPath);
            Directory.Delete(dirPath, recursive: true);
        }
    }

    private static void CleanFileItem(string filePath, bool sendToRecycleBin)
    {
        if (!File.Exists(filePath)) return;

        if (sendToRecycleBin)
        {
            FileSystem.DeleteFile(filePath, UIOption.OnlyErrorDialogs, RecycleOption.SendToRecycleBin);
        }
        else
        {
            File.SetAttributes(filePath, FileAttributes.Normal);
            File.Delete(filePath);
        }
    }

    private static void ClearReadOnlyAttributes(string dirPath)
    {
        try
        {
            var dirInfo = new DirectoryInfo(dirPath) { Attributes = FileAttributes.Normal };
            foreach (var file in dirInfo.GetFiles("*", System.IO.SearchOption.AllDirectories))
            {
                try { file.Attributes = FileAttributes.Normal; } catch { }
            }
        }
        catch { }
    }

    private static void ExportRegistryKeyBackup(string fullRegPath, string itemName, string backupDir)
    {
        try
        {
            string safeName = string.Join("_", itemName.Split(Path.GetInvalidFileNameChars(), StringSplitOptions.RemoveEmptyEntries));
            string outFile = Path.Combine(backupDir, $"{safeName}_{Guid.NewGuid().ToString("N")[..6]}.reg");

            var psi = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"export \"{fullRegPath}\" \"{outFile}\" /y",
                CreateNoWindow = true,
                UseShellExecute = false
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(4000);
        }
        catch
        {
            // Non-fatal if reg export fails
        }
    }

    private static void DeleteRegistryKeyTree(string fullRegPath)
    {
        var (root, subKeyPath) = SplitRegistryPath(fullRegPath);
        if (root == null || string.IsNullOrWhiteSpace(subKeyPath))
            throw new InvalidOperationException($"Path Registry tidak valid: {fullRegPath}");

        root.DeleteSubKeyTree(subKeyPath, throwOnMissingSubKey: false);
    }

    private static void CleanScheduledTaskOrStartupItem(LeftoverItem item, bool backupRegistry, string sessionBackupDir)
    {
        if (item.ExtraMetadata.StartsWith("RUNVALUE|", StringComparison.Ordinal))
        {
            // Format: RUNVALUE|HKEY_CURRENT_USER\Software\...\Run|ValueName
            var parts = item.ExtraMetadata.Split('|');
            if (parts.Length >= 3)
            {
                string keyPath = parts[1];
                string valName = parts[2];

                if (backupRegistry)
                {
                    Directory.CreateDirectory(sessionBackupDir);
                    ExportRegistryKeyBackup(keyPath, valName, sessionBackupDir);
                }

                var (root, subPath) = SplitRegistryPath(keyPath);
                if (root != null)
                {
                    using var key = root.OpenSubKey(subPath, writable: true)
                        ?? throw new UnauthorizedAccessException($"Tidak memiliki akses tulis ke {keyPath}. Jalankan sebagai Administrator.");
                    key.DeleteValue(valName, throwOnMissingValue: false);
                }
            }
        }
        else if (item.ExtraMetadata.StartsWith("TASK|", StringComparison.Ordinal))
        {
            // Format: TASK|\TaskRelativeName|C:\Windows\System32\Tasks\...
            var parts = item.ExtraMetadata.Split('|');
            string taskName = parts.Length >= 2 ? parts[1] : item.Name;

            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Delete /TN \"{taskName}\" /F",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            proc?.WaitForExit(5000);
            if (proc != null && proc.ExitCode != 0)
            {
                string err = proc.StandardError.ReadToEnd();
                throw new InvalidOperationException($"Gagal menghapus Scheduled Task (butuhkan akses Administrator): {err.Trim()}");
            }
        }
    }

    private static (RegistryKey? Root, string SubKeyPath) SplitRegistryPath(string fullPath)
    {
        int firstSlash = fullPath.IndexOf('\\');
        if (firstSlash <= 0) return (null, string.Empty);

        string rootName = fullPath[..firstSlash].ToUpperInvariant();
        string subPath = fullPath[(firstSlash + 1)..];

        RegistryKey? root = rootName switch
        {
            "HKEY_CURRENT_USER" or "HKCU" => Registry.CurrentUser,
            "HKEY_LOCAL_MACHINE" or "HKLM" => Registry.LocalMachine,
            "HKEY_USERS" or "HKU" => Registry.Users,
            "HKEY_CLASSES_ROOT" or "HKCR" => Registry.ClassesRoot,
            _ => null
        };

        return (root, subPath);
    }
}
