using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace cleaNclean.Modules.SandboxAndHooks.Services;

public class SecurityAuditLogger
{
    public string LogDirectory { get; }
    public string AuditLogFilePath { get; }
    public string AclBackupFilePath { get; }

    private readonly object _lock = new();

    public SecurityAuditLogger()
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        LogDirectory = Path.Combine(localAppData, "cleaNclean", "Logs");
        Directory.CreateDirectory(LogDirectory);

        string dateStamp = DateTime.Now.ToString("yyyyMMdd");
        AuditLogFilePath = Path.Combine(LogDirectory, $"sandbox_hook_audit_{dateStamp}.log");
        AclBackupFilePath = Path.Combine(LogDirectory, $"acl_sddl_backup_{dateStamp}.jsonl");
    }

    /// <summary>
    /// Checks whether the current process is running with elevated Administrator privileges (UAC).
    /// </summary>
    public static bool IsRunningAsAdministrator()
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Relaunches the current application with UAC Administrator elevation ("runas").
    /// </summary>
    public static bool TryRestartAsAdministrator(string? extraArguments = null)
    {
        try
        {
            string? exePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exePath)) return false;

            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = extraArguments ?? string.Empty,
                UseShellExecute = true,
                Verb = "runas"
            };

            Process.Start(psi);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void LogInfo(string module, string message) => WriteLog("INFO", module, message);
    public void LogWarning(string module, string message) => WriteLog("WARN", module, message);
    public void LogError(string module, string message, Exception? ex = null)
        => WriteLog("ERROR", module, ex == null ? message : $"{message} | Exception: {ex.GetType().Name}: {ex.Message}");

    /// <summary>
    /// Records the complete SDDL (Security Descriptor Definition Language) string of a directory
    /// BEFORE any ACL modification is performed, enabling full rollback if ever needed.
    /// </summary>
    public void BackupDirectoryAclBeforeModify(string directoryPath, DirectorySecurity security, string reason)
    {
        try
        {
            string sddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            var record = new
            {
                Timestamp = DateTime.Now.ToString("O"),
                DirectoryPath = directoryPath,
                Reason = reason,
                OriginalSddl = sddl
            };

            string jsonLine = JsonSerializer.Serialize(record);
            lock (_lock)
            {
                File.AppendAllText(AclBackupFilePath, jsonLine + Environment.NewLine, Encoding.UTF8);
            }

            LogInfo("ACL-Backup", $"Saved original SDDL for '{directoryPath}' before '{reason}'. SDDL={sddl}");
        }
        catch (Exception ex)
        {
            LogWarning("ACL-Backup", $"Failed to record SDDL backup for '{directoryPath}': {ex.Message}");
        }
    }

    public void LogRegistryBeforeModify(string keyPath, string valueName, object? oldValue, string action)
    {
        LogInfo("Registry-Audit", $"Action='{action}' | Key='{keyPath}' | ValueName='{valueName}' | PreviousValue='{oldValue ?? "null"}'");
    }

    private void WriteLog(string level, string module, string message)
    {
        string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] [{module}] [Admin={IsRunningAsAdministrator()}] {message}";
        lock (_lock)
        {
            try
            {
                File.AppendAllText(AuditLogFilePath, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
                // Ignore logging I/O error
            }
        }
    }
}
