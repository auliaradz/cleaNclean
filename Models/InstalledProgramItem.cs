using System.IO;
using System.Windows.Media;

namespace cleaNclean.Models;

public class InstalledProgramItem
{
    public string Name { get; set; } = string.Empty;
    public ImageSource? IconSource { get; set; }
    public long SizeInBytes { get; set; }
    public string Version { get; set; } = string.Empty;
    public string ArchitectureType { get; set; } = "64-bit";
    public DateTime? InstallDateValue { get; set; }
    public string Company { get; set; } = string.Empty;
    public string Website { get; set; } = string.Empty;
    public string Comment { get; set; } = string.Empty;
    public string InstallLocation { get; set; } = string.Empty;
    public string UninstallString { get; set; } = string.Empty;
    public string QuietUninstallString { get; set; } = string.Empty;
    public string RegistryKeyPath { get; set; } = string.Empty;
    public string DisplayIconRaw { get; set; } = string.Empty;
    public bool IsWindowsApp { get; set; }
    public string PackageFullName { get; set; } = string.Empty;
    public bool IsProtectedApp { get; set; }
    public bool IsSystemComponent { get; set; }

    public string ProtectionBadge => IsProtectedApp ? "🔒 Protected" : string.Empty;

    public string FormattedSize => FormatBytesRevoStyle(SizeInBytes);

    public string FormattedInstallDate =>
        InstallDateValue.HasValue
            ? InstallDateValue.Value.ToString("dd/MM/yyyy  HH.mm.ss")
            : string.Empty;

    public string EffectiveComment =>
        !string.IsNullOrWhiteSpace(Comment)
            ? Comment
            : (!string.IsNullOrWhiteSpace(InstallLocation) ? InstallLocation : RegistryKeyPath);

    public static string FormatBytesRevoStyle(long bytes)
    {
        if (bytes <= 0) return string.Empty;

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double val = bytes;
        int idx = 0;
        while (val >= 1024 && idx < units.Length - 1)
        {
            val /= 1024;
            idx++;
        }

        return $"{val:N2} {units[idx]}";
    }
}
