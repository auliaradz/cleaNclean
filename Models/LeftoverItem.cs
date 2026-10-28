using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace cleaNclean.Models;

public enum LeftoverCategory
{
    AppDataFolder,
    RegistryKey,
    BrokenShortcut,
    ScheduledTask
}

public class LeftoverItem : INotifyPropertyChanged
{
    private bool _isSelected = false;

    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                OnPropertyChanged();
            }
        }
    }

    public string Name { get; set; } = string.Empty;
    public LeftoverCategory Category { get; set; }

    public string CategoryDisplay => Category switch
    {
        LeftoverCategory.AppDataFolder => "📁 AppData / Folder",
        LeftoverCategory.RegistryKey => "🧩 Windows Registry",
        LeftoverCategory.BrokenShortcut => cleaNclean.Services.LocalizationManager.Instance.IsEnglish ? "🔗 Broken Shortcut" : "🔗 Shortcut Rusak",
        LeftoverCategory.ScheduledTask => "⏱️ Task & Startup",
        _ => Category.ToString()
    };

    public string CategoryIcon => Category switch
    {
        LeftoverCategory.AppDataFolder => "📁",
        LeftoverCategory.RegistryKey => "🧩",
        LeftoverCategory.BrokenShortcut => "🔗",
        LeftoverCategory.ScheduledTask => "⏱️",
        _ => "📄"
    };

    public string CategoryLabel => Category switch
    {
        LeftoverCategory.AppDataFolder => "AppData / Folder",
        LeftoverCategory.RegistryKey => "Windows Registry",
        LeftoverCategory.BrokenShortcut => cleaNclean.Services.LocalizationManager.Instance.IsEnglish ? "Broken Shortcut" : "Shortcut Rusak",
        LeftoverCategory.ScheduledTask => "Task & Startup",
        _ => Category.ToString()
    };

    public void RefreshLocalization()
    {
        OnPropertyChanged(nameof(CategoryDisplay));
        OnPropertyChanged(nameof(CategoryLabel));
    }

    public string CategoryBadgeBackground => Category switch
    {
        LeftoverCategory.AppDataFolder => "#EFF6FF",
        LeftoverCategory.RegistryKey => "#F5F3FF",
        LeftoverCategory.BrokenShortcut => "#FFFBEB",
        LeftoverCategory.ScheduledTask => "#ECFDF5",
        _ => "#F1F5F9"
    };

    public string CategoryBadgeForeground => Category switch
    {
        LeftoverCategory.AppDataFolder => "#1D4ED8",
        LeftoverCategory.RegistryKey => "#6D28D9",
        LeftoverCategory.BrokenShortcut => "#B45309",
        LeftoverCategory.ScheduledTask => "#047857",
        _ => "#334155"
    };

    public string CategoryBadgeBorder => Category switch
    {
        LeftoverCategory.AppDataFolder => "#BFDBFE",
        LeftoverCategory.RegistryKey => "#DDD6FE",
        LeftoverCategory.BrokenShortcut => "#FDE68A",
        LeftoverCategory.ScheduledTask => "#A7F3D0",
        _ => "#CBD5E1"
    };

    public string Location { get; set; } = string.Empty;
    public string TargetInfo { get; set; } = string.Empty;
    public long SizeInBytes { get; set; }
    public string FormattedSize => FormatBytes(SizeInBytes, Category);
    public string ConfidenceLevel { get; set; } = "Sedang";
    public string Reason { get; set; } = string.Empty;
    public DateTime? LastModified { get; set; }
    public string LastModifiedDisplay => LastModified?.ToString("dd MMM yyyy, HH:mm") ?? "-";

    // Extra metadata for TaskScheduler or Startup cleanup
    public string ExtraMetadata { get; set; } = string.Empty;

    public static string FormatBytes(long bytes, LeftoverCategory category)
    {
        if (bytes <= 0 && (category == LeftoverCategory.RegistryKey || category == LeftoverCategory.ScheduledTask))
            return "-";

        string[] suffixes = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int order = 0;
        while (value >= 1024 && order < suffixes.Length - 1)
        {
            order++;
            value /= 1024;
        }
        return $"{value:0.##} {suffixes[order]}";
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
