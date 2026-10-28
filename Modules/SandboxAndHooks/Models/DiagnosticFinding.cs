using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace cleaNclean.Modules.SandboxAndHooks.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FindingSeverity
{
    Low,
    Medium,
    High,
    Critical
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RemediationAction
{
    None,
    Remove,
    Disable,
    HealAcl,
    HealOrRemove
}

public class DiagnosticFinding : INotifyPropertyChanged
{
    private bool _isSelected = false;
    private RemediationAction _selectedAction;

    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    [JsonIgnore]
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

    public string Category { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public string IssueDescription { get; set; } = string.Empty;
    public FindingSeverity Severity { get; set; } = FindingSeverity.Medium;
    public RemediationAction RecommendedAction { get; set; } = RemediationAction.Remove;

    public RemediationAction SelectedAction
    {
        get => _selectedAction == RemediationAction.None ? RecommendedAction : _selectedAction;
        set
        {
            if (_selectedAction != value)
            {
                _selectedAction = value;
                OnPropertyChanged();
            }
        }
    }

    public bool RequiresAdmin { get; set; }
    public Dictionary<string, string> Metadata { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    [JsonIgnore]
    public List<RemediationAction> AvailableActions { get; set; } = [RemediationAction.Remove];

    // --- UI Display Helpers for 2-Line Table & Badges ---

    [JsonIgnore]
    public string TitleDisplay
    {
        get
        {
            if (Category == "OrphanedAppContainerSid" && Metadata.TryGetValue("Sid", out string? sid))
            {
                string folderName = Path.GetFileName(Target.TrimEnd(Path.DirectorySeparatorChar));
                return $"SID Yatim pada {folderName} ({sid[..Math.Min(sid.Length, 24)]}...)";
            }
            if (Category == "SandboxMissingAllAppPackages")
            {
                string folderName = Path.GetFileName(Target.TrimEnd(Path.DirectorySeparatorChar));
                return $"Sandbox Auto-Heal: {folderName}";
            }
            if (Category == "VulkanOverlayHook" && Metadata.TryGetValue("ValueName", out string? valName))
            {
                return Path.GetFileName(valName);
            }
            return Path.GetFileName(Target.TrimEnd(Path.DirectorySeparatorChar));
        }
    }

    [JsonIgnore]
    public string CategoryFriendlyDisplay => Category switch
    {
        "OrphanedAppContainerSid" => "🔒 AppContainer SID",
        "SandboxMissingAllAppPackages" => "🩹 Sandbox Auto-Heal",
        "VulkanOverlayHook" => "🎮 Vulkan GPU Hook",
        "BrokenLauncherOrPwaShortcut" => "🚀 Launcher / PWA",
        _ => Category
    };

    [JsonIgnore]
    public string CategoryBadge => CategoryFriendlyDisplay;

    [JsonIgnore]
    public string SeverityLabel => Severity.ToString();

    [JsonIgnore]
    public string RecommendedActionLabel => RecommendedAction switch
    {
        RemediationAction.HealAcl => "Heal ACL (*S-1-15-2-1)",
        RemediationAction.Disable => "Disable (DWORD=1)",
        RemediationAction.Remove => cleaNclean.Services.LocalizationManager.Instance.IsEnglish ? "Remove (Delete)" : "Remove (Hapus)",
        _ => RecommendedAction.ToString()
    };

    public void RefreshLocalization()
    {
        OnPropertyChanged(nameof(RecommendedActionLabel));
    }

    [JsonIgnore]
    public string CategoryBadgeBackground => Category switch
    {
        "OrphanedAppContainerSid" => "#EFF6FF",
        "SandboxMissingAllAppPackages" => "#FEF2F2",
        "VulkanOverlayHook" => "#F5F3FF",
        "BrokenLauncherOrPwaShortcut" => "#FFFBEB",
        _ => "#F1F5F9"
    };

    [JsonIgnore]
    public string CategoryBadgeForeground => Category switch
    {
        "OrphanedAppContainerSid" => "#1D4ED8",
        "SandboxMissingAllAppPackages" => "#B91C1C",
        "VulkanOverlayHook" => "#6D28D9",
        "BrokenLauncherOrPwaShortcut" => "#B45309",
        _ => "#334155"
    };

    [JsonIgnore]
    public string SeverityBadgeBackground => Severity switch
    {
        FindingSeverity.Critical => "#FEE2E2",
        FindingSeverity.High => "#FFEDD5",
        FindingSeverity.Medium => "#FEF3C7",
        _ => "#E0F2FE"
    };

    [JsonIgnore]
    public string SeverityBadgeForeground => Severity switch
    {
        FindingSeverity.Critical => "#991B1B",
        FindingSeverity.High => "#C2410C",
        FindingSeverity.Medium => "#92400E",
        _ => "#075985"
    };

    [JsonIgnore]
    public string AdminRequiredDisplay => RequiresAdmin ? "🔒 Admin (UAC)" : "Standar";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
