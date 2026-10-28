using System.IO;
using cleaNclean.Models;
using Microsoft.Win32;

namespace cleaNclean.Services;

public class RegistryScanner(InstalledAppsIndexer indexer)
{
    public List<LeftoverItem> ScanOrphanedRegistryKeys(IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();

        // 1. Scan HKCU\Software
        progress?.Report(@"Memindai Registry HKEY_CURRENT_USER\Software...");
        ScanSoftwareHive(Registry.CurrentUser, "HKEY_CURRENT_USER", @"Software", results, ct);

        // 2. Scan HKLM\SOFTWARE (and WOW6432Node)
        progress?.Report(@"Memindai Registry HKEY_LOCAL_MACHINE\SOFTWARE...");
        ScanSoftwareHive(Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE", results, ct);
        ScanSoftwareHive(Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\WOW6432Node", results, ct);

        return results;
    }

    private void ScanSoftwareHive(RegistryKey rootKey, string rootName, string softwarePath, List<LeftoverItem> results, CancellationToken ct)
    {
        try
        {
            using var softwareKey = rootKey.OpenSubKey(softwarePath);
            if (softwareKey == null) return;

            foreach (var subKeyName in softwareKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                if (subKeyName.Equals("cleaNclean", StringComparison.OrdinalIgnoreCase))
                    continue;

                string fullRegPath = $@"{rootName}\{softwarePath}\{subKeyName}";
                if (indexer.IsWhitelisted(subKeyName, fullRegPath))
                    continue;

                bool matchedInstalled = indexer.IsMatchedWithInstalledApp(subKeyName);

                using var subKey = softwareKey.OpenSubKey(subKeyName);
                if (subKey == null) continue;

                // Also check if any immediate child subkey matches an installed app (e.g., HKCU\Software\Vendor\InstalledProduct)
                if (!matchedInstalled && HasAnyMatchedChildSubKey(subKey))
                {
                    matchedInstalled = true;
                }

                // Check if this key references a broken install path on disk
                string? brokenReferencedPath = FindBrokenDiskPathInKey(subKey);

                if (brokenReferencedPath != null)
                {
                    results.Add(new LeftoverItem
                    {
                        Name = subKeyName,
                        Category = LeftoverCategory.RegistryKey,
                        Location = fullRegPath,
                        TargetInfo = $"Target hilang: {brokenReferencedPath}",
                        ConfidenceLevel = "Tinggi (Path Hilang)",
                        Reason = $"Nilai Registry menunjuk ke path yang sudah dihapus: {brokenReferencedPath}",
                        ExtraMetadata = fullRegPath
                    });
                }
                else if (!matchedInstalled && rootName == "HKEY_CURRENT_USER")
                {
                    // For HKCU\Software, vendor/app keys that have no match in InstalledApps and are not whitelisted
                    int valueCount = SafeGetSubtreeCount(subKey);
                    results.Add(new LeftoverItem
                    {
                        Name = subKeyName,
                        Category = LeftoverCategory.RegistryKey,
                        Location = fullRegPath,
                        TargetInfo = $"Kunci Registry yatim ({valueCount} item/subkey)",
                        ConfidenceLevel = "Sedang (Orphaned)",
                        Reason = $"Tidak ditemukan aplikasi terinstal yang cocok dengan '{subKeyName}'",
                        ExtraMetadata = fullRegPath
                    });
                }
            }
        }
        catch
        {
            // Ignore access errors
        }
    }

    public List<LeftoverItem> ScanByKeyword(string keyword, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        if (string.IsNullOrWhiteSpace(keyword) || keyword.Trim().Length < 2)
            return results;

        string kw = keyword.Trim();
        string normKw = InstalledAppsIndexer.NormalizeToken(kw);

        progress?.Report($@"Mencari '{kw}' di Registry HKCU & HKLM...");
        SearchHiveByKeyword(Registry.CurrentUser, "HKEY_CURRENT_USER", @"Software", kw, normKw, results, ct);
        SearchHiveByKeyword(Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE", kw, normKw, results, ct);
        SearchHiveByKeyword(Registry.LocalMachine, "HKEY_LOCAL_MACHINE", @"SOFTWARE\WOW6432Node", kw, normKw, results, ct);

        return results;
    }

    private void SearchHiveByKeyword(
        RegistryKey rootKey,
        string rootName,
        string softwarePath,
        string rawKeyword,
        string normKeyword,
        List<LeftoverItem> results,
        CancellationToken ct)
    {
        try
        {
            using var softwareKey = rootKey.OpenSubKey(softwarePath);
            if (softwareKey == null) return;

            foreach (var subKeyName in softwareKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (subKeyName.Equals("Classes", StringComparison.OrdinalIgnoreCase) ||
                    subKeyName.Equals("WOW6432Node", StringComparison.OrdinalIgnoreCase) ||
                    subKeyName.Equals("Clients", StringComparison.OrdinalIgnoreCase) ||
                    subKeyName.Equals("Policies", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string fullPath1 = $@"{rootName}\{softwarePath}\{subKeyName}";

                if (MatchesKeyword(subKeyName, rawKeyword, normKeyword))
                {
                    bool isInstalled = indexer.IsMatchedWithInstalledApp(subKeyName);
                    results.Add(new LeftoverItem
                    {
                        Name = subKeyName,
                        Category = LeftoverCategory.RegistryKey,
                        Location = fullPath1,
                        TargetInfo = $"Registry Key ({rootName})",
                        ConfidenceLevel = isInstalled ? "Perhatian (Mungkin Masih Terinstal)" : "Pencarian Manual",
                        Reason = $"Nama kunci Registry cocok dengan '{rawKeyword}'",
                        ExtraMetadata = fullPath1,
                        IsSelected = !isInstalled
                    });
                    continue;
                }

                // Check 2nd level (e.g. HKCU\Software\VendorName\AppName)
                try
                {
                    using var vendorKey = softwareKey.OpenSubKey(subKeyName);
                    if (vendorKey == null) continue;

                    foreach (var childName in vendorKey.GetSubKeyNames())
                    {
                        if (MatchesKeyword(childName, rawKeyword, normKeyword))
                        {
                            string fullPath2 = $@"{fullPath1}\{childName}";
                            bool isInstalled = indexer.IsMatchedWithInstalledApp(childName);
                            results.Add(new LeftoverItem
                            {
                                Name = $@"{subKeyName}\{childName}",
                                Category = LeftoverCategory.RegistryKey,
                                Location = fullPath2,
                                TargetInfo = $@"Subkey di bawah {subKeyName}",
                                ConfidenceLevel = isInstalled ? "Perhatian (Mungkin Masih Terinstal)" : "Pencarian Manual",
                                Reason = $"Subkey Registry cocok dengan '{rawKeyword}'",
                                ExtraMetadata = fullPath2,
                                IsSelected = !isInstalled
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
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

    private static string? FindBrokenDiskPathInKey(RegistryKey key)
    {
        try
        {
            foreach (var valName in key.GetValueNames())
            {
                string? val = key.GetValue(valName)?.ToString();
                if (string.IsNullOrWhiteSpace(val)) continue;

                string? candidatePath = ExtractCandidateExeOrProgramDir(val);
                if (candidatePath != null)
                {
                    if (!File.Exists(candidatePath) && !Directory.Exists(candidatePath))
                    {
                        return candidatePath;
                    }
                }
            }

            // Also inspect immediate child subkeys (up to 8)
            foreach (var subName in key.GetSubKeyNames().Take(8))
            {
                using var child = key.OpenSubKey(subName);
                if (child == null) continue;
                foreach (var valName in child.GetValueNames())
                {
                    string? val = child.GetValue(valName)?.ToString();
                    if (string.IsNullOrWhiteSpace(val)) continue;

                    string? candidatePath = ExtractCandidateExeOrProgramDir(val);
                    if (candidatePath != null && !File.Exists(candidatePath) && !Directory.Exists(candidatePath))
                    {
                        return candidatePath;
                    }
                }
            }
        }
        catch { }

        return null;
    }

    private static string? ExtractCandidateExeOrProgramDir(string rawValue)
    {
        string trimmed = rawValue.Trim('"', ' ', '\'');
        if (trimmed.Length < 6 || trimmed.Length > 260) return null;

        // Only check paths pointing to Program Files or AppData\Local\Programs ending in .exe
        if ((trimmed.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase) ||
             trimmed.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase)) &&
            trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed;
        }

        return null;
    }

    private bool HasAnyMatchedChildSubKey(RegistryKey key)
    {
        try
        {
            foreach (var childName in key.GetSubKeyNames().Take(40))
            {
                if (childName.Length >= 3 && indexer.IsMatchedWithInstalledApp(childName))
                    return true;
            }
        }
        catch { }
        return false;
    }

    private static int SafeGetSubtreeCount(RegistryKey key)
    {
        try
        {
            return key.ValueCount + key.SubKeyCount;
        }
        catch
        {
            return 0;
        }
    }
}
