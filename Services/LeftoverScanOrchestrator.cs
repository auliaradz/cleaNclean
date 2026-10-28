using cleaNclean.Models;

namespace cleaNclean.Services;

public class LeftoverScanOrchestrator
{
    public InstalledAppsIndexer Indexer { get; }
    private readonly AppDataScanner _appDataScanner;
    private readonly RegistryScanner _registryScanner;
    private readonly ShortcutScanner _shortcutScanner;
    private readonly TaskSchedulerScanner _taskScanner;

    public LeftoverScanOrchestrator()
    {
        Indexer = new InstalledAppsIndexer();
        _appDataScanner = new AppDataScanner(Indexer);
        _registryScanner = new RegistryScanner(Indexer);
        _shortcutScanner = new ShortcutScanner(Indexer);
        _taskScanner = new TaskSchedulerScanner(Indexer);
    }

    public async Task<List<LeftoverItem>> RunAutomaticOrphanScanAsync(
        bool scanAppData,
        bool scanRegistry,
        bool scanShortcuts,
        bool scanTasks,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        progress?.Report("Mengindeks daftar aplikasi yang masih terinstal di sistem...");
        await Indexer.BuildIndexAsync(ct);

        return await Task.Run(() =>
        {
            var allItems = new List<LeftoverItem>();

            if (scanAppData)
            {
                allItems.AddRange(_appDataScanner.ScanOrphanedFolders(progress, ct));
            }

            if (scanRegistry)
            {
                allItems.AddRange(_registryScanner.ScanOrphanedRegistryKeys(progress, ct));
            }

            if (scanShortcuts)
            {
                allItems.AddRange(_shortcutScanner.ScanBrokenShortcuts(progress, ct));
            }

            if (scanTasks)
            {
                allItems.AddRange(_taskScanner.ScanOrphanedTasksAndStartup(progress, ct));
            }

            return allItems
                .OrderByDescending(i => i.Category == LeftoverCategory.BrokenShortcut || i.Category == LeftoverCategory.ScheduledTask)
                .ThenByDescending(i => i.SizeInBytes)
                .ThenBy(i => i.Name)
                .ToList();
        }, ct);
    }

    public async Task<List<LeftoverItem>> RunKeywordScanAsync(
        string keyword,
        bool scanAppData,
        bool scanRegistry,
        bool scanShortcuts,
        bool scanTasks,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        progress?.Report("Memperbarui indeks aplikasi terinstal...");
        await Indexer.BuildIndexAsync(ct);

        return await Task.Run(() =>
        {
            var allItems = new List<LeftoverItem>();

            if (scanAppData)
            {
                allItems.AddRange(_appDataScanner.ScanByKeyword(keyword, progress, ct));
            }

            if (scanRegistry)
            {
                allItems.AddRange(_registryScanner.ScanByKeyword(keyword, progress, ct));
            }

            if (scanShortcuts)
            {
                allItems.AddRange(_shortcutScanner.ScanByKeyword(keyword, progress, ct));
            }

            if (scanTasks)
            {
                allItems.AddRange(_taskScanner.ScanByKeyword(keyword, progress, ct));
            }

            return allItems
                .OrderByDescending(i => i.IsSelected)
                .ThenByDescending(i => i.SizeInBytes)
                .ThenBy(i => i.Name)
                .ToList();
        }, ct);
    }
}
