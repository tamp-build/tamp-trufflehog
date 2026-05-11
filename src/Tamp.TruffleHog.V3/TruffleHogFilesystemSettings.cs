namespace Tamp.TruffleHog.V3;

/// <summary>
/// Settings for <c>trufflehog filesystem &lt;path...&gt;</c> — scan
/// arbitrary on-disk content. Useful for scanning build outputs or
/// downloaded artifacts before deploy.
/// </summary>
public sealed class TruffleHogFilesystemSettings : TruffleHogSettingsBase
{
    /// <summary>Paths to scan (positional, at least one required).</summary>
    public List<string> Paths { get; } = [];

    /// <summary>Include-paths file. Maps to <c>--include-paths</c> / <c>-i</c>.</summary>
    public string? IncludePathsFile { get; set; }

    /// <summary>Exclude-paths file. Maps to <c>--exclude-paths</c> / <c>-x</c>.</summary>
    public string? ExcludePathsFile { get; set; }

    public TruffleHogFilesystemSettings AddPath(string path) { Paths.Add(path); return this; }
    public TruffleHogFilesystemSettings SetIncludePathsFile(string path) { IncludePathsFile = path; return this; }
    public TruffleHogFilesystemSettings SetExcludePathsFile(string path) { ExcludePathsFile = path; return this; }

    protected override IEnumerable<string> BuildSourceArguments()
    {
        if (Paths.Count == 0)
            throw new InvalidOperationException("trufflehog filesystem: at least one path is required.");
        yield return "filesystem";
        if (!string.IsNullOrEmpty(IncludePathsFile)) { yield return "--include-paths"; yield return IncludePathsFile!; }
        if (!string.IsNullOrEmpty(ExcludePathsFile)) { yield return "--exclude-paths"; yield return ExcludePathsFile!; }
        foreach (var p in Paths) yield return p;
    }
}
