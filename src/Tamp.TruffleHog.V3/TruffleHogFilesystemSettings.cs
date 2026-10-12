namespace Tamp.TruffleHog.V3;

/// <summary>
/// Settings for <c>trufflehog filesystem &lt;path...&gt;</c> — scan arbitrary on-disk content.
/// Useful for scanning build outputs or downloaded artifacts before deploy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Scope the paths — don't scan <c>.</c> over a tree with a vendored toolchain.</b> TruffleHog
/// has no "skip these directories" traversal flag: <see cref="IncludePathsFile"/> /
/// <see cref="ExcludePathsFile"/> are regex filters applied to the file list, they do <b>not</b>
/// stop the walk. Pointing a scan at <c>.</c> on a repo that contains <c>node_modules</c> (e.g.
/// puppeteer's bundled Chromium) makes trufflehog walk — and read — that whole tree before
/// discarding it, which hangs for minutes. The performant pattern is to scan the real source
/// paths: <c>AddPaths("src", "build")</c> rather than <c>AddPath(".")</c> plus an exclude file.
/// </para>
/// <para>
/// When you must scan a broad path, add <see cref="TruffleHogSettingsBase.ForceSkipBinaries"/>
/// (<c>SetForceSkipBinaries()</c>) and/or <see cref="TruffleHogSettingsBase.ForceSkipArchives"/>
/// so the heavy binary/archive content under such trees isn't read.
/// </para>
/// </remarks>
public sealed class TruffleHogFilesystemSettings : TruffleHogSettingsBase
{
    /// <summary>
    /// Paths to scan (positional, at least one required). Scope these to real source directories
    /// for performance — trufflehog walks every path given, and <see cref="ExcludePathsFile"/> does
    /// not prevent the walk (see the type remarks).
    /// </summary>
    public List<string> Paths { get; } = [];

    /// <summary>
    /// File of newline-separated regexes; only matching files are <i>reported</i>. Maps to
    /// <c>--include-paths</c> / <c>-i</c>. This is a results filter over the walked file set — it
    /// does <b>not</b> reduce traversal. To go faster, scope <see cref="Paths"/> instead.
    /// </summary>
    public string? IncludePathsFile { get; set; }

    /// <summary>
    /// File of newline-separated regexes; matching files are dropped from <i>results</i>. Maps to
    /// <c>--exclude-paths</c> / <c>-x</c>. <b>Does not prevent traversal</b> — trufflehog still walks
    /// (and reads) excluded paths before discarding them. For heavy dirs, scope <see cref="Paths"/>
    /// and/or set <see cref="TruffleHogSettingsBase.ForceSkipBinaries"/>.
    /// </summary>
    public string? ExcludePathsFile { get; set; }

    /// <summary>Add one path to scan.</summary>
    public TruffleHogFilesystemSettings AddPath(string path) { Paths.Add(path); return this; }

    /// <summary>Add several paths to scan — the ergonomic way to scope a scan to real source dirs.</summary>
    public TruffleHogFilesystemSettings AddPaths(params string[] paths) { Paths.AddRange(paths); return this; }

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
