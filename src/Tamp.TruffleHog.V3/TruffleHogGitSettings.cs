namespace Tamp.TruffleHog.V3;

/// <summary>
/// Settings for <c>trufflehog git &lt;uri|path&gt;</c> — scan a local
/// or remote git repo. Most common CI invocation: scan working tree
/// for a PR diff.
/// </summary>
public sealed class TruffleHogGitSettings : TruffleHogSettingsBase
{
    /// <summary>Git URI or path. Required positional.</summary>
    public string? Uri { get; set; }

    /// <summary>Branch to scan. Maps to <c>--branch</c>.</summary>
    public string? Branch { get; set; }

    /// <summary>Stop at this commit SHA. Maps to <c>--head</c>.</summary>
    public string? Head { get; set; }

    /// <summary>Commit SHA to start from. Maps to <c>--since-commit</c>.</summary>
    public string? SinceCommit { get; set; }

    /// <summary>Max commits to walk. Maps to <c>--max-depth</c>.</summary>
    public int? MaxDepth { get; set; }

    /// <summary>Include-paths file (newline-separated paths or globs). Maps to <c>--include-paths</c> / <c>-i</c>.</summary>
    public string? IncludePathsFile { get; set; }

    /// <summary>Exclude-paths file. Maps to <c>--exclude-paths</c> / <c>-x</c>.</summary>
    public string? ExcludePathsFile { get; set; }

    /// <summary>Exclude globs (comma-list). Maps to <c>--exclude-globs</c>.</summary>
    public List<string> ExcludeGlobs { get; } = [];

    /// <summary>Treat the source as a bare repository. Maps to <c>--bare</c>.</summary>
    public bool Bare { get; set; }

    public TruffleHogGitSettings SetUri(string uri) { Uri = uri; return this; }
    public TruffleHogGitSettings SetBranch(string branch) { Branch = branch; return this; }
    public TruffleHogGitSettings SetHead(string sha) { Head = sha; return this; }
    public TruffleHogGitSettings SetSinceCommit(string sha) { SinceCommit = sha; return this; }
    public TruffleHogGitSettings SetMaxDepth(int depth) { MaxDepth = depth; return this; }
    public TruffleHogGitSettings SetIncludePathsFile(string path) { IncludePathsFile = path; return this; }
    public TruffleHogGitSettings SetExcludePathsFile(string path) { ExcludePathsFile = path; return this; }
    public TruffleHogGitSettings AddExcludeGlob(string glob) { ExcludeGlobs.Add(glob); return this; }
    public TruffleHogGitSettings SetBare(bool v = true) { Bare = v; return this; }

    protected override IEnumerable<string> BuildSourceArguments()
    {
        if (string.IsNullOrEmpty(Uri))
            throw new InvalidOperationException("trufflehog git: Uri is required.");
        yield return "git";
        if (!string.IsNullOrEmpty(Branch)) { yield return "--branch"; yield return Branch!; }
        if (!string.IsNullOrEmpty(Head)) { yield return "--head"; yield return Head!; }
        if (!string.IsNullOrEmpty(SinceCommit)) { yield return "--since-commit"; yield return SinceCommit!; }
        if (MaxDepth is { } d) { yield return "--max-depth"; yield return d.ToString(); }
        if (!string.IsNullOrEmpty(IncludePathsFile)) { yield return "--include-paths"; yield return IncludePathsFile!; }
        if (!string.IsNullOrEmpty(ExcludePathsFile)) { yield return "--exclude-paths"; yield return ExcludePathsFile!; }
        if (ExcludeGlobs.Count > 0) { yield return "--exclude-globs"; yield return string.Join(',', ExcludeGlobs); }
        if (Bare) yield return "--bare";
        yield return Uri!;
    }
}
