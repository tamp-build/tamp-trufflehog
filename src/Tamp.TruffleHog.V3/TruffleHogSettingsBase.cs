namespace Tamp.TruffleHog.V3;

/// <summary>
/// Common base for <c>trufflehog &lt;source&gt;</c> settings. All
/// sub-commands accept the same scanning + verification + output
/// knobs; concrete classes layer their source-specific args on top.
/// </summary>
public abstract class TruffleHogSettingsBase
{
    public string? WorkingDirectory { get; set; }
    public Dictionary<string, string> EnvironmentVariables { get; } = new();

    /// <summary>Emit results as JSON. Maps to <c>--json</c>.</summary>
    public bool Json { get; set; }

    /// <summary>Only show results that pass live API verification. Maps to <c>--only-verified</c>.</summary>
    public bool OnlyVerified { get; set; }

    /// <summary>Skip live API verification entirely (offline scan). Maps to <c>--no-verification</c>.</summary>
    public bool NoVerification { get; set; }

    /// <summary>Drop findings below this Shannon entropy. Maps to <c>--filter-entropy</c>.</summary>
    public double? FilterEntropy { get; set; }

    /// <summary>Drop unverified findings entirely. Maps to <c>--filter-unverified</c>.</summary>
    public bool FilterUnverified { get; set; }

    /// <summary>Restrict to specific detectors (comma-list). Maps to <c>--include-detectors</c>.</summary>
    public List<string> IncludeDetectors { get; } = [];

    /// <summary>Exclude specific detectors (comma-list). Maps to <c>--exclude-detectors</c>.</summary>
    public List<string> ExcludeDetectors { get; } = [];

    /// <summary>Concurrent verifications. Maps to <c>--concurrency</c>.</summary>
    public int? Concurrency { get; set; }

    /// <summary>Exit non-zero if any finding. CI gate. Maps to <c>--fail</c>.</summary>
    public bool Fail { get; set; }

    /// <summary>Log level: <c>-1</c> trace, <c>0</c> info, <c>5</c> debug+. Maps to <c>--log-level</c>.</summary>
    public int? LogLevel { get; set; }

    /// <summary>Suppress the self-update check (avoids network call). Maps to <c>--no-update</c>.</summary>
    public bool NoUpdate { get; set; }

    /// <summary>Show per-detector timing summary. Maps to <c>--print-avg-detector-time</c>.</summary>
    public bool PrintAvgDetectorTime { get; set; }

    /// <summary>Filter the results type set. Comma-list of <c>verified</c>, <c>unverified</c>, <c>unknown</c>, <c>filtered_unverified</c>. Maps to <c>--results</c>.</summary>
    public string? Results { get; set; }

    /// <summary>Write output to a file (in addition to printing to stdout). Maps to <c>--output</c>.</summary>
    public string? Output { get; set; }

    /// <summary>Max archive size in bytes before bailing. Maps to <c>--archive-max-size</c>.</summary>
    public long? ArchiveMaxSize { get; set; }

    /// <summary>Max archive nesting depth. Maps to <c>--archive-max-depth</c>.</summary>
    public int? ArchiveMaxDepth { get; set; }

    /// <summary>Archive scanning timeout (Go duration syntax, e.g. <c>30s</c>). Maps to <c>--archive-timeout</c>.</summary>
    public string? ArchiveTimeout { get; set; }

    /// <summary>Allow verifications to share quotas. Maps to <c>--allow-verification-overlap</c>.</summary>
    public bool AllowVerificationOverlap { get; set; }

    /// <summary>Subclasses produce the source verb (e.g. <c>git</c>) and the source-specific args.</summary>
    protected abstract IEnumerable<string> BuildSourceArguments();

    /// <summary>Subclasses override to expose typed Secrets (e.g. GitHub PAT) for the redaction table.</summary>
    protected virtual IReadOnlyList<Secret> CollectSecrets() => Array.Empty<Secret>();

    /// <summary>Emit the cross-cutting flags. Called by ToCommandPlan after the source-specific args.</summary>
    protected void EmitCommonArguments(List<string> args)
    {
        if (Json) args.Add("--json");
        if (OnlyVerified) args.Add("--only-verified");
        if (NoVerification) args.Add("--no-verification");
        if (FilterEntropy is { } fe) { args.Add("--filter-entropy"); args.Add(fe.ToString(System.Globalization.CultureInfo.InvariantCulture)); }
        if (FilterUnverified) args.Add("--filter-unverified");
        if (IncludeDetectors.Count > 0) { args.Add("--include-detectors"); args.Add(string.Join(',', IncludeDetectors)); }
        if (ExcludeDetectors.Count > 0) { args.Add("--exclude-detectors"); args.Add(string.Join(',', ExcludeDetectors)); }
        if (Concurrency is { } c) { args.Add("--concurrency"); args.Add(c.ToString()); }
        if (Fail) args.Add("--fail");
        if (LogLevel is { } ll) { args.Add("--log-level"); args.Add(ll.ToString()); }
        if (NoUpdate) args.Add("--no-update");
        if (PrintAvgDetectorTime) args.Add("--print-avg-detector-time");
        if (!string.IsNullOrEmpty(Results)) { args.Add("--results"); args.Add(Results!); }
        if (!string.IsNullOrEmpty(Output)) { args.Add("--output"); args.Add(Output!); }
        if (ArchiveMaxSize is { } ams) { args.Add("--archive-max-size"); args.Add(ams.ToString()); }
        if (ArchiveMaxDepth is { } amd) { args.Add("--archive-max-depth"); args.Add(amd.ToString()); }
        if (!string.IsNullOrEmpty(ArchiveTimeout)) { args.Add("--archive-timeout"); args.Add(ArchiveTimeout!); }
        if (AllowVerificationOverlap) args.Add("--allow-verification-overlap");
    }

    public CommandPlan ToCommandPlan(Tool tool)
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        var args = new List<string>();
        args.AddRange(BuildSourceArguments());
        EmitCommonArguments(args);
        return new CommandPlan
        {
            Executable = tool.Executable.Value,
            Arguments = args,
            Environment = new Dictionary<string, string>(EnvironmentVariables),
            WorkingDirectory = WorkingDirectory,
            Secrets = CollectSecrets(),
        };
    }
}

/// <summary>Fluent setters for the shared base. Generic so concrete settings preserve their type.</summary>
public static class TruffleHogSettingsBaseExtensions
{
    public static T SetWorkingDirectory<T>(this T s, string? cwd) where T : TruffleHogSettingsBase { s.WorkingDirectory = cwd; return s; }
    public static T SetEnv<T>(this T s, string key, string value) where T : TruffleHogSettingsBase { s.EnvironmentVariables[key] = value; return s; }
    public static T SetJson<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.Json = v; return s; }
    public static T SetOnlyVerified<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.OnlyVerified = v; return s; }
    public static T SetNoVerification<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.NoVerification = v; return s; }
    public static T SetFilterEntropy<T>(this T s, double threshold) where T : TruffleHogSettingsBase { s.FilterEntropy = threshold; return s; }
    public static T SetFilterUnverified<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.FilterUnverified = v; return s; }
    public static T AddIncludeDetector<T>(this T s, string name) where T : TruffleHogSettingsBase { s.IncludeDetectors.Add(name); return s; }
    public static T AddExcludeDetector<T>(this T s, string name) where T : TruffleHogSettingsBase { s.ExcludeDetectors.Add(name); return s; }
    public static T SetConcurrency<T>(this T s, int n) where T : TruffleHogSettingsBase { s.Concurrency = n; return s; }
    public static T SetFail<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.Fail = v; return s; }
    public static T SetLogLevel<T>(this T s, int level) where T : TruffleHogSettingsBase { s.LogLevel = level; return s; }
    public static T SetNoUpdate<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.NoUpdate = v; return s; }
    public static T SetPrintAvgDetectorTime<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.PrintAvgDetectorTime = v; return s; }
    public static T SetResults<T>(this T s, string spec) where T : TruffleHogSettingsBase { s.Results = spec; return s; }
    public static T SetOutput<T>(this T s, string path) where T : TruffleHogSettingsBase { s.Output = path; return s; }
    public static T SetArchiveMaxSize<T>(this T s, long bytes) where T : TruffleHogSettingsBase { s.ArchiveMaxSize = bytes; return s; }
    public static T SetArchiveMaxDepth<T>(this T s, int depth) where T : TruffleHogSettingsBase { s.ArchiveMaxDepth = depth; return s; }
    public static T SetArchiveTimeout<T>(this T s, string duration) where T : TruffleHogSettingsBase { s.ArchiveTimeout = duration; return s; }
    public static T SetAllowVerificationOverlap<T>(this T s, bool v = true) where T : TruffleHogSettingsBase { s.AllowVerificationOverlap = v; return s; }
}
