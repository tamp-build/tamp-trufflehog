namespace Tamp.TruffleHog.V3;

/// <summary>Facade for the TruffleHog 3.x CLI.</summary>
/// <remarks>
/// <para>Resolve via <c>[NuGetPackage(UseSystemPath = true)]</c>:</para>
/// <code>
/// [NuGetPackage("trufflehog", UseSystemPath = true)]
/// readonly Tool TruffleHog;
/// </code>
/// </remarks>
public static class TruffleHog
{
    public static CommandPlan Git(Tool tool, Action<TruffleHogGitSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        return Build(tool, configure);
    }

    public static CommandPlan GitHub(Tool tool, Action<TruffleHogGitHubSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        return Build(tool, configure);
    }

    public static CommandPlan Filesystem(Tool tool, Action<TruffleHogFilesystemSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        return Build(tool, configure);
    }

    public static CommandPlan Docker(Tool tool, Action<TruffleHogDockerSettings> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        return Build(tool, configure);
    }

    /// <summary>Escape hatch for sources we haven't typed (s3, gcs, slack, jira, …).</summary>
    public static CommandPlan Raw(Tool tool, params string[] arguments)
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        if (arguments is null || arguments.Length == 0)
            throw new ArgumentException("Raw requires at least one argument.", nameof(arguments));
        var s = new TruffleHogRawSettings();
        s.AddArgs(arguments);
        return s.ToCommandPlan(tool);
    }

    private static CommandPlan Build<T>(Tool tool, Action<T> configure) where T : TruffleHogSettingsBase, new()
    {
        if (tool is null) throw new ArgumentNullException(nameof(tool));
        var s = new T();
        configure(s);
        return s.ToCommandPlan(tool);
    }
}
