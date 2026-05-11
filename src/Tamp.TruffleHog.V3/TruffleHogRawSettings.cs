namespace Tamp.TruffleHog.V3;

/// <summary>Escape hatch for source/flag combinations we haven't typed (e.g. s3, slack, jira).</summary>
public sealed class TruffleHogRawSettings : TruffleHogSettingsBase
{
    public List<string> RawArguments { get; } = [];

    public TruffleHogRawSettings AddArgs(params string[] args) { RawArguments.AddRange(args); return this; }

    protected override IEnumerable<string> BuildSourceArguments() => RawArguments;
}
