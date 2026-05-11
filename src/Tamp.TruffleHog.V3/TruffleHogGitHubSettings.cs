namespace Tamp.TruffleHog.V3;

/// <summary>
/// Settings for <c>trufflehog github</c> — scan GitHub repos / orgs.
/// The <see cref="Token"/> is typed as <see cref="Secret"/> so it
/// joins the runner's redaction table — anything that reaches a log
/// pipeline will be masked.
/// </summary>
public sealed class TruffleHogGitHubSettings : TruffleHogSettingsBase
{
    /// <summary>Repos to scan. Repeated as <c>--repo &lt;url&gt;</c>.</summary>
    public List<string> Repos { get; } = [];

    /// <summary>Orgs to scan. Repeated as <c>--org &lt;name&gt;</c>.</summary>
    public List<string> Orgs { get; } = [];

    /// <summary>GitHub PAT for API access. Stays in the redaction table.</summary>
    public Secret? Token { get; set; }

    /// <summary>Scan forks. Maps to <c>--include-forks</c>.</summary>
    public bool IncludeForks { get; set; }

    /// <summary>Scan org members' personal repos. Maps to <c>--include-members</c>.</summary>
    public bool IncludeMembers { get; set; }

    /// <summary>Scan wiki content. Maps to <c>--include-wikis</c>.</summary>
    public bool IncludeWikis { get; set; }

    /// <summary>Scan issue comments. Maps to <c>--issue-comments</c>.</summary>
    public bool IssueComments { get; set; }

    /// <summary>Scan PR comments. Maps to <c>--pr-comments</c>.</summary>
    public bool PrComments { get; set; }

    /// <summary>Scan gist comments. Maps to <c>--gist-comments</c>.</summary>
    public bool GistComments { get; set; }

    /// <summary>Only scan commits since this date (RFC3339). Maps to <c>--commit-since</c>.</summary>
    public string? CommitSince { get; set; }

    /// <summary>Custom Enterprise GitHub host. Maps to <c>--endpoint</c>.</summary>
    public string? Endpoint { get; set; }

    public TruffleHogGitHubSettings AddRepo(string url) { Repos.Add(url); return this; }
    public TruffleHogGitHubSettings AddOrg(string name) { Orgs.Add(name); return this; }
    public TruffleHogGitHubSettings SetToken(Secret? token) { Token = token; return this; }
    public TruffleHogGitHubSettings SetIncludeForks(bool v = true) { IncludeForks = v; return this; }
    public TruffleHogGitHubSettings SetIncludeMembers(bool v = true) { IncludeMembers = v; return this; }
    public TruffleHogGitHubSettings SetIncludeWikis(bool v = true) { IncludeWikis = v; return this; }
    public TruffleHogGitHubSettings SetIssueComments(bool v = true) { IssueComments = v; return this; }
    public TruffleHogGitHubSettings SetPrComments(bool v = true) { PrComments = v; return this; }
    public TruffleHogGitHubSettings SetGistComments(bool v = true) { GistComments = v; return this; }
    public TruffleHogGitHubSettings SetCommitSince(string isoDate) { CommitSince = isoDate; return this; }
    public TruffleHogGitHubSettings SetEndpoint(string endpoint) { Endpoint = endpoint; return this; }

    protected override IEnumerable<string> BuildSourceArguments()
    {
        if (Repos.Count == 0 && Orgs.Count == 0)
            throw new InvalidOperationException("trufflehog github: at least one --repo or --org is required.");
        yield return "github";
        foreach (var r in Repos) { yield return "--repo"; yield return r; }
        foreach (var o in Orgs) { yield return "--org"; yield return o; }
        if (Token is not null) { yield return "--token"; yield return Token.Reveal(); }
        if (!string.IsNullOrEmpty(Endpoint)) { yield return "--endpoint"; yield return Endpoint!; }
        if (IncludeForks) yield return "--include-forks";
        if (IncludeMembers) yield return "--include-members";
        if (IncludeWikis) yield return "--include-wikis";
        if (IssueComments) yield return "--issue-comments";
        if (PrComments) yield return "--pr-comments";
        if (GistComments) yield return "--gist-comments";
        if (!string.IsNullOrEmpty(CommitSince)) { yield return "--commit-since"; yield return CommitSince!; }
    }

    protected override IReadOnlyList<Secret> CollectSecrets() =>
        Token is null ? Array.Empty<Secret>() : new[] { Token };
}
