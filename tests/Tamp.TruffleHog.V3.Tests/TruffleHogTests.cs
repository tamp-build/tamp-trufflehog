using System.IO;
using Bogus;
using Tamp;
using Xunit;

namespace Tamp.TruffleHog.V3.Tests;

public sealed class TruffleHogTests
{
    private static Tool FakeTool(string name = "trufflehog") =>
        new(AbsolutePath.Create(Path.Combine(Path.GetTempPath(), name)));

    private static int IndexOf(IReadOnlyList<string> args, string value, int start = 0)
    {
        for (var i = start; i < args.Count; i++)
            if (args[i] == value) return i;
        return -1;
    }

    // ---- common shape ----

    [Fact]
    public void Every_Verb_Uses_Tool_Path()
    {
        var t = FakeTool();
        Assert.Equal(t.Executable.Value, TruffleHog.Git(t, s => s.SetUri(".")).Executable);
        Assert.Equal(t.Executable.Value, TruffleHog.GitHub(t, s => s.AddOrg("x")).Executable);
        Assert.Equal(t.Executable.Value, TruffleHog.Filesystem(t, s => s.AddPath(".")).Executable);
        Assert.Equal(t.Executable.Value, TruffleHog.Docker(t, s => s.AddImage("alpine")).Executable);
        Assert.Equal(t.Executable.Value, TruffleHog.Raw(t, "--version").Executable);
    }

    [Theory]
    [InlineData("git")]
    [InlineData("github")]
    [InlineData("filesystem")]
    [InlineData("docker")]
    public void Verbs_Begin_With_Their_Source_Token(string source)
    {
        var plan = source switch
        {
            "git" => TruffleHog.Git(FakeTool(), s => s.SetUri(".")),
            "github" => TruffleHog.GitHub(FakeTool(), s => s.AddOrg("x")),
            "filesystem" => TruffleHog.Filesystem(FakeTool(), s => s.AddPath(".")),
            "docker" => TruffleHog.Docker(FakeTool(), s => s.AddImage("alpine")),
            _ => throw new InvalidOperationException()
        };
        Assert.Equal(source, plan.Arguments[0]);
    }

    // ---- common flags ----

    [Fact]
    public void Common_Flags_All_Round_Trip_Across_Sources()
    {
        var plan = TruffleHog.Git(FakeTool(), s => s
            .SetUri(".")
            .SetJson()
            .SetOnlyVerified()
            .SetFilterEntropy(3.5)
            .SetFilterUnverified()
            .AddIncludeDetector("github")
            .AddIncludeDetector("aws")
            .AddExcludeDetector("test-detector")
            .SetConcurrency(8)
            .SetFail()
            .SetLogLevel(2)
            .SetNoUpdate()
            .SetPrintAvgDetectorTime()
            .SetResults("verified,unknown")
            .SetOutput("scan.json")
            .SetArchiveMaxSize(20_000_000)
            .SetArchiveMaxDepth(3)
            .SetArchiveTimeout("30s")
            .SetAllowVerificationOverlap());
        var args = plan.Arguments;

        Assert.Contains("--json", args);
        Assert.Contains("--only-verified", args);
        Assert.Contains("--filter-entropy", args); Assert.Contains("3.5", args);
        Assert.Contains("--filter-unverified", args);
        Assert.Contains("--include-detectors", args);
        Assert.Contains("github,aws", args);
        Assert.Contains("--exclude-detectors", args);
        Assert.Contains("test-detector", args);
        Assert.Contains("--concurrency", args); Assert.Contains("8", args);
        Assert.Contains("--fail", args);
        Assert.Contains("--log-level", args); Assert.Contains("2", args);
        Assert.Contains("--no-update", args);
        Assert.Contains("--print-avg-detector-time", args);
        Assert.Contains("--results", args); Assert.Contains("verified,unknown", args);
        Assert.Contains("--output", args); Assert.Contains("scan.json", args);
        Assert.Contains("--archive-max-size", args); Assert.Contains("20000000", args);
        Assert.Contains("--archive-max-depth", args); Assert.Contains("3", args);
        Assert.Contains("--archive-timeout", args); Assert.Contains("30s", args);
        Assert.Contains("--allow-verification-overlap", args);
    }

    [Fact]
    public void NoVerification_And_OnlyVerified_Both_Emit_When_Set()
    {
        // The CLI rejects this combo at runtime, but the wrapper should
        // emit what the user requested. We don't pre-judge.
        var plan = TruffleHog.Git(FakeTool(), s => s.SetUri(".").SetNoVerification().SetOnlyVerified());
        Assert.Contains("--no-verification", plan.Arguments);
        Assert.Contains("--only-verified", plan.Arguments);
    }

    [Fact]
    public void FilterEntropy_Uses_Invariant_Culture()
    {
        // Some locales use comma as decimal separator — verify we always
        // emit dot so trufflehog's Go parser accepts the value.
        var prev = System.Threading.Thread.CurrentThread.CurrentCulture;
        try
        {
            System.Threading.Thread.CurrentThread.CurrentCulture = new System.Globalization.CultureInfo("de-DE");
            var plan = TruffleHog.Git(FakeTool(), s => s.SetUri(".").SetFilterEntropy(3.25));
            Assert.Contains("3.25", plan.Arguments);
            Assert.DoesNotContain("3,25", plan.Arguments);
        }
        finally
        {
            System.Threading.Thread.CurrentThread.CurrentCulture = prev;
        }
    }

    // ---- git ----

    [Fact]
    public void Git_Requires_Uri()
    {
        Assert.Throws<InvalidOperationException>(() => TruffleHog.Git(FakeTool(), s => { }));
    }

    [Fact]
    public void Git_Local_Path_Round_Trips_As_Last_Positional()
    {
        var plan = TruffleHog.Git(FakeTool(), s => s.SetUri("file:///repo"));
        Assert.Equal("git", plan.Arguments[0]);
        Assert.Equal("file:///repo", plan.Arguments[^1]);
    }

    [Fact]
    public void Git_All_Source_Flags_Round_Trip()
    {
        var plan = TruffleHog.Git(FakeTool(), s => s
            .SetUri("https://github.com/x/y")
            .SetBranch("main")
            .SetHead("abc123")
            .SetSinceCommit("def456")
            .SetMaxDepth(50)
            .SetIncludePathsFile("include.txt")
            .SetExcludePathsFile("exclude.txt")
            .AddExcludeGlob("**/node_modules/**")
            .AddExcludeGlob("**/dist/**")
            .SetBare());
        var args = plan.Arguments;
        Assert.Contains("--branch", args); Assert.Contains("main", args);
        Assert.Contains("--head", args); Assert.Contains("abc123", args);
        Assert.Contains("--since-commit", args); Assert.Contains("def456", args);
        Assert.Contains("--max-depth", args); Assert.Contains("50", args);
        Assert.Contains("--include-paths", args); Assert.Contains("include.txt", args);
        Assert.Contains("--exclude-paths", args); Assert.Contains("exclude.txt", args);
        Assert.Contains("--exclude-globs", args); Assert.Contains("**/node_modules/**,**/dist/**", args);
        Assert.Contains("--bare", args);
        Assert.Equal("https://github.com/x/y", args[^1]);
    }

    // ---- github ----

    [Fact]
    public void GitHub_Requires_Repo_Or_Org()
    {
        Assert.Throws<InvalidOperationException>(() => TruffleHog.GitHub(FakeTool(), s => { }));
    }

    [Fact]
    public void GitHub_Repo_Round_Trips()
    {
        var plan = TruffleHog.GitHub(FakeTool(), s => s.AddRepo("https://github.com/x/y"));
        Assert.Equal("github", plan.Arguments[0]);
        Assert.Contains("--repo", plan.Arguments);
        Assert.Contains("https://github.com/x/y", plan.Arguments);
    }

    [Fact]
    public void GitHub_Multiple_Repos_And_Orgs_Emit_Order_Preserving()
    {
        var plan = TruffleHog.GitHub(FakeTool(), s => s
            .AddRepo("https://github.com/x/a")
            .AddRepo("https://github.com/x/b")
            .AddOrg("acme")
            .AddOrg("widgets"));
        var args = plan.Arguments;
        var r1 = IndexOf(args, "--repo");
        var r2 = IndexOf(args, "--repo", r1 + 1);
        Assert.Equal("https://github.com/x/a", args[r1 + 1]);
        Assert.Equal("https://github.com/x/b", args[r2 + 1]);
        var o1 = IndexOf(args, "--org");
        var o2 = IndexOf(args, "--org", o1 + 1);
        Assert.Equal("acme", args[o1 + 1]);
        Assert.Equal("widgets", args[o2 + 1]);
    }

    [Fact]
    public void GitHub_All_Boolean_Flags_Round_Trip()
    {
        var plan = TruffleHog.GitHub(FakeTool(), s => s
            .AddOrg("acme")
            .SetIncludeForks()
            .SetIncludeMembers()
            .SetIncludeWikis()
            .SetIssueComments()
            .SetPrComments()
            .SetGistComments()
            .SetCommitSince("2026-01-01T00:00:00Z")
            .SetEndpoint("https://ghe.acme.com/api/v3"));
        var args = plan.Arguments;
        Assert.Contains("--include-forks", args);
        Assert.Contains("--include-members", args);
        Assert.Contains("--include-wikis", args);
        Assert.Contains("--issue-comments", args);
        Assert.Contains("--pr-comments", args);
        Assert.Contains("--gist-comments", args);
        Assert.Contains("--commit-since", args);
        Assert.Contains("2026-01-01T00:00:00Z", args);
        Assert.Contains("--endpoint", args);
        Assert.Contains("https://ghe.acme.com/api/v3", args);
    }

    [Fact]
    public void GitHub_Token_Reveals_In_Plan_And_Registers_For_Redaction()
    {
        var token = new Secret("GitHub PAT", "ghp_test_value_1234567890");
        var plan = TruffleHog.GitHub(FakeTool(), s => s.AddOrg("acme").SetToken(token));
        var args = plan.Arguments;
        Assert.Contains("--token", args);
        Assert.Contains("ghp_test_value_1234567890", args);
        Assert.Single(plan.Secrets);
        Assert.Same(token, plan.Secrets[0]);
    }

    [Fact]
    public void GitHub_No_Token_Yields_Empty_Secrets()
    {
        var plan = TruffleHog.GitHub(FakeTool(), s => s.AddOrg("acme"));
        Assert.Empty(plan.Secrets);
        Assert.DoesNotContain("--token", plan.Arguments);
    }

    // ---- filesystem ----

    [Fact]
    public void Filesystem_Requires_At_Least_One_Path()
    {
        Assert.Throws<InvalidOperationException>(() => TruffleHog.Filesystem(FakeTool(), s => { }));
    }

    [Fact]
    public void Filesystem_Multiple_Paths_Tail_The_Verb()
    {
        var plan = TruffleHog.Filesystem(FakeTool(), s => s
            .AddPath("src/")
            .AddPath("config/")
            .SetIncludePathsFile("include.txt"));
        var args = plan.Arguments;
        Assert.Equal("filesystem", args[0]);
        Assert.Contains("--include-paths", args);
        Assert.Equal("src/", args[^2]);
        Assert.Equal("config/", args[^1]);
    }

    // ---- docker ----

    [Fact]
    public void Docker_Requires_At_Least_One_Image()
    {
        Assert.Throws<InvalidOperationException>(() => TruffleHog.Docker(FakeTool(), s => { }));
    }

    [Fact]
    public void Docker_Multiple_Images_Emit_Order_Preserving()
    {
        var plan = TruffleHog.Docker(FakeTool(), s => s
            .AddImage("ghcr.io/x/web:1")
            .AddImage("ghcr.io/x/api:1"));
        var args = plan.Arguments;
        var i1 = IndexOf(args, "--image");
        var i2 = IndexOf(args, "--image", i1 + 1);
        Assert.Equal("ghcr.io/x/web:1", args[i1 + 1]);
        Assert.Equal("ghcr.io/x/api:1", args[i2 + 1]);
    }

    // ---- raw ----

    [Fact]
    public void Raw_Requires_Args()
    {
        Assert.Throws<ArgumentException>(() => TruffleHog.Raw(FakeTool()));
    }

    [Fact]
    public void Raw_Forwards_Verbatim()
    {
        var plan = TruffleHog.Raw(FakeTool(), "s3", "--bucket", "my-bucket");
        Assert.Equal(["s3", "--bucket", "my-bucket"], plan.Arguments);
    }

    // ---- nulls ----

    [Fact]
    public void Null_Tool_Throws_For_Every_Verb()
    {
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Git(null!, s => s.SetUri(".")));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.GitHub(null!, s => s.AddOrg("x")));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Filesystem(null!, s => s.AddPath(".")));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Docker(null!, s => s.AddImage("x")));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Raw(null!, "--version"));
    }

    [Fact]
    public void Null_Configure_Throws_For_Required_Verbs()
    {
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Git(FakeTool(), (Action<TruffleHogGitSettings>)null!));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.GitHub(FakeTool(), (Action<TruffleHogGitHubSettings>)null!));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Filesystem(FakeTool(), (Action<TruffleHogFilesystemSettings>)null!));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Docker(FakeTool(), (Action<TruffleHogDockerSettings>)null!));
    }

    [Fact]
    public void Working_Directory_And_Env_Flow_To_Plan()
    {
        var cwd = Path.GetTempPath();
        var plan = TruffleHog.Git(FakeTool(), s => s
            .SetUri(".")
            .SetWorkingDirectory(cwd)
            .SetEnv("TRUFFLEHOG_CI", "true"));
        Assert.Equal(cwd, plan.WorkingDirectory);
        Assert.Equal("true", plan.Environment["TRUFFLEHOG_CI"]);
    }

    [Fact]
    public void Many_Detectors_Preserve_Order_Under_Random_Names()
    {
        // --include-detectors joins with comma, so order is observable
        // to TruffleHog's detector loader.
        var faker = new Faker();
        var detectors = Enumerable.Range(0, 7).Select(_ => faker.Random.AlphaNumeric(8)).ToArray();
        var plan = TruffleHog.Git(FakeTool(), s =>
        {
            s.SetUri(".");
            foreach (var d in detectors) s.AddIncludeDetector(d);
        });
        var idx = IndexOf(plan.Arguments, "--include-detectors");
        Assert.Equal(string.Join(',', detectors), plan.Arguments[idx + 1]);
    }
}
