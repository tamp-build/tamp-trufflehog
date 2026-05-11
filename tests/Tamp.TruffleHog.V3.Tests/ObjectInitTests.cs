using System.IO;
using Tamp;
using Xunit;

namespace Tamp.TruffleHog.V3.Tests;

// ---- Object-init overloads (TAM-161, 0.1.1+) ----
public sealed class ObjectInitTests
{
    private static Tool FakeTool(string name = "trufflehog") =>
        new(AbsolutePath.Create(Path.Combine(Path.GetTempPath(), name)));

    [Fact]
    public void Git_ObjectInit_Emits_Identical_Plan_To_Fluent()
    {
        var tool = FakeTool();
        var fluent = TruffleHog.Git(tool, s => s
            .SetUri("https://github.com/x/y")
            .SetBranch("main")
            .SetJson()
            .SetFail());

        var objectInit = TruffleHog.Git(tool, new TruffleHogGitSettings
        {
            Uri = "https://github.com/x/y",
            Branch = "main",
            Json = true,
            Fail = true,
        });

        Assert.Equal(fluent.Executable, objectInit.Executable);
        Assert.Equal(fluent.Arguments, objectInit.Arguments);
    }

    [Fact]
    public void GitHub_ObjectInit_Emits_Identical_Plan_To_Fluent()
    {
        var tool = FakeTool();
        var token = new Secret("GitHub PAT", "ghp_test_value_1234567890");
        var fluent = TruffleHog.GitHub(tool, s => s
            .AddOrg("acme")
            .AddRepo("https://github.com/acme/widget")
            .SetToken(token)
            .SetIncludeForks()
            .SetEndpoint("https://ghe.acme.com/api/v3"));

        var objectInit = TruffleHog.GitHub(tool, new TruffleHogGitHubSettings
        {
            Orgs = { "acme" },
            Repos = { "https://github.com/acme/widget" },
            Token = token,
            IncludeForks = true,
            Endpoint = "https://ghe.acme.com/api/v3",
        });

        Assert.Equal(fluent.Arguments, objectInit.Arguments);
        Assert.Single(objectInit.Secrets);
        Assert.Same(token, objectInit.Secrets[0]);
    }

    [Fact]
    public void Filesystem_ObjectInit_Round_Trips()
    {
        var plan = TruffleHog.Filesystem(FakeTool(), new TruffleHogFilesystemSettings
        {
            Paths = { "src/", "config/" },
            IncludePathsFile = "include.txt",
            Json = true,
        });
        var args = plan.Arguments;
        Assert.Equal("filesystem", args[0]);
        Assert.Contains("--include-paths", args);
        Assert.Contains("include.txt", args);
        Assert.Contains("--json", args);
        Assert.Contains("src/", args);
        Assert.Contains("config/", args);
        // Paths preserve insertion order; src/ before config/ in argument list.
        var srcIdx = args.ToList().IndexOf("src/");
        var cfgIdx = args.ToList().IndexOf("config/");
        Assert.True(srcIdx < cfgIdx);
    }

    [Fact]
    public void Docker_ObjectInit_Round_Trips()
    {
        var plan = TruffleHog.Docker(FakeTool(), new TruffleHogDockerSettings
        {
            Images = { "ghcr.io/x/web:1", "ghcr.io/x/api:1" },
            OnlyVerified = true,
        });
        var args = plan.Arguments;
        Assert.Equal("docker", args[0]);
        Assert.Contains("--only-verified", args);
        Assert.Contains("ghcr.io/x/web:1", args);
        Assert.Contains("ghcr.io/x/api:1", args);
    }

    [Fact]
    public void All_ObjectInit_Overloads_Return_NonNull_CommandPlan()
    {
        // Smoke test: each wrapper accepts an object-init settings argument and returns a non-null CommandPlan.
        var tool = FakeTool();
        Assert.NotNull(TruffleHog.Git(tool, new TruffleHogGitSettings { Uri = "." }));
        Assert.NotNull(TruffleHog.GitHub(tool, new TruffleHogGitHubSettings { Orgs = { "acme" } }));
        Assert.NotNull(TruffleHog.Filesystem(tool, new TruffleHogFilesystemSettings { Paths = { "." } }));
        Assert.NotNull(TruffleHog.Docker(tool, new TruffleHogDockerSettings { Images = { "alpine" } }));
    }

    [Fact]
    public void Null_Tool_Throws_For_Every_ObjectInit_Verb()
    {
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Git(null!, new TruffleHogGitSettings { Uri = "." }));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.GitHub(null!, new TruffleHogGitHubSettings { Orgs = { "acme" } }));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Filesystem(null!, new TruffleHogFilesystemSettings { Paths = { "." } }));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Docker(null!, new TruffleHogDockerSettings { Images = { "alpine" } }));
    }

    [Fact]
    public void Null_Settings_Throws_For_Every_ObjectInit_Verb()
    {
        var tool = FakeTool();
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Git(tool, (TruffleHogGitSettings)null!));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.GitHub(tool, (TruffleHogGitHubSettings)null!));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Filesystem(tool, (TruffleHogFilesystemSettings)null!));
        Assert.Throws<ArgumentNullException>(() => TruffleHog.Docker(tool, (TruffleHogDockerSettings)null!));
    }
}
