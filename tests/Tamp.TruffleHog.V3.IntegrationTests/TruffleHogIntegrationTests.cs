using System.IO;
using Tamp;
using Xunit;
using Xunit.Abstractions;

namespace Tamp.TruffleHog.V3.IntegrationTests;

/// <summary>
/// Exercises the wrapper against a real TruffleHog 3.x binary. We
/// scan tiny local fixtures — no network calls, no API verification.
/// </summary>
public sealed class TruffleHogIntegrationTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly AbsolutePath _workdir;

    public TruffleHogIntegrationTests(ITestOutputHelper output)
    {
        _output = output;
        _workdir = AbsolutePath.Create(Path.Combine(Path.GetTempPath(), $"tamp-th-it-{Guid.NewGuid():N}"));
        Directory.CreateDirectory(_workdir.Value);

        // A file with no secrets — clean scan baseline.
        File.WriteAllText(Path.Combine(_workdir.Value, "clean.txt"), """
            This is a perfectly innocuous text file.
            No secrets here. Just words.
            """);

        // Synthetic Slack webhook URL — trufflehog's SlackWebhook
        // detector fires on this pattern reliably. Other shapes we
        // tried (AWS docs example, generic RSA PEM) are filtered out
        // as known-fake or fail PEM structural validation.
        //
        // Hosts and tokens are concatenated at runtime so this file
        // doesn't itself trip a secret scan on the wrapper repo.
        var host = "https://hooks." + "slack" + ".com/services";
        File.WriteAllText(Path.Combine(_workdir.Value, "dirty.txt"), $"""
            # synthetic incident-bot webhook (fake)
            INCIDENT_WEBHOOK_URL={host}/T08ZXKLMN/B0907QWERTY/aB3xR9p2zQ7vM4nL5kJ6hF8d
            """);
    }

    private static string? ResolveOnPath(string baseName)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        var names = OperatingSystem.IsWindows()
            ? new[] { $"{baseName}.exe", $"{baseName}.cmd", $"{baseName}.bat", baseName }
            : new[] { baseName };
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrEmpty(dir)) continue;
            foreach (var n in names)
            {
                var c = Path.Combine(dir, n);
                if (File.Exists(c)) return c;
            }
        }
        return null;
    }

    private static Tool ResolveTool() =>
        new(AbsolutePath.Create(ResolveOnPath("trufflehog")
            ?? throw new InvalidOperationException("trufflehog not found on PATH. Install: https://github.com/trufflesecurity/trufflehog")));

    private CaptureResult Run(CommandPlan plan)
    {
        _output.WriteLine($"$ {plan.Executable} {string.Join(' ', plan.Arguments)}");
        var result = ProcessRunner.Capture(plan);
        foreach (var line in result.Lines)
            _output.WriteLine($"  [{line.Type}] {line.Text}");
        _output.WriteLine($"  → exit {result.ExitCode}");
        return result;
    }

    [Fact]
    public void Raw_Version_Reports_3_x()
    {
        var tool = ResolveTool();
        var plan = TruffleHog.Raw(tool, "--version");
        var result = Run(plan);
        Assert.Equal(0, result.ExitCode);
        var combined = result.StdoutText + result.StderrText;
        Assert.Matches(@"3\.\d+\.\d+", combined);
    }

    [Fact]
    public void Filesystem_Clean_File_Exits_Zero()
    {
        var tool = ResolveTool();
        var plan = TruffleHog.Filesystem(tool, s => s
            .AddPath(Path.Combine(_workdir.Value, "clean.txt"))
            .SetNoVerification()
            .SetNoUpdate());
        var result = Run(plan);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void Filesystem_Dirty_File_Without_Fail_Still_Exits_Zero()
    {
        // Default behavior: report findings but exit 0. CI gate requires
        // explicit --fail.
        var tool = ResolveTool();
        var plan = TruffleHog.Filesystem(tool, s => s
            .AddPath(Path.Combine(_workdir.Value, "dirty.txt"))
            .SetNoVerification()
            .SetNoUpdate());
        var result = Run(plan);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void Filesystem_Dirty_File_With_Fail_Exits_NonZero()
    {
        var tool = ResolveTool();
        var plan = TruffleHog.Filesystem(tool, s => s
            .AddPath(Path.Combine(_workdir.Value, "dirty.txt"))
            .SetNoVerification()
            .SetNoUpdate()
            .SetFail());
        var result = Run(plan);
        Assert.NotEqual(0, result.ExitCode);
    }

    [Fact]
    public void Filesystem_Json_Output_Is_Parseable()
    {
        var tool = ResolveTool();
        var plan = TruffleHog.Filesystem(tool, s => s
            .AddPath(Path.Combine(_workdir.Value, "dirty.txt"))
            .SetNoVerification()
            .SetNoUpdate()
            .SetJson());
        var result = Run(plan);
        Assert.Equal(0, result.ExitCode);
        // Each line of JSON output should parse as a top-level JSON object.
        // (TruffleHog emits NDJSON, not a JSON array.)
        var lines = result.StdoutText
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(l => l.TrimStart().StartsWith('{'))
            .ToList();
        Assert.NotEmpty(lines);
        foreach (var line in lines)
        {
            using var doc = System.Text.Json.JsonDocument.Parse(line);
            Assert.Equal(System.Text.Json.JsonValueKind.Object, doc.RootElement.ValueKind);
        }
    }

    [Fact]
    public void Filesystem_ExcludeDetectors_Suppresses_SlackWebhook_Detection()
    {
        // With SlackWebhook detector excluded, the fake webhook URL
        // shouldn't trigger --fail. Demonstrates the detector filter
        // actually flows through to trufflehog.
        var tool = ResolveTool();
        var plan = TruffleHog.Filesystem(tool, s => s
            .AddPath(Path.Combine(_workdir.Value, "dirty.txt"))
            .SetNoVerification()
            .SetNoUpdate()
            .SetFail()
            .AddExcludeDetector("SlackWebhook"));
        var result = Run(plan);
        Assert.Equal(0, result.ExitCode);
    }

    public void Dispose()
    {
        try { Directory.Delete(_workdir.Value, recursive: true); } catch { }
    }
}
