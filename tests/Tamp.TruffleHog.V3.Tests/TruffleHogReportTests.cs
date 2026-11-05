using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tamp.Sarif;
using Tamp.TruffleHog.V3;
using Xunit;

namespace Tamp.TruffleHog.V3.Tests;

/// <summary>
/// #8 — TruffleHog emits JSON lines only, so nothing is publishable and a missing report is
/// indistinguishable from a clean scan.
/// </summary>
/// <remarks>
/// <para>
/// Every fixture here is hand-written TruffleHog-shaped JSON. No fixture contains a string any
/// detector would match: planting a detectable pattern in this repository would trip the fleet's own
/// secret scanning, and a test that needs a real secret to prove redaction has the wrong design.
/// The placeholder <c>NOT-A-SECRET-…</c> values stand in for <c>Raw</c>/<c>RawV2</c>/<c>Redacted</c>
/// and are asserted absent from every output.
/// </para>
/// <para>
/// Shapes and values are taken from real TruffleHog 3.95.3 output.
/// </para>
/// </remarks>
public sealed class TruffleHogReportTests
{
    private const string Placeholder = "NOT-A-SECRET-PLACEHOLDER-VALUE-0123456789";
    private const string Sha = "3c1bec17683933b088aa18b3eb6ee050eecacc02";

    /// <summary>A finding record as TruffleHog writes one for the git source, secrets included.</summary>
    /// <remarks>
    /// Built by token replacement rather than interpolation: the record ends in a run of closing braces
    /// that an interpolated raw string would read as escapes.
    /// </remarks>
    private static string GitFinding(
        string detector = "AWS", bool verified = false, string file = "creds.yml", int line = 2, string commit = Sha)
        => """
           {"SourceMetadata":{"Data":{"Git":{"commit":"@COMMIT@","file":"@FILE@","email":"Test <t@example.com>","repository":"file://C:/repo","timestamp":"2026-11-05 12:35:56 +0000","line":@LINE@,"repository_local_path":"C:\\Temp\\trufflehog-80408"}}},"SourceID":1,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":2,"DetectorName":"@DETECTOR@","DetectorDescription":"AWS keys.","DecoderName":"PLAIN","Verified":@VERIFIED@,"VerificationFromCache":false,"Raw":"@SECRET@","RawV2":"@SECRET@-v2","Redacted":"@SECRET@","ExtraData":{"resource_type":"Access key","account":"https://user:@SECRET@@example.invalid"},"StructuredData":null}
           """
            .Replace("@COMMIT@", commit, StringComparison.Ordinal)
            .Replace("@FILE@", file, StringComparison.Ordinal)
            .Replace("@LINE@", line.ToString(), StringComparison.Ordinal)
            .Replace("@DETECTOR@", detector, StringComparison.Ordinal)
            .Replace("@VERIFIED@", verified ? "true" : "false", StringComparison.Ordinal)
            .Replace("@SECRET@", Placeholder, StringComparison.Ordinal);

    /// <summary>The filesystem source: a path and a line, and no commit at all.</summary>
    private static string FilesystemFinding(string file = @"C:\src\repo\config\app.yml", int line = 7)
        => """
           {"SourceMetadata":{"Data":{"Filesystem":{"file":"@FILE@","line":@LINE@}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":2,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":false,"Raw":"@SECRET@","RawV2":"@SECRET@-v2","Redacted":"@SECRET@","ExtraData":null,"StructuredData":null}
           """
            .Replace("@FILE@", file.Replace("\\", "\\\\", StringComparison.Ordinal), StringComparison.Ordinal)
            .Replace("@LINE@", line.ToString(), StringComparison.Ordinal)
            .Replace("@SECRET@", Placeholder, StringComparison.Ordinal);

    private static string Finished(long chunks = 4, long bytes = 560) =>
        $$"""{"level":"info-0","ts":"2026-11-05T07:35:39-05:00","logger":"trufflehog","msg":"finished scanning","chunks":{{chunks}},"bytes":{{bytes}},"verified_secrets":0,"unverified_secrets":1,"scan_duration":"5.5ms","trufflehog_version":"3.95.3"}""";

    private const string Running =
        """{"level":"info-0","ts":"2026-11-05T07:35:39-05:00","logger":"trufflehog","msg":"running source","source_manager_worker_id":"BkPBk","with_units":true}""";

    private const string ErrorLine =
        """{"level":"error","ts":"2026-11-05T07:35:39-05:00","logger":"trufflehog","msg":"encountered errors during scan","error":null}""";

    private static SecretScanOptions Options(
        string? commitSha = null, string? sourceRoot = null, int? exitCode = 0, bool requireBytes = true) =>
        new()
        {
            CommitSha = commitSha,
            SourceRoot = sourceRoot,
            ExitCode = exitCode,
            RequireScannedBytes = requireBytes,
            StartedAt = new DateTimeOffset(2026, 11, 5, 12, 35, 50, TimeSpan.Zero),
            EndedAt = new DateTimeOffset(2026, 11, 5, 12, 35, 56, TimeSpan.Zero),
        };

    private static string Lines(params string[] lines) => string.Join('\n', lines) + "\n";

    // ─── nothing reversible is ever emitted ───────────────────────────────

    [Fact]
    public void No_Report_Carries_Raw_RawV2_Or_Redacted()
    {
        var result = TruffleHogReport.Read(Lines(Running, GitFinding(), Finished()), Options());

        var gitlab = TruffleHogReport.ToGitLabSecretDetection(result, Options());
        var sarif = JsonSerializer.Serialize(TruffleHogReport.ToSarif(result));

        Assert.DoesNotContain(Placeholder, gitlab, StringComparison.Ordinal);
        Assert.DoesNotContain(Placeholder, sarif, StringComparison.Ordinal);
        // ExtraData is excluded as a class — it is detector-defined and has carried credential-bearing URLs.
        Assert.DoesNotContain("example.invalid", gitlab, StringComparison.Ordinal);
        Assert.DoesNotContain("example.invalid", sarif, StringComparison.Ordinal);
        // Not even in the human-readable forms.
        Assert.DoesNotContain(Placeholder, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Placeholder, result.Findings[0].ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Placeholder, result.Findings[0].SafeDescription, StringComparison.Ordinal);
    }

    [Fact]
    public void The_Finding_Type_Has_No_Property_That_Could_Hold_A_Secret()
    {
        // Structural, not a filtering step: if a property existed, some future code path would emit it.
        var names = typeof(SecretFinding).GetProperties().Select(p => p.Name).ToArray();

        Assert.DoesNotContain("Raw", names);
        Assert.DoesNotContain("RawV2", names);
        Assert.DoesNotContain("Redacted", names);
        Assert.DoesNotContain("ExtraData", names);
        Assert.DoesNotContain("StructuredData", names);
    }

    [Fact]
    public void GitLabs_Raw_Source_Code_Extract_Is_Never_Populated()
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(), Finished()), Options());

        // The schema has the field; it is an excerpt of the affected source, so it stays absent.
        Assert.DoesNotContain("raw_source_code_extract", TruffleHogReport.ToGitLabSecretDetection(result, Options()), StringComparison.Ordinal);
    }

    [Fact]
    public void The_Fingerprint_Is_Not_Derived_From_The_Secret()
    {
        // Two findings differing only in their (placeholder) secret value must fingerprint identically:
        // proof the value is not an input, so the published fingerprint cannot be attacked to recover a
        // weak secret.
        var a = TruffleHogReport.Read(Lines(GitFinding(), Finished()), Options()).Findings[0];
        var b = TruffleHogReport.Read(
            Lines(GitFinding().Replace(Placeholder, "A-COMPLETELY-DIFFERENT-PLACEHOLDER", StringComparison.Ordinal), Finished()),
            Options()).Findings[0];

        Assert.Equal(a.Fingerprint, b.Fingerprint);
        Assert.Equal(64, a.Fingerprint.Length);                      // SHA-256, lower-case hex
        Assert.Matches("^[0-9a-f]{64}$", a.Fingerprint);
    }

    [Fact]
    public void The_Fingerprint_Distinguishes_Two_Secrets_In_One_File()
    {
        // Collapsing them would under-report, which is worse than re-identifying on an edit.
        var result = TruffleHogReport.Read(Lines(GitFinding(line: 2), GitFinding(line: 9), Finished()), Options());

        Assert.Equal(2, result.Findings.Count);
        Assert.NotEqual(result.Findings[0].Fingerprint, result.Findings[1].Fingerprint);
    }

    [Fact]
    public void The_Id_Is_Stable_Across_Runs()
    {
        var first = TruffleHogReport.Read(Lines(GitFinding(), Finished()), Options()).Findings[0];
        var second = TruffleHogReport.Read(Lines(GitFinding(), Finished()), Options()).Findings[0];

        // A random UUID would make every pipeline look like it found something new.
        Assert.Equal(first.Id, second.Id);
        Assert.Matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", first.Id);
    }

    // ─── a clean scan is a receipt, not silence ───────────────────────────

    [Fact]
    public void A_Clean_Scan_Succeeds_With_An_Explicit_Empty_Report()
    {
        var result = TruffleHogReport.Read(Lines(Running, Finished(chunks: 1, bytes: 12)), Options());

        Assert.Equal(SecretScanStatus.Success, result.Status);
        Assert.Empty(result.Findings);

        var report = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, Options()))!;
        Assert.Equal("success", (string?)report["scan"]!["status"]);
        Assert.Equal("secret_detection", (string?)report["scan"]!["type"]);
        // Present and empty — the positive artifact saying this scanner ran and found nothing.
        Assert.Empty((report["vulnerabilities"] as JsonArray)!);
    }

    // ─── a failed scan is not a clean scan ────────────────────────────────

    [Fact]
    public void A_Scan_That_Examined_Nothing_Is_A_Failure_Even_Though_TruffleHog_Exited_Zero()
    {
        // Measured on 3.95.3: a nonexistent target exits 0, reports zero findings, logs an error and
        // reports chunks 0 / bytes 0. Exit code alone cannot tell this from a clean scan.
        var result = TruffleHogReport.Read(Lines(Running, ErrorLine, Finished(chunks: 0, bytes: 0)), Options(exitCode: 0));

        Assert.Equal(SecretScanStatus.Failure, result.Status);
        Assert.Contains(result.Messages, m => m.Contains("0 bytes", StringComparison.Ordinal));
        Assert.Contains(result.Messages, m => m.Contains("encountered errors", StringComparison.Ordinal));

        var report = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, Options()))!;
        Assert.Equal("failure", (string?)report["scan"]!["status"]);
        // The reason travels with the report, so an empty list isn't read as "clean".
        Assert.Contains((report["scan"]!["messages"] as JsonArray)!, m => (string?)m!["level"] == "fatal");
    }

    [Fact]
    public void An_Error_Record_Alone_Fails_The_Scan()
    {
        var result = TruffleHogReport.Read(Lines(Running, ErrorLine, Finished()), Options());

        Assert.Equal(SecretScanStatus.Failure, result.Status);
    }

    [Fact]
    public void Output_With_No_Completion_Record_Fails_The_Scan()
    {
        // A killed process: findings may be partial, so an empty or short list proves nothing.
        var result = TruffleHogReport.Read(Lines(Running, GitFinding()), Options());

        Assert.Equal(SecretScanStatus.Failure, result.Status);
        Assert.False(result.Completed);
        Assert.Contains(result.Messages, m => m.Contains("never reported finishing", StringComparison.Ordinal));
    }

    [Fact]
    public void A_Truncated_Final_Line_Does_Not_Throw()
    {
        var result = TruffleHogReport.Read(Lines(Running, Finished()) + """{"SourceMetadata":{"Data":{"Gi""", Options());

        Assert.Equal(SecretScanStatus.Success, result.Status);
    }

    [Theory]
    [InlineData(0, SecretScanStatus.Success)]
    // 183 is TruffleHog's "secrets found" code under --fail. A completed scan, not a failure —
    // reporting it as one would make every pipeline that found a secret look broken instead.
    [InlineData(183, SecretScanStatus.Success)]
    [InlineData(1, SecretScanStatus.Failure)]
    [InlineData(2, SecretScanStatus.Failure)]
    [InlineData(127, SecretScanStatus.Failure)]
    public void Exit_Codes_Map_To_Status(int exitCode, SecretScanStatus expected)
        => Assert.Equal(expected, TruffleHogReport.Read(Lines(Running, GitFinding(), Finished()), Options(exitCode: exitCode)).Status);

    [Fact]
    public void The_Zero_Bytes_Check_Can_Be_Turned_Off()
    {
        var result = TruffleHogReport.Read(Lines(Running, Finished(chunks: 0, bytes: 0)), Options(requireBytes: false));

        Assert.Equal(SecretScanStatus.Success, result.Status);
    }

    // ─── the report is additive ───────────────────────────────────────────

    [Fact]
    public void Reading_A_Report_Does_Not_Decide_Whether_The_Build_Fails()
    {
        // Findings present, exit code 0 (no --fail): the result reports them and stays Success. Whether
        // that fails the build is --fail's job and the build script's, not the reporter's.
        var result = TruffleHogReport.Read(Lines(Running, GitFinding(verified: true), Finished()), Options(exitCode: 0));

        Assert.Equal(SecretScanStatus.Success, result.Status);
        Assert.Single(result.Findings);
        Assert.Equal(1, result.VerifiedCount);
    }

    // ─── locations and the mandatory commit ───────────────────────────────

    [Fact]
    public void A_Git_Finding_Uses_Its_Own_Commit()
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(), Finished()), Options(commitSha: "ffffffffffffffffffffffffffffffffffffffff"));

        var location = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, Options(commitSha: "ffffffffffffffffffffffffffffffffffffffff")))!
            ["vulnerabilities"]![0]!["location"]!;

        // Per-finding and more precise than the pipeline's HEAD: the commit that introduced it.
        Assert.Equal(Sha, (string?)location["commit"]!["sha"]);
        Assert.Equal("creds.yml", (string?)location["file"]);
        Assert.Equal(2, (int?)location["start_line"]);
    }

    [Fact]
    public void A_Filesystem_Finding_Takes_The_Commit_From_Options()
    {
        var options = Options(commitSha: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", sourceRoot: @"C:\src\repo");
        var result = TruffleHogReport.Read(Lines(FilesystemFinding(), Finished()), options);

        Assert.Null(result.Findings[0].Commit);
        var location = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, options))!["vulnerabilities"]![0]!["location"]!;
        Assert.Equal("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", (string?)location["commit"]!["sha"]);
        Assert.Equal("config/app.yml", (string?)location["file"]);
    }

    [Fact]
    public void A_Commitless_Finding_With_No_Commit_Option_Is_Refused_Rather_Than_Invented()
    {
        var options = Options(sourceRoot: @"C:\src\repo");
        var result = TruffleHogReport.Read(Lines(FilesystemFinding(), Finished()), options);

        // GitLab's schema makes location.commit.sha mandatory. Fabricating one would anchor the finding
        // to a commit that never contained it.
        var ex = Assert.Throws<InvalidOperationException>(() => TruffleHogReport.ToGitLabSecretDetection(result, options));
        Assert.Contains("CI_COMMIT_SHA", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Placeholder, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Sarif_Needs_No_Commit()
    {
        // SARIF has no such requirement, so a filesystem scan is still publishable that way.
        var result = TruffleHogReport.Read(Lines(FilesystemFinding(), Finished()), Options(sourceRoot: @"C:\src\repo"));

        var log = TruffleHogReport.ToSarif(result);
        Assert.Equal("config/app.yml", log.Runs[0].Results![0].Locations![0].PhysicalLocation!.ArtifactLocation!.Uri);
    }

    [Theory]
    [InlineData(@"C:\src\repo\config\app.yml", @"C:\src\repo", "config/app.yml")]
    [InlineData(@"C:\SRC\repo\config\app.yml", @"C:\src\repo", "config/app.yml")]
    [InlineData("/src/repo/config/app.yml", "/src/repo", "config/app.yml")]
    [InlineData("config/app.yml", "/src/repo", "config/app.yml")]
    [InlineData("./config/app.yml", "/src/repo", "config/app.yml")]
    // Outside the root: kept, not dropped. Losing the only location a human has for a leaked
    // credential is worse than an awkward path.
    [InlineData("/elsewhere/app.yml", "/src/repo", "/elsewhere/app.yml")]
    [InlineData(@"C:\src\repo\config\app.yml", null, "C:/src/repo/config/app.yml")]
    public void Paths_Are_Made_Repository_Relative(string location, string? root, string expected)
        => Assert.Equal(expected, TruffleHogReport.Relativize(location, root?.Replace('\\', '/').TrimEnd('/')));

    // ─── dedup ────────────────────────────────────────────────────────────

    [Fact]
    public void The_Same_Finding_Reported_Twice_Is_Collapsed()
    {
        // A filesystem scan of a working tree finds the same secret in the file and again in a packed
        // git object, which is the same leak twice.
        var result = TruffleHogReport.Read(Lines(GitFinding(), GitFinding(), Finished()), Options());

        Assert.Single(result.Findings);
        Assert.Equal(1, result.Duplicates);
    }

    [Fact]
    public void Different_Detectors_At_One_Location_Stay_Distinct()
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(detector: "AWS"), GitFinding(detector: "Slack"), Finished()), Options());

        Assert.Equal(2, result.Findings.Count);
    }

    // ─── severity semantics, stated ───────────────────────────────────────

    [Theory]
    [InlineData(true, "Critical")]    // verified: the credential was confirmed live
    [InlineData(false, "Unknown")]    // nothing checked whether it works; "Unknown" is literally true
    public void Severity_Follows_Verification_And_Nothing_Else(bool verified, string expected)
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(verified: verified), Finished()), Options());

        var report = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, Options()))!;
        Assert.Equal(expected, (string?)report["vulnerabilities"]![0]!["severity"]);
    }

    [Theory]
    [InlineData(true, SarifLevel.Error)]
    [InlineData(false, SarifLevel.Warning)]
    public void Sarif_Level_Matches_The_Same_Judgment(bool verified, SarifLevel expected)
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(verified: verified), Finished()), Options());

        Assert.Equal(expected, TruffleHogReport.ToSarif(result).Runs[0].Results![0].Level);
    }

    [Fact]
    public void Verification_Being_Off_Is_Said_Out_Loud()
    {
        var options = Options();
        options.VerificationEnabled = false;
        var result = TruffleHogReport.Read(Lines(GitFinding(), Finished()), options);

        Assert.False(result.VerificationRan);
        var messages = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, options))!["scan"]!["messages"] as JsonArray;
        Assert.Contains(messages!, m => ((string?)m!["value"])!.Contains("Verification was disabled", StringComparison.Ordinal));
    }

    [Fact]
    public void Verification_Is_Read_From_The_Settings_The_Scan_Ran_With()
    {
        var settings = new TruffleHogFilesystemSettings().SetNoVerification();

        Assert.False(new SecretScanOptions().SetVerificationFrom(settings).VerificationEnabled);
        Assert.True(new SecretScanOptions().SetVerificationFrom(new TruffleHogFilesystemSettings()).VerificationEnabled);
    }

    // ─── schema conformance details that reject a whole report ────────────

    [Theory]
    // GitLab's pattern is ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$ — a trailing Z or an offset fails it,
    // and the report is rejected for it.
    [InlineData("2026-11-05T12:35:56+00:00", "2026-11-05T12:35:56")]
    [InlineData("2026-11-05T07:35:56-05:00", "2026-11-05T12:35:56")]
    public void Timestamps_Are_Utc_With_No_Zone_Suffix(string input, string expected)
        => Assert.Equal(expected, TruffleHogReport.GitLabTimestamp(DateTimeOffset.Parse(input, System.Globalization.CultureInfo.InvariantCulture)));

    [Fact]
    public void The_Report_Carries_Everything_The_Schema_Requires()
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(), Finished()), Options());
        var report = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, Options()))!.AsObject();

        foreach (var required in new[] { "version", "scan", "vulnerabilities" })
            Assert.True(report.ContainsKey(required), $"missing top-level '{required}'");

        var scan = report["scan"]!.AsObject();
        foreach (var required in new[] { "analyzer", "scanner", "type", "status", "start_time", "end_time" })
            Assert.True(scan.ContainsKey(required), $"missing scan.{required}");
        foreach (var component in new[] { "analyzer", "scanner" })
            foreach (var required in new[] { "id", "name", "version", "vendor" })
                Assert.True(scan[component]!.AsObject().ContainsKey(required), $"missing scan.{component}.{required}");
        Assert.NotNull((string?)scan["analyzer"]!["vendor"]!["name"]);

        var vulnerability = report["vulnerabilities"]![0]!.AsObject();
        foreach (var required in new[] { "id", "identifiers", "location" })
            Assert.True(vulnerability.ContainsKey(required), $"missing vulnerability.{required}");
        var identifier = (vulnerability["identifiers"] as JsonArray)![0]!.AsObject();
        foreach (var required in new[] { "type", "name", "value" })
            Assert.True(identifier.ContainsKey(required), $"missing identifier.{required}");
        Assert.Equal(Sha, (string?)vulnerability["location"]!["commit"]!["sha"]);
        Assert.Matches(@"^\d+\.\d+\.\d+$", (string?)report["version"]);
    }

    [Fact]
    public void The_Fingerprint_Rides_In_GitLabs_Own_Tracking_Signatures()
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(), Finished()), Options());
        var tracking = JsonNode.Parse(TruffleHogReport.ToGitLabSecretDetection(result, Options()))!["vulnerabilities"]![0]!["tracking"]!;

        Assert.Equal("source", (string?)tracking["type"]);
        var signature = (tracking["items"] as JsonArray)![0]!["signatures"]![0]!;
        Assert.Equal(SecretFinding.FingerprintAlgorithm, (string?)signature["algorithm"]);
        Assert.Equal(result.Findings[0].Fingerprint, (string?)signature["value"]);
    }

    [Fact]
    public void Sarif_Carries_The_Fingerprint_And_One_Rule_Per_Detector()
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(detector: "AWS"), GitFinding(detector: "Slack"), GitFinding(detector: "AWS", line: 9), Finished()), Options());

        var run = TruffleHogReport.ToSarif(result).Runs[0];
        Assert.Equal(2, run.Tool.Driver.Rules!.Count);
        Assert.Equal("TruffleHog", run.Tool.Driver.Name);
        Assert.Equal("3.95.3", run.Tool.Driver.Version);
        Assert.Equal(3, run.Results!.Count);
        Assert.Equal(result.Findings[0].Fingerprint, run.Results[0].PartialFingerprints![SecretFinding.FingerprintAlgorithm]);
    }

    [Fact]
    public void Sarif_For_A_Clean_Scan_Is_An_Empty_Run_Not_A_Missing_File()
    {
        var log = TruffleHogReport.ToSarif(TruffleHogReport.Read(Lines(Finished(chunks: 1, bytes: 12)), Options()));

        Assert.Single(log.Runs);
        Assert.Empty(log.Runs[0].Results!);
        Assert.Null(log.Runs[0].Tool.Driver.Rules);
    }

    // ─── parsing ──────────────────────────────────────────────────────────

    [Fact]
    public void The_Source_Kind_Comes_From_The_Metadata_Key()
    {
        var result = TruffleHogReport.Read(Lines(GitFinding(), FilesystemFinding(), Finished()), Options());

        Assert.Equal(["git", "filesystem"], result.Findings.Select(f => f.SourceKind));
    }

    [Fact]
    public void Scanner_Telemetry_Is_Carried_Through()
    {
        var result = TruffleHogReport.Read(Lines(Running, GitFinding(), Finished(chunks: 27, bytes: 27608)), Options());

        Assert.Equal(27, result.Chunks);
        Assert.Equal(27608, result.Bytes);
        Assert.Equal("3.95.3", result.ScannerVersion);
        Assert.True(result.Completed);
    }

    [Fact]
    public void Empty_Output_Is_A_Failure_Rather_Than_A_Clean_Scan()
    {
        var result = TruffleHogReport.Read("", Options(exitCode: null));

        Assert.Equal(SecretScanStatus.Failure, result.Status);
        Assert.False(result.Completed);
    }

    [Fact]
    public void Null_Arguments_Are_Refused()
    {
        Assert.Throws<ArgumentNullException>(() => TruffleHogReport.Read(null!, Options()));
        Assert.Throws<ArgumentNullException>(() => TruffleHogReport.Read("", null!));
        Assert.Throws<ArgumentNullException>(() => TruffleHogReport.ToSarif(null!));
    }
}
