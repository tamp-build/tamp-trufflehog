using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Tamp.Sarif;

namespace Tamp.TruffleHog.V3;

/// <summary>
/// Turns TruffleHog's JSON-lines output into a report a CI system can publish: GitLab's native
/// <c>secret_detection</c> report, or SARIF 2.1.0.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> TruffleHog emits JSON lines and nothing else, so a consumer has nothing to
/// publish and a CI system has no record that a secret scan ran at all. The dangerous half of that is
/// the second: <b>a missing report is indistinguishable from a clean scan</b>, so an absent report, a
/// skipped scan and a crashed scan all look alike downstream. That is a silent failure in a security
/// control, and it is not hypothetical — TruffleHog 3.95.3 exits <b>0</b> when handed a path that does
/// not exist, reporting zero findings.
/// </para>
/// <para>
/// <b>Status is earned, not assumed.</b> <see cref="SecretScanStatus.Success"/> requires the scan's own
/// completion record, a non-failing exit code (0, or 183 for "secrets found" under <c>--fail</c>), no
/// error record, and — by default — more than zero bytes examined. A clean run then produces an
/// explicit empty report: a positive receipt saying this scanner ran and found nothing.
/// </para>
/// <para>
/// <b>Nothing reversible is emitted, by construction.</b> <c>Raw</c>, <c>RawV2</c>, <c>Redacted</c> and
/// <c>ExtraData</c> are never read out of the JSON, so no downstream code can emit them — see
/// <see cref="SecretFinding"/>, including the measurement showing TruffleHog's <c>Redacted</c> is
/// byte-identical to <c>Raw</c> for the AWS detector. GitLab's
/// <c>raw_source_code_extract</c> field is deliberately never populated.
/// </para>
/// <para>
/// <b>Additive only.</b> This reads output TruffleHog already produced. It does not change the
/// command, does not decide whether the build fails — keep using <c>--fail</c> / <c>SetFail()</c> for
/// that — and does not turn verification on. Proving a report format should never involve
/// authenticating anyone's credentials anywhere.
/// </para>
/// </remarks>
public static class TruffleHogReport
{
    /// <summary>
    /// The default GitLab security-report schema version declared in the emitted report: a
    /// <b>floor</b>, not the newest published patch.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A consumer validates against the schema bundled in its own release, not the newest one
    /// upstream.</b> A self-managed instance a release or two behind bundles an earlier patch, does
    /// not recognise a newer declared version, falls back to its own newest, and attaches a
    /// schema-version warning to every ingested finding. That is noise on every security report in
    /// every pipeline — the kind of warning that trains people to stop reading warnings, and that
    /// makes a genuine schema problem indistinguishable from the standing one.
    /// </para>
    /// <para>
    /// So the declared version is a compatibility claim and should be the <em>lowest</em> version
    /// whose schema this document satisfies, not the highest that exists. <c>15.2.0</c> is that
    /// floor, verified rather than assumed: the findings, clean and failure reports this emitter
    /// produces were each validated against the published <c>15.2.0</c>, <c>15.2.1</c> and
    /// <c>15.2.5</c> schemas, and all three accept all three. The required-field set does not move
    /// within a patch line.
    /// </para>
    /// <para>
    /// Override it with <see cref="SecretScanOptions.GitLabSchemaVersion"/> when the consuming
    /// instance's bundled version is known and an exact match is wanted. (tamp-trufflehog#11)
    /// </para>
    /// </remarks>
    public const string GitLabSchemaVersion = "15.2.0";

    /// <summary>TruffleHog's completion log record: the positive signal that a scan finished.</summary>
    private const string FinishedMessage = "finished scanning";

    // ─── reading ──────────────────────────────────────────────────────────

    /// <summary>
    /// Parse TruffleHog's <c>--json</c> output. Accepts the raw stream, log records and all: finding
    /// records and TruffleHog's own log lines share stdout, and the log lines carry the completion
    /// telemetry that decides <see cref="SecretScanResult.Status"/>, so both are needed.
    /// </summary>
    /// <param name="output">TruffleHog's JSON-lines output. Blank lines and unparseable lines are skipped.</param>
    /// <param name="options">Commit, source root, exit code and timing. Never null.</param>
    public static SecretScanResult Read(string output, SecretScanOptions options)
    {
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (options is null) throw new ArgumentNullException(nameof(options));

        var root = options.SourceRoot is { Length: > 0 } r ? NormalizeDirectory(r) : null;
        var findings = new List<SecretFinding>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var messages = new List<string>();
        var duplicates = 0;
        var completed = false;
        var errored = false;
        long? chunks = null;
        long? bytes = null;
        string? version = null;

        foreach (var line in output.Split('\n'))
        {
            var text = line.Trim();
            if (text.Length == 0 || text[0] != '{') continue;

            JsonObject? record;
            try { record = JsonNode.Parse(text) as JsonObject; }
            catch (JsonException) { continue; }        // a partial line from a killed process
            if (record is null) continue;

            if (record["DetectorName"] is not null)
            {
                var finding = ReadFinding(record, root);
                if (finding is null) continue;
                if (seen.Add(finding.Fingerprint)) findings.Add(finding);
                else duplicates++;
                continue;
            }

            // A log record. Two of them matter.
            var message = (string?)record["msg"];
            if (string.Equals(message, FinishedMessage, StringComparison.Ordinal))
            {
                completed = true;
                chunks = (long?)record["chunks"];
                bytes = (long?)record["bytes"];
                version = (string?)record["trufflehog_version"];
            }
            else if (((string?)record["level"])?.StartsWith("error", StringComparison.OrdinalIgnoreCase) == true)
            {
                errored = true;
                messages.Add($"TruffleHog reported an error during the scan: {message ?? "(no message)"}.");
            }
        }

        // Status. Every leg here is a way a scan can look clean without having been one.
        var status = SecretScanStatus.Success;

        if (!completed)
        {
            status = SecretScanStatus.Failure;
            messages.Add(
                "TruffleHog never reported finishing, so the output is truncated or the process died mid-scan. "
                + "An empty finding list from this run says nothing about the code.");
        }

        if (errored) status = SecretScanStatus.Failure;

        if (options.ExitCode is { } exitCode && exitCode != 0 && exitCode != SecretScanOptions.SecretsFoundExitCode)
        {
            status = SecretScanStatus.Failure;
            messages.Add($"TruffleHog exited {exitCode}; 0 (clean) and {SecretScanOptions.SecretsFoundExitCode} (secrets found, under --fail) are the completing codes.");
        }

        if (options.RequireScannedBytes && bytes is 0)
        {
            status = SecretScanStatus.Failure;
            messages.Add(
                "TruffleHog examined 0 bytes, so it scanned nothing — a missing or unreadable target, "
                + "or everything excluded. It exits 0 in that case, which is why this is checked separately.");
        }

        return new SecretScanResult
        {
            Findings = findings,
            Status = status,
            Messages = messages,
            ScannerVersion = version,
            Chunks = chunks,
            Bytes = bytes,
            Completed = completed,
            VerificationRan = options.VerificationEnabled,
            Duplicates = duplicates,
        };
    }

    /// <summary><see cref="Read(string, SecretScanOptions)"/> over a file TruffleHog's output was captured to.</summary>
    public static SecretScanResult ReadFile(AbsolutePath output, SecretScanOptions options)
    {
        if (output is null) throw new ArgumentNullException(nameof(output));
        return Read(File.ReadAllText(output.Value), options);
    }

    /// <summary>
    /// The safe projection of one TruffleHog finding record. Only these fields are read; the record's
    /// <c>Raw</c>, <c>RawV2</c>, <c>Redacted</c> and <c>ExtraData</c> are left in the JSON and never
    /// reach a type that could carry them onward. <c>ExtraData</c> is excluded as a class: it is
    /// detector-defined and has carried credential-bearing URLs.
    /// </summary>
    private static SecretFinding? ReadFinding(JsonObject record, string? normalizedRoot)
    {
        if ((string?)record["DetectorName"] is not { Length: > 0 } detector) return null;

        // SourceMetadata.Data is a one-key object whose key names the source: Git, Filesystem, Docker, …
        var data = record["SourceMetadata"]?["Data"] as JsonObject;
        var source = data?.FirstOrDefault(kv => kv.Value is JsonObject);
        var kind = source?.Key is { Length: > 0 } k ? k.ToLowerInvariant() : "unknown";
        var fields = source?.Value as JsonObject;

        var file = (string?)fields?["file"];
        return new SecretFinding
        {
            Detector = detector,
            Verified = (bool?)record["Verified"] ?? false,
            SourceKind = kind,
            File = file is { Length: > 0 } ? Relativize(file, normalizedRoot) : null,
            Line = (int?)fields?["line"],
            Commit = (string?)fields?["commit"] is { Length: > 0 } commit ? commit : null,
            Decoder = (string?)record["DecoderName"] is { Length: > 0 } decoder ? decoder : null,
        };
    }

    // ─── GitLab secret_detection ──────────────────────────────────────────

    /// <summary>
    /// GitLab's native <c>secret_detection</c> report, for <c>artifacts:reports:secret_detection</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A clean scan yields <c>status: "success"</c> with an empty <c>vulnerabilities</c> array — the
    /// positive receipt. A failed scan yields <c>status: "failure"</c> with
    /// <see cref="SecretScanResult.Messages"/> in <c>scan.messages</c>, so a consumer sees the reason
    /// instead of an empty list it would otherwise read as "clean".
    /// </para>
    /// <para>
    /// <b>Severity mapping, stated rather than implied.</b> A verified finding is <c>Critical</c>: the
    /// credential was confirmed live. An unverified finding is <c>Unknown</c>, which is a real value in
    /// GitLab's enum and is the literally accurate one — nothing checked whether it works. Neither is
    /// inferred from entropy or detector identity, and the scanner's own thresholds are untouched.
    /// </para>
    /// <para>
    /// <b>The commit is mandatory.</b> GitLab's schema requires <c>location.commit.sha</c>. Findings
    /// from the <c>git</c> source carry their own; everything else needs
    /// <see cref="SecretScanOptions.CommitSha"/>, and this throws without it rather than inventing one.
    /// </para>
    /// <para>
    /// <see cref="SecretFinding.Fingerprint"/> rides in <c>tracking.signatures</c> — GitLab's own
    /// mechanism for following a finding across runs, so no invented field is needed.
    /// </para>
    /// <para>
    /// <b>This and <see cref="ToSarif"/> are alternatives for ingestion, not a pair to publish
    /// together.</b> GitLab ingests the two report types independently and neither deduplicates
    /// against the other, so publishing both puts every secret in the security dashboard twice —
    /// once as a secret-detection finding and once, through the SARIF, as a generic finding at a
    /// different severity. Publish this one and keep the SARIF as a plain build artifact, or publish
    /// the SARIF alone. (tamp-trufflehog#11)
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// A finding has no commit and <see cref="SecretScanOptions.CommitSha"/> was not set.
    /// </exception>
    public static string ToGitLabSecretDetection(SecretScanResult result, SecretScanOptions options)
    {
        if (result is null) throw new ArgumentNullException(nameof(result));
        if (options is null) throw new ArgumentNullException(nameof(options));

        var missingCommit = result.Findings.FirstOrDefault(f => f.Commit is null && options.CommitSha is null);
        if (missingCommit is not null)
            throw new InvalidOperationException(
                $"GitLab's secret-detection schema requires location.commit.sha, and this finding has no commit "
                + $"({missingCommit}). The git source reports a commit per finding; a filesystem or docker scan does "
                + "not, so set SecretScanOptions.CommitSha — in GitLab CI, CI_COMMIT_SHA.");

        var endedAt = options.EndedAt ?? DateTimeOffset.UtcNow;
        var startedAt = options.StartedAt ?? endedAt;

        var vulnerabilities = new JsonArray();
        foreach (var finding in result.Findings)
        {
            var location = new JsonObject
            {
                ["commit"] = new JsonObject { ["sha"] = finding.Commit ?? options.CommitSha },
            };
            if (finding.File is { } file) location["file"] = file;
            if (finding.Line is { } line) { location["start_line"] = line; location["end_line"] = line; }

            var trackingItem = new JsonObject
            {
                ["signatures"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["algorithm"] = SecretFinding.FingerprintAlgorithm,
                        ["value"] = finding.Fingerprint,
                    },
                },
            };
            if (finding.File is { } trackedFile) trackingItem["file"] = trackedFile;
            if (finding.Line is { } trackedLine) { trackingItem["start_line"] = trackedLine; trackingItem["end_line"] = trackedLine; }

            vulnerabilities.Add(new JsonObject
            {
                ["id"] = finding.Id,
                // Schema: "must not include the finding's specific information". The detector, nothing else.
                ["name"] = $"{finding.Detector} credential",
                ["description"] = finding.SafeDescription,
                ["severity"] = finding.Verified ? "Critical" : "Unknown",
                ["solution"] = "Rotate the credential at the provider, then remove it from the repository's history. "
                    + "Rotation comes first: the value is already published to everyone who can read the history.",
                ["identifiers"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["type"] = "trufflehog_detector",
                        ["name"] = $"TruffleHog detector: {finding.Detector}",
                        ["value"] = finding.Detector,
                    },
                },
                ["location"] = location,
                ["tracking"] = new JsonObject
                {
                    ["type"] = "source",
                    ["items"] = new JsonArray { trackingItem },
                },
                // raw_source_code_extract is deliberately absent: it is an excerpt of the secret.
            });
        }

        var messages = new JsonArray();
        foreach (var message in result.Messages)
            messages.Add(new JsonObject
            {
                ["level"] = result.Status == SecretScanStatus.Failure ? "fatal" : "warn",
                ["value"] = message,
            });
        if (!result.VerificationRan)
            messages.Add(new JsonObject
            {
                ["level"] = "info",
                ["value"] = "Verification was disabled, so no finding was checked against its provider: "
                    + "every finding is reported as unverified regardless of whether the credential is live.",
            });

        var scan = new JsonObject
        {
            ["analyzer"] = new JsonObject
            {
                ["id"] = "tamp-trufflehog",
                ["name"] = "Tamp.TruffleHog.V3",
                ["version"] = WrapperVersion,
                ["vendor"] = new JsonObject { ["name"] = "Tamp" },
                ["url"] = "https://github.com/tamp-build/tamp-trufflehog",
            },
            ["scanner"] = new JsonObject
            {
                ["id"] = "trufflehog",
                ["name"] = "TruffleHog",
                ["version"] = result.ScannerVersion ?? "unknown",
                ["vendor"] = new JsonObject { ["name"] = "Truffle Security" },
                ["url"] = "https://github.com/trufflesecurity/trufflehog",
            },
            ["type"] = "secret_detection",
            ["status"] = result.Status == SecretScanStatus.Success ? "success" : "failure",
            ["start_time"] = GitLabTimestamp(startedAt),
            ["end_time"] = GitLabTimestamp(endedAt),
        };
        if (messages.Count > 0) scan["messages"] = messages;

        var report = new JsonObject
        {
            ["version"] = options.GitLabSchemaVersion,
            ["scan"] = scan,
            ["vulnerabilities"] = vulnerabilities,
        };

        return report.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Write <see cref="ToGitLabSecretDetection"/> to <paramref name="path"/>, creating its directory.
    /// A clean scan still writes the file — that is the point.
    /// </summary>
    public static void WriteGitLabSecretDetection(SecretScanResult result, AbsolutePath path, SecretScanOptions options)
    {
        if (path is null) throw new ArgumentNullException(nameof(path));
        var json = ToGitLabSecretDetection(result, options);
        var directory = Path.GetDirectoryName(path.Value);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory!);
        File.WriteAllText(path.Value, json);
    }

    // ─── SARIF ────────────────────────────────────────────────────────────

    /// <summary>
    /// SARIF 2.1.0: portable, and ingested natively by GitLab 19.1+ (Ultimate) under
    /// <c>artifacts:reports:sarif</c>, as well as by GitHub code scanning.
    /// </summary>
    /// <remarks>
    /// One rule per detector that fired, so a consumer can group and suppress by detector. The
    /// fingerprint goes in <c>partialFingerprints</c>, SARIF's equivalent of GitLab's tracking
    /// signatures. A verified finding is <c>error</c>; an unverified one is <c>warning</c>, matching
    /// the Critical/Unknown split in the GitLab report — the same judgment, in each format's own
    /// vocabulary. No message, rule description or location carries the secret or an excerpt of it.
    /// </remarks>
    public static SarifLog ToSarif(SecretScanResult result)
    {
        if (result is null) throw new ArgumentNullException(nameof(result));

        var rules = result.Findings
            .Select(f => f.Detector)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(d => d, StringComparer.Ordinal)
            .Select(detector => new SarifRule
            {
                Id = RuleId(detector),
                Name = $"{detector}Credential",
                ShortDescription = new SarifMultiformatMessage { Text = $"{detector} credential detected" },
                FullDescription = new SarifMultiformatMessage
                {
                    Text = $"TruffleHog's {detector} detector matched a credential pattern. "
                        + "Rotate the credential at the provider, then remove it from the repository's history.",
                },
                DefaultConfiguration = new SarifReportingConfiguration { Level = SarifLevel.Error },
            })
            .ToList();

        var results = result.Findings.Select(finding => new SarifResult
        {
            RuleId = RuleId(finding.Detector),
            Level = finding.Verified ? SarifLevel.Error : SarifLevel.Warning,
            Message = new SarifMessage { Text = finding.SafeDescription },
            Locations = finding.File is null ? null :
            [
                new SarifLocation
                {
                    PhysicalLocation = new SarifPhysicalLocation
                    {
                        ArtifactLocation = new SarifArtifactLocation { Uri = finding.File },
                        Region = finding.Line is { } line ? new SarifRegion { StartLine = line } : null,
                    },
                },
            ],
            PartialFingerprints = new Dictionary<string, string>
            {
                [SecretFinding.FingerprintAlgorithm] = finding.Fingerprint,
            },
            Properties = new SarifPropertyBag
            {
                Tags = finding.Verified ? ["security", "secret", "verified"] : ["security", "secret", "unverified"],
            },
        }).ToList();

        return new SarifLog
        {
            Runs =
            [
                new SarifRun
                {
                    Tool = new SarifTool
                    {
                        Driver = new SarifToolComponent
                        {
                            Name = "TruffleHog",
                            Version = result.ScannerVersion,
                            InformationUri = "https://github.com/trufflesecurity/trufflehog",
                            Rules = rules.Count > 0 ? rules : null,
                        },
                    },
                    Results = results,
                },
            ],
        };
    }

    /// <summary>Write <see cref="ToSarif"/> to <paramref name="path"/>. A clean scan writes an empty run.</summary>
    public static void WriteSarif(SecretScanResult result, AbsolutePath path)
    {
        if (path is null) throw new ArgumentNullException(nameof(path));
        var directory = Path.GetDirectoryName(path.Value);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory!);
        SarifWriter.WriteToFile(ToSarif(result), path);
    }

    private static string RuleId(string detector) => $"trufflehog/{detector}";

    /// <summary>
    /// GitLab's schema: <c>yyyy-mm-ddThh:mm:ss</c>, UTC, with <b>no</b> timezone suffix. An offset or a
    /// trailing <c>Z</c> fails the pattern, and the whole report is rejected for it.
    /// </summary>
    internal static string GitLabTimestamp(DateTimeOffset moment)
        => moment.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);

    private static string WrapperVersion =>
        typeof(TruffleHogReport).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0]
        ?? typeof(TruffleHogReport).Assembly.GetName().Version?.ToString(3)
        ?? "0.0.0";

    private static string NormalizeDirectory(string path) => path.Replace('\\', '/').TrimEnd('/');

    /// <summary>
    /// <paramref name="location"/> relative to <paramref name="normalizedRoot"/>, forward-slashed.
    /// Unlike the SBOM case a path that falls outside the root is <b>kept</b>, not dropped: losing the
    /// only location a human has for a leaked credential is worse than reporting an awkward path.
    /// String-based rather than <see cref="Path"/>-based, since output captured on a Linux runner is
    /// routinely turned into a report on Windows and vice versa.
    /// </summary>
    internal static string Relativize(string location, string? normalizedRoot)
    {
        var path = location.Replace('\\', '/');
        while (path.StartsWith("./", StringComparison.Ordinal)) path = path[2..];
        if (normalizedRoot is null || normalizedRoot.Length == 0) return path;

        var comparison = LooksWindows(path) || LooksWindows(normalizedRoot)
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        return path.StartsWith(normalizedRoot + "/", comparison) ? path[(normalizedRoot.Length + 1)..] : path;
    }

    private static bool LooksWindows(string forwardSlashPath)
        => forwardSlashPath.Length >= 2 && char.IsLetter(forwardSlashPath[0]) && forwardSlashPath[1] == ':';
}
