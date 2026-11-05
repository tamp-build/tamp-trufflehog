namespace Tamp.TruffleHog.V3;

/// <summary>
/// Whether the scanner ran. The whole point of the distinction: a missing report, a skipped scan and
/// a crashed scan otherwise all look like a clean one.
/// </summary>
public enum SecretScanStatus
{
    /// <summary>
    /// The scan ran to completion. Findings may be zero — that is a result, not an absence, and it is
    /// what makes a clean run a positive receipt rather than silence.
    /// </summary>
    Success,

    /// <summary>
    /// The scan did not complete, or completed having examined nothing. Its findings — including an
    /// empty list — say nothing about the code.
    /// </summary>
    Failure,
}

/// <summary>Inputs to <see cref="TruffleHogReport"/>.</summary>
public sealed class SecretScanOptions
{
    /// <summary>
    /// The commit the scan covers. Required for the GitLab report on any source that is not
    /// <c>git</c>: GitLab's secret-detection schema makes <c>location.commit.sha</c> mandatory, and a
    /// filesystem or docker scan has no commit of its own. In GitLab CI this is <c>CI_COMMIT_SHA</c>.
    /// Findings from the <c>git</c> source carry their own commit and ignore this.
    /// </summary>
    public string? CommitSha { get; set; }

    /// <summary>
    /// The repository root, used to make absolute file paths repository-relative. TruffleHog's
    /// filesystem source reports the path it was given — frequently absolute — and a report GitLab
    /// cannot anchor to a file in the repository is a report nobody can act on.
    /// </summary>
    public string? SourceRoot { get; set; }

    /// <summary>
    /// The process exit code, when known. <c>0</c> is a completed scan and <c>183</c> is TruffleHog's
    /// "secrets found" code under <c>--fail</c> — <b>also a completed scan</b>. Anything else is a
    /// failure. Leave null when the exit code wasn't captured; status is then judged on the scan's own
    /// telemetry alone.
    /// </summary>
    public int? ExitCode { get; set; }

    /// <summary>TruffleHog's "secrets found" exit code under <c>--fail</c>. Not a failure.</summary>
    public const int SecretsFoundExitCode = 183;

    /// <summary>When the scan started. Defaults to <see cref="EndedAt"/> if only that is known.</summary>
    public DateTimeOffset? StartedAt { get; set; }

    /// <summary>When the scan finished. Defaults to now.</summary>
    public DateTimeOffset? EndedAt { get; set; }

    /// <summary>
    /// Treat a scan that examined zero bytes as a failure. On by default, and this is the setting that
    /// catches the trap: TruffleHog exits <b>0</b> for a target that does not exist, reporting zero
    /// findings — byte-identical to a clean scan from the exit code alone. Measured on 3.95.3: a real
    /// but empty directory reported <c>chunks 1, bytes 12</c>; a nonexistent path reported
    /// <c>chunks 0, bytes 0</c> and an <c>"encountered errors during scan"</c> log line, and still
    /// exited 0.
    /// </summary>
    public bool RequireScannedBytes { get; set; } = true;

    /// <summary>
    /// Whether TruffleHog verified findings against their providers. Set it from the settings with
    /// <see cref="SetVerificationFrom"/> rather than by hand: under <c>--no-verification</c> every
    /// finding is unverified by construction, and a report that does not say so invites a reader to
    /// conclude the credentials are all dead.
    /// </summary>
    public bool VerificationEnabled { get; set; } = true;

    /// <summary>Take <see cref="VerificationEnabled"/> from the settings the scan actually ran with.</summary>
    public SecretScanOptions SetVerificationFrom(TruffleHogSettingsBase settings)
    {
        if (settings is null) throw new ArgumentNullException(nameof(settings));
        VerificationEnabled = !settings.NoVerification;
        return this;
    }

    /// <summary>
    /// The schema version declared in the GitLab report. Defaults to
    /// <see cref="TruffleHogReport.GitLabSchemaVersion"/>, which is a deliberately conservative
    /// floor — see its remarks for why the newest published patch is the wrong thing to claim.
    /// </summary>
    /// <remarks>
    /// Set this to the version bundled in the consuming instance's release when it is known and an
    /// exact match is wanted. Must be <c>major.minor.patch</c>; GitLab's own schema constrains the
    /// field to that shape and rejects the whole report otherwise.
    /// </remarks>
    public string GitLabSchemaVersion { get; set; } = TruffleHogReport.GitLabSchemaVersion;

    /// <summary>Set <see cref="GitLabSchemaVersion"/>.</summary>
    /// <exception cref="ArgumentException">Not a <c>major.minor.patch</c> version.</exception>
    public SecretScanOptions SetGitLabSchemaVersion(string version)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(version ?? "", @"^[0-9]+\.[0-9]+\.[0-9]+$"))
            throw new ArgumentException(
                $"'{version}' is not a major.minor.patch version. GitLab's report schema constrains "
                + "the version field to that shape and rejects the whole report otherwise.", nameof(version));
        GitLabSchemaVersion = version!;
        return this;
    }

    /// <summary>Set <see cref="CommitSha"/>.</summary>
    public SecretScanOptions SetCommitSha(string? sha) { CommitSha = sha; return this; }

    /// <summary>Set <see cref="SourceRoot"/>.</summary>
    public SecretScanOptions SetSourceRoot(string? path) { SourceRoot = path; return this; }

    /// <summary>Set <see cref="ExitCode"/>.</summary>
    public SecretScanOptions SetExitCode(int? exitCode) { ExitCode = exitCode; return this; }

    /// <summary>Set <see cref="StartedAt"/> and <see cref="EndedAt"/>.</summary>
    public SecretScanOptions SetWindow(DateTimeOffset startedAt, DateTimeOffset endedAt)
    { StartedAt = startedAt; EndedAt = endedAt; return this; }

    /// <summary>Set <see cref="RequireScannedBytes"/>.</summary>
    public SecretScanOptions SetRequireScannedBytes(bool v = true) { RequireScannedBytes = v; return this; }
}

/// <summary>
/// A parsed TruffleHog run: its findings, whether it actually ran, and why not when it didn't.
/// </summary>
public sealed record SecretScanResult
{
    /// <summary>Findings, deduplicated by <see cref="SecretFinding.Fingerprint"/>, in detection order.</summary>
    public required IReadOnlyList<SecretFinding> Findings { get; init; }

    /// <summary>Whether the scan ran. See <see cref="SecretScanStatus"/>.</summary>
    public required SecretScanStatus Status { get; init; }

    /// <summary>
    /// Why the status is <see cref="SecretScanStatus.Failure"/>, or notes worth carrying on a success.
    /// These ride into the GitLab report as <c>scan.messages</c>, so a consumer sees the reason rather
    /// than an empty finding list.
    /// </summary>
    public required IReadOnlyList<string> Messages { get; init; }

    /// <summary>TruffleHog's reported version, when it said. Goes into the report's scanner identity.</summary>
    public string? ScannerVersion { get; init; }

    /// <summary>Chunks TruffleHog examined, from its own completion record. Zero means it saw nothing.</summary>
    public long? Chunks { get; init; }

    /// <summary>Bytes TruffleHog examined. Zero means it saw nothing — see <see cref="SecretScanOptions.RequireScannedBytes"/>.</summary>
    public long? Bytes { get; init; }

    /// <summary>
    /// Whether TruffleHog's completion record was seen at all. False means the output was truncated or
    /// the process died mid-scan, so no finding count from it can be trusted.
    /// </summary>
    public required bool Completed { get; init; }

    /// <summary>
    /// Whether verification ran. False under <c>--no-verification</c>, in which case every finding is
    /// unverified by construction and <see cref="SecretFinding.Verified"/> says nothing about liveness.
    /// </summary>
    public required bool VerificationRan { get; init; }

    /// <summary>Findings dropped as duplicates of one already seen.</summary>
    public required int Duplicates { get; init; }

    /// <summary>Verified findings — credentials TruffleHog confirmed live against the provider.</summary>
    public int VerifiedCount => Findings.Count(f => f.Verified);

    /// <summary>A one-line summary for a build log. Carries no secret.</summary>
    public override string ToString()
        => Status == SecretScanStatus.Failure
            ? $"secret scan FAILED ({string.Join("; ", Messages)})"
            : $"secret scan completed: {Findings.Count} finding(s), {VerifiedCount} verified, "
              + $"{Bytes?.ToString() ?? "?"} byte(s) examined"
              + (Duplicates > 0 ? $", {Duplicates} duplicate(s) collapsed" : "")
              + (VerificationRan ? "" : " [verification off]");
}
