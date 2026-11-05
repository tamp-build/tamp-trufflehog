using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Tamp.TruffleHog.V3;

/// <summary>
/// One TruffleHog finding, reduced to what is safe to publish: who found it, whether it verified,
/// and where it is. <b>No field on this type can hold a secret.</b>
/// </summary>
/// <remarks>
/// <para>
/// The redaction is structural, not a filtering step. <c>Raw</c>, <c>RawV2</c>, <c>Redacted</c> and
/// <c>ExtraData</c> are never parsed into this type, so no code path downstream of it — a report, a
/// log line, an exception message, a debugger's <c>ToString()</c> — can emit a secret, because the
/// value was never carried past the parser.
/// </para>
/// <para>
/// <b>TruffleHog's <c>Redacted</c> field is not redacted.</b> Measured on TruffleHog 3.95.3 with the
/// AWS detector, <c>Redacted</c> was byte-for-byte identical to <c>Raw</c> — the full access key ID.
/// It is a per-detector courtesy with no guarantee behind it, and treating it as publishable means
/// publishing the credential. <c>RawV2</c> is worse: it contained <c>Raw</c> plus the secret half of
/// the pair. None of the three is safe, so none of them is read.
/// </para>
/// </remarks>
public sealed record SecretFinding
{
    /// <summary>The detector that fired, e.g. <c>AWS</c>. TruffleHog's <c>DetectorName</c>.</summary>
    public required string Detector { get; init; }

    /// <summary>
    /// Whether TruffleHog actively verified the credential against the provider. False covers both
    /// "checked and not live" and "never checked" — <see cref="SecretScanResult.VerificationRan"/>
    /// says which, since <c>--no-verification</c> makes every finding unverified by construction.
    /// </summary>
    public required bool Verified { get; init; }

    /// <summary>The TruffleHog source kind this came from: <c>git</c>, <c>filesystem</c>, <c>docker</c>, …</summary>
    public required string SourceKind { get; init; }

    /// <summary>
    /// Path to the file, repository-relative where that could be established. Null when TruffleHog
    /// reported no path (some sources report none).
    /// </summary>
    public string? File { get; init; }

    /// <summary>1-based line, when TruffleHog reported one.</summary>
    public int? Line { get; init; }

    /// <summary>
    /// The commit the secret was found in. Present for the <c>git</c> source, which reports it per
    /// finding; null for sources that have no commit (filesystem, docker), where
    /// <see cref="SecretScanOptions.CommitSha"/> supplies it for the GitLab report.
    /// </summary>
    public string? Commit { get; init; }

    /// <summary>The decoder that produced the match (<c>PLAIN</c>, <c>BASE64</c>, …), for triage.</summary>
    public string? Decoder { get; init; }

    /// <summary>
    /// A stable, non-reversible identity for this finding: lower-case hex SHA-256 over the detector,
    /// source kind, file, line and commit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The secret is deliberately not an input.</b> Hashing the value would be reversible for any
    /// low-entropy secret — a password, a short token — because the hash of a guessable input is a
    /// lookup, not a one-way function. Publishing such a hash of a live credential is a liability, and
    /// a report goes to places the source does not. So the fingerprint identifies the finding's
    /// *position*, never its value: it leaks nothing even if the secret is weak, and a secret rotated
    /// in place keeps its identity across runs, which is what tracking wants.
    /// </para>
    /// <para>
    /// The line number is included, so two different secrets in one file stay distinct findings —
    /// collapsing them would under-report, which is the worse error. The cost is that editing a line
    /// above a finding re-identifies it; GitLab's own source-tracking signatures behave the same way.
    /// </para>
    /// </remarks>
    public string Fingerprint => _fingerprint ??= ComputeFingerprint();

    private string? _fingerprint;

    private string ComputeFingerprint()
    {
        var material = string.Join(
            '\u001f',
            "tamp-secret-location-v1",
            Detector,
            SourceKind,
            File ?? "",
            Line?.ToString(CultureInfo.InvariantCulture) ?? "",
            Commit ?? "");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    /// <summary>The signature algorithm name reported alongside <see cref="Fingerprint"/>.</summary>
    public const string FingerprintAlgorithm = "tamp-secret-location-v1";

    /// <summary>
    /// A deterministic UUID for this finding, derived from <see cref="Fingerprint"/>. GitLab's report
    /// schema recommends a UUID for <c>vulnerability.id</c>; deriving it rather than generating a
    /// random one means a finding that persists across runs keeps the same id instead of looking new
    /// every pipeline.
    /// </summary>
    public string Id
    {
        get
        {
            var f = Fingerprint;
            return $"{f[..8]}-{f[8..12]}-{f[12..16]}-{f[16..20]}-{f[20..32]}";
        }
    }

    /// <summary>
    /// A description safe to publish: the detector and whether it verified. Never the value, and
    /// never an excerpt — GitLab's schema says a vulnerability name "must not include the finding's
    /// specific information", and the same reasoning applies to everything else that gets rendered.
    /// </summary>
    public string SafeDescription =>
        Verified
            ? $"{Detector} credential detected and verified live against the provider. Treat as compromised: rotate it, then purge it from history."
            : $"{Detector} credential pattern detected (not verified live). Confirm by hand, then rotate and purge it from history if real.";

    /// <summary>Location as a human-readable string, for a log line. Carries no secret.</summary>
    public override string ToString()
        => $"{Detector}{(Verified ? " (verified)" : "")} at {File ?? "(no path)"}{(Line is { } l ? $":{l}" : "")}"
           + (Commit is { } c ? $" in {c[..Math.Min(8, c.Length)]}" : "");
}
