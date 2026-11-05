# Tamp.TruffleHog

[TruffleHog](https://github.com/trufflesecurity/trufflehog) CLI
wrapper for [Tamp](https://github.com/tamp-build/tamp).

| Package | TruffleHog | Status |
|---|---|---|
| [`Tamp.TruffleHog.V3`](src/Tamp.TruffleHog.V3) | 3.x | preview |

Requires `Tamp.Core ≥ 1.0.3`. GitHub PAT typed as `Secret` —
registered with the runner's redaction table.

## Verbs

| Source | Notes |
|---|---|
| `Git` | Scan local or remote repo (`--branch`, `--head`, `--since-commit`, `--max-depth`, include/exclude paths). |
| `GitHub` | Scan repos/orgs. PAT typed as `Secret`. `--include-forks`, `--include-members`, `--include-wikis`, `--issue-comments`, `--pr-comments`, `--gist-comments`, `--commit-since`, `--endpoint` (Enterprise). |
| `Filesystem` | Scan paths on disk. Include/exclude path files. |
| `Docker` | Scan one or more images. |
| `Raw` | Escape hatch for the long tail (`s3`, `gcs`, `slack`, `jira`, …). |

Common flags (all verbs): `--json`, `--only-verified`,
`--no-verification`, `--filter-entropy`, `--filter-unverified`,
`--include-detectors` (comma-list), `--exclude-detectors`,
`--concurrency`, `--fail`, `--log-level`, `--no-update`,
`--print-avg-detector-time`, `--results`, `--output`,
`--archive-max-size`, `--archive-max-depth`, `--archive-timeout`,
`--allow-verification-overlap`.

## Quick example — pre-merge CI gate

```csharp
using Tamp;
using Tamp.TruffleHog.V3;

[NuGetPackage("trufflehog", UseSystemPath = true)]
readonly Tool TruffleHog = null!;

[Secret("GitHub PAT", EnvironmentVariable = "GH_TOKEN")]
readonly Secret? GitHubToken = null!;

Target SecretScan => _ => _.Executes(() =>
    TruffleHog.GitHubScan(TruffleHog, s => s
        .AddRepo($"https://github.com/{Repo}")
        .SetToken(GitHubToken)
        .SetCommitSince(LastReleaseDate)
        .SetOnlyVerified()
        .SetJson()
        .SetFail()
        .SetNoUpdate()));
```

(`GitHubScan` is the convention — the wrapper's static facade
exposes `TruffleHog.GitHub(...)`; pick a target name that doesn't
shadow it.)

## Reports: SARIF and GitLab `secret_detection`

TruffleHog emits JSON lines and nothing else, so there is nothing a CI system can publish and no
record that a secret scan ran at all. The second half is the dangerous one: **a missing report is
indistinguishable from a clean scan**, so an absent report, a skipped scan and a crashed scan all look
alike downstream. That is a silent failure in a security control.

It is not hypothetical. Measured on TruffleHog 3.95.3:

| | exit code | error record | chunks / bytes |
|---|---|---|---|
| clean scan of a real directory | 0 | -- | 1 / 12 |
| **scan of a path that does not exist** | **0** | `encountered errors during scan` | **0 / 0** |

Same exit code, same (empty) findings. `TruffleHogReport` reads the scan's own telemetry rather than
trusting the exit code, and calls the second case what it is.

```csharp
Target SecretScan => _ => _
    .Description("[Security] TruffleHog, with a publishable report either way")
    .Executes(() =>
    {
        var started = DateTimeOffset.UtcNow;
        var settings = new TruffleHogGitSettings()
            .SetUri($"file://{RootDirectory}")
            .SetJson()
            .SetFail();                      // still what decides the build

        var run = ProcessRunner.Run(TruffleHog.Git(TruffleHogTool, settings), exitHandling: ExitHandling.Capture);

        var options = new SecretScanOptions
        {
            SourceRoot = RootDirectory,
            CommitSha = Environment.GetEnvironmentVariable("CI_COMMIT_SHA"),
            ExitCode = run.ExitCode,
            StartedAt = started,
            EndedAt = DateTimeOffset.UtcNow,
        }.SetVerificationFrom(settings);

        var result = TruffleHogReport.Read(run.StandardOutput, options);
        Log.Information("{Result}", result);   // "secret scan completed: 1 finding(s), 0 verified, 560 byte(s) examined"

        TruffleHogReport.WriteGitLabSecretDetection(result, Artifacts / "gl-secret-detection-report.json", options);
        TruffleHogReport.WriteSarif(result, Artifacts / "secrets.sarif");

        if (result.Status == SecretScanStatus.Failure)
            throw new Exception("secret scan did not run: " + string.Join("; ", result.Messages));
    });
```

```yaml
# .gitlab-ci.yml -- secret_detection is the one to ingest. See the warning below before adding sarif.
secret-scan:
  script: ./tamp.sh SecretScan
  artifacts:
    paths:
      - artifacts/secrets.sarif           # kept as a plain artifact, deliberately not ingested
    reports:
      secret_detection: artifacts/gl-secret-detection-report.json
```

> **The two report types are alternatives for ingestion, not a belt-and-braces pair.** GitLab ingests
> `secret_detection` and `sarif` independently and neither deduplicates against the other, so
> publishing both puts **every secret in the dashboard twice** — once as a secret-detection finding
> and once, through the SARIF, as a generic finding at a different severity. Publish the native report
> and keep the SARIF as a plain artifact (above), or publish the SARIF alone. This is not discoverable
> until a report is ingested, which is why it is stated here.

### Which schema version the report declares

`version` defaults to **15.2.0** — a floor, not the newest published patch. A consumer validates
against the schema bundled in *its own* release, so declaring the newest upstream version makes every
instance even one release behind fall back to its own newest and attach a schema-version warning to
every finding. That is noise on every report in every pipeline, and it makes a genuine schema problem
indistinguishable from the standing one.

The floor is verified rather than assumed: the findings, clean and failure reports this emitter
produces were each validated against the published 15.2.0, 15.2.1 and 15.2.5 schemas, and all three
accept all three. Set `SecretScanOptions.SetGitLabSchemaVersion("15.2.4")` to match a specific
instance exactly.

### Three states, not two

| state | `scan.status` | `vulnerabilities` | how it is decided |
|---|---|---|---|
| clean | `success` | `[]` -- a positive receipt | completion record seen, bytes > 0, no error record, exit 0 |
| findings | `success` | populated | same, plus exit 0 or **183** (TruffleHog's "secrets found" code under `--fail` -- a completed scan, not a failure) |
| failed | `failure` | `[]`, with reasons in `scan.messages` | no completion record, an error record, 0 bytes examined, or any other exit code |

A clean run writes the file. That is the point: silence is not evidence.

### Nothing reversible is emitted, by construction

`SecretFinding` has no property that can hold a secret. `Raw`, `RawV2`, `Redacted`, `ExtraData` and
`StructuredData` are never read out of the JSON, so no downstream code -- a report, a log line, an
exception message, a debugger's `ToString()` -- can emit one. GitLab's `raw_source_code_extract` field
is deliberately never populated.

> **TruffleHog's `Redacted` field is not redacted.** Measured on 3.95.3 with the AWS detector,
> `Redacted` was byte-for-byte identical to `Raw` -- the full access key ID. It is a per-detector
> courtesy with no guarantee behind it, so treating it as publishable means publishing the credential.
> `RawV2` contained `Raw` plus the secret half of the pair. `ExtraData` is excluded as a class: it is
> detector-defined and has carried credential-bearing URLs.

**Fingerprints identify the position, never the value.** `SecretFinding.Fingerprint` is SHA-256 over
detector, source kind, file, line and commit. Hashing the secret would be reversible for any
low-entropy value -- the hash of a guessable input is a lookup, not a one-way function -- and publishing
such a hash of a live credential is a liability. So the value is not an input: the fingerprint leaks
nothing even when the secret is weak, and a secret rotated in place keeps its identity across runs. It
rides in GitLab's own `tracking.signatures`, not an invented field, and in SARIF's
`partialFingerprints`.

### The commit is mandatory, and not every source has one

GitLab's schema requires `location.commit.sha`. The `git` source reports a commit **per finding** --
the one that introduced the secret, which is more precise than the pipeline's HEAD. A `filesystem` or
`docker` scan has no commit at all, so `SecretScanOptions.CommitSha` supplies it (`CI_COMMIT_SHA`), and
the GitLab report **throws** without it rather than inventing one. SARIF has no such requirement, so a
filesystem scan is still publishable that way.

### Severity, stated rather than implied

Verified -> `Critical` / SARIF `error`: the credential was confirmed live. Unverified -> `Unknown` /
SARIF `warning`: nothing checked whether it works, and `Unknown` is a real value in GitLab's enum and
the literally accurate one. Neither is inferred from entropy or detector identity, and the scanner's
own thresholds are untouched.

### Additive

This reads output TruffleHog already produced. It does not change the command, does not decide whether
the build fails -- keep using `--fail` / `SetFail()` -- and never turns verification on. Proving a report
format should not involve authenticating anyone's credentials anywhere.

## Releasing

See [MAINTAINERS.md](MAINTAINERS.md).

## Settings authoring style

Examples above use the fluent `Set*`-chain shape. Every wrapper verb also accepts a `new XxxSettings { ... }` object-init form — both produce identical `CommandPlan`s. The fluent shape stays canonical in docs and the `tamp init` template; opt into object-init scaffolding via `tamp init --settings-style=init`.

See [Build Script Authoring → Two authoring styles](https://github.com/tamp-build/tamp/wiki/Build-Script-Authoring#two-authoring-styles-for-wrapper-calls-120) on the wiki for the side-by-side comparison.
