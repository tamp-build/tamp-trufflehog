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

## Releasing

See [MAINTAINERS.md](MAINTAINERS.md).
