# Changelog

All notable changes to this repo's packable projects are recorded here. Version
numbers refer to the central `<Version>` in `Directory.Build.props` (TAM-81).

## [Unreleased]

## [0.3.0] - 2026-11-05 - publishable secret-scan reports, and a clean scan you can prove

### Added

- **SARIF and GitLab `secret_detection` reports** ([#8](https://github.com/tamp-build/tamp-trufflehog/issues/8)). TruffleHog exposed JSON-line output only, so a consumer had nothing to publish and a CI system had no record a secret scan ran. The dangerous half of that: **a missing report is indistinguishable from a clean scan**, so an absent report, a skipped scan and a crashed scan all looked alike.

  `TruffleHogReport.Read(output, options)` parses the stream -- findings *and* TruffleHog's own log records, which share stdout -- and `ToGitLabSecretDetection` / `ToSarif` (plus `Write*` file helpers) emit publishable reports. Validated against GitLab's own `secret-detection-report-format.json` (schema 15.2.5) with `jsonschema`, for a findings run, a clean run and a failed run.

- **Three states, not two.** A clean scan writes `status: "success"` with an empty `vulnerabilities` array -- a positive receipt. A failed scan writes `status: "failure"` with the reasons in `scan.messages`, so an empty list is never read as "clean". **Status is earned from the scan's own telemetry, not from the exit code**, because the exit code cannot tell the two apart: measured on TruffleHog 3.95.3, a scan of a path that *does not exist* exits **0** and reports zero findings, exactly like a clean scan. It is distinguishable -- an `encountered errors during scan` record and `chunks 0, bytes 0` against `chunks 1, bytes 12` for a real empty directory -- and that is what is checked. Exit **183** (TruffleHog's "secrets found" code under `--fail`) is treated as a *completed* scan, not a failure.

### Security

- **Nothing reversible can be emitted, by construction.** `SecretFinding` has no property able to hold a secret: `Raw`, `RawV2`, `Redacted`, `ExtraData` and `StructuredData` are never read out of the JSON, so no report, log line, exception message or `ToString()` can carry one. GitLab's `raw_source_code_extract` is deliberately never populated. Tested by asserting the placeholder value is absent from every output *and* that the type has no such properties.

  **TruffleHog's `Redacted` field is not redacted** -- measured on 3.95.3 with the AWS detector it was byte-for-byte identical to `Raw`, the full access key ID. Anyone treating it as safe to publish is publishing the credential. `RawV2` contained `Raw` plus the secret half of the pair. `ExtraData` is excluded as a class: detector-defined, and has carried credential-bearing URLs.

- **Fingerprints identify position, never value.** SHA-256 over detector, source kind, file, line and commit -- the secret is deliberately not an input. Hashing the value would be reversible for any low-entropy secret, since the hash of a guessable input is a lookup rather than a one-way function, and a published hash of a live credential is a liability. A consequence worth having: a secret rotated in place keeps its identity across runs. The fingerprint rides in GitLab's own `tracking.signatures` and SARIF's `partialFingerprints` rather than an invented field, and `vulnerability.id` is derived from it so a persisting finding does not look new every pipeline.

- **The mandatory commit is never invented.** GitLab's schema requires `location.commit.sha`. The `git` source reports one per finding -- the commit that introduced the secret, more precise than the pipeline's HEAD. `filesystem` and `docker` scans have none, so `SecretScanOptions.CommitSha` supplies it and the GitLab report throws without it. SARIF has no such requirement and stays available for those sources.

### Notes

- Severity is stated, not inferred: verified -> `Critical` / SARIF `error`; unverified -> `Unknown` / SARIF `warning`. Nothing is derived from entropy or detector identity and no scanner threshold is changed.
- Additive by design: the reporter does not change the command, does not decide whether the build fails (`--fail` / `SetFail()` still does), and never enables verification. Proving a report format should not involve authenticating anyone's credentials.
- New dependency: `Tamp.Sarif`, for the SARIF model and writer. It ships in lockstep with `Tamp.Core`, so the two pins move together.

## [0.2.0] — 2026-10-12

### Added

- **`SetForceSkipBinaries()` / `SetForceSkipArchives()`** on the shared base (`--force-skip-binaries` / `--force-skip-archives`). The primary performance lever for large vendored binaries — e.g. puppeteer's bundled Chromium under `node_modules` — which trufflehog otherwise spends minutes reading. Common engine flags (valid on `git`, `filesystem`, etc.).
- **`TruffleHogFilesystemSettings.AddPaths(params string[])`** — ergonomic path-scoping to scan real source dirs (`AddPaths("src", "build")`) rather than `.`.

### Changed

- Clarified the docs on `IncludePathsFile` / `ExcludePathsFile`: these are **regex result filters** over the walked file set — they do **not** stop traversal. The performant approach for a tree with a vendored toolchain is to **scope the paths** (and/or `SetForceSkipBinaries()`), not to scan `.` with an exclude file. ([#5](https://github.com/tamp-build/tamp-trufflehog/issues/5))

## [0.1.3] — 2026-09-27

### Added

- Package now ships XML documentation files (`.xml`) alongside the assembly, so consumers get IntelliSense and API docs. (Mirrors [tamp-build/tamp#3](https://github.com/tamp-build/tamp/pull/50).)


## 0.1.2

### Fixed

- **TAM-263 (breaking)** — drop `Output` / `SetOutput` from `TruffleHogSettingsBase`. The TruffleHog v3 CLI has no `--output` flag; the wrapper was emitting an unsupported argument that caused `trufflehog: error: unknown long flag '--output'`. Results are emitted to stdout (JSON-per-line when `--json` is set); adopters who need a file capture should redirect stdout at the target level (shell / `Process`) or use `ProcessRunner.Capture` to read in-process. Callers of `SetOutput(...)` will see a compile error and should remove the call.

## 0.1.1

- Object-init overloads on every TruffleHog wrapper (TAM-161 satellite fanout).

## 0.1.0

- Initial release.
