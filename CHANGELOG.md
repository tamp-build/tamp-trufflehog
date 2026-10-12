# Changelog

All notable changes to this repo's packable projects are recorded here. Version
numbers refer to the central `<Version>` in `Directory.Build.props` (TAM-81).

## [Unreleased]

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
