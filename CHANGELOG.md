# Changelog

All notable changes to this repo's packable projects are recorded here. Version
numbers refer to the central `<Version>` in `Directory.Build.props` (TAM-81).

## [Unreleased]

### Added

- Package now ships XML documentation files (`.xml`) alongside the assembly, so consumers get IntelliSense and API docs. (Mirrors [tamp-build/tamp#3](https://github.com/tamp-build/tamp/pull/50).)


## 0.1.2

### Fixed

- **TAM-263 (breaking)** — drop `Output` / `SetOutput` from `TruffleHogSettingsBase`. The TruffleHog v3 CLI has no `--output` flag; the wrapper was emitting an unsupported argument that caused `trufflehog: error: unknown long flag '--output'`. Results are emitted to stdout (JSON-per-line when `--json` is set); adopters who need a file capture should redirect stdout at the target level (shell / `Process`) or use `ProcessRunner.Capture` to read in-process. Callers of `SetOutput(...)` will see a compile error and should remove the call.

## 0.1.1

- Object-init overloads on every TruffleHog wrapper (TAM-161 satellite fanout).

## 0.1.0

- Initial release.
