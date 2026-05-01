# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2025-05-01

### Added
- Three operating modes: `--baseline`, `--check`, `--watch`
- Full directory tree support (recursive)
- File metadata tracking: size, permissions, last modified
- Continuous watch mode with configurable interval
- JSON report export with `--report` flag
- Colored terminal output via colorama
- Persistent audit logging to `fim.log`
- Multi-algorithm support: MD5, SHA1, SHA256, SHA512
- Graceful Ctrl+C handling in watch mode

### Changed
- Rewrote CLI using argparse (replaces bare `input()`)
- Switched to chunk-based file reading (8192 bytes) for memory safety
- Hash database is now keyed by absolute file paths

### Fixed
- Memory issues with large files (now streamed in chunks)
- Silent failure on permission errors (now logs a warning)

## [1.0.0] - Initial Release

- Single-file monitoring with SHA-512
- Basic JSON change log
