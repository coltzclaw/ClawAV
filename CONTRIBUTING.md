# Contributing to ClawTower

Thank you for your interest in contributing to ClawTower! This document explains the process for contributing to the project.

## Contributor License Agreement (CLA)

**All contributors must sign a Contributor License Agreement before their first pull request can be merged.**

ClawTower uses a CLA to ensure that the project can be dual-licensed (AGPL-3.0 for the open-source community, and a separate commercial license). This is the same model used by the Apache Foundation, GitLab, and many other major open-source projects.

When you open your first pull request, the [CLA Assistant](https://github.com/cla-assistant/cla-assistant) bot will prompt you to sign the CLA electronically. This is a one-time process.

### What the CLA does

- Grants the project maintainer (JR Morton) a non-exclusive, irrevocable license to use your contributions under any license, including for commercial purposes
- You **retain full copyright** over your contributions
- You can continue to use your contributions in any way you choose
- This is based on the [Apache Individual Contributor License Agreement](https://www.apache.org/licenses/icla.pdf)

### Why a CLA is required

Without a CLA, every contributor retains exclusive copyright over their code, making it legally impossible to offer a commercial license. The CLA ensures ClawTower can sustain itself through dual-licensing while keeping the open-source version fully AGPL-3.0.

## Getting Started

1. **Fork the repository** and clone your fork
2. **Create a branch** for your changes: `git checkout -b my-feature`
3. **Make your changes** — see the development guidelines below
4. **Run tests**: `cargo test`
5. **Run clippy**: `cargo clippy -- -D warnings`
6. **Open a pull request** against `main`

## Development Guidelines

### Code Style

- Follow standard Rust conventions (`rustfmt` defaults)
- Run `cargo fmt` before committing
- All code must pass `cargo clippy -- -D warnings`
- Add `#[cfg(test)] mod tests` inline tests for new functionality

### Commit Messages

- Use imperative mood: "Add scanner" not "Added scanner" or "Adds scanner"
- Keep the first line under 72 characters
- Reference issues where applicable: "Fix #42: handle empty audit log"

### What Makes a Good Contribution

- **Bug fixes** with a test that reproduces the issue
- **New security scanners** — see `CLAUDE.md` "Adding a New Scanner" for the pattern
- **New monitoring sources** — see `CLAUDE.md` "Adding a New Monitoring Source"
- **Detection rules** — new behavioral patterns in `src/behavior.rs`
- **Documentation** improvements
- **Policy templates** — new YAML policies in `policies/`

### Architecture Notes

- Binary crate only (`src/main.rs`), no `lib.rs`
- All modules declared as `mod` in `main.rs`
- Async runtime is Tokio — monitoring sources are spawned tasks
- Alerts flow through `mpsc::channel` → Aggregator → TUI/Slack/API/audit chain
- See `CLAUDE.md` and `.docs/ARCHITECTURE.md` for full details

## Reporting Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Email security reports to the maintainer directly. You will receive an acknowledgment within 48 hours and a detailed response within 7 days.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing to ClawTower, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE) (or later), subject to the CLA terms above.
