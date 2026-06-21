# Contributing to Sentinel Oracle

Thank you for your interest in contributing! Sentinel Oracle is a community-driven
project. All contributions — code, documentation, bug reports, feature ideas,
and security research — are welcome.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Code Changes](#submitting-code-changes)
  - [Improving Documentation](#improving-documentation)
- [Development Setup](#development-setup)
- [Coding Guidelines](#coding-guidelines)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

Be respectful, constructive, and professional. We follow the [Contributor
Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Getting Started

1. Read the [README](README.md) to understand the project's architecture and
   threat model.
2. Read the docs in `docs/` for detailed operational and API documentation.
3. Check the [issues](https://github.com/javier20dev25/sentinel-oracle/issues)
   for open bugs or feature requests.
4. Join the discussion on open issues before starting significant work.

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/javier20dev25/sentinel-oracle/issues/new/choose)
using the **Bug Report** template. Include:

- Server version and Node.js version.
- Operating system and deployment mode (Linux, Windows, macOS, Termux).
- Tailscale or network configuration details.
- Steps to reproduce, expected behavior, and actual behavior.
- Relevant logs (sanitize any secrets before pasting).

### Suggesting Features

Open a [GitHub Issue](https://github.com/javier20dev25/sentinel-oracle/issues/new/choose)
using the **Feature Request** template. Describe:

- The problem you are trying to solve.
- How the feature would work (high-level).
- Any alternatives you have considered.

### Submitting Code Changes

1. Fork the repository.
2. Create a feature branch (`git checkout -b feat/my-change`).
3. Make your changes following the coding guidelines below.
4. Write or update tests as needed.
5. Run the test suite locally.
6. Push your branch and open a Pull Request.

### Improving Documentation

Documentation improvements are highly valued. This includes:

- Fixing typos or unclear explanations.
- Adding deployment guides for new platforms.
- Translating documentation.
- Adding diagrams or visual aids.

## Development Setup

```bash
git clone https://github.com/javier20dev25/sentinel-oracle.git
cd sentinel-oracle
npm install
npm run build

# Run tests
npm test

# Run a specific test file
npx vitest test/regression/ --reporter=verbose
```

The project uses TypeScript. Run the type checker separately:

```bash
npx tsc --noEmit
```

## Coding Guidelines

- **Language**: TypeScript (strict mode). Use `const` over `let` where possible.
- **Style**: 2-space indentation, semicolons, single quotes.
- **Naming**: `camelCase` for variables/functions, `PascalCase` for classes/types,
  `UPPER_CASE` for constants.
- **Imports**: Group by: 1) Node builtins, 2) third-party, 3) local modules.
  Use `type` prefix for type-only imports.
- **Error handling**: Prefer returning `Result` types or throwing typed errors
  over bare `throw new Error()`.
- **No secrets in code**: Never hardcode tokens, keys, or credentials.
- **Async**: Use `async`/`await` consistently. Avoid raw `.then()`.
- **Comments**: Prefer self-documenting code over explanatory comments.

## Testing

- All new features and bug fixes must include tests.
- Tests are organized by directory (see [Test Classification](README.md#test-classification)):
  - `test/regression/` — must-pass tests for core functionality.
  - `test/evasion/` — documented bypasses (pass = no detection expected).
  - `test/red-team/` — adversarial attack scenarios (pass = detection confirmed).
  - `test/integration/` — multi-layer integration tests.
- Run the full suite before submitting a PR:
  ```bash
  npm test
  ```

## Pull Request Process

1. Ensure your PR description clearly describes the problem and solution.
2. Reference any related issues (e.g., "Closes #42").
3. Update documentation if your change affects the API, config, or setup.
4. Verify all tests pass and there are no TypeScript errors.
5. Keep PRs focused — one change per PR. Large changes should be broken into
   smaller, reviewable increments.
6. Respond to review feedback promptly.

Thank you for helping make Sentinel Oracle more secure and useful for everyone.
