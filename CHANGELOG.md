# Changelog

## v1.2.0

- Added an advisory Sentinel Audit recommendation to PR scan responses and the scan panel for high/critical, CI/CD, dependency, elevated build-risk, or review-only signals.
- The advisory includes a pinned-commit preflight command when a full SHA is available and does not alter the Oracle verdict or merge authorization.
- Added tests for recommendation criteria and aligned package manifest and lockfile version.
