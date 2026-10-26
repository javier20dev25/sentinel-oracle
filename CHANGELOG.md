# Changelog

## v1.3.0

- Integrated Sentinel Audit into the Oracle PR scan panel as a separate, operator-started evidence workflow.
- The integration checks the current Oracle scan hash, verifies the live PR head, audits an isolated checkout pinned to that SHA, and presents analyzer coverage and corroborated evidence without changing Oracle's verdict or merge authorization.
- Added responsive evidence cards, per-candidate signal details, and setup instructions for the Audit runner on the Oracle host.

## v1.2.0

- Added an advisory Sentinel Audit recommendation to PR scan responses and the scan panel for high/critical, CI/CD, dependency, elevated build-risk, or review-only signals.
- The advisory includes a pinned-commit preflight command when a full SHA is available and does not alter the Oracle verdict or merge authorization.
- Added tests for recommendation criteria and aligned package manifest and lockfile version.
