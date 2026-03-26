# Omnisor App

`omnisor-app` is the ratatui-based terminal application built on top of:

- `omnisor` for core SSH and device-session APIs
- `omnisor-health` for reusable health and troubleshooting logic

This package owns the operator UX:

- launcher and feature registry
- app-level routing/navigation
- shared ratatui shell rendering
- top-level workflow orchestration

Feature-specific setup flows and runtime behavior live in dedicated feature crates such as
`omnisor-feature-device-health`.
