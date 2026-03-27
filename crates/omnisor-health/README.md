# Omnisor Health

Reusable health and troubleshooting domain logic for Omnisor.

This crate sits above the core `omnisor` SSH/device APIs and is intended to hold:

- health snapshot types
- findings and status modeling
- reusable collectors/checks
- vendor-specific health parsers and adapters

The ratatui app consumes this crate, but the logic here is intended to be reusable outside the UI.
