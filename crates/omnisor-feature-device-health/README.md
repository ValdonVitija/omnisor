# Omnisor Feature: Device Health

This crate contains the Device Health ratatui feature flow for `omnisor-app`.

It owns:

- device-health-specific setup flow
- feature-local state
- health screen rendering
- interaction over `omnisor-health`

It is mounted by the main `omnisor-app` shell through a static feature registry.
