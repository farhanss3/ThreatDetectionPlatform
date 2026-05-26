# Open-Source Detection Library

This repository now includes a starter detection library curated from common open-source detection patterns (primarily Sigma-style logic) and normalized into the project schema.

## Curation Rules

- Each detection is stored as a standalone `detection.json`.
- ATT&CK mapping is required for each entry.
- Query language is explicitly declared.
- A `source` section captures upstream open-source provenance.

## Current Library

- `execution/office_spawns_powershell_encoded.json`
- `persistence/registry_run_key_modification.json`
- `credential_access/lsass_memory_dump_access.json`
- `defense_evasion/clear_windows_event_logs.json`
- `command_and_control/suspicious_dns_tunneling_pattern.json`

## Next Curator Tasks

1. Add fixture-based tests per rule (`tests/positive` and `tests/negative`).
2. Add rule-level false-positive notes and tuning guidance.
3. Add engine-specific transpilation snapshots (KQL/EQL/SPL).
4. Add CI validation against `schemas/detection.schema.json`.
