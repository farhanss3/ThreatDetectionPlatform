# ThreatDetectionPlatform

A detection-as-code platform for collaborative threat detection engineering.

## Vision

ThreatDetectionPlatform is designed to make detection engineering as collaborative and iterative as modern software development. It combines:

- **Detection-as-Code** in GitHub repositories.
- **Multi-source detection ingestion** from tools and natural-language descriptions.
- **Universal log onboarding** with Elastic Common Schema (ECS) normalization.
- **Built-in testing and adversary emulation** before release.
- **First-class ATT&CK ecosystem mappings** (MITRE ATT&CK, ATLAS, D3FEND/DEFEND style controls).
- **Social collaboration mechanics** so detections can be shared, improved, and trusted by community consensus.

## Product Principles

1. **Git-native by default**
   - Every detection rule, test fixture, and metadata artifact is versioned in GitHub.
   - Pull requests are the primary review and promotion workflow.

2. **AI-assisted, human-verified**
   - Users can ingest detections from external tools or plain-English threat hypotheses.
   - The platform generates candidate detection logic, tests, and mappings; humans approve changes.

3. **Schema-first detection portability**
   - Raw logs are mapped into ECS so detections are reusable across data sources.

4. **Evidence-based quality**
   - No rule promotion without unit test coverage and replay/emulation validation.

5. **Community-driven trust**
   - Detections have reputation, maintainers, forks, and measurable quality scores.

## Core Capabilities

### 1) Detection-as-Code Repository Model

Each detection package lives in GitHub and includes:

- Detection query/logic (Sigma, EQL, KQL, SPL, SQL, etc.)
- Metadata (`id`, severity, confidence, status, owner)
- MITRE mappings (ATT&CK technique/sub-technique, ATLAS tactics, D3FEND associations)
- Unit tests with benign and malicious fixtures
- Emulation playbook references
- Changelog and peer-review history

Suggested detection folder structure:

```text
detections/
  credential_access/
    t1003_lsass_dumping/
      detection.yml
      query.sigma
      tests/
        positive/
        negative/
      mappings/
        mitre_attack.yml
        mitre_atlas.yml
        mitre_d3fend.yml
      emulation/
        atomic_red_team.yaml
      README.md
```

### 2) Ingestion of New Detections

Support two ingestion paths:

- **Tool import**
  - Parse detections from SIEM/EDR sources (Splunk, Sentinel, Elastic, Chronicle, etc.).
  - Normalize metadata and convert to internal detection schema.

- **Natural-language ingestion**
  - Example input: “Alert when an Office child process spawns PowerShell with encoded command.”
  - AI pipeline extracts entities, proposes logic in one or more rule languages, adds ATT&CK mapping candidates, and scaffolds tests.

### 3) Universal Log Ingestion + ECS Mapping

Pipeline:

1. Receive logs in any format (JSON, CSV, Syslog, vendor-specific).
2. Auto-infer field semantics.
3. Apply ECS mapping suggestions.
4. Validate mapped dataset quality and completeness.
5. Persist raw + normalized events with lineage.

Key features:

- Mapping confidence score per field.
- Human-in-the-loop override UI.
- Reusable mapping templates by log source.
- Drift detection when source schema changes.

### 4) Detection Testing & Validation

- **Unit tests**: Positive and negative fixture-based tests.
- **Contract tests**: Verify rule compiles and runs on target engines.
- **Regression tests**: Prevent quality regressions after edits.
- **Performance tests**: Measure query runtime/cost against sampled telemetry.

Quality gates before merge:

- Required ATT&CK mapping present.
- Minimum test pass threshold.
- False-positive baseline check.
- Linting and schema validation passed.

### 5) Threat Activity Emulation

Enable controlled adversary simulation to validate detections:

- Integrate Atomic Red Team, CALDERA, Prelude Operator, and custom scripts.
- Run scheduled emulation campaigns in isolated environments.
- Capture resulting telemetry and auto-link results to detection test history.
- Produce “detection efficacy score” based on true-positive hit rate + noise.

### 6) MITRE Knowledge Graph Mapping

Model a crosswalk graph for:

- **ATT&CK**: techniques/sub-techniques, data sources, mitigations.
- **ATLAS**: adversarial ML behaviors (for AI system security detections).
- **D3FEND / DEFEND-aligned controls**: defensive technique relationships.

Graph use cases:

- Suggest missing technique coverage.
- Recommend related detections.
- Surface defensive gaps by business unit.
- Auto-tag PRs impacted by matrix updates.

### 7) “Social Media for Detection Engineering”

Democratize detection content with collaboration features:

- User profiles, teams, and organization spaces.
- Detection feeds (“new”, “trending”, “high-confidence”, “industry-specific”).
- Fork, remix, submit PR, and cite upstream contributors.
- Reputation scoring based on rule quality, testing rigor, and community adoption.
- Comment threads, RFC discussions, and governance voting.
- Verified maintainers and signed releases for trust.

## Reference Architecture

- **Frontend**: React/Next.js collaboration portal.
- **API Layer**: GraphQL + REST for ingestion, testing, and feed interactions.
- **Detection Compiler Service**: Converts abstract detection schema into engine-specific dialects.
- **Normalization Service**: ECS mapping, validation, and schema drift analytics.
- **Execution/Test Service**: Runs unit, replay, and emulation validations.
- **Knowledge Graph Service**: MITRE matrix and relationship graph traversal.
- **GitHub Integration Service**: Repo sync, PR checks, branch protections, signed commits.
- **Storage**:
  - Relational DB for metadata.
  - Object storage for fixtures and telemetry samples.
  - Search datastore for normalized events.

## Proposed API Surface (MVP)

- `POST /detections/import` (tool payload import)
- `POST /detections/generate` (natural-language to detection scaffold)
- `POST /logs/ingest` (raw logs upload)
- `POST /logs/map/ecs` (field mapping suggestion)
- `POST /detections/{id}/test` (run unit + regression tests)
- `POST /emulation/run` (execute adversary simulation)
- `GET /coverage/mitre` (coverage analytics)
- `GET /feed/trending` (community detections)

## Governance & Security

- Mandatory code owners for production detection packs.
- Signed commits and provenance attestations for trusted content.
- Role-based access controls for org/private detections.
- Content moderation and abuse reporting for public collaboration spaces.
- Secrets redaction and PII controls in shared telemetry fixtures.

## MVP Delivery Plan

### Phase 1: Foundation

- GitHub-backed detection schema + repo scaffolding.
- Basic import/generation flows.
- ECS mapping assistant.

### Phase 2: Quality Engine

- Unit test runner and CI quality gates.
- Rule linting and compatibility checks.
- Initial ATT&CK coverage dashboard.

### Phase 3: Validation at Scale

- Emulation orchestration and replay testing.
- Performance benchmarking and detection scoring.

### Phase 4: Social Layer

- Feeds, forks, discussions, reputation, and verified maintainers.
- Cross-org detection exchange marketplace.

## Success Metrics

- Mean time to create validated detection.
- Detection test pass rate over time.
- ATT&CK/ATLAS coverage completeness.
- False-positive rate by detection family.
- Community adoption (forks, stars, deployments).

## Long-Term Outcome

ThreatDetectionPlatform becomes a shared security knowledge network: detections are not static artifacts, but continuously improved, testable, and transparent defenses co-developed by practitioners, analysts, and threat researchers.

## Execution Artifacts Added

To turn this blueprint into implementation work, see:

- `docs/NEXT_STEPS.md` for a 12-week delivery plan and immediate priority tickets.
- `schemas/detection.schema.json` for the initial detection contract.
- `detections/examples/t1059_powershell/` for an end-to-end sample detection package.

## Open-Source Detection Library

A starter detection library is available at `detections/library/` with curated rules normalized into the project schema and mapped to MITRE ATT&CK.

See `docs/DETECTION_LIBRARY.md` for curation details and next curator tasks.
