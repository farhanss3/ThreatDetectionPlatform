# Next Steps (Execution Plan)

This plan translates the product blueprint into concrete build work.

## 0) Week 0: Repo Bootstrap

- [ ] Add core detection schema JSON files under `schemas/`.
- [ ] Add one end-to-end sample detection package under `detections/examples/`.
- [ ] Add contribution workflow docs and code-owner model.
- [ ] Add CI stub for lint/test placeholders.

## 1) Weeks 1-2: Detection-as-Code Foundations

- [ ] Define canonical `detection.yml` contract (id, title, severity, query, mappings, tests).
- [ ] Implement schema validation script for detection packages.
- [ ] Add PR template requiring ATT&CK mapping + test evidence.
- [ ] Add semantic versioning + changelog conventions.

Deliverable: Contributors can submit detection PRs that are validated for structure.

## 2) Weeks 3-4: Ingestion MVP

- [ ] Build import adapter interface (tool name + payload -> normalized detection object).
- [ ] Implement first adapter (e.g., Sigma-like import).
- [ ] Build natural-language ingest prompt contract and output format.
- [ ] Save generated detections as branch + PR workflow.

Deliverable: Platform can ingest one external format and one NL-driven path.

## 3) Weeks 5-6: ECS Mapping MVP

- [ ] Define mapping contract: raw field -> ECS field + confidence + rationale.
- [ ] Add parser stubs for JSON and CSV logs.
- [ ] Implement mapping review workflow (accept/reject overrides).
- [ ] Persist mapping templates per source type.

Deliverable: Users can onboard raw logs and produce ECS-like normalized events.

## 4) Weeks 7-8: Testing & Quality Gates

- [ ] Add unit-test fixture format and test runner contract.
- [ ] Add baseline false-positive test shape (negative fixtures).
- [ ] Add CI checks: schema validation + test pass/fail + mapping existence.
- [ ] Create quality score model (coverage, test rigor, noise).

Deliverable: No detection merges without passing quality gates.

## 5) Weeks 9-10: Emulation + MITRE Coverage

- [ ] Add emulation manifest format (`emulation/manifest.yml`).
- [ ] Integrate one simulator path (local mock or Atomic-compatible command wrapper).
- [ ] Add ATT&CK technique coverage reporting.
- [ ] Add ATLAS and D3FEND relationship placeholders.

Deliverable: Detections can be validated against simulated behavior and mapped to MITRE frameworks.

## 6) Weeks 11-12: Collaboration Layer (MVP)

- [ ] Add detection metadata for ownership, status, and trust score.
- [ ] Build feed primitives: latest, trending, most-tested.
- [ ] Add comment/discussion model linked to detection IDs.
- [ ] Add fork/remix attribution metadata.

Deliverable: A basic social workflow for collaborative detection engineering.

---

## Immediate Priority Tickets (Start Here)

1. Create `schemas/detection.schema.json` and validate sample detection package.
2. Add one sample detection (`T1059 PowerShell`) with tests and ATT&CK mapping.
3. Add a script entrypoint for schema validation in CI.
4. Add docs for contribution workflow and quality gates.

