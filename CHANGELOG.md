# Changelog

All notable changes to this toolkit are recorded here. Dates are ISO (YYYY-MM-DD).

## [Unreleased]

### Added

Analyzer overhaul, driven by a gap analysis of the script's reports vs
AI skill reviews of the same bundles (7 lab server-runs + 1 production):

- Cluster-profile severity calibration: topology (SNO vs HA), connectivity,
  tenant-vs-platform namespaces and cluster age now scale or suppress
  findings; suppressions are listed in an auditable ledger and a
  `Calibration:` line heads issues.md.
- Tri-state data semantics: `.err`/empty files are classified
  verified-absent / defaults-in-effect / collection-FAILED; failed
  collections raise explicit blind-spot findings and the overview gains a
  "Data availability" section.
- Stock-object baselines: shipped cluster-admin bindings whitelisted,
  custom SCCs risk-scored beyond the PRIV column (with operator
  attribution), one-shot installer pods triaged out, auto-rotated platform
  certs separated from manually managed ones.
- ~15 new checks promoting already-collected data into findings, incl.
  upgrade posture (Failing/Upgradeable, patch staleness, RHSA backlog),
  warning-event mining (OOM, scheduling, etcd disk latency), pending CSRs,
  failure-domain inference, monitoring-stack health and persistence,
  data-egress inventory, foreign route hostnames, OLM hygiene
  (InstallPlan-chain dedup, catalog usage, floating channels, operator
  remnants and superseded pairs), naming hygiene, rate-aware restarts.
- Correlation checks: node-outage cascade consolidation (one root finding,
  downstream symptoms tagged; kubelet-Unknown and Machine-API-remediation
  context), operator condition messages surfaced with core-vs-peripheral
  severity, and failed platform Jobs tied to degraded operators.
- Composite findings that join files: databases on node-local storage
  without backup, StorageClass functional validation (zero PV/PVC +
  provisioner events/DaemonSet health), backup-failure window dating that
  empirically upgrades the alert-delivery finding, image-pull age
  stratification with mirror-drift framing, certificates referenced by
  config but invisible to the expiry report.
- Identity-path analysis: circular (own-ingress) and cross-cluster IdP
  dependencies, unproven IdPs, orphaned identities, cluster-admin subject
  resolution - and kubeadmin-removal advice now inverts to "keep as
  break-glass" while the identity path is fragile.
- Temporal forensics: recent condition transitions (a green cluster that
  recovered hours ago is reported as a recent incident), mass-restart and
  mass-pod-recreation signatures.
- Machine-readable `findings.json` (stable rule ids) and `--prev DIR` for
  cross-run diffs (new / resolved / severity-changed) rendered into
  issues.md.
- Report shape: Top-priorities list, verified-healthy ledger, per-file
  `oc`-command evidence appendix, and a bundle-specific
  `attention-points.md` (collection anomalies, heuristic-findings review
  list, auto-generated customer questions, freshness + confidentiality
  notes with a secret-content scan).
- Analyzer unit tests (`tests/test_analyzer.py`, synthetic fixtures only).

### Fixed

- Four dead or misleading analyzer checks: the `00-access.txt`
  write-permission check never matched real output; "Version history" was
  mined from `availableUpdates` instead of `status.history`; the
  etcd-encryption check was skipped by the "(empty result)" marker; the
  alert-forwarding finding cited a file that was never collected.
  OAuth checks are now scoped to the active `spec:` (historical config in
  annotations no longer raises HIGH), and blank lines no longer skew
  counts.

- `unpack-bundle.sh`: intermittent exit 141 on Linux (GNU tar receiving
  SIGPIPE from `tar -tzf | head -1` under `set -o pipefail`, after a
  successful extraction). The top-level-dir detection now reads the full
  listing instead of exiting the pipe early. Found by running the test
  suite on a RHEL host; macOS buffering masked it.

### Security

- `collect-ocp-review.sh`: `07-oauthclients.txt` no longer contains OAuth
  client secrets. The default `oc get oauthclients` table prints the SECRET
  column in cleartext; the collector now uses custom columns (name,
  challenge/grant flags, token max age, redirect URIs) instead.
- `sanitize-ocp-bundle.py`: defense in depth for bundles collected before
  this fix - the SECRET column of an oauthclients table and single-line
  `secret:`/`clientSecret:` yaml fields are replaced with
  `REDACTED-OAUTH-SECRET`. Redaction is irreversible: secrets are never
  written to the private map file. Leak tests added in
  `tests/test_sanitizer.py` with a seeded fixture.

## [2026.07] - 2026-07-17

### Added

Toolkit versioning (CalVer `YYYY.MM[.patch]`, starting at `2026.07`):

- `TOOLKIT_VERSION` and `BUNDLE_FORMAT` constants in both
  `collect-ocp-review.sh` and `ocp_analyzer.py`; the collector stamps them
  with the collection timestamp and cluster label into `00-meta.txt` in every
  bundle.
- The analyzer (`check_meta`) reads the stamp, shows the collector version in
  all report headers and the CLI summary, and raises an INFO finding when the
  bundle format is newer than the analyzer. `--version` flag added.
- README section on the versioning scheme and release procedure.

Collection checks inspired by the read-only, API-visible subset of Red Hat's
in-cluster-checks project (ideas reused, not code). All strictly read-only:

- **Control plane:** `01-etcd-cr.yaml` (`oc get etcd cluster`) and
  `01-etcd-readyz.txt` (`oc get --raw /readyz?verbose`) for etcd/API-server
  readiness gates and member status.
- **Nodes:** `02-nodes-conditions.txt` now reports MemoryPressure,
  DiskPressure, PIDPressure and NetworkUnavailable per node.
- **Networking:** `03-nncp.yaml` and `03-nnce.txt` (NodeNetworkConfiguration
  policy and enactment status), `03-whereabouts-ippools.yaml` and
  `03-whereabouts-overlap.txt` (Whereabouts IPAM), `03-ovnkube-pods.txt`
  (ovnkube-node coverage per node).
- **Workloads:** `06-workloads-status.txt` and `06-daemonsets-status.txt`
  (ready vs desired replicas).
- **Security:** `07-acm-policies.txt` (RHACM governance compliance) and
  `07-cert-expiry.txt` (platform certificate expiry read from the
  `auth.openshift.io/certificate-not-after` annotation only, never the
  certificate or key bytes).
- `SUMMARY.txt` red-flag blocks for node pressure, failing readiness gates,
  ovnkube-node coverage, under-replicated workloads, and NonCompliant RHACM
  policies.

- **Analyzer (`ocp_analyzer.py`):** new checks `check_node_pressure`,
  `check_workload_status`, `check_nncp`, `check_whereabouts`,
  `check_etcd_health`, `check_ovnkube_coverage`, `check_acm_policies`, and
  `check_cert_expiry`. Certificate days-to-expiry are computed from the bundle
  collection timestamp, not the analysis-machine clock, so results stay
  correct for air-gapped, after-the-fact review.
- **Skill (`ocp-bundle-review`):** checklist bullets for the new files.
- **README:** section documenting which in-cluster-checks ideas were adopted
  and which node-level checks are intentionally out of scope.

### Changed

- `02-nodes-conditions.txt` replaced a fragile `conditions[-1].type` column
  with explicit Ready and pressure-condition columns.
