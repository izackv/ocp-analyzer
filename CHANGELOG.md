# Changelog

All notable changes to this toolkit are recorded here. Dates are ISO (YYYY-MM-DD).

## [Unreleased]

(nothing yet)

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
