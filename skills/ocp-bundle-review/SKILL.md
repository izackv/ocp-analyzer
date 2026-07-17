---
name: ocp-bundle-review
description: Review an OpenShift cluster from a collect-ocp-review.sh (or collect-ocp-overview.sh) output bundle. Produces an architecture review, a severity-ranked issues list with evidence/risk/mitigation, and an attention-points file. Use when the user asks to analyze/review an OCP cluster bundle, cross-check a TSR report, or assess OpenShift health from collected oc outputs.
---

# OCP Bundle Review

You are reviewing an OpenShift cluster **offline**, from a directory of `oc`
command outputs collected by `collect-ocp-review.sh` (files named `NN-*.txt`,
`NN-*.yaml`, `NN-*.json`; failures recorded as `NN-*.err`). A Red Hat TSR
report PDF may also be present. You have no cluster access — every claim must
be backed by a file in the bundle (or a cited TSR section).

## Workflow

1. **Locate the data.** Find the bundle directory (files may be at the top
   level or in a `ocp-review_*` subdirectory). Read `SUMMARY.txt` first if
   present; `00-meta.txt` (if present) gives the collector version, bundle
   format, and collection timestamp — quote the collection time in the review
   (the data is a point-in-time snapshot). Read the collection script if present — it maps each output file
   to the exact `oc` command, which you must cite as evidence.
2. **Orient.** Read the small files fully (00, 01, 02, 03-network-config,
   04-storageclasses/storagecluster, 05-catalogsource/subscriptions/
   installplan, 07-oauth/scc/etcd-encryption, 08-*, 09-argocd, 10-*).
   Grep/sample the big ones (pods-all, pv, pvc, csv, clusterrolebindings,
   routes, networkpolicy, workloads, identities, events) — extract counts and
   outliers, don't read them whole.
3. **If a TSR/audit PDF exists**, extract its text and cross-check every
   finding against the raw data. Record confirmations, contradictions, and
   scope differences — TSRs are AI-generated and DO contain errors (a real
   example: a TSR attributed logging-Elasticsearch PVCs to the wrong
   storage class; the live `04-pvc.txt` disproved it).
4. **Run the checklist below**, then write the three deliverables.
5. If `ocp-analyzer/ocp_analyzer.py` is available, you may run it for a fast
   first pass (`python3 ocp_analyzer.py <bundle>`) — but always go beyond it:
   it is heuristic, and you can correlate across files in ways it cannot.

## Checklist (findings repeatedly seen in the field)

Work through ALL of these; each cites the file to check.

**Lifecycle / control plane**
- `01-clusterversion.yaml`: `force: true` in spec; "Forced through blocking
  failures" in history; update cadence (gaps between completionTimes);
  RetrievedUpdates condition; release image mirror.
- `01-clusteroperators.txt`: anything not Available=True/Progressing=False/
  Degraded=False.
- `01-version.txt`: client/server skew; EUS minor? (verify current phase online).
- `02-nodes-capacity.txt` + `02-top-nodes.txt`: master sizing vs load —
  masters ≥70% memory or <16 vCPU on a busy cluster is a finding; ties into
  any TSR etcd-latency findings.
- `02-mcp.txt`, `02-machineconfigs.txt`, `02-kubeletconfig.yaml`: pools not
  converged; systemReserved vs node RAM.
- `02-nodes-conditions.txt`: any node with MemoryPressure/DiskPressure/
  PIDPressure=True (eviction risk) or NetworkUnavailable=True (no pod network).
- `01-etcd-readyz.txt`: any `[-]` line = an API-server readiness gate failing
  (etcd, informers, controllers). `01-etcd-cr.yaml`: etcd operator conditions
  and control-plane member status. Note: WAL-fsync/backend-commit latency is
  NOT in the bundle; recommend a live check if etcd latency is suspected.

**Backup / DR (most-missed critical)**
- `10-cronjobs.txt` + `06-pods-all.txt`: find backup/etcd-named CronJobs,
  then check their recent pods actually `Completed` — consecutive `Error`
  pods with an old last-success = no restore point. Also: OADP/Velero/Kasten
  presence (`10-*`); ask when a restore was last TESTED.

**Storage**
- `04-pvc.txt`: database/Elasticsearch-looking PVCs on CephFS or other file
  storage (unsupported for DBs/ES) — name-based heuristic, say so.
- `04-pv.txt`: Released/Failed PVs (storage leaks); distribution by class.
- `04-localvolume.yaml`: OSD device paths must be /dev/disk/by-id, not dm-name-*.
- `04-storagecluster.yaml`: ODF version (compare with known corruption-fix
  z-streams), MDS/OSD resource sizing.

**Operators**
- `05-installplan.txt`: APPROVED=false rows (pending updates piling up).
- `05-catalogsource.txt`: deprecated redhat-marketplace, community sources.
- `05-csv.txt`: EOL stacks (ES-based logging 5.x), duplicate/legacy operators
  (e.g. RHSSO+RHBK both installed), operators that will block the next OCP
  minor upgrade.
- `05-subscriptions.txt`: empty file despite installed operators = collection
  bug (resource-name collision) — flag it, use installplans instead.

**Security**
- `07-scc.txt`: default `restricted`/`restricted-v2`/`node-exporter` drift
  vs stock (restricted SELINUX must be MustRunAs); custom PRIV=true SCCs.
- `07-clusterrolebindings.txt`: count cluster-admin grants; flag service
  accounts (monitoring/GitOps/backup tools), individual users, and stale
  `must-gather-*` bindings.
- `00-access.txt`: `can-i create clusterrolebindings` = yes → audit account
  not read-only.
- `07-etcd-encryption.txt` empty → encryption off. `07-kubeadmin-exists.txt`.
- `07-oauth.yaml`: HTPasswd in production; `insecure: true` / `ldap://`
  (check last-applied annotation too — may be historical); mappingMethod.
- `07-webhooks.txt`: failurePolicy=Fail on core resources.
- `07-cert-expiry.txt`: platform cert expiry from the `certificate-not-after`
  annotation (metadata only, no key material). Anything under ~30 days from the
  collection date is a finding; cert-manager CRs are separate in
  `07-certificates.txt`.
- `07-acm-policies.txt`: RHACM policies reporting NonCompliant (governance/
  config drift), if the cluster is ACM-managed.

**Network**
- `03-network-config.yaml`: cluster/service CIDRs private? (public ranges =
  permanent, document-only finding).
- `03-networkpolicy.txt` vs `06-projects.txt`: coverage ratio.
- `03-ingresscontroller.yaml`: replicas, zone spread, endpoint strategy.
- `03-routes.txt`: routes without TLS termination.
- `03-nnce.txt`: enactments in Failing/Aborted state (declared bond/VLAN/DNS/
  bridge config did not apply on a node); `03-nncp.yaml` for the intended state.
- `03-whereabouts-ippools.yaml`: allocations with an empty/absent `podref` =
  leaked IPs that can exhaust the range. Cross-ref pods for true duplicates.
- `03-ovnkube-pods.txt` vs `02-nodes-wide.txt`: every node needs one
  `ovnkube-node` pod; a node without one has no working pod network.

**Workloads / tenancy**
- `06-pods-all.txt`: restart-count outliers (≥100), ImagePullBackOff (on
  disconnected clusters = images missing from the mirror — also breaks DR),
  clusters of pods stuck in the same Init state (shared root cause),
  "test"-named workloads in prod namespaces.
- `06-pdb.txt`: ALLOWED=0 (blocks drains → blocks patching).
- `06-resourcequota.txt`/`06-limitrange.txt` coverage; maxed-out quotas.
- `06-projects.txt`: stale openshift-debug-*/must-gather-* namespaces.
- `06-workloads-status.txt` / `06-daemonsets-status.txt`: Deployments/
  StatefulSets with READY < DESIRED and DaemonSets with unavailable pods
  (redundancy loss or crash loops); confirm against `06-pods-all.txt`.

**Observability**
- `08-cluster-monitoring.yaml`: additionalAlertmanagerConfigs (forwarding to
  a hub?) — receivers live in a Secret you cannot see, so ALWAYS phrase as
  "verify a test alert reaches a human end-to-end".
- `08-active-alerts.json`: triage critical alerts. `08-clusterlogging.yaml`:
  stack version, storage class, forwarder targets.

**GPU / DGX (if `12-*` files present)**
- GPU capacity vs allocatable mismatch; ClusterPolicy driver/MIG config vs
  node labels; NicClusterPolicy/IPoIB for InfiniBand; idle GPUs (no
  consumers); PerformanceProfile. GPU *health* is not in the bundle — say so.

## Deliverables

Write three markdown files next to the bundle, named
`<cluster>-architecture-review.md`, `<cluster>-issues.md`,
`<cluster>-attention-points.md`:

1. **Architecture review** — customer-facing: identity/lifecycle table,
   topology, network, storage, operators & platform services, identity &
   security, observability, backup/DR, tenancy; end with genuine strengths
   and top recommendations. Facts only, each traceable to a file.
2. **Issues list** — severity-ranked (CRITICAL/HIGH/MEDIUM/LOW). Per issue:
   **Source** ([Script]/[TSR]/[Both]), **Evidence** (file + the `oc` command
   that produced it + short excerpt; or TSR section §), **Risk** (concrete
   consequence), **Mitigation** (actionable steps). Group findings sharing a
   root cause. If a TSR exists, append a mapping table: every TSR finding →
   your issue number, plus a list of script-only findings the TSR missed.
3. **Attention points** — for the reviewer, not the customer:
   TSR-vs-data discrepancies, findings you could not verify (and why),
   collection anomalies (empty files, .err contents), questions to ask the
   customer, data-freshness and confidentiality warnings.

## Rules

- **Every claim needs evidence.** Cite file + command; quote the line when short.
- **Mark assumptions explicitly** (name-based classification, thresholds,
  build-time knowledge such as EOL dates).
- **Distinguish "verified absent" from "not collected"** — a missing file or
  `.err` means unknown, not "no".
- Data is point-in-time: state the collection date; recommend a fresh run if
  the review is presented much later.
- The bundle contains real usernames, hostnames, and the full route
  inventory — treat outputs as confidential; suggest `sanitize-ocp-bundle.py`
  before sharing beyond the account team.
