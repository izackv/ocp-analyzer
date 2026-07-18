# ocp-analyzer — OpenShift cluster review toolkit

A self-contained toolkit for reviewing OpenShift clusters, built for
environments ranging from fully connected to fully air-gapped. Copy this one
folder to wherever the work happens; nothing here needs internet access or
pip packages — just `bash`, `oc`, and Python 3.6+ (stock RHEL 8/9 is enough).

> **Personal project — no warranty.**
> This is a personal project by **Izack Varsanno**. I did my best to verify
> that it is safe (read-only collection, no secret data) and of good quality,
> but it is provided **as-is, without warranty of any kind**. You are
> responsible for reviewing what it does and for any consequences of using it
> in your environment. See [LICENSE](LICENSE).

> **Note for existing clones:** repository history was rewritten on
> 2026-07-18 (commit messages only — file contents are unchanged). If you
> cloned before that date, update with:
> `git fetch origin && git reset --hard origin/main && git fetch --tags --force`

## Quick start

### Get the code

```bash
git clone https://github.com/izackv/ocp-analyzer.git
# air-gapped? download a release archive from GitHub instead and carry the
# folder in — the target machine needs no internet or pip (see intro above)
```

### Get the data

```bash
# on a machine with cluster access; strictly read-only
export KUBECONFIG=/path/to/kubeconfig
./collect-ocp-review.sh                      # -> bundle dir: ocp-review_<cluster>_<ts>/
./collect-ocp-review.sh --sanitize           # ...plus a sanitized copy for external sharing

# analyzing on another machine? move the bundle as ONE checksummed file
./pack-bundle.sh ocp-review_prod_20260705-090000
#   ... transfer the .tar.gz + .sha256 ...
./unpack-bundle.sh ocp-review_prod_20260705-090000.tar.gz
```

### Analyze the data with Python

Runs wherever the bundle is — on the bastion itself or after transferring it.
No cluster or internet access needed:

```bash
python3 ocp_analyzer.py ocp-review_prod_20260705-090000
#   -> ocp-review_prod_20260705-090000-analysis/{architecture-overview,issues,attention-points,manual-review-guide}.md + findings.json
```

### Analyze the data with AI

Likewise runs wherever the bundle is, in-place or transferred (details in
"The Claude Code skill" below). Install the skill once, either for your
user (all projects) or into the folder holding the evidence:

```bash
cp -r skills/ocp-bundle-review ~/.claude/skills/                # user-wide
cp -r skills/ocp-bundle-review <data-folder>/.claude/skills/    # this data folder only
```

Then `cd` into the directory holding the bundle, open a Claude Code
session (`claude`), and run:

```
/ocp-bundle-review
```

## Choosing a workflow

| Situation | Do this |
|---|---|
| Bundle may leave the network, AI available | Collect → pack → transfer → review with the **skill** (deepest analysis) |
| Bundle may leave only sanitized | Collect with `--sanitize` → pack the `-sanitized` directory → analyze that. Keep the reverse map at home; it translates findings back. |
| Nothing leaves the network | Collect → run `ocp_analyzer.py` in place → hand the generated `.md` files to the reviewer. `manual-review-guide.md` tells a human what the analyzer could not judge. |

## Terminology

| Term | What it means |
|---|---|
| **Bundle** (or *bundle directory*) | The **directory of files** produced by the collector, named `ocp-review_<cluster>_<timestamp>/`. It contains ~90 plain-text files (`NN-*.txt`, `NN-*.yaml`, `NN-*.json`) plus `SUMMARY.txt`. Every other tool in this kit takes this directory as input. |
| **Packed bundle** (or *archive*) | The bundle directory compressed into **one single file** (`<bundle>.tar.gz`, plus a `.sha256` checksum, optionally a `.b64` text version) by `pack-bundle.sh` — for moving it between machines. Unpack it back into a bundle directory before analyzing. |
| **Sanitized bundle** | A pseudonymized **copy** of a bundle directory (`<bundle>-sanitized/`), safe(r) to share externally. The original is never modified. |
| **Reverse map** | `<bundle>-sanitized-map.json` — the private file that translates sanitized names back to the real ones. **Never ship it together with the sanitized bundle.** |

In short: tools work on the bundle **directory**; the `.tar.gz` exists only
for transport.

## What's in the folder

| File | Role |
|---|---|
| `collect-ocp-review.sh` | **Collector.** Runs read-only `oc` commands against a cluster and writes a bundle directory. |
| `sanitize-ocp-bundle.py` | **Sanitizer.** Creates a pseudonymized copy of a bundle for external sharing. |
| `ocp_analyzer.py` | **Offline analyzer.** Reads a bundle and generates markdown reports — for air-gapped situations where no AI review is possible. |
| `pack-bundle.sh` / `unpack-bundle.sh` | **Transport.** Turn a bundle directory into one checksummed file and back. |
| `skills/ocp-bundle-review/` | **Claude Code skill.** The full review methodology, for when the bundle *can* be analyzed with AI. |
| `tests/` | **Test suite** (stdlib `unittest`) — sanitizer leak tests and pack/unpack round-trip tests, with a synthetic fixture bundle (fake data only). |
| `README.md`, `LICENSE` | This file; MIT license. |

---

## Tool reference

### `collect-ocp-review.sh` — collector

Runs once per cluster, needs `oc` logged in (via `KUBECONFIG` or `oc login`).
Strictly read-only: only `oc get`, `oc adm top`, `oc auth can-i`, `oc whoami`,
`oc version`, `oc adm upgrade` and raw GET requests. It never reads
Secret/ConfigMap *data* (one existence-only check for the kubeadmin secret,
via `-o name`). Commands that fail (missing operator, RBAC denied) don't stop
the run — each failure is recorded in a `.err` file next to the intended
output, so "absent" and "not collectable" stay distinguishable.

```
./collect-ocp-review.sh [--sanitize] [cluster-label]
```

| Parameter | Meaning |
|---|---|
| `cluster-label` | Optional name used in the bundle directory name (`ocp-review_<label>_<ts>`). Default: derived from the API server hostname. |
| `-s`, `--sanitize` | After collecting, automatically run the sanitizer on the new bundle. |
| `-h`, `--help` | Show usage. |
| `KUBECONFIG` (env) | Which cluster to collect from. |

Output: a **bundle directory** covering access/identity, version & lifecycle,
nodes/machine-config, networking, storage (incl. ODF/Ceph), operators & OLM,
workloads & tenancy, security & RBAC, observability, GitOps, backup/DR,
warning events, and GPU/NVIDIA DGX (skipped gracefully on non-GPU clusters).
`SUMMARY.txt` at the top collects the red flags — read it first.

Tip: use a **read-only audit account**. The script checks its own permissions
and warns if the account can write to the cluster.

### `sanitize-ocp-bundle.py` — sanitizer

Creates a shareable copy of a bundle. The original bundle is never touched.
Python 3.6+, stdlib only.

```
./sanitize-ocp-bundle.py BUNDLE_DIR [-o OUTDIR] [-r ORIG[=NEW]]...
```

| Parameter | Meaning |
|---|---|
| `BUNDLE_DIR` | The bundle **directory** to sanitize (not the `.tar.gz` — unpack first). |
| `-o`, `--outdir OUTDIR` | Where to write the sanitized copy. Default: `<bundle>-sanitized/` next to the original. Must not already contain files. |
| `-r`, `--replace ORIG[=NEW]` | Extra literal replacement, repeatable. `ORIG` is replaced everywhere (case-insensitive) with `NEW`, or with `REDACTED` if `=NEW` is omitted. Use for org-specific strings the auto-detection can't know: other cluster names, company names, project code names. Example: `-r ocpmgmtlan=mgmt-cluster -r "Acme Corp"`. |

What gets replaced automatically, consistently across all files: the cluster
base domain and org domain, the cluster and org names, node hostnames
(→ `master01`, `worker01`, ...), usernames (from user lists, RBAC binding
subjects, group members, and the collecting account), every IPv4 address
(→ stable fakes from TEST-NET ranges), every UUID, email addresses, LDAP DN
components, and non-ASCII name runs.

Outputs:

- `<bundle>-sanitized/` — the shareable copy.
- `<bundle>-sanitized-map.json` — the **private reverse map**, written *next
  to* the sanitized directory, never inside it. Keep it; never share it.

**Sanitization is best-effort.** Spot-check the output before sharing, and
add `-r` rules for anything the auto-detection missed.

**Order matters:** sanitize the bundle first, then analyze the *sanitized*
bundle — that way the generated reports are clean too:

```bash
./sanitize-ocp-bundle.py <bundle> -r <other-cluster-name>=mgmt-cluster
python3 ocp_analyzer.py <bundle>-sanitized
```

### `ocp_analyzer.py` — offline analyzer

Heuristic analysis with zero cluster or internet access. Python 3.6+, stdlib
only. Never modifies the bundle.

```
python3 ocp_analyzer.py BUNDLE_DIR [-o OUTDIR]
```

| Parameter | Meaning |
|---|---|
| `BUNDLE_DIR` | The bundle **directory** to analyze (accepts v1 `collect-ocp-overview.sh` bundles too). |
| `-o`, `--outdir OUTDIR` | Where to write the reports. Default: `<bundle>-analysis/` next to the bundle. |

Generates three markdown reports:

- `architecture-overview.md` — what the cluster *is*: topology, versions, stack.
- `issues.md` — findings ranked CRITICAL/HIGH/MEDIUM/LOW/INFO, each with
  evidence, risk, and recommendation. Heuristic assumptions are stated
  explicitly in the report.
- `manual-review-guide.md` — what a human should still check per file, i.e.
  everything the heuristics cannot judge.

Limitations (by design, stated in the reports): YAML is mined with regexes
(no YAML parser in stdlib), and lifecycle/EOL statements rely on knowledge
baked in at build time — see `BUILD_KNOWLEDGE_DATE` in the script and
re-verify online when possible.

### `pack-bundle.sh` — pack for transport

Turns a bundle **directory** into **one file** plus a checksum.

```
./pack-bundle.sh BUNDLE_DIR [--text]
```

| Parameter | Meaning |
|---|---|
| `BUNDLE_DIR` | The directory to pack (works for any directory, e.g. a `-sanitized` copy). |
| `-t`, `--text` | Additionally write `<dir>.tar.gz.b64` — a base64 **text** version of the archive, for transfer paths that only allow text (mail filters, copy/paste through a jump host). |
| `-h`, `--help` | Show usage. |

Creates `<dir>.tar.gz` and `<dir>.tar.gz.sha256` (and `.b64` with `--text`).
Transfer the archive **and** the `.sha256` together.

### `unpack-bundle.sh` — restore a packed bundle

```
./unpack-bundle.sh FILE [DEST_DIR]
```

| Parameter | Meaning |
|---|---|
| `FILE` | Either the binary archive (`<name>.tar.gz`) or the base64 text version (`<name>.tar.gz.b64`) — detected by extension. |
| `DEST_DIR` | Where to unpack. Default: current directory. |

Verifies the `.sha256` checksum when present (mismatch aborts; a missing
checksum file only warns). Restores the original bundle directory.

## The Claude Code skill

Copy the skill into your personal or project skills directory:

```bash
cp -r skills/ocp-bundle-review ~/.claude/skills/          # personal, all projects
# or
cp -r skills/ocp-bundle-review <project>/.claude/skills/  # this project only
```

Then `cd` into the directory holding the bundle (and the TSR PDF, if you
have one), open a Claude Code session (`claude`), and run:

```
/ocp-bundle-review
```

or just ask: *"review the OCP bundle in this folder"*. The skill directs
Claude to produce the same three documents as a full manual review:
`<cluster>-architecture-review.md`, `<cluster>-issues.md` (each issue with
Source/Evidence/Risk/Mitigation and a TSR-mapping appendix when a TSR is
present), and `<cluster>-attention-points.md` (discrepancies, unverifiable
findings, questions for the customer).

### Using other agents / local models

The skill is plain markdown instructions plus files on disk — nothing in it
is Claude-specific. With any coding agent that can read files and run shell
commands (opencode, aider, goose, ...), `cd` into the bundle directory and
prompt:

> Read `<repo>/skills/ocp-bundle-review/SKILL.md` and perform the review it
> describes on the bundle in this directory.

Model quality matters more than the agent: the review needs long-context,
multi-file correlation with disciplined evidence citation. Hosted frontier
models handle it; local models (vLLM/Ollama on a DGX, Ollama/MLX on Apple
Silicon) vary — validate a local setup by comparing its output against
`ocp_analyzer.py` and a known-good review before trusting it, and treat the
deterministic analyzer as the floor either way.

## Tests

The suite uses only the Python standard library, so it runs anywhere the
tools do — including an air-gapped bastion:

```bash
python3 -m unittest discover tests
```

What it covers:

- **Sanitizer leak tests** (`tests/test_sanitizer.py`): a synthetic fixture
  bundle (`tests/fixtures/`, fake data only) is seeded with known sensitive
  values — domain, cluster/org names, usernames (including RBAC-only and
  group-member-only users), node hostnames, IPs, UUIDs, emails, LDAP DNs and
  a non-ASCII name. The core assertion: **none of them may survive
  sanitization**. Also verified: the reverse map is complete and lands
  outside the shareable directory, the same IP maps to the same fake value
  in every file, the original bundle is untouched, non-text files are
  skipped, and `-r` extra rules work.
- **Pack/unpack round-trip** (`tests/test_pack_roundtrip.py`): pack → unpack
  reproduces the bundle byte-for-byte, both via the binary archive and the
  base64 `--text` path; a tampered archive is rejected by the checksum
  check; a missing checksum warns but unpacks.

Run the tests after copying the toolkit into a new environment — they double
as a self-check that the tools work there.

## Safety & data-handling notes

- The collector is strictly read-only and never reads Secret/ConfigMap data.
- Bundles still contain sensitive metadata: usernames, hostnames, IPs, the
  full application route inventory. Treat every bundle as confidential;
  sanitize before any external sharing.
- Point-in-time: all statements reflect the collection moment. Re-collect
  before presenting if significant time has passed.
- The offline analyzer's lifecycle/EOL statements rely on knowledge baked in
  at build time (`BUILD_KNOWLEDGE_DATE` in `ocp_analyzer.py`) — refresh when
  updating the toolkit, and re-verify online when possible.

## Checks inspired by in-cluster-checks

Some of the collector's later checks were inspired by the Red Hat
[in-cluster-checks](https://github.com/RedHatInsights/incluster-checks)
project, which validates cluster health by running rules **on the nodes** via
`oc debug`. The **ideas** were reused, not the code: in-cluster-checks is a
Python rule engine that needs live, privileged node access, whereas this
toolkit stays read-only, offline-analyzable, and `oc get`-only. Where one of
its node-level rules describes a condition that is also visible at the cluster
API, that condition was reproduced here as a plain read-only collection line.

Only the API-visible subset was ported. Node-shell-only checks (BIOS/firmware
inventory, OVS/OVN internal state, Ceph OSD internals, thermal sensors, SELinux,
etcd WAL-fsync latency, and similar) are intentionally out of scope, because
they cannot be gathered without a shell on the node. For those, use
in-cluster-checks or a live session; the two tools stay complementary.

Collection lines added under this inspiration (all strictly read-only):

| Area | Command | Condition it surfaces |
|---|---|---|
| Control plane | `oc get etcd cluster -o yaml` | etcd operator conditions, member status |
| Control plane | `oc get --raw /readyz?verbose` | per-component API readiness gates (etcd, informers) |
| Nodes | `oc get nodes` (condition columns) | MemoryPressure / DiskPressure / PIDPressure / NetworkUnavailable |
| Networking | `oc get nncp -o yaml`, `oc get nnce` | NodeNetworkConfigurationPolicy status and per-node enactment |
| Networking | `oc get ippools -A -o yaml` | Whereabouts IPAM allocations (leaked/orphan IPs) |
| Networking | `oc get pods -n openshift-ovn-kubernetes -o wide` | one ovnkube-node pod per node (pod network up) |
| Workloads | `oc get deploy,statefulset,daemonset` (status columns) | replicas ready vs desired |
| Security | `oc get policies.policy.open-cluster-management.io -A` | RHACM governance compliance |
| Security | `oc get secret -A` (not-after annotation only) | platform certificate expiry (metadata only, never key data) |

The certificate-expiry line reads only the
`auth.openshift.io/certificate-not-after` **annotation**; the certificate and
key bytes in a Secret's `data` are never read, keeping the collector's
read-only, no-secret-data guarantee intact.

## Versioning & releases

The toolkit uses **CalVer**: `YYYY.MM`, with a `.patch` suffix only if the
same month gets a second release (e.g. `2026.07`, then `2026.07.1`). A date
makes the most important property — how stale the analyzer's baked-in
knowledge is — visible at a glance; the collector and analyzer are always
released together under one number.

Two version numbers exist, on different cadences:

- **`TOOLKIT_VERSION`** (in both `collect-ocp-review.sh` and
  `ocp_analyzer.py`) — the release of the tools themselves.
- **`BUNDLE_FORMAT`** (currently `2`) — the bundle *layout*. It only changes
  when files are renamed/removed or restructured incompatibly, **not** when
  new collection lines are added; the analyzer already tolerates missing
  files.

The collector stamps both into `00-meta.txt` inside every bundle, along with
the collection timestamp and cluster label. The analyzer reads that stamp,
reports the collector version in every generated report header, and raises an
INFO finding if the bundle format is newer than the analyzer understands.
Bundles without `00-meta.txt` are simply from a pre-2026.07 collector.

A version marks a **release**, not a commit — cut one only when the toolkit
leaves this repo (a real review, or handing it to someone for a bastion).
Between releases, changes accumulate under `[Unreleased]` in `CHANGELOG.md`.

Release procedure:

1. Bump `TOOLKIT_VERSION` in `collect-ocp-review.sh` and `ocp_analyzer.py`
   (and `BUILD_KNOWLEDGE_DATE` if the baked-in facts were refreshed —
   normally yes).
2. Rename `[Unreleased]` in `CHANGELOG.md` to the version + date; start a
   fresh `[Unreleased]`.
3. `git tag v<version>` on the release commit.

## Related projects

If this toolkit is useful to you, you may also be interested in:

- **[in-cluster-checks](https://github.com/RedHatInsights/incluster-checks)**
  by Red Hat Insights — a framework that runs health-validation rules
  *directly on the cluster nodes* via `oc debug` (hardware, networking, Linux
  and storage checks, executed live and in parallel). It takes the opposite
  approach to this toolkit: it probes running nodes in-cluster, whereas
  ocp-analyzer does read-only collection and reviews the data **offline**
  (air-gapped-friendly, no node exec). The two complement each other well.

*ocp-analyzer is an independent personal project. It is **not** affiliated
with, endorsed by, or maintained by Red Hat or the Red Hat Insights team; the
link above is provided purely as a helpful pointer.*

## License & disclaimer

MIT — see [LICENSE](LICENSE). You may use, copy, modify and redistribute this
freely, **as long as the copyright notice stays intact** (that's the credit).
The software is provided *"as is"*, without warranty of any kind; the author
is **not liable for any claim, damage or other issue** arising from its use.
Always review scripts before running them against production clusters.

*OpenShift and Red Hat are trademarks of Red Hat, Inc. This project is an
independent work and is not affiliated with or endorsed by Red Hat, Inc.*
