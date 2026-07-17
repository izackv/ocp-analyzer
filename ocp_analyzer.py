#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ocp_analyzer.py - offline analyzer for OCP review bundles.

Analyzes the output of collect-ocp-review.sh (v2) or collect-ocp-overview.sh
(v1) WITHOUT any cluster or internet access, and generates:

    architecture-overview.md   what the cluster is (topology, versions, stack)
    issues.md                  findings with evidence / risk / recommendation
    manual-review-guide.md     what a human should still check in each file

Design constraints (deliberate):
  * Python 3.6+ standard library ONLY - runs on a stock RHEL 8/9 bastion in an
    air-gapped network, no pip required.
  * Never modifies the bundle; output goes to a sibling directory.
  * No YAML parser in stdlib -> YAML files are mined with targeted regexes,
    not fully parsed. Every heuristic that follows from this (or from having
    no access to Red Hat lifecycle/errata data) is written into the reports
    as an explicit ASSUMPTION.

Usage:
    python3 ocp_analyzer.py BUNDLE_DIR [-o OUTPUT_DIR]
"""
import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime
from pathlib import Path

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Toolkit release (CalVer YYYY.MM[.patch]); released together with
# collect-ocp-review.sh, which stamps the same values into 00-meta.txt.
# BUNDLE_FORMAT is the newest bundle layout this analyzer understands.
TOOLKIT_VERSION = "2026.07"
BUNDLE_FORMAT = 2

# Static knowledge baked in at build time - verify against current Red Hat docs.
BUILD_KNOWLEDGE_DATE = "2026-07"
EUS_MINORS = {"4.12", "4.14", "4.16", "4.18", "4.20"}   # even minors are EUS
DEFAULT_CLUSTER_ADMIN_CRBS = {
    "cluster-admin", "cluster-admins",
}
# `restricted` SCC defaults on OCP 4.11+ (columns of `oc get scc`)
RESTRICTED_SCC_DEFAULT_SELINUX = "MustRunAs"


# --------------------------------------------------------------------------- #
# bundle access helpers
# --------------------------------------------------------------------------- #
class Bundle(object):
    """Read-only view over a collection bundle; tolerant of v1/v2 file names."""

    # v2 name -> acceptable alternatives (v1 names)
    ALIASES = {
        "02-nodes-roles-zones.txt": ["02-nodes-roles.txt"],
        "01-clusteroperators.txt": [],
    }

    def __init__(self, path):
        self.path = Path(path)
        self._cache = {}

    def read(self, name):
        """Return file text, or None if absent/failed-marker."""
        if name in self._cache:
            return self._cache[name]
        text = None
        for candidate in [name] + self.ALIASES.get(name, []):
            f = self.path / candidate
            if f.is_file():
                t = f.read_text(errors="replace")
                if not t.startswith("(command failed"):
                    text = t
                break
        self._cache[name] = text
        return text

    def lines(self, name, skip_header=True):
        t = self.read(name)
        if t is None or t.startswith("(empty result)"):
            return []
        out = t.splitlines()
        return out[1:] if (skip_header and out) else out

    def exists(self, name):
        return self.read(name) is not None


def parse_age_days(s):
    """k8s age like '4y287d', '193d', '6h57m', '55s' -> float days."""
    total = 0.0
    for num, unit in re.findall(r"(\d+)([ywdhms])", s or ""):
        total += int(num) * {"y": 365.0, "w": 7.0, "d": 1.0,
                             "h": 1 / 24.0, "m": 1 / 1440.0,
                             "s": 1 / 86400.0}[unit]
    return total


def col_slice(header, line, col, next_cols):
    """Extract a fixed-width column from aligned `oc get` output."""
    start = header.find(col)
    if start < 0:
        return ""
    end = len(line)
    for nc in next_cols:
        p = header.find(nc)
        if p > start:
            end = min(end, p)
    return line[start:end].strip()


def yaml_grab(text, key):
    """First scalar value for `key:` in a YAML text (regex, not a parser)."""
    m = re.search(r"^\s*%s:\s*(\S.*?)\s*$" % re.escape(key), text or "", re.M)
    return m.group(1).strip("'\"") if m else None


# --------------------------------------------------------------------------- #
# analyzer
# --------------------------------------------------------------------------- #
class Analyzer(object):
    def __init__(self, bundle):
        self.b = bundle
        self.findings = []        # list of dicts
        self.facts = {}           # for the overview
        self.assumptions = [
            "YAML files are mined with regular expressions (Python stdlib has "
            "no YAML parser); deeply nested or unusually formatted manifests "
            "may be misread.",
            "The analyzer has NO access to Red Hat lifecycle, errata or CVE "
            "data. 'Latest version' and 'support phase' statements rely on "
            "knowledge baked in at build time (%s) and MUST be re-verified "
            "online." % BUILD_KNOWLEDGE_DATE,
            "Workload classification (e.g. 'database on CephFS') is inferred "
            "from PVC/namespace NAMES - a PVC named 'postgres-data' is assumed "
            "to hold PostgreSQL. Verify before acting.",
            "Point-in-time data: the bundle reflects the cluster at collection "
            "time only; restart counts, alerts and pod states may differ now.",
        ]

    # ---- finding helper ----------------------------------------------------
    def add(self, sev, area, title, evidence, risk, rec, assumption=None):
        self.findings.append({
            "sev": sev, "area": area, "title": title,
            "evidence": evidence, "risk": risk, "rec": rec,
            "assumption": assumption,
        })

    # ---- individual checks -------------------------------------------------
    def check_meta(self):
        t = self.b.read("00-meta.txt")
        if t is None:
            self.facts["collector_version"] = "unknown (pre-2026.07 collector)"
            return
        self.facts["collector_version"] = yaml_grab(t, "toolkit-version") or "?"
        fmt = yaml_grab(t, "bundle-format")
        if fmt and fmt.isdigit():
            self.facts["bundle_format"] = int(fmt)
            if int(fmt) > BUNDLE_FORMAT:
                self.add("INFO", "Analyzer",
                         "Bundle format %s is newer than this analyzer "
                         "(format %d)" % (fmt, BUNDLE_FORMAT),
                         "00-meta.txt: bundle-format: %s; analyzer %s."
                         % (fmt, TOOLKIT_VERSION),
                         "Files may have been renamed or restructured since "
                         "this analyzer was released; some checks may "
                         "silently miss their input.",
                         "Re-run with an analyzer from the same toolkit "
                         "release as the collector.")

    def check_access(self):
        t = self.b.read("00-access.txt")
        if not t:
            return
        m = re.search(r"whoami\n(\S+)", t)
        if m:
            self.facts["collector"] = m.group(1)
        m = re.search(r"## server\n(\S+)", t)
        if m:
            self.facts["api_url"] = m.group(1)
        # the 'yes' following the create-clusterrolebindings question
        m = re.search(r"create clusterrolebindings[^\n]*\n(?:[^\n]*\n)?(yes|no)", t)
        if m and m.group(1) == "yes":
            self.add("MEDIUM", "Process",
                     "Collection account has cluster write permissions",
                     "00-access.txt: `oc auth can-i create clusterrolebindings` "
                     "returned `yes`.",
                     "Audits should run least-privilege; a compromised audit "
                     "kubeconfig would grant full cluster control.",
                     "Create a dedicated read-only ServiceAccount/ClusterRole "
                     "for reviews.")

    def check_version(self):
        t = self.b.read("01-version.txt") or ""
        sm = re.search(r"Server Version:\s*(\d+)\.(\d+)\.(\S+)", t)
        cm = re.search(r"Client Version:\s*(\d+)\.(\d+)", t)
        if sm:
            self.facts["ocp_version"] = "%s.%s.%s" % sm.groups()
            self.facts["ocp_minor"] = "%s.%s" % (sm.group(1), sm.group(2))
        km = re.search(r"Kubernetes Version:\s*(\S+)", t)
        if km:
            self.facts["k8s_version"] = km.group(1)
        if sm and cm and abs(int(sm.group(2)) - int(cm.group(2))) >= 2:
            self.add("INFO", "Process", "oc client / server version skew >= 2 minors",
                     "01-version.txt: client %s.%s vs server %s.%s." %
                     (cm.group(1), cm.group(2), sm.group(1), sm.group(2)),
                     "Out of the supported +/-1 skew; some commands may "
                     "misbehave.", "Collect with a matching oc client.")
        minor = self.facts.get("ocp_minor")
        if minor:
            self.add("INFO", "Lifecycle",
                     "Verify OCP %s support phase" % minor,
                     "01-version.txt: server %s." % self.facts["ocp_version"],
                     "Running in EUS/maintenance phase limits fixes and can "
                     "gate Red Hat support.",
                     "Check the OpenShift life-cycle page for the current "
                     "phase of %s and plan upgrades accordingly." % minor,
                     assumption="%s is %san EUS-designated minor per build-time "
                                "knowledge (%s); the *current phase* cannot be "
                                "determined offline."
                                % (minor,
                                   "" if minor in EUS_MINORS else "NOT ",
                                   BUILD_KNOWLEDGE_DATE))

    def check_clusterversion(self):
        t = self.b.read("01-clusterversion.yaml")
        if not t:
            return
        self.facts["channel"] = yaml_grab(t, "channel")
        self.facts["cluster_id"] = yaml_grab(t, "clusterID")
        if re.search(r"^\s*force:\s*true\s*$", t, re.M):
            self.add("HIGH", "Lifecycle",
                     "`force: true` set in ClusterVersion spec",
                     "01-clusterversion.yaml: spec.desiredUpdate.force: true.",
                     "The next upgrade will silently bypass upgradeable checks "
                     "(admin acks, incompatible operators) - a common cause of "
                     "wedged upgrades.",
                     "Clear spec.desiredUpdate; adopt a pre-upgrade checklist "
                     "instead of forcing.")
        forced = len(re.findall(r"Forced through blocking failures", t))
        if forced:
            self.add("MEDIUM", "Lifecycle",
                     "%d past upgrade(s) forced through blocking preconditions" % forced,
                     "01-clusterversion.yaml history: 'Forced through blocking "
                     "failures' appears %d time(s), incl. reasons such as "
                     "AdminAckRequired / IncompatibleOperatorsInstalled." % forced,
                     "Indicates a pattern of bypassing safety gates; residual "
                     "risk may remain from skipped admin-acks.",
                     "Review each acceptedRisks entry; verify the skipped "
                     "preconditions were eventually satisfied.")
        if re.search(r"type:\s*RetrievedUpdates", t) and \
           re.search(r"reason:\s*RemoteFailed", t):
            self.add("INFO", "Lifecycle",
                     "Cluster cannot retrieve update graphs (disconnected)",
                     "01-clusterversion.yaml: RetrievedUpdates=False "
                     "(RemoteFailed).",
                     "Expected on air-gapped clusters, but it means update "
                     "discovery, upgrade-path validation and admin-ack hints "
                     "are entirely manual.",
                     "Ensure a documented process exists for mirroring new "
                     "releases and checking upgrade paths (e.g. via the "
                     "offline update-path tool).")
        # history versions for the overview
        hist = re.findall(r"^\s+version:\s*(\d+\.\d+\.\d+)\s*$", t, re.M)
        if hist:
            self.facts["version_history"] = list(dict.fromkeys(hist))
        # release image mirror
        img = yaml_grab(t, "image")
        if img and "/" in img:
            self.facts["release_mirror"] = img.split("/")[0]

    def check_clusteroperators(self):
        rows = self.b.lines("01-clusteroperators.txt")
        bad = []
        for line in rows:
            tok = line.split()
            if len(tok) >= 5 and (tok[2] != "True" or tok[3] != "False" or tok[4] != "False"):
                bad.append("%s (A=%s P=%s D=%s)" % (tok[0], tok[2], tok[3], tok[4]))
        self.facts["cluster_operators"] = len(rows)
        if bad:
            self.add("CRITICAL", "Stability",
                     "%d cluster operator(s) unavailable/degraded/progressing" % len(bad),
                     "01-clusteroperators.txt: " + "; ".join(bad[:8]) +
                     ("..." if len(bad) > 8 else ""),
                     "Degraded core operators mean platform functions are "
                     "impaired right now.",
                     "Inspect the operators' conditions in "
                     "01-clusteroperators.yaml and remediate before anything "
                     "else.")

    def check_nodes(self):
        rows = self.b.lines("02-nodes-wide.txt")
        if not rows:
            return
        roles, notready = {}, []
        for line in rows:
            tok = line.split()
            if len(tok) < 3:
                continue
            roles.setdefault(tok[2], []).append(tok[0])
            if tok[1] != "Ready":
                notready.append("%s (%s)" % (tok[0], tok[1]))
        self.facts["nodes_by_role"] = {r: len(v) for r, v in roles.items()}
        self.facts["node_count"] = sum(len(v) for v in roles.values())
        if notready:
            self.add("CRITICAL", "Stability",
                     "%d node(s) not Ready" % len(notready),
                     "02-nodes-wide.txt: " + ", ".join(notready[:6]),
                     "Reduced capacity/redundancy; workloads may be pending or "
                     "rescheduled.",
                     "Investigate kubelet/network/storage on the affected "
                     "nodes.")
        # master sizing heuristic
        caps = self.b.lines("02-nodes-capacity.txt")
        masters_small = []
        for line in caps:
            tok = line.split()
            if len(tok) >= 3 and ("mst" in tok[0] or "master" in tok[0]):
                try:
                    cpu = int(tok[1])
                    mem_gib = int(re.sub(r"\D", "", tok[2])) / (1024 * 1024)
                except ValueError:
                    continue
                if cpu < 16 or mem_gib < 63:
                    masters_small.append("%s: %d vCPU / %.0f GiB" % (tok[0], cpu, mem_gib))
        if masters_small:
            self.add("MEDIUM", "Capacity",
                     "Control-plane nodes may be undersized",
                     "02-nodes-capacity.txt: " + "; ".join(masters_small),
                     "Small masters correlate with etcd latency and API "
                     "slowness on busy clusters.",
                     "Compare against Red Hat control-plane sizing guidance "
                     "for this cluster's node/pod/CRD count; plan a resize if "
                     "utilization (02-top-nodes.txt) is high.",
                     assumption="Threshold used: <16 vCPU or <64 GiB flags a "
                                "master as 'small' for a multi-tenant "
                                "production cluster; master nodes are matched "
                                "by 'mst'/'master' in the hostname.")
        # utilization
        top = self.b.lines("02-top-nodes.txt")
        hot = []
        for line in top:
            tok = line.split()
            if len(tok) >= 5:
                mem_pct = tok[4].rstrip("%")
                cpu_pct = tok[2].rstrip("%")
                if mem_pct.isdigit() and int(mem_pct) >= 70:
                    hot.append("%s mem=%s%%" % (tok[0], mem_pct))
                elif cpu_pct.isdigit() and int(cpu_pct) >= 80:
                    hot.append("%s cpu=%s%%" % (tok[0], cpu_pct))
        if hot:
            self.add("MEDIUM", "Capacity",
                     "%d node(s) above utilization thresholds at collection time" % len(hot),
                     "02-top-nodes.txt: " + "; ".join(hot[:8]),
                     "Nodes near memory limits risk OOM/eviction storms; on "
                     "masters this endangers etcd.",
                     "Check trends in Prometheus; rebalance workloads, raise "
                     "systemReserved, or add capacity.",
                     assumption="Thresholds: memory >=70%, CPU >=80% at the "
                                "single point of collection.")

    def check_mcp(self):
        for line in self.b.lines("02-mcp.txt"):
            tok = line.split()
            if len(tok) >= 5 and (tok[2] != "True" or tok[3] != "False" or tok[4] != "False"):
                self.add("HIGH", "Stability",
                         "MachineConfigPool '%s' not converged" % tok[0],
                         "02-mcp.txt: UPDATED=%s UPDATING=%s DEGRADED=%s."
                         % (tok[2], tok[3], tok[4]),
                         "Nodes are mid-rollout or stuck; upgrades and config "
                         "changes will not complete.",
                         "`oc describe mcp %s` and check nodes' "
                         "machineconfiguration annotations." % tok[0])

    def check_pods(self):
        rows = self.b.lines("06-pods-all.txt")
        if not rows:
            return
        status_count, restarts, pull_fail = {}, [], []
        for line in rows:
            tok = line.split()
            if len(tok) < 5:
                continue
            ns, name, status = tok[0], tok[1], tok[3]
            if status not in ("Running", "Completed"):
                status_count[status] = status_count.get(status, 0) + 1
            if "ImagePull" in status or "ErrImage" in status:
                pull_fail.append("%s/%s" % (ns, name))
            if tok[4].isdigit() and int(tok[4]) >= 100:
                restarts.append((int(tok[4]), "%s/%s" % (ns, name), status))
        self.facts["pod_total"] = len(rows)
        self.facts["pod_not_running"] = status_count
        if restarts:
            restarts.sort(reverse=True)
            top = ["%s restarts=%d (%s)" % (n, c, s) for c, n, s in restarts[:6]]
            self.add("HIGH", "Workloads",
                     "%d pod(s) with >=100 restarts" % len(restarts),
                     "06-pods-all.txt: " + "; ".join(top),
                     "Crash-looping workloads burn resources, hide real "
                     "incidents and indicate unhealthy applications.",
                     "Triage with the app owners; fix or remove the top "
                     "offenders.")
        if pull_fail:
            self.add("HIGH", "Workloads",
                     "%d pod(s) failing image pulls" % len(pull_fail),
                     "06-pods-all.txt: " + ", ".join(pull_fail[:8]) +
                     ("..." if len(pull_fail) > 8 else ""),
                     "Services run below intended replicas AND the images are "
                     "not pullable - a redeploy or node failure would not "
                     "recover these workloads. On disconnected clusters this "
                     "usually means images were removed from the mirror "
                     "registry.",
                     "Audit the mirror registry for the missing tags; fix or "
                     "remove dead references.")
        crash = status_count.get("CrashLoopBackOff", 0)
        errors = status_count.get("Error", 0)
        if crash or errors:
            self.add("MEDIUM", "Workloads",
                     "Pods in CrashLoopBackOff/Error state",
                     "06-pods-all.txt: CrashLoopBackOff=%d, Error=%d." % (crash, errors),
                     "Failing workloads; Error pods from CronJobs often mean "
                     "silently broken scheduled tasks.",
                     "Review each; see also the backup check below.")
        stale = status_count.get("ContainerStatusUnknown", 0) + \
            sum(v for k, v in status_count.items() if k.startswith("Init"))
        if stale > 10:
            self.add("LOW", "Hygiene",
                     "Many stale/stuck pods need pruning or triage",
                     "06-pods-all.txt: ContainerStatusUnknown+Init-stuck = %d." % stale,
                     "Consumes etcd/API resources and clutters operations.",
                     "Prune old pods (`oc adm prune`); investigate pods stuck "
                     "in Init states (shared root cause is likely when many "
                     "sit in one namespace).")

    def check_etcd_backup(self):
        """Heuristic: find backup-ish CronJobs, then failed pods near them."""
        cron = self.b.lines("10-cronjobs.txt")
        backup_ns = set()
        for line in cron:
            tok = line.split()
            if len(tok) >= 2 and re.search(r"backup|etcd", tok[0] + tok[1], re.I):
                backup_ns.add(tok[0])
        if backup_ns:
            pods = self.b.lines("06-pods-all.txt")
            bad, ok_age = [], None
            for line in pods:
                tok = line.split()
                if len(tok) >= 5 and tok[0] in backup_ns:
                    if tok[3] == "Error":
                        bad.append("%s/%s" % (tok[0], tok[1]))
                    elif tok[3] == "Completed":
                        age = tok[7] if tok[5].startswith("(") and len(tok) > 7 else tok[5]
                        d = parse_age_days(age)
                        ok_age = d if ok_age is None else min(ok_age, d)
            if bad:
                self.add("CRITICAL", "Backup/DR",
                         "Backup job pods are failing (namespace(s): %s)"
                         % ", ".join(sorted(backup_ns)),
                         "10-cronjobs.txt + 06-pods-all.txt: Error pods: "
                         + ", ".join(bad[:6]) +
                         ("; most recent Completed backup pod is ~%.0f days old"
                          % ok_age if ok_age is not None else
                          "; NO Completed backup pod visible"),
                         "If these are etcd/cluster backups, there may be no "
                         "usable restore point.",
                         "Read the failing job logs, fix, verify the backup "
                         "destination, and alert on failures. Perform a "
                         "restore test.",
                         assumption="CronJobs are classified as backups by "
                                    "name/namespace matching 'backup' or "
                                    "'etcd'.")
        # platform-level backup tooling presence
        has_oadp = bool(self.b.lines("10-oadp-dpa.txt"))
        has_velero = bool(self.b.lines("10-velero-crs.txt"))
        has_kasten = bool(self.b.lines("10-kasten-policies.txt")) or \
            "kasten" in (self.b.read("06-projects.txt") or "")
        self.facts["backup_stack"] = ", ".join(
            [x for x, ok in (("OADP/Velero", has_oadp or has_velero),
                             ("Kasten K10", has_kasten),
                             ("custom CronJobs", bool(backup_ns))) if ok]) or "none detected"
        if not (has_oadp or has_velero or has_kasten or backup_ns):
            self.add("HIGH", "Backup/DR",
                     "No backup tooling detected on the cluster",
                     "10-*: no OADP DataProtectionApplication, no Velero CRs, "
                     "no Kasten policies, no backup-named CronJobs.",
                     "No apparent path to restore applications or etcd after "
                     "data loss.",
                     "Confirm with the customer how (or whether) this cluster "
                     "is backed up; external agents would not be visible here.",
                     assumption="Backup products visible only via their "
                                "cluster CRs; external/agent-based backup "
                                "cannot be detected from this bundle.")

    def check_storage(self):
        pvs = self.b.lines("04-pv.txt")
        by_status, by_sc = {}, {}
        for line in pvs:
            tok = line.split()
            if len(tok) >= 7:
                by_status[tok[4]] = by_status.get(tok[4], 0) + 1
                by_sc[tok[6]] = by_sc.get(tok[6], 0) + 1
        self.facts["pv_total"] = len(pvs)
        self.facts["pv_by_sc"] = by_sc
        released = by_status.get("Released", 0) + by_status.get("Failed", 0)
        if released:
            self.add("MEDIUM", "Storage",
                     "%d PV(s) in Released/Failed state" % released,
                     "04-pv.txt: statuses %s." % by_status,
                     "Orphaned volumes consume backend capacity invisibly "
                     "('storage leak'), and can push the backend toward full.",
                     "Review each Released PV: delete + reclaim backend space, "
                     "or re-bind if the data is still needed.")
        # default storage class
        sc_rows = self.b.lines("04-storageclasses.txt")
        defaults = [r.split()[0] for r in sc_rows
                    if r.split() and r.split()[-1] == "true"]
        self.facts["default_sc"] = defaults
        if len(defaults) == 0 and sc_rows:
            self.add("MEDIUM", "Storage", "No default StorageClass",
                     "04-storageclasses.txt: no class annotated as default.",
                     "PVCs without an explicit class stay Pending.",
                     "Mark exactly one class as default.")
        elif len(defaults) > 1:
            self.add("MEDIUM", "Storage",
                     "Multiple default StorageClasses",
                     "04-storageclasses.txt: defaults: %s." % ", ".join(defaults),
                     "Ambiguous default; PVC placement becomes "
                     "non-deterministic.",
                     "Keep a single default class.")
        # databases / ES on CephFS or other file storage
        db_re = re.compile(r"postgres|pgsql|\bpg\b|mysql|maria|mongo|oracle|"
                           r"mssql|redis|kafka|etcd|elastic|opensearch", re.I)
        offenders = []
        for line in self.b.lines("04-pvc.txt"):
            tok = line.split()
            if len(tok) >= 7 and "cephfs" in tok[6].lower():
                if db_re.search(tok[0]) or db_re.search(tok[1]):
                    offenders.append("%s/%s (%s, %s)" % (tok[0], tok[1], tok[4], tok[6]))
        if offenders:
            self.add("CRITICAL", "Storage",
                     "Database/Elasticsearch-looking PVCs on CephFS (file storage)",
                     "04-pvc.txt: " + "; ".join(offenders[:8]) +
                     ("... (%d total)" % len(offenders) if len(offenders) > 8 else ""),
                     "Red Hat does not support databases on CephFS; heavy "
                     "metadata I/O can degrade CephFS for ALL applications, "
                     "and corruption cases may not be supportable.",
                     "Verify each workload; migrate genuine databases/ES data "
                     "volumes to block storage (Ceph RBD).",
                     assumption="Classified by PVC/namespace NAME matching "
                                "database keywords - verify the actual "
                                "workload before migrating.")

    def check_olm(self):
        plans = self.b.lines("05-installplan.txt")
        pending = [" ".join((l.split() + ["", ""])[:3])
                   for l in plans if l.split() and l.split()[-1] == "false"]
        if pending:
            self.add("MEDIUM", "Lifecycle",
                     "%d operator InstallPlan(s) pending manual approval" % len(pending),
                     "05-installplan.txt: " + "; ".join(pending[:8]),
                     "Bug fixes / security patches for these operators are "
                     "waiting; the gap grows silently.",
                     "Review and approve in a maintenance window; add a "
                     "recurring review for Manual-approval subscriptions.")
        cats = self.b.read("05-catalogsource.txt") or ""
        if "redhat-marketplace" in cats:
            self.add("LOW", "Lifecycle",
                     "Deprecated Red Hat Marketplace catalog present",
                     "05-catalogsource.txt: redhat-marketplace source exists.",
                     "The Marketplace (IBM-operated) is sunset; operators "
                     "sourced from it will stop receiving updates.",
                     "Migrate any operators using this source to vendor "
                     "catalogs; then remove the source.",
                     assumption="Marketplace sunset status per build-time "
                                "knowledge (%s)." % BUILD_KNOWLEDGE_DATE)
        csvs = self.b.read("05-csv.txt") or ""
        uniq = sorted(set(re.findall(r"^\S+\s+(\S+?\.v?\d[\w.\-]*)\s", csvs, re.M)))
        self.facts["operators"] = uniq
        if re.search(r"cluster-logging\.v?5\.", csvs):
            self.add("HIGH", "Lifecycle",
                     "Elasticsearch-based OpenShift Logging 5.x detected",
                     "05-csv.txt: cluster-logging 5.x (+ elasticsearch-operator).",
                     "The ES-based logging stack is deprecated/EOL; no fixes, "
                     "and log-loss issues may be unsupportable.",
                     "Plan migration to the Loki-based logging stack.",
                     assumption="Logging 5.x EOL status per build-time "
                                "knowledge (%s)." % BUILD_KNOWLEDGE_DATE)
        if "community" in (self.b.read("05-catalogsource.txt") or ""):
            self.add("INFO", "Lifecycle",
                     "Community operator catalog enabled",
                     "05-catalogsource.txt: community-operators present.",
                     "Community operators carry no Red Hat support.",
                     "Inventory which installed operators come from it; "
                     "accept-risk or replace.")

    def check_tenancy(self):
        n_proj = len(self.b.lines("06-projects.txt"))
        self.facts["projects"] = n_proj
        if not n_proj:
            return
        rq_ns = {l.split()[0] for l in self.b.lines("06-resourcequota.txt") if l.split()}
        np_ns = {l.split()[0] for l in self.b.lines("03-networkpolicy.txt") if l.split()}
        lr_ns = {l.split()[0] for l in self.b.lines("06-limitrange.txt") if l.split()}
        self.facts["governance"] = (len(rq_ns), len(lr_ns), len(np_ns), n_proj)
        if n_proj > 20 and len(rq_ns) < n_proj * 0.5:
            self.add("MEDIUM", "Tenancy",
                     "ResourceQuotas cover only %d of %d namespaces" % (len(rq_ns), n_proj),
                     "06-resourcequota.txt vs 06-projects.txt.",
                     "Unquotad tenants can exhaust node memory (incompressible) "
                     "and trigger cascading evictions.",
                     "Define a quota+LimitRange baseline for every tenant "
                     "namespace (templated, e.g. via GitOps).")
        if n_proj > 20 and len(np_ns) < n_proj * 0.5:
            self.add("MEDIUM", "Security",
                     "NetworkPolicies cover only %d of %d namespaces" % (len(np_ns), n_proj),
                     "03-networkpolicy.txt vs 06-projects.txt.",
                     "Flat east-west network: any compromised pod reaches "
                     "every unprotected namespace.",
                     "Roll out default-deny + allow-DNS/ingress baseline "
                     "policies to all tenant namespaces.")
        stale = [l.split()[0] for l in self.b.lines("06-projects.txt")
                 if re.match(r"openshift-(debug|must-gather)|must-gather", l)]
        if stale:
            self.add("LOW", "Hygiene",
                     "%d stale debug/must-gather namespace(s)" % len(stale),
                     "06-projects.txt: " + ", ".join(stale[:6]) + "...",
                     "Leftovers from troubleshooting sessions; may include "
                     "privileged pods and stale RBAC.",
                     "Delete them (and any matching clusterrolebindings).")

    def check_pdb_webhooks(self):
        pdbs = [l for l in self.b.lines("06-pdb.txt")
                if l.split() and l.split()[-1] == "0"]
        if pdbs:
            self.add("HIGH", "Workloads",
                     "%d PodDisruptionBudget(s) allow zero disruptions" % len(pdbs),
                     "06-pdb.txt (ALLOWED=0): " +
                     "; ".join(" ".join(l.split()[:2]) for l in pdbs[:6]),
                     "Node drains hang on these pods - blocking MachineConfig "
                     "rollouts, patching and upgrades.",
                     "Add replicas or relax the PDBs so at least one "
                     "disruption is allowed.")
        wh = self.b.read("07-webhooks.txt") or ""
        n_fail = sum(1 for l in wh.splitlines()[1:] if "Fail" in l)
        if n_fail:
            self.add("MEDIUM", "Stability",
                     "%d webhook configuration(s) contain failurePolicy=Fail" % n_fail,
                     "07-webhooks.txt.",
                     "If a webhook backend is down (e.g. during recovery), API "
                     "object creation can be blocked cluster-wide.",
                     "For each: change to Ignore where not security-critical, "
                     "scope namespaceSelectors away from openshift-*, and make "
                     "backends HA.")

    def check_security(self):
        # restricted SCC drift
        for line in self.b.lines("07-scc.txt"):
            norm = line.replace("<no value>", "<no-value>")
            tok = norm.split()
            if tok and tok[0] == "restricted" and len(tok) >= 4:
                if tok[3] != RESTRICTED_SCC_DEFAULT_SELINUX:
                    self.add("HIGH", "Security",
                             "Default 'restricted' SCC has been modified",
                             "07-scc.txt: restricted SELINUX=%s (default %s)."
                             % (tok[3], RESTRICTED_SCC_DEFAULT_SELINUX),
                             "Modifying shipped SCCs is unsupported, weakens "
                             "every matching workload, and upgrades may "
                             "partially revert it unpredictably.",
                             "Revert to defaults; move workloads needing more "
                             "onto purpose-built custom SCCs.",
                             assumption="Compared against OCP 4.11+ default "
                                        "(seLinuxContext MustRunAs).")
        priv = [l.split()[0] for l in self.b.lines("07-scc.txt")
                if len(l.split()) > 1 and l.split()[1] == "true"
                and l.split()[0] not in
                ("privileged", "hostmount-anyuid", "node-exporter",
                 "hostnetwork", "hostaccess")]
        if priv:
            self.add("MEDIUM", "Security",
                     "%d custom privileged SCC(s)" % len(priv),
                     "07-scc.txt (PRIV=true): " + ", ".join(priv[:10]),
                     "Each privileged SCC is root-equivalent for whatever can "
                     "use it.",
                     "Verify each is bound only to the intended service "
                     "accounts and still needed.",
                     assumption="node-exporter listed as expected-privileged "
                                "(monitoring default); verify no one modified "
                                "it.")
        # cluster-admin bindings
        crb = self.b.read("07-clusterrolebindings.txt") or ""
        admins, mg = [], []
        for line in crb.splitlines()[1:]:
            if re.search(r"ClusterRole/cluster-admin(\s|$)", line):
                name = line.split()[0]
                if name.startswith("system:"):
                    continue
                if name.startswith("must-gather-"):
                    mg.append(name)
                elif name not in DEFAULT_CLUSTER_ADMIN_CRBS:
                    admins.append(name)
        if len(admins) > 5:
            self.add("HIGH", "Security",
                     "%d non-default cluster-admin ClusterRoleBindings" % len(admins),
                     "07-clusterrolebindings.txt: " + ", ".join(admins[:10]) +
                     ("..." if len(admins) > 10 else ""),
                     "Every extra cluster-admin grant (users, operators' "
                     "service accounts, monitoring tools) is a full-cluster "
                     "compromise path.",
                     "Replace SA grants with scoped roles; move humans to "
                     "group-based, just-in-time elevation.",
                     assumption="Bindings named system:* and the shipped "
                                "cluster-admin(s) bindings are treated as "
                                "defaults.")
        if mg:
            self.add("MEDIUM", "Security",
                     "%d stale must-gather cluster-admin binding(s)" % len(mg),
                     "07-clusterrolebindings.txt: " + ", ".join(mg[:6]),
                     "Leftover full-admin grants from old support sessions.",
                     "Delete them.")
        if "kubeadmin" in (self.b.read("07-kubeadmin-exists.txt") or ""):
            self.add("MEDIUM", "Security",
                     "kubeadmin bootstrap user still exists",
                     "07-kubeadmin-exists.txt: secret/kubeadmin present.",
                     "A static, unauditable break-glass password account "
                     "remains active.",
                     "Remove it once IdP-based admin access is confirmed "
                     "working.")
        # etcd encryption
        enc = (self.b.read("07-etcd-encryption.txt") or "").strip()
        self.facts["etcd_encryption"] = enc or "NOT ENABLED"
        if not enc:
            self.add("HIGH", "Security",
                     "etcd encryption at rest is not enabled",
                     "07-etcd-encryption.txt is empty (apiserver "
                     "spec.encryption.type unset).",
                     "Secrets/config in etcd are stored in plaintext on the "
                     "control-plane disks and inside etcd backups.",
                     "Enable aesgcm (or aescbc) etcd encryption.")
        # oauth
        oauth = self.b.read("07-oauth.yaml") or ""
        if "type: HTPasswd" in oauth:
            self.add("MEDIUM", "Security",
                     "HTPasswd identity provider active",
                     "07-oauth.yaml: identityProviders contains type: HTPasswd.",
                     "Local password file: no MFA, no central "
                     "joiner/mover/leaver process.",
                     "Restrict to a documented break-glass account or remove; "
                     "authenticate through the enterprise IdP.")
        if re.search(r"insecure:\s*true", oauth) or "ldap://" in oauth:
            self.add("HIGH", "Security",
                     "LDAP identity provider configured without TLS",
                     "07-oauth.yaml: 'insecure: true' and/or ldap:// URL "
                     "(check also the last-applied annotation - it may be "
                     "historical).",
                     "Bind credentials and user passwords cross the network "
                     "in cleartext.",
                     "Use ldaps:// with CA validation.")

    def check_network(self):
        t = self.b.read("03-network-config.yaml") or ""
        # dedupe: the same CIDRs appear under both spec and status
        cidrs = list(dict.fromkeys(re.findall(r"cidr:\s*(\S+)", t)))
        svc = list(dict.fromkeys(re.findall(r"serviceNetwork:\s*\n\s*-\s*(\S+)", t)))
        self.facts["cluster_cidrs"] = cidrs
        self.facts["service_cidrs"] = svc
        self.facts["cni"] = yaml_grab(t, "networkType")
        bad = []
        for c in set(cidrs + svc):
            try:
                if not ipaddress.ip_network(c).is_private:
                    bad.append(c)
            except ValueError:
                pass
        if bad:
            self.add("MEDIUM", "Network",
                     "Cluster/service network uses public (non-RFC1918) ranges",
                     "03-network-config.yaml: %s." % ", ".join(sorted(bad)),
                     "Traffic to the real owners of those ranges is "
                     "black-holed; future interconnects may collide. "
                     "Immutable after install.",
                     "Document on the risk register; use private ranges for "
                     "any future cluster.")
        # ingress replicas
        ic = self.b.read("03-ingresscontroller.yaml") or ""
        m = re.search(r"^\s*replicas:\s*(\d+)", ic, re.M)
        if m and int(m.group(1)) < 2:
            self.add("HIGH", "Network",
                     "Default ingress controller has <2 replicas",
                     "03-ingresscontroller.yaml: replicas: %s." % m.group(1),
                     "Single point of failure for all routes.",
                     "Scale to >=2 replicas across failure domains.")
        # insecure routes (fixed-width TERMINATION column)
        routes = self.b.read("03-routes.txt")
        if routes:
            lines_ = routes.splitlines()
            if lines_ and "TERMINATION" in lines_[0]:
                insecure = 0
                for line in lines_[1:]:
                    term = col_slice(lines_[0], line, "TERMINATION", ("WILDCARD",))
                    if line.strip() and not term:
                        insecure += 1
                self.facts["routes"] = len(lines_) - 1
                if insecure:
                    self.add("LOW", "Security",
                             "%d route(s) without TLS termination" % insecure,
                             "03-routes.txt: TERMINATION column empty.",
                             "Plain-HTTP application traffic.",
                             "Move to edge/reencrypt termination unless "
                             "deliberately internal-only.")

    def check_monitoring(self):
        mon = self.b.read("08-cluster-monitoring.yaml") or ""
        fwd = "additionalAlertmanagerConfigs" in mon
        self.facts["alert_forwarding"] = fwd
        self.add("HIGH" if not fwd else "MEDIUM", "Observability",
                 "Verify alert notifications reach a human",
                 "08-cluster-monitoring.yaml: additionalAlertmanagerConfigs "
                 + ("present (alerts forwarded to an external/hub "
                    "Alertmanager)." if fwd else "absent."),
                 "Alertmanager receiver config lives in a Secret this bundle "
                 "does not (and should not) collect - silent-alerting is the "
                 "most common root cause of long outages.",
                 "Send a synthetic test alert and confirm the on-call channel "
                 "receives it end-to-end.",
                 assumption="Receiver configuration is in a Secret and "
                            "therefore invisible to this analyzer; this "
                            "finding is a mandatory manual verification, not "
                            "a confirmed defect.")
        alerts = self.b.read("08-active-alerts.json")
        if alerts:
            try:
                data = json.loads(alerts)
                sev = {}
                for a in data:
                    s = a.get("labels", {}).get("severity", "none")
                    sev[s] = sev.get(s, 0) + 1
                crit = sev.get("critical", 0)
                self.facts["active_alerts"] = sev
                if crit:
                    names = sorted({a["labels"].get("alertname", "?")
                                    for a in data
                                    if a.get("labels", {}).get("severity") == "critical"})
                    self.add("CRITICAL", "Observability",
                             "%d critical alert(s) firing at collection time" % crit,
                             "08-active-alerts.json: " + ", ".join(names[:8]),
                             "Active critical alerts are unresolved incidents.",
                             "Triage every firing alert to zero, runbooks "
                             "first.")
            except (ValueError, KeyError):
                pass
        if self.b.exists("08-clusterlogging.txt") and \
           not self.b.exists("08-lokistack.txt"):
            pass  # logging stack finding handled in check_olm via CSV version

    def check_gpu(self):
        rows = self.b.lines("12-gpu-capacity.txt")
        gpus = [(l.split()[0], l.split()[1]) for l in rows
                if len(l.split()) > 1 and l.split()[1] not in ("<none>", "")]
        self.facts["gpu_nodes"] = gpus
        if not gpus:
            # also try labels file from either script version
            lbl = self.b.read("12-gpu-node-labels.txt") or self.b.read("02-gpu-nodes.txt") or ""
            if "true" not in lbl:
                return
        consumers = 0
        for l in self.b.lines("12-gpu-consumers.txt"):
            tok = l.split()
            if len(tok) >= 4 and tok[3][:1].isdigit():
                consumers += 1
        self.facts["gpu_consumers"] = consumers
        if gpus and not (self.b.read("12-clusterpolicy.yaml") or
                         self.b.read("02-clusterpolicy.txt")):
            self.add("HIGH", "GPU",
                     "GPU nodes present but no GPU Operator ClusterPolicy found",
                     "12-gpu-capacity.txt shows GPU capacity; clusterpolicy "
                     "file empty/absent.",
                     "GPUs may be driven by manually installed drivers - "
                     "unmanaged and upgrade-fragile.",
                     "Deploy/repair the NVIDIA GPU Operator.")
        if gpus and consumers == 0:
            self.add("LOW", "GPU",
                     "GPU capacity present but no pod requests GPUs",
                     "12-gpu-consumers.txt: zero pods with nvidia.com/gpu "
                     "limits.",
                     "Expensive accelerators sitting idle (or consumed via "
                     "time-slicing not visible in limits).",
                     "Confirm intended usage/MIG/time-slicing configuration.")

    def check_identity_facts(self):
        oauth = self.b.read("07-oauth.yaml") or ""
        self.facts["idps"] = re.findall(r"^\s*type:\s*(\w+)\s*$", oauth, re.M)
        self.facts["users"] = len(self.b.lines("07-users.txt"))

    def check_infra_facts(self):
        infra = self.b.read("01-infrastructure.yaml") or ""
        self.facts["platform"] = yaml_grab(infra, "type") or "?"
        self.facts["infra_name"] = yaml_grab(infra, "infrastructureName")
        dns = self.b.read("01-dns.yaml") or ""
        self.facts["base_domain"] = yaml_grab(dns, "baseDomain")
        reg = self.b.read("07-imageregistry.yaml") or ""
        self.facts["registry_state"] = yaml_grab(reg, "managementState")
        self.facts["argo_apps"] = len(self.b.lines("09-applications.txt"))

    def check_node_pressure(self):
        flagged = []
        for line in self.b.lines("02-nodes-conditions.txt"):
            tok = line.split()
            if len(tok) < 6:
                continue
            pressures = [name for name, val in zip(
                ("MemoryPressure", "DiskPressure", "PIDPressure",
                 "NetworkUnavailable"), tok[2:6]) if val == "True"]
            if pressures:
                flagged.append("%s (%s)" % (tok[0], ", ".join(pressures)))
        if flagged:
            self.add("HIGH", "Stability",
                     "%d node(s) reporting resource pressure" % len(flagged),
                     "02-nodes-conditions.txt: " + "; ".join(flagged[:6]),
                     "Nodes under Memory/Disk/PID pressure evict pods and stop "
                     "scheduling; NetworkUnavailable means no pod network on "
                     "that node.",
                     "Free resources or add capacity on the affected nodes; "
                     "check kubelet and CNI health.")

    def check_workload_status(self):
        under = []
        for line in self.b.lines("06-workloads-status.txt"):
            tok = line.split()
            if len(tok) < 5:
                continue
            kind, ns, name, desired, ready = tok[:5]
            if not desired.isdigit():
                continue
            got = ready if ready.isdigit() else "0"
            if int(got) < int(desired):
                under.append("%s %s/%s ready=%s/%s"
                             % (kind, ns, name, got, desired))
        for line in self.b.lines("06-daemonsets-status.txt"):
            tok = line.split()
            if len(tok) < 5:
                continue
            ns, name, _, _, unavail = tok[:5]
            if unavail.isdigit() and int(unavail) > 0:
                under.append("DaemonSet %s/%s unavailable=%s"
                             % (ns, name, unavail))
        if under:
            self.add("MEDIUM", "Workloads",
                     "%d workload(s) below desired replicas" % len(under),
                     "06-workloads-status.txt / 06-daemonsets-status.txt: " +
                     "; ".join(under[:8]) + ("..." if len(under) > 8 else ""),
                     "Under-replicated Deployments/StatefulSets and DaemonSets "
                     "with unavailable pods reduce redundancy or indicate crash "
                     "loops.",
                     "Correlate with 06-pods-all.txt and 11-events-warning.txt "
                     "for the root cause.")

    def check_nncp(self):
        bad = []
        for line in self.b.lines("03-nnce.txt"):
            tok = line.split()
            if len(tok) >= 2 and tok[1] in ("Failing", "Aborted"):
                bad.append("%s (%s)" % (tok[0], tok[1]))
        if bad:
            self.add("HIGH", "Network",
                     "%d node network enactment(s) not applied" % len(bad),
                     "03-nnce.txt: " + "; ".join(bad[:8]),
                     "Declared node network config (bonds, VLANs, DNS, "
                     "bridges) failed to apply on these nodes; secondary "
                     "networking may be broken.",
                     "Inspect the failing NNCP (03-nncp.yaml) and the nmstate "
                     "handler on the affected nodes.")

    def check_whereabouts(self):
        text = self.b.read("03-whereabouts-ippools.yaml")
        if not text:
            return
        # allocation with an empty/absent podref = an IP reserved but not in use
        orphans = len(re.findall(r'^\s*podref:\s*("")?\s*$', text, re.M))
        if orphans:
            self.add("MEDIUM", "Network",
                     "%d Whereabouts IP allocation(s) without a pod reference"
                     % orphans,
                     "03-whereabouts-ippools.yaml: allocations missing podref.",
                     "IPs reserved but not tied to a pod are leaked from the "
                     "Whereabouts range and can exhaust it over time.",
                     "Run the whereabouts ip-reconciler and verify no "
                     "duplicate assignments.",
                     assumption="Offline check flags allocations with an empty/"
                                "absent podref only; cross-pod duplicate-IP "
                                "detection needs live pod network-status.")

    def check_etcd_health(self):
        readyz = self.b.read("01-etcd-readyz.txt") or ""
        failing = [l.strip() for l in readyz.splitlines() if l.startswith("[-]")]
        if failing:
            self.add("HIGH", "Stability",
                     "%d API-server readiness gate(s) failing" % len(failing),
                     "01-etcd-readyz.txt: " + "; ".join(failing[:6]),
                     "A failing readyz gate (etcd, informers, controllers) "
                     "means the control plane is not fully healthy.",
                     "Investigate the named component; if etcd is listed, "
                     "check control-plane node health and etcd pod status "
                     "(01-etcd-cr.yaml).")

    def check_ovnkube_coverage(self):
        pods = self.b.lines("03-ovnkube-pods.txt")
        if not pods:
            return
        # -o wide (namespace fixed): NAME READY STATUS RESTARTS AGE IP NODE ...
        ovn_nodes = {tok[6] for tok in (l.split() for l in pods)
                     if len(tok) >= 7 and tok[0].startswith("ovnkube-node-")}
        node_names = {tok[0] for tok in
                      (l.split() for l in self.b.lines("02-nodes-wide.txt"))
                      if tok}
        missing = node_names - ovn_nodes
        if node_names and missing:
            self.add("HIGH", "Network",
                     "%d node(s) without an ovnkube-node pod" % len(missing),
                     "03-ovnkube-pods.txt vs 02-nodes-wide.txt: " +
                     ", ".join(sorted(missing)[:8]),
                     "A node without its ovnkube-node pod has no functioning "
                     "pod network; workloads scheduled there fail to get "
                     "connectivity.",
                     "Check the ovnkube-node DaemonSet and the node's "
                     "kubelet/CNI.")

    def check_acm_policies(self):
        noncompliant = []
        for line in self.b.lines("07-acm-policies.txt"):
            if "NonCompliant" in line:
                tok = line.split()
                noncompliant.append("%s/%s" % (tok[0], tok[1])
                                    if len(tok) >= 2 else line.strip())
        if noncompliant:
            self.add("HIGH", "Security",
                     "%d RHACM policy(ies) NonCompliant" % len(noncompliant),
                     "07-acm-policies.txt: " + "; ".join(noncompliant[:8]),
                     "Governance policies enforced by RHACM are violated; the "
                     "cluster has drifted from its declared security/config "
                     "baseline.",
                     "Review each NonCompliant policy and remediate the drift.")

    def _collection_time(self):
        m = re.search(r"_(\d{8})-(\d{6})$", self.b.path.name)
        if not m:
            return None
        try:
            return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
        except ValueError:
            return None

    def check_cert_expiry(self):
        rows = self.b.lines("07-cert-expiry.txt")
        now = self._collection_time()
        if not rows or now is None:
            return
        soon = []
        for line in rows:
            tok = line.split()
            if len(tok) < 3 or tok[2] in ("<none>", ""):
                continue
            try:
                exp = datetime.strptime(tok[2], "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
            days = (exp - now).days
            if days <= 90:
                soon.append((days, "%s/%s (%dd)" % (tok[0], tok[1], days)))
        if not soon:
            return
        soon.sort()
        buckets = [
            ("CRITICAL", 7, [s for d, s in soon if d <= 7]),
            ("HIGH", 30, [s for d, s in soon if 7 < d <= 30]),
            ("MEDIUM", 90, [s for d, s in soon if 30 < d <= 90]),
        ]
        for sev, within, names in buckets:
            if not names:
                continue
            self.add(sev, "Security",
                     "%d certificate(s) expiring within %d days"
                     % (len(names), within),
                     "07-cert-expiry.txt: " + ", ".join(names[:8]) +
                     ("..." if len(names) > 8 else ""),
                     "Expired platform certificates break API/kubelet/serving "
                     "TLS and can take the cluster offline.",
                     "Confirm automatic cert rotation is healthy; renew any "
                     "manually managed certificates before expiry.",
                     assumption="Days counted from the bundle collection time "
                                "(%s), not today; expiry read from the "
                                "auth.openshift.io/certificate-not-after "
                                "annotation (no key material)."
                                % now.strftime("%Y-%m-%d"))

    ALL_CHECKS = [
        check_meta, check_access, check_version, check_clusterversion,
        check_clusteroperators, check_nodes, check_node_pressure, check_mcp,
        check_pods, check_workload_status, check_etcd_backup, check_etcd_health,
        check_storage, check_olm, check_tenancy, check_pdb_webhooks,
        check_security, check_acm_policies, check_cert_expiry, check_network,
        check_nncp, check_whereabouts, check_ovnkube_coverage, check_monitoring,
        check_gpu, check_identity_facts, check_infra_facts,
    ]

    def run(self):
        for chk in self.ALL_CHECKS:
            try:
                chk(self)
            except Exception as exc:                        # noqa: BLE001
                self.add("INFO", "Analyzer",
                         "Check %s failed on this bundle" % chk.__name__,
                         "internal error: %r" % exc,
                         "A malformed/unexpected file layout; that area was "
                         "not analyzed.",
                         "Review the corresponding files manually.")
        self.findings.sort(key=lambda f: SEV_ORDER.index(f["sev"]))


# --------------------------------------------------------------------------- #
# report rendering
# --------------------------------------------------------------------------- #
def render_overview(a, bundle_name):
    f = a.facts
    L = []
    L.append("# Architecture Overview (auto-generated, offline)")
    L.append("")
    L.append("*Bundle:* `%s` (collector %s) - *generated:* %s by "
             "ocp_analyzer.py %s, knowledge %s (offline)*"
             % (bundle_name, f.get("collector_version", "?"),
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                TOOLKIT_VERSION, BUILD_KNOWLEDGE_DATE))
    L.append("")
    L.append("> This overview is machine-generated from `oc get` output only. "
             "Anything the collector could not see (external load balancers, "
             "DNS, firewalls, backup targets, business context) is absent. "
             "Assumptions are listed at the end of issues.md.")
    L.append("")
    L.append("## Cluster identity")
    L.append("")
    L.append("| Item | Value |")
    L.append("|---|---|")
    L.append("| API | %s |" % f.get("api_url", "?"))
    L.append("| Base domain | %s |" % f.get("base_domain", "?"))
    L.append("| Cluster ID | %s |" % f.get("cluster_id", "?"))
    L.append("| OCP version | %s (channel %s) |"
             % (f.get("ocp_version", "?"), f.get("channel", "?")))
    L.append("| Kubernetes | %s |" % f.get("k8s_version", "?"))
    L.append("| Platform | %s |" % f.get("platform", "?"))
    L.append("| Release image mirror | %s |" % f.get("release_mirror", "-"))
    L.append("| Internal image registry | %s |" % f.get("registry_state", "?"))
    L.append("| etcd encryption | %s |" % f.get("etcd_encryption", "?"))
    hist = f.get("version_history") or []
    if hist:
        L.append("| Version history | %s |" % " → ".join(reversed(hist[:12])))
    L.append("")
    L.append("## Topology")
    L.append("")
    roles = f.get("nodes_by_role", {})
    if roles:
        L.append("- **%d nodes**: %s" % (f.get("node_count", 0),
                 ", ".join("%d× %s" % (n, r) for r, n in sorted(roles.items()))))
    L.append("- Cluster operators: %d (see issues.md for any degraded)"
             % f.get("cluster_operators", 0))
    L.append("- Pods at collection time: %d (non-running: %s)"
             % (f.get("pod_total", 0), f.get("pod_not_running", {}) or "none"))
    gpus = f.get("gpu_nodes") or []
    if gpus:
        L.append("- **GPU nodes**: " +
                 ", ".join("%s (%s GPUs)" % (n, c) for n, c in gpus) +
                 "; pods consuming GPUs: %s" % f.get("gpu_consumers", "?"))
    L.append("")
    L.append("## Network")
    L.append("")
    L.append("- CNI: %s" % f.get("cni", "?"))
    L.append("- Cluster network: %s | Service network: %s"
             % (", ".join(f.get("cluster_cidrs", []) or ["?"]),
                ", ".join(f.get("service_cidrs", []) or ["?"])))
    if "routes" in f:
        L.append("- Routes: %d" % f["routes"])
    L.append("")
    L.append("## Storage")
    L.append("")
    L.append("- PVs: %d, by StorageClass: %s"
             % (f.get("pv_total", 0),
                ", ".join("%s=%d" % kv for kv in
                          sorted((f.get("pv_by_sc") or {}).items(),
                                 key=lambda kv: -kv[1])) or "?"))
    L.append("- Default StorageClass: %s"
             % (", ".join(f.get("default_sc", []) or ["NONE"])))
    L.append("")
    L.append("## Identity & access")
    L.append("")
    L.append("- Identity providers: %s" % (", ".join(f.get("idps", [])) or "?"))
    L.append("- Users: %d" % f.get("users", 0))
    L.append("")
    L.append("## Platform services")
    L.append("")
    ops = f.get("operators") or []
    L.append("- Installed operators (%d unique CSVs): %s"
             % (len(ops), ", ".join(ops[:30]) + ("..." if len(ops) > 30 else "")))
    L.append("- GitOps applications: %d" % f.get("argo_apps", 0))
    L.append("- Backup tooling detected: %s" % f.get("backup_stack", "?"))
    L.append("- Alert forwarding configured: %s"
             % ("yes (additional Alertmanager targets)" if f.get("alert_forwarding")
                else "not visible"))
    if f.get("active_alerts"):
        L.append("- Alerts firing at collection: %s" % f["active_alerts"])
    L.append("")
    L.append("## Tenancy & governance")
    L.append("")
    gov = f.get("governance")
    if gov:
        rq, lr, np_, tot = gov
        L.append("- Projects: %d | with ResourceQuota: %d | with LimitRange: "
                 "%d | with NetworkPolicy: %d" % (tot, rq, lr, np_))
    L.append("")
    return "\n".join(L) + "\n"


def render_issues(a, bundle_name):
    counts = {}
    for f in a.findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    L = []
    L.append("# Issues (auto-generated, offline)")
    L.append("")
    L.append("*Bundle:* `%s` - analyzer %s (knowledge %s) - findings: %s"
             % (bundle_name, TOOLKIT_VERSION, BUILD_KNOWLEDGE_DATE,
                ", ".join("%s: %d" % (s, counts[s]) for s in SEV_ORDER if s in counts)))
    L.append("")
    L.append("> Every finding cites the bundle file it came from. Findings "
             "marked with an **Assumption** are heuristic - verify them "
             "before presenting to the customer. This offline analyzer "
             "CANNOT check: Red Hat lifecycle/CVE status, etcd latency "
             "metrics, Ceph internal health, or anything inside Secrets. "
             "See manual-review-guide.md.")
    L.append("")
    cur = None
    idx = 0
    for f in a.findings:
        if f["sev"] != cur:
            cur = f["sev"]
            L.append("## %s" % cur)
            L.append("")
        idx += 1
        L.append("### %d. %s  `[%s]`" % (idx, f["title"], f["area"]))
        L.append("")
        L.append("- **Evidence:** %s" % f["evidence"])
        L.append("- **Risk:** %s" % f["risk"])
        L.append("- **Recommendation:** %s" % f["rec"])
        if f["assumption"]:
            L.append("- **Assumption:** %s" % f["assumption"])
        L.append("")
    L.append("## Global assumptions & limitations")
    L.append("")
    for s in a.assumptions:
        L.append("- %s" % s)
    L.append("")
    return "\n".join(L) + "\n"


GUIDE = [
    ("00-access.txt", "Access & identity",
     ["Collector identity and API endpoint.",
      "`can-i create clusterrolebindings` MUST be `no` for a clean read-only "
      "audit; `yes` means results were collected with admin rights."]),
    ("01-*.{txt,yaml}", "Version & lifecycle",
     ["Degraded/Progressing cluster operators (01-clusteroperators.*) - read "
      "the condition messages in the YAML, not just the table.",
      "ClusterVersion history: forced upgrades, acceptedRisks, update "
      "frequency (long gaps = patching debt), `force: true` left in spec.",
      "Channel vs installed version; on disconnected clusters check the "
      "mirror (ICSP/IDMS files) and OperatorHub source state.",
      "apiserver.yaml: TLS profile, audit profile, encryption type."]),
    ("02-*.{txt,yaml}", "Nodes & machine config",
     ["Node Ready state, version skew between nodes, container runtime.",
      "Master sizing vs cluster scale; top-nodes utilization (memory% on "
      "masters is an etcd risk).",
      "MCP UPDATED/DEGRADED; custom MachineConfigs overlapping the same "
      "files; KubeletConfig systemReserved vs node RAM (Red Hat sizing "
      "table).",
      "Pending CSRs (broken node joins); zone labels for HA spread."]),
    ("03-*.{txt,yaml}", "Networking",
     ["Cluster/service CIDRs: private ranges? overlap with the DC network?",
      "Ingress controller replicas, placement (one zone?), endpoint "
      "strategy, TLS policy; routes without TLS termination.",
      "NetworkPolicy coverage per namespace (default-deny baseline?).",
      "EgressIP placement; MetalLB/SR-IOV/NAD presence vs expectations."]),
    ("04-*.{txt,yaml}", "Storage",
     ["Released/Failed PVs (storage leaks); default StorageClass sanity.",
      "Databases/Elasticsearch on CephFS or NFS-like classes - unsupported.",
      "ODF: StorageCluster/CephCluster health, MDS/OSD sizing in the "
      "StorageCluster YAML, LocalVolume device paths (must be "
      "/dev/disk/by-id, NOT dm-name-*).",
      "PVC sizes vs alerts; snapshot classes for the backup product."]),
    ("05-*.txt", "Operators (OLM)",
     ["InstallPlans pending approval; Manual-approval subscriptions without "
      "a review process.",
      "Operators from community/marketplace/deprecated catalogs.",
      "Operator versions: EOL stacks (e.g. ES-based logging 5.x), operators "
      "incompatible with the next OCP minor (blocks upgrades)."]),
    ("06-*.txt", "Workloads & tenancy",
     ["Non-running pods by status; restart-count outliers; ImagePullBackOff "
      "(mirror registry gaps!).",
      "Quota/LimitRange coverage; PDBs with ALLOWED=0 (block drains).",
      "Old Completed pods/jobs (pruning); suspicious 'test' workloads in "
      "production namespaces."]),
    ("07-*.{txt,yaml}", "Security & access",
     ["Modified default SCCs (compare restricted/restricted-v2 with a stock "
      "cluster); custom privileged SCCs and who can use them.",
      "cluster-admin bindings: humans, service accounts, stale must-gather-*.",
      "kubeadmin still present; etcd encryption enabled; OAuth IdPs "
      "(HTPasswd in prod? insecure LDAP?); token lifetimes.",
      "Webhooks with failurePolicy=Fail intercepting core resources."]),
    ("08-*.{txt,yaml,json}", "Observability",
     ["Alertmanager receivers are in a Secret - VERIFY notification "
      "end-to-end with a test alert; check additionalAlertmanagerConfigs.",
      "Active alerts snapshot: triage every critical.",
      "Prometheus retention/storage; logging stack version (ES 5.x is EOL), "
      "collector error alerts, forwarder destinations."]),
    ("09-*.txt", "GitOps",
     ["Application count vs namespaces (how much is GitOps-managed?).",
      "OutOfSync/Missing apps; AppProject restrictions; the Argo "
      "controller's RBAC (often cluster-admin)."]),
    ("10-*.txt", "Backup & DR",
     ["WHAT backs up etcd and applications? OADP/Velero/Kasten CRs here, or "
      "backup-named CronJobs - then check their pods actually Complete.",
      "Ask for the last successful restore test; backups nobody restored "
      "are hopes, not backups."]),
    ("11-events-warning.txt", "Events",
     ["Recurring warning reasons (FailedScheduling, OOMKilling, "
      "FailedMount, ImageGCFailed) - each recurring reason is usually a "
      "finding in disguise."]),
    ("12-gpu-*.{txt,yaml}", "GPU / DGX",
     ["GPU capacity vs allocatable (mismatch = driver/device-plugin broken).",
      "ClusterPolicy: driver version, MIG strategy vs the mig.config node "
      "labels; DCGM enabled.",
      "NicClusterPolicy + IPoIB/HostDevice networks + SriovNetworkNodeState "
      "for the InfiniBand fabric on DGX.",
      "GPU-consuming pods vs inventory (idle GPUs are expensive); "
      "PerformanceProfile for CPU isolation/hugepages.",
      "NOTE: GPU health (XID errors, nvidia-smi, DCGM diagnostics) is NOT "
      "in the bundle - check DCGM metrics in the console."]),
]


def render_guide(a, bundle_name):
    L = []
    L.append("# Manual Review Guide - what to look for in each file")
    L.append("")
    L.append("*Bundle:* `%s` (analyzer %s). "
             "The analyzer automates part of this; this guide "
             "covers what a human reviewer should STILL examine, including "
             "everything the offline analyzer cannot judge."
             % (bundle_name, TOOLKIT_VERSION))
    L.append("")
    L.append("Files marked **MISSING** were not collected (older collector "
             "version, or the resource/operator is absent on the cluster - "
             "check the matching `.err` file).")
    L.append("")
    for pattern, title, items in GUIDE:
        # presence: does any file matching the leading token exist?
        prefix = pattern.split("*")[0]
        present = any(p.name.startswith(prefix) and not p.name.endswith(".err")
                      for p in a.b.path.iterdir()) if a.b.path.is_dir() else False
        L.append("## %s  (`%s`)%s" % (title, pattern,
                                      "" if present else "  - **MISSING**"))
        L.append("")
        for it in items:
            L.append("- %s" % it)
        L.append("")
    L.append("## What this bundle can NEVER show (collect separately)")
    L.append("")
    for item in [
        "etcd disk latency / fsync metrics - Prometheus queries or a "
        "must-gather; the #1 control-plane health signal.",
        "Ceph internal health (`ceph status`, full ratios, PG counts, OSD "
        "crashes) - needs the rook-ceph toolbox or ODF must-gather.",
        "Secret contents: Alertmanager receivers, IdP bind credentials, "
        "certificates' expiry dates.",
        "Node-level state: SSH/config drift, disk health, GPU XID errors.",
        "Anything external: load balancers, DNS, firewall rules, storage "
        "arrays, the mirror registry's own health.",
        "Current Red Hat lifecycle/CVE/errata status - must be checked "
        "online against the installed versions listed in the overview.",
    ]:
        L.append("- %s" % item)
    L.append("")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Offline analyzer for OCP review bundles (stdlib only).")
    ap.add_argument("bundle", help="bundle directory (collect-ocp-review.sh output)")
    ap.add_argument("-o", "--outdir",
                    help="output directory (default: <bundle>-analysis)")
    ap.add_argument("--version", action="version",
                    version="ocp_analyzer.py %s (bundle format %d, knowledge %s)"
                            % (TOOLKIT_VERSION, BUNDLE_FORMAT,
                               BUILD_KNOWLEDGE_DATE))
    args = ap.parse_args()

    bdir = Path(args.bundle.rstrip("/") or "/")
    if not bdir.is_dir():
        sys.exit("error: %s is not a directory" % bdir)
    outdir = Path(args.outdir) if args.outdir else \
        bdir.parent / (bdir.name + "-analysis")
    outdir.mkdir(parents=True, exist_ok=True)

    a = Analyzer(Bundle(bdir))
    a.run()

    reports = {
        "architecture-overview.md": render_overview(a, bdir.name),
        "issues.md": render_issues(a, bdir.name),
        "manual-review-guide.md": render_guide(a, bdir.name),
    }
    for name, text in reports.items():
        (outdir / name).write_text(text)

    counts = {}
    for f in a.findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    print("analyzer        : %s (knowledge %s)"
          % (TOOLKIT_VERSION, BUILD_KNOWLEDGE_DATE))
    print("analyzed bundle : %s (collector %s)"
          % (bdir, a.facts.get("collector_version", "?")))
    print("findings        : " + (", ".join(
        "%s=%d" % (s, counts[s]) for s in SEV_ORDER if s in counts) or "none"))
    print("reports written : %s" % outdir)
    for name in reports:
        print("   - %s" % name)


if __name__ == "__main__":
    main()
