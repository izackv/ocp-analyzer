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
# ClusterRoleBindings to cluster-admin that ship with OCP 4.x (in addition to
# every system:* and system:openshift:* binding).
DEFAULT_CLUSTER_ADMIN_CRBS = {
    "cluster-admin", "cluster-admins",
    "cluster-version-operator", "cluster-network-operator",
    "cluster-storage-operator-role", "storage-version-migration-migrator",
    "custom-account-openshift-machine-config-operator",
    "default-account-cluster-network-operator",
}
# `restricted` SCC defaults on OCP 4.11+ (columns of `oc get scc`)
RESTRICTED_SCC_DEFAULT_SELINUX = "MustRunAs"
# SCCs shipped with OCP 4.x (platform + default operators)
STOCK_SCCS = {
    "anyuid", "hostaccess", "hostmount-anyuid", "hostmount-anyuid-v2",
    "hostnetwork", "hostnetwork-v2", "machine-api-termination-handler",
    "node-exporter", "nonroot", "nonroot-v2", "privileged", "restricted",
    "restricted-v2",
}
# custom-SCC name prefix -> keyword expected among installed CSVs
# (05-csv.txt); a match attributes the SCC to that operator.
OPERATOR_SCC_HINTS = [
    ("lvms-", "lvms"), ("rook-ceph", "ocs-operator|odf-operator|rook"),
    ("trident", "trident"), ("noobaa", "noobaa|mcg-operator"),
    ("insights-runtime-extractor", "insights"),
    ("nvidia", "gpu-operator"), ("sriov", "sriov"),
    ("stackrox|rhacs", "rhacs|stackrox"), ("elasticsearch", "elasticsearch"),
]
# capabilities that make an SCC root-equivalent-ish even with PRIV=false
DANGEROUS_CAPS_RE = re.compile(
    r"NET_ADMIN|SYS_ADMIN|SYS_PTRACE|SYS_MODULE|\bALL\b|\"\*\"", re.I)
# control-plane pods that legitimately end in Error/Completed once and stay
ONE_SHOT_POD_RE = re.compile(
    r"^(installer-\d+-|revision-pruner-\d+-|collect-profiles-\d+)")
# cert issuers that OCP rotates automatically (short-lived by design)
AUTOROTATED_ISSUER_RE = re.compile(
    r"kube-apiserver|kube-control-plane-signer|kube-csr-signer|csr-signer|"
    r"aggregator|service-ca|ingress-operator|node-system-admin|"
    r"loadbalancer-serving|localhost-serving|service-network-serving", re.I)
PLATFORM_NS_RE = re.compile(
    r"^(openshift($|-)|kube-|default$|assisted-installer$)")

# per-file collection status (tri-state semantics for .err / empty files)
S_OK = "ok"                        # file present with content
S_EMPTY = "empty"                  # present, "(empty result)" = verified zero
S_MISSING = "missing"              # not collected (older collector?)
S_ERR_ABSENT = "verified-absent"   # .err: resource type not on the cluster
S_ERR_NOTFOUND = "not-configured"  # .err: named object absent = defaults
S_ERR_FAILED = "collection-failed" # .err: request failed = data UNKNOWN

# file -> collecting command (evidence citations); generated from
# collect-ocp-review.sh - regenerate when the collector changes.
FILE_COMMANDS = {
    "01-apiserver.yaml": "oc get apiserver cluster -o yaml",
    "01-clusteroperators.txt": "oc get clusteroperators",
    "01-clusteroperators.yaml": "oc get clusteroperators -o yaml",
    "01-clusterversion.yaml": "oc get clusterversion -o yaml",
    "01-dns.yaml": "oc get dns.config cluster -o yaml",
    "01-etcd-cr.yaml": "oc get etcd cluster -o yaml",
    "01-etcd-readyz.txt": "oc get --request-timeout=20s --raw '/readyz?verbose'",
    "01-featuregate.yaml": "oc get featuregate cluster -o yaml",
    "01-infrastructure.yaml": "oc get infrastructure cluster -o yaml",
    "01-ingress-config.yaml": "oc get ingress.config cluster -o yaml",
    "01-mirrors-icsp.yaml": "oc get imagecontentsourcepolicy -o yaml",
    "01-mirrors-idms.yaml": "oc get imagedigestmirrorset -o yaml",
    "01-mirrors-itms.yaml": "oc get imagetagmirrorset -o yaml",
    "01-operatorhub.yaml": "oc get operatorhub cluster -o yaml",
    "01-proxy.yaml": "oc get proxy cluster -o yaml",
    "01-upgrade.txt": "oc adm upgrade",
    "01-version.txt": "oc version",
    "02-autoscalers.txt": "oc get clusterautoscaler,machineautoscaler -A",
    "02-containerruntimeconfig.yaml": "oc get containerruntimeconfig -o yaml",
    "02-csr.txt": "oc get csr",
    "02-kubeletconfig.yaml": "oc get kubeletconfig -o yaml",
    "02-machineconfigs.txt": "oc get machineconfig",
    "02-machines.txt": "oc get machines -n openshift-machine-api -o wide",
    "02-machinesets.txt": "oc get machineset -n openshift-machine-api",
    "02-mcp.txt": "oc get machineconfigpool",
    "02-nodes-capacity.txt": "oc get nodes -o custom-columns=...",
    "02-nodes-conditions.txt": "oc get nodes -o 'custom-columns=NAME:.metadata.name,READY:.status.conditions[?(@.type=='Ready')].status,MEM-PRESSURE:.status.conditions[?(@.type=='MemoryPressure')].status,DISK-PRESSURE:.status.conditions[?(@.type=='DiskPressure')].status,PID-PRESSURE:.status.conditions[?(@.type=='PIDPressure')].status,NET-UNAVAIL:.status.conditions[?(@.type=='NetworkUnavailable')].status,TAINTS:.spec.taints[*].key'",
    "02-nodes-roles-zones.txt": "oc get nodes -L <labels>",
    "02-nodes-wide.txt": "oc get nodes -o wide",
    "02-top-nodes.txt": "oc adm top nodes",
    "02-tuned.txt": "oc get tuned -n openshift-cluster-node-tuning-operator",
    "03-anp-banp.txt": "oc get adminnetworkpolicy,baselineadminnetworkpolicy",
    "03-egressfirewall.txt": "oc get egressfirewall -A",
    "03-egressips.txt": "oc get egressip",
    "03-ingress-svc.txt": "oc get svc -n openshift-ingress",
    "03-ingresscontroller.yaml": "oc get ingresscontroller -n openshift-ingress-operator -o yaml",
    "03-metallb.txt": "oc get ipaddresspools,l2advertisements,bgpadvertisements -A",
    "03-net-attach-def.txt": "oc get network-attachment-definitions -A",
    "03-network-config.yaml": "oc get network.config cluster -o yaml",
    "03-network-operator.yaml": "oc get network.operator cluster -o yaml",
    "03-networkpolicy.txt": "oc get networkpolicy -A",
    "03-nnce.txt": "oc get nnce",
    "03-nncp.yaml": "oc get nncp -o yaml",
    "03-ovnkube-pods.txt": "oc get pods -n openshift-ovn-kubernetes -o wide",
    "03-routes.txt": "oc get routes -A",
    "03-services-all.txt": "oc get svc -A",
    "03-sriov.txt": "oc get sriovnetworknodepolicy,sriovnetwork -A",
    "03-whereabouts-ippools.yaml": "oc get ippools -A -o yaml",
    "03-whereabouts-overlap.txt": "oc get overlappingrangeipreservations -A",
    "04-cephblockpool.txt": "oc get cephblockpool -n openshift-storage",
    "04-cephcluster.txt": "oc get cephcluster -n openshift-storage",
    "04-cephfilesystem.txt": "oc get cephfilesystem -n openshift-storage",
    "04-csidrivers.txt": "oc get csidrivers",
    "04-imagepruner.yaml": "oc get imagepruner cluster -o yaml",
    "04-localvolume.yaml": "oc get localvolume -n openshift-local-storage -o yaml",
    "04-noobaa.txt": "oc get noobaa -n openshift-storage",
    "04-obc.txt": "oc get objectbucketclaim -A",
    "04-pv.txt": "oc get pv",
    "04-pvc.txt": "oc get pvc -A",
    "04-storageclasses.txt": "oc get sc -o custom-columns=...",
    "04-storagecluster.txt": "oc get storagecluster -n openshift-storage",
    "04-storagecluster.yaml": "oc get storagecluster -n openshift-storage -o yaml",
    "04-trident.txt": "oc get tridentbackendconfig -A",
    "04-volumesnapshotclass.txt": "oc get volumesnapshotclass",
    "04-volumesnapshots.txt": "oc get volumesnapshot -A",
    "05-catalogsource.txt": "oc get catalogsource -A",
    "05-crd-count.txt": "oc get crd -o custom-columns=...",
    "05-csv.txt": "oc get csv -A",
    "05-installplan.txt": "oc get installplan -A",
    "05-operatorgroup.txt": "oc get operatorgroup -A",
    "05-subscriptions.txt": "oc get subscriptions.operators.coreos.com -A -o custom-columns=...",
    "06-clusterresourcequota.txt": "oc get clusterresourcequota",
    "06-daemonsets-status.txt": "oc get daemonset -A -o custom-columns=...",
    "06-hpa.txt": "oc get hpa -A",
    "06-jobs.txt": "oc get jobs -A",
    "06-limitrange.txt": "oc get limitrange -A",
    "06-pdb.txt": "oc get pdb -A -o custom-columns=...",
    "06-pods-all.txt": "oc get pods -A -o wide",
    "06-priorityclasses.txt": "oc get priorityclasses",
    "06-projects.txt": "oc get projects",
    "06-resourcequota.txt": "oc get resourcequota -A",
    "06-top-pods.txt": "oc adm top pods -A --sum",
    "06-workloads-status.txt": "oc get deploy,statefulset -A -o custom-columns=...",
    "06-workloads.txt": "oc get deploy,statefulset,daemonset -A",
    "07-acm-policies.txt": "oc get policies.policy.open-cluster-management.io -A",
    "07-acs-central.txt": "oc get central -A",
    "07-acs-secured.txt": "oc get securedcluster -A",
    "07-cert-expiry.txt": "oc get secret -A -o custom-columns=...",
    "07-certificates.txt": "oc get certificates.cert-manager.io -A",
    "07-clusterrolebindings.txt": "oc get clusterrolebinding -o wide",
    "07-compliance.txt": "oc get compliancesuite,compliancescan -A",
    "07-etcd-encryption.txt": "oc get apiserver cluster -o jsonpath=...",
    "07-groups.txt": "oc get groups",
    "07-identities.txt": "oc get identity",
    "07-imageregistry.yaml": "oc get configs.imageregistry.operator.openshift.io cluster -o yaml",
    "07-kubeadmin-exists.txt": "oc get secret kubeadmin -n kube-system -o name",
    "07-oauth.yaml": "oc get oauth cluster -o yaml",
    "07-oauthclients.txt": "oc get oauthclients -o custom-columns=...",
    "07-registry-route.txt": "oc get route -n openshift-image-registry",
    "07-rolebindings.txt": "oc get rolebindings -A -o wide",
    "07-scc.txt": "oc get scc",
    "07-scc.yaml": "oc get scc -o yaml",
    "07-users.txt": "oc get user",
    "07-webhooks.txt": "oc get mutatingwebhookconfiguration,validatingwebhookconfiguration -o custom-columns=...",
    "08-active-alerts.json": "oc get --request-timeout=20s --raw '/api/v1/namespaces/openshift-monitoring/services/alertmanager-main:9094/proxy/api/v2/alerts?active=true'",
    "08-alertmanagerconfig.txt": "oc get alertmanagerconfig -A",
    "08-cluster-monitoring.yaml": "oc get configmap cluster-monitoring-config -n openshift-monitoring -o yaml",
    "08-clusterlogging.txt": "oc get clusterlogging,clusterlogforwarder -n openshift-logging",
    "08-clusterlogging.yaml": "oc get clusterlogging,clusterlogforwarder -n openshift-logging -o yaml",
    "08-lokistack.txt": "oc get lokistack -A",
    "08-prom-am.txt": "oc get prometheus,alertmanager -n openshift-monitoring",
    "08-prometheusrules.txt": "oc get prometheusrule -A",
    "08-uwm.yaml": "oc get configmap user-workload-monitoring-config -n openshift-user-workload-monitoring -o yaml",
    "09-applications.txt": "oc get applications.argoproj.io -A",
    "09-applicationsets.txt": "oc get applicationsets.argoproj.io -A",
    "09-appprojects.txt": "oc get appprojects.argoproj.io -A",
    "09-argocd.txt": "oc get argocd -A",
    "09-tektonconfig.txt": "oc get tektonconfig",
    "10-backup-locations.txt": "oc get backupstoragelocation,volumesnapshotlocation -A",
    "10-cronjobs.txt": "oc get cronjob -A",
    "10-etcd-backup-fg.txt": "oc get featuregate cluster -o jsonpath=...",
    "10-kasten-policies.txt": "oc get policies.config.kio.kasten.io -A",
    "10-oadp-dpa.txt": "oc get dataprotectionapplication -A",
    "10-velero-crs.txt": "oc get backup,restore,schedule -A",
    "11-events-warning.txt": "oc get events -A --field-selector type=Warning --sort-by=.lastTimestamp",
    "12-clusterpolicy.yaml": "oc get clusterpolicy -A -o yaml",
    "12-gpu-capacity.txt": "oc get nodes -o custom-columns=...",
    "12-gpu-consumers.txt": "oc get pods -A -o custom-columns=...",
    "12-gpu-node-labels.txt": "oc get nodes -L <labels>",
    "12-gpu-operator-pods.txt": "oc get pods -n nvidia-gpu-operator -o wide",
    "12-nfd.txt": "oc get nodefeaturediscovery -A",
    "12-nicclusterpolicy.yaml": "oc get nicclusterpolicy -A -o yaml",
    "12-nv-network-pods.txt": "oc get pods -n nvidia-network-operator -o wide",
    "12-nvidia-networks.txt": "oc get macvlannetwork,hostdevicenetwork,ipoibnetwork -A",
    "12-performanceprofile.yaml": "oc get performanceprofile -o yaml",
    "12-sriov-node-state.txt": "oc get sriovnetworknodestate -n openshift-sriov-network-operator",
}



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
        out = [l for l in t.splitlines() if l.strip()]
        return out[1:] if (skip_header and out) else out

    def exists(self, name):
        return self.read(name) is not None

    def err_text(self, name):
        """Content of the sibling .err file, or None."""
        for candidate in [name] + self.ALIASES.get(name, []):
            f = self.path / (candidate + ".err")
            if f.is_file():
                return f.read_text(errors="replace")
        return None

    def status(self, name):
        """Classify a bundle file: S_OK/S_EMPTY/S_MISSING/S_ERR_*."""
        t = self.read(name)
        if t is not None:
            if t.startswith("(empty result)") or not t.strip():
                return S_EMPTY
            return S_OK
        err = self.err_text(name)
        if err is None:
            return S_MISSING
        if re.search(r"doesn't have a resource type|no matches for kind|"
                     r"could not find the requested resource", err):
            return S_ERR_ABSENT
        if "NotFound" in err or "not found" in err:
            return S_ERR_NOTFOUND
        return S_ERR_FAILED


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


def yaml_block(text, key):
    """Lines of the first block under `key:` (everything indented deeper).

    Indentation-based, so it distinguishes e.g. the real `spec:` block from
    the same keys inside a last-applied-configuration annotation.
    """
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)%s:\s*$" % re.escape(key), line)
        if m is None:
            continue
        ind = len(m.group(1))
        out = []
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                out.append(nxt)
                continue
            nxt_ind = len(nxt) - len(nxt.lstrip())
            # block members are indented deeper, EXCEPT list items, which
            # YAML allows at the same indent as their key ("history:\n- x")
            if nxt_ind < ind or (nxt_ind == ind
                                 and not nxt.lstrip().startswith("- ")):
                break
            out.append(nxt)
        return "\n".join(out)
    return ""


def parse_conditions(text, all_blocks=False):
    """Condition dicts from `conditions:` block(s) of a YAML text.

    Returns [{'type':..,'status':..,'reason':..,'message':..,
    'lastTransitionTime':..}, ...]; multi-line messages are joined.
    With all_blocks=True every conditions: block in the text is parsed
    (needed when nested blocks precede the interesting one, e.g.
    ClusterVersion conditionalUpdates) - filter the result by type.
    """
    if all_blocks:
        out, rest = [], text or ""
        while True:
            m = re.search(r"^\s*conditions:\s*$", rest, re.M)
            if not m:
                return out
            out.extend(parse_conditions(rest[m.start():]))
            rest = rest[m.end():]
    conds, cur = [], None
    for line in yaml_block(text, "conditions").splitlines():
        s = line.strip()
        if s.startswith("- "):
            if cur:
                conds.append(cur)
            cur = {}
            s = s[2:]
        if cur is None:
            continue
        m = re.match(r"(lastTransitionTime|message|reason|status|type):"
                     r"\s*(.*)$", s)
        if m:
            cur[m.group(1)] = m.group(2).strip("'\"")
        elif "message" in cur and s:
            cur["message"] += " " + s          # folded continuation line
    if cur:
        conds.append(cur)
    return conds


def parse_named_conditions(text):
    """{metadata.name: [condition dicts]} for every item of a List YAML."""
    out = {}
    for chunk in re.split(r"^- apiVersion:", text or "", flags=re.M)[1:]:
        name = yaml_grab(yaml_block(chunk, "metadata") or chunk, "name")
        if name:
            out[name] = parse_conditions(chunk)
    return out


def parse_iso_time(s):
    try:
        return datetime.strptime((s or "").strip('"'), "%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# cluster profile - context every check calibrates against
# --------------------------------------------------------------------------- #
class Profile(object):
    """Deterministic cluster archetype derived from the bundle.

    Drives severity calibration: findings inherent to the topology are
    suppressed or reweighted, coverage ratios run over tenant namespaces
    only, and absence-of-backup escalates on SNO.
    """

    def __init__(self, bundle):
        infra = bundle.read("01-infrastructure.yaml") or ""
        self.cp_topology = yaml_grab(infra, "controlPlaneTopology") or "?"
        self.infra_topology = yaml_grab(infra, "infrastructureTopology") or "?"
        self.sno = self.cp_topology == "SingleReplica"
        cv = bundle.read("01-clusterversion.yaml") or ""
        # disconnected ONLY when the cluster provably cannot reach the
        # update graph; mirror entries alone also occur on connected
        # appliance-style installs
        mirrors = ((bundle.read("01-mirrors-idms.yaml") or "")
                   + (bundle.read("01-mirrors-icsp.yaml") or ""))
        self.mirrored = "mirrors:" in mirrors
        self.disconnected = bool(re.search(r"reason:\s*RemoteFailed", cv))
        names = [l.split()[0] for l in bundle.lines("06-projects.txt")
                 if l.split()]
        self.tenant_namespaces = [n for n in names
                                  if not PLATFORM_NS_RE.match(n)]
        self.namespace_count = len(names)
        # install date = completionTime of the OLDEST history entry
        times = [parse_iso_time(t) for t in re.findall(
            r"completionTime:\s*(\S+)", yaml_block(cv, "history"))]
        times = [t for t in times if t]
        self.install_date = min(times) if times else None
        self.last_update = max(times) if times else None

    def describe(self):
        parts = ["control plane: %s" % self.cp_topology]
        if self.sno:
            parts.append("single-node (SNO) - severity calibrated: "
                         "single-replica findings inherent to SNO are "
                         "suppressed or downgraded")
        parts.append("connectivity: %s" %
                     ("disconnected (cannot reach update graph)"
                      if self.disconnected else
                      "connected, image mirrors configured" if self.mirrored
                      else "connected (no mirror/proxy signals)"))
        parts.append("tenant namespaces: %d of %d"
                     % (len(self.tenant_namespaces), self.namespace_count))
        return "; ".join(parts)


# --------------------------------------------------------------------------- #
# analyzer
# --------------------------------------------------------------------------- #
class Analyzer(object):
    def __init__(self, bundle):
        self.b = bundle
        self.profile = Profile(bundle)
        self.findings = []        # list of dicts
        self.suppressed = []      # (title, reason) dropped by calibration
        self.facts = {}           # for the overview
        self.outage_nodes = set() # NotReady nodes -> downstream cascade tags
        self.greens = []          # (area, statement) verified-healthy ledger
        self.questions = []       # customer questions harvested from findings
        self._check = "?"         # current check name (stamped into rule ids)
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

    # ---- finding helpers ---------------------------------------------------
    def add(self, sev, area, title, evidence, risk, rec, assumption=None,
            cascade=False, question=None):
        # stable rule id: check name + title with counts normalized - the
        # cross-run diff (--prev) matches findings on this
        rid = "%s/%s" % (self._check.replace("check_", ""),
                         re.sub(r"[^a-z0-9]+", "-",
                                re.sub(r"\d+", "N", title.lower())).strip("-"))
        self.findings.append({
            "id": rid, "sev": sev, "area": area, "title": title,
            "evidence": evidence, "risk": risk, "rec": rec,
            "assumption": assumption,
            "cascade": cascade and bool(self.outage_nodes),
        })
        if question:
            self.questions.append(question)

    def suppress(self, title, reason):
        """Record a finding dropped by profile calibration (auditable)."""
        self.suppressed.append((title, reason))

    def green(self, area, statement):
        """Record a verified-healthy assertion (positive evidence ledger)."""
        self.greens.append((area, statement))

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
        # the yes/no anywhere inside the create-clusterrolebindings section
        # (real output holds Warning + blank lines before the answer)
        m = re.search(r"##[^\n]*create clusterrolebindings[^\n]*\n(.*?)(?=\n## |\Z)",
                      t, re.S)
        if m and re.search(r"^yes\s*$", m.group(1), re.M):
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
        # history versions for the overview - ONLY the status.history block
        # (a bare version: regex would also harvest availableUpdates/desired)
        hist_block = yaml_block(t, "history")
        hist = re.findall(r"^\s+version:\s*(\d+\.\d+\.\S+)\s*$", hist_block, re.M)
        if hist:
            self.facts["version_history"] = list(dict.fromkeys(hist))
        if self.profile.install_date:
            self.facts["install_date"] = \
                self.profile.install_date.strftime("%Y-%m-%d")
        # release image mirror
        img = yaml_grab(t, "image")
        if img and "/" in img:
            self.facts["release_mirror"] = img.split("/")[0]

    def check_clusteroperators(self):
        rows = self.b.lines("01-clusteroperators.txt")
        # per-CO condition reason/message from the YAML - the root-cause
        # lead usually sits in the Degraded/Available message text
        conds = parse_named_conditions(
            self.b.read("01-clusteroperators.yaml") or "")
        bad = []
        for line in rows:
            tok = line.split()
            if len(tok) >= 5 and (tok[2] != "True" or tok[3] != "False" or tok[4] != "False"):
                why = ""
                for c in conds.get(tok[0], []):
                    if (c.get("type") == "Degraded" and c.get("status") == "True") \
                            or (c.get("type") == "Available"
                                and c.get("status") == "False"):
                        why = " - %s: %s" % (c.get("reason", "?"),
                                             (c.get("message") or "")[:160])
                        break
                bad.append("%s (A=%s P=%s D=%s)%s"
                           % (tok[0], tok[2], tok[3], tok[4], why))
        self.facts["cluster_operators"] = len(rows)
        self.facts["bad_cos"] = {b.split()[0] for b in bad}
        if rows and not bad:
            self.green("Stability", "All %d cluster operators Available, not Progressing, not Degraded (01-clusteroperators.txt)." % len(rows))
        if bad:
            core = ("authentication", "etcd", "kube-apiserver",
                    "kube-controller-manager", "kube-scheduler", "network",
                    "dns", "openshift-apiserver", "machine-config")
            # a lone degraded NON-core operator (e.g. image-registry over a
            # failed pruner job) is HIGH; core operators stay CRITICAL
            sev = "HIGH" if (len(bad) == 1 and not self.outage_nodes
                             and not bad[0].startswith(core)) else "CRITICAL"
            self.add(sev, "Stability",
                     "%d cluster operator(s) unavailable/degraded/progressing" % len(bad),
                     "01-clusteroperators.txt + 01-clusteroperators.yaml: "
                     + "; ".join(bad[:8]) + ("..." if len(bad) > 8 else ""),
                     "Degraded core operators mean platform functions are "
                     "impaired right now.",
                     "Follow the condition message(s) above to the failing "
                     "component and remediate before anything else.",
                     cascade=True)

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
        if rows and not notready:
            self.green("Stability", "All %d nodes Ready (02-nodes-wide.txt)." % len(rows))
        if notready:
            self.outage_nodes = {n.split()[0] for n in notready}
            # READY=Unknown means the kubelet stopped REPORTING (node
            # unreachable), not a failed health check - different diagnosis
            unknown = [l.split()[0] for l in
                       self.b.lines("02-nodes-conditions.txt")
                       if len(l.split()) > 1 and l.split()[1] == "Unknown"]
            unmanaged = any(l.split()[-1] == "unmanaged"
                            for l in self.b.lines("02-machines.txt")
                            if l.split())
            self.add("CRITICAL", "Stability",
                     "%d node(s) not Ready - treat dependent findings as one "
                     "incident" % len(notready),
                     "02-nodes-wide.txt: " + ", ".join(notready[:6])
                     + (". 02-nodes-conditions.txt: Ready=Unknown on %s - "
                        "the kubelet stopped reporting (node unreachable), "
                        "not a failed health probe."
                        % ", ".join(unknown[:6]) if unknown else "")
                     + (" 02-machines.txt: Machines are 'unmanaged' "
                        "(bare-metal) - the Machine API cannot auto-remediate;"
                        " recovery is manual." if unmanaged else ""),
                     "Reduced capacity/redundancy; degraded operators, "
                     "under-replicated workloads, stuck rollouts and pending "
                     "pods below are most likely CASCADE EFFECTS of this "
                     "outage, not independent problems.",
                     "Recover the nodes first (power/network/kubelet), then "
                     "re-collect and re-assess whatever findings remain.")
        # master sizing - masters identified by their ROLES column, with a
        # hostname fallback for older bundles; thresholds depend on topology
        masters = {n for r, nodes in roles.items() for n in nodes
                   if "master" in r or "control-plane" in r}
        min_cpu, min_mem = (8, 15) if self.profile.sno else (16, 63)
        caps = self.b.lines("02-nodes-capacity.txt")
        masters_small = []
        for line in caps:
            tok = line.split()
            if len(tok) < 3:
                continue
            is_master = (tok[0] in masters if masters
                         else ("mst" in tok[0] or "master" in tok[0]))
            if not is_master:
                continue
            try:
                cpu = int(tok[1])
                mem_gib = int(re.sub(r"\D", "", tok[2])) / (1024 * 1024)
            except ValueError:
                continue
            if cpu < min_cpu or mem_gib < min_mem:
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
                     assumption="Threshold used: <%d vCPU or <%d GiB for a "
                                "%s cluster; masters matched by node role."
                                % (min_cpu, min_mem + 1,
                                   "single-node" if self.profile.sno
                                   else "multi-tenant production"))
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
            # name the top memory consumers so the finding is actionable
            top_pods = []
            for line in self.b.lines("06-top-pods.txt"):
                tok = line.split()
                if len(tok) >= 4 and tok[3].endswith("Mi"):
                    try:
                        top_pods.append((int(tok[3][:-2]),
                                         "%s/%s" % (tok[0], tok[1])))
                    except ValueError:
                        pass
            top_pods.sort(reverse=True)
            attribution = ("; top memory consumers (06-top-pods.txt): "
                           + ", ".join("%s %dMi" % (n, m)
                                       for m, n in top_pods[:5])
                           if top_pods else "")
            self.add("MEDIUM", "Capacity",
                     "%d node(s) above utilization thresholds at collection time" % len(hot),
                     "02-top-nodes.txt: " + "; ".join(hot[:8]) + attribution,
                     "Nodes near memory limits risk OOM/eviction storms; on "
                     "masters this endangers etcd.",
                     "Check trends in Prometheus; rebalance workloads or "
                     "reclaim platform overhead (top consumers above), raise "
                     "systemReserved, or add capacity.",
                     assumption="Thresholds: memory >=70%, CPU >=80% at the "
                                "single point of collection. Top consumers "
                                "are cluster-wide (pod-to-node mapping is "
                                "not in the top-pods output).")

    def check_mcp(self):
        mcp_rows = self.b.lines("02-mcp.txt")
        bad_mcp = False
        for line in mcp_rows:
            tok = line.split()
            if len(tok) >= 5 and (tok[2] != "True" or tok[3] != "False" or tok[4] != "False"):
                bad_mcp = True
                self.add("HIGH", "Stability",
                         "MachineConfigPool '%s' not converged" % tok[0],
                         "02-mcp.txt: UPDATED=%s UPDATING=%s DEGRADED=%s."
                         % (tok[2], tok[3], tok[4]),
                         "Nodes are mid-rollout or stuck; upgrades and config "
                         "changes will not complete.",
                         "`oc describe mcp %s` and check nodes' "
                         "machineconfiguration annotations." % tok[0],
                         cascade=True)
        if mcp_rows and not bad_mcp:
            self.green("Stability", "All MachineConfigPools converged (02-mcp.txt).")

    def check_pods(self):
        rows = self.b.lines("06-pods-all.txt")
        if not rows:
            return
        status_count, restarts, pull_fail = {}, [], []
        one_shot = 0
        for line in rows:
            tok = line.split()
            if len(tok) < 5:
                continue
            ns, name, status = tok[0], tok[1], tok[3]
            if status not in ("Running", "Completed"):
                if status == "Error" and ONE_SHOT_POD_RE.match(name):
                    # superseded static-pod installers/pruners: benign leftovers
                    one_shot += 1
                else:
                    status_count[status] = status_count.get(status, 0) + 1
            if "ImagePull" in status or "ErrImage" in status:
                pull_fail.append(("%s/%s" % (ns, name),
                                  parse_age_days(tok[5]) if len(tok) > 5
                                  else 0.0))
            if tok[4].isdigit() and int(tok[4]) > 0:
                # RESTARTS may be "5 (3d14h ago)" - recency in tok[5..6];
                # AGE is the column after the optional recency
                count = int(tok[4])
                recent = tok[5].lstrip("(") if (len(tok) > 5 and
                                                tok[5].startswith("(")) else ""
                age_col = tok[7] if recent and len(tok) > 7 else \
                    (tok[5] if len(tok) > 5 else "")
                age_days = parse_age_days(age_col)
                rate = count / age_days if age_days >= 1 else count
                if count >= 100 or (rate >= 10 and count >= 20):
                    restarts.append((count, "%s/%s" % (ns, name), status,
                                     recent, rate))
        self.facts["pod_total"] = len(rows)
        self.facts["pod_not_running"] = dict(status_count)
        if one_shot:
            self.facts["pod_not_running"]["Error (benign one-shot "
                                          "installer/pruner)"] = one_shot
        if restarts:
            restarts.sort(reverse=True)
            top = ["%s restarts=%d (%s%s, ~%.1f/day)"
                   % (n, c, s, ", last %s ago" % r if r else "", rt)
                   for c, n, s, r, rt in restarts[:6]]
            self.add("HIGH", "Workloads",
                     "%d pod(s) with excessive restarts" % len(restarts),
                     "06-pods-all.txt: " + "; ".join(top),
                     "Crash-looping workloads burn resources, hide real "
                     "incidents and indicate unhealthy applications.",
                     "Triage with the app owners; fix or remove the top "
                     "offenders.",
                     cascade=True,
                     assumption="Flagged at >=100 total restarts OR a rate "
                                ">=10/day with >=20 restarts (restart count "
                                "normalized by pod age - a steady trickle "
                                "over years is different from an active "
                                "crash loop).")
        if pull_fail:
            # age stratification separates chronic debt from an ACTIVE
            # regression (e.g. images freshly removed from the mirror)
            chronic = [n for n, d in pull_fail if d >= 30]
            fresh = [n for n, d in pull_fail if d < 7]
            strata = []
            if chronic:
                strata.append("%d chronic (>=30d old)" % len(chronic))
            if fresh:
                strata.append("%d RECENT (<7d - active regression?)"
                              % len(fresh))
            self.add("HIGH", "Workloads",
                     "%d pod(s) failing image pulls%s"
                     % (len(pull_fail),
                        " - " + ", ".join(strata) if strata else ""),
                     "06-pods-all.txt: " +
                     ", ".join(n for n, _ in pull_fail[:8]) +
                     ("..." if len(pull_fail) > 8 else ""),
                     "Services run below intended replicas AND the images are "
                     "not pullable - a redeploy or node failure would not "
                     "recover these workloads."
                     + (" On this disconnected cluster that points at "
                        "MIRROR-REGISTRY DRIFT: the running copies are "
                        "unrecoverable after any restart, which is also a "
                        "DR gap; recent failures suggest the drift is still "
                        "happening." if self.profile.disconnected else ""),
                     "Audit the source registry/mirror for the missing tags; "
                     "fix or remove dead references"
                     + ("; reconcile the mirroring pipeline."
                        if self.profile.disconnected else "."),
                     assumption="Failure age approximated by pod AGE (the "
                                "pod has been failing to pull since it was "
                                "created).")
        crash = status_count.get("CrashLoopBackOff", 0)
        errors = status_count.get("Error", 0)
        if crash or errors:
            self.add("MEDIUM", "Workloads",
                     "Pods in CrashLoopBackOff/Error state",
                     "06-pods-all.txt: CrashLoopBackOff=%d, Error=%d." % (crash, errors),
                     "Failing workloads; Error pods from CronJobs often mean "
                     "silently broken scheduled tasks.",
                     "Review each; see also the backup check below.",
                     assumption="One-shot control-plane pods (installer-*, "
                                "revision-pruner-*, collect-profiles-*) are "
                                "excluded as benign leftovers%s."
                                % (" (%d such pod(s) in this bundle)" % one_shot
                                   if one_shot else ""))
        if one_shot > 10:
            self.add("LOW", "Hygiene",
                     "%d superseded installer/pruner pods linger" % one_shot,
                     "06-pods-all.txt: Error-state one-shot control-plane pods.",
                     "Cosmetic, but clutters pod listings and monitoring.",
                     "Prune with `oc adm prune` or ignore; no action urgent.")
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
            bad, ok_age, worst_err = [], None, 0.0
            for line in pods:
                tok = line.split()
                if len(tok) >= 5 and tok[0] in backup_ns:
                    age = tok[7] if len(tok) > 7 and tok[5].startswith("(") \
                        else (tok[5] if len(tok) > 5 else "")
                    d = parse_age_days(age)
                    if tok[3] == "Error":
                        bad.append("%s/%s" % (tok[0], tok[1]))
                        worst_err = max(worst_err, d)
                    elif tok[3] == "Completed":
                        ok_age = d if ok_age is None else min(ok_age, d)
            if bad:
                # Job history limits cap retained pods: the observable span
                # is a LOWER BOUND on how long this has been failing
                window = worst_err if (ok_age is None or worst_err < ok_age) \
                    else ok_age
                self.facts["unnoticed_failure_days"] = window
                self.add("CRITICAL", "Backup/DR",
                         "Backup job pods are failing (namespace(s): %s)"
                         % ", ".join(sorted(backup_ns)),
                         "10-cronjobs.txt + 06-pods-all.txt: Error pods: "
                         + ", ".join(bad[:6]) +
                         ("; most recent Completed backup pod is ~%.0f days old"
                          % ok_age if ok_age is not None else
                          "; NO Completed backup pod visible")
                         + ("; failing for AT LEAST ~%.0f days (only the "
                            "job-history-limit's worth of pods is retained, "
                            "so the real window may be longer)" % window
                            if window >= 1 else ""),
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
            # tri-state: .err "no resource type" PROVES the product is not
            # installed; a missing file only means "not collected"
            absent = [n for n in ("10-oadp-dpa.txt", "10-velero-crs.txt",
                                  "10-kasten-policies.txt")
                      if self.b.status(n) == S_ERR_ABSENT]
            fg = self.b.read("10-etcd-backup-fg.txt") or \
                self.b.read("01-featuregate.yaml") or ""
            no_fg = "AutomatedEtcdBackup" not in fg
            # CRITICAL only when stateful data actually exists to lose
            sev = "CRITICAL" if self.b.lines("04-pv.txt") else "HIGH"
            self.add(sev, "Backup/DR",
                     "No backup tooling detected on the cluster",
                     "10-*: no OADP DataProtectionApplication, no Velero CRs, "
                     "no Kasten policies, no backup-named CronJobs."
                     + (" CRDs verified ABSENT (not installed): %s."
                        % ", ".join(absent) if absent else "")
                     + (" AutomatedEtcdBackup feature gate not enabled."
                        if no_fg else ""),
                     "No apparent path to restore applications or etcd after "
                     "data loss."
                     + (" On a single-node cluster the lone etcd member IS "
                        "the cluster: losing its disk without a backup is "
                        "total, unrecoverable cluster loss."
                        if self.profile.sno else ""),
                     "Confirm with the customer how (or whether) this cluster "
                     "is backed up; external agents would not be visible here."
                     + (" Interim: run cluster-backup.sh to OFF-node storage "
                        "and schedule it." if self.profile.sno else ""),
                     assumption="Backup products visible only via their "
                                "cluster CRs; external/agent-based backup "
                                "cannot be detected from this bundle.",
                     question="How is this cluster backed up (external agents "
                              "are invisible to the bundle)? When was a "
                              "restore last TESTED?")

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
        # StorageClass risk classification: provisioner type x workload x
        # backup posture composes into data-loss findings
        sc_info = {}   # name -> (provisioner, reclaim)
        for r in sc_rows:
            tok = r.split()
            if len(tok) >= 3:
                sc_info[tok[0]] = (tok[1].lower(), tok[2])
        file_re = re.compile(r"cephfs|nfs|azurefile|efs\.|filestore")
        local_re = re.compile(r"topolvm|lvms|local\.storage|no-provisioner|"
                              r"rancher\.io/local-path|hostpath")
        db_re = re.compile(r"postgres|pgsql|\bpg\b|mysql|maria|mongo|oracle|"
                           r"mssql|redis|kafka|etcd|elastic|opensearch|"
                           r"keycloak|(^|[-_])db([-_\d]|$)|database", re.I)
        pvc_total = 0
        on_file, on_local = [], []
        for line in self.b.lines("04-pvc.txt"):
            tok = line.split()
            if len(tok) < 7:
                continue
            pvc_total += 1
            sc = tok[6]
            prov, reclaim = sc_info.get(sc, (sc.lower(), "?"))
            if not (db_re.search(tok[0]) or db_re.search(tok[1])):
                continue
            entry = "%s/%s (%s, %s)" % (tok[0], tok[1], tok[4], sc)
            if file_re.search(prov) or file_re.search(sc.lower()):
                on_file.append(entry)
            elif local_re.search(prov):
                on_local.append(entry + (", reclaim=Delete"
                                         if reclaim == "Delete" else ""))
        if on_file:
            self.add("CRITICAL", "Storage",
                     "Database/Elasticsearch-looking PVCs on file storage "
                     "(CephFS/NFS-class)",
                     "04-pvc.txt: " + "; ".join(on_file[:8]) +
                     ("... (%d total)" % len(on_file) if len(on_file) > 8 else ""),
                     "Red Hat does not support databases on file storage; "
                     "heavy metadata I/O can degrade it for ALL applications, "
                     "and corruption cases may not be supportable.",
                     "Verify each workload; migrate genuine databases/ES data "
                     "volumes to block storage.",
                     assumption="Classified by PVC/namespace NAME matching "
                                "database keywords - verify the actual "
                                "workload before migrating.")
        if on_local:
            no_backup = self.facts.get("backup_stack") == "none detected"
            self.add("CRITICAL" if no_backup else "HIGH", "Storage",
                     "Database-looking PVCs on node-local, non-replicated "
                     "storage%s" % (" WITH NO BACKUP TOOLING" if no_backup
                                    else ""),
                     "04-pvc.txt + 04-storageclasses.txt: "
                     + "; ".join(on_local[:8]) +
                     ("... (%d total)" % len(on_local) if len(on_local) > 8
                      else ""),
                     "Node-local volumes (LVMS/topolvm/local) have no "
                     "replication: losing that node's disk destroys the data"
                     + (" - and no backup product is installed to recover "
                        "it. A single disk failure is permanent data loss."
                        if no_backup else "."),
                     "Back these volumes up (with a data mover - snapshots "
                     "stay on the same disk), or move the data to "
                     "replicated/external storage.",
                     assumption="Classified by PVC/namespace NAME matching "
                                "database keywords and by provisioner type.")
        # functional validation: a cluster with StorageClasses but ZERO
        # PVs+PVCs is either intentionally stateless or a BROKEN provisioner
        if sc_rows and not pvs and pvc_total == 0:
            ev_text = self.b.read("11-events-warning.txt") or ""
            keywords = set()
            for name, (prov, _r) in sc_info.items():
                keywords.update(x for x in re.split(r"[-.]", name) if len(x) > 2)
                keywords.add(prov.split(".")[0])
            hits = sorted({w for w in keywords
                           if w and re.search(re.escape(w), ev_text, re.I)})
            # generic provisioner-failure signatures count as corroboration
            m = re.search(r"NoAvailableDevices\w*|Provisioning ?Failed|"
                          r"failed to provision|no volume plugin|"
                          r"volume group|VolumeBinding\w*", ev_text, re.I)
            if m:
                hits.append(m.group(0))
            ds_bad = [l.split()[1] for l in
                      self.b.lines("06-daemonsets-status.txt")
                      if len(l.split()) >= 5 and l.split()[4].isdigit()
                      and int(l.split()[4]) > 0
                      and re.search(r"storage|lvms|ceph|csi|trident",
                                    l.split()[0] + l.split()[1])]
            broken = hits or ds_bad
            age_days = (self._collection_time() - self.profile.install_date).days \
                if (self.profile.install_date and self._collection_time()) \
                else None
            young = age_days is not None and age_days < 30
            # broken default-or-only class = no working storage at all
            sev = ("CRITICAL" if broken and (defaults or len(sc_info) == 1)
                   else "HIGH" if broken else
                   "LOW" if young else "MEDIUM")
            self.add(sev, "Storage",
                     "StorageClass(es) exist but ZERO PVs/PVCs cluster-wide"
                     + (" - provisioner appears NON-FUNCTIONAL" if broken
                        else " - stateless by design or broken provisioner?"),
                     "04-storageclasses.txt: %s; 04-pv.txt/04-pvc.txt empty."
                     % ", ".join(sorted(sc_info)[:4])
                     + (" 11-events-warning.txt mentions: %s."
                        % ", ".join(hits[:4]) if hits else "")
                     + (" Unhealthy provisioner DaemonSet(s): %s."
                        % ", ".join(ds_bad[:3]) if ds_bad else ""),
                     "Any workload requesting a PVC will hang Pending; "
                     "platform components may silently fall back to "
                     "ephemeral storage."
                     + (" Cluster is %d day(s) old - possibly just unused "
                        "so far." % age_days if young and not broken else ""),
                     "Provision test: create a PVC against the default class "
                     "and watch the provisioner logs; fix the backing "
                     "storage (e.g. volume group, device paths) or remove "
                     "the class if storage is genuinely not wanted.")

    # operator pairs where the first is superseded by the second - both
    # installed usually means an unfinished migration
    SUPERSEDED_PAIRS = [
        (r"rhsso-operator", r"rhbk-operator|keycloak-operator",
         "RH SSO 7.x is superseded by RH build of Keycloak"),
        (r"elasticsearch-operator", r"loki-operator",
         "ES-based logging is superseded by the Loki stack"),
    ]

    def check_olm(self):
        plans = self.b.lines("05-installplan.txt")
        # long-lived clusters accumulate InstallPlan CHAINS (one per version);
        # count only the newest pending plan per operator, not each link
        pending_by_op = {}
        for l in plans:
            tok = l.split()
            if len(tok) >= 5 and tok[-1] == "false":
                base = re.sub(r"\.v?\d[\w.\-]*$", "", tok[2])  # CSV w/o version
                key = (tok[0], base)
                if key not in pending_by_op or tok[2] > pending_by_op[key][2]:
                    pending_by_op[key] = tok
        pending = ["%s %s -> %s" % (t[0], t[1], t[2])
                   for t in pending_by_op.values()]
        if pending:
            self.add("MEDIUM", "Lifecycle",
                     "%d operator(s) with InstallPlans pending manual approval"
                     % len(pending),
                     "05-installplan.txt: " + "; ".join(sorted(pending)[:8]),
                     "Bug fixes / security patches for these operators are "
                     "waiting; the gap grows silently.",
                     "Review and approve in a maintenance window; add a "
                     "recurring review for Manual-approval subscriptions.",
                     assumption="Superseded plans in the same upgrade chain "
                                "are deduplicated; only the newest pending "
                                "version per operator is counted.")
        cats = self.b.read("05-catalogsource.txt") or ""
        csvs_for_cat = self.b.read("05-csv.txt") or ""
        # which catalogs do installed operators actually USE?
        sub_sources = {}
        subs_usable = bool(self.b.lines("05-subscriptions.txt"))
        for l in self.b.lines("05-subscriptions.txt"):
            tok = l.split()
            if len(tok) >= 4:
                sub_sources.setdefault(tok[3], []).append(tok[1])
        # Marketplace builds are recognizable by the -rhmp CSV suffix even
        # when the subscriptions listing is empty
        rhmp = sorted(set(re.findall(r"(\S+-rhmp)\.v?[\d.]", csvs_for_cat)))
        if rhmp:
            sub_sources.setdefault("redhat-marketplace", []).extend(rhmp)
        for cat, label in (("redhat-marketplace",
                            "Deprecated Red Hat Marketplace catalog"),
                           ("community-operators",
                            "Community operator catalog")):
            if cat not in cats:
                continue
            users = sub_sources.get(cat, [])
            if not users and not subs_usable:
                self.add("LOW", "Lifecycle",
                         "%s present - usage UNKNOWN" % label,
                         "05-catalogsource.txt: %s exists; "
                         "05-subscriptions.txt is empty (known collector "
                         "limitation), so usage cannot be verified." % cat,
                         "Operators may depend on this catalog without any "
                         "visible Subscription rows.",
                         "Check each installed operator's catalog provenance "
                         "live before disabling the source.")
                continue
            if users:
                self.add("MEDIUM" if cat == "redhat-marketplace" else "LOW",
                         "Lifecycle",
                         "%s IN USE by %d operator(s)" % (label, len(users)),
                         "05-catalogsource.txt + 05-subscriptions.txt: %s."
                         % ", ".join(users[:6]),
                         "Marketplace is sunset / community operators carry "
                         "no Red Hat support - the dependent operators lose "
                         "updates or supportability.",
                         "Migrate the listed operators to vendor catalogs, "
                         "then remove the source.",
                         assumption="Catalog status per build-time knowledge "
                                    "(%s)." % BUILD_KNOWLEDGE_DATE)
            else:
                self.add("LOW" if cat == "redhat-marketplace" else "INFO",
                         "Lifecycle",
                         "%s present but unused" % label,
                         "05-catalogsource.txt: %s exists; no Subscription "
                         "references it." % cat,
                         "Unused catalogs cost memory (catalog pods) and "
                         "invite unsupported installs.",
                         "Disable it (`oc patch operatorhub cluster` "
                         "disableAllDefaultSources or per-source).",
                         assumption="Catalog status per build-time knowledge "
                                    "(%s). Usage judged from "
                                    "05-subscriptions.txt; if that file is "
                                    "empty due to a collection issue, verify "
                                    "manually." % BUILD_KNOWLEDGE_DATE)
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
        # unfinished migrations: superseded + successor stack both installed
        for old_re, new_re, why in self.SUPERSEDED_PAIRS:
            old_m = re.search(old_re, csvs)
            if old_m and re.search(new_re, csvs):
                self.add("LOW", "Lifecycle",
                         "Superseded and successor operator both installed "
                         "(%s)" % old_m.group(0),
                         "05-csv.txt: %s alongside its successor." % old_m.group(0),
                         "%s; running both suggests an unfinished migration - "
                         "double resource cost and a stale attack/upgrade "
                         "surface." % why,
                         "Finish the migration and uninstall the superseded "
                         "operator (check for leftover PVs/CRDs too).",
                         assumption="Superseded pairs per build-time "
                                    "knowledge (%s)." % BUILD_KNOWLEDGE_DATE)
        # floating channels auto-approve unpredictable jumps
        floating = ["%s/%s" % (l.split()[0], l.split()[1])
                    for l in self.b.lines("05-subscriptions.txt")
                    if len(l.split()) >= 5 and l.split()[2] in
                    ("latest", "alpha", "beta") and l.split()[4] == "Automatic"]
        if floating:
            self.add("LOW", "Lifecycle",
                     "%d subscription(s) on a floating channel with "
                     "Automatic approval" % len(floating),
                     "05-subscriptions.txt: " + ", ".join(floating[:6]),
                     "`latest`/alpha/beta channels can jump operator major "
                     "versions without review.",
                     "Pin to a versioned stable channel or switch to Manual "
                     "approval.")
        # OperatorGroups without any CSV = uninstall remnants
        og_ns = {l.split()[0] for l in self.b.lines("05-operatorgroup.txt")
                 if l.split()}
        ns_by_csv = {}
        for l in self.b.lines("05-csv.txt"):
            tok = l.split()
            if len(tok) > 1:
                ns_by_csv.setdefault(tok[1], set()).add(tok[0])
        owning_ns = {ns for name, nss in ns_by_csv.items()
                     if len(nss) <= 2 for ns in nss}
        remnants = sorted(ns for ns in og_ns - owning_ns
                          if not PLATFORM_NS_RE.match(ns))
        if remnants:
            self.add("LOW", "Hygiene",
                     "%d namespace(s) with an OperatorGroup but no operator"
                     % len(remnants),
                     "05-operatorgroup.txt vs 05-csv.txt: " +
                     ", ".join(remnants[:10]) +
                     ("..." if len(remnants) > 10 else "") +
                     " (namespaces holding only copied CSVs of operators "
                     "installed elsewhere count as remnants).",
                     "Leftovers from uninstalled operators; a stray "
                     "OperatorGroup also breaks future installs into that "
                     "namespace.",
                     "Delete the OperatorGroups (and namespaces) or finish "
                     "the uninstall.")

    def check_tenancy(self):
        n_proj = len(self.b.lines("06-projects.txt"))
        self.facts["projects"] = n_proj
        if not n_proj:
            return
        rq_ns = {l.split()[0] for l in self.b.lines("06-resourcequota.txt") if l.split()}
        np_ns = {l.split()[0] for l in self.b.lines("03-networkpolicy.txt") if l.split()}
        lr_ns = {l.split()[0] for l in self.b.lines("06-limitrange.txt") if l.split()}
        self.facts["governance"] = (len(rq_ns), len(lr_ns), len(np_ns), n_proj)
        # coverage is judged over TENANT namespaces only - platform namespaces
        # (openshift-*, kube-*, default) legitimately carry no tenant quotas
        tenants = self.profile.tenant_namespaces
        self.facts["tenant_namespaces"] = len(tenants)
        if not tenants:
            self.add("LOW", "Tenancy",
                     "No tenant namespaces yet - governance baseline missing "
                     "for onboarding",
                     "06-projects.txt: all %d namespaces are platform "
                     "namespaces; no ResourceQuota/NetworkPolicy baseline "
                     "exists for future tenants." % n_proj,
                     "Not a live exposure today, but the first onboarded "
                     "workload will land without quota or network isolation.",
                     "Prepare a templated quota+LimitRange+default-deny "
                     "baseline (e.g. via GitOps) before onboarding tenants.",
                     question="This cluster has no tenant workloads yet - "
                              "what is its intended role?")
            return
        rq_cov = len(rq_ns & set(tenants))
        np_cov = len(np_ns & set(tenants))
        lr_cov = len(lr_ns & set(tenants))
        gov_sev = "MEDIUM" if len(tenants) > 5 else "LOW"
        if len(tenants) > 5 and lr_cov == 0 and rq_cov:
            self.add("LOW", "Tenancy",
                     "ResourceQuotas exist but no LimitRange in any tenant "
                     "namespace",
                     "06-limitrange.txt vs 06-projects.txt.",
                     "Without LimitRanges, pods without explicit "
                     "requests/limits bypass sensible defaults and skew "
                     "quota accounting.",
                     "Pair every tenant quota with a LimitRange default.")
        if rq_cov < len(tenants) * 0.5:
            self.add(gov_sev, "Tenancy",
                     "ResourceQuotas cover only %d of %d tenant namespaces"
                     % (rq_cov, len(tenants)),
                     "06-resourcequota.txt vs 06-projects.txt (platform "
                     "namespaces excluded from the ratio).",
                     "Unquotad tenants can exhaust node memory (incompressible) "
                     "and trigger cascading evictions.",
                     "Define a quota+LimitRange baseline for every tenant "
                     "namespace (templated, e.g. via GitOps).")
        uncovered = len(tenants) - np_cov
        if np_cov < len(tenants) * 0.5 or uncovered >= 20:
            self.add(gov_sev, "Security",
                     "%d tenant namespace(s) have no NetworkPolicy "
                     "(%d of %d covered)" % (uncovered, np_cov, len(tenants)),
                     "03-networkpolicy.txt vs 06-projects.txt (platform "
                     "namespaces excluded from the ratio).",
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
            self.add("LOW" if self.profile.sno else "HIGH", "Workloads",
                     "%d PodDisruptionBudget(s) allow zero disruptions" % len(pdbs),
                     "06-pdb.txt (ALLOWED=0): " +
                     "; ".join(" ".join(l.split()[:2]) for l in pdbs[:6]),
                     "Node drains hang on these pods - blocking MachineConfig "
                     "rollouts, patching and upgrades."
                     + (" (Downgraded on SNO: the single node reboots in "
                        "place, drains are not the upgrade mechanism.)"
                        if self.profile.sno else ""),
                     "Add replicas or relax the PDBs so at least one "
                     "disruption is allowed.",
                     assumption="ALLOWED=0 can be a transient artifact while "
                                "an outage keeps the guarded pods down - "
                                "recheck once any ongoing incident is over.",
                     cascade=True)
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
        scc_drift = False
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
                    scc_drift = True
        if self.b.lines("07-scc.txt") and not scc_drift:
            self.green("Security", "Default restricted SCC matches stock values (07-scc.txt).")
        # custom SCC risk scoring - PRIV=true is NOT the only root-equivalent
        # signal (dangerous capabilities, RunAsAny, hostPath, volumes: * are
        # just as bad and slip past a PRIV-column-only filter)
        csvs_txt = self.b.read("05-csv.txt") or ""
        risky, attributed = [], []
        for line in self.b.lines("07-scc.txt"):
            tok = line.replace("<no value>", "<no-value>").split()
            if len(tok) < 10 or tok[0] in STOCK_SCCS:
                continue
            name, priv, caps, selinux, runasuser = tok[0], tok[1], tok[2], tok[3], tok[4]
            volumes = tok[9]
            score, why = 0, []
            if priv == "true":
                score += 3
                why.append("PRIV")
            if DANGEROUS_CAPS_RE.search(caps):
                score += 2
                why.append("caps=%s" % caps)
            if runasuser == "RunAsAny":
                score += 1
                why.append("RunAsAny uid")
            if selinux == "RunAsAny":
                score += 1
                why.append("RunAsAny selinux")
            if '"*"' in volumes or "hostPath" in volumes:
                score += 2
                why.append("volumes incl. %s"
                           % ("*" if '"*"' in volumes else "hostPath"))
            if score < 2:
                continue
            owner = next((hint for pat, hint in OPERATOR_SCC_HINTS
                          if re.match(pat, name) and re.search(hint, csvs_txt)),
                         None)
            entry = "%s (%s)" % (name, ", ".join(why))
            (attributed if owner else risky).append(entry)
        if risky:
            self.add("HIGH" if any("PRIV" in r or "caps=" in r for r in risky)
                     else "MEDIUM", "Security",
                     "%d high-risk custom SCC(s) not attributable to an "
                     "installed operator" % len(risky),
                     "07-scc.txt: " + "; ".join(risky[:8]),
                     "Each grants near-root capability to whatever service "
                     "account can use it - regardless of the PRIV column.",
                     "Identify the owner of each SCC, verify its bindings, "
                     "and remove or narrow unneeded grants.",
                     assumption="Risk scored from the scc table columns "
                                "(capabilities, RunAsAny, hostPath/volumes); "
                                "SCCs matching a known operator pattern with "
                                "that operator installed are listed "
                                "separately.")
        if attributed:
            self.add("LOW", "Security",
                     "%d operator-owned elevated SCC(s) present" % len(attributed),
                     "07-scc.txt: " + "; ".join(attributed[:8]),
                     "Expected for the installed operators, but each is still "
                     "an elevated-privilege surface.",
                     "Confirm the SCCs are unmodified and bound only to the "
                     "operators' service accounts.")
        # cluster-admin bindings - resolve WHO each one grants to
        crb = self.b.read("07-clusterrolebindings.txt") or ""
        crb_lines = crb.splitlines()
        crb_header = crb_lines[0] if crb_lines else ""
        groups_ok = self.b.status("07-groups.txt") in (S_OK, S_EMPTY)
        groups_members = {l.split()[0]: (l.split() + [""])[1]
                          for l in self.b.lines("07-groups.txt") if l.split()}
        admins, mg = [], []
        for line in crb_lines[1:]:
            if re.search(r"ClusterRole/cluster-admin(\s|$)", line):
                name = line.split()[0]
                if name.startswith("system:"):
                    continue
                if name.startswith("must-gather-"):
                    mg.append(name)
                elif name not in DEFAULT_CLUSTER_ADMIN_CRBS:
                    subjects = []
                    if "USERS" in crb_header:
                        for col, kind in (("USERS", "user"),
                                          ("GROUPS", "group"),
                                          ("SERVICEACCOUNTS", "SA")):
                            val = col_slice(crb_header, line, col,
                                            ("GROUPS", "SERVICEACCOUNTS"))
                            if val:
                                subjects.append("%s:%s" % (kind, val))
                                if kind == "group" and groups_ok \
                                        and val in groups_members \
                                        and not groups_members[val]:
                                    subjects.append("(group %s has no "
                                                    "members!)" % val)
                    admins.append(name + (" -> %s" % " ".join(subjects)
                                          if subjects else ""))
        if admins:
            self.add("HIGH" if len(admins) > 5 else "MEDIUM", "Security",
                     "%d non-default cluster-admin ClusterRoleBindings" % len(admins),
                     "07-clusterrolebindings.txt: " + ", ".join(admins[:10]) +
                     ("..." if len(admins) > 10 else ""),
                     "Every extra cluster-admin grant (users, operators' "
                     "service accounts, monitoring tools) is a full-cluster "
                     "compromise path.",
                     "Replace SA grants with scoped roles; move humans to "
                     "group-based, just-in-time elevation.",
                     assumption="Bindings named system:* and the OCP-shipped "
                                "cluster-admin bindings (%s) are treated as "
                                "defaults per build-time knowledge (%s)."
                                % (", ".join(sorted(DEFAULT_CLUSTER_ADMIN_CRBS)),
                                   BUILD_KNOWLEDGE_DATE))
        if mg:
            self.add("MEDIUM", "Security",
                     "%d stale must-gather cluster-admin binding(s)" % len(mg),
                     "07-clusterrolebindings.txt: " + ", ".join(mg[:6]),
                     "Leftover full-admin grants from old support sessions.",
                     "Delete them.")
        if "kubeadmin" in (self.b.read("07-kubeadmin-exists.txt") or ""):
            # do NOT advise removal while it is the only login path that
            # survives an IdP/ingress outage (identity-path analysis)
            fragile_idp = self.facts.get("idp_fragile", False)
            self.add("MEDIUM", "Security",
                     "kubeadmin bootstrap user still exists",
                     "07-kubeadmin-exists.txt: secret/kubeadmin present.",
                     "A static, unauditable break-glass password account "
                     "remains active.",
                     "KEEP it for now as documented break-glass - the "
                     "identity path is fragile (no IdP, unproven, or "
                     "ingress-dependent; see the identity findings) and "
                     "removing kubeadmin could lock admins out. Re-evaluate "
                     "once a robust IdP path exists." if fragile_idp else
                     "Remove it once IdP-based admin access is confirmed "
                     "working.")
        # etcd encryption - "(empty result)" is the collector's empty marker,
        # so test the file STATUS, not string truthiness
        enc = (self.b.read("07-etcd-encryption.txt") or "").strip()
        enc_missing = self.b.status("07-etcd-encryption.txt") in (
            S_EMPTY, S_MISSING) or not enc
        self.facts["etcd_encryption"] = "NOT ENABLED" if enc_missing else enc
        if not enc_missing:
            self.green("Security", "etcd encryption at rest enabled: %s (07-etcd-encryption.txt)." % enc)
        if enc_missing and self.b.status("07-etcd-encryption.txt") != S_MISSING:
            self.add("HIGH", "Security",
                     "etcd encryption at rest is not enabled",
                     "07-etcd-encryption.txt is empty (apiserver "
                     "spec.encryption.type unset).",
                     "Secrets/config in etcd are stored in plaintext on the "
                     "control-plane disks and inside etcd backups.",
                     "Enable aesgcm (or aescbc) etcd encryption.")
        # oauth - judge the ACTIVE spec block only; the last-applied
        # annotation preserves historical config and must not raise findings
        oauth = self.b.read("07-oauth.yaml") or ""
        spec = yaml_block(oauth, "spec") or oauth
        if "type: HTPasswd" in spec:
            self.add("MEDIUM", "Security",
                     "HTPasswd identity provider active",
                     "07-oauth.yaml: spec.identityProviders contains "
                     "type: HTPasswd.",
                     "Local password file: no MFA, no central "
                     "joiner/mover/leaver process.",
                     "Restrict to a documented break-glass account or remove; "
                     "authenticate through the enterprise IdP.")
        insecure_active = bool(re.search(r"insecure:\s*true", spec)
                               or "ldap://" in spec)
        insecure_hist = bool(re.search(r"insecure.{0,4}true", oauth)
                             or "ldap://" in oauth)
        if insecure_active:
            self.add("HIGH", "Security",
                     "LDAP identity provider configured without TLS",
                     "07-oauth.yaml: spec contains 'insecure: true' and/or an "
                     "ldap:// URL.",
                     "Bind credentials and user passwords cross the network "
                     "in cleartext.",
                     "Use ldaps:// with CA validation.")
        elif insecure_hist:
            self.add("LOW", "Security",
                     "Historical insecure-LDAP config in OAuth annotations "
                     "(not active)",
                     "07-oauth.yaml: insecure/ldap:// appears only outside "
                     "the active spec (last-applied annotation).",
                     "The active configuration is clean; the annotation "
                     "records that cleartext LDAP was used in the past.",
                     "Confirm the old bind credentials were rotated after "
                     "the migration.")

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
            if self.profile.sno:
                self.suppress("Default ingress controller has <2 replicas",
                              "inherent to single-node topology "
                              "(controlPlaneTopology: SingleReplica)")
            else:
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
                if not insecure and self.facts["routes"]:
                    self.green("Security", "All %d routes use TLS termination "
                               "(03-routes.txt)." % self.facts["routes"])
                if insecure:
                    self.add("LOW", "Security",
                             "%d route(s) without TLS termination" % insecure,
                             "03-routes.txt: TERMINATION column empty.",
                             "Plain-HTTP application traffic.",
                             "Move to edge/reencrypt termination unless "
                             "deliberately internal-only.")

    def check_monitoring(self):
        mon_status = self.b.status("08-cluster-monitoring.yaml")
        mon = self.b.read("08-cluster-monitoring.yaml") or ""
        fwd = mon_status == S_OK and "additionalAlertmanagerConfigs" in mon
        self.facts["alert_forwarding"] = fwd
        if mon_status == S_OK:
            fwd_evidence = ("08-cluster-monitoring.yaml: "
                            "additionalAlertmanagerConfigs "
                            + ("present (alerts forwarded to an external/hub "
                               "Alertmanager)." if fwd else "absent."))
        else:
            # cluster-monitoring-config ConfigMap does not exist: that is a
            # CONFIG FACT (stock defaults in effect), not a collection gap
            fwd_evidence = ("cluster-monitoring-config ConfigMap not present "
                            "(08-cluster-monitoring.yaml: %s) - monitoring "
                            "runs on stock defaults, no alert forwarding "
                            "configured." % mon_status)
            mon_pvcs = [l for l in self.b.lines("04-pvc.txt")
                        if l.split() and l.split()[0] == "openshift-monitoring"]
            if not mon_pvcs and self.b.status("04-pvc.txt") in (S_OK, S_EMPTY):
                self.add("MEDIUM", "Observability",
                         "Monitoring stack runs on ephemeral storage "
                         "(defaults in effect)",
                         "cluster-monitoring-config not found + 04-pvc.txt: "
                         "no PVCs in openshift-monitoring.",
                         "Prometheus/Alertmanager state lives on emptyDir: "
                         "every pod restart or node reboot erases all metric "
                         "history and silences - post-incident analysis "
                         "becomes impossible.",
                         "Create cluster-monitoring-config with "
                         "volumeClaimTemplates (and a retention policy) on a "
                         "suitable StorageClass.")
        # empirical cross-check: a failure nobody fixed for days is PROOF
        # the alert path is broken or ignored, not just "verify it"
        unnoticed = self.facts.get("unnoticed_failure_days", 0)
        UNNOTICED_MIN = 3
        self.add("HIGH" if (not fwd or unnoticed >= UNNOTICED_MIN) else "MEDIUM",
                 "Observability",
                 "Verify alert notifications reach a human"
                 + (" - evidence suggests they do NOT"
                    if unnoticed >= UNNOTICED_MIN
                    else ""),
                 fwd_evidence
                 + (" Empirical signal: backup jobs have been failing for "
                    "at least ~%.0f days without correction - either no "
                    "alert fires for them or nobody acts on it."
                    % unnoticed if unnoticed >= UNNOTICED_MIN else ""),
                 "Alertmanager receiver config lives in a Secret this bundle "
                 "does not (and should not) collect - silent-alerting is the "
                 "most common root cause of long outages.",
                 "Send a synthetic test alert and confirm the on-call channel "
                 "receives it end-to-end"
                 + ("; add an explicit alert on failed backup jobs."
                    if unnoticed >= UNNOTICED_MIN else "."),
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
        spec = yaml_block(oauth, "spec") or oauth
        self.facts["idps"] = re.findall(r"^\s*type:\s*(\w+)\s*$", spec, re.M)
        self.facts["users"] = len(self.b.lines("07-users.txt"))
        if self.b.status("07-oauth.yaml") == S_OK and not self.facts["idps"] \
                and self.facts["users"] == 0:
            self.add("HIGH", "Security",
                     "No identity provider configured - kubeadmin/kubeconfig "
                     "are the only access paths",
                     "07-oauth.yaml: spec has no identityProviders; "
                     "07-users.txt: 0 users (no login has ever succeeded).",
                     "All access rides on the bootstrap password or "
                     "certificate kubeconfigs: unauditable, shared, and "
                     "unrevokable per-person.",
                     "Configure an identity provider (OIDC/LDAP) and "
                     "group-based RBAC; keep kubeadmin only as documented "
                     "break-glass.")

    def check_infra_facts(self):
        infra = self.b.read("01-infrastructure.yaml") or ""
        self.facts["platform"] = yaml_grab(infra, "type") or "?"
        self.facts["infra_name"] = yaml_grab(infra, "infrastructureName")
        dns = self.b.read("01-dns.yaml") or ""
        self.facts["base_domain"] = yaml_grab(dns, "baseDomain")
        reg = self.b.read("07-imageregistry.yaml") or ""
        self.facts["registry_state"] = yaml_grab(reg, "managementState")
        self.facts["argo_apps"] = len(self.b.lines("09-applications.txt"))
        if self.facts["registry_state"] == "Removed":
            self.add("MEDIUM", "Process",
                     "Internal image registry is Removed - confirm this is "
                     "intentional",
                     "07-imageregistry.yaml: spec.managementState: Removed.",
                     "No in-cluster builds or ImageStream pushes are "
                     "possible; every image must come from an external "
                     "registry"
                     + (" - on this disconnected cluster that makes the "
                        "mirror registry a single dependency for all image "
                        "serving and DR." if self.profile.disconnected
                        else "."),
                     "Confirm with the owner that Removed is deliberate "
                     "(it is a supported minimal-footprint choice); document "
                     "the external registry dependency.",
                     question="Is the internal image registry's Removed state "
                              "deliberate? Where are images built and served "
                              "from?")
        # apiserver posture - supported-but-consequential defaults
        apisrv = self.b.read("01-apiserver.yaml") or ""
        audit = yaml_grab(apisrv, "profile")
        if audit == "None":
            self.add("MEDIUM", "Security",
                     "API audit logging is disabled (profile: None)",
                     "01-apiserver.yaml: spec.audit.profile: None.",
                     "No API audit trail: forensics and compliance evidence "
                     "are impossible after an incident.",
                     "Set the audit profile to Default (or stricter).")
        if re.search(r"tlsSecurityProfile:\s*\n\s*old:", apisrv):
            self.add("MEDIUM", "Security",
                     "API server TLS security profile set to Old",
                     "01-apiserver.yaml: tlsSecurityProfile: old.",
                     "Permits legacy TLS versions/ciphers for every API "
                     "client.",
                     "Move to Intermediate unless a legacy client is "
                     "documented.")

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
        if not flagged and self.b.lines("02-nodes-conditions.txt"):
            self.green("Stability", "No node reports Memory/Disk/PID pressure or NetworkUnavailable (02-nodes-conditions.txt).")
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
        if not under and self.b.lines("06-workloads-status.txt"):
            self.green("Workloads", "All Deployments/StatefulSets at desired replicas; no DaemonSet unavailability (06-workloads-status.txt).")
        if under:
            self.add("MEDIUM", "Workloads",
                     "%d workload(s) below desired replicas" % len(under),
                     "06-workloads-status.txt / 06-daemonsets-status.txt: " +
                     "; ".join(under[:8]) + ("..." if len(under) > 8 else ""),
                     "Under-replicated Deployments/StatefulSets and DaemonSets "
                     "with unavailable pods reduce redundancy or indicate crash "
                     "loops.",
                     "Correlate with 06-pods-all.txt and 11-events-warning.txt "
                     "for the root cause.",
                     cascade=True)

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
        if not failing and self.b.status("01-etcd-readyz.txt") == S_OK:
            self.green("Stability", "All API-server readiness gates ok (01-etcd-readyz.txt).")
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
                     "kubelet/CNI.",
                     cascade=True)

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

    def check_data_availability(self):
        """Classify every .err file: verified-absent vs defaults vs FAILED.

        A failed collection is a declared blind spot - the report must never
        read 'no data' as 'no problem'.
        """
        if not self.b.path.is_dir():
            return
        absent, notfound, failed = [], [], []
        for err in sorted(self.b.path.glob("*.err")):
            base = err.name[:-4]
            {S_ERR_ABSENT: absent, S_ERR_NOTFOUND: notfound,
             S_ERR_FAILED: failed}.get(self.b.status(base), failed).append(base)
        self.facts["data_availability"] = {
            "verified_absent": absent, "not_configured": notfound,
            "failed": failed,
        }
        if not failed:
            return
        alerts_failed = any(f.startswith("08-active-alerts") for f in failed)
        first_line = (self.b.err_text(failed[0]) or "").splitlines()
        self.add("MEDIUM" if alerts_failed else "LOW", "Analyzer",
                 "%d collection(s) FAILED - that data is unknown, not clean"
                 % len(failed),
                 "Failed .err files: " + ", ".join(failed[:8]) +
                 ("..." if len(failed) > 8 else "") +
                 ("; first error: %r" % first_line[0] if first_line else ""),
                 ("The active-alerts snapshot is among the failures: the "
                  "cluster's current alert state is UNKNOWN - do not report "
                  "'no alerts firing'. " if alerts_failed else "")
                 + "Every failed collection is a blind spot in this review.",
                 "Re-run the failed commands live (or fix the collector) and "
                 "review that data manually.")

    def check_upgrade_posture(self):
        """ClusterVersion conditions + patch staleness + update backlog."""
        cv = self.b.read("01-clusterversion.yaml") or ""
        cv_types = {"Upgradeable", "Failing", "Available", "Progressing",
                    "RetrievedUpdates", "ReleaseAccepted"}
        conds = {c["type"]: c for c in parse_conditions(cv, all_blocks=True)
                 if c.get("type") in cv_types}
        c = conds.get("Failing")
        if c and c.get("status") == "True":
            self.add("HIGH", "Lifecycle",
                     "ClusterVersion is Failing",
                     "01-clusterversion.yaml: Failing=True (%s): %s"
                     % (c.get("reason", "?"), (c.get("message") or "")[:200]),
                     "The CVO cannot reconcile the desired release - upgrades "
                     "and even steady-state payload repair are broken.",
                     "Resolve the named component first; do not attempt "
                     "further upgrades while Failing.")
        c = conds.get("Upgradeable")
        if c and c.get("status") == "False":
            self.add("MEDIUM", "Lifecycle",
                     "Upgradeable=False - next MINOR upgrade is blocked (%s)"
                     % c.get("reason", "?"),
                     "01-clusterversion.yaml: %s" % (c.get("message") or "")[:250],
                     "The next minor version will refuse to start until this "
                     "is resolved; z-stream (patch) updates are NOT blocked.",
                     "Address the reason (e.g. provide the admin-ack after "
                     "checking removed-API usage) before the upgrade window.")
        # patch staleness + cadence from history completionTimes
        now = self._collection_time()
        times = sorted(t for t in
                       (parse_iso_time(x) for x in re.findall(
                           r"completionTime:\s*(\S+)", yaml_block(cv, "history")))
                       if t)
        if times:
            gaps = [(b - a).days for a, b in zip(times, times[1:])]
            if any(g > 365 for g in gaps):
                self.add("MEDIUM", "Lifecycle",
                         "Update history shows gap(s) longer than a year",
                         "01-clusterversion.yaml history: largest gap %d "
                         "days across %d recorded updates."
                         % (max(gaps), len(times)),
                         "Long gaps force multi-minor catch-up jumps later - "
                         "the riskiest upgrade pattern.",
                         "Adopt a fixed patching cadence.")
        if now and times:
            stale_days = (now - times[-1]).days
            if stale_days >= 90:
                self.add("HIGH" if stale_days >= 180 else "MEDIUM",
                         "Lifecycle",
                         "No update applied for ~%d months" % (stale_days // 30),
                         "01-clusterversion.yaml history: last completed "
                         "update %s." % times[-1].strftime("%Y-%m-%d"),
                         "Accumulating z-streams usually include security "
                         "errata; the gap grows silently and complicates the "
                         "eventual jump.",
                         "Schedule regular z-stream patching (e.g. "
                         "quarterly); review the pending-updates list.",
                         assumption="Staleness measured from the bundle "
                                    "collection time, thresholds 90/180 days.")
        # pending updates backlog (01-upgrade.txt table) + security errata
        upg = self.b.read("01-upgrade.txt") or ""
        m = re.search(r"Recommended updates:\s*\n(.*)", upg, re.S)
        n_updates = len(re.findall(r"^\s+(\d+\.\d+\.\d+)\s", m.group(1), re.M)) \
            if m else 0
        rhsa = len(set(re.findall(r"(RHSA-\d{4}:\d+)",
                                  yaml_block(cv, "availableUpdates"))))
        if n_updates >= 5 or (rhsa and n_updates >= 1):
            self.add("MEDIUM", "Lifecycle",
                     "%d recommended z-stream update(s) pending%s"
                     % (n_updates,
                        ", incl. %d security erratum/errata (RHSA)" % rhsa
                        if rhsa else ""),
                     "01-upgrade.txt: Recommended updates table"
                     + ("; 01-clusterversion.yaml availableUpdates reference "
                        "RHSA advisories." if rhsa else "."),
                     "The cluster is missing published fixes"
                     + (" including security updates" if rhsa else "") + ".",
                     "Plan a z-stream update to the latest recommended "
                     "version%s." % (" (z-streams are not blocked by "
                                     "Upgradeable=False)"
                                     if conds.get("Upgradeable", {}).get(
                                         "status") == "False" else ""))

    def check_events(self):
        """Mine 11-events-warning.txt: recurring reasons ARE findings."""
        rows = self.b.lines("11-events-warning.txt")
        if not rows:
            return
        by_key, oom, sched, mount, etcd_ms, reg5xx, probes = \
            {}, [], [], [], [], [], {}
        for line in rows:
            tok = line.split(None, 5)
            if len(tok) < 6:
                continue
            ns, _seen, _type, reason, obj, msg = tok
            by_key[(ns, reason)] = by_key.get((ns, reason), 0) + 1
            if "OOM" in reason or "OOMKilled" in msg:
                oom.append("%s/%s" % (ns, obj))
            elif reason == "FailedScheduling":
                sched.append("%s/%s" % (ns, obj))
            elif reason in ("FailedMount", "FailedAttachVolume"):
                mount.append("%s/%s" % (ns, obj))
            elif "leader changed" in msg or "LeaderChange" in reason \
                    or "took too long" in msg:
                etcd_ms.extend(float(x) for x in
                               re.findall(r"(\d+(?:\.\d+)?)\s*ms", msg))
                etcd_ms.append(0.0)   # count the event even without a number
            elif re.search(r"\b50[0-9]\b", msg) and \
                    ("pull" in msg.lower() or "registry" in msg.lower()):
                reg5xx.append("%s/%s" % (ns, obj))
            elif reason == "Unhealthy":
                probes[ns] = probes.get(ns, 0) + 1
        if oom:
            self.add("HIGH", "Capacity",
                     "OOM kill event(s) in the warning-event window",
                     "11-events-warning.txt: %d event(s), e.g. %s."
                     % (len(oom), ", ".join(sorted(set(oom))[:5])),
                     "Workloads are being killed for memory; limits are too "
                     "tight or nodes are overcommitted.",
                     "Right-size the affected workloads' memory "
                     "requests/limits; check node memory headroom.")
        if len(sched) >= 3:
            self.add("MEDIUM", "Capacity",
                     "Recurring FailedScheduling events (%d)" % len(sched),
                     "11-events-warning.txt: e.g. %s."
                     % ", ".join(sorted(set(sched))[:5]),
                     "Pods cannot be placed - capacity, taints, affinity or "
                     "PVC binding is blocking scheduling.",
                     "Read one event's full message for the exact predicate "
                     "that failed.",
                     cascade=True)
        if len(mount) >= 3:
            self.add("MEDIUM", "Storage",
                     "Recurring volume mount/attach failures (%d)" % len(mount),
                     "11-events-warning.txt: e.g. %s."
                     % ", ".join(sorted(set(mount))[:5]),
                     "Workloads cannot access their storage; often a CSI "
                     "driver or backend issue.",
                     "Check the CSI driver pods and the storage backend for "
                     "the listed volumes.")
        if etcd_ms:
            peaks = [x for x in etcd_ms if x > 0]
            self.add("HIGH", "Stability",
                     "etcd leader-change / slow-request warning events",
                     "11-events-warning.txt: %d event(s)%s."
                     % (len(etcd_ms),
                        "; disk metrics up to %.0f ms (fsync guidance ~10 ms)"
                        % max(peaks) if peaks else ""),
                     "Leader elections stall every write; recurring ones "
                     "signal disk latency or CPU starvation on control-plane "
                     "nodes - an outage precursor.",
                     "Check control-plane disk performance (etcd fsync "
                     "metrics live only in Prometheus - collect them live).")
        if reg5xx:
            self.add("INFO", "Workloads",
                     "Registry 5xx pull errors in the event window (likely "
                     "upstream/transient)",
                     "11-events-warning.txt: %d event(s), e.g. %s."
                     % (len(reg5xx), ", ".join(sorted(set(reg5xx))[:4])),
                     "Image pulls failed with server errors - usually a "
                     "registry-side incident, not a cluster fault.",
                     "Correlate timestamps across clusters; verify the pulls "
                     "have since succeeded.")
        flappy = {ns: n for ns, n in probes.items() if n >= 5}
        if flappy:
            self.add("LOW", "Workloads",
                     "Recurring probe failures in %d namespace(s)" % len(flappy),
                     "11-events-warning.txt (reason=Unhealthy): "
                     + ", ".join("%s (%d)" % kv for kv in
                                 sorted(flappy.items(), key=lambda kv: -kv[1])[:5]),
                     "Flapping probes cause restarts and mask real failures; "
                     "often undersized probes timeouts or resource pressure.",
                     "Inspect the probe messages; tune timeouts or fix the "
                     "slow startup.")
        covered = ("FailedScheduling", "FailedMount", "FailedAttachVolume",
                   "Unhealthy")
        other = {k: n for k, n in by_key.items()
                 if n >= 10 and k[1] not in covered and "OOM" not in k[1]}
        if other:
            top = sorted(other.items(), key=lambda kv: -kv[1])[:5]
            self.add("MEDIUM", "Stability",
                     "Other recurring warning-event pattern(s): %s"
                     % ", ".join(sorted({k[1] for k, _ in top})),
                     "11-events-warning.txt: "
                     + "; ".join("%s/%s x%d" % (k[0], k[1], n) for k, n in top),
                     "Each recurring warning reason is usually a finding in "
                     "disguise.",
                     "Read the full messages for each recurring "
                     "namespace+reason pair.")

    def check_csr(self):
        pend = [l.split()[0] for l in self.b.lines("02-csr.txt")
                if "Pending" in l]
        if not pend and self.b.status("02-csr.txt") in (S_OK, S_EMPTY):
            self.green("Stability", "No pending certificate signing requests (02-csr.txt).")
        if pend:
            self.add("HIGH", "Stability",
                     "%d certificate signing request(s) Pending" % len(pend),
                     "02-csr.txt: " + ", ".join(pend[:6]) +
                     ("..." if len(pend) > 6 else ""),
                     "Unapproved CSRs block node joins and kubelet cert "
                     "renewal - nodes can drop NotReady when their cert "
                     "expires.",
                     "Review and approve legitimate CSRs "
                     "(`oc adm certificate approve`); investigate why "
                     "auto-approval did not handle them.")

    def check_topology_spread(self):
        """Failure-domain signals - HA clusters only."""
        if self.profile.sno:
            return
        rows = self.b.lines("02-nodes-roles-zones.txt")
        t = self.b.read("02-nodes-roles-zones.txt") or ""
        header = t.splitlines()[0] if t else ""
        if rows and "ZONE" in header:
            zones = {col_slice(header, l, "ZONE", ()) for l in rows}
            if zones == {""}:
                self.add("LOW", "Stability",
                         "No failure-domain (zone) labels on any node",
                         "02-nodes-roles-zones.txt: ZONE column empty for "
                         "all nodes.",
                         "Zone-aware scheduling, PV topology and HA spread "
                         "cannot work without topology labels.",
                         "Label nodes with topology.kubernetes.io/zone per "
                         "rack/site/failure domain.")
        # hostname-prefix inference: all masters in one site-prefix while
        # workers span several suggests a single-site control plane
        masters, workers = set(), set()
        for line in self.b.lines("02-nodes-wide.txt"):
            tok = line.split()
            if len(tok) >= 3:
                prefix = re.sub(r"[-_]?\d+$", "", tok[0].split(".")[0].lower())
                # strip the role token so site prefixes become comparable
                # (site1-mst01 / site1-wrk03 -> site1)
                prefix = re.sub(r"[-_]?(mst|master|wrk|worker|inf|infra|"
                                r"cp|ctl|node)$", "", prefix)
                (masters if "master" in tok[2] or "control-plane" in tok[2]
                 else workers).add(prefix)
        if len(workers) >= 2 and len(masters) == 1 and masters <= workers:
            self.add("MEDIUM", "Stability",
                     "All control-plane nodes share one hostname prefix "
                     "while workers span several",
                     "02-nodes-wide.txt: master prefix %s vs worker prefixes "
                     "%s." % (", ".join(sorted(masters)),
                              ", ".join(sorted(workers))),
                     "If the prefixes encode sites/racks, the entire control "
                     "plane may sit in ONE failure domain - a site loss "
                     "takes down etcd quorum.",
                     "Confirm the physical placement of the control-plane "
                     "nodes; spread across failure domains if possible.",
                     assumption="Failure domains inferred from hostname "
                                "prefixes (trailing digits stripped) - "
                                "verify against the real site layout.")

    def check_prom_am(self):
        for line in self.b.lines("08-prom-am.txt", skip_header=False):
            tok = line.split()
            if len(tok) < 6 or not re.match(r"(prometheus|alertmanager)\.",
                                            tok[0]):
                continue
            name, desired, ready, avail = tok[0], tok[2], tok[3], tok[5]
            if (desired.isdigit() and ready.isdigit()
                    and int(ready) < int(desired)) or avail == "False":
                self.add("HIGH", "Observability",
                         "Monitoring component %s not fully available"
                         % name.split(".")[0],
                         "08-prom-am.txt: %s ready %s/%s, available=%s."
                         % (name, ready, desired, avail),
                         "Degraded Prometheus/Alertmanager means gaps in "
                         "metrics and undelivered alerts RIGHT NOW.",
                         "Check the pods and PVCs in openshift-monitoring; "
                         "see also 06-pods-all.txt.",
                         cascade=True)

    def check_egress_targets(self):
        urls = []
        for f in ("08-uwm.yaml", "08-cluster-monitoring.yaml"):
            t = self.b.read(f) or ""
            if "remoteWrite" in t:
                urls += ["%s (%s)" % (u, f) for u in
                         re.findall(r"url:\s*(\S+)", t)]
        if urls:
            self.add("INFO", "Observability",
                     "Metrics leave the cluster via remoteWrite",
                     "; ".join(sorted(set(urls))[:5]),
                     "Telemetry/metrics egress to external endpoints - a "
                     "data-flow the owner should be able to name.",
                     "Confirm each destination is intended (and reachable "
                     "on air-gapped networks).",
                     question="Are the remoteWrite/telemetry egress "
                              "destinations listed in the report intended?")

    def check_routes_hosts(self):
        t = self.b.read("03-routes.txt")
        apps = yaml_grab(self.b.read("01-ingress-config.yaml") or "", "domain")
        base = yaml_grab(self.b.read("01-dns.yaml") or "", "baseDomain")
        if not t or not apps:
            return
        lines_ = t.splitlines()
        header = lines_[0]
        if "HOST/PORT" not in header:
            return
        foreign = []
        for line in lines_[1:]:
            host = col_slice(header, line, "HOST/PORT", ("PATH", "SERVICES"))
            if host and "." in host and not host.endswith(apps) \
                    and not (base and host.endswith(base)):
                foreign.append("%s (%s)" % (host, line.split()[0]))
        if foreign:
            self.add("LOW", "Security",
                     "%d route(s) claim hostnames outside the cluster's "
                     "domains" % len(foreign),
                     "03-routes.txt vs ingress domain %s: %s."
                     % (apps, "; ".join(sorted(set(foreign))[:5])),
                     "A route claiming a foreign hostname only works with "
                     "external DNS pointing here - or it is a leftover / "
                     "spoofing risk (first-claim wins inside the router).",
                     "Verify each is intentional; delete leftovers.",
                     question="Are the routes claiming hostnames outside the "
                              "cluster's domains intentional?")

    def check_naming_hygiene(self):
        test_re = re.compile(r"(^|[-_])(test\w{0,3}|tmp|temp|debug|demo|"
                             r"scratch|todelete|delete-?me|my)([-_\d]|$)",
                             re.I)
        suspects = sorted(n for n in self.profile.tenant_namespaces
                          if test_re.search(n))
        if suspects:
            self.add("LOW", "Hygiene",
                     "%d namespace(s) look like test/temporary environments"
                     % len(suspects),
                     "06-projects.txt: " + ", ".join(suspects[:8]) +
                     ("..." if len(suspects) > 8 else ""),
                     "Ad-hoc namespaces accumulate without quotas, owners or "
                     "cleanup - and often outlive their purpose by years.",
                     "Confirm owners; delete or formalize each.",
                     assumption="Matched by name keywords "
                                "(test/tmp/temp/debug/demo/...).")
        prod_re = re.compile(r"(^|[-_])pr[o]?d([-_]|$)|production", re.I)
        test_in_prod = []
        for line in self.b.lines("06-workloads-status.txt"):
            tok = line.split()
            if len(tok) >= 3 and prod_re.search(tok[1]) and \
                    re.search(r"test", tok[2], re.I):
                test_in_prod.append("%s/%s" % (tok[1], tok[2]))
        if test_in_prod:
            self.add("LOW", "Hygiene",
                     "%d 'test'-named workload(s) inside production "
                     "namespaces" % len(test_in_prod),
                     "06-workloads-status.txt: "
                     + ", ".join(sorted(set(test_in_prod))[:6]),
                     "Test workloads in prod namespaces share prod quotas, "
                     "secrets exposure and backup scope.",
                     "Move them to non-prod namespaces or delete.")
        cron = self.b.read("10-cronjobs.txt")
        if cron:
            header = cron.splitlines()[0]
            odd = []
            for line in cron.splitlines()[1:]:
                if not line.strip():
                    continue
                sched = col_slice(header, line, "SCHEDULE", ("TIMEZONE",))
                name = line.split()[1] if len(line.split()) > 1 else "?"
                ns = line.split()[0]
                if sched.strip() == "* * * * *":
                    odd.append("%s/%s runs EVERY MINUTE" % (ns, name))
                elif re.search(r"unseal|secret-sync|token-refresh", name):
                    odd.append("%s/%s (secret-handling cron)" % (ns, name))
            if odd:
                self.add("LOW", "Hygiene",
                         "%d CronJob(s) with unusual schedule or purpose"
                         % len(odd),
                         "10-cronjobs.txt: " + "; ".join(odd[:5]),
                         "Every-minute jobs generate pod churn and often "
                         "paper over a broken mechanism (e.g. auto-unseal "
                         "loops imply unseal keys stored nearby).",
                         "Review each: is the cadence justified, and where "
                         "do its credentials live?",
                         question="For the unusual CronJobs flagged: where do "
                                  "their credentials live and is the design "
                                  "intended?")

    def check_failed_jobs(self):
        """Failed platform Jobs; a wedged Job often explains a degraded CO."""
        failed = []
        for line in self.b.lines("06-jobs.txt"):
            tok = line.split()
            if len(tok) >= 4 and tok[0].startswith("openshift-") and (
                    tok[2] == "Failed" or tok[3].startswith("0/")):
                failed.append("%s/%s (%s)" % (tok[0], tok[1], tok[2]))
        if not failed:
            return
        pruner = [f for f in failed if "image-pruner" in f]
        registry_removed = yaml_grab(
            self.b.read("07-imageregistry.yaml") or "", "managementState") \
            == "Removed"
        self.add("MEDIUM", "Stability",
                 "%d failed platform Job(s)" % len(failed),
                 "06-jobs.txt: " + "; ".join(failed[:6]) +
                 ("..." if len(failed) > 6 else ""),
                 "Failed jobs in openshift-* namespaces often drive operator "
                 "Degraded conditions (check the operators' condition "
                 "messages for the job name)."
                 + (" The image-pruner job is failing although the internal "
                    "registry is Removed - it prunes nothing and only "
                    "degrades the image-registry operator."
                    if pruner and registry_removed else ""),
                 ("Suspend the pruner (imagepruner CR) or delete the failed "
                  "job, then confirm the operator recovers. "
                  if pruner and registry_removed else "")
                 + "Read each failed job's logs and fix or remove it.")

    # installed operator -> the collected file that would hold its instances
    IDLE_OPERATOR_MAP = [
        (r"loki-operator", "08-lokistack.txt", "LokiStack"),
        (r"kubernetes-nmstate|nmstate-operator", "03-nncp.yaml",
         "node network policies"),
        (r"metallb", "03-metallb.txt", "MetalLB address pools"),
        (r"odf-operator\.|ocs-operator\.", "04-storagecluster.txt",
         "StorageCluster"),
        (r"oadp-operator|redhat-oadp", "10-oadp-dpa.txt",
         "DataProtectionApplication"),
        (r"sriov-network-operator", "03-sriov.txt", "SR-IOV networks"),
        (r"gpu-operator", "12-clusterpolicy.yaml", "GPU ClusterPolicy"),
        (r"rhacs-operator|advanced-cluster-security", "07-acs-central.txt",
         "ACS Central"),
        (r"compliance-operator", "07-compliance.txt", "compliance scans"),
        (r"cluster-logging\.", "08-clusterlogging.txt", "ClusterLogging"),
        (r"openshift-gitops-operator", "09-argocd.txt", "Argo CD instance"),
        (r"openshift-pipelines-operator", "09-tektonconfig.txt",
         "TektonConfig"),
    ]

    def check_idle_operators(self):
        # match against CSV NAMES only - `oc get csv -A` repeats copied CSVs
        # in every namespace, and namespace names must not count as installs
        csv_names = " ".join(l.split()[1] for l in self.b.lines("05-csv.txt")
                             if len(l.split()) > 1)
        idle = []
        for pat, cr_file, label in self.IDLE_OPERATOR_MAP:
            m = re.search(pat, csv_names)
            if m and self.b.status(cr_file) in (S_EMPTY, S_ERR_ABSENT,
                                                S_ERR_NOTFOUND):
                idle.append("%s (no %s - %s)" % (m.group(0), label, cr_file))
        if idle:
            self.add("LOW", "Hygiene",
                     "%d operator(s) installed but with no configured "
                     "instances" % len(idle),
                     "05-csv.txt cross-referenced with instance files: "
                     + "; ".join(idle[:6]) + ("..." if len(idle) > 6 else ""),
                     "Idle operators consume memory, enlarge the upgrade "
                     "test matrix, and mislead reviewers about what the "
                     "cluster actually does.",
                     "Configure each operator or uninstall it (and its "
                     "OperatorGroup/namespace).",
                     assumption="Judged by the absence of the operator's "
                                "primary CR in the bundle; instances of "
                                "kinds the collector does not gather are "
                                "invisible.")

    def check_identity_path(self):
        """Where does login actually depend on - and does it loop?"""
        oauth = self.b.read("07-oauth.yaml") or ""
        spec = yaml_block(oauth, "spec") or oauth
        apps = yaml_grab(self.b.read("01-ingress-config.yaml") or "", "domain")
        base = yaml_grab(self.b.read("01-dns.yaml") or "", "baseDomain")
        hosts = set()
        for u in re.findall(r"(?:url|issuer):\s*(\S+)", spec):
            m = re.match(r"[a-z]+s?://([^/:?]+)", u)
            if m:
                hosts.add(m.group(1))
        fragile = False
        for h in sorted(hosts):
            if apps and h.endswith(apps):
                fragile = True
                self.add("HIGH", "Security",
                         "Identity provider is hosted on THIS cluster's own "
                         "ingress (circular dependency)",
                         "07-oauth.yaml: IdP endpoint %s is under the "
                         "cluster's apps domain %s." % (h, apps),
                         "Any ingress/worker outage also removes all "
                         "interactive login - exactly when admins need to "
                         "get in. Break-glass access must not depend on the "
                         "cluster being healthy.",
                         "Document the kubeconfig/kubeadmin break-glass "
                         "path; consider hosting SSO outside the cluster it "
                         "authenticates.")
            elif ".apps." in h and not (base and h.endswith(base)):
                fragile = True
                self.add("MEDIUM", "Security",
                         "Identity provider appears to be hosted on ANOTHER "
                         "OpenShift cluster",
                         "07-oauth.yaml: IdP endpoint %s looks like a "
                         "different cluster's apps domain." % h,
                         "Login here depends on that other cluster's "
                         "health - a cross-cluster single point of failure "
                         "for the whole estate.",
                         "Confirm the dependency direction is intended; "
                         "verify both clusters' reviews cover it.",
                         assumption="Cluster-of-origin inferred from the "
                                    "'.apps.' hostname convention.")
        idps = re.findall(r"^\s*type:\s*(\w+)\s*$", spec, re.M)
        users = len(self.b.lines("07-users.txt"))
        if idps and users == 0 and self.b.status("07-users.txt") in (
                S_OK, S_EMPTY):
            fragile = True
            self.add("MEDIUM", "Security",
                     "IdP configured but no user has ever logged in through it",
                     "07-oauth.yaml: identityProviders %s; 07-users.txt: 0 "
                     "users." % ", ".join(idps),
                     "The login path is unproven - it may be broken "
                     "(endpoint, CA, client secret) without anyone noticing.",
                     "Perform a test login; fix or remove the IdP.",
                     question="Has anyone ever logged in through the "
                              "configured IdP? What is the break-glass path "
                              "if it fails?")
        if re.search(r"mappingMethod:\s*add", spec):
            self.add("LOW", "Security",
                     "IdP mappingMethod 'add' in use",
                     "07-oauth.yaml: mappingMethod: add.",
                     "'add' merges identities from different providers into "
                     "one user when names collide - an account-takeover "
                     "vector if provider namespaces overlap.",
                     "Prefer 'claim' unless deliberate cross-provider "
                     "merging is required.")
        # identities whose IdP no longer exists in the spec
        # (the name: key may open a list item: "- name: x")
        idp_names = set(re.findall(r"^\s*-?\s*name:\s*(\S+)\s*$", spec, re.M))
        orphans = {l.split()[1] for l in self.b.lines("07-identities.txt")
                   if len(l.split()) >= 2 and idp_names
                   and l.split()[1] not in idp_names}
        if orphans:
            self.add("LOW", "Hygiene",
                     "Identities from removed identity provider(s): %s"
                     % ", ".join(sorted(orphans)[:4]),
                     "07-identities.txt references IdP name(s) absent from "
                     "07-oauth.yaml spec.",
                     "Stale identities keep old user mappings (and their "
                     "RBAC) alive after a provider is retired.",
                     "Delete the orphaned Identity/User objects after "
                     "confirming they are unused.")
        self.facts["idp_fragile"] = fragile or not idps

    def check_recent_transitions(self):
        """Incident forensics on a green snapshot: a healthy state that
        became healthy HOURS ago is a recent incident, not a clean bill."""
        now = self._collection_time()
        if now is None:
            return
        window_h = 48
        recent = []
        conds = parse_named_conditions(
            self.b.read("01-clusteroperators.yaml") or "")
        bad_cos = self.facts.get("bad_cos", set())
        for co, cl in sorted(conds.items()):
            if co in bad_cos:
                continue     # still unhealthy: covered by its own finding
            for c in cl:
                if c.get("type") not in ("Available", "Degraded",
                                         "Progressing"):
                    continue
                healthy = (c["type"] == "Available"
                           and c.get("status") == "True") or \
                    (c["type"] in ("Degraded", "Progressing")
                     and c.get("status") == "False")
                t = parse_iso_time(c.get("lastTransitionTime"))
                if healthy and t and 0 <= (now - t).total_seconds() \
                        <= window_h * 3600:
                    recent.append("%s %s->%s %sh ago"
                                  % (co, c["type"],
                                     c.get("status"),
                                     int((now - t).total_seconds() // 3600)))
        cv = self.b.read("01-clusterversion.yaml") or ""
        for c in parse_conditions(cv, all_blocks=True):
            t = parse_iso_time(c.get("lastTransitionTime"))
            if c.get("type") == "Failing" and c.get("status") == "False" \
                    and t and 0 <= (now - t).total_seconds() <= window_h * 3600:
                recent.append("ClusterVersion Failing cleared %sh ago"
                              % int((now - t).total_seconds() // 3600))
        if len(recent) >= 2:
            self.add("MEDIUM", "Stability",
                     "%d operator condition(s) transitioned within the last "
                     "%dh - a recent incident likely resolved" % (len(recent),
                                                                  window_h),
                     "01-clusteroperators.yaml lastTransitionTime: "
                     + "; ".join(recent[:8]) +
                     ("..." if len(recent) > 8 else ""),
                     "The cluster is healthy NOW, but these conditions "
                     "flipped very recently - a same-day incident leaves no "
                     "other trace in a point-in-time snapshot.",
                     "Ask what happened in this window; check metrics/logs "
                     "before they age out (see the monitoring persistence "
                     "finding if metrics are ephemeral).",
                     question="Operator conditions transitioned within the "
                              "last %dh - what happened, and is it fully "
                              "resolved?" % window_h)
        # mass-restart clustering: many pods restarted in one recent window
        cluster_age = (now - self.profile.install_date).days \
            if self.profile.install_date else None
        recency, young = [], 0
        rows = self.b.lines("06-pods-all.txt")
        for line in rows:
            tok = line.split()
            if len(tok) > 6 and tok[5].startswith("("):
                h = parse_age_days(tok[5].lstrip("(")) * 24
                if h <= window_h:
                    recency.append(h)
            age_col = tok[7] if len(tok) > 7 and tok[5].startswith("(") else \
                (tok[5] if len(tok) > 5 else "")
            if parse_age_days(age_col) < 1:
                young += 1
        if len(recency) >= 10:
            self.add("MEDIUM", "Stability",
                     "%d pod(s) restarted within the last %dh (mass-restart "
                     "signature)" % (len(recency), window_h),
                     "06-pods-all.txt RESTARTS recency: restarts cluster "
                     "between ~%dh and ~%dh ago."
                     % (min(recency), max(recency)),
                     "Synchronized restarts point at a node reboot, network "
                     "blip or control-plane event in that window.",
                     "Correlate with the condition transitions above and "
                     "with 11-events-warning.txt.")
        if cluster_age and cluster_age > 30 and rows \
                and young / len(rows) > 0.3:
            self.add("MEDIUM", "Stability",
                     "%d%% of pods are younger than 24h on a %d-day-old "
                     "cluster" % (100 * young // len(rows), cluster_age),
                     "06-pods-all.txt AGE column vs install date.",
                     "Mass pod recreation - node reboot, drain, or upgrade - "
                     "happened within the last day.",
                     "Confirm what maintenance/incident occurred; verify "
                     "stateful workloads came back consistent.")

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
        # user-referenced certs MISSING from the expiry report are the ones
        # most likely to be manually managed - and to expire unnoticed
        referenced = set()
        ic = self.b.read("03-ingresscontroller.yaml") or ""
        m = re.search(r"defaultCertificate:\s*\n\s*name:\s*(\S+)", ic)
        if m:
            referenced.add((m.group(1), "IngressController "
                            "defaultCertificate"))
        apisrv = self.b.read("01-apiserver.yaml") or ""
        for m in re.finditer(r"servingCertificate:\s*\n\s*name:\s*(\S+)",
                             apisrv):
            referenced.add((m.group(1), "APIServer namedCertificate"))
        expiry_named = {l.split()[1]: (l.split() + ["", ""])[2]
                        for l in rows if l.split()}
        unobservable = ["%s (%s)" % (name, role)
                        for name, role in sorted(referenced)
                        if expiry_named.get(name, "<none>") in ("<none>", "")]
        if unobservable:
            cert_mgr = self.b.status("07-certificates.txt") == S_OK
            expiry_src = ("no certificate-not-after annotation in "
                          "07-cert-expiry.txt"
                          if self.b.status("07-cert-expiry.txt") == S_OK else
                          "07-cert-expiry.txt was not collected (older "
                          "bundle)")
            self.add("MEDIUM", "Security",
                     "%d user-supplied certificate(s) with UNOBSERVABLE "
                     "expiry" % len(unobservable),
                     "Referenced by config but %s: " % expiry_src
                     + "; ".join(unobservable)
                     + (". cert-manager Certificates exist "
                        "(07-certificates.txt) - renewal may be handled."
                        if cert_mgr else
                        ". No cert-manager CRs visible to renew them."),
                     "Exactly the certs most likely to be manually managed "
                     "(console/API/all routes break at once when the "
                     "ingress default cert expires) - and this review "
                     "cannot see their dates.",
                     "Check their expiry live (`openssl x509 -enddate`) and "
                     "put renewal under cert-manager or a calendar process.")
        now = self._collection_time()
        if not rows or now is None:
            return
        soon, rotated = [], []
        for line in rows:
            tok = line.split()
            if len(tok) < 3 or tok[2] in ("<none>", ""):
                continue
            try:
                exp = datetime.strptime(tok[2], "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
            days = (exp - now).days
            if days > 90:
                continue
            # ISSUER column (v2 collector) or namespace tells rotation class:
            # platform-signer leaf certs are short-lived BY DESIGN and
            # auto-rotated - only manually managed certs deserve escalation
            issuer = tok[3] if len(tok) > 3 else ""
            auto = bool(AUTOROTATED_ISSUER_RE.search(issuer)
                        or (not issuer and re.match(
                            r"openshift-(kube-|etcd|config-managed|"
                            r"service-ca|machine-config|oauth-apiserver|"
                            r"apiserver$|authentication)", tok[0])))
            (rotated if auto else soon).append(
                (days, "%s/%s (%dd)" % (tok[0], tok[1], days)))
        base_assumption = ("Days counted from the bundle collection time "
                           "(%s), not today; expiry read from the "
                           "auth.openshift.io/certificate-not-after "
                           "annotation (no key material)."
                           % now.strftime("%Y-%m-%d"))
        if rotated:
            rotated.sort()
            rot_owner_bad = sorted(self.facts.get("bad_cos", set()) &
                                   {"kube-apiserver", "kube-controller-manager",
                                    "etcd"})
            self.add("HIGH" if rot_owner_bad else "LOW", "Security",
                     "%d auto-rotated platform certificate(s) in their "
                     "normal renewal window" % len(rotated),
                     "07-cert-expiry.txt: " +
                     ", ".join(s for _, s in rotated[:6]) +
                     ("..." if len(rotated) > 6 else "")
                     + (" ROTATION AT RISK: the rotating operator(s) %s are "
                        "currently unhealthy." % ", ".join(rot_owner_bad)
                        if rot_owner_bad else ""),
                     "Platform-signer leaf certs are short-lived by design; "
                     "the risk is only a STALLED rotation (unhealthy owning "
                     "operator) or, on SNO, a node powered off across the "
                     "rotation window waking with expired certs.",
                     "Verify the kube-apiserver/kube-controller-manager "
                     "operators are healthy so rotation advances; no manual "
                     "renewal needed.",
                     assumption=base_assumption + " Rotation class inferred "
                                "from the ISSUER column / namespace.")
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
                     assumption=base_assumption)

    # order matters: nodes (outage root) before its cascade consumers;
    # backup before storage/monitoring (composite findings read its facts);
    # identity_path before security (kubeadmin advice gating)
    ALL_CHECKS = [
        check_meta, check_access, check_version, check_clusterversion,
        check_upgrade_posture, check_nodes, check_node_pressure,
        check_clusteroperators, check_recent_transitions,
        check_topology_spread, check_csr, check_mcp,
        check_pods, check_workload_status, check_failed_jobs,
        check_etcd_backup, check_etcd_health,
        check_storage, check_olm, check_idle_operators, check_tenancy,
        check_naming_hygiene, check_pdb_webhooks, check_identity_path,
        check_security, check_acm_policies, check_cert_expiry, check_network,
        check_routes_hosts, check_nncp, check_whereabouts,
        check_ovnkube_coverage, check_monitoring, check_prom_am,
        check_egress_targets, check_events,
        check_gpu, check_identity_facts, check_infra_facts,
        check_data_availability,
    ]

    def run(self):
        for chk in self.ALL_CHECKS:
            self._check = chk.__name__
            try:
                chk(self)
            except Exception as exc:                        # noqa: BLE001
                self.add("INFO", "Analyzer",
                         "Check %s failed on this bundle" % chk.__name__,
                         "internal error: %r" % exc,
                         "A malformed/unexpected file layout; that area was "
                         "not analyzed.",
                         "Review the corresponding files manually.")
        # cascade consolidation: point the outage root at its symptom count
        n_casc = sum(1 for f in self.findings if f.get("cascade"))
        if n_casc:
            for f in self.findings:
                if "node(s) not Ready" in f["title"]:
                    f["evidence"] += (" %d further finding(s) below are "
                                      "tagged as likely cascade effects of "
                                      "this outage." % n_casc)
                    break
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
    L.append("| Topology | control plane: %s, workers: %s |"
             % (a.profile.cp_topology, a.profile.infra_topology))
    L.append("| Connectivity | %s |"
             % ("disconnected (cannot reach update graph)"
                if a.profile.disconnected else
                "connected, image mirrors configured" if a.profile.mirrored
                else "connected (no mirror/proxy signals)"))
    L.append("| Release image mirror | %s |" % f.get("release_mirror", "-"))
    L.append("| Internal image registry | %s |" % f.get("registry_state", "?"))
    L.append("| etcd encryption | %s |" % f.get("etcd_encryption", "?"))
    if f.get("install_date"):
        L.append("| Installed | %s |" % f["install_date"])
    hist = f.get("version_history") or []
    if hist:
        L.append("| Update history | %s |" % " → ".join(reversed(hist[:12])))
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
        L.append("- Projects: %d (tenant namespaces: %s) | with "
                 "ResourceQuota: %d | with LimitRange: %d | with "
                 "NetworkPolicy: %d"
                 % (tot, f.get("tenant_namespaces", "?"), rq, lr, np_))
    L.append("")
    da = f.get("data_availability")
    if da:
        L.append("## Data availability")
        L.append("")
        L.append("- Features verified ABSENT (resource type not on the "
                 "cluster): %d file(s)" % len(da["verified_absent"]))
        if da["not_configured"]:
            L.append("- Optional config objects not present (defaults in "
                     "effect): %s" % ", ".join(da["not_configured"]))
        if da["failed"]:
            L.append("- **Collections FAILED (data unknown - blind spots):** "
                     "%s" % ", ".join(da["failed"]))
        L.append("")
    return "\n".join(L) + "\n"


def render_issues(a, bundle_name, prev_diff=None):
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
    L.append("> Every finding cites the bundle file it came from (the "
             "'Evidence file reference' appendix maps files to the `oc` "
             "commands that produced them). Findings marked with an "
             "**Assumption** are heuristic - verify them before presenting "
             "to the customer. This offline analyzer CANNOT check: Red Hat "
             "lifecycle/CVE status, etcd latency metrics, Ceph internal "
             "health, or anything inside Secrets. See "
             "manual-review-guide.md and attention-points.md.")
    L.append("")
    L.append("**Calibration:** %s." % a.profile.describe())
    L.append("")
    # top priorities: the first CRITICAL/HIGH findings, cascade children
    # excluded (their root already ranks)
    top = [(i + 1, f) for i, f in enumerate(a.findings)
           if f["sev"] in ("CRITICAL", "HIGH") and not f.get("cascade")][:5]
    if top:
        L.append("## Top priorities")
        L.append("")
        for rank, (n, f) in enumerate(top, 1):
            L.append("%d. **#%d %s** (%s)" % (rank, n, f["title"], f["sev"]))
        L.append("")
    if prev_diff:
        L.append("## Changes since previous run")
        L.append("")
        for label, items in (("New", prev_diff["new"]),
                             ("Resolved", prev_diff["resolved"]),
                             ("Severity changed", prev_diff["changed"])):
            if items:
                L.append("- **%s (%d):** %s" % (label, len(items),
                                                "; ".join(items[:8])
                                                + ("..." if len(items) > 8
                                                   else "")))
        if not any(prev_diff.values()):
            L.append("- No changes vs the previous run.")
        L.append("")
    cur = None
    idx = 0
    files_cited = set()
    for f in a.findings:
        if f["sev"] != cur:
            cur = f["sev"]
            L.append("## %s" % cur)
            L.append("")
        idx += 1
        files_cited.update(re.findall(r"\b(\d{2}-[\w.-]+?\.(?:txt|yaml|json))",
                                      f["evidence"]))
        L.append("### %d. %s  `[%s]`" % (idx, f["title"], f["area"]))
        L.append("")
        if f.get("cascade"):
            L.append("- **Cascade:** likely a downstream symptom of the "
                     "node outage (see the 'not Ready' finding) - re-assess "
                     "after recovery.")
        L.append("- **Evidence:** %s" % f["evidence"])
        L.append("- **Risk:** %s" % f["risk"])
        L.append("- **Recommendation:** %s" % f["rec"])
        if f["assumption"]:
            L.append("- **Assumption:** %s" % f["assumption"])
        L.append("")
    if a.greens:
        L.append("## Verified healthy")
        L.append("")
        L.append("Positive assertions, each backed by bundle data (absence "
                 "of a finding above does NOT imply health - this list "
                 "does):")
        L.append("")
        for area, statement in a.greens:
            L.append("- `[%s]` %s" % (area, statement))
        L.append("")
    if a.suppressed:
        L.append("## Suppressed by topology calibration")
        L.append("")
        L.append("The following would be findings on a standard HA cluster "
                 "but are inherent to this cluster's topology:")
        L.append("")
        for title, reason in a.suppressed:
            L.append("- %s - *%s*" % (title, reason))
        L.append("")
    L.append("## Global assumptions & limitations")
    L.append("")
    for s in a.assumptions:
        L.append("- %s" % s)
    L.append("")
    for _area, statement in a.greens:
        files_cited.update(re.findall(r"\b(\d{2}-[\w.-]+?\.(?:txt|yaml|json))",
                                      statement))
    cited = sorted(f for f in files_cited if f in FILE_COMMANDS)
    if cited:
        L.append("## Evidence file reference")
        L.append("")
        L.append("| File | Command |")
        L.append("|---|---|")
        for f in cited:
            L.append("| %s | `%s` |" % (f, FILE_COMMANDS[f]))
        L.append("")
    return "\n".join(L) + "\n"


def render_attention(a, bundle_name):
    """Reviewer-facing, bundle-specific notes (not for the customer)."""
    L = []
    L.append("# Attention Points (reviewer-internal, auto-generated)")
    L.append("")
    L.append("*Bundle:* `%s` - analyzer %s. Internal notes: collection "
             "anomalies, unverifiable items, and questions to ask the "
             "customer. Not part of the customer-facing deliverable."
             % (bundle_name, TOOLKIT_VERSION))
    L.append("")
    # data freshness
    coll = a._collection_time()
    if coll:
        age = (datetime.now() - coll).days
        L.append("## Data freshness")
        L.append("")
        L.append("- Collected %s (%d day(s) before this analysis).%s"
                 % (coll.strftime("%Y-%m-%d %H:%M"), age,
                    " **Older than 14 days - recommend a fresh collection "
                    "before presenting.**" if age > 14 else ""))
        L.append("")
    # collection anomalies
    L.append("## Collection anomalies")
    L.append("")
    da = a.facts.get("data_availability") or {}
    anomalies = []
    if a.facts.get("collector") and "admin" in a.facts["collector"]:
        anomalies.append("Collected as `%s` - not a least-privilege audit "
                         "account (see the write-permissions finding, if "
                         "raised)." % a.facts["collector"])
    for f in da.get("failed", []):
        anomalies.append("`%s` FAILED to collect - that data is unknown."
                         % f)
    if a.facts.get("bundle_format", BUNDLE_FORMAT) > BUNDLE_FORMAT:
        anomalies.append("Bundle format is newer than this analyzer.")
    if not a.facts.get("collector_version") or \
            "unknown" in str(a.facts.get("collector_version")):
        anomalies.append("Pre-versioning collector (old bundle layout); "
                         "some checks may have skipped silently - see "
                         "MISSING notes in manual-review-guide.md.")
    for line in anomalies or ["- none detected"]:
        L.append("- %s" % line if not line.startswith("-") else line)
    L.append("")
    # secret-shaped content scan (defense in depth after 41ab1f5)
    leaks = []
    if a.b.path.is_dir():
        for p in sorted(a.b.path.iterdir()):
            if p.suffix not in (".yaml", ".txt", ".json") or \
                    p.stat().st_size > 1024 * 1024:
                continue
            t = p.read_text(errors="replace")
            if re.search(r"(clientSecret|bindPassword|password|token):\s*"
                         r"[A-Za-z0-9+/=_-]{12,}\s*$", t, re.M):
                leaks.append(p.name)
    L.append("## Confidentiality")
    L.append("")
    if leaks:
        L.append("- **Possible secret material in:** %s - inspect and "
                 "redact before sharing; rotate if the bundle traveled."
                 % ", ".join(leaks[:6]))
    L.append("- The bundle contains real hostnames, usernames and the full "
             "route inventory. Run `sanitize-ocp-bundle.py` before sharing "
             "beyond the account team.")
    L.append("")
    # unverifiable / heuristic findings
    hedged = [(f["title"], f["assumption"]) for f in a.findings
              if f.get("assumption")]
    if hedged:
        L.append("## Verify before presenting (heuristic findings)")
        L.append("")
        for title, assumption in hedged:
            L.append("- **%s** - %s" % (title, assumption))
        L.append("")
    # customer questions
    if a.questions:
        L.append("## Questions for the customer")
        L.append("")
        for i, q in enumerate(dict.fromkeys(a.questions), 1):
            L.append("%d. %s" % (i, q))
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
    ap.add_argument("--prev", metavar="DIR",
                    help="previous analysis output dir (reads its "
                         "findings.json and reports new/resolved/changed "
                         "findings)")
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

    # cross-run diff: match findings on their stable rule ids
    prev_diff = None
    if args.prev:
        prev_file = Path(args.prev) / "findings.json"
        try:
            prev = json.loads(prev_file.read_text())
            old = {f["id"]: f for f in prev.get("findings", [])}
            new = {f["id"]: f for f in a.findings}
            prev_diff = {
                "new": sorted(new[i]["title"] for i in new.keys() - old.keys()),
                "resolved": sorted(old[i]["title"]
                                   for i in old.keys() - new.keys()),
                "changed": sorted("%s (%s -> %s)" %
                                  (new[i]["title"], old[i]["sev"],
                                   new[i]["sev"])
                                  for i in new.keys() & old.keys()
                                  if old[i]["sev"] != new[i]["sev"]),
            }
        except (OSError, ValueError) as exc:
            print("warning: cannot diff against %s: %s" % (prev_file, exc),
                  file=sys.stderr)

    reports = {
        "architecture-overview.md": render_overview(a, bdir.name),
        "issues.md": render_issues(a, bdir.name, prev_diff),
        "manual-review-guide.md": render_guide(a, bdir.name),
        "attention-points.md": render_attention(a, bdir.name),
    }
    for name, text in reports.items():
        (outdir / name).write_text(text)
    coll = a._collection_time()
    (outdir / "findings.json").write_text(json.dumps({
        "analyzer": TOOLKIT_VERSION,
        "knowledge": BUILD_KNOWLEDGE_DATE,
        "bundle": bdir.name,
        "collected": coll.strftime("%Y-%m-%dT%H:%M:%SZ") if coll else None,
        "profile": a.profile.describe(),
        "findings": a.findings,
        "suppressed": a.suppressed,
        "verified_healthy": a.greens,
        "questions": list(dict.fromkeys(a.questions)),
    }, indent=1) + "\n")

    counts = {}
    for f in a.findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    print("analyzer        : %s (knowledge %s)"
          % (TOOLKIT_VERSION, BUILD_KNOWLEDGE_DATE))
    print("analyzed bundle : %s (collector %s)"
          % (bdir, a.facts.get("collector_version", "?")))
    print("findings        : " + (", ".join(
        "%s=%d" % (s, counts[s]) for s in SEV_ORDER if s in counts) or "none"))
    if prev_diff:
        print("vs previous run : new=%d resolved=%d severity-changed=%d"
              % (len(prev_diff["new"]), len(prev_diff["resolved"]),
                 len(prev_diff["changed"])))
    print("reports written : %s" % outdir)
    for name in list(reports) + ["findings.json"]:
        print("   - %s" % name)


if __name__ == "__main__":
    main()
