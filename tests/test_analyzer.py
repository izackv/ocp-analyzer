#!/usr/bin/env python3
"""Unit tests for ocp_analyzer.py (Phase 0 bug fixes + Phase 1 foundations).

All fixtures are synthetic - no customer-derived strings may appear here.

    python3 -m unittest discover tests
"""
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ocp_analyzer",
                                              REPO / "ocp_analyzer.py")
oa = importlib.util.module_from_spec(spec)
sys.modules["ocp_analyzer"] = oa
spec.loader.exec_module(oa)


ACCESS_YES = """## whoami
system:admin
## server
https://api.example.test:6443
## can-i get nodes
Warning: resource 'nodes' is not namespace scoped

yes
## can-i create clusterrolebindings (MUST be 'no' for a proper read-only audit account)
Warning: resource 'clusterrolebindings' is not namespace scoped in group 'rbac.authorization.k8s.io'

yes
"""

CLUSTERVERSION = """apiVersion: v1
items:
- apiVersion: config.openshift.io/v1
  kind: ClusterVersion
  metadata:
    name: version
  spec:
    channel: stable-4.18
    clusterID: 00000000-0000-0000-0000-000000000000
  status:
    availableUpdates:
    - image: registry.example.test/release@sha256:aaa
      version: 4.18.47
    - image: registry.example.test/release@sha256:bbb
      version: 4.18.46
    conditions:
    - lastTransitionTime: "2026-07-10T07:49:13Z"
      message: Kubernetes 1.32 and therefore OpenShift 4.19 remove several APIs
        which require admin consideration.
      reason: AdminAckRequired
      status: "False"
      type: Upgradeable
    desired:
      version: 4.18.35
    history:
    - completionTime: "2026-07-10T08:17:34Z"
      image: registry.example.test/release@sha256:ccc
      startedTime: "2026-07-10T07:49:13Z"
      state: Completed
      verified: false
      version: 4.18.35
kind: List
"""

OAUTH_ANNOTATION_ONLY = """apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"spec":{"identityProviders":[{"ldap":{"insecure":true,"url":"ldap://old.example.test"}}]}}
  name: cluster
spec:
  identityProviders:
  - name: corp-sso
    type: OpenID
"""

OAUTH_ACTIVE_INSECURE = """apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - ldap:
      insecure: true
      url: ldap://dir.example.test
    name: corp-ldap
    type: LDAP
"""

SCC_TXT = """NAME                PRIV    CAPS                          SELINUX     RUNASUSER        FSGROUP     SUPGROUP    PRIORITY     READONLYROOTFS   VOLUMES
restricted          false   <no value>                    MustRunAs   MustRunAsRange   MustRunAs   RunAsAny    <no value>   false            ["configMap","secret"]
privileged          true    ["*"]                         RunAsAny    RunAsAny         RunAsAny    RunAsAny    <no value>   false            ["*"]
agent-scc           false   ["NET_ADMIN","SYS_ADMIN"]     RunAsAny    RunAsAny        RunAsAny    RunAsAny    <no value>   false            ["*"]
lvms-vgmanager      true    <no value>                    RunAsAny    RunAsAny        RunAsAny    RunAsAny    <no value>   false            ["configMap","hostPath","secret"]
quiet-scc           false   <no value>                    MustRunAs   MustRunAsRange  MustRunAs   RunAsAny    <no value>   false            ["configMap","secret"]
"""

CRB_TXT = """NAME                                     ROLE                        AGE
cluster-admin                            ClusterRole/cluster-admin   400d
cluster-version-operator                 ClusterRole/cluster-admin   400d
cluster-network-operator                 ClusterRole/cluster-admin   400d
system:openshift:operator:etcd-operator  ClusterRole/cluster-admin   400d
backup-tool-admin                        ClusterRole/cluster-admin   200d
must-gather-abc12                        ClusterRole/cluster-admin   90d
"""

CERT_EXPIRY = """NS                             NAME                        NOT-AFTER              ISSUER
openshift-kube-apiserver       platform-leaf-cert          2026-01-20T00:00:00Z   kube-control-plane-signer
openshift-ingress              custom-router-cert          2026-01-25T00:00:00Z   corp-issuing-ca
"""


def make_bundle(tmp, files):
    b = Path(tmp) / "ocp-review_test_20260101-000000"
    b.mkdir(exist_ok=True)
    for name, content in files.items():
        (b / name).write_text(content)
    return b


def analyzer(tmp, files):
    return oa.Analyzer(oa.Bundle(make_bundle(tmp, files)))


def titles(a):
    return [f["title"] for f in a.findings]


SNO_INFRA = "status:\n  controlPlaneTopology: SingleReplica\n" \
            "  infrastructureTopology: SingleReplica\n  platform: None\n"
HA_INFRA = "status:\n  controlPlaneTopology: HighlyAvailable\n" \
           "  infrastructureTopology: HighlyAvailable\n  platform: BareMetal\n"


class TestAccessCheck(unittest.TestCase):
    def test_yes_with_warning_and_blank_lines_fires(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"00-access.txt": ACCESS_YES})
            a.check_access()
            self.assertTrue(any("write permissions" in x for x in titles(a)))

    def test_no_answer_stays_silent(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"00-access.txt":
                             ACCESS_YES.replace(
                                 "'rbac.authorization.k8s.io'\n\nyes",
                                 "'rbac.authorization.k8s.io'\n\nno")})
            a.check_access()
            self.assertFalse(any("write permissions" in x for x in titles(a)))


class TestClusterVersion(unittest.TestCase):
    def test_history_not_polluted_by_available_updates(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-clusterversion.yaml": CLUSTERVERSION})
            a.check_clusterversion()
            self.assertEqual(a.facts["version_history"], ["4.18.35"])
            self.assertEqual(a.facts["install_date"], "2026-07-10")

    def test_parse_conditions(self):
        conds = oa.parse_conditions(CLUSTERVERSION)
        self.assertEqual(len(conds), 1)
        c = conds[0]
        self.assertEqual(c["type"], "Upgradeable")
        self.assertEqual(c["status"], "False")
        self.assertEqual(c["reason"], "AdminAckRequired")
        self.assertIn("admin consideration", c["message"])  # folded line joined


class TestBundleStatus(unittest.TestCase):
    def test_tri_state(self):
        with tempfile.TemporaryDirectory() as t:
            b = make_bundle(t, {
                "04-pv.txt": "NAME CAP\npv1 1Gi\n",
                "06-hpa.txt": "(empty result)\n",
                "10-oadp-dpa.txt.err":
                    'error: the server doesn\'t have a resource type "dpa"\n',
                "08-cluster-monitoring.yaml.err":
                    'Error from server (NotFound): configmaps '
                    '"cluster-monitoring-config" not found\n',
                "08-active-alerts.json.err":
                    "Error from server (BadRequest): the server rejected our "
                    "request for an unknown reason\n",
            })
            bd = oa.Bundle(b)
            self.assertEqual(bd.status("04-pv.txt"), oa.S_OK)
            self.assertEqual(bd.status("06-hpa.txt"), oa.S_EMPTY)
            self.assertEqual(bd.status("10-oadp-dpa.txt"), oa.S_ERR_ABSENT)
            self.assertEqual(bd.status("08-cluster-monitoring.yaml"),
                             oa.S_ERR_NOTFOUND)
            self.assertEqual(bd.status("08-active-alerts.json"),
                             oa.S_ERR_FAILED)
            self.assertEqual(bd.status("99-never-collected.txt"), oa.S_MISSING)

    def test_failed_collection_becomes_blind_spot_finding(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"08-active-alerts.json.err":
                             "Error from server (BadRequest): rejected\n"})
            a.check_data_availability()
            self.assertTrue(any("FAILED" in x for x in titles(a)))
            self.assertIn("08-active-alerts.json",
                          a.facts["data_availability"]["failed"])


class TestMonitoring(unittest.TestCase):
    def test_absent_configmap_means_ephemeral_finding_and_honest_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "08-cluster-monitoring.yaml.err":
                    'Error from server (NotFound): configmaps '
                    '"cluster-monitoring-config" not found\n',
                "04-pvc.txt": "NAMESPACE NAME STATUS\napp1 data Bound\n",
            })
            a.check_monitoring()
            self.assertTrue(any("ephemeral" in x for x in titles(a)))
            verify = next(f for f in a.findings if "reach a human" in f["title"])
            self.assertNotIn("08-cluster-monitoring.yaml: additional",
                             verify["evidence"])

    def test_present_configmap_keeps_forwarding_logic(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"08-cluster-monitoring.yaml":
                             "data:\n  config.yaml: |\n"
                             "    additionalAlertmanagerConfigs: [x]\n"})
            a.check_monitoring()
            self.assertTrue(a.facts["alert_forwarding"])
            self.assertFalse(any("ephemeral" in x for x in titles(a)))


class TestOAuthSpecScoping(unittest.TestCase):
    def test_annotation_only_insecure_is_downgraded_to_historical(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-oauth.yaml": OAUTH_ANNOTATION_ONLY})
            a.check_security()
            self.assertFalse(any("without TLS" in x for x in titles(a)))
            self.assertTrue(any("Historical" in x for x in titles(a)))

    def test_active_insecure_still_high(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-oauth.yaml": OAUTH_ACTIVE_INSECURE})
            a.check_security()
            f = next(f for f in a.findings if "without TLS" in f["title"])
            self.assertEqual(f["sev"], "HIGH")

    def test_idp_facts_from_spec_only(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-oauth.yaml": OAUTH_ANNOTATION_ONLY})
            a.check_identity_facts()
            self.assertEqual(a.facts["idps"], ["OpenID"])


class TestSCCScoring(unittest.TestCase):
    def test_dangerous_caps_flagged_even_without_priv(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-scc.txt": SCC_TXT, "05-csv.txt":
                             "NAME\nlvms-operator.v4.18.0  Succeeded\n"})
            a.check_security()
            risky = next(f for f in a.findings
                         if "not attributable" in f["title"])
            self.assertIn("agent-scc", risky["evidence"])
            self.assertEqual(risky["sev"], "HIGH")
            # stock + harmless SCCs never flagged
            self.assertNotIn("privileged", risky["evidence"])
            self.assertNotIn("quiet-scc", risky["evidence"])
            # operator-owned SCC attributed, not alarmed
            owned = next(f for f in a.findings
                         if "operator-owned" in f["title"])
            self.assertIn("lvms-vgmanager", owned["evidence"])
            self.assertEqual(owned["sev"], "LOW")


class TestCRBWhitelist(unittest.TestCase):
    def test_stock_bindings_not_flagged_custom_ones_are(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-clusterrolebindings.txt": CRB_TXT})
            a.check_security()
            f = next(f for f in a.findings if "non-default" in f["title"])
            self.assertIn("backup-tool-admin", f["evidence"])
            self.assertNotIn("cluster-version-operator", f["evidence"])
            self.assertNotIn("cluster-network-operator", f["evidence"])
            self.assertEqual(f["sev"], "MEDIUM")  # 1 custom, not >5
            self.assertTrue(any("must-gather" in x for x in titles(a)))


class TestTopologyCalibration(unittest.TestCase):
    def test_sno_suppresses_ingress_and_escalates_backup(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "01-infrastructure.yaml": SNO_INFRA,
                "03-ingresscontroller.yaml": "spec:\n  replicas: 1\n",
                "06-projects.txt": "NAME\ndefault\nopenshift-monitoring\n",
            })
            self.assertTrue(a.profile.sno)
            a.check_network()
            self.assertFalse(any("<2 replicas" in x for x in titles(a)))
            self.assertTrue(any("<2 replicas" in s for s, _ in a.suppressed))
            a.check_etcd_backup()
            backup = next(f for f in a.findings
                          if "No backup tooling" in f["title"])
            self.assertEqual(backup["sev"], "HIGH")  # no PVs = nothing stateful
            # with stateful data present it escalates
            (Path(t) / "ocp-review_test_20260101-000000" / "04-pv.txt").write_text(
                "NAME CAP MODE RECLAIM STATUS CLAIM SC\n"
                "pv1 5Gi RWO Delete Bound app/pg lvms-vg1\n")
            a2 = oa.Analyzer(oa.Bundle(
                Path(t) / "ocp-review_test_20260101-000000"))
            a2.check_etcd_backup()
            b2 = next(f for f in a2.findings
                      if "No backup tooling" in f["title"])
            self.assertEqual(b2["sev"], "CRITICAL")

    def test_ha_keeps_ingress_finding_and_high_backup(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "01-infrastructure.yaml": HA_INFRA,
                "03-ingresscontroller.yaml": "spec:\n  replicas: 1\n",
            })
            a.check_network()
            self.assertTrue(any("<2 replicas" in x for x in titles(a)))
            a.check_etcd_backup()
            backup = next(f for f in a.findings
                          if "No backup tooling" in f["title"])
            self.assertEqual(backup["sev"], "HIGH")

    def test_tenancy_reframed_when_no_tenants(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "01-infrastructure.yaml": SNO_INFRA,
                "06-projects.txt": "NAME\n" + "\n".join(
                    "openshift-ns%d" % i for i in range(30)) + "\n",
            })
            a.check_tenancy()
            self.assertFalse(any("cover only" in x for x in titles(a)))
            self.assertTrue(any("No tenant namespaces" in x for x in titles(a)))


class TestCertTaxonomy(unittest.TestCase):
    def test_autorotated_split_from_manual(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-cert-expiry.txt": CERT_EXPIRY})
            a.check_cert_expiry()
            auto = next(f for f in a.findings if "auto-rotated" in f["title"])
            self.assertEqual(auto["sev"], "LOW")
            self.assertIn("platform-leaf-cert", auto["evidence"])
            manual = next(f for f in a.findings
                          if "expiring within" in f["title"])
            self.assertIn("custom-router-cert", manual["evidence"])
            self.assertNotIn("platform-leaf-cert", manual["evidence"])


class TestOneShotPods(unittest.TestCase):
    def test_installer_error_pods_not_counted(self):
        pods = ("NAMESPACE NAME READY STATUS RESTARTS AGE\n"
                "openshift-etcd installer-4-node1 0/1 Error 0 100d\n"
                "openshift-etcd revision-pruner-4-node1 0/1 Error 0 100d\n"
                "app1 worker-1 0/1 Error 3 5d\n")
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"06-pods-all.txt": pods})
            a.check_pods()
            f = next(f for f in a.findings if "CrashLoopBackOff/Error" in f["title"])
            self.assertIn("Error=1", f["evidence"])  # only the real one


UPGRADE_TXT = """Cluster version is 4.18.26

Upgradeable=False

  Reason: AdminAckRequired
  Message: Kubernetes 1.32 removes several APIs.

Recommended updates:

  VERSION     IMAGE
  4.18.47     registry.example.test/release@sha256:aaa
  4.18.46     registry.example.test/release@sha256:bbb
  4.18.45     registry.example.test/release@sha256:ccc
  4.18.44     registry.example.test/release@sha256:ddd
  4.18.43     registry.example.test/release@sha256:eee
  4.18.42     registry.example.test/release@sha256:fff
"""

CV_WITH_NESTED_CONDITIONS = """apiVersion: v1
items:
- apiVersion: config.openshift.io/v1
  kind: ClusterVersion
  status:
    availableUpdates:
    - image: registry.example.test/release@sha256:new
      url: https://errata.example.test/RHSA-2026:9999
      version: 4.16.10
    conditionalUpdates:
    - conditions:
      - lastTransitionTime: "2025-01-01T00:00:00Z"
        message: risk applies
        reason: SomeRisk
        status: "False"
        type: Recommended
    conditions:
    - lastTransitionTime: "2025-01-01T00:00:00Z"
      message: cannot reconcile payload
      reason: WorkloadNotAvailable
      status: "True"
      type: Failing
    desired:
      url: https://errata.example.test/RHSA-2026:1234
      version: 4.18.35
    history:
    - completionTime: "2024-06-01T08:00:00Z"
      state: Completed
      version: 4.16.9
    - completionTime: "2023-01-01T08:00:00Z"
      state: Completed
      version: 4.14.2
kind: List
"""

EVENTS_TXT = """NAMESPACE   LAST SEEN   TYPE      REASON             OBJECT              MESSAGE
app1        10m         Warning   OOMKilling         node/worker-1       Memory cgroup out of memory: OOMKilled process
app2        20m         Warning   FailedScheduling   pod/web-1           0/6 nodes are available: Insufficient cpu
app2        25m         Warning   FailedScheduling   pod/web-2           0/6 nodes are available: Insufficient cpu
app2        30m         Warning   FailedScheduling   pod/web-3           0/6 nodes are available: Insufficient cpu
openshift-etcd  5m      Warning   EtcdLeaderChangeMetrics   pod/etcd-m1  leader changed, disk fsync took 38 ms
"""

SUBS_TXT = """NS       NAME          CHANNEL   SOURCE               APPROVAL    CSV            STATE
ns1      good-op       stable-1  redhat-operators     Automatic   good-op.v1.0   AtLatestKnown
ns2      floaty-op     latest    community-operators  Automatic   floaty.v2.0    AtLatestKnown
"""

INSTALLPLAN_TXT = """NAMESPACE   NAME          CSV                APPROVAL   APPROVED
ns1         install-aaa   pg-operator.v5.8.1   Manual   false
ns1         install-bbb   pg-operator.v5.8.2   Manual   false
ns1         install-ccc   pg-operator.v5.8.3   Manual   false
ns2         install-ddd   other-op.v1.2.0      Manual   false
"""


class TestUpgradePosture(unittest.TestCase):
    def test_upgradeable_false_and_failing_from_nested_yaml(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-clusterversion.yaml": CLUSTERVERSION})
            a.check_upgrade_posture()
            up = next(f for f in a.findings if "Upgradeable=False" in f["title"])
            self.assertIn("AdminAckRequired", up["title"])
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-clusterversion.yaml":
                             CV_WITH_NESTED_CONDITIONS})
            a.check_upgrade_posture()
            self.assertTrue(any("Failing" in x for x in titles(a)))
            # nested conditionalUpdates condition must not shadow Failing
            self.assertFalse(any("Recommended" in x for x in titles(a)))

    def test_staleness_and_cadence_gap(self):
        # bundle collected 2026-01-01; last update 2024-06-01 => very stale
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-clusterversion.yaml":
                             CV_WITH_NESTED_CONDITIONS})
            a.check_upgrade_posture()
            stale = next(f for f in a.findings if "No update applied" in f["title"])
            self.assertEqual(stale["sev"], "HIGH")
            self.assertTrue(any("longer than a year" in x for x in titles(a)))

    def test_pending_updates_with_rhsa(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-upgrade.txt": UPGRADE_TXT,
                             "01-clusterversion.yaml":
                                 CV_WITH_NESTED_CONDITIONS})
            a.check_upgrade_posture()
            f = next(f for f in a.findings if "z-stream update" in f["title"])
            self.assertIn("6 recommended", f["title"])
            self.assertIn("1 security", f["title"])


class TestEvents(unittest.TestCase):
    def test_patterns_detected(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"11-events-warning.txt": EVENTS_TXT})
            a.check_events()
            self.assertTrue(any("OOM kill" in x for x in titles(a)))
            self.assertTrue(any("FailedScheduling" in x for x in titles(a)))
            etcd = next(f for f in a.findings if "etcd leader" in f["title"])
            self.assertIn("38 ms", etcd["evidence"])


class TestSmallChecks(unittest.TestCase):
    def test_pending_csr(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"02-csr.txt":
                             "NAME  AGE  SIGNERNAME  REQUESTOR  CONDITION\n"
                             "csr-abc12  5m  kubernetes.io/kubelet-serving "
                             "system:node:w1  Pending\n"})
            a.check_csr()
            self.assertTrue(any("Pending" in x for x in titles(a)))

    def test_master_prefix_failure_domain(self):
        nodes = ("NAME STATUS ROLES AGE VERSION\n"
                 "siteA-mst1.x Ready control-plane,master 100d v1\n"
                 "siteA-mst2.x Ready control-plane,master 100d v1\n"
                 "siteA-mst3.x Ready control-plane,master 100d v1\n"
                 "siteA-wrk1.x Ready worker 100d v1\n"
                 "siteB-wrk1.x Ready worker 100d v1\n")
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"02-nodes-wide.txt": nodes,
                             "01-infrastructure.yaml": HA_INFRA})
            a.check_topology_spread()
            self.assertTrue(any("hostname prefix" in x for x in titles(a)))

    def test_prom_am_degraded(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"08-prom-am.txt":
                             "NAME VERSION DESIRED READY RECONCILED AVAILABLE AGE\n"
                             "prometheus.monitoring.coreos.com/k8s 2.55 2 0 "
                             "True False 100d\n"})
            a.check_prom_am()
            f = next(f for f in a.findings if "prometheus" in f["title"])
            self.assertEqual(f["sev"], "HIGH")

    def test_foreign_route_host(self):
        routes = ("NAMESPACE   NAME   HOST/PORT                 PATH   SERVICES   PORT   TERMINATION   WILDCARD\n"
                  "app1        ext    api.somewhere-else.test          svc1       http   edge          None\n"
                  "app2        ok     app2.apps.c.example.test         svc2       http   edge          None\n")
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"03-routes.txt": routes,
                             "01-ingress-config.yaml":
                                 "spec:\n  domain: apps.c.example.test\n",
                             "01-dns.yaml": "spec:\n  baseDomain: c.example.test\n"})
            a.check_routes_hosts()
            f = next(f for f in a.findings if "outside the cluster" in f["title"])
            self.assertIn("somewhere-else", f["evidence"])
            self.assertNotIn("app2.apps", f["evidence"])

    def test_naming_hygiene(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "06-projects.txt": "NAME\napp-prod\nidan-temp\ntest\n"
                                   "openshift-monitoring\n",
                "06-workloads-status.txt":
                    "KIND NS NAME DESIRED READY\n"
                    "Deployment app-prod srv-test-x 1 1\n",
                "10-cronjobs.txt":
                    "NAMESPACE   NAME           SCHEDULE      TIMEZONE   SUSPEND   ACTIVE   LAST SCHEDULE   AGE\n"
                    "vault       vault-unseal   * * * * *     <none>     False     0        30s             100d\n"})
            a.check_naming_hygiene()
            self.assertTrue(any("test/temporary" in x for x in titles(a)))
            self.assertTrue(any("production namespaces" in x for x in titles(a)))
            cron = next(f for f in a.findings if "CronJob" in f["title"])
            self.assertIn("EVERY MINUTE", cron["evidence"])

    def test_etcd_encryption_empty_marker_now_fires(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-etcd-encryption.txt": "(empty result)\n"})
            a.check_security()
            self.assertTrue(any("etcd encryption" in x for x in titles(a)))

    def test_no_idp_finding(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"07-oauth.yaml":
                             "apiVersion: config.openshift.io/v1\n"
                             "kind: OAuth\nspec: {}\n",
                             "07-users.txt": "(empty result)\n"})
            a.check_identity_facts()
            self.assertTrue(any("No identity provider" in x for x in titles(a)))


class TestOLMExtensions(unittest.TestCase):
    def test_installplan_chain_dedup(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"05-installplan.txt": INSTALLPLAN_TXT})
            a.check_olm()
            f = next(f for f in a.findings if "pending manual approval" in f["title"])
            self.assertIn("2 operator", f["title"])          # not 4 plans
            self.assertIn("pg-operator.v5.8.3", f["evidence"])
            self.assertNotIn("v5.8.1", f["evidence"])

    def test_catalog_usage_cross_reference(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "05-catalogsource.txt":
                    "NAME DISPLAY TYPE PUBLISHER AGE\n"
                    "community-operators Community grpc RH 100d\n"
                    "redhat-marketplace Marketplace grpc RH 100d\n",
                "05-subscriptions.txt": SUBS_TXT})
            a.check_olm()
            used = next(f for f in a.findings if "IN USE" in f["title"])
            self.assertIn("floaty-op", used["evidence"])
            self.assertTrue(any("present but unused" in x for x in titles(a)))
            self.assertTrue(any("floating channel" in x for x in titles(a)))

    def test_operatorgroup_remnant(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "05-operatorgroup.txt": "NAMESPACE NAME AGE\n"
                                        "ghost-ns leftover-og 200d\n"
                                        "live-ns live-og 200d\n",
                "05-csv.txt": "NS NAME DISPLAY VERSION PHASE\n"
                              "live-ns live-op.v1.0 Live 1.0 Succeeded\n"})
            a.check_olm()
            f = next(f for f in a.findings if "no operator" in f["title"])
            self.assertIn("ghost-ns", f["evidence"])
            self.assertNotIn("live-ns", f["evidence"])

    def test_superseded_pair(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"05-csv.txt":
                             "NS NAME DISPLAY VERSION PHASE\n"
                             "sso rhsso-operator.7.6.11 SSO 7.6 Succeeded\n"
                             "kc rhbk-operator.v26.0.0 RHBK 26.0 Succeeded\n"})
            a.check_olm()
            self.assertTrue(any("Superseded and successor" in x
                                for x in titles(a)))


CO_YAML = """apiVersion: v1
items:
- apiVersion: config.openshift.io/v1
  kind: ClusterOperator
  metadata:
    name: image-registry
  status:
    conditions:
    - lastTransitionTime: "2026-01-01T00:00:00Z"
      message: ImagePrunerJobFailed - the image pruner job failed
      reason: ImagePrunerJobFailed
      status: "True"
      type: Degraded
kind: List
"""


class TestCascade(unittest.TestCase):
    def _bundle(self, t):
        return analyzer(t, {
            "02-nodes-wide.txt":
                "NAME STATUS ROLES AGE VERSION\n"
                "w1 NotReady worker 100d v1\nw2 NotReady worker 100d v1\n"
                "m1 Ready control-plane,master 100d v1\n",
            "02-nodes-conditions.txt":
                "NAME READY MEM DISK PID NET TAINTS\n"
                "w1 Unknown False False False <none> unreachable\n"
                "w2 Unknown False False False <none> unreachable\n"
                "m1 True False False False <none> <none>\n",
            "02-machines.txt":
                "NAME PHASE TYPE REGION ZONE AGE NODE PROVIDERID STATE\n"
                "c-w1 Running x r z 100d w1 baremetal:///x unmanaged\n",
            "01-clusteroperators.txt":
                "NAME VERSION AVAILABLE PROGRESSING DEGRADED SINCE\n"
                "image-registry 4.18 True False True 2d\n",
            "01-clusteroperators.yaml": CO_YAML,
        })

    def test_outage_root_and_cascade_tagging(self):
        with tempfile.TemporaryDirectory() as t:
            a = self._bundle(t)
            a.check_nodes()
            root = next(f for f in a.findings if "not Ready" in f["title"])
            self.assertIn("kubelet stopped reporting", root["evidence"])
            self.assertIn("unmanaged", root["evidence"])
            a.check_clusteroperators()
            co = next(f for f in a.findings if "cluster operator" in f["title"])
            self.assertTrue(co["cascade"])
            self.assertIn("ImagePrunerJobFailed", co["evidence"])

    def test_no_outage_no_cascade_and_single_co_high(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "01-clusteroperators.txt":
                    "NAME VERSION AVAILABLE PROGRESSING DEGRADED SINCE\n"
                    "image-registry 4.18 True False True 2d\n",
                "01-clusteroperators.yaml": CO_YAML})
            a.check_clusteroperators()
            co = next(f for f in a.findings if "cluster operator" in f["title"])
            self.assertFalse(co["cascade"])
            self.assertEqual(co["sev"], "HIGH")  # 1 CO, no outage


class TestStorageComposition(unittest.TestCase):
    def test_db_on_node_local_without_backup_is_critical(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "04-storageclasses.txt":
                    "NAME PROVISIONER RECLAIM BINDMODE EXPANSION DEFAULT\n"
                    "lvms-vg1 topolvm.io Delete WaitForFirstConsumer true true\n",
                "04-pv.txt": "NAME CAP MODE RECLAIM STATUS CLAIM SC\n"
                             "pv1 5Gi RWO Delete Bound app/pg lvms-vg1\n",
                "04-pvc.txt": "NS NAME STATUS VOLUME CAP MODE SC AGE\n"
                              "app postgres-data Bound pv1 5Gi RWO lvms-vg1 10d\n"})
            a.facts["backup_stack"] = "none detected"
            a.check_storage()
            f = next(f for f in a.findings if "node-local" in f["title"])
            self.assertEqual(f["sev"], "CRITICAL")
            self.assertIn("NO BACKUP", f["title"])

    def test_zero_pv_pvc_with_events_is_broken_provisioner(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "04-storageclasses.txt":
                    "NAME PROVISIONER RECLAIM BINDMODE EXPANSION DEFAULT\n"
                    "lvms-vg1 topolvm.io Delete WaitForFirstConsumer true true\n",
                "11-events-warning.txt":
                    "NAMESPACE LAST TYPE REASON OBJECT MESSAGE\n"
                    "openshift-storage 5m Warning ResourceReconciliationIncomplete "
                    "lvmcluster/x NoAvailableDevicesForVG on node w1\n"})
            a.check_storage()
            f = next(f for f in a.findings if "ZERO PVs" in f["title"])
            self.assertEqual(f["sev"], "CRITICAL")  # broken DEFAULT class
            self.assertIn("NON-FUNCTIONAL", f["title"])


class TestJobsAndIdleOperators(unittest.TestCase):
    def test_failed_pruner_with_registry_removed(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "06-jobs.txt": "NAMESPACE NAME STATUS COMPLETIONS DURATION AGE\n"
                               "openshift-image-registry image-pruner-29 "
                               "Failed 0/1 2d 2d\n",
                "07-imageregistry.yaml": "spec:\n  managementState: Removed\n"})
            a.check_failed_jobs()
            f = next(f for f in a.findings if "failed platform Job" in f["title"])
            self.assertIn("prunes nothing", f["risk"])
            self.assertIn("Suspend the pruner", f["rec"])

    def test_idle_operator(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "05-csv.txt": "NS NAME DISPLAY VERSION PHASE\n"
                              "openshift-operators-redhat loki-operator.v6.1 "
                              "Loki 6.1 Succeeded\n",
                "08-lokistack.txt": "(empty result)\n"})
            a.check_idle_operators()
            f = next(f for f in a.findings if "no configured" in f["title"])
            self.assertIn("loki-operator", f["evidence"])


class TestIdentityPath(unittest.TestCase):
    def test_circular_idp_and_kubeadmin_gating(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "07-oauth.yaml":
                    "spec:\n  identityProviders:\n"
                    "  - mappingMethod: add\n    name: sso\n    type: OpenID\n"
                    "    openID:\n"
                    "      issuer: https://sso.apps.c.example.test/realms/r\n",
                "01-ingress-config.yaml": "spec:\n  domain: apps.c.example.test\n",
                "01-dns.yaml": "spec:\n  baseDomain: c.example.test\n",
                "07-users.txt": "(empty result)\n",
                "07-kubeadmin-exists.txt": "kubeadmin   Opaque   1   400d\n"})
            a.check_identity_path()
            self.assertTrue(any("circular dependency" in x for x in titles(a)))
            self.assertTrue(any("no user has ever logged in" in x
                                for x in titles(a)))
            self.assertTrue(any("mappingMethod 'add'" in x for x in titles(a)))
            self.assertTrue(a.facts["idp_fragile"])
            a.check_security()
            kub = next(f for f in a.findings if "kubeadmin" in f["title"])
            self.assertIn("KEEP it for now", kub["rec"])

    def test_foreign_cluster_idp(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "07-oauth.yaml":
                    "spec:\n  identityProviders:\n"
                    "  - name: sso\n    type: OpenID\n    openID:\n"
                    "      issuer: https://sso.apps.other.example.test/r\n",
                "01-ingress-config.yaml": "spec:\n  domain: apps.c.example.test\n",
                "01-dns.yaml": "spec:\n  baseDomain: c.example.test\n"})
            a.check_identity_path()
            self.assertTrue(any("ANOTHER" in x for x in titles(a)))

    def test_orphaned_identities(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "07-oauth.yaml": "spec:\n  identityProviders:\n"
                                 "  - name: current-idp\n    type: OpenID\n",
                "07-identities.txt":
                    "NAME IDPNAME IDPUSER USER UID\n"
                    "old-ldap:u1 old-ldap u1 alice 123\n"
                    "current-idp:u2 current-idp u2 bob 456\n"})
            a.check_identity_path()
            f = next(f for f in a.findings if "removed identity" in f["title"])
            self.assertIn("old-ldap", f["title"])
            self.assertNotIn("current-idp", f["title"])


class TestCertReferences(unittest.TestCase):
    def test_referenced_cert_unobservable(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "03-ingresscontroller.yaml":
                    "spec:\n  defaultCertificate:\n    name: custom-ingress-cert\n",
                "07-cert-expiry.txt":
                    "NS NAME NOT-AFTER ISSUER\n"
                    "openshift-ingress custom-ingress-cert <none> <none>\n"})
            a.check_cert_expiry()
            f = next(f for f in a.findings if "UNOBSERVABLE" in f["title"])
            self.assertIn("custom-ingress-cert", f["evidence"])


class TestBackupWindowAndAlertCorrelation(unittest.TestCase):
    def test_failure_window_feeds_alerting_finding(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "10-cronjobs.txt":
                    "NAMESPACE NAME SCHEDULE TIMEZONE SUSPEND ACTIVE LAST AGE\n"
                    "backup-ns etcd-backup 0 2 * * * <none> False 0 20h 300d\n",
                "06-pods-all.txt":
                    "NAMESPACE NAME READY STATUS RESTARTS AGE\n"
                    "backup-ns etcd-backup-1 0/1 Error 0 6d\n"
                    "backup-ns etcd-backup-2 0/1 Error 0 5d\n"
                    "backup-ns etcd-backup-3 0/1 Completed 0 76d\n"})
            a.check_etcd_backup()
            b = next(f for f in a.findings if "Backup job pods" in f["title"])
            self.assertIn("AT LEAST ~6 days", b["evidence"])
            a.check_monitoring()
            alert = next(f for f in a.findings if "reach a human" in f["title"])
            self.assertEqual(alert["sev"], "HIGH")
            self.assertIn("Empirical signal", alert["evidence"])


class TestImagePullStratification(unittest.TestCase):
    def test_fresh_vs_chronic(self):
        pods = ("NAMESPACE NAME READY STATUS RESTARTS AGE\n"
                "a old-1 0/1 ImagePullBackOff 0 90d\n"
                "a old-2 0/1 ImagePullBackOff 0 45d\n"
                "b new-1 0/1 ImagePullBackOff 0 3d\n")
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"06-pods-all.txt": pods,
                             "01-clusterversion.yaml":
                                 "status:\n  conditions:\n"
                                 "  - reason: RemoteFailed\n"
                                 "    type: RetrievedUpdates\n"})
            f_ = None
            a.check_pods()
            f_ = next(f for f in a.findings if "image pulls" in f["title"])
            self.assertIn("2 chronic", f_["title"])
            self.assertIn("1 RECENT", f_["title"])
            self.assertIn("MIRROR-REGISTRY DRIFT", f_["risk"])


RECENT_CO_YAML = """apiVersion: v1
items:
- apiVersion: config.openshift.io/v1
  kind: ClusterOperator
  metadata:
    name: authentication
  status:
    conditions:
    - lastTransitionTime: "2025-12-31T20:00:00Z"
      message: recovered
      reason: AsExpected
      status: "False"
      type: Degraded
    - lastTransitionTime: "2025-12-31T21:00:00Z"
      message: back
      reason: AsExpected
      status: "True"
      type: Available
kind: List
"""


class TestRecentTransitions(unittest.TestCase):
    def test_recent_recovery_detected_on_green_cluster(self):
        # collection time is 20260101-000000; transitions 3-4h earlier
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-clusteroperators.yaml": RECENT_CO_YAML})
            a.check_recent_transitions()
            f = next(f for f in a.findings if "recent incident" in f["title"])
            self.assertIn("authentication", f["evidence"])

    def test_old_transitions_stay_silent(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-clusteroperators.yaml":
                             RECENT_CO_YAML.replace("2025-12-31", "2025-01-01")})
            a.check_recent_transitions()
            self.assertFalse(any("recent incident" in x for x in titles(a)))

    def test_mass_restart_signature(self):
        pods = "NAMESPACE NAME READY STATUS RESTARTS AGE\n" + "".join(
            "ns%d pod%d 1/1 Running 3 (5h ago) 90d\n" % (i, i)
            for i in range(12))
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"06-pods-all.txt": pods})
            a.check_recent_transitions()
            self.assertTrue(any("mass-restart" in x for x in titles(a)))


class TestRuleIdsAndReports(unittest.TestCase):
    def test_rule_id_stable_across_counts(self):
        with tempfile.TemporaryDirectory() as t:
            a1 = analyzer(t, {})
            a1._check = "check_pods"
            a1.add("HIGH", "Workloads", "3 pod(s) failing image pulls",
                   "e", "r", "rec")
            a2 = analyzer(t, {})
            a2._check = "check_pods"
            a2.add("HIGH", "Workloads", "17 pod(s) failing image pulls",
                   "e", "r", "rec")
            self.assertEqual(a1.findings[0]["id"], a2.findings[0]["id"])
            self.assertTrue(a1.findings[0]["id"].startswith("pods/"))

    def test_issues_render_has_top_priorities_greens_and_appendix(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "01-clusteroperators.txt":
                    "NAME VERSION AVAILABLE PROGRESSING DEGRADED SINCE\n"
                    "etcd 4.18 True False False 100d\n",
                "07-etcd-encryption.txt": "aesgcm",
            })
            a.run()
            text = oa.render_issues(a, "b")
            self.assertIn("## Top priorities", text)
            self.assertIn("## Verified healthy", text)
            self.assertIn("All 1 cluster operators Available", text)
            self.assertIn("etcd encryption at rest enabled: aesgcm", text)
            self.assertIn("## Evidence file reference", text)
            self.assertIn("oc get clusteroperators", text)

    def test_attention_points_questions_and_secret_scan(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {
                "07-imageregistry.yaml": "spec:\n  managementState: Removed\n",
                "08-leaky.yaml":
                    "data:\n  clientSecret: c3VwZXJzZWNyZXR2YWx1ZTEyMw\n",
            })
            a.run()
            text = oa.render_attention(a, "b")
            self.assertIn("Questions for the customer", text)
            self.assertIn("Removed state", text)
            self.assertIn("08-leaky.yaml", text)
            self.assertIn("sanitize-ocp-bundle.py", text)
            self.assertIn("Verify before presenting", text)


class TestCrossRunDiff(unittest.TestCase):
    def test_prev_diff_resolved_and_new(self):
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            b1 = make_bundle(t, {"07-kubeadmin-exists.txt":
                                 "secret/kubeadmin\n"})
            out1 = Path(t) / "out1"
            subprocess.run([sys.executable, str(REPO / "ocp_analyzer.py"),
                            str(b1), "-o", str(out1)], check=True,
                           capture_output=True)
            self.assertTrue((out1 / "findings.json").exists())
            self.assertTrue((out1 / "attention-points.md").exists())
            # second bundle: kubeadmin gone, pending CSR appeared
            b2 = Path(t) / "ocp-review_test2_20260102-000000"
            b2.mkdir()
            (b2 / "02-csr.txt").write_text(
                "NAME AGE SIGNER REQUESTOR CONDITION\n"
                "csr-x 5m kubelet node:w1 Pending\n")
            out2 = Path(t) / "out2"
            r = subprocess.run([sys.executable, str(REPO / "ocp_analyzer.py"),
                                str(b2), "-o", str(out2),
                                "--prev", str(out1)], check=True,
                               capture_output=True, text=True)
            self.assertIn("vs previous run", r.stdout)
            issues = (out2 / "issues.md").read_text()
            self.assertIn("## Changes since previous run", issues)
            self.assertIn("Resolved", issues)
            self.assertIn("kubeadmin", issues)
            self.assertIn("New", issues)


GPU_CAPACITY = """NAME     GPU-CAP   GPU-ALLOC   HUGEPG-2M   HUGEPG-1G
gpu-a    2         2           0           0
gpu-b    4         4           0           0
cpu-a    <none>    <none>      0           0
"""
GPU_CLUSTERPOLICY = """apiVersion: v1
items:
- apiVersion: nvidia.com/v1
  kind: ClusterPolicy
  metadata:
    name: gpu-cluster-policy
  spec:
    mig:
      strategy: single
  status:
    namespace: nvidia-gpu-operator
    state: %s
kind: List
"""
GPU_TAINTED = """NAME    TAINT-KEYS       TAINT-EFFECTS
gpu-a   nvidia.com/gpu   NoSchedule
gpu-b   nvidia.com/gpu   NoSchedule
cpu-a   <none>           <none>
"""


def gpu_files(**over):
    files = {"12-gpu-capacity.txt": GPU_CAPACITY,
             "12-clusterpolicy.yaml": GPU_CLUSTERPOLICY % "ready",
             "02-nodes-taints.txt": GPU_TAINTED,
             "12-gpu-consumers.txt":
                 "NS     NAME    NODE    GPU-LIMITS\n"
                 "team   job-1   gpu-a   1\n"}
    files.update(over)
    return files


class TestGpuChecks(unittest.TestCase):
    def run_gpu(self, t, **over):
        a = analyzer(t, gpu_files(**over))
        a._check = "check_gpu"
        a.check_gpu()
        return a

    def test_healthy_gpu_cluster_is_quiet(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t)
            self.assertEqual(titles(a), [])
            self.assertIn(("GPU", "GPU Operator ClusterPolicy state is ready"),
                          a.greens)

    def test_allocatable_below_capacity(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{"12-gpu-capacity.txt":
                                   GPU_CAPACITY.replace("4         4", "4         3")})
            hit = [f for f in a.findings if "fewer GPUs" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertEqual(hit[0]["sev"], "HIGH")
            self.assertIn("gpu-b (3 of 4)", hit[0]["evidence"])

    def test_clusterpolicy_not_ready(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{"12-clusterpolicy.yaml":
                                   GPU_CLUSTERPOLICY % "notReady"})
            self.assertIn("GPU Operator ClusterPolicy state is 'notReady'",
                          titles(a))

    def test_kyverno_clusterpolicy_is_not_mistaken_for_nvidia(self):
        """Old collectors used the bare name `clusterpolicy`, which returns
        Kyverno objects where Kyverno is installed."""
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{"12-clusterpolicy.yaml":
                                   "items:\n- apiVersion: kyverno.io/v1\n"
                                   "  kind: ClusterPolicy\n  status:\n"
                                   "    ready: true\n"})
            self.assertEqual(titles(a), [])
            self.assertTrue(any("Kyverno" in x for x in a.assumptions))

    def test_time_slicing_detected(self):
        sharing = ("NAME    PRODUCT            GPU-MEM-MIB   REPLICAS   SHARING        MIG-CAPABLE   MIG-CONFIG     MIG-STRATEGY   DRIVER\n"
                   "gpu-a   Tesla-T4-SHARED    15360         4          time-slicing   false         <none>         single         550.1\n"
                   "gpu-b   NVIDIA-A100        40960         1          none           true          all-disabled   single         550.1\n")
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{"12-gpu-sharing.txt": sharing})
            hit = [f for f in a.findings if "time-slicing" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertIn("gpu-a", hit[0]["evidence"])
            self.assertNotIn("gpu-b", hit[0]["evidence"])
            self.assertEqual(a.facts["gpu_sharing"], "time-slicing on 1 node(s)")

    def test_untainted_gpu_node_lists_non_gpu_pods(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{
                "02-nodes-taints.txt": GPU_TAINTED.replace(
                    "gpu-b   nvidia.com/gpu   NoSchedule",
                    "gpu-b   <none>           <none>"),
                "12-gpu-consumers.txt":
                    "NS                    NAME       NODE    GPU-LIMITS\n"
                    "team                  job-1      gpu-a   1\n"
                    "shop                  web-1      gpu-b   <none>\n"
                    "openshift-dns         dns-x      gpu-b   <none>\n"
                    "nvidia-gpu-operator   driver-x   gpu-b   <none>\n"})
            hit = [f for f in a.findings if "no taint" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertIn("gpu-b", hit[0]["evidence"])
            self.assertIn("shop/web-1", hit[0]["evidence"])
            self.assertNotIn("dns-x", hit[0]["evidence"])
            self.assertNotIn("driver-x", hit[0]["evidence"])

    def test_taint_keys_fall_back_to_conditions_file(self):
        """Bundles from older collectors have taint keys only."""
        cond = ("NAME    READY   MEM-PRESSURE   DISK-PRESSURE   PID-PRESSURE   NET-UNAVAIL   TAINTS\n"
                "gpu-a   True    False          False           False          <none>        nvidia.com/gpu\n"
                "gpu-b   True    False          False           False          <none>        <none>\n")
        with tempfile.TemporaryDirectory() as t:
            files = gpu_files(**{"02-nodes-conditions.txt": cond})
            del files["02-nodes-taints.txt"]
            a = analyzer(t, files)
            a.check_gpu()
            hit = [f for f in a.findings if "no taint" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertIn("gpu-b", hit[0]["evidence"])
            self.assertNotIn("gpu-a", hit[0]["evidence"])

    def test_all_gpus_held_and_workbench_named(self):
        pods = ("NAMESPACE   NAME       READY   STATUS      RESTARTS       AGE   IP         NODE\n"
                "team        wb-0       2/2     Running     3 (2d ago)     12d   10.0.0.1   gpu-a\n"
                "team        job-1      1/1     Running     0              1h    10.0.0.2   gpu-b\n"
                "team        old-job    0/1     Completed   0              30d   10.0.0.3   gpu-b\n")
        cons = ("NS     NAME      NODE    GPU-LIMITS\n"
                "team   wb-0      gpu-a   2\n"
                "team   job-1     gpu-b   4\n"
                "team   old-job   gpu-b   4\n")
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{
                "06-pods-all.txt": pods, "12-gpu-consumers.txt": cons,
                "13-rhoai-notebooks.txt": "NAMESPACE   NAME   AGE\nteam        wb     12d\n"})
            hit = [f for f in a.findings if "are in use" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertEqual(hit[0]["sev"], "LOW")
            self.assertIn("team/wb-0 (2 GPU, age 12d, workbench)",
                          hit[0]["evidence"])
            self.assertNotIn("old-job", hit[0]["evidence"])   # Completed

    def test_completed_pods_do_not_count_as_holding(self):
        pods = ("NAMESPACE   NAME      READY   STATUS      RESTARTS   AGE   IP         NODE\n"
                "team        old-a     0/1     Completed   0          3d    10.0.0.3   gpu-a\n"
                "team        old-b     0/1     Completed   0          3d    10.0.0.4   gpu-b\n")
        cons = ("NS     NAME    NODE    GPU-LIMITS\n"
                "team   old-a   gpu-a   2\n"
                "team   old-b   gpu-b   4\n")
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{"06-pods-all.txt": pods,
                                   "12-gpu-consumers.txt": cons})
            self.assertFalse([x for x in titles(a) if "are in use" in x])

    def test_dcgm_servicemonitor_missing(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{"12-gpu-servicemonitors.txt":
                                   "NAME           AGE\ngpu-operator   9d\n"})
            self.assertIn("GPU metrics (DCGM) are not scraped by cluster "
                          "monitoring", titles(a))
        with tempfile.TemporaryDirectory() as t:
            a = self.run_gpu(t, **{"12-gpu-servicemonitors.txt":
                                   "NAME                   AGE\n"
                                   "nvidia-dcgm-exporter   9d\n"})
            self.assertEqual(titles(a), [])


DSC_YAML = """apiVersion: v1
items:
- apiVersion: datasciencecluster.opendatahub.io/v2
  kind: DataScienceCluster
  metadata:
    name: default-dsc
  spec:
    components:
      kserve:
        managementState: Managed
        nim:
          managementState: Removed
      kueue:
        defaultClusterQueueName: default
        managementState: Unmanaged
      llamastackoperator:
        managementState: Removed
      trainer:
        managementState: Managed
      workbenches:
        managementState: Managed
  status:
    components:
      kserve:
        managementState: Managed
        releases:
        - name: KServe
          version: v0.19.0
        - name: platform
          version: 3.5.3
      llamastackoperator: {}
      trainer:
        managementState: Managed
        releases:
        - name: Kubeflow Trainer
          repoUrl: https://example.test/trainer
          version: 2.1.0
      workbenches:
        managementState: Managed
        releases:
        - name: Notebook Controller
          version: 1.10.0
        - name: platform
          version: %(wb)s
    conditions:
    - lastTransitionTime: "2026-11-01T00:00:00Z"
      status: "True"
      type: Ready
    - lastTransitionTime: "2026-11-01T00:00:00Z"
      message: Component ManagementState is set to Removed
      reason: Removed
      severity: Info
      status: "False"
      type: SparkOperatorReady
%(extra)s    observedGeneration: 3
    phase: %(phase)s
    release:
      name: OpenShift AI Self-Managed
      version: 3.5.3
kind: List
"""
CSV_AI = ("NAMESPACE   NAME                     DISPLAY   VERSION   REPLACES   PHASE\n"
          "ods         rhods-operator.3.5.3     x         3.5.3     y          Succeeded\n"
          "jobset      jobset-operator.v1.0.1   x         1.0.1     y          Succeeded\n"
          "kueue       kueue-operator.v%s       x         1         y          Succeeded\n")


def dsc(wb="3.5.3", phase="Ready", extra=""):
    return DSC_YAML % {"wb": wb, "phase": phase, "extra": extra}


class TestRhoaiChecks(unittest.TestCase):
    def run_ai(self, t, files):
        a = analyzer(t, files)
        a._check = "check_rhoai"
        a.check_rhoai()
        return a

    def test_component_parsers(self):
        comps = oa.dsc_components(oa.yaml_block(
            oa.yaml_block(dsc(), "spec"), "components"))
        self.assertEqual(comps, {"kserve": "Managed", "kueue": "Unmanaged",
                                 "llamastackoperator": "Removed",
                                 "trainer": "Managed",
                                 "workbenches": "Managed"})
        vers = oa.dsc_platform_versions(oa.yaml_block(
            oa.yaml_block(dsc(wb="3.5.1"), "status"), "components"))
        self.assertEqual(vers, {"kserve": "3.5.3", "workbenches": "3.5.1"})

    def test_healthy_dsc_is_green_and_feeds_overview(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_ai(t, {"13-rhoai-dsc.yaml": dsc(),
                                "05-csv.txt": CSV_AI % "1.3.2",
                                "13-rhoai-notebooks.txt":
                                    "NAMESPACE   NAME   AGE\nteam   wb   1d\n"})
            self.assertEqual(titles(a), [])
            self.assertTrue(any(area == "AI platform" for area, _ in a.greens))
            ai = a.facts["rhoai"]
            self.assertEqual(ai["version"], "3.5.3")
            self.assertEqual(ai["managed"], ["kserve", "trainer", "workbenches"])
            self.assertEqual(ai["workbenches"], 1)
            self.assertIn("## AI / ML platform",
                          oa.render_overview(a, "bundle"))

    def test_removed_components_are_not_failures_but_real_ones_are(self):
        extra = ("    - lastTransitionTime: \"2026-11-01T00:00:00Z\"\n"
                 "      message: deployment not available\n"
                 "      reason: DeploymentsNotReady\n"
                 "      status: \"False\"\n"
                 "      type: KserveReady\n")
        with tempfile.TemporaryDirectory() as t:
            a = self.run_ai(t, {"13-rhoai-dsc.yaml":
                                dsc(phase="Not Ready", extra=extra)})
            hit = [f for f in a.findings if "not fully healthy" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertEqual(hit[0]["sev"], "HIGH")
            self.assertIn("KserveReady", hit[0]["evidence"])
            self.assertNotIn("SparkOperatorReady", hit[0]["evidence"])

    def test_component_behind_release(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_ai(t, {"13-rhoai-dsc.yaml": dsc(wb="3.5.1")})
            hit = [f for f in a.findings if "older platform version" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertIn("workbenches=3.5.1", hit[0]["evidence"])

    def test_missing_dependency_operator(self):
        with tempfile.TemporaryDirectory() as t:
            csv = "\n".join(l for l in (CSV_AI % "1.3.2").splitlines()
                            if "jobset" not in l) + "\n"
            a = self.run_ai(t, {"13-rhoai-dsc.yaml": dsc(), "05-csv.txt": csv})
            self.assertTrue([x for x in titles(a)
                             if "`trainer` is Managed but the JobSet" in x])
        with tempfile.TemporaryDirectory() as t:     # no CSV data: stay silent
            a = self.run_ai(t, {"13-rhoai-dsc.yaml": dsc()})
            self.assertEqual(titles(a), [])

    def test_known_issues_are_version_gated(self):
        hw = "NAMESPACE   NAME     AGE\nods         gpu-1x   2d\n"
        with tempfile.TemporaryDirectory() as t:
            a = self.run_ai(t, {"13-rhoai-dsc.yaml": dsc(),
                                "05-csv.txt": CSV_AI % "1.4.0",
                                "13-rhoai-hardwareprofiles.txt": hw})
            got = " ".join(titles(a))
            self.assertIn("RHOAIENG-87625", got)
            self.assertIn("RHOAIENG-67403", got)
        with tempfile.TemporaryDirectory() as t:     # Kueue 1.3: only one hits
            a = self.run_ai(t, {"13-rhoai-dsc.yaml": dsc(),
                                "05-csv.txt": CSV_AI % "1.3.2",
                                "13-rhoai-hardwareprofiles.txt": hw})
            got = " ".join(titles(a))
            self.assertNotIn("RHOAIENG-87625", got)
            self.assertIn("RHOAIENG-67403", got)
        with tempfile.TemporaryDirectory() as t:     # other release: silent
            a = self.run_ai(t, {"13-rhoai-dsc.yaml":
                                dsc().replace("3.5.3", "3.6.0"),
                                "05-csv.txt": CSV_AI % "1.4.0",
                                "13-rhoai-hardwareprofiles.txt": hw})
            self.assertNotIn("known issue", " ".join(titles(a)))

    def test_failed_trainjobs_and_pending_kueue_workloads(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_ai(t, {
                "13-trainjobs.txt":
                    "NAMESPACE   NAME    STATE      AGE\n"
                    "team        run-1   Complete   9d\n"
                    "team        run-2   Failed     3d\n"
                    "team        run-3              5m\n",
                "13-kueue-clusterqueues.txt":
                    "NAME      COHORT   PENDING WORKLOADS\ndefault            2\n",
                "13-kueue-localqueues.txt":
                    "NAMESPACE   NAME      CLUSTERQUEUE   PENDING WORKLOADS   ADMITTED WORKLOADS\n"
                    "team        default   default        2                   1\n",
                "13-kueue-workloads.txt":
                    "NAMESPACE   NAME           QUEUE     RESERVED IN   ADMITTED   FINISHED   AGE\n"
                    "team        trainjob-a     default   default       True       True       9d\n"
                    "team        trainjob-b     default                                       5m\n"
                    "team        trainjob-c     default                                       4m\n"})
            self.assertIn("1 failed training job(s)", titles(a))
            hit = [f for f in a.findings if "waiting in Kueue" in f["title"]]
            self.assertEqual(len(hit), 1)
            self.assertIn("team/trainjob-b", hit[0]["evidence"])
            self.assertNotIn("trainjob-a", hit[0]["evidence"])
            self.assertEqual(a.facts["rhoai"]["train_jobs"],
                             {"Complete": 1, "Failed": 1, "(no state)": 1})

    def test_dashboard_open_to_all_authenticated_users(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.run_ai(t, {"13-rhoai-auth.txt":
                                "NAME   ADMIN-GROUPS   ALLOWED-GROUPS\n"
                                "auth   ai-admins      system:authenticated\n"})
            self.assertIn("Every authenticated user can use the OpenShift AI "
                          "dashboard", titles(a))

    def test_cluster_without_openshift_ai_stays_silent(self):
        with tempfile.TemporaryDirectory() as t:
            b = make_bundle(t, {"01-version.txt": "Server Version: 4.18.35\n"})
            (b / "13-rhoai-dsc.yaml").write_text(
                "(command failed or resource absent - see .err)\n")
            (b / "13-rhoai-dsc.yaml.err").write_text(
                "error: the server doesn't have a resource type "
                "\"datascienceclusters\"\n")
            a = oa.Analyzer(oa.Bundle(b))
            a.check_rhoai()
            self.assertEqual(titles(a), [])
            self.assertNotIn("rhoai", a.facts)

    def test_operator_installed_without_datasciencecluster_is_idle(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"05-csv.txt": CSV_AI % "1.3.2",
                             "13-rhoai-dsc.yaml": "(empty result)\n"})
            a.check_idle_operators()
            self.assertTrue(any("rhods-operator" in f["evidence"]
                                for f in a.findings))


class TestActiveAlerts(unittest.TestCase):
    ALERTS = ('[{"labels": {"alertname": "EtcdDown", "severity": "critical"}},'
              ' {"labels": {"alertname": "Slow", "severity": "warning"}}]')

    def test_collected_alerts_are_reported(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"08-active-alerts.json": self.ALERTS})
            a.check_monitoring()
            self.assertIn("1 critical alert(s) firing at collection time",
                          titles(a))
            self.assertEqual(a.facts["active_alerts"],
                             {"critical": 1, "warning": 1})
            self.assertFalse(any("NOT collected" in x for x in a.assumptions))

    def test_not_requested_is_declared_unknown(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-version.txt": "Server Version: 4.18.35\n"})
            a.check_monitoring()
            self.assertTrue(any("NOT collected" in x for x in a.assumptions))
            self.assertNotIn("active_alerts", a.facts)


class TestOvnkubeCoverage(unittest.TestCase):
    NODES = ("NAME    STATUS   ROLES    AGE   VERSION\n"
             "node-a  Ready    worker   9d    v1.33.1\n"
             "node-b  Ready    worker   9d    v1.33.1\n")

    def test_restarted_pods_still_count(self):
        """`1 (31d ago)` in RESTARTS must not shift the NODE column."""
        pods = ("NAME               READY   STATUS    RESTARTS      AGE   IP         NODE     NOMINATED NODE   READINESS GATES\n"
                "ovnkube-node-aaa   8/8     Running   0             9d    10.0.0.1   node-a   <none>           <none>\n"
                "ovnkube-node-bbb   8/8     Running   1 (31d ago)   9d    10.0.0.2   node-b   <none>           <none>\n")
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"02-nodes-wide.txt": self.NODES,
                             "03-ovnkube-pods.txt": pods})
            a.check_ovnkube_coverage()
            self.assertEqual(titles(a), [])

    def test_missing_pod_is_reported(self):
        pods = ("NAME               READY   STATUS    RESTARTS   AGE   IP         NODE\n"
                "ovnkube-node-aaa   8/8     Running   0          9d    10.0.0.1   node-a\n")
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"02-nodes-wide.txt": self.NODES,
                             "03-ovnkube-pods.txt": pods})
            a.check_ovnkube_coverage()
            self.assertEqual(titles(a), ["1 node(s) without an ovnkube-node pod"])


class TestReportsAreNotWorkOrders(unittest.TestCase):
    """Findings, severities and suggestions can be wrong - the output must
    say so where the reader meets it, and must not invite copy-paste."""

    WRITE_CMD = re.compile(
        r"\b(?:oc|kubectl)\s+(?:patch|delete|apply|create|edit|scale|label|"
        r"annotate|set|replace|rollout|debug|exec|rsh|"
        r"adm\s+(?!top\b|upgrade\b)\w+)")

    def reports(self, t):
        a = analyzer(t, {"07-kubeadmin-exists.txt": "secret/kubeadmin\n",
                         "07-etcd-encryption.txt": "(empty result)\n"})
        a.run()
        self.assertTrue(a.findings)
        return {"overview": oa.render_overview(a, "b"),
                "issues": oa.render_issues(a, "b"),
                "attention": oa.render_attention(a, "b"),
                "guide": oa.render_guide(a, "b")}

    def test_every_report_opens_with_the_notice(self):
        with tempfile.TemporaryDirectory() as t:
            for name, text in self.reports(t).items():
                head = "\n".join(text.splitlines()[:12])
                for sentence in ("Read before acting",
                                 "Findings can be wrong or incomplete",
                                 "Severity levels are estimates",
                                 "Suggested directions are not instructions"):
                    self.assertIn(sentence, head, name)

    def test_issue_wording(self):
        with tempfile.TemporaryDirectory() as t:
            issues = self.reports(t)["issues"]
            self.assertIn("- **Suggested direction (verify first):**", issues)
            self.assertNotIn("Recommendation", issues)
            headers = re.findall(r"^## (?:CRITICAL|HIGH|MEDIUM|LOW|INFO).*$",
                                 issues, re.M)
            self.assertTrue(headers)
            for h in headers:
                self.assertTrue(h.endswith("(estimated)"), h)

    def test_findings_json_carries_the_notice(self):
        import json
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            b = make_bundle(t, {"07-kubeadmin-exists.txt": "secret/kubeadmin\n"})
            out = Path(t) / "out"
            r = subprocess.run([sys.executable, str(REPO / "ocp_analyzer.py"),
                                str(b), "-o", str(out)], check=True,
                               stdout=subprocess.PIPE, universal_newlines=True)
            self.assertIn("can be wrong", r.stdout)
            data = json.loads((out / "findings.json").read_text())
            self.assertEqual(len(data["notice"]), len(oa.NOTICE))
            self.assertIn("estimated", data["field_notes"]["sev"])

    def test_no_state_changing_commands_in_suggestions(self):
        """Static scan of every self.add(...) call: the suggestion (6th
        argument) must describe a direction, never a command to paste."""
        import ast
        tree = ast.parse((REPO / "ocp_analyzer.py").read_text())
        bad = []
        for n in ast.walk(tree):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "add" and len(n.args) >= 6):
                text = " ".join(c.value for c in ast.walk(n.args[5])
                                if isinstance(c, ast.Constant)
                                and isinstance(c.value, str))
                if self.WRITE_CMD.search(text):
                    bad.append((n.lineno, self.WRITE_CMD.search(text).group(0)))
        self.assertEqual(bad, [])

    def test_the_word_mitigation_is_gone(self):
        for rel in ("ocp_analyzer.py", "README.md", "collect-ocp-review.sh",
                    "sanitize-ocp-bundle.py"):
            self.assertNotIn("mitigation", (REPO / rel).read_text().lower(),
                             rel)
        skill = (REPO / "skills/ocp-bundle-review/SKILL.md").read_text()
        # the skill may only mention the word to forbid it
        for line in skill.lower().splitlines():
            if "mitigation" in line:
                self.assertIn("never use the words", line)

    def test_skill_carries_the_same_notice_and_rules(self):
        skill = " ".join((REPO / "skills/ocp-bundle-review/SKILL.md")
                         .read_text().split())
        for n in oa.NOTICE[1:]:
            self.assertIn(" ".join(n.split()), skill)
        self.assertIn("written by an AI model", skill)
        self.assertIn("**Suggested direction (verify first)**", skill)
        self.assertIn("No state-changing commands", skill)
        self.assertIn("**How to verify**", skill)


class TestCollectorScript(unittest.TestCase):
    """Static checks on collect-ocp-review.sh (no cluster needed)."""

    SCRIPT = (REPO / "collect-ocp-review.sh").read_text()

    def collected(self):
        return dict(re.findall(r'^run "([^"]+)"\s+(.*)$', self.SCRIPT, re.M))

    def test_only_read_verbs(self):
        for name, args in self.collected().items():
            self.assertRegex(args, r"^(get|version|adm (top|upgrade))\b",
                             "%s runs a non-read command" % name)

    def test_alerts_are_opt_in_and_token_stays_off_the_command_line(self):
        self.assertNotIn("services/alertmanager-main", self.SCRIPT)
        self.assertIn('if [ "$ALERTS" != 0 ]; then collect_alerts; fi',
                      self.SCRIPT)
        curl = [l for l in self.SCRIPT.splitlines()
                if l.strip().startswith("curl ")]
        self.assertEqual(len(curl), 1)
        self.assertIn("-K -", curl[0])
        self.assertNotIn("$token", curl[0])
        self.assertNotIn("-X", curl[0])            # plain GET only

    def test_every_call_has_a_request_timeout(self):
        self.assertIn('oc --request-timeout="$REQUEST_TIMEOUT" "$@"',
                      self.SCRIPT)

    def test_collision_prone_resources_are_fully_qualified(self):
        c = self.collected()
        for name in ("12-clusterpolicy.yaml", "10-velero-crs.txt",
                     "07-acs-central.txt", "03-whereabouts-ippools.yaml"):
            self.assertRegex(c[name], r"^get [a-z]+\.[a-z0-9.-]+",
                             "%s uses a bare resource name" % name)
        for name, args in c.items():
            if name.startswith("13-"):
                self.assertRegex(args, r"^get [a-z]+\.[a-z0-9.-]+\.[a-z]+",
                                 "%s uses a bare resource name" % name)

    def test_every_collected_file_has_an_evidence_command(self):
        missing = [n for n in self.collected() if n not in oa.FILE_COMMANDS]
        self.assertEqual(missing, [])


class TestFullRunSmoke(unittest.TestCase):
    def test_run_never_raises_on_minimal_bundle(self):
        with tempfile.TemporaryDirectory() as t:
            a = analyzer(t, {"01-version.txt": "Server Version: 4.18.35\n"})
            a.run()
            self.assertFalse(any("internal error" in f["evidence"]
                                 for f in a.findings),
                             [f for f in a.findings
                              if "internal error" in f["evidence"]])


if __name__ == "__main__":
    unittest.main()
