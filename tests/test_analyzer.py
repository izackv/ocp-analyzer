#!/usr/bin/env python3
"""Unit tests for ocp_analyzer.py (Phase 0 bug fixes + Phase 1 foundations).

All fixtures are synthetic - no customer-derived strings may appear here.

    python3 -m unittest discover tests
"""
import importlib.util
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
    b.mkdir()
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
            self.assertEqual(backup["sev"], "CRITICAL")

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
