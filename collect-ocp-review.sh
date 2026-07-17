#!/usr/bin/env bash
#
# collect-ocp-review.sh  (v2 — successor of collect-ocp-overview.sh)
# Read-only OCP architecture/health-review collector. Run once per cluster.
# Produces a timestamped, per-domain bundle suitable for offline review and
# for cross-checking a Red Hat TSR report.
#
# Safety: this script ONLY runs read verbs:
#   oc get / oc adm top / oc auth can-i / oc whoami / oc version /
#   oc adm upgrade (no args) / oc get --raw <GET endpoints>
# It performs NO writes and does NOT exec into pods.
#
# Data sensitivity:
#   This script does NOT read Secret or ConfigMap *data*. It does capture:
#     - user / group / service-account identities (RBAC, identities, OAuth)
#     - internal hostnames, FQDNs and IP addresses (nodes, routes, services)
#     - cluster ID, base domain, registry/mirror references, route inventory
#   Before sharing the bundle externally, create a sanitized copy:
#       ./collect-ocp-review.sh --sanitize            (during collection)
#       ./sanitize-ocp-bundle.py <bundle-dir>          (any time later)
#   The sanitized copy lands in <bundle-dir>-sanitized; the reversible
#   mapping stays in <bundle-dir>-sanitized-map.json — keep that file private.
#
# Usage:
#   export KUBECONFIG=/path/to/cluster-kubeconfig
#   ./collect-ocp-review.sh [--sanitize] [cluster-label]
#
set -uo pipefail

# Toolkit release (CalVer YYYY.MM[.patch]) and bundle layout format.
# BUNDLE_FORMAT only changes when files are renamed/removed or their layout
# changes incompatibly - NOT when new collection lines are added.
TOOLKIT_VERSION="2026.07"
BUNDLE_FORMAT=2

SANITIZE=0
CLUSTER_LABEL=""
for arg in "$@"; do
  case "$arg" in
    -s|--sanitize) SANITIZE=1 ;;
    -h|--help)
      sed -n '2,25p' "$0"; exit 0 ;;
    *) CLUSTER_LABEL="$arg" ;;
  esac
done
[ -n "$CLUSTER_LABEL" ] || CLUSTER_LABEL="$(oc whoami --show-server 2>/dev/null | sed 's|https\?://||; s|[:/].*||' || echo cluster)"

TS="$(date +%Y%m%d-%H%M%S)"
OUT="ocp-review_${CLUSTER_LABEL}_${TS}"
mkdir -p "$OUT"

# Stamp the bundle so the analyzer (possibly a different release, run weeks
# later on another machine) can detect version/format mismatches.
{
  echo "toolkit-version: $TOOLKIT_VERSION"
  echo "bundle-format: $BUNDLE_FORMAT"
  echo "collected: $TS"
  echo "cluster-label: $CLUSTER_LABEL"
} > "$OUT/00-meta.txt"

log()  { printf '  [+] %s\n' "$1"; }
warn() { printf '  [!] %s\n' "$1" >&2; }

# run <outfile> <oc args...>  — never fails the script; records missing/denied
run() {
  local f="$OUT/$1"; shift
  if oc "$@" > "$f" 2>"$f.err"; then
    [ -s "$f" ] || echo "(empty result)" > "$f"
    rm -f "$f.err"
  else
    echo "(command failed or resource absent — see $1.err)" > "$f"
  fi
}

echo "=== OCP Review collection: $CLUSTER_LABEL (toolkit $TOOLKIT_VERSION) ==="
echo "    Output dir: $OUT"

# ---- 0. Access sanity -------------------------------------------------------
log "Access & identity"
{
  echo "## whoami";        oc whoami 2>&1
  echo "## server";        oc whoami --show-server 2>&1
  echo "## client/server version"; oc version 2>&1
  echo "## can-i get nodes";              oc auth can-i get nodes 2>&1
  echo "## can-i list clusteroperators";  oc auth can-i list clusteroperators 2>&1
  echo "## can-i create clusterrolebindings (MUST be 'no' for a proper read-only audit account)"
  oc auth can-i create clusterrolebindings 2>&1
  echo "## can-i get secrets -A (informational; this script never reads secret data)"
  oc auth can-i get secrets -A 2>&1
} > "$OUT/00-access.txt"
if grep -qx yes < <(oc auth can-i create clusterrolebindings 2>/dev/null); then
  warn "collection account has WRITE permissions — use a read-only audit account next time"
fi

# ---- 1. Identity, version & lifecycle --------------------------------------
log "Version, lifecycle & cluster config"
run "01-version.txt"            version
run "01-clusterversion.yaml"    get clusterversion -o yaml   # includes history, force flags, acceptedRisks
run "01-upgrade.txt"            adm upgrade
run "01-clusteroperators.txt"   get clusteroperators
run "01-clusteroperators.yaml"  get clusteroperators -o yaml  # full conditions/messages for degraded analysis
run "01-infrastructure.yaml"    get infrastructure cluster -o yaml
run "01-apiserver.yaml"         get apiserver cluster -o yaml           # TLS profile, audit profile, etcd encryption
run "01-ingress-config.yaml"    get ingress.config cluster -o yaml      # apps domain, appsDomain override
run "01-proxy.yaml"             get proxy cluster -o yaml
run "01-dns.yaml"               get dns.config cluster -o yaml
run "01-featuregate.yaml"       get featuregate cluster -o yaml
run "01-operatorhub.yaml"       get operatorhub cluster -o yaml         # default catalog sources on/off (disconnected)
run "01-mirrors-icsp.yaml"      get imagecontentsourcepolicy -o yaml    # image mirror config (disconnected)
run "01-mirrors-idms.yaml"      get imagedigestmirrorset -o yaml
run "01-mirrors-itms.yaml"      get imagetagmirrorset -o yaml
run "01-etcd-cr.yaml"           get etcd cluster -o yaml                 # etcd operator conditions + control-plane member status
# read-only GET against the API-server readiness endpoint; shows per-component gates (etcd, informers)
run "01-etcd-readyz.txt"        get --request-timeout=20s --raw "/readyz?verbose"

# ---- 2. Topology & compute --------------------------------------------------
log "Nodes, machine config, MCPs"
run "02-nodes-wide.txt"         get nodes -o wide
run "02-nodes-roles-zones.txt"  get nodes -L node-role.kubernetes.io/master -L node-role.kubernetes.io/worker -L node-role.kubernetes.io/infra -L topology.kubernetes.io/zone -L failure-domain.beta.kubernetes.io/zone
run "02-nodes-capacity.txt"     get nodes -o custom-columns=NAME:.metadata.name,CPU:.status.capacity.cpu,MEM:.status.capacity.memory,ALLOC-CPU:.status.allocatable.cpu,ALLOC-MEM:.status.allocatable.memory,KERNEL:.status.nodeInfo.kernelVersion,RUNTIME:.status.nodeInfo.containerRuntimeVersion
# quoted because the jsonpath condition filters contain shell metacharacters ( ) *
run "02-nodes-conditions.txt"   get nodes -o "custom-columns=NAME:.metadata.name,READY:.status.conditions[?(@.type=='Ready')].status,MEM-PRESSURE:.status.conditions[?(@.type=='MemoryPressure')].status,DISK-PRESSURE:.status.conditions[?(@.type=='DiskPressure')].status,PID-PRESSURE:.status.conditions[?(@.type=='PIDPressure')].status,NET-UNAVAIL:.status.conditions[?(@.type=='NetworkUnavailable')].status,TAINTS:.spec.taints[*].key"
run "02-mcp.txt"                get machineconfigpool
run "02-machineconfigs.txt"     get machineconfig                        # names reveal overlapping custom MCs
run "02-kubeletconfig.yaml"     get kubeletconfig -o yaml                # systemReserved etc.
run "02-containerruntimeconfig.yaml" get containerruntimeconfig -o yaml
run "02-tuned.txt"              get tuned -n openshift-cluster-node-tuning-operator
run "02-machinesets.txt"        get machineset -n openshift-machine-api
run "02-machines.txt"           get machines -n openshift-machine-api -o wide
run "02-autoscalers.txt"        get clusterautoscaler,machineautoscaler -A
run "02-top-nodes.txt"          adm top nodes
run "02-csr.txt"                get csr                                  # pending CSRs = broken node joins

# ---- 3. Networking ----------------------------------------------------------
log "Networking"
run "03-network-config.yaml"    get network.config cluster -o yaml
run "03-network-operator.yaml"  get network.operator cluster -o yaml
run "03-ingresscontroller.yaml" get ingresscontroller -n openshift-ingress-operator -o yaml
run "03-ingress-svc.txt"        get svc -n openshift-ingress
run "03-services-all.txt"       get svc -A                               # NodePort/LoadBalancer/ExternalName usage
run "03-routes.txt"             get routes -A
run "03-networkpolicy.txt"      get networkpolicy -A
run "03-anp-banp.txt"           get adminnetworkpolicy,baselineadminnetworkpolicy
run "03-egressips.txt"          get egressip
run "03-egressfirewall.txt"     get egressfirewall -A
run "03-metallb.txt"            get ipaddresspools,l2advertisements,bgpadvertisements -A
run "03-net-attach-def.txt"     get network-attachment-definitions -A
run "03-sriov.txt"              get sriovnetworknodepolicy,sriovnetwork -A
run "03-nncp.yaml"              get nncp -o yaml                         # NodeNetworkConfigurationPolicy status (nmstate)
run "03-nnce.txt"               get nnce                                 # per-node enactment of the NNCPs above
run "03-whereabouts-ippools.yaml" get ippools -A -o yaml                # Whereabouts IPAM pools: allocations, podrefs (duplicate/orphan IP detection)
run "03-whereabouts-overlap.txt"  get overlappingrangeipreservations -A
run "03-ovnkube-pods.txt"       get pods -n openshift-ovn-kubernetes -o wide   # expect one ovnkube-node pod per node

# ---- 4. Storage -------------------------------------------------------------
log "Storage"
run "04-storageclasses.txt"     get sc -o custom-columns=NAME:.metadata.name,PROVISIONER:.provisioner,RECLAIM:.reclaimPolicy,BINDMODE:.volumeBindingMode,EXPANSION:.allowVolumeExpansion,DEFAULT:.metadata.annotations.storageclass\\.kubernetes\\.io/is-default-class
run "04-csidrivers.txt"         get csidrivers
run "04-volumesnapshotclass.txt" get volumesnapshotclass
run "04-volumesnapshots.txt"    get volumesnapshot -A
run "04-pv.txt"                 get pv
run "04-pvc.txt"                get pvc -A
run "04-storagecluster.txt"     get storagecluster -n openshift-storage
run "04-storagecluster.yaml"    get storagecluster -n openshift-storage -o yaml   # resource sizing (MDS mem), device sets
run "04-cephcluster.txt"        get cephcluster -n openshift-storage
run "04-cephblockpool.txt"      get cephblockpool -n openshift-storage
run "04-cephfilesystem.txt"     get cephfilesystem -n openshift-storage
run "04-noobaa.txt"             get noobaa -n openshift-storage
run "04-obc.txt"                get objectbucketclaim -A
run "04-localvolume.yaml"       get localvolume -n openshift-local-storage -o yaml  # OSD device paths (persistent or not)
run "04-trident.txt"            get tridentbackendconfig -A
run "04-imagepruner.yaml"       get imagepruner cluster -o yaml

# ---- 5. Operators & OLM -----------------------------------------------------
log "Operators & OLM"
run "05-catalogsource.txt"      get catalogsource -A
run "05-operatorgroup.txt"      get operatorgroup -A
# NOTE: fully-qualified name — bare "subscription" can resolve to a third-party
# CRD on clusters with Confluent/Zedoc/etc. installed (returned empty on ocplanp).
run "05-subscriptions.txt"      get subscriptions.operators.coreos.com -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,CHANNEL:.spec.channel,SOURCE:.spec.source,APPROVAL:.spec.installPlanApproval,CSV:.status.installedCSV,STATE:.status.state
run "05-csv.txt"                get csv -A
run "05-installplan.txt"        get installplan -A
run "05-crd-count.txt"          get crd -o custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp

# ---- 6. Workloads & tenancy -------------------------------------------------
log "Workloads & tenancy"
run "06-projects.txt"           get projects
run "06-resourcequota.txt"      get resourcequota -A
run "06-clusterresourcequota.txt" get clusterresourcequota
run "06-limitrange.txt"         get limitrange -A
run "06-pods-all.txt"           get pods -A -o wide
run "06-top-pods.txt"           adm top pods -A --sum
run "06-workloads.txt"          get deploy,statefulset,daemonset -A
run "06-workloads-status.txt"   get deploy,statefulset -A -o custom-columns=KIND:.kind,NS:.metadata.namespace,NAME:.metadata.name,DESIRED:.spec.replicas,READY:.status.readyReplicas   # replica parity
run "06-daemonsets-status.txt"  get daemonset -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,DESIRED:.status.desiredNumberScheduled,READY:.status.numberReady,UNAVAIL:.status.numberUnavailable
run "06-hpa.txt"                get hpa -A
run "06-pdb.txt"                get pdb -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,MIN-AVAIL:.spec.minAvailable,MAX-UNAVAIL:.spec.maxUnavailable,ALLOWED:.status.disruptionsAllowed
run "06-jobs.txt"               get jobs -A
run "06-priorityclasses.txt"    get priorityclasses

# ---- 7. Security & access ---------------------------------------------------
log "Security & access"
run "07-oauth.yaml"             get oauth cluster -o yaml
# custom columns: the default oauthclients table prints the client SECRET in cleartext
run "07-oauthclients.txt"       get oauthclients -o custom-columns=NAME:.metadata.name,WWW-CHALLENGE:.respondWithChallenges,TOKEN-MAX-AGE:.accessTokenMaxAgeSeconds,GRANT-METHOD:.grantMethod,REDIRECT-URIS:.redirectURIs[*]
run "07-users.txt"              get user
run "07-groups.txt"             get groups
run "07-identities.txt"         get identity
run "07-clusterrolebindings.txt" get clusterrolebinding -o wide
run "07-rolebindings.txt"       get rolebindings -A -o wide
run "07-scc.txt"                get scc
run "07-scc.yaml"               get scc -o yaml                          # diff default SCCs against a stock cluster
run "07-webhooks.txt"           get mutatingwebhookconfiguration,validatingwebhookconfiguration -o custom-columns=KIND:.kind,NAME:.metadata.name,FAILURE-POLICIES:.webhooks[*].failurePolicy
run "07-etcd-encryption.txt"    get apiserver cluster -o jsonpath={.spec.encryption.type}
# existence check only (-o name prints no secret data): kubeadmin left in place is a finding
run "07-kubeadmin-exists.txt"   get secret kubeadmin -n kube-system -o name
run "07-imageregistry.yaml"     get configs.imageregistry.operator.openshift.io cluster -o yaml
run "07-registry-route.txt"     get route -n openshift-image-registry
run "07-certificates.txt"       get certificates.cert-manager.io -A
run "07-acs-central.txt"        get central -A
run "07-acs-secured.txt"        get securedcluster -A
run "07-compliance.txt"         get compliancesuite,compliancescan -A    # Compliance Operator, if present
run "07-acm-policies.txt"       get policies.policy.open-cluster-management.io -A   # RHACM governance compliance, if ACM present
# cert expiry from the not-after ANNOTATION only (metadata); the certificate and key bytes in .data are never read
run "07-cert-expiry.txt"        get secret -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,NOT-AFTER:.metadata.annotations.auth\\.openshift\\.io/certificate-not-after,ISSUER:.metadata.annotations.auth\\.openshift\\.io/certificate-issuer

# ---- 8. Observability -------------------------------------------------------
log "Observability"
run "08-cluster-monitoring.yaml" get configmap cluster-monitoring-config -n openshift-monitoring -o yaml
run "08-uwm.yaml"               get configmap user-workload-monitoring-config -n openshift-user-workload-monitoring -o yaml
run "08-prom-am.txt"            get prometheus,alertmanager -n openshift-monitoring
run "08-alertmanagerconfig.txt" get alertmanagerconfig -A
# Active alerts snapshot (GET via API-server service proxy; best effort — may be
# denied by RBAC/oauth-proxy, in which case the .err file records why):
run "08-active-alerts.json"     get --request-timeout=20s --raw "/api/v1/namespaces/openshift-monitoring/services/alertmanager-main:9094/proxy/api/v2/alerts?active=true"
run "08-clusterlogging.txt"     get clusterlogging,clusterlogforwarder -n openshift-logging
run "08-clusterlogging.yaml"    get clusterlogging,clusterlogforwarder -n openshift-logging -o yaml  # storage class, retention, outputs
run "08-lokistack.txt"          get lokistack -A
run "08-prometheusrules.txt"    get prometheusrule -A

# ---- 9. GitOps / CD ---------------------------------------------------------
log "GitOps / CD"
run "09-argocd.txt"             get argocd -A
# NOTE: fully-qualified — bare "applications" can resolve to applications.app.k8s.io
# and lose the Sync/Health printer columns (bit us on ocplanp).
run "09-applications.txt"       get applications.argoproj.io -A
run "09-appprojects.txt"        get appprojects.argoproj.io -A
run "09-applicationsets.txt"    get applicationsets.argoproj.io -A
run "09-tektonconfig.txt"       get tektonconfig

# ---- 10. Backup & DR --------------------------------------------------------
log "Backup & DR"
run "10-cronjobs.txt"           get cronjob -A
run "10-oadp-dpa.txt"           get dataprotectionapplication -A
run "10-backup-locations.txt"   get backupstoragelocation,volumesnapshotlocation -A
run "10-velero-crs.txt"         get backup,restore,schedule -A
run "10-kasten-policies.txt"    get policies.config.kio.kasten.io -A     # Kasten K10, if present
run "10-etcd-backup-fg.txt"     get featuregate cluster -o jsonpath={.status.featureGates[0].enabled}

# ---- 11. Events -------------------------------------------------------------
log "Recent warning events"
run "11-events-warning.txt"     get events -A --field-selector type=Warning --sort-by=.lastTimestamp

# ---- 12. GPU / NVIDIA DGX ----------------------------------------------------
# Best effort — every command degrades to a .err file on clusters without
# GPUs / the NVIDIA operators. Covers GPU Operator, NFD, MIG, and the
# Network Operator (InfiniBand/RDMA) stack found on DGX systems.
log "GPU / NVIDIA DGX (skipped gracefully on non-GPU clusters)"
run "12-gpu-node-labels.txt"    get nodes -L nvidia.com/gpu.present -L nvidia.com/gpu.count -L nvidia.com/gpu.product -L nvidia.com/gpu.machine -L nvidia.com/mig.config -L nvidia.com/mig.strategy -L nvidia.com/gpu.deploy.driver
run "12-gpu-capacity.txt"       get nodes -o custom-columns=NAME:.metadata.name,GPU-CAP:.status.capacity.nvidia\\.com/gpu,GPU-ALLOC:.status.allocatable.nvidia\\.com/gpu,HUGEPG-2M:.status.capacity.hugepages-2Mi,HUGEPG-1G:.status.capacity.hugepages-1Gi
run "12-clusterpolicy.yaml"     get clusterpolicy -A -o yaml             # driver version, MIG strategy, DCGM, GDS, vGPU, toolkit
run "12-nfd.txt"                get nodefeaturediscovery -A              # Node Feature Discovery (GPU Operator prerequisite)
run "12-nicclusterpolicy.yaml"  get nicclusterpolicy -A -o yaml          # NVIDIA Network Operator: MOFED/OFED, RDMA device plugin, IB
run "12-nvidia-networks.txt"    get macvlannetwork,hostdevicenetwork,ipoibnetwork -A   # Network Operator secondary networks
run "12-sriov-node-state.txt"   get sriovnetworknodestate -n openshift-sriov-network-operator   # actual NIC/IB port state per node
run "12-performanceprofile.yaml" get performanceprofile -o yaml          # CPU isolation, hugepages, topology policy
run "12-gpu-operator-pods.txt"  get pods -n nvidia-gpu-operator -o wide  # driver/toolkit/device-plugin/DCGM daemonset health
run "12-nv-network-pods.txt"    get pods -n nvidia-network-operator -o wide
run "12-gpu-consumers.txt"      get pods -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,NODE:.spec.nodeName,GPU-LIMITS:.spec.containers[*].resources.limits.nvidia\\.com/gpu

# ---- Summary ----------------------------------------------------------------
log "Building SUMMARY.txt"
{
  echo "# Collection summary: $CLUSTER_LABEL ($TS)"
  echo
  echo "## Cluster operators not fully healthy (Available!=True / Progressing / Degraded)"
  awk 'NR==1 || $3!="True" || $4!="False" || $5!="False"' "$OUT/01-clusteroperators.txt" 2>/dev/null | head -40
  echo
  echo "## ClusterVersion red flags"
  grep -nE 'force: true' "$OUT/01-clusterversion.yaml" 2>/dev/null && echo "  ^^ WARNING: forced-upgrade flag set in spec" || echo "  (no force flag)"
  grep -cE 'Forced through blocking failures' "$OUT/01-clusterversion.yaml" 2>/dev/null | sed 's/^/  forced upgrades in history: /'
  echo
  echo "## Non-running pods (by status)"
  tail -n +2 "$OUT/06-pods-all.txt" 2>/dev/null | awk '$4!="Running" && $4!="Completed"{c[$4]++} END{for(s in c) printf "  %5d %s\n", c[s], s}'
  echo
  echo "## Top 10 pod restart counts"
  tail -n +2 "$OUT/06-pods-all.txt" 2>/dev/null | sort -k5 -rn | head -10 | awk '{printf "  %s/%s  restarts=%s  status=%s\n", $1, $2, $5, $4}'
  echo
  echo "## PVs not Bound"
  tail -n +2 "$OUT/04-pv.txt" 2>/dev/null | awk '$5!="Bound"{c[$5]++} END{for(s in c) printf "  %5d %s\n", c[s], s}'
  echo
  echo "## InstallPlans pending approval"
  awk '$5=="false"{print "  "$1"  "$3}' "$OUT/05-installplan.txt" 2>/dev/null
  echo
  echo "## PDBs allowing zero disruptions (block node drains)"
  awk 'NR>1 && $5==0{print "  "$1"/"$2}' "$OUT/06-pdb.txt" 2>/dev/null | head -20
  echo
  echo "## Webhooks with failurePolicy=Fail"
  grep -c 'Fail' "$OUT/07-webhooks.txt" 2>/dev/null | sed 's/^/  configurations containing Fail: /'
  echo
  echo "## ClusterRoleBindings granting cluster-admin"
  grep -cE 'ClusterRole/cluster-admin([^-]|$)' "$OUT/07-clusterrolebindings.txt" 2>/dev/null | sed 's/^/  count: /'
  echo
  echo "## kubeadmin secret still present?"
  cat "$OUT/07-kubeadmin-exists.txt" 2>/dev/null
  echo
  echo "## etcd encryption type (empty = NOT enabled)"
  cat "$OUT/07-etcd-encryption.txt" 2>/dev/null; echo
  echo
  echo "## Namespace governance coverage"
  NS_TOTAL=$(tail -n +2 "$OUT/06-projects.txt" 2>/dev/null | wc -l | tr -d ' ')
  NS_RQ=$(tail -n +2 "$OUT/06-resourcequota.txt" 2>/dev/null | awk '{print $1}' | sort -u | wc -l | tr -d ' ')
  NS_NP=$(tail -n +2 "$OUT/03-networkpolicy.txt" 2>/dev/null | awk '{print $1}' | sort -u | wc -l | tr -d ' ')
  echo "  projects: $NS_TOTAL | with ResourceQuota: $NS_RQ | with NetworkPolicy: $NS_NP"
  echo
  echo "## Default StorageClass"
  cat "$OUT/04-storageclasses.txt" 2>/dev/null
  echo
  echo "## GPU inventory (nodes with nvidia.com/gpu capacity)"
  awk 'NR>1 && $2!="<none>" && $2!=""{print "  "$1"  gpus="$2}' "$OUT/12-gpu-capacity.txt" 2>/dev/null
  awk 'NR>1 && $2!="<none>" && $2!=""{n++} END{if(!n) print "  (no GPU nodes detected)"}' "$OUT/12-gpu-capacity.txt" 2>/dev/null
  GPU_PODS=$(awk 'NR>1 && $4 ~ /^[0-9]/' "$OUT/12-gpu-consumers.txt" 2>/dev/null | wc -l | tr -d ' ')
  echo "  pods requesting GPUs: ${GPU_PODS:-0}"
  echo
  echo "## Nodes reporting pressure (Memory/Disk/PID/NetworkUnavailable)"
  awk 'NR>1 && ($3=="True"||$4=="True"||$5=="True"||$6=="True"){print "  "$1}' "$OUT/02-nodes-conditions.txt" 2>/dev/null | head -20
  echo
  echo "## etcd / apiserver readiness gates failing (from /readyz?verbose)"
  grep -E '^\[-\]' "$OUT/01-etcd-readyz.txt" 2>/dev/null | head -20
  echo
  echo "## ovnkube-node coverage (a node without a pod has no working pod network)"
  NODES=$(tail -n +2 "$OUT/02-nodes-wide.txt" 2>/dev/null | wc -l | tr -d ' ')
  OVN=$(grep -c 'ovnkube-node-' "$OUT/03-ovnkube-pods.txt" 2>/dev/null)
  echo "  nodes: ${NODES:-?} | ovnkube-node pods: ${OVN:-0}"
  echo
  echo "## Workloads with READY < DESIRED (deploy/statefulset)"
  awk 'NR>1 && $4!="<none>" && $5!="<none>" && ($5+0)<($4+0){print "  "$1" "$2"/"$3"  ready="$5"/"$4}' "$OUT/06-workloads-status.txt" 2>/dev/null | head -20
  echo
  echo "## RHACM policies NonCompliant"
  grep -i 'NonCompliant' "$OUT/07-acm-policies.txt" 2>/dev/null | head -20
} > "$OUT/SUMMARY.txt"

echo
echo "=== Done. Bundle: $OUT ==="
echo "    Review $OUT/SUMMARY.txt first, then per-domain files."

# ---- Optional sanitization ---------------------------------------------------
if [ "$SANITIZE" = "1" ]; then
  SANITIZER="$(cd "$(dirname "$0")" && pwd)/sanitize-ocp-bundle.py"
  if command -v python3 >/dev/null && [ -f "$SANITIZER" ]; then
    log "Creating sanitized copy"
    python3 "$SANITIZER" "$OUT" || warn "sanitization failed — original bundle is untouched"
  else
    warn "python3 or sanitize-ocp-bundle.py not found — skipping sanitization"
    warn "run later:  ./sanitize-ocp-bundle.py $OUT"
  fi
fi
