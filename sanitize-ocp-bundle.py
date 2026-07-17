#!/usr/bin/env python3
"""
sanitize-ocp-bundle.py — create a shareable, pseudonymized copy of an OCP
collection bundle (output of collect-ocp-review.sh / collect-ocp-overview.sh).

The ORIGINAL bundle is never modified. A sanitized copy is written to
<bundle>-sanitized/ and a private mapping file to <bundle>-sanitized-map.json
so the reviewer can translate findings back. KEEP THE MAP FILE PRIVATE —
it reverses the sanitization.

What gets replaced (consistently across all files):
  * cluster base domain + parent org domain     -> ocp.example.com / example.com
  * the cluster name label (also inside infrastructureName, account names...)
  * node hostnames                              -> master01/worker01/infra01...
  * OpenShift usernames (from 07-users.txt)     -> user0001, user0002, ...
  * every IPv4 address                          -> stable fake (TEST-NET ranges)
  * every UUID/GUID (cluster ID, identities...) -> stable fake UUIDs
  * e-mail addresses                            -> userNNNN@example.com
  * LDAP DN components (CN=/OU=/DC=...)         -> CN=REDACTED,...
  * non-ASCII runs (e.g. Hebrew full names)     -> REDACTED-NAME
  * OAuth client secrets (oauthclients table
    SECRET column and yaml secret: fields)      -> REDACTED-OAUTH-SECRET
    (irreversible: secrets are never written to the map file)
  * any extra strings given with --replace

Usage:
  ./sanitize-ocp-bundle.py BUNDLE_DIR [-o OUTDIR] [-r ORIG[=NEW]]...
Examples:
  ./sanitize-ocp-bundle.py ocp-review_prod_20260704-101500
  ./sanitize-ocp-bundle.py bundle/ -r ocpmgmtlan=mgmt-cluster -r "Clalit=CUSTOMER"
"""
import argparse
import json
import re
import sys
from pathlib import Path

TEXT_SUFFIXES = {".txt", ".yaml", ".yml", ".json", ".err", ".md", ""}

IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
NONASCII_RE = re.compile(r"[^\x00-\x7F][^\x00-\x7F\s]*(?:\s+[^\x00-\x7F][^\x00-\x7F\s]*)*")
DN_RE = re.compile(r"\b(CN|OU|DC)=([^,\"'\n{}]+)", re.IGNORECASE)
# `secret: <value>` on one line, as in OAuthClient yaml. Does not match the
# `clientSecret:` name reference in oauth.yaml (value is on the next line).
SECRET_LINE_RE = re.compile(r"^(\s*(?:secret|clientSecret):\s*)(\S+)\s*$", re.MULTILINE)


def detect_domains(bundle: Path):
    """Find the cluster base domain and cluster name from dns config or access file."""
    base = None
    for name in ("01-dns.yaml",):
        f = bundle / name
        if f.is_file():
            m = re.search(r"baseDomain:\s*([A-Za-z0-9.-]+)", f.read_text(errors="replace"))
            if m:
                base = m.group(1).strip()
                break
    if not base:
        f = bundle / "00-access.txt"
        if f.is_file():
            m = re.search(r"https?://api\.([A-Za-z0-9.-]+?):\d+", f.read_text(errors="replace"))
            if m:
                base = m.group(1)
    if not base:
        return None, None, None
    labels = base.split(".")
    cluster_name = labels[0] if len(labels) >= 3 else None
    org_domain = ".".join(labels[1:]) if len(labels) >= 3 else base
    return base, cluster_name, org_domain


def _column_slice(header: str, line: str, col: str, next_cols):
    """Extract a fixed-width column from aligned `oc get -o wide` output."""
    start = header.find(col)
    if start < 0:
        return ""
    end = len(line)
    for nc in next_cols:
        pos = header.find(nc)
        if pos > start:
            end = min(end, pos)
    return line[start:end]


def redact_oauthclient_table(text: str) -> str:
    """Blank the SECRET column of a default `oc get oauthclients` table
    (bundles from collectors older than 2026.07 contain it). Irreversible on
    purpose: secrets are redacted, never mapped."""
    lines = text.splitlines(keepends=True)
    if not lines or "SECRET" not in lines[0]:
        return text
    header = lines[0]
    out = [header]
    for line in lines[1:]:
        tok = _column_slice(header, line, "SECRET",
                            ("WWW-CHALLENGE", "TOKEN-MAX-AGE")).strip()
        if tok:
            line = line.replace(tok, "REDACTED-OAUTH-SECRET", 1)
        out.append(line)
    return "".join(out)


def detect_usernames(bundle: Path):
    """Usernames from `oc get user`, RBAC binding subjects, group members,
    and the collecting account. RBAC subjects matter: a User named in a
    binding needs no User object to exist."""
    users = []

    def add(name):
        name = name.strip().rstrip(",")
        if name and "/" not in name and ":" not in name and name not in users:
            users.append(name)

    f = bundle / "07-users.txt"
    if f.is_file():
        for line in f.read_text(errors="replace").splitlines()[1:]:
            tok = line.split()
            if tok and tok[0] not in ("(empty", "(command"):
                add(tok[0])

    # USERS column of (cluster)rolebindings -o wide — fixed-width aligned
    for name in ("07-clusterrolebindings.txt", "07-rolebindings.txt"):
        f = bundle / name
        if not f.is_file():
            continue
        lines = f.read_text(errors="replace").splitlines()
        if not lines or "USERS" not in lines[0]:
            continue
        header = lines[0]
        for line in lines[1:]:
            field = _column_slice(header, line, "USERS", ("GROUPS", "SERVICEACCOUNTS"))
            for name_ in field.split(","):
                add(name_)

    # group members: `oc get groups` -> NAME USERS(comma list)
    f = bundle / "07-groups.txt"
    if f.is_file():
        for line in f.read_text(errors="replace").splitlines()[1:]:
            tok = line.split(None, 1)
            if len(tok) == 2:
                for name_ in tok[1].split(","):
                    add(name_)

    f = bundle / "00-access.txt"
    if f.is_file():
        lines = f.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines):
            if line.strip() == "## whoami" and i + 1 < len(lines):
                add(lines[i + 1])
    return users


def detect_nodes(bundle: Path):
    """Map node short hostnames -> roleNN, using any nodes listing present."""
    mapping = {}
    counters = {"master": 0, "worker": 0, "infra": 0, "node": 0}
    for name in ("02-nodes-roles-zones.txt", "02-nodes-roles.txt", "02-nodes-wide.txt"):
        f = bundle / name
        if not f.is_file():
            continue
        for line in f.read_text(errors="replace").splitlines()[1:]:
            tok = line.split()
            if len(tok) < 3 or "." not in tok[0]:
                continue
            short = tok[0].split(".")[0]
            if short in mapping:
                continue
            # roles column is column 3 in both `get nodes` listings
            roles_col = tok[2] if len(tok) > 2 else ""
            role = "node"
            for r in ("master", "infra", "worker"):
                if r in roles_col:
                    role = r
                    break
            counters[role] += 1
            mapping[short] = f"{role}{counters[role]:02d}"
        if mapping:
            break
    return mapping


class Pseudonymizer:
    def __init__(self):
        self.ip_map, self.uuid_map, self.email_map = {}, {}, {}
        self._ip_pools = ["203.0.113.", "198.51.100.", "192.0.2."]

    def ip(self, orig):
        if orig not in self.ip_map:
            n = len(self.ip_map)
            pool, host = divmod(n, 254)
            if pool < len(self._ip_pools):
                self.ip_map[orig] = f"{self._ip_pools[pool]}{host + 1}"
            else:  # overflow: 10.254.x.y
                extra = n - len(self._ip_pools) * 254
                self.ip_map[orig] = f"10.254.{extra // 254}.{extra % 254 + 1}"
        return self.ip_map[orig]

    def uuid(self, orig):
        key = orig.lower()
        if key not in self.uuid_map:
            n = len(self.uuid_map) + 1
            self.uuid_map[key] = f"00000000-0000-4000-8000-{n:012d}"
        return self.uuid_map[key]

    def email(self, orig):
        if orig not in self.email_map:
            self.email_map[orig] = f"user{len(self.email_map) + 1:04d}@example.com"
        return self.email_map[orig]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", help="bundle directory produced by the collection script")
    ap.add_argument("-o", "--outdir", help="output directory (default: <bundle>-sanitized)")
    ap.add_argument("-r", "--replace", action="append", default=[], metavar="ORIG[=NEW]",
                    help="extra literal replacement, repeatable (default NEW: REDACTED)")
    args = ap.parse_args()

    bundle = Path(args.bundle.rstrip("/") or "/")
    if not bundle.is_dir():
        sys.exit(f"error: {bundle} is not a directory")
    outdir = Path(args.outdir) if args.outdir else bundle.parent / (bundle.name + "-sanitized")
    if outdir.exists() and any(outdir.iterdir()):
        sys.exit(f"error: {outdir} already exists and is not empty — remove it or pass -o")
    outdir.mkdir(parents=True, exist_ok=True)

    # ---- build the replacement plan ----
    # Two tiers, both case-insensitive:
    #   unbounded — replaced anywhere, even inside longer tokens
    #               (domains, cluster name, org name, --replace extras)
    #   bounded   — replaced only as whole word-ish tokens
    #               (usernames, node hostnames — avoids mangling substrings)
    unbounded, bounded = {}, {}
    base, cluster_name, org_domain = detect_domains(bundle)
    if base:
        unbounded[base.lower()] = "ocp.example.com"
        if org_domain and org_domain != base:
            unbounded[org_domain.lower()] = "example.com"
        if cluster_name and len(cluster_name) > 3:
            unbounded[cluster_name.lower()] = "ocpcluster"
        # the org's own name (first label of the org domain) shows up standalone:
        # identity-provider names, LDAP paths, "<org>rhbk" resources, etc.
        org_label = (org_domain or "").split(".")[0]
        if len(org_label) > 3:
            unbounded[org_label.lower()] = "exampleorg"
        print(f"  base domain : {base} -> ocp.example.com")
        if cluster_name:
            print(f"  cluster name: {cluster_name} -> ocpcluster")
        if len(org_label) > 3:
            print(f"  org name    : {org_label} -> exampleorg")
    else:
        print("  warning: could not auto-detect base domain (use -r to add it manually)")

    users = [u for u in detect_usernames(bundle) if len(u) > 2]
    for i, user in enumerate(users, 1):
        bounded[user.lower()] = f"user{i:04d}"
    node_map = detect_nodes(bundle)
    for short, repl in node_map.items():
        bounded[short.lower()] = repl
    for extra in args.replace:
        orig, _, new = extra.partition("=")
        if orig:
            unbounded[orig.lower()] = new or "REDACTED"
    print(f"  literal replacements: {len(unbounded) + len(bounded)} "
          f"(users: {len(users)}, nodes: {len(node_map)})")

    def alternation(strings, bound):
        if not strings:
            return None
        parts = []
        for s in sorted(strings, key=len, reverse=True):
            pat = re.escape(s)
            if bound:
                pat = r"(?<![A-Za-z0-9])" + pat + r"(?![A-Za-z0-9])"
            parts.append(pat)
        return re.compile("|".join(parts), re.IGNORECASE)

    unb_re = alternation(unbounded, bound=False)
    bnd_re = alternation(bounded, bound=True)

    pseudo = Pseudonymizer()

    def sanitize_text(text: str) -> str:
        # bounded (usernames/nodes) first — an unbounded hit inside a username
        # (e.g. cluster name inside "<cluster>admin") would break the match
        if bnd_re:
            text = bnd_re.sub(lambda m: bounded[m.group(0).lower()], text)
        if unb_re:
            text = unb_re.sub(lambda m: unbounded[m.group(0).lower()], text)
        text = UUID_RE.sub(lambda m: pseudo.uuid(m.group(0)), text)
        text = EMAIL_RE.sub(lambda m: pseudo.email(m.group(0)), text)
        text = IP_RE.sub(lambda m: pseudo.ip(m.group(1)), text)
        text = DN_RE.sub(lambda m: f"{m.group(1)}=REDACTED", text)
        text = NONASCII_RE.sub("REDACTED-NAME", text)
        text = SECRET_LINE_RE.sub(lambda m: m.group(1) + "REDACTED-OAUTH-SECRET", text)
        return text

    # ---- process files ----
    done, skipped = 0, []
    for f in sorted(bundle.iterdir()):
        if not f.is_file():
            continue
        if f.suffix.lower() not in TEXT_SUFFIXES:
            skipped.append(f.name)
            continue
        text = f.read_text(errors="replace")
        if "oauthclient" in f.name.lower():
            text = redact_oauthclient_table(text)
        (outdir / f.name).write_text(sanitize_text(text))
        done += 1

    # ---- write the private map ----
    map_path = outdir.parent / (outdir.name + "-map.json")
    map_path.write_text(json.dumps({
        "note": "PRIVATE — reverses the sanitization; do not share with the bundle",
        "literals": {**unbounded, **bounded},
        "ips": pseudo.ip_map,
        "uuids": pseudo.uuid_map,
        "emails": pseudo.email_map,
    }, indent=2, ensure_ascii=False))

    print(f"  sanitized {done} files -> {outdir}/")
    if skipped:
        print(f"  skipped (non-text, review manually before sharing): {', '.join(skipped)}")
    print(f"  private mapping       -> {map_path}  (DO NOT SHARE)")
    print(f"  replaced: {len(pseudo.ip_map)} IPs, {len(pseudo.uuid_map)} UUIDs, "
          f"{len(pseudo.email_map)} emails")
    print("  reminder: spot-check the output — sanitization is best-effort, "
          "org-specific strings may need extra -r rules")


if __name__ == "__main__":
    main()
