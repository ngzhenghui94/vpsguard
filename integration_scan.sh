#!/usr/bin/env bash
# Run only inside the disposable Docker guests in verify.yml, never on a VPS.
set -Eeuo pipefail
umask 077

phase='container prerequisites'
trap 'code=$?; printf "Integration failed during %s (exit %s); raw diagnostics withheld.\n" "$phase" "$code" >&2; exit "$code"' ERR
if [[ $# != 1 || $EUID != 0 || ! -f /.dockerenv ]]; then
    printf 'Requires one target name and root inside a disposable Docker container.\n' >&2
    exit 1
fi
source /etc/os-release
python=python3
mode=scan
case "$1:${ID}:${VERSION_ID}" in
    debian13:debian:13|ubuntu24:ubuntu:24.04) backend=apt ;;
    alma9:almalinux:9|alma9:almalinux:9.*) backend=dnf; python=python3.12 ;;
    opensuse16:opensuse-leap:16.0) backend=zypper; python=python3.13 ;;
    fedora43:fedora:43) backend=dnf; mode=audit-only ;;
    amazon2023:amzn:2023) backend=dnf; python=python3.12; mode=audit-only ;;
    *) printf 'Target does not match an allowed native OS release.\n' >&2; exit 1 ;;
esac

scratch=$(mktemp -d /tmp/vpsguard-integration.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export PYTHONDONTWRITEBYTECODE=1
export LC_ALL=C
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

phase='signed native package installation'
case "$backend" in
    apt)
        apt-get update >"$scratch/install.log" 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
            python3 ca-certificates openscap-scanner >>"$scratch/install.log" 2>&1
        ;;
    dnf)
        packages=("$python" ca-certificates)
        if [[ $mode == scan ]]; then packages+=(openscap-scanner); fi
        dnf -y --setopt=gpgcheck=1 install "${packages[@]}" >"$scratch/install.log" 2>&1
        ;;
    zypper)
        zypper --non-interactive refresh >"$scratch/install.log" 2>&1
        zypper --non-interactive install --no-recommends \
            python313 ca-certificates openscap-utils >>"$scratch/install.log" 2>&1
        ;;
esac

phase='read-only audit'
"$python" vpsguard.py audit >"$scratch/audit.json" 2>"$scratch/audit.stderr"
phase='audit contract checks'
"$python" - "$scratch/audit.json" "$mode" 2>"$scratch/check.stderr" <<'PY'
import json
import platform
import sys
from collections import Counter
from pathlib import Path
from profiles import select_profile

report = json.loads(Path(sys.argv[1]).read_text())
profile = select_profile(platform.freedesktop_os_release())
assert sys.version_info >= (3, 12)
assert report['supported'] is True
assert all(report['profile'][key] == profile[key] for key in ('id', 'version', 'feed_url'))
assert report['checks']
statuses = Counter(check['status'] for check in report['checks'].values())
assert set(statuses) <= {'ok', 'warning', 'unknown'}
assert 'security_updates' in report['checks']
limitations = [
    'Container integration checks native package paths only, not host/kernel/firewall validation.',
    'Audit collection success is not a security pass; unknown checks remain unknown.',
]
if sys.argv[2] == 'audit-only':
    assert profile['feed_url'] is None
    assert profile['scan_unavailable']
    limitations.append(profile['scan_unavailable'])
else:
    assert profile['feed_url'] and profile['oscap_package']
print(json.dumps({'mode': sys.argv[2], 'audit_status': 'collected',
                  'check_counts': dict(statuses), 'findings': len(report['findings']),
                  'limitations': limitations}, indent=2))
PY

if [[ $mode == audit-only ]]; then
    exit 0
fi

phase='native OpenSCAP scan'
status=0
"$python" vpsguard.py scan --output "$scratch/scan" \
    >"$scratch/scan-console.json" 2>"$scratch/scan.stderr" || status=$?
phase='scan evidence checks'
"$python" - "$scratch/scan" "$status" "$backend" 2>"$scratch/check.stderr" <<'PY'
import json
import stat
import sys
from pathlib import Path
from xml.parsers import expat

root = Path(sys.argv[1])
report = json.loads((root / 'summary.json').read_text())
print(json.dumps({'status': report['status'], 'counts': report['counts'],
                  'findings': len(report['findings']),
                  'limitations': report['limitations'] + [
                      'Container package evidence only; not host/kernel/firewall validation.',
                      'Zero findings never establishes that the host is vulnerability-free.',
                  ]}, indent=2))
assert report['status'] == 'complete'
assert int(sys.argv[2]) == (2 if report['findings'] else 0)
assert sum(report['counts'].values()) > 0
assert report['provenance']['engine']['name'] == 'OpenSCAP'
assert report['provenance']['engine']['version']
assert report['provenance']['engine']['exit_code'] == 0
assert stat.S_IMODE(root.stat().st_mode) == 0o700
for artifact in root.iterdir():
    assert artifact.is_file() and not artifact.is_symlink()
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600

# Check actual native package probe evidence, not merely a successful process exit.
item = 'dpkginfo_item' if sys.argv[3] == 'apt' else 'rpminfo_item'
item_tag = 'http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux}' + item
package_items = 0

def start(name, attributes):
    global package_items
    if name == item_tag and attributes.get('status', 'exists') == 'exists':
        package_items += 1

parser = expat.ParserCreate(namespace_separator='}')
parser.StartElementHandler = start
with (root / 'results.xml').open('rb') as source:
    parser.ParseFile(source)
assert package_items > 0
print(json.dumps({'native_package_items': package_items, 'evidence_status': 'verified'}))
PY
