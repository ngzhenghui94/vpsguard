# VPSGuard

A Python-standard-library command-line tool for read-only Linux auditing and vendor OVAL package scanning. **Hardening remains restricted to Ubuntu 24.04 LTS** and requires explicit approval; broader audit/scan support does not authorize configuration changes on other distributions.

## Usage

```sh
python3 vpsguard.py                 # Read-only JSON audit
sudo python3 vpsguard.py plan --allow tcp:22 --allow tcp:443
sudo python3 vpsguard.py apply --allow tcp:22 --allow tcp:443 --approve DIGEST
```

Replace the example ports with every externally bound TCP/UDP service you intend to keep, including the actual SSH port. Use `--allow udp:PORT` for UDP. Review the entire plan and replace `DIGEST` with its exact SHA-256 digest.

The first `apply` prepares a transaction without changing configuration. Follow its printed command from a **new, independent SSH connection** authenticated with a key as a non-root sudo user. Disable SSH multiplexing (`ssh -o ControlMaster=no -o ControlPath=none user@host`) so an old connection cannot count as new access. Then repeat the identical `apply` command within ten minutes.

After changes are applied, use another new key-authenticated SSH connection and run the printed `confirm` command before the rollback deadline (five minutes by default). Until confirmation, a persistent systemd timer is scheduled to restore the saved configuration. Failure to restore is an error, not a guarantee of recovery: keep console access.

```sh
sudo python3 vpsguard.py status
sudo python3 vpsguard.py rollback TRANSACTION_ID
```

Do not edit server configuration while a transaction is pending. Backups and the recovery runner live under root-owned `/var/lib/vpsguard`.

Before applying, VPSGuard rechecks backup contents and approved configuration snapshots. An interrupted apply attempts immediate recovery; failed recovery keeps its retry service. Confirmation checks both IPv4 and IPv6 runtime firewall rules for drift. These checks do not make concurrent administrator changes safe: avoid them during a transaction. Finish existing transactions with their archived recovery runner before upgrading; older plans without runtime firewall baselines are refused by the updated CLI.

## Supported audit and scan targets

Profiles use the exact `/etc/os-release` ID and release, not `ID_LIKE`. Every target below supports read-only audit collection; missing tools, permissions or evidence remain `unknown`.

| Distribution | Releases | Official OVAL scan stream |
| --- | --- | --- |
| Ubuntu LTS | 20.04, 22.04, 24.04, 26.04 | CVE vulnerability definitions |
| Debian | 11, 12, 13 | Vulnerability and patch definitions; Debian 11 needs a separately provisioned trusted OpenSCAP |
| RHEL | 8, 9 | Security-advisory patch definitions, base stream only |
| AlmaLinux | 8, 9, 10 | Security-advisory patch definitions |
| Oracle Linux | 8, 9, 10 | Security-advisory patch definitions |
| Rocky Linux | 8, 9 | Security-advisory patch streams configured, but currently stale and rejected |
| SLES | 12.5; 15.4, 15.5, 15.6, 15.7; 16.0, 16.1 | Vulnerability definitions |
| openSUSE Leap | 16.0, 16.1 | Vulnerability definitions |
| openSUSE Tumbleweed | Dated eight-digit `VERSION_ID` (`YYYYMMDD`, beginning with `20`) | Rolling vulnerability stream |
| RHEL | 10 | **Audit only:** publisher does not provide OVAL; CSAF/VEX is not implemented |
| Rocky Linux | 10 | **Audit only:** no verified official OVAL stream |
| Amazon Linux | 2, 2023 | **Audit only:** no verified official OVAL stream; ALAS advisories/RSS are not OVAL |
| Fedora | 43, 44, 45 | **Audit only:** no verified official OVAL stream; Bodhi metadata is not OVAL |

A configured stream is not a guarantee of vendor support entitlement, current coverage or successful evaluation. Feed generator timestamps older than seven days are refused on every scan, including Rocky 8/9; an unavailable or stale feed produces an incomplete scan, never a clean result. RHEL base feeds do not cover extended-support or layered-product streams. VPSGuard never substitutes RHEL OVAL for another distribution.

Publisher indexes are recorded in `profiles.py` and report provenance: [Canonical](https://security-metadata.canonical.com/oval/), [Debian](https://www.debian.org/security/oval/), [Red Hat](https://security.access.redhat.com/data/oval/v2/), [AlmaLinux](https://security.almalinux.org/oval/), [Oracle](https://linux.oracle.com/security/oval/), [Rocky](https://dl.rockylinux.org/pub/oval/) and [SUSE/openSUSE](https://ftp.suse.com/pub/projects/security/oval/).

Audit checks SSH configuration, listeners, firewall observations, cached update metadata, privileged accounts and local Docker publishing. `ok` means that scoped collection succeeded without a known warning, not that the host is secure. It does not refresh repositories or install packages. Ubuntu `-security` candidate suites are only a partial security hint; Debian candidates are not classified using that heuristic. DNF/DNF5/YUM security advisories and Zypper security patches are cache-only observations. Missing/stale metadata, held or excluded packages, unsupported output and absent advisory coverage remain limitations; zero updates is not proof the host is patched. Container observations describe their local namespace, not the host's firewall or kernel.

## Supported hardening configuration

Applying changes deliberately refuses configurations it cannot safely handle:

- Ubuntu 24.04 with running systemd, Python 3.12+, and installed OpenSSH server, UFW, unattended-upgrades, nftables and iptables tools.
- `ssh.service` and the APT daily timers must already be active and enabled. SSH socket activation is not supported; a default Ubuntu installation may need manual migration with console access before hardening.
- Complex SSH Match/custom Include configurations, active Docker/containerd, custom firewall tables/chains, and incompatible existing UFW rules need manual review.
- UFW must have IPv6 enabled and initialized IPv4/IPv6 rule files. Existing rules are not reset; standard UFW before/after exceptions remain.
- SSH access proof requires matching journal records for the fresh connection and successful non-root sudo access. Missing evidence blocks changes.

No packages are installed automatically. Security-update policy targets Ubuntu's `noble-security` origin and disables automatic reboot; third-party repositories are not covered.

## Vulnerability scanning

VPSGuard uses **OpenSCAP** to evaluate the selected distribution's official OVAL feed against local packages. It does not implement its own package-version matching. Vendor definitions account for distribution fixes within the feed's coverage.

Use **Python 3.10 or later** for the CLI: scanning calls `platform.freedesktop_os_release()`, introduced in 3.10. Older distribution defaults, notably Ubuntu 20.04 and RHEL-family 8/9, may need a newer trusted Python installation. Do not replace the operating system's Python or mix distribution repositories. Install `ca-certificates` and the native scanner package explicitly:

| Target | Package supplying `oscap` | Native installation command |
| --- | --- | --- |
| Ubuntu 20.04 / 22.04 | `libopenscap8` | `sudo apt-get install --no-install-recommends ca-certificates libopenscap8` |
| Ubuntu 24.04 / 26.04; Debian 12 / 13 | `openscap-scanner` | `sudo apt-get install --no-install-recommends ca-certificates openscap-scanner` |
| Debian 11 | No official scanner package in its release repository | Provision a compatible, trusted OpenSCAP separately; no cross-release repository mixing |
| RHEL 8/9; AlmaLinux and Oracle Linux 8/9/10; Rocky Linux 8/9 | `openscap-scanner` | `sudo dnf install ca-certificates openscap-scanner` |
| Listed SLES and openSUSE releases | `openscap-utils` | `sudo zypper install --no-recommends ca-certificates openscap-utils` |

Refresh native repository metadata as needed before manual installation (for example, `sudo apt-get update`). Installing OpenSCAP does not enable scans on audit-only targets or bypass stale-feed rejection. VPSGuard itself installs no packages.

```sh
sudo python3 vpsguard.py scan --output /var/lib/vpsguard-scan-001
```

Run scans as root for authenticated local probe access. The output directory must not already exist. Scanning downloads definitions and writes local evidence; it does not install fixes or modify firewall/SSH settings. `summary.json` contains definition-level findings, vendor severity and CVE references where supplied, evaluation counts, limitations and feed provenance. Raw OVAL results and an HTML report provide supporting evidence.

Read each finding's `class`: `vulnerability` identifies a matching vendor vulnerability definition; `patch` identifies an applicable vendor security advisory, not a complete inventory of CVEs. Security-advisory patch feeds are not interchangeable with CVE vulnerability feeds or a general all-updates inventory. A finding may reference multiple CVEs or none, and definition counts are not unique CVE counts. Coverage is limited to vendor-covered packages, releases, repositories and support entitlements.

The feed is fetched over verified HTTPS; recorded SHA-256 hashes identify downloaded bytes but are not detached publisher signatures. XML inputs have a 2 GiB ceiling and are parsed incrementally by VPSGuard; OpenSCAP itself can still require substantial memory. Resource exhaustion, stale feeds, missing evidence and unsupported evaluations must be treated as incomplete, not as a clean bill of health.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Complete evaluation with no matching finding-class definitions |
| `2` | Complete evaluation with vulnerability or security-advisory patch findings |
| `1` | Failed or incomplete evaluation; never interpret as clean |

**Coverage is not equivalent to Tenable Nessus.** This is an authenticated local vendor-package assessment, not a network, web-application, container-image, third-party dependency or exploit scanner. A complete evaluation only describes the supplied feed's coverage, not proof that the server is secure. Reports can contain sensitive host/package information; keep them private.

The manual **Verify native distro scans** GitHub Actions workflow is configured to run regression tests, then real native-package scans in disposable Debian 13, Ubuntu 24.04, AlmaLinux 9 and openSUSE Leap 16.0 containers. Fedora 43 and Amazon Linux 2023 containers exercise audit-only behavior. The scan checks require actual DPKG/RPM package-probe evidence, not merely a successful process exit. This is not host/kernel/firewall validation, does not exercise destructive hardening, and is not evidence that every listed release works. No passing workflow or test result is asserted here.

Live validation on 2026-11-16 completed the Ubuntu 24.04 scan and Fedora 43/Amazon Linux 2023 audits, but did **not** establish complete scanning on the other tested distributions. Debian's published feed declared a future generator timestamp and was rejected; its timestamp is not silently reinterpreted. AlmaLinux's feed server returned HTTP 403 to the CI runner. The openSUSE feed omitted criteria for 2,198 active definitions and required release package version `16.0`, while the official container installed `16.0+leap`. These failures are not clean vulnerability results; VPSGuard does not rewrite publisher definitions or bypass feed access restrictions. The workflow retains its complete-evaluation assertions so such failures stay visible.

## Safety boundaries

- Keep provider-console access and an independent backup before changing a server.
- Host hardening does not fix vulnerable applications, stolen cloud credentials, or provider-network exposure.
- Review every listening service before choosing a firewall allowlist. Docker-published ports can bypass ordinary host INPUT filtering.
- Security-update results depend on local package metadata. An old cache is not proof that a host is up to date.
- Configuration rollback is not a full system snapshot and cannot undo packages already upgraded by the operating system.
- Never upload audit reports without reviewing them: they can contain host addresses, account names, and service information.

## Development

No third-party Python dependencies. The CLI requires Python 3.10+; hardening targets Ubuntu 24.04 with Python 3.12+, and the container integration checks require Python 3.12+. Older-release Python/OpenSCAP combinations still need native validation; the support matrix describes configured profiles, not a tested-version certification.

```sh
python3 -m unittest discover -v
python3 vpsguard.py --help
```

Real SSH, firewall, systemd rollback, and automatic-update integration must be validated on a disposable Ubuntu VM before production deployment. Local unit tests alone do not establish lockout safety.
