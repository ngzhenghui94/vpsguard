# VPSGuard

A Python-standard-library command-line tool for auditing and hardening Ubuntu 24.04 LTS VPS hosts. Read-only auditing is the default; configuration changes require explicit approval.

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

## Supported hardening configuration

Auditing can report uncertainty on a wider range of configurations. Applying changes deliberately refuses configurations it cannot safely handle:

- Ubuntu 24.04 with running systemd, Python 3.12+, and installed OpenSSH server, UFW, unattended-upgrades, nftables and iptables tools.
- `ssh.service` and the APT daily timers must already be active and enabled. SSH socket activation is not supported; a default Ubuntu installation may need manual migration with console access before hardening.
- Complex SSH Match/custom Include configurations, active Docker/containerd, custom firewall tables/chains, and incompatible existing UFW rules need manual review.
- UFW must have IPv6 enabled and initialized IPv4/IPv6 rule files. Existing rules are not reset; standard UFW before/after exceptions remain.
- SSH access proof requires matching journal records for the fresh connection and successful non-root sudo access. Missing evidence blocks changes.

No packages are installed automatically. Security-update policy targets Ubuntu's `noble-security` origin and disables automatic reboot; third-party repositories are not covered.

## Vulnerability scanning

VPSGuard uses **OpenSCAP** to evaluate Canonical's official Ubuntu 24.04 **CVE OVAL** feed against the local host. It does not implement its own package-version matching. Canonical's Ubuntu-specific vulnerability definitions account for distribution fixes; see [Ubuntu OVAL documentation](https://documentation.ubuntu.com/security/security-updates/oval/).

Install the external scanner explicitly on the Ubuntu host:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends openscap-scanner
sudo python3 vpsguard.py scan --output /var/lib/vpsguard-scan-001
```

The output directory must not already exist. Scanning downloads vulnerability definitions and writes local evidence; it does not install fixes or modify firewall/SSH settings. The report contains definition-level findings, Canonical severity and CVE references, evaluation counts, and feed provenance. Raw OVAL results and an HTML report provide supporting evidence.

Run scans as root on Ubuntu 24.04 so local package probes can collect their evidence. The feed is fetched over verified HTTPS; recorded SHA-256 hashes identify the downloaded bytes but are not detached publisher signatures. XML inputs are limited to 256 MiB each, and parsing large feeds/results can use substantial memory. Resource exhaustion, stale feeds, missing evidence, and unsupported evaluations must be treated as incomplete, not as a clean bill of health.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Complete evaluation with no matching vulnerability definitions |
| `2` | Complete evaluation with vulnerability findings |
| `1` | Failed or incomplete evaluation; never interpret as clean |

**Coverage is not equivalent to Tenable Nessus.** This is an authenticated local Ubuntu package assessment, not a network, web-application, container-image, third-party dependency, or exploit scanner. A complete evaluation only describes the supplied feed's coverage, not proof that the server is secure. Reports can contain sensitive host/package information; keep them private.

The manual **Verify Ubuntu scanner** GitHub Actions workflow runs regression tests and the real scanner on a disposable Ubuntu 24.04 runner. It does not connect to your VPS or exercise destructive hardening.

## Safety boundaries

- Keep provider-console access and an independent backup before changing a server.
- Host hardening does not fix vulnerable applications, stolen cloud credentials, or provider-network exposure.
- Review every listening service before choosing a firewall allowlist. Docker-published ports can bypass ordinary host INPUT filtering.
- Security-update results depend on local package metadata. An old cache is not proof that a host is up to date.
- Configuration rollback is not a full system snapshot and cannot undo packages already upgraded by the operating system.
- Never upload audit reports without reviewing them: they can contain host addresses, account names, and service information.

## Development

Requires Python 3.12 or later on the supported Ubuntu target. No third-party Python dependencies.

```sh
python3 -m unittest discover -v
python3 vpsguard.py --help
```

Real SSH, firewall, systemd rollback, and automatic-update integration must be validated on a disposable Ubuntu VM before production deployment. Local unit tests alone do not establish lockout safety.
