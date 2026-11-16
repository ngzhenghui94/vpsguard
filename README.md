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

## Supported hardening configuration

Auditing can report uncertainty on a wider range of configurations. Applying changes deliberately refuses configurations it cannot safely handle:

- Ubuntu 24.04 with running systemd, Python 3.12+, and installed OpenSSH server, UFW, unattended-upgrades, nftables and iptables tools.
- `ssh.service` and the APT daily timers must already be active and enabled. SSH socket activation is not supported; a default Ubuntu installation may need manual migration with console access before hardening.
- Complex SSH Match/custom Include configurations, active Docker/containerd, custom firewall tables/chains, and incompatible existing UFW rules need manual review.
- UFW must have IPv6 enabled and initialized IPv4/IPv6 rule files. Existing rules are not reset; standard UFW before/after exceptions remain.
- SSH access proof requires matching journal records for the fresh connection and successful non-root sudo access. Missing evidence blocks changes.

No packages are installed automatically. Security-update policy targets Ubuntu's `noble-security` origin and disables automatic reboot; third-party repositories are not covered.

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
