#!/usr/bin/env python3
"""Conservative Ubuntu 24.04 hardening with a persistent rollback transaction."""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time

STATE = Path('/var/lib/vpsguard')
UNITS = Path('/etc/systemd/system')
SSH_MAIN = Path('/etc/ssh/sshd_config')
SSH_DIR = Path('/etc/ssh/sshd_config.d')
SSH_DROP = SSH_DIR / '00-vpsguard.conf'
APT_DROP = Path('/etc/apt/apt.conf.d/99zz-vpsguard')
TARGETS = (SSH_MAIN, SSH_DIR, Path('/etc/ufw'), Path('/etc/default/ufw'), APT_DROP)
SAFE_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
TERMINAL = {'confirmed', 'rolled_back'}
SSH_TEXT = ('PermitRootLogin no\nPasswordAuthentication no\n'
            'KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n'
            'AuthenticationMethods publickey\n')
APT_TEXT = '''APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Allowed-Origins { "Ubuntu:noble-security"; };
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
'''


class Refusal(Exception):
    """An unsafe or unsupported condition; never interpreted as success."""


def run(*args, ok=(0,), timeout=60):
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout,
                                env={'PATH': SAFE_PATH, 'LC_ALL': 'C', 'HOME': '/root'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal(f'Cannot execute {args[0]}: {exc}') from exc
    if result.returncode not in ok:
        raise Refusal(f'{shlex.join(args)} failed ({result.returncode}): '
                      f'{result.stderr.strip() or result.stdout.strip()}')
    return result


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def require_root():
    if os.geteuid() != 0:
        raise Refusal('This command requires root. Audit can run without root.')


def require_platform():
    values = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip('"')
    if values.get('ID') != 'ubuntu' or values.get('VERSION_ID') != '24.04':
        raise Refusal('Only Ubuntu 24.04 is supported; no changes made.')
    if not Path('/run/systemd/system').is_dir():
        raise Refusal('A running systemd system is required.')


def trusted(path, directory=False):
    """Reject links and writable/non-root-owned ancestors, including the leaf."""
    path = Path(path)
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if part == path:
                return False
            raise Refusal(f'Missing parent directory: {part}')
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Refusal(f'Unsafe ownership, permissions or symlink: {part}')
        if part != path or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise Refusal(f'Not a directory: {part}')
        elif not stat.S_ISREG(info.st_mode):
            raise Refusal(f'Not a regular file: {part}')
    return True


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    trusted(path)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextlib.contextmanager
def locked():
    require_root()
    if not trusted(STATE, directory=True):
        STATE.mkdir(mode=0o700)
        sync_dir(STATE.parent)
    if stat.S_IMODE(STATE.stat().st_mode) != 0o700:
        raise Refusal(f'{STATE} must have mode 0700.')
    lockfile = STATE / 'lock'
    trusted(lockfile)
    fd = os.open(lockfile, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise Refusal('Another vpsguard command is running; retry after it finishes.') from exc
    try:
        yield
    finally:
        os.close(fd)


def snapshot(paths=None):
    result = {}
    if paths is None:
        paths = TARGETS
    for root in paths:
        root = Path(root)
        exists = root.exists() or root.is_symlink()
        if not exists:
            trusted(root)
            result[str(root)] = {'kind': 'absent'}
            continue
        entries = [root]
        if root.is_dir() and not root.is_symlink():
            entries += sorted(root.rglob('*'))
        for path in entries:
            directory = path.is_dir() and not path.is_symlink()
            trusted(path, directory=directory)
            info = path.stat()
            record = {'kind': 'directory' if directory else 'file',
                      'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
            if not directory:
                record['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            result[str(path)] = record
    return result


def allow_port(value):
    match = re.fullmatch(r'(tcp|udp):([0-9]{1,5})', value)
    if not match or not 1 <= int(match[2]) <= 65535:
        raise argparse.ArgumentTypeError('Use tcp:PORT or udp:PORT, with PORT 1..65535.')
    return f'{match[1]}:{int(match[2])}'


def exposed_ports(text):
    ports = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ('tcp', 'udp'):
            raise Refusal(f'Unrecognized ss listener: {line}')
        host, separator, port = fields[4].rpartition(':')
        if not separator or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise Refusal(f'Unrecognized listener address: {fields[4]}')
        host = host.strip('[]').split('%', 1)[0]
        if host != '*':
            try:
                if ipaddress.ip_address(host).is_loopback:
                    continue
            except ValueError as exc:
                raise Refusal(f'Unrecognized listener address: {host}') from exc
        ports.add(f'{fields[0]}:{int(port)}')
    return sorted(ports)


def firewall_inventory(text):
    table = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or line == 'COMMIT':
            continue
        if line.startswith('*'):
            table = line[1:]
        elif line.startswith(':'):
            chain = line[1:].split()[0]
            if chain not in {'INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING'} and not chain.startswith('ufw-'):
                raise Refusal(f'Unmanaged firewall chain {chain}; Docker/CNI rules are not protected by UFW.')
        elif line.startswith('-A '):
            fields = shlex.split(line)
            if table != 'filter':
                raise Refusal('Existing NAT/raw/mangle rules are unsupported; no firewall reset is performed.')
            if not fields[1].startswith('ufw-'):
                if len(fields) != 4 or fields[2] != '-j' or not fields[3].startswith('ufw-'):
                    raise Refusal(f'Unmanaged firewall rule: {line}')
        else:
            raise Refusal(f'Unrecognized firewall inventory: {line}')


def ssh_configuration():
    if not trusted(SSH_MAIN) or not trusted(SSH_DIR, directory=True):
        raise Refusal('Standard sshd_config and sshd_config.d directory are required.')
    names = sorted(SSH_DIR.glob('*.conf'))
    if names and names[0].name < SSH_DROP.name:
        raise Refusal('An SSH drop-in sorts before 00-vpsguard.conf; refusing ambiguous precedence.')
    main = SSH_MAIN.read_text()
    active = [line.strip() for line in main.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    include = 'Include /etc/ssh/sshd_config.d/*.conf'
    if not active or active[0] != include:
        raise Refusal(f'The first SSH directive must be exactly: {include}')
    for path, text in [(SSH_MAIN, main)] + [(path, path.read_text()) for path in names]:
        trusted(path)
        for line in text.splitlines():
            directive = line.strip().split(None, 1)
            if not directive or directive[0].startswith('#'):
                continue
            if directive[0].lower() == 'match':
                raise Refusal('SSH Match blocks require manual review and are unsupported.')
            if directive[0].lower() == 'include' and not (path == SSH_MAIN and line.strip() == include):
                raise Refusal('Custom or nested SSH Includes are unsupported.')
    run('sshd', '-t')
    effective = {}
    for line in run('sshd', '-T').stdout.splitlines():
        key, _, value = line.partition(' ')
        effective.setdefault(key, []).append(value)
    if len(effective.get('port', [])) != 1:
        raise Refusal('Exactly one SSH port is supported.')
    if effective.get('pubkeyauthentication') != ['yes']:
        raise Refusal('SSH public-key authentication must already be enabled.')
    if effective.get('authenticationmethods') not in (['any'], ['publickey']):
        raise Refusal('Existing SSH multi-factor authentication will not be weakened.')
    return effective


def preflight(allow):
    require_root()
    require_platform()
    for command in ('iptables', 'ip6tables'):
        if '(nf_tables)' not in run(command, '--version').stdout:
            raise Refusal('Only the Ubuntu nftables-backed iptables alternatives are supported.')
    tools = ('sshd', 'ss', 'ufw', 'systemctl', 'journalctl', 'iptables-save', 'ip6tables-save',
             'iptables', 'ip6tables', 'nft', 'apt-config', 'unattended-upgrade', 'dpkg-query')
    for command in tools:
        if shutil.which(command, path=SAFE_PATH) is None:
            raise Refusal(f'Prerequisite missing: {command}. Install/configure it manually, then re-plan.')
    for package in ('openssh-server', 'ufw', 'unattended-upgrades'):
        if run('dpkg-query', '-W', '-f=${Status}', package).stdout.strip() != 'install ok installed':
            raise Refusal(f'Prerequisite package is not fully installed: {package}')
    if run('systemctl', 'is-active', 'ssh.socket', ok=(0, 3, 4)).returncode == 0 or run(
            'systemctl', 'is-enabled', 'ssh.socket', ok=(0, 1, 3, 4)).returncode == 0:
        raise Refusal('ssh.socket activation is unsupported. Manually migrate to ssh.service with console access, then re-plan.')
    for unit in ('ssh.service', 'apt-daily.timer', 'apt-daily-upgrade.timer'):
        run('systemctl', 'is-active', '--quiet', unit)
        run('systemctl', 'is-enabled', '--quiet', unit)
    for unit in ('docker.service', 'docker.socket', 'containerd.service'):
        if run('systemctl', 'is-active', unit, ok=(0, 3, 4)).returncode == 0:
            raise Refusal(f'{unit} is active. Docker/container networking bypasses UFW; unsupported.')
    ssh = ssh_configuration()
    allow = sorted(set(allow))
    if not allow or f'tcp:{ssh["port"][0]}' not in allow:
        raise Refusal('The explicit --allow list must include the current SSH TCP port.')
    listeners = exposed_ports(run('ss', '-H', '-lntu').stdout)
    missing = sorted(set(listeners) - set(allow))
    if missing:
        raise Refusal(f'Allow every non-loopback listener explicitly before proceeding: {", ".join(missing)}')
    for command in ('iptables-save', 'ip6tables-save'):
        saved = run(command)
        if saved.stderr.strip():
            raise Refusal(f'Firewall inspection reported uncertainty: {saved.stderr.strip()}')
        firewall_inventory(saved.stdout)
    nft = json.loads(run('nft', '-j', 'list', 'ruleset').stdout)
    for entry in nft.get('nftables', []):
        if 'table' in entry:
            table = entry['table']
            if table.get('family') not in ('ip', 'ip6') or table.get('name') not in ('filter', 'nat', 'mangle', 'raw', 'security'):
                raise Refusal('Native nftables/custom tables are unsupported; UFW cannot protect them.')
    for line in run('ufw', 'show', 'added').stdout.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line == "Added user rules (see 'ufw status' for running firewall):":
            continue
        match = re.fullmatch(r'ufw allow ([0-9]+)/(tcp|udp)', line)
        if not match or f'{match[2]}:{int(match[1])}' not in allow:
            raise Refusal(f'Existing UFW rule needs manual review: {line}. No rules are deleted/reset.')
    ufw_status = run('ufw', 'status').stdout
    if not (ufw_status.startswith('Status: active\n') or ufw_status.strip() == 'Status: inactive'):
        raise Refusal('Cannot determine UFW state.')
    if not re.search(r'^IPV6=yes\s*$', Path('/etc/default/ufw').read_text(), re.MULTILINE):
        raise Refusal('UFW IPv6 support must already be enabled (IPV6=yes).')
    apt_files = [p.name for p in APT_DROP.parent.iterdir() if re.fullmatch(r'[A-Za-z0-9_-]+', p.name)]
    if any(name > APT_DROP.name for name in apt_files):
        raise Refusal('An APT configuration sorts after 99zz-vpsguard; unsupported precedence.')
    files = snapshot()
    for version in ('', '6'):
        for prefix in ('before', 'after', 'user'):
            if files.get(f'/etc/ufw/{prefix}{version}.rules', {}).get('kind') != 'file':
                raise Refusal('All six UFW before/after/user IPv4/IPv6 rules files must exist; initialize UFW manually first.')
    run('ufw', '--dry-run', 'enable')
    # Include all APT inputs in the approval digest, without backing up files we never change.
    apt_inputs = snapshot((APT_DROP.parent, Path('/etc/apt/apt.conf')))
    plan = {'version': 1, 'allow': allow, 'ssh_port': int(ssh['port'][0]),
            'listeners': listeners, 'ufw_active': ufw_status.startswith('Status: active\n'),
            'files': files, 'apt_inputs': apt_inputs,
            'changes': ['SSH: public keys only; disable root and password/keyboard-interactive login',
                        'UFW: preserve existing rules, add listed ports, deny incoming, allow outgoing, enable IPv4/IPv6',
                        'APT: automatic Ubuntu noble-security updates only; no automatic reboot'],
            'warnings': ['UFW standard before/after rules remain in force, including their exceptions.',
                         'Docker/container-published ports are not protected by this policy.',
                         'No service/configuration edits should be made while rollback is pending.']}
    plan['digest'] = digest(plan)
    return plan


def transaction_path(identifier):
    if not re.fullmatch(r'[0-9a-f]{24}', identifier):
        raise Refusal('Invalid transaction identifier.')
    return STATE / identifier


def save_state(state):
    atomic_write(transaction_path(state['id']) / 'state.json', json.dumps(state, sort_keys=True, indent=2) + '\n')


def load_state(identifier=None):
    if identifier is None:
        active = STATE / 'active'
        if not trusted(active):
            return None
        identifier = active.read_text().strip()
    path = transaction_path(identifier) / 'state.json'
    if not trusted(path):
        raise Refusal('Transaction does not exist.')
    state = json.loads(path.read_text())
    if state.get('id') != identifier or state.get('version') != 1:
        raise Refusal('Invalid transaction state.')
    return state


def backup(plan, identifier):
    directory = transaction_path(identifier)
    directory.mkdir(mode=0o700)
    (directory / 'backup').mkdir(mode=0o700)
    for name, item in plan['files'].items():
        if item['kind'] == 'file':
            data = Path(name).read_bytes()
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise Refusal(f'Configuration changed during backup: {name}; re-plan.')
            atomic_write(directory / 'backup' / hashlib.sha256(name.encode()).hexdigest(), data)
    atomic_write(directory / 'runner.py', Path(__file__).read_bytes())
    sync_dir(directory)
    sync_dir(STATE)


def unit_name(state):
    return 'vpsguard-rollback-' + state['id']


def arm_rollback(state):
    name = unit_name(state)
    runner = transaction_path(state['id']) / 'runner.py'
    deadline = datetime.datetime.fromtimestamp(state['deadline'], datetime.timezone.utc)
    service = ('[Unit]\nDescription=Restore vpsguard transaction\nAfter=local-fs.target\n'
               'StartLimitIntervalSec=0\n'
               '[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=5min\n'
               f'ExecStart=/usr/bin/python3 {runner} rollback {state["id"]} --scheduled\n'
               'Restart=on-failure\nRestartSec=30s\n')
    timer = ('[Unit]\nDescription=Rollback unconfirmed vpsguard changes\n'
             '[Timer]\n'
             f'OnCalendar={deadline.strftime("%Y-%m-%d %H:%M:%S UTC")}\n'
             'Persistent=true\nAccuracySec=1s\n'
             '[Install]\nWantedBy=timers.target\n')
    atomic_write(UNITS / (name + '.service'), service, 0o644)
    atomic_write(UNITS / (name + '.timer'), timer, 0o644)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', name + '.timer')
    run('systemctl', 'is-active', '--quiet', name + '.timer')
    next_time = run('systemctl', 'show', name + '.timer', '--property=NextElapseUSecRealtime', '--value').stdout.strip()
    if not next_time or next_time == 'n/a':
        raise Refusal('Rollback timer has no scheduled deadline; refusing changes.')


def disarm_rollback(state):
    name = unit_name(state)
    timer = UNITS / (name + '.timer')
    if timer.exists():
        run('systemctl', 'disable', '--now', name + '.timer')
    for suffix in ('.timer', '.service'):
        path = UNITS / (name + suffix)
        trusted(path)
        path.unlink(missing_ok=True)
    sync_dir(UNITS)
    run('systemctl', 'daemon-reload')


def prove_access(since):
    """Bind a recent sshd public-key journal event to THIS non-root sudo session."""
    require_root()
    user = os.environ.get('SUDO_USER', '')
    uid = os.environ.get('SUDO_UID', '')
    if not uid.isdecimal() or int(uid) == 0 or not user or pwd.getpwnam(user).pw_uid != int(uid):
        raise Refusal('Run through sudo from a non-root SSH account, not a root shell.')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) != 4 or not connection[1].isdecimal() or not connection[3].isdecimal():
        raise Refusal('Preserve SSH_CONNECTION through sudo: sudo --preserve-env=SSH_CONNECTION ...')
    for address in (connection[0], connection[2]):
        try:
            if ipaddress.ip_address(address).is_loopback:
                raise Refusal('A separate external SSH client is required; loopback proofs are refused.')
        except ValueError as exc:
            raise Refusal('Invalid SSH_CONNECTION address.') from exc
    pids = []
    parent = os.getppid()
    sudo_seen = False
    visited = set()
    while parent > 1 and parent not in visited:
        visited.add(parent)
        process = Path('/proc') / str(parent)
        comm = (process / 'comm').read_text().strip()
        status = (process / 'status').read_text()
        if comm == 'sudo':
            sudo_seen = True
        if comm == 'sshd':
            pids.append(parent)
        match = re.search(r'^PPid:\s+(\d+)$', status, re.MULTILINE)
        if not match:
            raise Refusal('Cannot establish SSH process ancestry.')
        parent = int(match[1])
    if not sudo_seen or not pids:
        raise Refusal('No independent sshd + sudo ancestry found; do not use tmux/screen or a root shell.')
    service_pid = run('systemctl', 'show', 'ssh.service', '--property=MainPID', '--value').stdout.strip()
    if not service_pid.isdecimal() or int(service_pid) not in visited:
        raise Refusal('This SSH session is not descended from the managed ssh.service.')
    expected = f'Accepted publickey for {user} from {connection[0]} port {connection[1]} ssh2:'
    for pid in pids:
        output = run('journalctl', '-b', '--no-pager', '-o', 'json', '--since', f'@{since:.6f}', f'_PID={pid}', '_COMM=sshd').stdout
        for line in output.splitlines():
            event = json.loads(line)
            message = event.get('MESSAGE', '')
            timestamp = int(event.get('__REALTIME_TIMESTAMP', '0')) / 1_000_000
            if isinstance(message, str) and message.startswith(expected) and timestamp >= since and timestamp <= time.time():
                return {'user': user, 'uid': int(uid), 'client': connection[0],
                        'server_port': int(connection[3]), 'login_at': timestamp, 'verified_at': time.time()}
    raise Refusal('No fresh public-key SSH login for this process found in journal. Open a NEW connection with ControlMaster=no and ControlPath=none; missing logs never count as proof.')


def verify_access(identifier):
    with locked():
        state = load_state(identifier)
        if state['status'] != 'awaiting_access':
            raise Refusal('This transaction is not awaiting access verification.')
        proof = prove_access(state['created_at'])
        if proof['server_port'] != state['plan']['ssh_port']:
            raise Refusal('The verified SSH connection used a different port.')
        state['proof'] = proof
        save_state(state)
        return {'id': identifier, 'status': 'access_verified', 'user': proof['user'],
                'next': 'Re-run the identical apply command within ten minutes.'}


def validate_effective():
    run('sshd', '-t')
    ssh = dict(line.split(' ', 1) for line in run('sshd', '-T').stdout.splitlines())
    for key, value in (('permitrootlogin', 'no'), ('passwordauthentication', 'no'),
                       ('kbdinteractiveauthentication', 'no'), ('pubkeyauthentication', 'yes'),
                       ('authenticationmethods', 'publickey')):
        if ssh.get(key) != value:
            raise Refusal(f'Effective SSH setting did not take effect: {key}')
    apt = run('apt-config', 'dump').stdout
    expected = {'APT::Periodic::Enable': '1', 'APT::Periodic::Update-Package-Lists': '1',
                'APT::Periodic::Unattended-Upgrade': '1',
                'Unattended-Upgrade::Automatic-Reboot': 'false',
                'Unattended-Upgrade::Automatic-Reboot-WithUsers': 'false'}
    for key, value in expected.items():
        if f'{key} "{value}";' not in apt.splitlines():
            raise Refusal(f'Effective APT setting did not take effect: {key}')
    origins = [line for line in apt.splitlines() if line.startswith('Unattended-Upgrade::Allowed-Origins::')]
    patterns = [line for line in apt.splitlines() if line.startswith('Unattended-Upgrade::Origins-Pattern::')]
    if origins != ['Unattended-Upgrade::Allowed-Origins:: "Ubuntu:noble-security";'] or patterns:
        raise Refusal('Effective unattended-upgrade origins are not security-only.')


def change_configuration(state):
    atomic_write(SSH_DROP, SSH_TEXT, 0o644)
    atomic_write(APT_DROP, APT_TEXT, 0o644)
    validate_effective()
    # Add all service rules before changing policy or enabling the firewall; never reset it.
    for item in state['plan']['allow']:
        protocol, port = item.split(':')
        run('ufw', 'allow', f'{port}/{protocol}')
    run('ufw', 'default', 'deny', 'incoming')
    run('ufw', 'default', 'allow', 'outgoing')
    run('ufw', '--force', 'enable')
    if not run('ufw', 'status').stdout.startswith('Status: active\n'):
        raise Refusal('UFW did not become active.')
    run('systemctl', 'reload', 'ssh.service')
    run('systemctl', 'is-active', '--quiet', 'ssh.service')


def validate_backups(state):
    files = state['plan']['files']
    directory = transaction_path(state['id'])
    data = {}
    for name, item in files.items():
        if not any(Path(name) == root or root in Path(name).parents for root in TARGETS):
            raise Refusal(f'Backup path outside managed scope: {name}')
        if item['kind'] == 'file':
            path = directory / 'backup' / hashlib.sha256(name.encode()).hexdigest()
            if not trusted(path):
                raise Refusal(f'Missing backup for {name}')
            data[name] = path.read_bytes()
            if hashlib.sha256(data[name]).hexdigest() != item['sha256']:
                raise Refusal(f'Corrupt backup for {name}; rollback not attempted.')
    include = 'Include /etc/ssh/sshd_config.d/*.conf'
    snippets = '\n'.join(data[name].decode() for name in sorted(data)
                         if Path(name).parent == SSH_DIR and name.endswith('.conf'))
    original = data[str(SSH_MAIN)].decode()
    candidate = '\n'.join(snippets if line.strip() == include else line for line in original.splitlines()) + '\n'
    validation = directory / 'validate-sshd.conf'
    atomic_write(validation, candidate)
    run('sshd', '-t', '-f', str(validation))
    return data


def restore_configuration(state):
    data = validate_backups(state)
    files = state['plan']['files']
    # Validate every current target before changing anything; never follow a newly introduced link.
    current = snapshot()
    for name in sorted(current, key=lambda value: (len(Path(value).parts), value), reverse=True):
        if name not in files or files[name]['kind'] == 'absent':
            path = Path(name)
            if current[name]['kind'] == 'directory':
                path.rmdir()
            elif current[name]['kind'] == 'file':
                path.unlink()
            sync_dir(path.parent)
    for name, item in sorted(files.items(), key=lambda pair: (len(Path(pair[0]).parts), pair[0])):
        path = Path(name)
        if item['kind'] == 'absent':
            continue
        if item['kind'] == 'directory':
            path.mkdir(mode=item['mode'], exist_ok=True)
        else:
            atomic_write(path, data[name], item['mode'])
        os.chown(path, item['uid'], item['gid'])
        os.chmod(path, item['mode'])
    run('sshd', '-t')
    run('ufw', '--dry-run', 'enable' if state['plan']['ufw_active'] else 'disable')
    if state['plan']['ufw_active']:
        run('ufw', '--force', 'enable')
        run('ufw', 'reload')
    else:
        run('ufw', '--force', 'disable')
    run('systemctl', 'reload', 'ssh.service')
    run('systemctl', 'is-active', '--quiet', 'ssh.service')


def rollback_locked(state):
    if state['status'] in TERMINAL:
        disarm_rollback(state)
        return {'id': state['id'], 'status': state['status']}
    if state['status'] == 'awaiting_access':
        state['status'] = 'rolled_back'
        save_state(state)
        disarm_rollback(state)
        return {'id': state['id'], 'status': 'rolled_back', 'changed': False}
    state['status'] = 'rolling_back'
    save_state(state)
    try:
        restore_configuration(state)
    except Exception as exc:
        state['status'] = 'rollback_failed'
        state['error'] = str(exc)
        save_state(state)
        raise Refusal(f'Rollback failed; timer/service retained for retry. Use provider console. {exc}') from exc
    state['status'] = 'rolled_back'
    save_state(state)
    disarm_rollback(state)
    return {'id': state['id'], 'status': 'rolled_back'}


def rollback(identifier):
    with locked():
        return rollback_locked(load_state(identifier))


def apply_plan(allow, approval, rollback_minutes):
    with locked():
        plan = preflight(allow)
        if approval != plan['digest']:
            raise Refusal(f'Approval must match the current plan digest: {plan["digest"]}. Re-plan and review.')
        state = load_state()
        if state and state['status'] not in TERMINAL:
            if state['status'] != 'awaiting_access':
                raise Refusal(f'Transaction {state["id"]} is {state["status"]}; confirm or rollback it first.')
            if state['plan']['digest'] != approval:
                raise Refusal('An outstanding prepared transaction has a different plan; rollback it first.')
        else:
            identifier = secrets.token_hex(12)
            backup(plan, identifier)
            state = {'version': 1, 'id': identifier, 'created_at': time.time(),
                     'status': 'awaiting_access', 'plan': plan}
            save_state(state)
            atomic_write(STATE / 'active', identifier + '\n')
        if not state.get('proof'):
            return {'id': state['id'], 'status': 'awaiting_access', 'changed': False,
                    'next': f'From a NEW external public-key SSH connection, run: sudo --preserve-env=SSH_CONNECTION /usr/bin/python3 {transaction_path(state["id"]) / "runner.py"} verify-access {state["id"]}'}
        if not 0 <= time.time() - state['proof']['verified_at'] <= 600:
            state.pop('proof')
            state['created_at'] = time.time()
            save_state(state)
            raise Refusal('Access proof expired. Open a new SSH connection and run verify-access again.')
        state['deadline'] = time.time() + rollback_minutes * 60
        state['status'] = 'arming'
        save_state(state)
        arm_rollback(state)
        if time.time() >= state['deadline']:
            rollback_locked(state)
            raise Refusal('Rollback deadline elapsed while arming; no hardening changes were started.')
        state['status'] = 'applying'
        save_state(state)
        try:
            change_configuration(state)
            state['changed_at'] = time.time()
            state['applied_files'] = snapshot()
            state['status'] = 'applied'
            save_state(state)
        except Exception as exc:
            rollback_locked(state)
            raise Refusal(f'Apply failed and configuration was rolled back: {exc}') from exc
        return {'id': state['id'], 'status': 'applied', 'rollback_at': state['deadline'],
                'next': f'Open another NEW external SSH connection and run: sudo --preserve-env=SSH_CONNECTION /usr/bin/python3 {transaction_path(state["id"]) / "runner.py"} confirm {state["id"]}'}


def confirm(identifier):
    with locked():
        state = load_state(identifier)
        if state['status'] != 'applied':
            raise Refusal('Only an applied, unexpired transaction can be confirmed.')
        if time.time() >= state['deadline']:
            rollback_locked(state)
            raise Refusal('The confirmation deadline elapsed; rollback completed.')
        proof = prove_access(state['changed_at'])
        if proof['uid'] != state['proof']['uid'] or proof['server_port'] != state['plan']['ssh_port']:
            raise Refusal('Confirm using the same non-root account and SSH port that were verified before apply.')
        validate_effective()
        if snapshot() != state['applied_files']:
            raise Refusal('Managed configuration changed since apply; refusing confirmation. Rollback remains armed.')
        if not run('ufw', 'status').stdout.startswith('Status: active\n'):
            raise Refusal('UFW is no longer active; rollback remains armed.')
        if time.time() >= state['deadline']:
            rollback_locked(state)
            raise Refusal('The confirmation deadline elapsed during verification; rollback completed.')
        state['status'] = 'confirmed'
        state['confirmation'] = proof
        save_state(state)
        disarm_rollback(state)
        return {'id': identifier, 'status': 'confirmed', 'backups': str(transaction_path(identifier) / 'backup')}


def parser():
    result = argparse.ArgumentParser(description=__doc__, epilog='No command means audit. Keep provider-console access. Plan is read-only; apply requires exact digest approval and a fresh independent key+sudo SSH proof. No packages are installed.')
    sub = result.add_subparsers(dest='command')
    sub.add_parser('audit', help='Read-only host observations, returned as JSON')
    for name in ('plan', 'apply'):
        command = sub.add_parser(name, help='Inspect and print a read-only plan' if name == 'plan' else 'Prepare/resume an explicitly approved transaction')
        command.add_argument('--allow', type=allow_port, action='append', required=True, metavar='tcp:PORT', help='Repeat for EVERY externally bound TCP/UDP service, including SSH')
        if name == 'apply':
            command.add_argument('--approve', required=True, metavar='SHA256', help='Exact digest from the reviewed plan')
            command.add_argument('--rollback-minutes', type=int, default=5, choices=range(2, 31), metavar='2..30', help='Confirmation window (default: 5 minutes)')
    for name in ('verify-access', 'confirm', 'rollback'):
        command = sub.add_parser(name, help={'verify-access': 'Prove a fresh public-key SSH login and non-root sudo access', 'confirm': 'Keep changes after another fresh SSH+sudo login', 'rollback': 'Restore a transaction from verified backups'}[name])
        command.add_argument('transaction', metavar='ID')
        if name == 'rollback':
            command.add_argument('--scheduled', action='store_true', help=argparse.SUPPRESS)
    sub.add_parser('status', help='Read the latest durable transaction state (root only)')
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command in (None, 'audit'):
            from audit import run_audit
            output = run_audit()
        elif args.command == 'plan':
            output = preflight(args.allow)
        elif args.command == 'apply':
            output = apply_plan(args.allow, args.approve, args.rollback_minutes)
        elif args.command == 'verify-access':
            output = verify_access(args.transaction)
        elif args.command == 'confirm':
            output = confirm(args.transaction)
        elif args.command == 'rollback':
            require_root()
            require_platform()
            output = rollback(args.transaction)
        else:
            require_root()
            output = load_state() or {'status': 'none'}
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (Refusal, OSError, ValueError, KeyError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
