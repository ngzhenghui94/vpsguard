"""Read-only Ubuntu 24.04 observations; successful collection is not a security pass."""

import json
import os
from pathlib import Path
import platform
import subprocess
import time


_TIMEOUT = 15
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_SSH_KEYS = {
    "port", "listenaddress", "permitrootlogin", "passwordauthentication",
    "kbdinteractiveauthentication", "pubkeyauthentication", "authenticationmethods",
    "permitemptypasswords", "usepam", "allowusers", "allowgroups", "denyusers",
    "denygroups", "maxauthtries", "x11forwarding", "allowtcpforwarding",
}


def _run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=_TIMEOUT,
                                env=_ENV, check=False, errors="replace")
    except FileNotFoundError:
        return None, "Command is not installed."
    except subprocess.TimeoutExpired:
        return None, "Command timed out."
    except OSError:
        return None, "Command could not be executed."
    if result.returncode:
        # Never echo diagnostics: command errors can contain configuration secrets.
        return None, f"Command failed (exit {result.returncode}); permissions may be required."
    return result.stdout, None


def _check(status, data=None, note=None):
    result = {"status": status, "data": data if data is not None else {}}
    if note:
        result["note"] = note
    return result


def _os_release():
    values = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "VERSION_ID", "PRETTY_NAME"}:
                values[key] = value.strip().strip("\"'")
    except (OSError, UnicodeError):
        pass
    return values


def _unsigned(value, maximum):
    if not value.isascii() or not value.isdecimal():
        return None
    try:
        number = int(value)
    except ValueError:
        return None
    return number if number <= maximum else None


def _ssh():
    text, error = _run(["sshd", "-T"])
    if error:
        return _check("unknown", note=error)
    settings = {}
    for line in text.splitlines():
        key, separator, value = line.partition(" ")
        if separator and key in _SSH_KEYS and value.strip():
            settings.setdefault(key, []).append(value.strip())
    required = {"port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication"}
    status = "ok" if required <= settings.keys() else "unknown"
    return _check(status, {"settings": settings, "scope": "global defaults"},
                  "sshd -T reads configuration on disk, not the running daemon. Match blocks "
                  "can change settings for individual connections; access is not verified.")


def _listeners():
    text, error = _run(["ss", "-H", "-lntu"])
    if error:
        return _check("unknown", note=error)
    listeners = []
    malformed = False
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            malformed = True
            continue
        address, separator, value = fields[4].rpartition(":")
        port = _unsigned(value, 65535)
        if not separator or not port:
            malformed = True
            continue
        listeners.append({"protocol": fields[0], "address": address.strip("[]"),
                          "port": port})
    return _check("unknown" if malformed else "ok", {"listeners": listeners},
                  "Local network namespace only; listeners do not prove Internet reachability.")


def _firewall():
    text, error = _run(["ufw", "status", "verbose"])
    if error:
        return _check("unknown", note=error + " Non-UFW rules were not inspected.")
    lines = [line.split("#", 1)[0].rstrip() for line in text.splitlines()]
    active = "Status: active" in lines
    inactive = "Status: inactive" in lines
    if active == inactive:
        return _check("unknown", note="UFW returned an unrecognized or conflicting status.")
    status = "ok" if active else "warning"
    return _check(status, {"backend": "ufw", "active": active, "rules": lines},
                  "UFW view only: other nftables/iptables rules, cloud firewalls and Docker "
                  "forwarding are not established by this output.")


def _cache_age():
    try:
        timestamps = [path.stat().st_mtime for path in Path("/var/lib/apt/lists").iterdir()
                      if path.name.endswith(("_InRelease", "_Release")) and path.is_file()]
    except OSError:
        return None
    if not timestamps or max(timestamps) > time.time():
        return None
    return round(time.time() - min(timestamps))


def _updates():
    age = _cache_age()
    data = {"cache_age_seconds": age, "cache_age_basis": "oldest cached repository Release mtime",
            "security_updates": [], "pending_candidate_count": None}
    text, error = _run(["apt", "list", "--upgradable", "-o", "APT::Color=0"])
    if error:
        return _check("unknown", data, error)
    malformed = False
    pending = 0
    for line in text.splitlines():
        if not line.strip() or line.startswith("Listing..."):
            continue
        fields = line.split()
        package, separator, suites = fields[0].partition("/")
        if not separator or len(fields) < 3:
            malformed = True
            continue
        pending += 1
        if any(suite.endswith("-security") for suite in suites.split(",")):
            data["security_updates"].append({"package": package, "version": fields[1],
                                             "architecture": fields[2]})
    data["pending_candidate_count"] = pending
    data["cache_stale_or_unknown"] = age is None or age > 86400
    # Candidate suites are not a complete security classification (e.g. superseded fixes).
    status = "warning" if data["security_updates"] else "unknown"
    if malformed:
        status = "unknown"
    return _check(status, data,
                  "No repository refresh performed. Counts use cached candidate suites only and "
                  "may miss superseded security fixes or held packages; zero is not proof that "
                  "the host is patched. Cache age is a file timestamp, not refresh verification.")


def _accounts():
    passwd, error = _run(["getent", "passwd"])
    if error:
        return _check("unknown", note=error)
    groups, error = _run(["getent", "group"])
    if error:
        return _check("unknown", note=error)
    privileged_groups = {}
    malformed = not groups.strip()
    for line in groups.splitlines():
        fields = line.split(":")
        gid = _unsigned(fields[2], 4294967295) if len(fields) == 4 else None
        if gid is None:
            malformed = True
            continue
        if fields[0] in {"sudo", "admin"}:
            privileged_groups[fields[0]] = (gid, set(filter(None, fields[3].split(","))))
    accounts = []
    seen = set()
    for line in passwd.splitlines():
        fields = line.split(":")
        uid = _unsigned(fields[2], 4294967295) if len(fields) == 7 else None
        gid = _unsigned(fields[3], 4294967295) if len(fields) == 7 else None
        if uid is None or gid is None:
            malformed = True
            continue
        name = fields[0]
        seen.add(name)
        memberships = [group for group, (group_id, members) in privileged_groups.items()
                       if gid == group_id or name in members]
        if uid == 0 or memberships:
            accounts.append({"name": name, "uid": uid, "groups": memberships})
    unresolved = sorted({member for _, members in privileged_groups.values()
                         for member in members if member not in seen})
    return _check("unknown" if malformed or not seen or unresolved else "ok",
                  {"accounts": accounts, "unresolved_group_members": unresolved},
                  "UID 0 and sudo/admin groups only; custom sudoers, polkit, capabilities and "
                  "non-enumerable directory users can grant additional privileges.")


def _docker():
    text, error = _run(["docker", "--host", "unix:///var/run/docker.sock", "ps", "--format",
                        '{{json .Ports}}'])
    if error:
        return _check("unknown", note=error + " Docker absence or port safety is not established.")
    if not text.strip():
        return _check("unknown", note="Docker returned no container observations; "
                      "Docker absence or port safety is not established.")
    published = []
    malformed = False
    for line in text.splitlines():
        try:
            ports = json.loads(line)
        except (ValueError, RecursionError):
            malformed = True
            continue
        if not isinstance(ports, str):
            malformed = True
        elif "->" in ports:
            published.append(ports)
    status = "unknown" if malformed else ("warning" if published else "ok")
    return _check(status, {"published_ports": published},
                  "Published Docker ports can bypass UFW. Only the local rootful Docker socket "
                  "was queried; rootless daemons, host networking and other runtimes are not covered.")


def run_audit():
    """Return JSON-safe observations without changing files, packages, services or firewall rules.

    ``checks`` maps names to ``status`` (ok/warning/unknown), ``data`` and ``note``.
    ``ok`` means the scoped observation succeeded without a known warning, not that
    the host is secure. Incomplete observations stay ``unknown`` even with warnings.
    Unsupported hosts return empty checks and never invoke host commands.
    """
    release = _os_release()
    supported = platform.system() == "Linux" and release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04"
    report = {"supported": supported, "platform": release, "checks": {}, "findings": []}
    if not supported:
        report["findings"].append({"check": "platform", "severity": "unknown",
                                   "message": "Unsupported host: requires Ubuntu 24.04 Linux; no commands were run."})
        return report
    checks = report["checks"]
    for name, collect in (("ssh", _ssh), ("listeners", _listeners), ("firewall", _firewall),
                          ("security_updates", _updates), ("privileged_accounts", _accounts),
                          ("docker", _docker)):
        try:
            checks[name] = collect()
        except (OSError, ValueError):
            checks[name] = _check("unknown", note="Observation could not be collected or parsed.")
        if checks[name]["status"] != "ok":
            report["findings"].append({"check": name, "severity": checks[name]["status"],
                                       "message": checks[name].get("note", "Review required.")})
    settings = checks["ssh"]["data"].get("settings", {})
    for key in ("passwordauthentication", "kbdinteractiveauthentication", "permitemptypasswords"):
        if "yes" in settings.get(key, []):
            report["findings"].append({"check": "ssh", "severity": "warning",
                                       "message": f"Global SSH {key} is enabled."})
    if settings.get("permitrootlogin") not in (None, ["no"]):
        report["findings"].append({"check": "ssh", "severity": "warning",
                                   "message": "Global SSH configuration permits some form of root login."})
    for account in checks["privileged_accounts"]["data"].get("accounts", []):
        if account["uid"] == 0 and account["name"] != "root":
            report["findings"].append({"check": "privileged_accounts", "severity": "warning",
                                       "message": f"Additional UID 0 account: {account['name']}"})
    for finding in report["findings"]:
        if finding["severity"] == "warning" and checks[finding["check"]]["status"] == "ok":
            checks[finding["check"]]["status"] = "warning"
    return report
