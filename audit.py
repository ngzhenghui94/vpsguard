"""Read-only Linux observations; successful collection is not a security pass."""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

from profiles import select_profile


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
    backends = {}
    incomplete = False
    warning = False
    for command in ("ufw", "firewall-cmd", "nft"):
        if not shutil.which(command, path=_ENV["PATH"]):
            continue
        backend = {"ufw": "ufw", "firewall-cmd": "firewalld", "nft": "nftables"}[command]
        args = {"ufw": ["ufw", "status", "verbose"],
                "firewall-cmd": ["firewall-cmd", "--state"],
                "nft": ["nft", "--json", "list", "ruleset"]}[command]
        text, error = _run(args)
        if error:
            backends[backend] = _check("unknown", note=error)
            incomplete = True
            continue
        if command == "ufw":
            lines = [line.split("#", 1)[0].rstrip() for line in text.splitlines()]
            active = "Status: active" in lines
            inactive = "Status: inactive" in lines
            if active == inactive:
                backends[backend] = _check("unknown", note="Unrecognized or conflicting UFW status.")
                incomplete = True
                continue
            backends[backend] = _check("ok" if active else "warning",
                                       {"active": active, "rules": lines})
            warning |= inactive
        elif command == "firewall-cmd":
            if text.strip() != "running":
                backends[backend] = _check("unknown", note="firewalld is not confirmed running.")
                incomplete = True
                continue
            zones, error = _run(["firewall-cmd", "--get-active-zones"])
            rules, rules_error = _run(["firewall-cmd", "--list-all-zones"])
            backends[backend] = _check(
                "unknown" if error or rules_error or not rules.strip() else "ok",
                {"active": True, "active_zones": zones.splitlines() if zones is not None else [],
                 "zones": rules.splitlines() if rules is not None else []},
                error or rules_error)
            incomplete |= backends[backend]["status"] == "unknown"
        else:
            try:
                entries = json.loads(text)["nftables"]
                if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                    raise ValueError("Invalid ruleset")
                chains = []
                rule_count = 0
                for entry in entries:
                    if "chain" in entry:
                        chain = entry["chain"]
                        if not isinstance(chain, dict):
                            raise ValueError("Invalid chain")
                        chains.append({key: chain[key] for key in
                                       ("family", "table", "name", "type", "hook", "prio", "policy")
                                       if key in chain})
                    if "rule" in entry:
                        if not isinstance(entry["rule"], dict):
                            raise ValueError("Invalid rule")
                        rule_count += 1
                backends[backend] = _check("ok" if chains else "warning",
                                           {"chains": chains, "rule_count": rule_count})
                warning |= not chains
            except (ValueError, KeyError, TypeError, RecursionError):
                backends[backend] = _check("unknown", note="Unrecognized nftables JSON ruleset.")
                incomplete = True
    return _check("warning" if warning and not incomplete else "unknown",
                  {"backends": backends},
                  "Installed UFW, firewalld and nftables views only; missing tools are not evidence "
                  "of an absent firewall. Collection does not establish effective filtering: "
                  "rule ordering, interfaces, legacy iptables, cloud firewalls and Docker forwarding "
                  "need review. Backend errors remain unknown; no firewall changes were made.")


def _cache_age():
    try:
        timestamps = [path.stat().st_mtime for path in Path("/var/lib/apt/lists").iterdir()
                      if path.name.endswith(("_InRelease", "_Release")) and path.is_file()]
    except OSError:
        return None
    if not timestamps or max(timestamps) > time.time():
        return None
    return round(time.time() - min(timestamps))


def _updates(profile):
    if profile["family"] != "debian":
        return _rpm_updates(profile["family"])
    age = _cache_age()
    ubuntu = profile["id"] == "ubuntu"
    data = {"backend": "apt", "scope": "cached APT upgrade candidates",
            "cache_age_seconds": age, "cache_age_basis": "oldest cached repository Release mtime",
            "security_updates": [] if ubuntu else None, "pending_candidates": [],
            "pending_candidate_count": None}
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
        candidate = {"package": package, "version": fields[1], "architecture": fields[2]}
        data["pending_candidates"].append(candidate)
        if ubuntu and any(suite.endswith("-security") for suite in suites.split(",")):
            data["security_updates"].append(candidate)
    data["pending_candidate_count"] = pending
    data["cache_stale_or_unknown"] = age is None or age > 86400
    # Candidate suites are not a complete security classification (e.g. superseded fixes).
    status = "warning" if data["security_updates"] else "unknown"
    if malformed:
        status = "unknown"
    return _check(status, data,
                  "No repository refresh performed. Counts use cached candidates only; Ubuntu "
                  "-security suites are a partial hint, not used to classify Debian candidates. "
                  "Security provenance, superseded fixes and held packages may be missing; zero is not proof "
                  "that the host is patched. Cache age is a file timestamp, not refresh verification.")


def _rpm_updates(family):
    candidates = ("zypper",) if family == "suse" else ("dnf", "dnf5", "yum")
    backend = next((name for name in candidates if shutil.which(name, path=_ENV["PATH"])), None)
    data = {"backend": backend, "scope": "cached applicable security patches" if family == "suse"
            else "cached security update advisories", "security_updates": [],
            "cache_age_seconds": None, "cache_stale_or_unknown": True,
            "pending_candidate_count": None}
    note = ("No repository refresh or installation performed. Cached advisory metadata may be "
            "missing, stale or incomplete; repositories without security advisories, excluded "
            "packages and unsupported output are not covered. Zero is not proof that the host is patched.")
    if backend is None:
        return _check("unknown", data, f"No {'/'.join(candidates)} command is installed. " + note)
    if family == "suse":
        args = ["zypper", "--non-interactive", "--no-refresh", "list-patches", "--category", "security"]
    elif backend == "yum":
        args = ["yum", "--cacheonly", "--quiet", "--color=never", "updateinfo", "list", "updates", "security"]
    else:
        args = [backend, "--cacheonly", "--quiet", "--color=never", "updateinfo", "list", "--updates", "--security"]
    text, error = _run(args)
    if error:
        return _check("unknown", data, error + " " + note)
    malformed = False
    columns = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if family == "suse":
            if "|" not in line:
                continue
            fields = [field.strip() for field in line.split("|")]
            if {"Name", "Category", "Status"} <= set(fields):
                columns = {name: fields.index(name) for name in ("Name", "Category", "Status")}
                continue
            if columns is None or len(fields) <= max(columns.values()):
                malformed = True
                continue
            if fields[columns["Category"]] == "security":
                data["security_updates"].append({"advisory": fields[columns["Name"]],
                                                "status": fields[columns["Status"]]})
            else:
                malformed = True
        else:
            fields = line.split()
            if fields[0] in {"Name", "Advisory"}:
                continue
            if len(fields) == 3 and (fields[1].lower().endswith("/sec.") or fields[1].lower() == "security"):
                data["security_updates"].append({"advisory": fields[0], "package": fields[2]})
            elif len(fields) >= 5 and fields[1].lower() == "security":
                data["security_updates"].append({"advisory": fields[0], "package": fields[3]})
            else:
                malformed = True
    return _check("warning" if data["security_updates"] and not malformed else "unknown", data, note)


def _accounts(family="debian"):
    passwd, error = _run(["getent", "passwd"])
    if error:
        return _check("unknown", note=error)
    groups, error = _run(["getent", "group"])
    if error:
        return _check("unknown", note=error)
    privileged_groups = {}
    group_names = {"sudo", "admin", "wheel"} if family in {"rhel", "suse"} else {"sudo", "admin"}
    malformed = not groups.strip()
    for line in groups.splitlines():
        fields = line.split(":")
        gid = _unsigned(fields[2], 4294967295) if len(fields) == 4 else None
        if gid is None:
            malformed = True
            continue
        if fields[0] in group_names:
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
                  {"accounts": accounts, "unresolved_group_members": unresolved,
                   "privileged_groups_checked": sorted(group_names)},
                  "UID 0 and " + "/".join(sorted(group_names)) + " groups only; group membership "
                  "does not prove sudo authorization. Custom sudoers, polkit, capabilities and "
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
    """Return JSON-safe observations without changing configuration, packages, services or firewall rules.

    ``checks`` maps names to ``status`` (ok/warning/unknown), ``data`` and ``note``.
    ``ok`` means the scoped observation succeeded without a known warning, not that
    the host is secure. Incomplete observations stay ``unknown`` even with warnings.
    Unsupported hosts return empty checks and never invoke host commands.
    """
    release = _os_release()
    profile = select_profile(release)
    supported = platform.system() == "Linux" and profile["family"] in {"debian", "rhel", "suse"}
    report = {"supported": supported, "platform": release, "profile": profile, "checks": {}, "findings": []}
    if not supported:
        report["findings"].append({"check": "platform", "severity": "unknown",
                                   "message": "Unsupported host ID/version or non-Linux platform; no commands were run."})
        return report
    checks = report["checks"]
    for name, collect in (("ssh", _ssh), ("listeners", _listeners), ("firewall", _firewall),
                          ("security_updates", lambda: _updates(profile)),
                          ("privileged_accounts", lambda: _accounts(profile["family"])),
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
