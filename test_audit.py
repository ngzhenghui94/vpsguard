import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import audit


class AuditTests(unittest.TestCase):
    def setUp(self):
        tools = patch.object(audit.shutil, "which", return_value=None)
        self.which = tools.start()
        self.addCleanup(tools.stop)

    def test_unsupported_host_runs_no_commands(self):
        with patch.object(audit.platform, "system", return_value="Darwin"), \
                patch.object(audit, "_os_release", return_value={}), \
                patch.object(audit.subprocess, "run") as run:
            report = audit.run_audit()
        self.assertFalse(report["supported"])
        self.assertEqual(report["checks"], {})
        self.assertIn("Unsupported", report["findings"][0]["message"])
        run.assert_not_called()
        json.dumps(report)

    def test_unknown_id_or_version_is_unsupported_without_guessed_commands(self):
        for release in ({"ID": "mint", "ID_LIKE": "ubuntu", "VERSION_ID": "24.04"},
                        {"ID": "ubuntu", "VERSION_ID": "unknown"},
                        {"ID": "debian"}, {}):
            with self.subTest(release=release), \
                    patch.object(audit.platform, "system", return_value="Linux"), \
                    patch.object(audit, "_os_release", return_value=release), \
                    patch.object(audit.subprocess, "run") as run:
                report = audit.run_audit()
            self.assertFalse(report["supported"])
            self.assertEqual(report["checks"], {})
            run.assert_not_called()

    def test_command_failures_are_unknown_without_diagnostics(self):
        failures = [FileNotFoundError(), subprocess.TimeoutExpired(["sshd"], 15), PermissionError()]
        for failure in failures:
            with self.subTest(failure=failure), patch.object(audit.subprocess, "run", side_effect=failure):
                self.assertEqual(audit._ssh()["status"], "unknown")
        result = subprocess.CompletedProcess(["sshd"], 1, stdout="private-key", stderr="secret-token")
        with patch.object(audit.subprocess, "run", return_value=result):
            encoded = json.dumps(audit._ssh())
        self.assertNotIn("private-key", encoded)
        self.assertNotIn("secret-token", encoded)

    def test_command_uses_argv_timeout_and_fixed_environment(self):
        result = subprocess.CompletedProcess(["ss"], 0, stdout="", stderr="")
        with patch.object(audit.subprocess, "run", return_value=result) as run:
            self.assertEqual(audit._run(["ss", "-H", "-lntu"]), ("", None))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["ss", "-H", "-lntu"])
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["timeout"], 15)
        self.assertEqual(kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})

    def test_ssh_retains_multiple_listeners_but_not_command_secrets(self):
        text = ("port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n"
                "permitrootlogin prohibit-password\npasswordauthentication no\n"
                "pubkeyauthentication yes\nauthorizedkeyscommand /bin/foo secret-token\n")
        with patch.object(audit, "_run", return_value=(text, None)):
            result = audit._ssh()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["data"]["settings"]["listenaddress"]), 2)
        self.assertNotIn("secret-token", json.dumps(result))
        self.assertIn("Match", result["note"])
        with patch.object(audit, "_run", return_value=("", None)):
            self.assertEqual(audit._ssh()["status"], "unknown")

    def test_listeners_parse_ipv6_udp_and_wildcards(self):
        text = ("tcp LISTEN 0 128 [::]:22 [::]:*\n"
                "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
                "tcp LISTEN 0 128 *:443 *:*\n")
        with patch.object(audit, "_run", return_value=(text, None)):
            result = audit._listeners()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["listeners"], [
            {"protocol": "tcp", "address": "::", "port": 22},
            {"protocol": "udp", "address": "127.0.0.53%lo", "port": 53},
            {"protocol": "tcp", "address": "*", "port": 443},
        ])
        with patch.object(audit, "_run", return_value=(text + "truncated\n", None)):
            self.assertEqual(audit._listeners()["status"], "unknown")

    def test_firewall_inactive_is_not_secure_and_comments_are_omitted(self):
        self.which.side_effect = lambda name, **kwargs: name if name == "ufw" else None
        with patch.object(audit, "_run", return_value=("Status: inactive\n", None)):
            self.assertEqual(audit._firewall()["status"], "warning")
        text = "Status: active\nDefault: deny (incoming)\n22/tcp ALLOW IN Anywhere # secret-token\n"
        with patch.object(audit, "_run", return_value=(text, None)):
            result = audit._firewall()
        self.assertTrue(result["data"]["backends"]["ufw"]["data"]["active"])
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("secret-token", json.dumps(result))
        self.assertIn("legacy iptables", result["note"])

    def test_security_updates_use_cached_suites_without_refresh(self):
        text = ("Listing...\nopenssl/noble-updates,noble-security 3.0.13 amd64 [upgradable from: 3.0.12]\n"
                "curl/noble-updates 8.5.0 amd64 [upgradable from: 8.4.0]\n")
        with patch.object(audit, "_cache_age", return_value=90000), \
                patch.object(audit, "_run", return_value=(text, None)) as run:
            result = audit._updates({"id": "ubuntu", "family": "debian"})
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["data"]["pending_candidate_count"], 2)
        self.assertEqual(result["data"]["security_updates"][0]["package"], "openssl")
        self.assertTrue(result["data"]["cache_stale_or_unknown"])
        self.assertEqual(run.call_args.args[0], ["apt", "list", "--upgradable", "-o", "APT::Color=0"])

    def test_no_security_candidates_does_not_claim_patched(self):
        for text in ("Listing...\n", "unexpected output\n"):
            with self.subTest(text=text), patch.object(audit, "_cache_age", return_value=None), \
                    patch.object(audit, "_run", return_value=(text, None)):
                result = audit._updates({"id": "ubuntu", "family": "debian"})
            self.assertEqual(result["status"], "unknown")
            self.assertIn("zero is not proof", result["note"])

    def test_cache_age_uses_oldest_repository_and_handles_absence(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old_InRelease"
            new = root / "new_InRelease"
            old.touch()
            new.touch()
            os.utime(old, (100, 100))
            os.utime(new, (200, 200))
            with patch.object(audit, "Path", return_value=root), patch.object(audit.time, "time", return_value=300):
                self.assertEqual(audit._cache_age(), 200)
            old.unlink()
            new.unlink()
            with patch.object(audit, "Path", return_value=root):
                self.assertIsNone(audit._cache_age())

    def test_privileged_accounts_include_primary_sudo_group(self):
        passwd = ("root:x:0:0:root:/root:/bin/bash\n"
                  "primary:x:1000:27:Primary:/home/primary:/bin/bash\n"
                  "secondary:x:1001:1001:Secondary:/home/secondary:/bin/bash\n"
                  "backdoor:x:0:1002:Other:/home/other:/bin/bash\n")
        groups = "root:x:0:\nsudo:x:27:secondary,external\n"
        with patch.object(audit, "_run", side_effect=[(passwd, None), (groups, None)]):
            result = audit._accounts()
        accounts = {account["name"]: account for account in result["data"]["accounts"]}
        self.assertEqual(accounts["primary"]["groups"], ["sudo"])
        self.assertEqual(accounts["secondary"]["groups"], ["sudo"])
        self.assertEqual(accounts["backdoor"]["uid"], 0)
        self.assertEqual(result["data"]["unresolved_group_members"], ["external"])
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("/home", json.dumps(result))

    def test_docker_warns_only_published_ports_and_forces_local_socket(self):
        text = '"80/tcp"\n"0.0.0.0:8080->80/tcp, [::]:8080->80/tcp"\n'
        with patch.object(audit, "_run", return_value=(text, None)) as run:
            result = audit._docker()
        self.assertEqual(result["status"], "warning")
        self.assertEqual(len(result["data"]["published_ports"]), 1)
        self.assertEqual(run.call_args.args[0][1:3], ["--host", "unix:///var/run/docker.sock"])
        with patch.object(audit, "_run", return_value=("not json\n", None)):
            self.assertEqual(audit._docker()["status"], "unknown")

    def test_malformed_docker_json_preserves_valid_observations(self):
        published = "*:8080->80/tcp"
        for malformed in ("9" * 5000, "[" * 10000 + "]" * 10000, '{"Ports": "unexpected"}'):
            text = json.dumps(published) + "\n" + malformed + "\n"
            with self.subTest(value=malformed[:12]), \
                    patch.object(audit, "_run", return_value=(text, None)):
                result = audit._docker()
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["data"]["published_ports"], [published])

    def test_supported_report_is_json_safe_when_commands_are_missing(self):
        with patch.object(audit.platform, "system", return_value="Linux"), \
                patch.object(audit, "_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), \
                patch.object(audit, "_cache_age", return_value=None), \
                patch.object(audit, "_run", return_value=(None, "Command is not installed.")):
            report = audit.run_audit()
        self.assertTrue(report["supported"])
        self.assertEqual(len(report["checks"]), 6)
        self.assertTrue(all(check["status"] == "unknown" for check in report["checks"].values()))
        self.assertEqual(len(report["findings"]), 6)
        json.dumps(report)

    def test_empty_command_output_does_not_establish_security_state(self):
        self.which.side_effect = lambda name, **kwargs: name if name == "ufw" else None
        for collect in (audit._ssh, audit._firewall, audit._docker):
            for text in ("", " \n"):
                with self.subTest(collector=collect.__name__, text=text), \
                        patch.object(audit, "_run", return_value=(text, None)):
                    result = collect()
                self.assertEqual(result["status"], "unknown")
                self.assertNotIn("active", result["data"])
        with patch.object(audit, "_run", return_value=('""\n', None)):
            self.assertEqual(audit._docker()["status"], "ok")

    def test_empty_required_ssh_values_are_unknown(self):
        text = "port 22\npermitrootlogin no\npasswordauthentication \npubkeyauthentication yes\n"
        with patch.object(audit, "_run", return_value=(text, None)):
            self.assertEqual(audit._ssh()["status"], "unknown")

    def test_conflicting_firewall_status_is_unknown(self):
        self.which.side_effect = lambda name, **kwargs: name if name == "ufw" else None
        text = "Status: active\nStatus: inactive\nprivate-diagnostic\n"
        with patch.object(audit, "_run", return_value=(text, None)):
            result = audit._firewall()
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("active", result["data"])
        self.assertNotIn("private-diagnostic", json.dumps(result))

    def test_malformed_listener_ports_preserve_valid_observations(self):
        valid = "tcp LISTEN 0 128 *:22 *:*\n"
        for value in ("²", "１２", "9" * 5000, "65536", "0"):
            with self.subTest(value=value[:12]), \
                    patch.object(audit, "_run", return_value=(valid + f"tcp LISTEN 0 128 *:{value} *:*\n", None)):
                result = audit._listeners()
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["data"]["listeners"], [
                {"protocol": "tcp", "address": "*", "port": 22},
            ])

    def test_malformed_account_ids_preserve_valid_observations(self):
        root = "root:x:0:0:Root:/root:/bin/bash\n"
        for value in ("²", "１２", "9" * 5000, "4294967296"):
            for field in ("uid", "gid", "group"):
                uid = value if field == "uid" else "1000"
                gid = value if field == "gid" else "1000"
                group_id = value if field == "group" else "27"
                entries = root + f"ordinary:x:{uid}:{gid}:User:/home/user:/bin/bash\n"
                groups = f"root:x:0:\nsudo:x:{group_id}:\n"
                with self.subTest(field=field, value=value[:12]), \
                        patch.object(audit, "_run", side_effect=[(entries, None), (groups, None)]):
                    result = audit._accounts()
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["data"]["accounts"], [{"name": "root", "uid": 0, "groups": []}])

    def test_empty_groups_do_not_establish_privileged_memberships(self):
        entries = "root:x:0:0:Root:/root:/bin/bash\n"
        with patch.object(audit, "_run", side_effect=[(entries, None), ("", None)]):
            result = audit._accounts()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["data"]["accounts"][0]["name"], "root")

    def test_collector_os_and_parse_failures_are_scoped_without_diagnostics(self):
        for failure in (OSError("private-key"), ValueError("secret-token"),
                        UnicodeDecodeError("utf8", b"\xff", 0, 1, "private-diagnostic")):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(audit.platform, "system", return_value="Linux"), \
                    patch.object(audit, "_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), \
                    patch.object(audit, "_ssh", side_effect=failure), \
                    patch.object(audit, "_cache_age", return_value=None), \
                    patch.object(audit, "_run", return_value=(None, "Command is not installed.")), \
                    patch.object(audit, "_docker", return_value=audit._check("ok", {"published_ports": []})) as docker:
                report = audit.run_audit()
            self.assertEqual(len(report["checks"]), 6)
            self.assertEqual(report["checks"]["ssh"]["status"], "unknown")
            self.assertEqual(report["checks"]["docker"]["status"], "ok")
            docker.assert_called_once_with()
            encoded = json.dumps(report)
            for secret in ("private-key", "secret-token", "private-diagnostic"):
                self.assertNotIn(secret, encoded)

    def test_collector_programming_errors_are_not_suppressed(self):
        for failure in (TypeError("bug"), KeyError("bug"), AttributeError("bug"), RuntimeError("bug")):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(audit.platform, "system", return_value="Linux"), \
                    patch.object(audit, "_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), \
                    patch.object(audit, "_ssh", side_effect=failure):
                with self.assertRaises(type(failure)):
                    audit.run_audit()

    def test_ssh_warning_findings_update_check_status_without_hiding_unknown(self):
        for key in ("passwordauthentication", "kbdinteractiveauthentication",
                    "permitemptypasswords", "permitrootlogin"):
            for complete in (True, False):
                settings = {"permitrootlogin": "no", "passwordauthentication": "no",
                            "pubkeyauthentication": "yes", key: "yes"}
                if complete:
                    settings["port"] = "22"
                text = "".join(f"{name} {value}\n" for name, value in settings.items())

                def command(args):
                    return (text, None) if args[0] == "sshd" else (None, "Command is not installed.")

                with self.subTest(key=key, complete=complete), \
                        patch.object(audit.platform, "system", return_value="Linux"), \
                        patch.object(audit, "_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), \
                        patch.object(audit, "_cache_age", return_value=None), \
                        patch.object(audit, "_run", side_effect=command):
                    report = audit.run_audit()
                self.assertEqual(report["checks"]["ssh"]["status"], "warning" if complete else "unknown")
                self.assertTrue(any(finding["check"] == "ssh" and finding["severity"] == "warning"
                                    for finding in report["findings"]))

    def test_additional_root_account_warning_updates_check_status(self):
        accounts = audit._check("ok", {"accounts": [{"name": "extra", "uid": 0, "groups": []}]})
        with patch.object(audit.platform, "system", return_value="Linux"), \
                patch.object(audit, "_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), \
                patch.object(audit, "_cache_age", return_value=None), \
                patch.object(audit, "_run", return_value=(None, "Command is not installed.")), \
                patch.object(audit, "_accounts", return_value=accounts):
            report = audit.run_audit()
        self.assertEqual(report["checks"]["privileged_accounts"]["status"], "warning")

    def test_supported_families_use_exact_profiles_and_native_cached_queries(self):
        cases = [
            ("debian", "13", "debian", "apt", ["apt", "list", "--upgradable", "-o", "APT::Color=0"]),
            ("fedora", "43", "rhel", "dnf", ["dnf", "--cacheonly", "--quiet", "--color=never",
                                            "updateinfo", "list", "--updates", "--security"]),
            ("rhel", "9.6", "rhel", "dnf", ["dnf", "--cacheonly", "--quiet", "--color=never",
                                          "updateinfo", "list", "--updates", "--security"]),
            ("sles", "15.6", "suse", "zypper", ["zypper", "--non-interactive", "--no-refresh",
                                               "list-patches", "--category", "security"]),
            ("opensuse-leap", "16.0", "suse", "zypper", ["zypper", "--non-interactive", "--no-refresh",
                                                        "list-patches", "--category", "security"]),
        ]
        common = [["sshd", "-T"], ["ss", "-H", "-lntu"], ["getent", "passwd"], ["getent", "group"],
                  ["docker", "--host", "unix:///var/run/docker.sock", "ps", "--format", '{{json .Ports}}']]
        for distro, version, family, backend, query in cases:
            release = {"ID": distro, "VERSION_ID": version}
            self.which.side_effect = lambda name, **kwargs: name if name == backend else None
            with self.subTest(distro=distro), \
                    patch.object(audit.platform, "system", return_value="Linux"), \
                    patch.object(audit, "_os_release", return_value=release), \
                    patch.object(audit, "_cache_age", return_value=None), \
                    patch.object(audit, "_run", return_value=("", None)) as run:
                report = audit.run_audit()
            self.assertTrue(report["supported"])
            self.assertEqual(report["platform"], release)
            self.assertEqual(report["profile"]["id"], distro)
            self.assertEqual(report["profile"]["version"], version)
            self.assertEqual(report["profile"]["family"], family)
            self.assertEqual(report["checks"]["security_updates"]["data"]["backend"], backend)
            self.assertEqual(len(report["checks"]), 6)
            self.assertCountEqual([call.args[0] for call in run.call_args_list], common + [query])
            json.dumps(report)

    def test_debian_candidates_are_not_classified_using_ubuntu_suite_names(self):
        text = "Listing...\nopenssl/trixie-security 3.5 amd64 [upgradable from: 3.4]\n"
        with patch.object(audit, "_cache_age", return_value=100), \
                patch.object(audit, "_run", return_value=(text, None)):
            result = audit._updates({"id": "debian", "family": "debian"})
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["data"]["security_updates"])
        self.assertEqual(result["data"]["pending_candidate_count"], 1)
        self.assertEqual(result["data"]["pending_candidates"][0]["package"], "openssl")
        self.assertIn("not used to classify Debian", result["note"])

    def test_rpm_cached_advisories_and_yum_fallback(self):
        for backend, output in (
            ("dnf", "RHSA-2026:1234 Important/Sec. openssl-3.0-1.el9.x86_64\n"),
            ("dnf5", "Name Type Severity Package Issued\n"
                     "FEDORA-2026-abc security Important openssl-3.5-1.fc43.x86_64 2026-10-01\n"),
            ("yum", "ALAS-2026-1234 important/Sec. openssl-1.0-1.amzn2.x86_64\n"),
        ):
            self.which.side_effect = lambda name, **kwargs: name if name == backend else None
            with self.subTest(backend=backend), patch.object(audit, "_run", return_value=(output, None)) as run:
                result = audit._updates({"id": "amzn", "family": "rhel"})
            self.assertEqual(result["status"], "warning")
            self.assertEqual(result["data"]["backend"], backend)
            self.assertEqual(len(result["data"]["security_updates"]), 1)
            self.assertIn("--cacheonly", run.call_args.args[0])
            self.assertIn("updateinfo", run.call_args.args[0])
            self.assertIn("zero is not proof", result["note"].lower())

    def test_suse_cached_security_patches(self):
        self.which.side_effect = lambda name, **kwargs: name if name == "zypper" else None
        output = ("Repository | Name | Category | Severity | Interactive | Status | Summary\n"
                  "-----------+------+----------+----------+-------------+--------+--------\n"
                  "SLES-Updates | SUSE-SLE-2026-1234 | security | important | --- | needed | Fix\n")
        with patch.object(audit, "_run", return_value=(output, None)) as run:
            result = audit._updates({"id": "sles", "family": "suse"})
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["data"]["security_updates"],
                         [{"advisory": "SUSE-SLE-2026-1234", "status": "needed"}])
        self.assertEqual(run.call_args.args[0],
                         ["zypper", "--non-interactive", "--no-refresh", "list-patches", "--category", "security"])

    def test_missing_package_tools_and_cache_failures_are_scoped_unknowns(self):
        for family in ("rhel", "suse"):
            with self.subTest(family=family), patch.object(audit, "_run") as run:
                result = audit._updates({"id": "test", "family": family})
            run.assert_not_called()
            self.assertEqual(result["status"], "unknown")
            self.assertIn("command is installed", result["note"])
            self.assertIn("cached", result["data"]["scope"])
        for family, backend in (("debian", "apt"), ("rhel", "dnf"), ("suse", "zypper")):
            self.which.side_effect = lambda name, **kwargs: name if name == backend else None
            for output, error in (("", None), (None, "Command is not installed."),
                                  (None, "Command failed (exit 1); permissions may be required.")):
                with self.subTest(family=family, error=error), \
                        patch.object(audit, "_cache_age", return_value=None), \
                        patch.object(audit, "_run", return_value=(output, error)):
                    result = audit._updates({"id": "debian", "family": family})
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["data"]["backend"], backend)
                if error:
                    self.assertIn(error, result["note"])

    def test_firewall_without_ufw_inspects_firewalld_and_nft_read_only(self):
        self.which.side_effect = lambda name, **kwargs: name if name in {"firewall-cmd", "nft"} else None
        nft = {"nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input",
                                      "hook": "input", "policy": "accept"}},
                            {"rule": {"comment": "secret-token", "expr": []}}]}
        replies = [("running\n", None), ("public\n  interfaces: eth0\n", None),
                   ("public (active)\n  target: default\n  services: ssh\n", None),
                   (json.dumps(nft), None)]
        with patch.object(audit, "_run", side_effect=replies) as run:
            result = audit._firewall()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(set(result["data"]["backends"]), {"firewalld", "nftables"})
        self.assertEqual(result["data"]["backends"]["nftables"]["data"]["chains"][0]["policy"], "accept")
        self.assertNotIn("secret-token", json.dumps(result))
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["firewall-cmd", "--state"], ["firewall-cmd", "--get-active-zones"],
                          ["firewall-cmd", "--list-all-zones"], ["nft", "--json", "list", "ruleset"]])

    def test_firewall_missing_tools_and_partial_errors_never_claim_security(self):
        with patch.object(audit, "_run") as run:
            result = audit._firewall()
        run.assert_not_called()
        self.assertEqual(result["status"], "unknown")
        self.assertIn("missing tools are not evidence", result["note"])
        self.which.side_effect = lambda name, **kwargs: name if name in {"ufw", "nft"} else None
        for nft in ((None, "Command failed (exit 1); permissions may be required."),
                    ("not json", None), ('{"nftables": [null]}', None)):
            with self.subTest(nft=nft), \
                    patch.object(audit, "_run", side_effect=[("Status: inactive\n", None), nft]):
                result = audit._firewall()
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["data"]["backends"]["ufw"]["status"], "warning")
            self.assertEqual(result["data"]["backends"]["nftables"]["status"], "unknown")

    def test_rpm_and_suse_wheel_membership_includes_primary_groups(self):
        passwd = ("root:x:0:0:Root:/root:/bin/bash\n"
                  "primary:x:1000:10:Primary:/home/primary:/bin/bash\n"
                  "secondary:x:1001:1001:Secondary:/home/secondary:/bin/bash\n")
        groups = "root:x:0:\nwheel:x:10:secondary\n"
        for family in ("rhel", "suse"):
            with self.subTest(family=family), \
                    patch.object(audit, "_run", side_effect=[(passwd, None), (groups, None)]):
                result = audit._accounts(family)
            accounts = {account["name"]: account for account in result["data"]["accounts"]}
            self.assertEqual(accounts["primary"]["groups"], ["wheel"])
            self.assertEqual(accounts["secondary"]["groups"], ["wheel"])
            self.assertIn("custom sudoers", result["note"].lower())
            self.assertIn("does not prove sudo authorization", result["note"])

    def test_malformed_cached_advisories_retain_known_findings_as_unknown(self):
        for backend, family, text in (
            ("dnf", "rhel", "RHSA-2026:1234 Important/Sec. openssl-3.0-1.el9.x86_64\ntruncated\n"),
            ("zypper", "suse", "Repository | Name | Category | Status\n"
                              "updates | SUSE-2026-1234 | security | needed\ntruncated | row\n"),
        ):
            self.which.side_effect = lambda name, **kwargs: name if name == backend else None
            with self.subTest(backend=backend), patch.object(audit, "_run", return_value=(text, None)):
                result = audit._updates({"id": "test", "family": family})
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(len(result["data"]["security_updates"]), 1)

    def test_firewalld_running_does_not_hide_unreadable_rules(self):
        self.which.side_effect = lambda name, **kwargs: name if name == "firewall-cmd" else None
        error = "Command failed (exit 1); permissions may be required."
        with patch.object(audit, "_run",
                          side_effect=[("running\n", None), ("public\n", None), (None, error)]):
            result = audit._firewall()
        self.assertEqual(result["status"], "unknown")
        backend = result["data"]["backends"]["firewalld"]
        self.assertEqual(backend["status"], "unknown")
        self.assertTrue(backend["data"]["active"])
        self.assertEqual(backend["note"], error)


if __name__ == "__main__":
    unittest.main()
