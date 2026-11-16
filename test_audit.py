import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import audit


class AuditTests(unittest.TestCase):
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

    def test_other_ubuntu_version_is_unsupported(self):
        with patch.object(audit.platform, "system", return_value="Linux"), \
                patch.object(audit, "_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "22.04"}), \
                patch.object(audit.subprocess, "run") as run:
            self.assertFalse(audit.run_audit()["supported"])
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
        with patch.object(audit, "_run", return_value=("Status: inactive\n", None)):
            self.assertEqual(audit._firewall()["status"], "warning")
        text = "Status: active\nDefault: deny (incoming)\n22/tcp ALLOW IN Anywhere # secret-token\n"
        with patch.object(audit, "_run", return_value=(text, None)):
            result = audit._firewall()
        self.assertTrue(result["data"]["active"])
        self.assertNotIn("secret-token", json.dumps(result))
        self.assertIn("other nftables", result["note"])

    def test_security_updates_use_cached_suites_without_refresh(self):
        text = ("Listing...\nopenssl/noble-updates,noble-security 3.0.13 amd64 [upgradable from: 3.0.12]\n"
                "curl/noble-updates 8.5.0 amd64 [upgradable from: 8.4.0]\n")
        with patch.object(audit, "_cache_age", return_value=90000), \
                patch.object(audit, "_run", return_value=(text, None)) as run:
            result = audit._updates()
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["data"]["pending_candidate_count"], 2)
        self.assertEqual(result["data"]["security_updates"][0]["package"], "openssl")
        self.assertTrue(result["data"]["cache_stale_or_unknown"])
        self.assertEqual(run.call_args.args[0], ["apt", "list", "--upgradable", "-o", "APT::Color=0"])

    def test_no_security_candidates_does_not_claim_patched(self):
        for text in ("Listing...\n", "unexpected output\n"):
            with self.subTest(text=text), patch.object(audit, "_cache_age", return_value=None), \
                    patch.object(audit, "_run", return_value=(text, None)):
                result = audit._updates()
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


if __name__ == "__main__":
    unittest.main()
