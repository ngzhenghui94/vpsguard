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


if __name__ == "__main__":
    unittest.main()
