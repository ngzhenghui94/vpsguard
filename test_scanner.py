import bz2
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.request

import scanner


NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
D = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
R = "http://oval.mitre.org/XMLSchema/oval-results-5"
C = "http://oval.mitre.org/XMLSchema/oval-common-5"


def feed(timestamp=None):
    timestamp = timestamp or NOW.isoformat()
    return f'''<oval_definitions xmlns="{D}" xmlns:oval="{C}">
      <generator><oval:timestamp>{timestamp}</oval:timestamp></generator>
      <definitions>
        <definition id="oval:com.ubuntu.noble:def:100" version="1" class="inventory">
          <metadata><title>Ubuntu 24.04</title></metadata>
        </definition>
        <definition id="oval:com.ubuntu.noble:def:200" version="1" class="vulnerability">
          <metadata><title>Fixture package CVE</title>
            <reference source="CVE" ref_id="CVE-2026-1234" ref_url="https://ubuntu.com/security/CVE-2026-1234"/>
            <advisory><severity>High</severity></advisory>
          </metadata>
        </definition>
      </definitions>
    </oval_definitions>'''.encode()


def results(value="false"):
    return f'''<oval_results xmlns="{R}"><results><system><definitions>
      <definition definition_id="oval:com.ubuntu.noble:def:100" version="1" result="true"/>
      <definition definition_id="oval:com.ubuntu.noble:def:200" version="1" result="{value}"/>
    </definitions></system></results></oval_results>'''.encode()


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.output = self.parent / "scan"
        self.uid = os.geteuid()

    def scan(self, *, xml=None, payload=None, result_xml=None, code=0, missing=None,
             system="Linux", release=None, uid=0, executable="/usr/bin/oscap", error=None):
        xml = feed() if xml is None else xml
        payload = bz2.compress(xml) if payload is None else payload
        result_xml = results() if result_xml is None else result_xml
        response = io.BytesIO(payload)
        response.status = 200
        response.geturl = lambda: scanner.FEED_URL
        opener = MagicMock()
        opener.open.return_value = response

        def process(args, **kwargs):
            instance = MagicMock()
            instance.__enter__.return_value = instance
            instance.wait.return_value = 0
            if args[1:] == ["--version"]:
                kwargs["stdout"].write(b"OpenSCAP command line tool (oscap) 1.3.9\n")
                kwargs["stdout"].flush()
            else:
                self.assertEqual(args[1:4], ["oval", "eval", "--results"])
                self.assertEqual(args[5], "--report")
                self.assertFalse(kwargs.get("shell", False))
                self.assertTrue(kwargs["start_new_session"])
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                self.assertEqual(kwargs["env"]["PATH"], scanner._ENV["PATH"])
                self.assertTrue(kwargs["pass_fds"])
                if missing != "results.xml":
                    Path(args[4]).write_bytes(result_xml)
                if missing != "report.html":
                    Path(args[6]).write_text("<html>Fixture report</html>")
                instance.wait.return_value = code
                if error:
                    instance.wait.side_effect = [error, -9]
            return instance

        # Exercise the real wrapper and parser on macOS too; only remap Linux's fd path.
        def path(value):
            return self.output if str(value).startswith("/proc/self/fd/") else Path(value)

        with ExitStack() as stack:
            stack.enter_context(patch.object(scanner, "Path", side_effect=path))
            stack.enter_context(patch.object(scanner.platform, "system", return_value=system))
            stack.enter_context(patch.object(scanner.platform, "freedesktop_os_release",
                                             return_value=release or {"ID": "ubuntu", "VERSION_ID": "24.04"}))
            stack.enter_context(patch.object(scanner.os, "geteuid", side_effect=[self.uid, uid]))
            stack.enter_context(patch.object(scanner.shutil, "which", return_value=executable))
            stack.enter_context(patch.object(scanner, "_now", return_value=NOW))
            stack.enter_context(patch.object(scanner.urllib.request, "build_opener", return_value=opener))
            popen = stack.enter_context(patch.object(scanner.subprocess, "Popen", side_effect=process))
            kill = stack.enter_context(patch.object(scanner.os, "killpg"))
            report = scanner.run_scan(self.output)
        self.assertEqual(json.loads((self.output / "summary.json").read_text()), report)
        return report, popen, opener, kill

    def test_complete_no_findings_retains_private_evidence_and_provenance(self):
        report, popen, opener, _ = self.scan()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["counts"]["false"], 1)
        self.assertEqual(report["provenance"]["feed"]["sha256"], hashlib.sha256(feed()).hexdigest())
        self.assertEqual(report["provenance"]["engine"]["version"], "1.3.9")
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for path in report["artifacts"].values():
            self.assertEqual(stat.S_IMODE(Path(path).stat().st_mode), 0o600)
        self.assertEqual(len(report["artifacts"]), 6)
        self.assertEqual(popen.call_count, 2)
        opener.open.assert_called_once_with(scanner.FEED_URL, timeout=scanner._SOCKET_TIMEOUT)

    def test_true_cve_is_a_finding_not_engine_error(self):
        report, _, _, _ = self.scan(result_xml=results("true"))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"][0]["cves"], ["CVE-2026-1234"])

    def test_unknown_result_is_incomplete(self):
        report, _, _, _ = self.scan(result_xml=results("unknown"))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["counts"]["unknown"], 1)

    def test_prerequisites_fail_before_network_or_engine(self):
        cases = [{"system": "Darwin"}, {"release": {"ID": "ubuntu", "VERSION_ID": "22.04"}},
                 {"uid": 12345}, {"executable": None}]
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                self.output = self.parent / f"scan-{index}"
                report, popen, opener, _ = self.scan(**case)
                self.assertEqual(report["status"], "incomplete")
                popen.assert_not_called()
                opener.open.assert_not_called()

    def test_existing_directory_and_symlinks_are_not_overwritten(self):
        existing = self.parent / "existing"
        existing.mkdir()
        marker = existing / "summary.json"
        marker.write_text("keep")
        link = self.parent / "linked"
        link.symlink_to(existing, target_is_directory=True)
        for target in (existing, link, link / "new"):
            with self.subTest(target=target):
                self.assertEqual(scanner.run_scan(target)["status"], "incomplete")
        self.assertEqual(marker.read_text(), "keep")
        self.assertFalse((existing / "new").exists())

    def test_private_file_rejects_existing_symlink(self):
        target = self.parent / "target"
        target.write_text("keep")
        (self.parent / "feed.xml").symlink_to(target)
        fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(FileExistsError):
                scanner._private_file(fd, "feed.xml")
        finally:
            os.close(fd)
        self.assertEqual(target.read_text(), "keep")

    def test_nonzero_oval_exit_is_incomplete_even_with_usable_findings(self):
        for code in (1, 2, -9):
            with self.subTest(code=code):
                self.output = self.parent / f"scan-{code}"
                report, _, _, _ = self.scan(code=code, result_xml=results("true"))
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(len(report["findings"]), 1)
                self.assertEqual(report["provenance"]["engine"]["exit_code"], code)

    def test_missing_malformed_and_empty_results_are_incomplete(self):
        cases = [{"missing": "results.xml"}, {"missing": "report.html"},
                 {"result_xml": b"<broken secret-token>"}, {"result_xml": b""},
                 {"result_xml": f'<oval_results xmlns="{R}"><results><system><definitions/></system></results></oval_results>'.encode()}]
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                self.output = self.parent / f"scan-{index}"
                report, _, _, _ = self.scan(**case)
                self.assertEqual(report["status"], "incomplete")
                self.assertNotIn("secret-token", json.dumps(report))

    def test_stale_future_missing_and_invalid_generator_dates_stop_before_eval(self):
        cases = [feed((NOW - timedelta(days=8)).isoformat()),
                 feed((NOW + timedelta(days=1)).isoformat()),
                 feed("invalid"), feed().replace(b"<generator>", b"<other>").replace(b"</generator>", b"</other>")]
        for index, xml in enumerate(cases):
            with self.subTest(index=index):
                self.output = self.parent / f"scan-{index}"
                report, popen, _, _ = self.scan(xml=xml)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(popen.call_count, 1)
                if index == 0:
                    self.assertIn("stale", " ".join(report["limitations"]))

    def test_xml_doctype_and_entities_are_rejected_before_eval(self):
        dangerous = b'<!DOCTYPE oval_definitions [<!ENTITY secret SYSTEM "file:///etc/shadow">]>' + feed()
        for index, xml in enumerate((dangerous, dangerous.decode().encode("utf-16"))):
            with self.subTest(index=index):
                self.output = self.parent / f"scan-{index}"
                report, popen, _, _ = self.scan(xml=xml)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(popen.call_count, 1)
                self.assertIn("DTDs", " ".join(report["limitations"]))

    def test_compression_limits_and_corruption_stop_before_eval(self):
        cases = [("_MAX_COMPRESSED", 1, None), ("_MAX_XML", 32, None),
                 ("_MAX_XML", 65536, b"invalid secret-token"),
                 ("_MAX_XML", 65536, bz2.compress(feed())[:-2]),
                 ("_MAX_XML", 65536, bz2.compress(feed()) + b"trailing")]
        for index, (constant, value, payload) in enumerate(cases):
            with self.subTest(index=index), patch.object(scanner, constant, value):
                self.output = self.parent / f"scan-{index}"
                report, popen, _, _ = self.scan(payload=payload)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(popen.call_count, 1)
                self.assertNotIn("secret-token", json.dumps(report))

    def test_redirects_cannot_leave_verified_official_https(self):
        handler = scanner._OfficialRedirect()
        request = urllib.request.Request(scanner.FEED_URL)
        for url in ("http://security-metadata.canonical.com/feed", "https://example.com/feed",
                    "https://security-metadata.canonical.com:444/feed",
                    "https://user:secret@security-metadata.canonical.com/feed",
                    "file:///etc/shadow", "https://security-metadata.canonical.com:invalid/feed"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "Found", {}, url)
        redirected = handler.redirect_request(request, None, 302, "Found", {}, scanner.FEED_URL)
        self.assertEqual(redirected.full_url, scanner.FEED_URL)

    def test_network_failure_is_incomplete_without_sensitive_details(self):
        with patch.object(scanner, "_download", side_effect=OSError("secret-token")):
            report, _, _, _ = self.scan()
        self.assertEqual(report["status"], "incomplete")
        self.assertNotIn("secret-token", json.dumps(report))

    def test_timeout_kills_process_group_and_keeps_incomplete_summary(self):
        error = subprocess.TimeoutExpired(["oscap"], 900, output="secret-token", stderr="private-key")
        report, _, _, kill = self.scan(error=error)
        self.assertEqual(report["status"], "incomplete")
        kill.assert_called_once()
        self.assertEqual(kill.call_args.args[1], signal.SIGKILL)
        self.assertNotIn("secret-token", json.dumps(report))
        self.assertNotIn("private-key", json.dumps(report))

    def test_download_total_deadline_is_enforced(self):
        with patch.object(scanner.time, "monotonic", side_effect=[0, 121]):
            report, popen, _, _ = self.scan()
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(popen.call_count, 1)
        self.assertIn("time limit", " ".join(report["limitations"]))

    def test_symlinked_engine_result_is_not_parsed_or_chmodded(self):
        target = self.parent / "private"
        target.write_text("secret-token")
        target.chmod(0o640)
        original_execute = scanner._execute

        def execute(args, directory_fd, root, timeout, stdout):
            code = original_execute(args, directory_fd, root, timeout, stdout)
            if args[1:3] == ["oval", "eval"]:
                result = root / "results.xml"
                result.unlink()
                result.symlink_to(target)
            return code

        with patch.object(scanner, "_execute", side_effect=execute), \
                patch.object(scanner, "parse_results") as parse:
            report, _, _, _ = self.scan()
        self.assertEqual(report["status"], "incomplete")
        parse.assert_not_called()
        self.assertEqual(target.read_text(), "secret-token")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertNotIn("secret-token", json.dumps(report))

    def test_cli_exit_codes_are_driven_by_completeness_and_findings(self):
        for status, findings, code in (("complete", [], 0), ("complete", [{}], 2),
                                       ("incomplete", [], 1), ("incomplete", [{}], 1)):
            with self.subTest(status=status, findings=findings), \
                    patch.object(scanner, "run_scan", return_value={"status": status, "findings": findings}) as run, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(scanner.main(["--output", "new-scan"]), code)
                run.assert_called_once_with("new-scan")


if __name__ == "__main__":
    unittest.main()
