import bz2
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import signal
import ssl
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import urllib.request

import scanner
from profiles import select_profile


PROFILE = select_profile({"ID": "ubuntu", "VERSION_ID": "24.04"})
FEED_URL = PROFILE["feed_url"]


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
          <metadata><title>Ubuntu 24.04</title><affected family="unix"><platform>Ubuntu 24.04 LTS</platform></affected></metadata>
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
             system="Linux", release=None, uid=0, executable="/usr/bin/oscap", error=None, final_url=None):
        xml = feed() if xml is None else xml
        payload = bz2.compress(xml) if payload is None else payload
        result_xml = results() if result_xml is None else result_xml
        response = io.BytesIO(payload)
        response.status = 200
        selected = select_profile(release or {"ID": "ubuntu", "VERSION_ID": "24.04"})
        response.geturl = lambda: final_url or selected["feed_url"]
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
                self.assertEqual(args[7:], [str(self.output / "feed.xml")])
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
        opener.open.assert_called_once_with(FEED_URL, timeout=scanner._SOCKET_TIMEOUT)

    def test_true_cve_is_a_finding_not_engine_error(self):
        report, _, _, _ = self.scan(result_xml=results("true"))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"][0]["cves"], ["CVE-2026-1234"])

    def test_unknown_result_is_incomplete(self):
        report, _, _, _ = self.scan(result_xml=results("unknown"))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["counts"]["unknown"], 1)

    def test_prerequisites_fail_before_network_or_engine(self):
        cases = [{"system": "Darwin"}, {"release": {"ID": "ubuntu", "VERSION_ID": "18.04"}},
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

    def test_debian_explicit_offset_is_not_reinterpreted_as_utc(self):
        timestamp = "2026-11-16T11:25:21.188-04:00"
        xml = feed(timestamp).replace(b"Ubuntu 24.04 LTS", b"Debian GNU/Linux 13")
        profile = select_profile({"ID": "debian", "VERSION_ID": "13"})
        for hour, minute, future in ((14, 32, True), (15, 26, False)):
            path = MagicMock()
            path.open.return_value = io.BytesIO(xml)
            now = datetime(2026, 11, 16, hour, minute, tzinfo=timezone.utc)
            with self.subTest(now=now), patch.object(scanner, "_now", return_value=now):
                if future:
                    with self.assertRaisesRegex(ValueError, "timestamp is in the future"):
                        scanner._validate_feed(path, profile)
                else:
                    self.assertEqual(scanner._validate_feed(path, profile),
                                     "2026-11-16T11:25:21.188000-04:00")

    def test_xml_doctype_and_entities_are_rejected_before_eval(self):
        dangerous = b'<!DOCTYPE oval_definitions [<!ENTITY secret SYSTEM "file:///etc/shadow">]>' + feed()
        for index, xml in enumerate((dangerous, dangerous.decode().encode("utf-16"))):
            with self.subTest(index=index):
                self.output = self.parent / f"scan-{index}"
                report, popen, _, _ = self.scan(xml=xml)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(popen.call_count, 1)
                self.assertIn("DTDs" if index == 0 else "UTF-8", " ".join(report["limitations"]))

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

    def test_feed_growth_remains_bounded_and_reaches_evaluation(self):
        self.assertEqual(scanner._MAX_XML, 2 * 1024 * 1024 * 1024)
        former_limit = 64 * 1024
        xml = feed().replace(b"<definitions>", b"<definitions>" + b" " * (former_limit * 2))
        for index, limit in enumerate((former_limit, len(xml))):
            with self.subTest(limit=limit), patch.object(scanner, "_MAX_XML", limit):
                self.output = self.parent / f"growth-{index}"
                report, popen, _, _ = self.scan(xml=xml)
                self.assertEqual(report["status"], "incomplete" if index == 0 else "complete")
                self.assertEqual(popen.call_count, 1 if index == 0 else 2)
                if index == 1:
                    self.assertEqual(report["provenance"]["feed"]["bytes"], len(xml))

    def test_feed_validation_streams_and_enforces_exact_byte_limit(self):
        xml = feed().replace(b"<definitions>", b"<definitions>" + b" " * (128 * 1024))

        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= 64 * 1024:
                    raise AssertionError("Feed validation must use bounded reads.")
                return super().read(size)

        for limit in (len(xml), len(xml) - 1):
            path = MagicMock()
            path.open.return_value = BoundedReader(xml)
            with self.subTest(limit=limit), patch.object(scanner, "_MAX_XML", limit), \
                    patch.object(scanner, "_now", return_value=NOW):
                if limit == len(xml):
                    self.assertEqual(scanner._validate_feed(path, PROFILE), NOW.isoformat())
                else:
                    with self.assertRaisesRegex(ValueError, "size limit"):
                        scanner._validate_feed(path, PROFILE)

    def test_feed_encoding_duplicate_timestamps_and_depth_stop_before_eval(self):
        duplicate = feed().replace(b"</generator>",
                                   f"<oval:timestamp>{NOW.isoformat()}</oval:timestamp></generator>".encode())
        deep = feed().replace(b"<definitions>", b"<definitions>" + b"<nested>" * 256)
        deep = deep.replace(b"</definitions>", b"</nested>" * 256 + b"</definitions>")
        cases = [
            b'<?xml version="1.0" encoding="ISO-8859-1"?>' + feed(),
            feed().decode().encode("utf-16"),
            feed().replace(b"Fixture", b"\xffFixture"),
            duplicate,
            deep,
        ]
        for index, xml in enumerate(cases):
            with self.subTest(index=index):
                self.output = self.parent / f"invalid-xml-{index}"
                report, popen, _, _ = self.scan(xml=xml)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(popen.call_count, 1)

    def test_utf8_bom_and_split_multibyte_text_are_accepted(self):
        xml = b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>' + feed()
        offset = xml.index(b"Fixture")
        xml = xml[:offset] + b" " * (65535 - offset) + "\u00e9".encode() + xml[offset:]
        report, _, _, _ = self.scan(xml=xml)
        self.assertEqual(report["status"], "complete")

    def test_redirects_cannot_leave_verified_official_https(self):
        handler = scanner._OfficialRedirect(PROFILE)
        request = urllib.request.Request(FEED_URL)
        for url in ("http://security-metadata.canonical.com/feed", "https://example.com/feed",
                    "https://security-metadata.canonical.com:444/feed",
                    "https://user:secret@security-metadata.canonical.com/feed",
                    "file:///etc/shadow", "https://security-metadata.canonical.com:invalid/feed",
                    FEED_URL.replace("noble", "jammy"), FEED_URL + "?mirror=1",
                    "https://www.debian.org/security/oval/oval-definitions-trixie.xml.bz2"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "Found", {}, url)
        redirected = handler.redirect_request(request, None, 302, "Found", {}, FEED_URL)
        self.assertEqual(redirected.full_url, FEED_URL)

    def test_download_failure_categories_are_safe_and_incomplete(self):
        secret = "https://private-host/secret-token"
        cases = [
            (urllib.error.HTTPError(secret, 403, secret, {"Private": secret}, None), "HTTP status 403"),
            (ssl.SSLCertVerificationError(secret), "TLS certificate verification failure"),
            (urllib.error.URLError(ssl.SSLCertVerificationError(secret)), "TLS certificate verification failure"),
            (ssl.SSLError(secret), "TLS connection error"),
            (urllib.error.URLError(ssl.SSLError(secret)), "TLS connection error"),
            (TimeoutError(secret), "network timeout"),
            (urllib.error.URLError(TimeoutError(secret)), "network timeout"),
            (ConnectionResetError(secret), "network connection error"),
            (urllib.error.URLError(secret), "network connection error"),
            (http.client.IncompleteRead(secret.encode()), "HTTP protocol error"),
            (OSError(secret), "system/network diagnostics withheld"),
        ]
        self.addCleanup(cases[0][0].close)
        for index, (error, reason) in enumerate(cases):
            with self.subTest(reason=reason, error=type(error).__name__):
                self.output = self.parent / f"download-error-{index}"
                with patch.object(scanner, "_download", side_effect=error):
                    report, popen, _, _ = self.scan()
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(popen.call_count, 1)
                self.assertIn(f"Scan failed during official feed download; {reason}.", report["limitations"])
                self.assertNotIn("private-host", json.dumps(report))
                self.assertNotIn("secret-token", json.dumps(report))

    def test_download_diagnostics_do_not_mislabel_other_phases(self):
        with patch.object(scanner, "_unpack", side_effect=OSError("secret-token")):
            report, popen, _, _ = self.scan()
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(popen.call_count, 1)
        self.assertIn("Scan failed during official feed validation; system/network diagnostics withheld.",
                      report["limitations"])
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

    def test_release_profile_provenance_and_class_selection(self):
        releases = [
            ("ubuntu", "26.04"), ("debian", "13"), ("rhel", "9.6"),
            ("almalinux", "9.5"), ("ol", "10"), ("rocky", "8.10"),
            ("opensuse-leap", "16.0"), ("sles", "15.7"),
        ]
        for index, (distro, version) in enumerate(releases):
            with self.subTest(distro=distro):
                self.output = self.parent / f"profile-{index}"
                release = {"ID": distro, "VERSION_ID": version}
                profile = select_profile(release)
                xml = feed().replace(b"Ubuntu 24.04 LTS", profile["platform"].encode())
                finding_class = profile["finding_classes"][0]
                xml = xml.replace(b'class="vulnerability"', f'class="{finding_class}"'.encode())
                report, _, opener, _ = self.scan(release=release, xml=xml, result_xml=results("true"))
                self.assertEqual(report["status"], "complete")
                self.assertEqual(report["platform"], profile)
                self.assertEqual(report["provenance"]["feed"]["finding_classes"], profile["finding_classes"])
                self.assertEqual(len(report["findings"]), 1)
                self.assertEqual(report["findings"][0]["class"], finding_class)
                self.assertEqual(report["counts"]["true"], 2)
                opener.open.assert_called_once_with(profile["feed_url"], timeout=scanner._SOCKET_TIMEOUT)

    def test_unavailable_platforms_never_download_or_evaluate(self):
        cases = [("rhel", "10"), ("rocky", "10"), ("amzn", "2023"), ("fedora", "45"),
                 ("centos", "9"), ("debian", "10"), ("ubuntu;curl", "24.04")]
        for index, (distro, version) in enumerate(cases):
            with self.subTest(distro=distro):
                self.output = self.parent / f"unavailable-{index}"
                report, popen, opener, _ = self.scan(
                    release={"ID": distro, "VERSION_ID": version, "ID_LIKE": "rhel ubuntu"})
                self.assertEqual(report["status"], "incomplete")
                self.assertIsNone(report["provenance"]["feed"]["url"])
                self.assertTrue(report["platform"]["scan_unavailable"])
                popen.assert_not_called()
                opener.open.assert_not_called()

    def test_version_or_vendor_mismatched_feed_stops_before_eval(self):
        for index, platform_name in enumerate(("Ubuntu 22.04 LTS", "Debian GNU/Linux 13", "Ubuntu 24.040 LTS")):
            with self.subTest(platform=platform_name):
                self.output = self.parent / f"mismatch-{index}"
                report, popen, _, _ = self.scan(
                    xml=feed().replace(b"Ubuntu 24.04 LTS", platform_name.encode()))
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(popen.call_count, 1)
                self.assertIn("platform identity", " ".join(report["limitations"]))

    def test_final_response_cannot_switch_official_stream(self):
        report, popen, _, _ = self.scan(final_url=FEED_URL.replace("noble", "jammy"))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(popen.call_count, 1)

    def test_stale_rocky_feed_explains_missing_current_vendor_coverage(self):
        xml = feed("2025-03-31T18:50:00Z").replace(b"Ubuntu 24.04 LTS", b"Rocky Linux 9")
        report, popen, _, _ = self.scan(release={"ID": "rocky", "VERSION_ID": "9"}, xml=xml)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(popen.call_count, 1)
        self.assertIn("Rocky Linux 9 official OVAL patch feed is stale", " ".join(report["limitations"]))

    def test_distro_specific_install_prerequisite(self):
        report, popen, opener, _ = self.scan(
            release={"ID": "opensuse-leap", "VERSION_ID": "16.0"}, executable=None)
        self.assertIn("openscap-utils", " ".join(report["limitations"]))
        popen.assert_not_called()
        opener.open.assert_not_called()

    def test_debian_eleven_does_not_suggest_nonexistent_native_package(self):
        report, popen, opener, _ = self.scan(
            release={"ID": "debian", "VERSION_ID": "11"}, executable=None)
        self.assertIn("no scanner package", " ".join(report["limitations"]))
        popen.assert_not_called()
        opener.open.assert_not_called()

    def test_forged_profile_url_is_rejected_before_network(self):
        profile = dict(PROFILE, feed_url="https://attacker.invalid/feed.xml.bz2")
        with patch.object(scanner.urllib.request, "build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "allowlisted"):
                scanner._download(-1, profile)
        opener.assert_not_called()

    def test_feed_test_identity_without_affected_metadata(self):
        xml = feed().replace(b"<platform>Ubuntu 24.04 LTS</platform>", b"")
        xml = xml.replace(b"</oval_definitions>", b'<tests><test comment="AlmaLinux 9 is installed"/></tests></oval_definitions>')
        path = MagicMock()
        path.open.return_value = io.BytesIO(xml)
        profile = select_profile({"ID": "almalinux", "VERSION_ID": "9"})
        with patch.object(scanner, "_now", return_value=NOW):
            self.assertEqual(scanner._validate_feed(path, profile), NOW.isoformat())

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
