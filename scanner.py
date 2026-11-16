"""Local package security evaluation using vendor OVAL and installed OpenSCAP."""

import argparse
import bz2
import codecs
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request
from xml.parsers import expat

from oval_report import MAX_XML_BYTES, parse_results
from profiles import select_profile


_MAX_COMPRESSED = 64 * 1024 * 1024
_MAX_XML = MAX_XML_BYTES
_DOWNLOAD_TIMEOUT = 120
_SOCKET_TIMEOUT = 15
_SCAN_TIMEOUT = 900
_FEED_MAX_AGE = timedelta(days=7)
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_LIMITATIONS = [
    "Only the selected vendor OVAL stream is evaluated; this is not a Tenable equivalent.",
    "No remote targets, exploit attempts, application dependency audit, or automatic remediation.",
    "A complete scan with no findings does not prove the host is secure; feed coverage and probe visibility apply.",
    "Raw results and HTML contain local system inventory; keep the private output directory confidential.",
    "Feed authenticity relies on verified HTTPS, not a separately verified publisher signature.",
]
_OVAL = "http://oval.mitre.org/XMLSchema/oval-definitions-5}"
_COMMON = "http://oval.mitre.org/XMLSchema/oval-common-5}"


class _ScanError(ValueError):
    """A safe, locally authored diagnostic suitable for the summary."""


def _now():
    return datetime.now(timezone.utc)


def _allowed_url(url, profile):
    # Pin both host and release-specific path; even another official feed is wrong.
    selected = select_profile({"ID": profile["id"], "VERSION_ID": profile["version"]})
    return (selected["feed_url"] is not None and url == selected["feed_url"]
            and profile["feed_url"] == selected["feed_url"])


class _OfficialRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    max_repeats = 1

    def __init__(self, profile):
        super().__init__()
        self.profile = profile

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed_url(newurl, self.profile):
            raise _ScanError("Feed redirect left the selected official HTTPS stream.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _private_file(directory_fd, name, mode="wb"):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    return os.fdopen(fd, mode)


def _new_directory(output_dir):
    path = Path(os.path.abspath(output_dir))
    parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        if os.fstat(fd).st_uid != os.geteuid():
            os.close(fd)
            raise _ScanError("Output directory is not owned by the current user.")
        os.fchmod(fd, 0o700)
        return path, fd
    finally:
        os.close(parent_fd)


def _download(directory_fd, profile):
    if not _allowed_url(profile["feed_url"], profile):
        raise _ScanError("No allowlisted official HTTPS stream exists for this profile.")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _OfficialRedirect(profile),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + _DOWNLOAD_TIMEOUT
    digest = hashlib.sha256()
    size = 0
    with opener.open(profile["feed_url"], timeout=_SOCKET_TIMEOUT) as response, \
            _private_file(directory_fd, "feed.xml.bz2") as output:
        if response.status != 200 or not _allowed_url(response.geturl(), profile):
            raise _ScanError("Official feed download returned an invalid response.")
        while True:
            if time.monotonic() > deadline:
                raise _ScanError("Official feed download exceeded its time limit.")
            block = response.read1(64 * 1024)
            if time.monotonic() > deadline:
                raise _ScanError("Official feed download exceeded its time limit.")
            if not block:
                break
            size += len(block)
            if size > _MAX_COMPRESSED:
                raise _ScanError("Compressed feed exceeded its size limit.")
            digest.update(block)
            output.write(block)
        final_url = response.geturl()
    if not size:
        raise _ScanError("Official feed download was empty.")
    return {"url": profile["feed_url"], "final_url": final_url, "downloaded_at": _now().isoformat(),
            "compressed_sha256": digest.hexdigest(), "compressed_bytes": size}


def _unpack(directory_fd, root):
    decoder = bz2.BZ2Decompressor()
    digest = hashlib.sha256()
    size = 0
    with (root / "feed.xml.bz2").open("rb") as source, \
            _private_file(directory_fd, "feed.xml") as output:
        while block := source.read(64 * 1024):
            if decoder.eof:
                raise _ScanError("Compressed feed contains trailing data.")
            while True:
                decoded = decoder.decompress(block, max_length=min(64 * 1024, _MAX_XML - size + 1))
                block = b""
                size += len(decoded)
                if size > _MAX_XML:
                    raise _ScanError("Decompressed feed exceeded its size limit.")
                digest.update(decoded)
                output.write(decoded)
                if decoder.eof or decoder.needs_input:
                    break
            if decoder.unused_data:
                raise _ScanError("Compressed feed contains trailing data.")
    if not decoder.eof or not size:
        raise _ScanError("Compressed feed is truncated or empty.")
    return {"sha256": digest.hexdigest(), "bytes": size}


def _validate_feed(path, profile):
    parser = expat.ParserCreate(namespace_separator="}")
    stack = []
    timestamp = None
    text = []
    timestamp_path = [_OVAL + "oval_definitions", _OVAL + "generator", _COMMON + "timestamp"]
    platform_path = [_OVAL + part for part in
                     ("oval_definitions", "definitions", "definition", "metadata", "affected", "platform")]
    platform_text = []
    identity_found = False

    def reject(*args):
        raise _ScanError("Feed XML DTDs and entities are prohibited.")

    def declaration(version, encoding, standalone):
        if encoding and encoding.lower() not in ("utf-8", "utf8"):
            raise _ScanError("Feed XML must be UTF-8.")

    def start(name, attrs):
        nonlocal identity_found
        if not stack and name != _OVAL + "oval_definitions":
            raise _ScanError("Feed is not an OVAL definitions document.")
        if len(stack) >= 256:
            raise _ScanError("Feed XML exceeds the nesting limit.")
        stack.append(name)
        if stack == timestamp_path:
            text.clear()
        if stack == platform_path:
            platform_text.clear()
        if len(stack) == 3 and stack[1] == _OVAL + "tests":
            identity_found |= attrs.get("comment") == profile["platform"] + " is installed"

    def characters(value):
        if stack == timestamp_path:
            if sum(map(len, text)) + len(value) > 100:
                raise _ScanError("Feed generator timestamp is invalid.")
            text.append(value)
        if stack == platform_path:
            if sum(map(len, platform_text)) + len(value) > 1024:
                raise _ScanError("Feed platform metadata exceeds the size limit.")
            platform_text.append(value)

    def end(name):
        nonlocal timestamp, identity_found
        if stack == timestamp_path:
            if timestamp is not None:
                raise _ScanError("Feed must contain exactly one generator timestamp.")
            timestamp = "".join(text).strip()
        if stack == platform_path:
            identity_found |= "".join(platform_text).strip() == profile["platform"]
        stack.pop()

    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.XmlDeclHandler = declaration
    parser.StartElementHandler = start
    parser.CharacterDataHandler = characters
    parser.EndElementHandler = end
    decoder = codecs.getincrementaldecoder("utf-8-sig")()
    size = 0
    try:
        with path.open("rb") as source:
            while block := source.read(min(64 * 1024, _MAX_XML - size + 1)):
                size += len(block)
                if size > _MAX_XML:
                    raise _ScanError("Feed XML exceeds the size limit.")
                if b"\x00" in block:
                    raise _ScanError("Feed XML must be UTF-8.")
                decoder.decode(block)
                parser.Parse(block, False)
            decoder.decode(b"", final=True)
            parser.Parse(b"", True)
    except UnicodeError:
        raise _ScanError("Feed XML must be UTF-8.") from None
    except expat.ExpatError:
        raise _ScanError("Official feed XML is malformed.") from None
    if timestamp is None:
        raise _ScanError("Feed must contain exactly one generator timestamp.")
    try:
        generated = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise _ScanError("Feed generator timestamp is invalid.") from None
    # Vendor timezone-less OVAL generator timestamps are interpreted as UTC.
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    age = _now() - generated
    if age < -timedelta(minutes=5):
        raise _ScanError("Feed generator timestamp is in the future; check the host clock.")
    if age > _FEED_MAX_AGE:
        raise _ScanError(f"{profile['label']} official {profile['feed_kind']} feed is stale "
                         "(generator timestamp older than seven days); current coverage is unavailable.")
    if not identity_found:
        raise _ScanError(f"Official feed lacks matching {profile['platform']} platform identity; refusing another vendor or release.")
    return generated.isoformat()


def _execute(args, directory_fd, root, timeout, stdout):
    env = dict(_ENV, TMPDIR=str(root), HOME=str(root))
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=subprocess.DEVNULL,
                          cwd=root, env=env, pass_fds=(directory_fd,), start_new_session=True) as process:
        try:
            return process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


def run_scan(output_dir):
    """Return a complete/incomplete report; never reuse an output directory."""
    report = {"status": "incomplete", "counts": {}, "findings": [],
              "limitations": list(_LIMITATIONS), "started_at": _now().isoformat(),
              "platform": None,
              "provenance": {"feed": {}, "engine": {"name": "OpenSCAP"}},
              "artifacts": {}}
    try:
        output, directory_fd = _new_directory(output_dir)
    except (OSError, ValueError):
        report["limitations"].append("Cannot create a new private output directory; existing paths are never overwritten.")
        report["finished_at"] = _now().isoformat()
        return report
    # Pin every engine path to the private directory inode, even if its parent is renamed.
    root = Path(f"/proc/self/fd/{directory_fd}")
    phase = "host prerequisites"
    try:
        if platform.system() != "Linux":
            raise _ScanError("Only local Linux hosts are supported.")
        profile = select_profile(platform.freedesktop_os_release())
        report["platform"] = profile
        report["provenance"]["feed"].update({
            "url": profile["feed_url"], "kind": profile["feed_kind"],
            "finding_classes": profile["finding_classes"], "source_url": profile["source_url"],
        })
        if profile["scan_unavailable"]:
            raise _ScanError(profile["scan_unavailable"])
        report["limitations"].append(
            f"{profile['label']}: {profile['feed_kind']} definitions only. "
            "Patch findings mean vendor security advisories apply, not a complete inventory of all CVEs. "
            "Only vendor-covered packages, releases, repositories and support entitlements are represented.")
        if profile["id"] == "rhel":
            report["limitations"].append(
                "RHEL base-stream security advisories only; EUS/E4S/AUS/TUS and layered-product streams are not evaluated.")
        if os.geteuid() != 0:
            raise _ScanError("Run as root to provide authenticated local probe access.")
        executable = shutil.which("oscap", path=_ENV["PATH"])
        if executable is None:
            if profile["oscap_package"] is None:
                raise _ScanError("OpenSCAP is not installed; Debian 11 has no scanner package in its release repository. "
                                 "A compatible, trusted OpenSCAP installation is required; do not mix distribution repositories.")
            raise _ScanError(f"OpenSCAP is not installed; install the {profile['oscap_package']} system package for {profile['label']}.")
        phase = "OpenSCAP version"
        with _private_file(directory_fd, "engine-version.txt") as version_output:
            code = _execute([executable, "--version"], directory_fd, root, 15, version_output)
        with (root / "engine-version.txt").open("rb") as version_output:
            version = re.search(rb"OpenSCAP command line tool \(oscap\) ([0-9][0-9A-Za-z.+~-]{0,63})",
                                version_output.read(8192))
        if code != 0 or version is None:
            raise _ScanError("Could not determine the installed OpenSCAP version.")
        report["provenance"]["engine"].update({"version": version.group(1).decode("ascii"), "path": executable})
        phase = "official feed download"
        report["provenance"]["feed"].update(_download(directory_fd, profile))
        phase = "official feed validation"
        report["provenance"]["feed"].update(_unpack(directory_fd, root))
        report["provenance"]["feed"]["generated_at"] = _validate_feed(root / "feed.xml", profile)
        phase = "OpenSCAP evaluation"
        args = [executable, "oval", "eval", "--results", str(root / "results.xml"),
                "--report", str(root / "report.html"), str(root / "feed.xml")]
        code = _execute(args, directory_fd, root, _SCAN_TIMEOUT, subprocess.DEVNULL)
        report["provenance"]["engine"]["exit_code"] = code
        phase = "OVAL results parsing"
        for name in ("results.xml", "report.html"):
            info = (root / name).lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
                raise _ScanError("OpenSCAP did not produce regular, nonempty XML and HTML results.")
        parsed = parse_results(root / "results.xml", root / "feed.xml",
                               finding_classes=tuple(profile["finding_classes"]), host_platform=profile["platform"])
        report.update({key: parsed[key] for key in ("status", "counts", "findings")})
        report["limitations"].extend(parsed["limitations"])
        # Unlike XCCDF, `oval eval` documents only zero as successful evaluation.
        if code != 0:
            report["status"] = "incomplete"
            report["limitations"].append(f"OpenSCAP OVAL evaluation failed (exit {code}).")
    except _ScanError as error:
        report["status"] = "incomplete"
        # Only locally authored messages cross this boundary; never raw XML or engine diagnostics.
        report["limitations"].append(f"Scan stopped during {phase}: {error}")
    except subprocess.TimeoutExpired:
        report["status"] = "incomplete"
        report["limitations"].append(f"Scan timed out during {phase}; engine diagnostics withheld.")
    except (OSError, EOFError, ValueError, urllib.error.URLError, http.client.HTTPException) as error:
        report["status"] = "incomplete"
        reason = "system/network diagnostics withheld"
        if phase == "official feed download":
            cause = error.reason if isinstance(error, urllib.error.URLError) else error
            if isinstance(error, urllib.error.HTTPError) and isinstance(error.code, int) and 100 <= error.code <= 599:
                reason = f"HTTP status {error.code}"
            elif isinstance(cause, ssl.SSLCertVerificationError):
                reason = "TLS certificate verification failure"
            elif isinstance(cause, ssl.SSLError):
                reason = "TLS connection error"
            elif isinstance(cause, TimeoutError):
                reason = "network timeout"
            elif isinstance(error, urllib.error.URLError) or isinstance(cause, ConnectionError):
                reason = "network connection error"
            elif isinstance(cause, http.client.HTTPException):
                reason = "HTTP protocol error"
        report["limitations"].append(f"Scan failed during {phase}; {reason}.")
    except KeyboardInterrupt:
        report["status"] = "incomplete"
        report["limitations"].append("Scan interrupted; evaluation is incomplete.")
    finally:
        report["finished_at"] = _now().isoformat()
        for name in ("feed.xml.bz2", "feed.xml", "results.xml", "report.html", "engine-version.txt"):
            try:
                artifact_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                try:
                    if not stat.S_ISREG(os.fstat(artifact_fd).st_mode):
                        raise OSError("Artifact is not a regular file.")
                    os.fchmod(artifact_fd, 0o600)
                    report["artifacts"][name] = str(output / name)
                finally:
                    os.close(artifact_fd)
            except OSError:
                report["status"] = "incomplete"
        report["artifacts"]["summary.json"] = str(output / "summary.json")
        try:
            with _private_file(directory_fd, "summary.json", "w") as summary:
                json.dump(report, summary, indent=2)
                summary.write("\n")
        except OSError:
            report["status"] = "incomplete"
            report["artifacts"].pop("summary.json", None)
            report["limitations"].append("Could not persist summary.json; this scan is incomplete.")
        finally:
            os.close(directory_fd)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, metavar="DIR", help="new private artifact directory (must not exist)")
    args = parser.parse_args(argv)
    report = run_scan(args.output)
    print(json.dumps(report, indent=2))
    if report["status"] != "complete":
        return 1
    return 2 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
