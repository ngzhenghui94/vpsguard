"""Interpret local OpenSCAP OVAL results against their exact source feed."""

import codecs
from pathlib import Path
import re
import xml.etree.ElementTree as ET


DEFINITIONS_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
RESULTS_NS = "http://oval.mitre.org/XMLSchema/oval-results-5"
SYSTEM_NS = "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
_ADVISORY_NAMESPACES = (DEFINITIONS_NS, "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux")
_TEST_NAMESPACES = tuple(DEFINITIONS_NS + "#" + kind for kind in ("linux", "unix", "independent"))
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
RESULT_VALUES = ("true", "false", "unknown", "error", "not evaluated", "not applicable")
# The measured Noble feed is 277,893,224 bytes; leave bounded growth headroom.
MAX_XML_BYTES = 2 * 1024 * 1024 * 1024
_XML_CHUNK_BYTES = 64 * 1024
_MAX_XML_DEPTH = 256


class _XMLReader:
    """Validate each bounded UTF-8 chunk before ElementTree sees it."""

    def __init__(self, stream):
        self.stream = stream
        self.decoder = codecs.getincrementaldecoder("utf-8-sig")()
        self.size = 0
        self.declaration = ""
        self.tail = ""

    def read(self, size=-1):
        if size == 0:
            return ""
        size = min(size, _XML_CHUNK_BYTES) if size > 0 else _XML_CHUNK_BYTES
        while True:
            data = self.stream.read(min(size, MAX_XML_BYTES - self.size + 1))
            self.size += len(data)
            if self.size > MAX_XML_BYTES:
                raise ValueError("OVAL XML exceeds the size limit.")
            try:
                text = self.decoder.decode(data, final=not data)
            except UnicodeError:
                raise ValueError("OVAL XML must be UTF-8.") from None
            if text or not data:
                break
        # Collapse whitespace so even a declaration split by long whitespace is caught.
        probe = re.sub(r"\s+", " ", self.tail + text)
        for match in re.finditer(r"<!\s*(?:DOCTYPE|ENTITY)\b", probe, re.IGNORECASE):
            if not data or match.end() < len(probe):
                raise ValueError("OVAL XML DTDs and entities are prohibited.")
        if "\x00" in text:
            raise ValueError("OVAL XML DTDs and entities are prohibited.")
        self.tail = probe[-16:]
        if self.declaration is not None:
            self.declaration += text
            prefix = self.declaration.lstrip()
            if "?>" in prefix:
                declaration = re.match(r"<\?xml\s+([^?]*)\?>", prefix)
                if declaration:
                    encoding = re.search(r"encoding\s*=\s*['\"]([^'\"]+)['\"]", declaration[1])
                    if encoding and encoding[1].lower() not in ("utf-8", "utf8"):
                        raise ValueError("OVAL XML must be UTF-8.")
                self.declaration = None
            elif prefix and not "<?xml".startswith(prefix) and not prefix.startswith("<?xml"):
                self.declaration = None
            elif len(self.declaration) > _XML_CHUNK_BYTES:
                raise ValueError("OVAL XML declaration exceeds the size limit.")
        return text


def _keep_metadata(stack):
    if (len(stack) < 4 or stack[1].tag != f"{{{DEFINITIONS_NS}}}definitions"
            or stack[2].tag != f"{{{DEFINITIONS_NS}}}definition"
            or stack[3].tag.rsplit("}", 1)[-1] != "metadata"):
        return False
    if len(stack) == 4:
        return True
    if stack[3].tag != f"{{{DEFINITIONS_NS}}}metadata":
        return False
    name = stack[4].tag.rsplit("}", 1)[-1]
    if len(stack) == 5:
        return name in ("title", "reference", "advisory", "affected")
    if name == "advisory":
        if stack[4].tag not in tuple(f"{{{ns}}}advisory" for ns in _ADVISORY_NAMESPACES):
            return False
        return stack[5].tag.rsplit("}", 1)[-1] in (
            "severity", "cve", "ref", "bug", "bugzilla")
    if stack[4].tag != f"{{{DEFINITIONS_NS}}}{name}":
        return False
    return name == "title" or (name == "affected" and stack[5].tag.rsplit("}", 1)[-1] == "platform")


def _xml_events(path, namespace, root_name, keep_metadata=False):
    stack = []
    try:
        with Path(path).open("rb") as stream:
            for event, element in ET.iterparse(_XMLReader(stream), events=("start", "end")):
                if event == "start":
                    stack.append(element)
                    if len(stack) > _MAX_XML_DEPTH:
                        raise ValueError("OVAL XML nesting exceeds the depth limit.")
                    if len(stack) == 1 and element.tag != f"{{{namespace}}}{root_name}":
                        raise ValueError("Unexpected OVAL XML root or namespace.")
                yield event, stack
                if event == "end":
                    if not keep_metadata or not _keep_metadata(stack):
                        element.clear()
                        if len(stack) > 1:
                            stack[-2].remove(element)
                    stack.pop()
    except OSError:
        raise ValueError("Unable to read OVAL XML evidence.") from None
    except ET.ParseError:
        raise ValueError("Malformed OVAL XML evidence.") from None


def _matches(element, name, namespace, limitations):
    if element.tag.rsplit("}", 1)[-1] != name:
        return False
    if element.tag != f"{{{namespace}}}{name}":
        limitations.add("An OVAL evidence element has the wrong namespace.")
        return False
    return True


def _children(parent, name, namespace, limitations):
    matches = []
    for child in parent:
        if child.tag.rsplit("}", 1)[-1] == name:
            if child.tag != f"{{{namespace}}}{name}":
                limitations.add("An OVAL evidence element has the wrong namespace.")
            else:
                matches.append(child)
    return matches

def _advisory_children(parent, name, limitations):
    children = []
    for child in parent:
        if child.tag.rsplit("}", 1)[-1] == name:
            if child.tag in tuple(f"{{{ns}}}{name}" for ns in _ADVISORY_NAMESPACES):
                children.append(child)
            else:
                limitations.add("An OVAL evidence element has the wrong namespace.")
    return children


def _platform_name(value):
    """Normalize spelling only, never alias one vendor to another."""
    return " ".join(value.casefold().split())


def _host_matches(platform, name, version):
    platform = _platform_name(platform).removesuffix(" lts")
    name = _platform_name(name)
    version = _platform_name(version)
    if not name or not version:
        return False
    # os_name may already contain the release; otherwise os_version supplies it.
    for candidate in (name, name + " " + version):
        if candidate == platform or candidate.startswith(platform + " "):
            return True
        if candidate.startswith(platform + "."):
            return True
    return False


def _metadata(definition, limitations):
    metadata = _children(definition, "metadata", DEFINITIONS_NS, limitations)
    if len(metadata) != 1:
        limitations.add("A source definition has missing or ambiguous metadata.")
        return {"title": "", "cves": [], "severity": None, "references": [], "platforms": []}
    metadata = metadata[0]
    titles = _children(metadata, "title", DEFINITIONS_NS, limitations)
    title = "".join(titles[0].itertext()).strip() if len(titles) == 1 else ""
    if not title:
        limitations.add("A source definition has no unambiguous title.")
    references = [
        {"source": ref.get("source", ""), "ref_id": ref.get("ref_id", ""),
         "ref_url": ref.get("ref_url", "")}
        for ref in _children(metadata, "reference", DEFINITIONS_NS, limitations)
    ]
    cves = {match.upper() for ref in references if ref["source"].upper() in ("CVE", "SUSE CVE")
            for match in _CVE.findall(ref["ref_id"])}
    platforms = [
        "".join(platform.itertext()).strip()
        for affected in _children(metadata, "affected", DEFINITIONS_NS, limitations)
        for platform in _children(affected, "platform", DEFINITIONS_NS, limitations)
    ]
    severities = []
    for advisory in _advisory_children(metadata, "advisory", limitations):
        for severity in _advisory_children(advisory, "severity", limitations):
            value = "".join(severity.itertext()).strip()
            if value:
                severities.append(value)
        for cve in _advisory_children(advisory, "cve", limitations):
            identifier = "".join(cve.itertext()).strip()
            cves.update(match.upper() for match in _CVE.findall(identifier))
            references.append({"source": "CVE", "ref_id": identifier,
                               "ref_url": cve.get("href", "")})
        for kind in ("ref", "bug", "bugzilla"):
            for link in _advisory_children(advisory, kind, limitations):
                value = "".join(link.itertext()).strip()
                references.append({"source": kind, "ref_id": link.get("id", ""),
                                   "ref_url": link.get("href", value)})
    if len(set(severities)) > 1:
        limitations.add("A source definition has conflicting severity metadata.")
    return {"title": title, "cves": sorted(cves), "platforms": platforms,
            "severity": severities[0] if severities else None, "references": references}


def parse_results(results_path, feed_path, *, finding_classes=("vulnerability",), host_platform=None):
    """Return counts, findings and completeness; reject unreadable/unsafe XML.

    Counts describe observed result rows, including duplicate or unmatched rows;
    findings require an unambiguous ID/version match to an allowed finding class.
    host_platform is an optional scanner assertion from authenticated local OS
    identity and a vendor-specific feed profile, never a value taken from the feed.
    Metadata is untrusted source data, not HTML or an instruction to follow links.
    Memory retains metadata/identity maps, not the XML documents; individual XML
    text/attribute tokens and selected metadata can still approach the byte cap.
    """
    limitations = set()
    if (not isinstance(finding_classes, tuple) or not finding_classes
            or any(kind not in ("vulnerability", "patch") for kind in finding_classes)):
        raise ValueError("Unsupported OVAL finding classes.")
    if host_platform is not None and (not isinstance(host_platform, str) or not host_platform.strip()):
        raise ValueError("Invalid host platform assertion.")
    platform_tests = {}
    ambiguous_tests = set()
    platform_names = set()
    referenced_tests = set()
    platform_test_refs = set()
    referenced_inventory = set()
    seen_tests = set()
    source = {}
    seen_source = set()
    ambiguous_source = set()
    section_count = 0
    for event, stack in _xml_events(feed_path, DEFINITIONS_NS, "oval_definitions", keep_metadata=True):
        definition = stack[-1]
        if len(stack) == 2 and event == "start":
            section_count += _matches(definition, "definitions", DEFINITIONS_NS, limitations)
        if (len(stack) == 6 and event == "end"
                and stack[1].tag == f"{{{DEFINITIONS_NS}}}definitions"
                and stack[2].tag == f"{{{DEFINITIONS_NS}}}definition"
                and stack[3].tag == f"{{{DEFINITIONS_NS}}}metadata"
                and stack[4].tag == f"{{{DEFINITIONS_NS}}}affected"
                and definition.tag == f"{{{DEFINITIONS_NS}}}platform"):
            platform_names.add(_platform_name("".join(definition.itertext())))
        if (len(stack) >= 5 and event == "end"
                and stack[1].tag == f"{{{DEFINITIONS_NS}}}definitions"
                and stack[2].tag == f"{{{DEFINITIONS_NS}}}definition"
                and stack[3].tag == f"{{{DEFINITIONS_NS}}}criteria"):
            if _matches(definition, "criterion", DEFINITIONS_NS, limitations):
                referenced_tests.add(definition.get("test_ref"))
                comment = definition.get("comment", "")
                known = {_platform_name(host_platform)} if host_platform else platform_names
                if (comment.endswith(" is installed")
                        and _platform_name(comment[:-len(" is installed")]) in known
                        and definition.get("negate", "false") == "false"):
                    platform_test_refs.add(definition.get("test_ref"))
            if (_matches(definition, "extend_definition", DEFINITIONS_NS, limitations)
                    and stack[2].get("class") in finding_classes
                    and definition.get("negate", "false") == "false"):
                referenced_inventory.add(definition.get("definition_ref"))
        if (len(stack) == 3 and event == "end"
                and stack[1].tag == f"{{{DEFINITIONS_NS}}}tests"
                and definition.tag.rsplit("}", 1)[-1].endswith("_test")):
            identifier = definition.get("id")
            if identifier in referenced_tests:
                if identifier in seen_tests:
                    ambiguous_tests.add(identifier)
                    limitations.add("The feed contains duplicate referenced test IDs.")
                seen_tests.add(identifier)
            comment = definition.get("comment", "")
            platform = comment.removesuffix(" is installed")
            known = {_platform_name(host_platform)} if host_platform else platform_names
            if (identifier in platform_test_refs
                    or (comment.endswith(" is installed") and _platform_name(platform) in known)):
                if identifier in referenced_tests:
                    if definition.tag.split("}", 1)[0].lstrip("{") not in _TEST_NAMESPACES:
                        limitations.add("A platform test has the wrong namespace.")
                    elif not identifier or not definition.get("version"):
                        limitations.add("A platform test lacks its ID or version.")
                    elif identifier in platform_tests:
                        ambiguous_tests.add(identifier)
                        limitations.add("The feed contains duplicate platform test IDs.")
                    else:
                        platform_tests[identifier] = definition.get("version")
        if (len(stack) != 3 or stack[1].tag != f"{{{DEFINITIONS_NS}}}definitions"
                or event != "end" or not _matches(definition, "definition", DEFINITIONS_NS, limitations)):
            continue
        identifier = definition.get("id")
        duplicate = identifier in seen_source
        if identifier:
            seen_source.add(identifier)
        if duplicate:
            ambiguous_source.add(identifier)
            limitations.add("The feed contains duplicate definition IDs.")
        if not identifier or not definition.get("version") or not definition.get("class"):
            limitations.add("A source definition lacks its ID, version or class.")
            continue
        if duplicate:
            continue
        source[identifier] = {
            "version": definition.get("version"), "class": definition.get("class"),
            **_metadata(definition, limitations),
        }
        platform_names.update(_platform_name(name) for name in source[identifier]["platforms"])
        if definition.get("class") not in (*finding_classes, "inventory"):
            limitations.add("The source feed contains an unsupported definition class.")
    del seen_source
    if section_count != 1:
        limitations.add("The feed must contain exactly one definitions section.")
    if not source:
        limitations.add("The feed contains no usable definitions.")
    if platform_test_refs.difference(platform_tests):
        limitations.add("A source platform criterion has no unambiguous test definition.")

    counts = dict.fromkeys(RESULT_VALUES, 0)
    rows = {}
    duplicates = set()
    result_sections = 0
    system_count = 0
    definition_sections = 0
    test_rows = {}
    duplicate_tests = set()
    host_info = {}
    for event, stack in _xml_events(results_path, RESULTS_NS, "oval_results"):
        element = stack[-1]
        if len(stack) == 2 and event == "start":
            result_sections += _matches(element, "results", RESULTS_NS, limitations)
        if len(stack) < 3 or stack[1].tag != f"{{{RESULTS_NS}}}results":
            continue
        if len(stack) == 3:
            if event == "start" and _matches(element, "system", RESULTS_NS, limitations):
                system_count += 1
                definition_sections = 0
            elif event == "end" and element.tag == f"{{{RESULTS_NS}}}system" and definition_sections != 1:
                limitations.add("An OVAL system has missing or ambiguous definition results.")
        if stack[2].tag != f"{{{RESULTS_NS}}}system":
            continue
        if (len(stack) == 6 and event == "end"
                and stack[3].tag == f"{{{SYSTEM_NS}}}oval_system_characteristics"
                and stack[4].tag == f"{{{SYSTEM_NS}}}system_info"):
            for name in ("os_name", "os_version"):
                if _matches(element, name, SYSTEM_NS, limitations):
                    if name in host_info:
                        limitations.add("OVAL host identity is ambiguous.")
                    host_info[name] = (element.text or "").strip()
        if (len(stack) == 5 and event == "end"
                and stack[3].tag == f"{{{RESULTS_NS}}}tests"
                and _matches(element, "test", RESULTS_NS, limitations)):
            identifier = element.get("test_id")
            if identifier in platform_tests:
                if identifier in test_rows:
                    duplicate_tests.add(identifier)
                    limitations.add("OVAL evidence contains duplicate platform test results.")
                test_rows[identifier] = (element.get("version"), element.get("result"))
        if len(stack) == 4 and event == "start":
            definition_sections += _matches(element, "definitions", RESULTS_NS, limitations)
        if (len(stack) != 5 or stack[3].tag != f"{{{RESULTS_NS}}}definitions"
                or event != "end" or not _matches(element, "definition", RESULTS_NS, limitations)):
            continue
        result = element.get("result")
        if result in counts:
            counts[result] += 1
        else:
            limitations.add("A definition has a missing or unrecognized OVAL result value.")
        identifier = element.get("definition_id")
        if not identifier or identifier not in source:
            limitations.add("A result definition ID is absent from the source feed.")
            continue
        if identifier in rows:
            duplicates.add(identifier)
            limitations.add("OVAL evidence contains duplicate definition results.")
        rows[identifier] = {key: element.get(key) for key in ("version", "class", "result")}
    if result_sections != 1:
        limitations.add("OVAL evidence must contain exactly one results section.")
    if system_count != 1:
        limitations.add("OVAL evidence must contain exactly one system; results cannot be attributed to this host.")
    if any(identifier not in rows for identifier in source):
        limitations.add("OVAL evidence omits source definitions; coverage is incomplete.")
    for result in ("unknown", "error", "not evaluated"):
        if counts[result]:
            limitations.add(f"{counts[result]} definition result(s) are {result}.")

    findings = []
    inventory = []
    inventory_count = sum(definition["class"] == "inventory" for definition in source.values())
    for identifier, row in rows.items():
        definition = source[identifier]
        if identifier in ambiguous_source or identifier in duplicates:
            continue
        if row.get("version") != definition["version"]:
            limitations.add("A result definition version does not match the source feed.")
            continue
        if row.get("class") not in (None, definition["class"]):
            limitations.add("A result definition class does not match the source feed.")
            continue
        result = row.get("result")
        if definition["class"] == "inventory":
            relevant = (identifier in referenced_inventory if referenced_inventory
                        else inventory_count == 1 or any(
                            _host_matches(platform, host_info.get("os_name", ""), host_info.get("os_version", ""))
                            or (host_platform is not None and _platform_name(platform) == _platform_name(host_platform))
                            for platform in definition["platforms"]))
            if relevant and (not host_platform or not definition["platforms"]
                             or _platform_name(host_platform) in map(_platform_name, definition["platforms"])):
                inventory.append(result == "true")
        if result == "true" and definition["class"] in finding_classes and system_count == 1:
            findings.append({"id": identifier, "title": definition["title"],
                             "class": definition["class"],
                             "cves": definition["cves"], "severity": definition["severity"],
                             "references": definition["references"], "result": "true"})
    if platform_tests:
        applicable = any(
            identifier not in ambiguous_tests and identifier not in duplicate_tests
            and test_rows.get(identifier) == (version, "true")
            for identifier, version in platform_tests.items())
        for identifier, version in platform_tests.items():
            row = test_rows.get(identifier)
            if row is None or row[0] != version or row[1] not in ("true", "false", "not applicable"):
                limitations.add("Platform test evidence is missing, mismatched or inconclusive.")
    elif inventory_count:
        applicable = any(inventory)
    else:
        applicable = any(_host_matches(platform, host_info.get("os_name", ""), host_info.get("os_version", ""))
                         for platform in platform_names)
        if host_platform:
            applicable = _platform_name(host_platform) in platform_names
    if host_platform and platform_names and _platform_name(host_platform) not in platform_names:
        limitations.add("The source feed's platforms do not match the asserted host platform.")
        applicable = False
    if host_info.get("os_name") not in (None, "", "Linux"):
        expected = (host_platform,) if host_platform else platform_names
        if expected and not any(_host_matches(platform, host_info["os_name"], host_info.get("os_version", ""))
                                for platform in expected):
            limitations.add("OVAL system identity does not match the source or asserted host platform.")
            applicable = False
    if not applicable:
        limitations.add("The source feed's platform evidence did not confirm host applicability.")
        findings = []
    return {"status": "incomplete" if limitations else "complete", "counts": counts,
            "findings": findings, "limitations": sorted(limitations)}
