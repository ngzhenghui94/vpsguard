"""Interpret local OpenSCAP OVAL results against their exact source feed."""

import codecs
from pathlib import Path
import re
import xml.etree.ElementTree as ET


DEFINITIONS_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
RESULTS_NS = "http://oval.mitre.org/XMLSchema/oval-results-5"
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
        return name in ("title", "reference", "advisory")
    if stack[4].tag != f"{{{DEFINITIONS_NS}}}{name}":
        return False
    if name == "title":
        return True
    if name != "advisory":
        return False
    name = stack[5].tag.rsplit("}", 1)[-1]
    return (name in ("severity", "cve", "ref", "bug")
            and (len(stack) == 6 or stack[5].tag == f"{{{DEFINITIONS_NS}}}{name}"))


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


def _metadata(definition, limitations):
    metadata = _children(definition, "metadata", DEFINITIONS_NS, limitations)
    if len(metadata) != 1:
        limitations.add("A source definition has missing or ambiguous metadata.")
        return {"title": "", "cves": [], "severity": None, "references": []}
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
    cves = {ref["ref_id"] for ref in references
            if ref["source"].upper() == "CVE" and ref["ref_id"]}
    severities = []
    for advisory in _children(metadata, "advisory", DEFINITIONS_NS, limitations):
        for severity in _children(advisory, "severity", DEFINITIONS_NS, limitations):
            value = "".join(severity.itertext()).strip()
            if value:
                severities.append(value)
        for cve in _children(advisory, "cve", DEFINITIONS_NS, limitations):
            identifier = "".join(cve.itertext()).strip()
            if identifier:
                cves.add(identifier)
            references.append({"source": "CVE", "ref_id": identifier,
                               "ref_url": cve.get("href", "")})
        for kind in ("ref", "bug"):
            for link in _children(advisory, kind, DEFINITIONS_NS, limitations):
                value = "".join(link.itertext()).strip()
                references.append({"source": kind, "ref_id": "",
                                   "ref_url": link.get("href", value)})
    if len(set(severities)) > 1:
        limitations.add("A source definition has conflicting severity metadata.")
    return {"title": title, "cves": sorted(cves),
            "severity": severities[0] if severities else None, "references": references}


def parse_results(results_path, feed_path):
    """Return counts, findings and completeness; reject unreadable/unsafe XML.

    Counts describe observed result rows, including duplicate or unmatched rows;
    findings require an unambiguous ID/version match to a vulnerability definition.
    Metadata is untrusted source data, not HTML or an instruction to follow links.
    Memory retains metadata/identity maps, not the XML documents; individual XML
    text/attribute tokens and selected metadata can still approach the byte cap.
    """
    limitations = set()
    source = {}
    seen_source = set()
    ambiguous_source = set()
    section_count = 0
    for event, stack in _xml_events(feed_path, DEFINITIONS_NS, "oval_definitions", keep_metadata=True):
        definition = stack[-1]
        if len(stack) == 2 and event == "start":
            section_count += _matches(definition, "definitions", DEFINITIONS_NS, limitations)
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
    del seen_source
    if section_count != 1:
        limitations.add("The feed must contain exactly one definitions section.")
    if not source:
        limitations.add("The feed contains no usable definitions.")

    counts = dict.fromkeys(RESULT_VALUES, 0)
    rows = {}
    duplicates = set()
    result_sections = 0
    system_count = 0
    definition_sections = 0
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
        if definition["class"] == "inventory" and result != "true":
            limitations.add("The source feed's platform inventory did not evaluate true; host applicability is unconfirmed.")
        if result == "true" and definition["class"] == "vulnerability" and system_count == 1:
            findings.append({"id": identifier, "title": definition["title"],
                             "cves": definition["cves"], "severity": definition["severity"],
                             "references": definition["references"], "result": "true"})
    return {"status": "incomplete" if limitations else "complete", "counts": counts,
            "findings": findings, "limitations": sorted(limitations)}
