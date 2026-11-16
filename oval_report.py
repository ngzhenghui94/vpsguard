"""Interpret local OpenSCAP OVAL results against their exact source feed."""

from pathlib import Path
import re
import xml.etree.ElementTree as ET


DEFINITIONS_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
RESULTS_NS = "http://oval.mitre.org/XMLSchema/oval-results-5"
RESULT_VALUES = ("true", "false", "unknown", "error", "not evaluated", "not applicable")
MAX_XML_BYTES = 256 * 1024 * 1024


def _load_xml(path, namespace, root_name):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_XML_BYTES + 1)
    except OSError:
        raise ValueError("Unable to read OVAL XML evidence.") from None
    if len(data) > MAX_XML_BYTES:
        raise ValueError("OVAL XML exceeds the size limit.")
    # Canonical/OpenSCAP emit UTF-8; disallow alternate encodings that hide declarations.
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("OVAL XML must be UTF-8.") from None
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise ValueError("OVAL XML DTDs and entities are prohibited.")
    declaration = re.match(r"\s*<\?xml\s+([^?]*)\?>", text)
    if declaration:
        encoding = re.search(r"encoding\s*=\s*['\"]([^'\"]+)['\"]", declaration[1])
        if encoding and encoding[1].lower() not in ("utf-8", "utf8"):
            raise ValueError("OVAL XML must be UTF-8.")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        raise ValueError("Malformed OVAL XML evidence.") from None
    if root.tag != f"{{{namespace}}}{root_name}":
        raise ValueError("Unexpected OVAL XML root or namespace.")
    return root


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
    """
    limitations = set()
    feed = _load_xml(feed_path, DEFINITIONS_NS, "oval_definitions")
    sections = _children(feed, "definitions", DEFINITIONS_NS, limitations)
    if len(sections) != 1:
        limitations.add("The feed must contain exactly one definitions section.")
    source = {}
    ambiguous_source = set()
    for section in sections:
        for definition in _children(section, "definition", DEFINITIONS_NS, limitations):
            identifier = definition.get("id")
            if not identifier or not definition.get("version") or not definition.get("class"):
                limitations.add("A source definition lacks its ID, version or class.")
                continue
            if identifier in source:
                ambiguous_source.add(identifier)
                limitations.add("The feed contains duplicate definition IDs.")
                continue
            source[identifier] = {
                "version": definition.get("version"), "class": definition.get("class"),
                **_metadata(definition, limitations),
            }
        section.clear()
    if not source:
        limitations.add("The feed contains no usable definitions.")
    del feed, sections

    root = _load_xml(results_path, RESULTS_NS, "oval_results")
    result_sections = _children(root, "results", RESULTS_NS, limitations)
    if len(result_sections) != 1:
        limitations.add("OVAL evidence must contain exactly one results section.")
    systems = [system for section in result_sections
               for system in _children(section, "system", RESULTS_NS, limitations)]
    if len(systems) != 1:
        limitations.add("OVAL evidence must contain exactly one system; results cannot be attributed to this host.")
    counts = dict.fromkeys(RESULT_VALUES, 0)
    rows = {}
    duplicates = set()
    for system in systems:
        sections = _children(system, "definitions", RESULTS_NS, limitations)
        if len(sections) != 1:
            limitations.add("An OVAL system has missing or ambiguous definition results.")
        for section in sections:
            for definition in _children(section, "definition", RESULTS_NS, limitations):
                result = definition.get("result")
                if result in counts:
                    counts[result] += 1
                else:
                    limitations.add("A definition has a missing or unrecognized OVAL result value.")
                identifier = definition.get("definition_id")
                if not identifier or identifier not in source:
                    limitations.add("A result definition ID is absent from the source feed.")
                    continue
                if identifier in rows:
                    duplicates.add(identifier)
                    limitations.add("OVAL evidence contains duplicate definition results.")
                rows[identifier] = definition
    if source.keys() - rows.keys():
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
        if result == "true" and definition["class"] == "vulnerability" and len(systems) == 1:
            findings.append({"id": identifier, "title": definition["title"],
                             "cves": definition["cves"], "severity": definition["severity"],
                             "references": definition["references"], "result": "true"})
    return {"status": "incomplete" if limitations else "complete", "counts": counts,
            "findings": findings, "limitations": sorted(limitations)}
