import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import oval_report


D = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
R = "http://oval.mitre.org/XMLSchema/oval-results-5"
C = "http://oval.mitre.org/XMLSchema/oval-common-5"
S = "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
INVENTORY = "oval:com.ubuntu.noble:def:100"
VULNERABILITY = "oval:com.ubuntu.noble:def:202512340000000"


def add(parent, namespace, name, text=None, **attributes):
    element = ET.SubElement(parent, f"{{{namespace}}}{name}", attributes)
    element.text = text
    return element


def generator(parent, namespace):
    element = add(parent, namespace, "generator")
    add(element, C, "product_name", "OpenSCAP fixture")
    add(element, C, "schema_version", "5.11.1")
    add(element, C, "timestamp", "2026-11-16T00:00:00")


def feed_fixture(extra=()):
    root = ET.Element(f"{{{D}}}oval_definitions")
    generator(root, D)
    definitions = add(root, D, "definitions")
    for identifier, kind in [(INVENTORY, "inventory"), (VULNERABILITY, "vulnerability"), *extra]:
        definition = add(definitions, D, "definition", id=identifier, version="1", **{"class": kind})
        metadata = add(definition, D, "metadata")
        add(metadata, D, "title", "CVE-2099-9999 in title is not evidence")
        if kind == "vulnerability":
            affected = add(metadata, D, "affected", family="unix")
            add(affected, D, "platform", "Ubuntu 24.04 LTS")
            add(metadata, D, "reference", source="CVE", ref_id="CVE-2025-1234",
                ref_url="https://www.cve.org/CVERecord?id=CVE-2025-1234")
        add(metadata, D, "description", "Fixture only, not a live vulnerability assessment.")
        if kind == "vulnerability":
            advisory = add(metadata, D, "advisory", **{"from": "security@ubuntu.com"})
            add(advisory, D, "severity", "Medium")
            add(advisory, D, "cve", "CVE-2025-1234",
                href="https://ubuntu.com/security/CVE-2025-1234", priority="medium")
        criteria = add(definition, D, "criteria")
        if kind == "vulnerability":
            add(criteria, D, "extend_definition", definition_ref=INVENTORY, applicability_check="true")
        else:
            add(criteria, D, "criterion", test_ref="oval:com.ubuntu.noble:tst:100")
    return root


def results_fixture(results=None):
    if results is None:
        results = [(INVENTORY, "true"), (VULNERABILITY, "false")]
    root = ET.Element(f"{{{R}}}oval_results")
    generator(root, R)
    directives = add(root, R, "directives", include_source_definitions="false")
    for value in oval_report.RESULT_VALUES:
        add(directives, R, "definition_" + value.replace(" ", "_"), reported="true", content="thin")
    systems = add(root, R, "results")
    system = add(systems, R, "system")
    definitions = add(system, R, "definitions")
    for identifier, result in results:
        add(definitions, R, "definition", definition_id=identifier, version="1", result=result)
    characteristics = add(system, S, "oval_system_characteristics")
    generator(characteristics, S)
    info = add(characteristics, S, "system_info")
    for name, value in (("os_name", "Ubuntu"), ("os_version", "24.04"),
                        ("architecture", "aarch64"), ("primary_host_name", "private-host")):
        add(info, S, name, value)
    add(info, S, "interfaces")
    return root


class OvalReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.feed_path = Path(self.directory.name) / "feed.xml"
        self.results_path = Path(self.directory.name) / "results.xml"

    def parse(self, results=None, feed=None):
        self.feed_path.write_bytes(ET.tostring(feed if feed is not None else feed_fixture(), encoding="utf-8"))
        self.results_path.write_bytes(ET.tostring(results if results is not None else results_fixture(), encoding="utf-8"))
        return oval_report.parse_results(self.results_path, self.feed_path)

    def test_real_shaped_false_results_are_complete_without_findings(self):
        report = self.parse()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["limitations"], [])
        self.assertEqual(report["counts"], {
            "true": 1, "false": 1, "unknown": 0, "error": 0,
            "not evaluated": 0, "not applicable": 0,
        })
        self.assertNotIn("private-host", json.dumps(report))

    def test_true_vulnerability_uses_source_metadata_not_title_or_result_metadata(self):
        results = results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")])
        embedded = add(results, D, "oval_definitions")
        definitions = add(embedded, D, "definitions")
        definition = add(definitions, D, "definition", id=VULNERABILITY, version="1")
        add(add(definition, D, "metadata"), D, "title", "Forged result metadata")
        report = self.parse(results)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["id"], VULNERABILITY)
        self.assertEqual(finding["result"], "true")
        self.assertEqual(finding["cves"], ["CVE-2025-1234"])
        self.assertEqual(finding["severity"], "Medium")
        self.assertNotIn("cvss", finding)
        self.assertEqual(finding["title"], "CVE-2099-9999 in title is not evidence")
        self.assertEqual([ref["ref_url"] for ref in finding["references"]], [
            "https://www.cve.org/CVERecord?id=CVE-2025-1234",
            "https://ubuntu.com/security/CVE-2025-1234",
        ])

    def test_mixed_results_expose_each_enum_and_incompleteness(self):
        extra = [(f"oval:com.ubuntu.noble:def:{index}", "vulnerability") for index in range(2, 7)]
        identifiers = [VULNERABILITY, *[identifier for identifier, _ in extra]]
        rows = [(INVENTORY, "true"), *zip(identifiers, oval_report.RESULT_VALUES)]
        report = self.parse(results_fixture(rows), feed_fixture(extra))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["counts"], dict.fromkeys(oval_report.RESULT_VALUES, 1) | {"true": 2})
        self.assertEqual([finding["id"] for finding in report["findings"]], [VULNERABILITY])
        for result in ("unknown", "error", "not evaluated"):
            self.assertTrue(any(result in item for item in report["limitations"]))

    def test_not_applicable_is_neutral(self):
        report = self.parse(results_fixture([(INVENTORY, "true"), (VULNERABILITY, "not applicable")]))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["counts"]["not applicable"], 1)

    def test_same_cve_in_distinct_definitions_retains_both_findings(self):
        other = "oval:com.ubuntu.noble:def:202512340000001"
        report = self.parse(results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true"), (other, "true")]),
                            feed_fixture([(other, "vulnerability")]))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["findings"]), 2)
        self.assertEqual(report["findings"][0]["cves"], report["findings"][1]["cves"])

    def test_missing_results_and_missing_definition_cannot_be_clean(self):
        cases = [results_fixture([]), results_fixture([(INVENTORY, "true")])]
        missing_results = results_fixture()
        missing_results.remove(missing_results.find(f"{{{R}}}results"))
        cases.append(missing_results)
        missing_definitions = results_fixture()
        system = missing_definitions.find(f"{{{R}}}results/{{{R}}}system")
        system.remove(system.find(f"{{{R}}}definitions"))
        cases.append(missing_definitions)
        for results in cases:
            with self.subTest(xml=ET.tostring(results)):
                self.assertEqual(self.parse(results)["status"], "incomplete")

    def test_duplicate_results_and_source_ids_are_incomplete_and_not_findings(self):
        rows = [(INVENTORY, "true"), (VULNERABILITY, "true"), (VULNERABILITY, "false")]
        report = self.parse(results_fixture(rows))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["counts"]["true"], 2)
        report = self.parse(results_fixture(rows[:2]), feed_fixture([(VULNERABILITY, "vulnerability")]))
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["findings"], [])

    def test_unknown_id_result_enum_version_and_class_cannot_be_clean(self):
        cases = [results_fixture([(INVENTORY, "true"), ("oval:other:def:1", "false")]),
                 results_fixture([(INVENTORY, "true"), (VULNERABILITY, "TRUE")])]
        for attribute, value in (("version", "2"), ("class", "inventory")):
            results = results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")])
            results.find(f"{{{R}}}results/{{{R}}}system/{{{R}}}definitions")[1].set(attribute, value)
            cases.append(results)
        for results in cases:
            with self.subTest(xml=ET.tostring(results)):
                report = self.parse(results)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["findings"], [])

    def test_multiple_systems_or_wrong_platform_cannot_be_clean(self):
        results = results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")])
        systems = results.find(f"{{{R}}}results")
        systems.append(ET.fromstring(ET.tostring(systems[0])))
        report = self.parse(results)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["findings"], [])
        report = self.parse(results_fixture([(INVENTORY, "false"), (VULNERABILITY, "false")]))
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(any("host applicability" in item for item in report["limitations"]))

    def test_wrong_nested_namespace_and_misplaced_definition_are_incomplete(self):
        for path in (f"{{{R}}}results", f"{{{R}}}results/{{{R}}}system",
                     f"{{{R}}}results/{{{R}}}system/{{{R}}}definitions/{{{R}}}definition"):
            results = results_fixture()
            element = results.find(path)
            element.tag = "{urn:wrong}" + element.tag.rsplit("}", 1)[-1]
            with self.subTest(path=path):
                self.assertEqual(self.parse(results)["status"], "incomplete")
        results = results_fixture([])
        add(results, R, "definition", definition_id=VULNERABILITY, version="1", result="false")
        self.assertEqual(self.parse(results)["status"], "incomplete")

    def test_wrong_root_namespace_or_document_type_raises_value_error(self):
        for root in (ET.Element("oval_results"), ET.Element("{urn:wrong}oval_results"),
                     ET.Element(f"{{{R}}}oval_definitions")):
            with self.subTest(root=root.tag), self.assertRaises(ValueError):
                self.parse(root)
        with self.assertRaises(ValueError):
            self.parse(feed=ET.Element(f"{{{R}}}oval_definitions"))

    def test_missing_cve_and_severity_are_not_guessed_from_title(self):
        feed = feed_fixture()
        metadata = feed.find(f"{{{D}}}definitions")[1].find(f"{{{D}}}metadata")
        metadata.remove(metadata.find(f"{{{D}}}reference"))
        metadata.remove(metadata.find(f"{{{D}}}advisory"))
        finding = self.parse(results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")]), feed)["findings"][0]
        self.assertEqual(finding["cves"], [])
        self.assertIsNone(finding["severity"])
        self.assertEqual(finding["references"], [])

    def test_canonical_metadata_links_are_preserved_as_data(self):
        feed = feed_fixture()
        advisory = feed.find(f"{{{D}}}definitions")[1].find(f"{{{D}}}metadata/{{{D}}}advisory")
        add(advisory, D, "ref", "https://ubuntu.com/security/notices/USN-1234-1?x=1&y=2")
        add(advisory, D, "bug", "https://bugs.launchpad.net/bugs/1234")
        finding = self.parse(results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")]), feed)["findings"][0]
        self.assertEqual(finding["references"][-2:], [
            {"source": "ref", "ref_id": "", "ref_url": "https://ubuntu.com/security/notices/USN-1234-1?x=1&y=2"},
            {"source": "bug", "ref_id": "", "ref_url": "https://bugs.launchpad.net/bugs/1234"},
        ])

    def test_unsafe_xml_is_rejected_in_both_inputs_without_raw_xml_in_error(self):
        unsafe = [
            f'<!DOCTYPE oval_results [<!ENTITY secret SYSTEM "file:///private-secret">]><oval_results xmlns="{R}">&secret;</oval_results>'.encode(),
            f'<!DOCTYPE oval_results SYSTEM "https://invalid.example/private-secret"><oval_results xmlns="{R}"/>'.encode(),
            f'<!DOCTYPE oval_results [<!ENTITY secret "private-secret">]><oval_results xmlns="{R}">&secret;</oval_results>'.encode(),
            '<!DOCTYPE oval_results [<!ENTITY secret "private-secret">]><oval_results/>'.encode("utf-16"),
            b'<?xml version="1.0" encoding="iso-8859-1"?><oval_results/>',
            b'<oval_results>private-secret',
            b'\xffprivate-secret',
        ]
        for data in unsafe:
            for target in (self.feed_path, self.results_path):
                self.parse()
                target.write_bytes(data)
                with self.subTest(target=target.name, data=data), self.assertRaises(ValueError) as error:
                    oval_report.parse_results(self.results_path, self.feed_path)
                self.assertNotIn("private-secret", str(error.exception))

    def test_oversized_and_unreadable_files_raise_value_error(self):
        self.parse()
        with patch.object(oval_report, "MAX_XML_BYTES", 16), self.assertRaises(ValueError):
            oval_report.parse_results(self.results_path, self.feed_path)
        self.results_path.unlink()
        with self.assertRaises(ValueError):
            oval_report.parse_results(self.results_path, self.feed_path)


if __name__ == "__main__":
    unittest.main()
