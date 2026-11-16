import io
import json
from pathlib import Path
import tempfile
import unittest
import tracemalloc
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


def vendor_fixture(platform, *, classes=("vulnerability",), platform_test=True, affected=True):
    """Reduced shapes from Debian, RHEL/Alma/Oracle and SUSE official OVAL feeds."""
    root = ET.Element(f"{{{D}}}oval_definitions")
    definitions = add(root, D, "definitions")
    rows = []
    for number, kind in enumerate(classes, 1):
        identifier = f"oval:vendor:def:{number}"
        definition = add(definitions, D, "definition", id=identifier, version="7", **{"class": kind})
        metadata = add(definition, D, "metadata")
        add(metadata, D, "title", "Vendor advisory")
        if affected:
            add(add(metadata, D, "affected", family="unix"), D, "platform", platform)
        add(metadata, D, "reference", source="CVE", ref_id="Mitre CVE-2025-1234",
            ref_url="https://example.invalid/CVE-2025-1234")
        advisory = add(metadata, D, "advisory")
        add(advisory, D, "severity", "Moderate")
        add(advisory, D, "cve", "CVE-2025-1234 at SUSE", href="https://example.invalid/cve")
        add(advisory, D, "bugzilla", "Vendor bug", id="1234", href="https://example.invalid/bug")
        if platform_test:
            criteria = add(definition, D, "criteria", operator="AND")
            add(criteria, D, "criterion", test_ref="oval:vendor:tst:1",
                comment=platform + " is installed")
        rows.append((identifier, "false"))
    if platform_test:
        add(add(root, D, "tests"), D + "#linux", "rpmverifyfile_test",
            id="oval:vendor:tst:1", version="3", comment=platform + " is installed", check="at least one")
    results = results_fixture(rows)
    system = results.find(f"{{{R}}}results/{{{R}}}system")
    for definition in system.find(f"{{{R}}}definitions"):
        definition.set("version", "7")
    info = system.find(f"{{{S}}}oval_system_characteristics/{{{S}}}system_info")
    info.find(f"{{{S}}}os_name").text = platform
    info.find(f"{{{S}}}os_version").text = "1"
    if platform_test:
        add(add(system, R, "tests"), R, "test", test_id="oval:vendor:tst:1", version="3", result="true")
    return root, results


class OvalReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.feed_path = Path(self.directory.name) / "feed.xml"
        self.results_path = Path(self.directory.name) / "results.xml"

    def parse(self, results=None, feed=None, **kwargs):
        self.feed_path.write_bytes(ET.tostring(feed if feed is not None else feed_fixture(), encoding="utf-8"))
        self.results_path.write_bytes(ET.tostring(results if results is not None else results_fixture(), encoding="utf-8"))
        return oval_report.parse_results(self.results_path, self.feed_path, **kwargs)

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
        self.assertEqual(finding["class"], "vulnerability")

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

    def test_debian_mixed_vulnerabilities_and_missing_patches(self):
        feed, results = vendor_fixture("Debian GNU/Linux 13", classes=("vulnerability", "patch"))
        test = feed.find(f"{{{D}}}tests")[0]
        test.tag = f"{{{D}#independent}}textfilecontent54_test"
        definitions = results.find(f"{{{R}}}results/{{{R}}}system/{{{R}}}definitions")
        for definition in definitions:
            definition.set("result", "true")
        report = self.parse(results, feed, finding_classes=("vulnerability", "patch"))
        self.assertEqual(report["status"], "complete")
        self.assertEqual([finding["class"] for finding in report["findings"]], ["vulnerability", "patch"])
        self.assertEqual(report["findings"][0]["cves"], ["CVE-2025-1234"])
        self.assertEqual(self.parse(results, feed)["status"], "incomplete")

    def test_vendor_missing_patch_streams_require_explicit_patch_class(self):
        for platform in ("Red Hat Enterprise Linux 9", "AlmaLinux 9", "Oracle Linux 9"):
            with self.subTest(platform=platform):
                feed, results = vendor_fixture(platform, classes=("patch",), affected=not platform.startswith("Alma"))
                row = results.find(f"{{{R}}}results/{{{R}}}system/{{{R}}}definitions")[0]
                row.set("result", "true")
                report = self.parse(results, feed, finding_classes=("patch",), host_platform=platform)
                self.assertEqual(report["status"], "complete")
                self.assertEqual(report["findings"][0]["class"], "patch")
                self.assertEqual(report["findings"][0]["severity"], "Moderate")
                self.assertEqual(self.parse(results, feed, host_platform=platform)["status"], "incomplete")

    def test_missing_or_mismatched_platform_test_cannot_be_clean(self):
        for value in ("false", "unknown", "error", "not evaluated", "not applicable", "missing", "version", "duplicate"):
            feed, results = vendor_fixture("Debian GNU/Linux 13")
            tests = results.find(f"{{{R}}}results/{{{R}}}system/{{{R}}}tests")
            if value == "missing":
                tests.remove(tests[0])
            elif value == "duplicate":
                tests.append(ET.fromstring(ET.tostring(tests[0])))
            elif value == "version":
                tests[0].set("version", "2")
            else:
                tests[0].set("result", value)
            with self.subTest(value=value):
                report = self.parse(results, feed, host_platform="Debian GNU/Linux 13")
                self.assertEqual(report["status"], "incomplete")
                self.assertTrue(any("host applicability" in item for item in report["limitations"]))

    def test_platform_tests_are_bound_to_source_references_and_namespace(self):
        for corruption in ("duplicate", "namespace", "unreferenced"):
            feed, results = vendor_fixture("AlmaLinux 9", classes=("patch",), affected=False)
            tests = feed.find(f"{{{D}}}tests")
            if corruption == "duplicate":
                tests.append(ET.fromstring(ET.tostring(tests[0])))
            elif corruption == "namespace":
                tests[0].tag = "{urn:wrong}rpmverifyfile_test"
            else:
                tests[0].set("id", "oval:vendor:tst:999")
            with self.subTest(corruption=corruption):
                self.assertEqual(self.parse(results, feed, finding_classes=("patch",),
                                            host_platform="AlmaLinux 9")["status"], "incomplete")

    def test_suse_platform_metadata_and_cve_labels(self):
        feed, results = vendor_fixture("openSUSE Leap 16.0", platform_test=False)
        row = results.find(f"{{{R}}}results/{{{R}}}system/{{{R}}}definitions")[0]
        row.set("result", "true")
        report = self.parse(results, feed)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"][0]["cves"], ["CVE-2025-1234"])
        self.assertEqual(report["findings"][0]["references"][-1],
                         {"source": "bugzilla", "ref_id": "1234", "ref_url": "https://example.invalid/bug"})
        info = results.find(f"{{{R}}}results/{{{R}}}system/{{{S}}}oval_system_characteristics/{{{S}}}system_info")
        info.find(f"{{{S}}}os_name").text = "Linux"
        self.assertEqual(self.parse(results, feed)["status"], "incomplete")
        self.assertEqual(self.parse(results, feed, host_platform="openSUSE Leap 16.0")["status"], "complete")
        self.assertEqual(self.parse(results, feed, host_platform="openSUSE Leap 16.1")["status"], "incomplete")

    def test_mismatched_results_host_is_not_replaced_by_scanner_assertion(self):
        feed, results = vendor_fixture("Debian GNU/Linux 13", platform_test=False)
        info = results.find(f"{{{R}}}results/{{{R}}}system/{{{S}}}oval_system_characteristics/{{{S}}}system_info")
        for name in ("Ubuntu 24.04", "Debian GNU/Linux 12", "Debian GNU/Linux 130"):
            info.find(f"{{{S}}}os_name").text = name
            with self.subTest(name=name):
                self.assertEqual(self.parse(results, feed, host_platform="Debian GNU/Linux 13")["status"], "incomplete")

    def test_multiple_inventory_definitions_need_matching_true_evidence_not_all_true(self):
        other = "oval:vendor:def:999"
        feed = feed_fixture([(other, "inventory")])
        rows = [(INVENTORY, "true"), (VULNERABILITY, "false"), (other, "false")]
        self.assertEqual(self.parse(results_fixture(rows), feed)["status"], "complete")
        rows = [(INVENTORY, "false"), (VULNERABILITY, "false"), (other, "true")]
        self.assertEqual(self.parse(results_fixture(rows), feed)["status"], "incomplete")
        self.assertEqual(self.parse(results_fixture(rows[:-1]), feed)["status"], "incomplete")

    def test_unknown_or_unselected_classes_fail_closed(self):
        for kind in ("compliance", "miscellaneous", "patch", "made-up"):
            feed = feed_fixture()
            feed.find(f"{{{D}}}definitions")[1].set("class", kind)
            with self.subTest(kind=kind):
                report = self.parse(feed=feed)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["findings"], [])
        for kinds in ((), ("inventory",), ("made-up",), ["patch"], "vulnerability"):
            with self.subTest(kinds=kinds), self.assertRaisesRegex(ValueError, "finding classes"):
                self.parse(finding_classes=kinds)

    def test_linux_advisory_extension_namespace_preserves_evidence(self):
        feed, results = vendor_fixture("Red Hat Enterprise Linux 9", classes=("patch",))
        advisory = feed.find(f"{{{D}}}definitions/{{{D}}}definition/{{{D}}}metadata/{{{D}}}advisory")
        for element in advisory.iter():
            element.tag = f"{{{D}#linux}}" + element.tag.rsplit("}", 1)[-1]
        results.find(f"{{{R}}}results/{{{R}}}system/{{{R}}}definitions")[0].set("result", "true")
        report = self.parse(results, feed, finding_classes=("patch",))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"][0]["severity"], "Moderate")
        self.assertEqual(report["findings"][0]["cves"], ["CVE-2025-1234"])

    def test_source_platform_criterion_binds_test_without_test_comment(self):
        feed, results = vendor_fixture("SUSE Linux Enterprise Server 15 SP7")
        test = feed.find(f"{{{D}}}tests")[0]
        test.set("comment", "sles-release package version is 15.7")
        report = self.parse(results, feed, host_platform="SUSE Linux Enterprise Server 15 SP7")
        self.assertEqual(report["status"], "complete")
        row = results.find(f"{{{R}}}results/{{{R}}}system/{{{R}}}tests")[0]
        row.set("result", "false")
        self.assertEqual(self.parse(results, feed, host_platform="SUSE Linux Enterprise Server 15 SP7")["status"], "incomplete")
        feed.find(f"{{{D}}}tests").remove(test)
        self.assertEqual(self.parse(results, feed, host_platform="SUSE Linux Enterprise Server 15 SP7")["status"], "incomplete")

    def test_unreferenced_inventories_need_matching_platform_metadata(self):
        other = "oval:vendor:def:999"
        feed = feed_fixture([(other, "inventory")])
        definitions = feed.find(f"{{{D}}}definitions")
        definitions[1].remove(definitions[1].find(f"{{{D}}}criteria"))
        rows = [(INVENTORY, "true"), (VULNERABILITY, "false"), (other, "false")]
        self.assertEqual(self.parse(results_fixture(rows), feed)["status"], "incomplete")
        metadata = definitions[0].find(f"{{{D}}}metadata")
        platform = add(add(metadata, D, "affected", family="unix"), D, "platform", "Ubuntu 24.04 LTS")
        self.assertEqual(self.parse(results_fixture(rows), feed)["status"], "complete")
        platform.text = "Debian GNU/Linux 13"
        self.assertEqual(self.parse(results_fixture(rows), feed)["status"], "incomplete")

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

    def test_large_irrelevant_trees_are_streamed_and_removed(self):
        feed = feed_fixture()
        metadata = feed.find(f"{{{D}}}definitions")[1].find(f"{{{D}}}metadata")
        metadata.find(f"{{{D}}}description").text = "STREAM_PLACEHOLDER"
        results = results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")])
        embedded = add(results, D, "oval_definitions")
        add(embedded, D, "definitions").text = "STREAM_PLACEHOLDER"
        leaf = b"<discard>" + b"x" * 2048 + b"</discard>"
        for path, root in ((self.feed_path, feed), (self.results_path, results)):
            before, after = ET.tostring(root, encoding="utf-8").split(b"STREAM_PLACEHOLDER")
            with path.open("wb") as stream:
                stream.write(before)
                for _ in range(8192):
                    stream.write(leaf)
                stream.write(after)

        real_open = Path.open
        reads = []

        class BoundedStream:
            def __init__(self, path, *args, **kwargs):
                self.stream = real_open(path, *args, **kwargs)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def read(self, size=-1):
                if not 0 < size <= 64 * 1024:
                    raise AssertionError("XML must use bounded reads")
                reads.append(size)
                return self.stream.read(size)

        tracemalloc.start()
        try:
            with patch.object(Path, "open", lambda path, mode: BoundedStream(path, mode)), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("Whole-file copy")), \
                    patch.object(ET, "fromstring", side_effect=AssertionError("Whole-tree parse")), \
                    patch.object(ET, "iterparse", wraps=ET.iterparse) as parser:
                report = oval_report.parse_results(self.results_path, self.feed_path)
                self.assertEqual(parser.call_count, 2)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertGreater(len(reads), 100)
        self.assertLess(peak, 3 * 1024 * 1024)
        self.assertEqual(report["status"], "complete")
        self.assertEqual([finding["id"] for finding in report["findings"]], [VULNERABILITY])
        self.assertEqual(report["findings"][0]["cves"], ["CVE-2025-1234"])

    def test_reader_validates_split_utf8_and_declaration_tokens(self):
        safe = '<?xml version="1.0" encoding="UTF-8"?><root>é茶<!-- <!DOCTYPEX --></root>'
        encoded = b"\xef\xbb\xbf" + safe.encode()
        reader = oval_report._XMLReader(io.BytesIO(encoded))
        self.assertEqual("".join(iter(lambda: reader.read(1), "")), safe)
        unsafe = [
            b'<?xml version="1.0" encoding="iso-8859-1"?><root/>',
            b"<root><!-- <!" + b" " * 100000 + b"DOCTYPE root --></root>",
            b"<root><!-- <!ENTITY x --></root>",
            b"<root>\x00</root>",
            b"<root>\xc3",
        ]
        for data in unsafe:
            with self.subTest(data=data[:60]), self.assertRaises(ValueError):
                reader = oval_report._XMLReader(io.BytesIO(data))
                while reader.read(7):
                    pass

    def test_streaming_byte_and_depth_limits_apply_to_both_inputs(self):
        for target in (self.feed_path, self.results_path):
            self.parse()
            size = max(self.feed_path.stat().st_size, self.results_path.stat().st_size)
            with target.open("ab") as stream:
                stream.write(b" " * size)
            with patch.object(oval_report, "MAX_XML_BYTES", size), self.assertRaisesRegex(ValueError, "size limit"):
                oval_report.parse_results(self.results_path, self.feed_path)
            self.parse()
            namespace, name = (D, "oval_definitions") if target == self.feed_path else (R, "oval_results")
            target.write_text(f'<{name} xmlns="{namespace}">' + "<ignored>" * 256
                              + "</ignored>" * 256 + f"</{name}>", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "depth limit"):
                oval_report.parse_results(self.results_path, self.feed_path)

    def test_duplicate_ids_survive_pruning_and_multiple_sections(self):
        feed = feed_fixture()
        second = add(feed, D, "definitions")
        duplicate = ET.fromstring(ET.tostring(feed.find(f"{{{D}}}definitions")[1]))
        second.append(duplicate)
        results = results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")])
        report = self.parse(results, feed)
        self.assertIn("The feed contains duplicate definition IDs.", report["limitations"])
        self.assertEqual(report["findings"], [])
        results = results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")])
        system = results.find(f"{{{R}}}results/{{{R}}}system")
        second = add(system, R, "definitions")
        add(second, R, "definition", definition_id=VULNERABILITY, version="1", result="false")
        report = self.parse(results)
        self.assertIn("OVAL evidence contains duplicate definition results.", report["limitations"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["counts"]["true"], 2)
        self.assertEqual(report["counts"]["false"], 1)

    def test_malformed_duplicate_source_identity_never_produces_a_finding(self):
        for malformed_first in (False, True):
            feed = feed_fixture([(VULNERABILITY, "vulnerability")])
            definitions = feed.find(f"{{{D}}}definitions")
            del definitions[1 if malformed_first else 2].attrib["version"]
            with self.subTest(malformed_first=malformed_first):
                report = self.parse(results_fixture([(INVENTORY, "true"), (VULNERABILITY, "true")]), feed)
                self.assertEqual(report["status"], "incomplete")
                self.assertIn("The feed contains duplicate definition IDs.", report["limitations"])
                self.assertEqual(report["findings"], [])

    def test_pruned_metadata_preserves_namespace_checks(self):
        for path in ("metadata", "metadata/title", "metadata/reference", "metadata/advisory",
                     "metadata/advisory/severity", "metadata/advisory/cve"):
            feed = feed_fixture()
            definition = feed.find(f"{{{D}}}definitions")[1]
            element = definition.find("/".join(f"{{{D}}}{part}" for part in path.split("/")))
            element.tag = "{urn:wrong}" + element.tag.rsplit("}", 1)[-1]
            with self.subTest(path=path):
                report = self.parse(feed=feed)
                self.assertEqual(report["status"], "incomplete")
                self.assertIn("An OVAL evidence element has the wrong namespace.", report["limitations"])

    def test_streaming_rejects_invalid_trailers_after_complete_evidence(self):
        for target in (self.feed_path, self.results_path):
            for trailer in (b"<", b"\xff", b"<!-- <!DOCTYPE hidden -->"):
                self.parse()
                with target.open("ab") as stream:
                    stream.write(trailer)
                with self.subTest(target=target.name, trailer=trailer), self.assertRaises(ValueError):
                    oval_report.parse_results(self.results_path, self.feed_path)


if __name__ == "__main__":
    unittest.main()
