import unittest

from profiles import SOURCES, select_profile


class ProfileTests(unittest.TestCase):
    def test_verified_vendor_stream_matrix(self):
        # Exact filenames from the official indexes listed in SOURCES, read 2026-11-16.
        cases = [
            ("ubuntu", "20.04", "com.ubuntu.focal.cve.oval.xml.bz2", ["vulnerability"]),
            ("ubuntu", "22.04", "com.ubuntu.jammy.cve.oval.xml.bz2", ["vulnerability"]),
            ("ubuntu", "24.04", "com.ubuntu.noble.cve.oval.xml.bz2", ["vulnerability"]),
            ("ubuntu", "26.04", "com.ubuntu.resolute.cve.oval.xml.bz2", ["vulnerability"]),
            ("debian", "11", "oval-definitions-bullseye.xml.bz2", ["vulnerability", "patch"]),
            ("debian", "12", "oval-definitions-bookworm.xml.bz2", ["vulnerability", "patch"]),
            ("debian", "13", "oval-definitions-trixie.xml.bz2", ["vulnerability", "patch"]),
        ]
        for major in ("8", "9", "10"):
            cases.extend([
                ("almalinux", major, f"org.almalinux.alsa-{major}.xml.bz2", ["patch"]),
                ("ol", major, f"com.oracle.elsa-ol{major}.xml.bz2", ["patch"]),
            ])
        for major in ("8", "9"):
            cases.extend([
                ("rhel", major, f"RHEL{major}/rhel-{major}.oval.xml.bz2", ["patch"]),
                ("rocky", major, f"org.rockylinux.rlsa-{major}.xml.bz2", ["patch"]),
            ])
        for version in ("16.0", "16.1"):
            cases.extend([
                ("opensuse-leap", version, f"opensuse.leap.{version}-affected.xml.bz2", ["vulnerability"]),
                ("sles", version, f"suse.linux.enterprise.{version}-affected.xml.bz2", ["vulnerability"]),
            ])
        for version in ("12.5", "15.4", "15.5", "15.6", "15.7"):
            major, service_pack = version.split(".")
            cases.append(("sles", version, f"suse.linux.enterprise.{major}-sp{service_pack}-affected.xml.bz2", ["vulnerability"]))
        cases.append(("opensuse-tumbleweed", "20261115", "opensuse.tumbleweed-affected.xml.bz2", ["vulnerability"]))
        for distro, version, filename, classes in cases:
            with self.subTest(distro=distro, version=version):
                profile = select_profile({"ID": distro, "VERSION_ID": version})
                self.assertEqual(profile["feed_url"], SOURCES.get(distro, SOURCES["suse"]) + filename)
                self.assertEqual(profile["finding_classes"], classes)
                self.assertIsNone(profile["scan_unavailable"])
                self.assertIn(profile["family"], ("debian", "rhel", "suse"))
                self.assertTrue(profile["platform"])

    def test_minor_versions_select_only_the_same_vendors_major_stream(self):
        for distro, version in (("debian", "13.7"), ("rhel", "9.6"), ("almalinux", "10.1"),
                                ("ol", "8.10"), ("rocky", "9.6")):
            with self.subTest(distro=distro):
                profile = select_profile({"ID": distro, "VERSION_ID": version})
                major = select_profile({"ID": distro, "VERSION_ID": version.split(".")[0]})
                self.assertEqual(profile["feed_url"], major["feed_url"])
                self.assertEqual(profile["version"], version)
                self.assertEqual(profile["feed_version"], version.split(".")[0])

    def test_unknown_eol_and_injection_never_guess_from_id_like(self):
        for distro, version in (("centos", "9"), ("linuxmint", "22"), ("Ubuntu", "24.04"),
                                ("ubuntu", "18.04"), ("ubuntu", "24.04.1"), ("debian", "10"),
                                ("rhel", "7.9"), ("opensuse-leap", "15.6"), ("sles", "15.3"),
                                ("fedora", "42"), ("ubuntu;curl attacker", "24.04"),
                                ("ubuntu", "24.04/../../noble"), ("ubuntu", "24.04\n"),
                                ("", "24.04"), (None, None), ([], {})):
            with self.subTest(distro=distro, version=version):
                profile = select_profile({"ID": distro, "VERSION_ID": version, "ID_LIKE": "ubuntu rhel"})
                self.assertIsNone(profile["feed_url"])
                self.assertIsNone(profile["family"])
                self.assertTrue(profile["scan_unavailable"])
                self.assertNotIn("attacker", str(profile))

    def test_unavailable_vendors_have_auditing_identity_not_fake_feed(self):
        # RHEL10 exclusion: https://access.redhat.com/security/oval-v2-deprecation-announcement
        # Rocky10 absent from https://dl.rockylinux.org/pub/oval/; AWS ALAS and Fedora Bodhi
        # publish advisory metadata, not a verified OVAL stream.
        for distro, versions in (("rhel", ("10", "10.1")), ("rocky", ("10",)),
                                 ("amzn", ("2", "2023")), ("fedora", ("43", "44", "45"))):
            for version in versions:
                with self.subTest(distro=distro, version=version):
                    profile = select_profile({"ID": distro, "VERSION_ID": version})
                    self.assertEqual(profile["family"], "rhel")
                    self.assertIsNone(profile["feed_url"])
                    self.assertTrue(profile["scan_unavailable"])
                    self.assertEqual(profile["finding_classes"], [])

    def test_prerequisite_packages_follow_native_distribution(self):
        for distro, version, package in (("ubuntu", "20.04", "libopenscap8"),
                                        ("ubuntu", "22.04", "libopenscap8"),
                                        ("debian", "11", None),
                                        ("ubuntu", "24.04", "openscap-scanner"),
                                        ("debian", "13", "openscap-scanner"),
                                        ("almalinux", "9", "openscap-scanner"),
                                        ("sles", "16.0", "openscap-utils"),
                                        ("opensuse-leap", "16.0", "openscap-utils")):
            with self.subTest(distro=distro):
                self.assertEqual(select_profile({"ID": distro, "VERSION_ID": version})["oscap_package"], package)

    def test_profiles_do_not_share_mutable_finding_classes(self):
        release = {"ID": "debian", "VERSION_ID": "13"}
        select_profile(release)["finding_classes"].clear()
        self.assertEqual(select_profile(release)["finding_classes"], ["vulnerability", "patch"])


if __name__ == "__main__":
    unittest.main()
