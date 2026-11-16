"""Exact os-release identities and official OVAL streams; never use ID_LIKE."""

import re


# Publisher indexes verified 2026-11-16; feed timestamps are checked on every scan.
SOURCES = {
    "ubuntu": "https://security-metadata.canonical.com/oval/",
    "debian": "https://www.debian.org/security/oval/",
    "rhel": "https://security.access.redhat.com/data/oval/v2/",
    "almalinux": "https://security.almalinux.org/oval/",
    "ol": "https://linux.oracle.com/security/oval/",
    "rocky": "https://dl.rockylinux.org/pub/oval/",
    "suse": "https://ftp.suse.com/pub/projects/security/oval/",
    "amzn": "https://alas.aws.amazon.com/",
    "fedora": "https://fedoraproject.org/wiki/Bodhi",
}
_NAMES = {
    "ubuntu": ("Ubuntu", "debian"), "debian": ("Debian", "debian"),
    "rhel": ("Red Hat Enterprise Linux", "rhel"), "almalinux": ("AlmaLinux", "rhel"),
    "ol": ("Oracle Linux", "rhel"), "rocky": ("Rocky Linux", "rhel"),
    "amzn": ("Amazon Linux", "rhel"), "fedora": ("Fedora", "rhel"),
    "sles": ("SUSE Linux Enterprise Server", "suse"),
    "opensuse-leap": ("openSUSE Leap", "suse"),
    "opensuse-tumbleweed": ("openSUSE Tumbleweed", "suse"),
}


def select_profile(release):
    """Return a fresh JSON-ready profile, including an explicit unavailable reason."""
    distro = release.get("ID", "")
    version = release.get("VERSION_ID", "")
    if not isinstance(distro, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", distro):
        distro = "unknown"
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]{1,8}(?:\.[0-9]{1,2})?", version):
        version = "unknown"
    profile = {
        "id": distro, "version": version, "label": "Unsupported platform", "family": None,
        "feed_url": None, "feed_kind": None, "finding_classes": [], "oscap_package": None,
        "scan_unavailable": "Unsupported distro or release; no vendor OVAL profile is configured. ID_LIKE is not used.",
        "platform": None, "feed_version": None, "source_url": None,
    }
    if distro not in _NAMES or version == "unknown":
        return profile
    name, family = _NAMES[distro]
    major = version.split(".")[0]
    filename = None
    classes = ["vulnerability"]
    feed_version = version
    platform_name = f"{name} {version}"
    source = SOURCES.get(distro, SOURCES["suse"])
    package = "openscap-utils" if family == "suse" else "openscap-scanner"
    reason = None
    if distro == "ubuntu":
        codename = {"20.04": "focal", "22.04": "jammy", "24.04": "noble", "26.04": "resolute"}.get(version)
        if not codename:
            return profile
        filename = f"com.ubuntu.{codename}.cve.oval.xml.bz2"
        platform_name += " LTS"
        if version in ("20.04", "22.04"):
            package = "libopenscap8"
    elif distro == "debian":
        codename = {"11": "bullseye", "12": "bookworm", "13": "trixie"}.get(major)
        if not codename:
            return profile
        feed_version = major
        platform_name = f"Debian GNU/Linux {major}"
        filename = f"oval-definitions-{codename}.xml.bz2"
        classes = ["vulnerability", "patch"]
        if major == "11":
            package = None
    elif distro in ("rhel", "almalinux", "ol", "rocky"):
        if major not in ("8", "9", "10"):
            return profile
        feed_version = major
        platform_name = f"{name} {major}"
        classes = ["patch"]
        if distro == "rhel":
            if major == "10":
                reason = "Red Hat does not publish OVAL for RHEL 10; CSAF/VEX is not supported by this OVAL scanner."
            else:
                filename = f"RHEL{major}/rhel-{major}.oval.xml.bz2"
        elif distro == "almalinux":
            filename = f"org.almalinux.alsa-{major}.xml.bz2"
        elif distro == "ol":
            filename = f"com.oracle.elsa-ol{major}.xml.bz2"
        elif major == "10":
            reason = "No official Rocky Linux 10 OVAL stream was verified; RHEL feeds are not a substitute."
        else:
            filename = f"org.rockylinux.rlsa-{major}.xml.bz2"
    elif distro == "opensuse-leap":
        if version not in ("16.0", "16.1"):
            return profile
        filename = f"opensuse.leap.{version}-affected.xml.bz2"
    elif distro == "opensuse-tumbleweed":
        if not re.fullmatch(r"20[0-9]{6}", version):
            return profile
        feed_version = "rolling"
        platform_name = name
        filename = "opensuse.tumbleweed-affected.xml.bz2"
    elif distro == "sles":
        if version == "12.5" or version in ("15.4", "15.5", "15.6", "15.7"):
            service_pack = version.split(".")[1]
            filename = f"suse.linux.enterprise.{major}-sp{service_pack}-affected.xml.bz2"
            platform_name = f"{name} {major} SP{service_pack}"
        elif version in ("16.0", "16.1"):
            filename = f"suse.linux.enterprise.{version}-affected.xml.bz2"
        else:
            return profile
    elif distro == "amzn":
        if version not in ("2", "2023"):
            return profile
        reason = "No official Amazon Linux OVAL stream was verified; ALAS advisories/RSS are not OVAL and RHEL feeds are not a substitute."
    elif distro == "fedora":
        if version not in ("43", "44", "45"):
            return profile
        reason = "No official Fedora OVAL stream was verified; Bodhi update metadata is not OVAL and RHEL feeds are not a substitute."
    profile.update({
        "label": f"{name} {version}", "family": family, "feed_url": source + filename if filename else None,
        "feed_kind": "OVAL " + "/".join(classes) if filename else None,
        "finding_classes": classes if filename else [], "oscap_package": package,
        "scan_unavailable": reason, "platform": platform_name, "feed_version": feed_version,
        "source_url": source,
    })
    return profile
