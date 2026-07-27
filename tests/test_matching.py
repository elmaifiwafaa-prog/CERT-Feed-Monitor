from cert_watcher.matching import match
from cert_watcher.models import Asset, Contact, Software, Vulnerability


def test_matching_requires_vendor_product_and_affected_version():
    asset = Asset("a1", "Web", "Web", Contact("A", "a@example.invalid"), (Software("Apache", "HTTP Server", "2.4.58"),))
    vulnerability = Vulnerability("CVE-2026-1000", "Test", "Test", "Apache", "HTTP Server", ["2.4.58"])
    assert len(match(vulnerability, [asset])) == 1


def test_no_match_for_different_product():
    asset = Asset("a1", "Web", "Web", Contact("A", "a@example.invalid"), (Software("Apache", "Tomcat", "2.4.58"),))
    vulnerability = Vulnerability("CVE-2026-1000", "Test", "Test", "Apache", "HTTP Server")
    assert match(vulnerability, [asset]) == []
