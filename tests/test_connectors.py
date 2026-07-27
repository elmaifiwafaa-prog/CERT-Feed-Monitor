from cert_watcher.connectors import CertFrRssConnector, CisaKevConnector, NvdConnector


def test_cisa_kev_normalizes_exploited_vulnerability(monkeypatch):
    monkeypatch.setattr("cert_watcher.connectors.fetch_json", lambda _: {"vulnerabilities": [{"cveID": "CVE-2026-1234", "vulnerabilityName": "VPN issue", "vendorProject": "Example", "product": "VPN", "shortDescription": "Issue", "requiredAction": "Patch"}]})
    item = CisaKevConnector().collect()[0]
    assert item.cve_id == "CVE-2026-1234"
    assert item.actively_exploited is True
    assert item.affected_versions == []


def test_cert_fr_rss_extracts_cves(monkeypatch):
    feed = "<rss><channel><item><title>Alerte CVE-2026-1234</title><description>Test</description><link>https://example.invalid/a</link></item></channel></rss>"
    monkeypatch.setattr("cert_watcher.connectors.fetch_text", lambda _: feed)
    item = CertFrRssConnector().collect()[0]
    assert item.cve_id == "CVE-2026-1234"


def test_nvd_requests_only_the_recent_publication_window():
    url = NvdConnector(7)._url()
    assert "pubStartDate=" in url
    assert "pubEndDate=" in url
