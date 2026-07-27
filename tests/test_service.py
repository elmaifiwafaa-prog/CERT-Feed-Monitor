from pathlib import Path
from datetime import datetime, timedelta, timezone

from cert_watcher.models import Asset, Contact, Software, Vulnerability
from cert_watcher.repository import Repository
from cert_watcher.service import merge, run_cycle


class FakeConnector:
    def collect(self):
        return [Vulnerability("CVE-2026-1000", "Test", "Description", "Vendor", "Product", ["1.0"], actively_exploited=True)]


class FakeNotifier:
    def send(self, vulnerability, contacts, alert_path):
        return [(contact.email, "simulated") for contact in contacts]


def test_merge_combines_kev_flag_and_sources():
    entries = merge([Vulnerability("CVE-2026-1", "T", "D", sources=["a"]), Vulnerability("CVE-2026-1", "T", "D", actively_exploited=True, sources=["b"])])
    assert entries[0].actively_exploited is True
    assert entries[0].sources == ["a", "b"]


def test_cycle_generates_only_once(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    asset = Asset("a", "A", "Team", Contact("A", "a@example.invalid"), (Software("Vendor", "Product", "1.0"),))
    repository = Repository(tmp_path / "db.sqlite")
    assert run_cycle([FakeConnector()], [asset], repository, FakeNotifier()) == 1
    assert Path("data/alerts/CVE-2026-1000.md").exists()
    assert run_cycle([FakeConnector()], [asset], repository, FakeNotifier()) == 0


def test_cycle_backfills_ticket_for_previously_processed_alert(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    asset = Asset("a", "A", "Team", Contact("A", "a@example.invalid"), (Software("Vendor", "Product", "1.0"),))
    repository = Repository(tmp_path / "db.sqlite")
    repository.mark_processed("CVE-2026-1000")
    assert run_cycle([FakeConnector()], [asset], repository, FakeNotifier()) == 0
    assert repository.has_ticket("CVE-2026-1000")


def test_cycle_ignores_old_vulnerability_and_records_cti_provenance(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    asset = Asset("a", "A", "Team", Contact("A", "a@example.invalid"), (Software("Vendor", "Product", "1.0"),))
    old = Vulnerability("CVE-2020-1000", "Old", "Description", "Vendor", "Product", ["1.0"], published_at=datetime.now(timezone.utc) - timedelta(days=31), sources=["https://services.nvd.nist.gov/rest/json/cves/2.0/"])
    class OldConnector:
        def collect(self): return [old]
    repository = Repository(tmp_path / "db.sqlite")
    assert run_cycle([OldConnector()], [asset], repository, FakeNotifier()) == 0
    assert repository.connection.execute("SELECT count(*) FROM vulnerabilities").fetchone()[0] == 0
    fresh = Vulnerability("CVE-2026-1001", "Fresh", "Description", "Vendor", "Product", ["1.0"], published_at=datetime.now(timezone.utc), sources=["https://services.nvd.nist.gov/rest/json/cves/2.0/"])
    class FreshConnector:
        def collect(self): return [fresh]
    assert run_cycle([FreshConnector()], [asset], repository, FakeNotifier()) == 1
    assert repository.cti_sources("CVE-2026-1001")[0]["source_name"] == "NIST NVD"
