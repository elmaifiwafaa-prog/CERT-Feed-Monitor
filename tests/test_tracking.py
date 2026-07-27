from datetime import datetime, timedelta, timezone

from cert_watcher.repository import Repository
from cert_watcher.tracking import process_reminders, write_report


class FakeNotifier:
    def __init__(self): self.calls = []
    def send_tracking(self, cve_id, recipients, alert_path, prefix):
        self.calls.append((cve_id, recipients, prefix))
        return [(recipient, "simulated") for recipient in recipients]


def test_reminder_then_escalation_and_report(tmp_path):
    repository = Repository(tmp_path / "db.sqlite")
    ticket = repository.create_ticket("CVE-2026-1000", "HIGH", ["a1"], ["a@example.invalid"], ["manager@example.invalid"], "data/alerts/CVE-2026-1000.md")
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    repository.connection.execute("UPDATE tickets SET opened_at = ? WHERE id = ?", (old, ticket))
    repository.connection.commit()
    notifier = FakeNotifier()
    assert process_reminders(repository, notifier) == 1
    assert notifier.calls[0][2] == "RELANCE J+7"
    repository.connection.execute("UPDATE tickets SET opened_at = ?, last_reminder_at = NULL WHERE id = ?", ((datetime.now(timezone.utc) - timedelta(days=15)).isoformat(), ticket))
    repository.connection.commit()
    assert process_reminders(repository, notifier) == 1
    assert notifier.calls[1][2] == "ESCALATION J+14"
    assert notifier.calls[1][1] == ["manager@example.invalid"]
    assert write_report(repository, tmp_path / "report.md").exists()
