from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .repository import Repository


def process_reminders(repository: Repository, notifier, now: datetime | None = None) -> int:
    """Send J+7 reminders and a single J+14 escalation for open tickets."""
    now = now or datetime.now(timezone.utc)
    sent = 0
    for ticket in repository.open_tickets():
        opened = datetime.fromisoformat(ticket["opened_at"])
        age_days = (now - opened).days
        recipients = [email for email in ticket["owner_contacts"].split(",") if email]
        if age_days >= 14 and not ticket["escalation_sent_at"]:
            escalation_recipients = [email for email in ticket["escalation_contacts"].split(",") if email] or recipients
            notifier.send_tracking(ticket["cve_id"], escalation_recipients, Path(ticket["alert_path"]), "ESCALATION J+14")
            repository.record_reminder(ticket["id"], escalated=True)
            sent += len(escalation_recipients)
        elif age_days >= 7 and not ticket["last_reminder_at"]:
            notifier.send_tracking(ticket["cve_id"], recipients, Path(ticket["alert_path"]), "RELANCE J+7")
            repository.record_reminder(ticket["id"])
            sent += len(recipients)
    return sent


def write_report(repository: Repository, path: str | Path = "data/reports/vulnerability-status.md") -> Path:
    tickets = repository.all_tickets()
    vulnerabilities = repository.tracked_vulnerabilities()
    counts = {status: sum(ticket["status"] == status for ticket in tickets) for status in ("OPEN", "IN_PROGRESS", "PATCHED", "RISK_ACCEPTED", "CLOSED")}
    lines = ["# Rapport de suivi des vulnérabilités", "", f"Généré le : {datetime.now(timezone.utc).isoformat()}", "", "## Synthèse", ""]
    lines.extend(f"- {status}: {count}" for status, count in counts.items())
    lines.extend(["", "## Tickets", "", "| ID | CVE | Criticité | Statut | Actifs | Ouvert le |", "|---:|---|---|---|---|---|"])
    lines.extend(f"| {ticket['id']} | {ticket['cve_id']} | {ticket['severity']} | {ticket['status']} | {ticket['affected_assets']} | {ticket['opened_at'][:10]} |" for ticket in tickets)
    lines.extend(["", "## Nouvelles détections CTI", "", "| CVE | Publiée / ajoutée | Première détection | Exploitée | Sources |", "|---|---|---|---|---|"])
    for vulnerability in vulnerabilities:
        sources = ", ".join(source["source_name"] for source in repository.cti_sources(vulnerability["cve_id"]))
        source_date = vulnerability["source_added_at"] or vulnerability["published_at"] or "Non fournie"
        lines.append(f"| {vulnerability['cve_id']} | {source_date} | {vulnerability['first_detected_at'][:10]} | {'Oui' if vulnerability['actively_exploited'] else 'Non confirmée'} | {sources} |")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target
