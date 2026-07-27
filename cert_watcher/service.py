from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .alerts import render_alert, severity, write_alert
from .connectors import Connector
from .latex_reports import LatexReportGenerator
from .matching import match
from .models import Vulnerability
from .notifications import Notifier
from .repository import Repository

LOG = logging.getLogger(__name__)


def merge(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    merged: dict[str, Vulnerability] = {}
    for vulnerability in vulnerabilities:
        current = merged.get(vulnerability.cve_id)
        if current is None:
            merged[vulnerability.cve_id] = vulnerability
            continue
        current.actively_exploited |= vulnerability.actively_exploited
        current.sources = list(dict.fromkeys(current.sources + vulnerability.sources))
        current.cvss_score = current.cvss_score or vulnerability.cvss_score
        current.cvss_vector = current.cvss_vector or vulnerability.cvss_vector
        current.vendor = current.vendor or vulnerability.vendor
        current.product = current.product or vulnerability.product
        current.affected_versions = current.affected_versions or vulnerability.affected_versions
        current.remediation = current.remediation or vulnerability.remediation
        current.published_at = current.published_at or vulnerability.published_at
        current.source_added_at = current.source_added_at or vulnerability.source_added_at
    return list(merged.values())


def is_recent(vulnerability: Vulnerability, now: datetime | None = None, lookback_days: int | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    days = lookback_days if lookback_days is not None else int(os.getenv("NEW_VULNERABILITY_DAYS", "30"))
    reference = vulnerability.source_added_at or vulnerability.published_at
    return reference is None or reference >= now - timedelta(days=days)


def vulnerability_fingerprint(vulnerability: Vulnerability) -> str:
    sources = []
    for source in vulnerability.sources:
        # NVD collection URLs contain a moving date range and must not create a false revision.
        sources.append(source.split("?", 1)[0] if "nvd.nist.gov" in source.casefold() else source)
    payload = {
        "title": vulnerability.title, "description": vulnerability.description,
        "vendor": vulnerability.vendor, "product": vulnerability.product,
        "versions": sorted(vulnerability.affected_versions), "cvss": vulnerability.cvss_score,
        "vector": vulnerability.cvss_vector, "kev": vulnerability.actively_exploited,
        "remediation": vulnerability.remediation, "sources": sorted(sources),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _sources(repository: Repository, cve_id: str) -> list[dict]:
    return [{"name": row["source_name"], "url": row["source_url"]} for row in repository.cti_sources(cve_id)]


def _deliver_ticket(repository: Repository, notifier: Notifier, generator: LatexReportGenerator, ticket, vulnerability: Vulnerability, asset) -> None:
    # A ticket keeps the recipients it had when it was opened. Inventory
    # changes must not cause an already-issued report to be sent to a new
    # contact (or regenerated merely because the YAML was edited).
    ticket_recipients = set(json.loads(ticket["responsible_contacts"]))
    contacts = [contact for contact in asset.responsible_contacts if contact.email in ticket_recipients]
    mode = notifier.mode()
    pending = [contact for contact in contacts if not repository.delivery_exists(ticket["ticket_id"], ticket["revision"], contact.email, mode)]
    if not pending:
        return
    report_path = generator.generate(ticket, vulnerability, asset, _sources(repository, vulnerability.cve_id))
    for contact in pending:
        status, gmail_message_id = notifier.send_ticket_report(contact, ticket["ticket_id"], vulnerability.cve_id, asset.name, report_path)
        repository.record_delivery(ticket["ticket_id"], ticket["revision"], contact.email, mode, status, str(report_path), gmail_message_id)


def run_cycle(connectors: list[Connector], assets, repository: Repository, notifier: Notifier, report_generator: LatexReportGenerator | None = None) -> int:
    """Collect, match, revise CVE+asset tickets, then send targeted PDF reports."""
    report_generator = report_generator or LatexReportGenerator()
    collected = []
    for connector in connectors:
        try:
            collected.extend(connector.collect())
        except Exception:
            LOG.exception("Collecte échouée : %s", connector.__class__.__name__)
    generated = 0
    for vulnerability in merge(collected):
        if not is_recent(vulnerability):
            continue
        is_new = repository.record_vulnerability(vulnerability)
        matches = match(vulnerability, assets)
        if not matches:
            continue
        alert_path = write_alert(vulnerability, render_alert(vulnerability, matches))
        matched_assets = {item.asset.id: item.asset for item in matches}
        for asset in matched_assets.values():
            ticket, changed = repository.upsert_asset_ticket(
                vulnerability.cve_id, asset.id, severity(vulnerability),
                [contact.email for contact in asset.responsible_contacts], vulnerability_fingerprint(vulnerability),
            )
            if changed and is_new:
                generated += 1
            if hasattr(notifier, "send_ticket_report"):
                try:
                    _deliver_ticket(repository, notifier, report_generator, ticket, vulnerability, asset)
                except Exception:
                    LOG.exception("Rapport ou livraison Gmail échoué pour %s / %s", vulnerability.cve_id, asset.id)
            else:
                # Backwards compatibility for simple notifier fakes used by the original MVP tests.
                for recipient, status in notifier.send(vulnerability, set(asset.responsible_contacts), Path(alert_path)):
                    repository.log_notification(vulnerability.cve_id, recipient, "simulation", status)
        repository.mark_processed(vulnerability.cve_id)
    return generated
