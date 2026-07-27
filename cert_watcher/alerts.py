from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .models import Match, Vulnerability


def severity(vulnerability: Vulnerability) -> str:
    if vulnerability.actively_exploited or (vulnerability.cvss_score or 0) >= 9:
        return "CRITICAL"
    if (vulnerability.cvss_score or 0) >= 7:
        return "HIGH"
    if (vulnerability.cvss_score or 0) >= 4:
        return "MEDIUM"
    return "LOW"


def render_alert(vulnerability: Vulnerability, matches: list[Match]) -> str:
    generated = datetime.now(timezone.utc).isoformat()
    assets = "\n".join(f"- **{m.asset.name}** (`{m.asset.id}`), {m.reason}, équipe : {m.asset.owner_team}" for m in matches)
    sources = "\n".join(f"- {source}" for source in vulnerability.sources)
    return f"""# Alerte {vulnerability.cve_id}

| Champ | Valeur |
|---|---|
| Criticité | {severity(vulnerability)} |
| TLP | TLP:AMBER |
| Publication / ajout CTI | {(vulnerability.source_added_at or vulnerability.published_at).isoformat() if (vulnerability.source_added_at or vulnerability.published_at) else 'Date non fournie par la source'} |
| Générée le | {generated} |
| Exploitation active | {'Oui (CISA KEV)' if vulnerability.actively_exploited else 'Non confirmée'} |
| CVSS | {vulnerability.cvss_score or 'Non disponible'} {vulnerability.cvss_vector or ''} |

## Résumé

{vulnerability.title}

{vulnerability.description}

## Actifs internes concernés

{assets}

## Recommandation

{vulnerability.remediation or 'Consulter l’avis officiel de l’éditeur et appliquer le correctif ou le contournement recommandé.'}

## Sources officielles

{sources}
"""


def write_alert(vulnerability: Vulnerability, markdown: str, directory: str | Path = "data/alerts") -> Path:
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    target = path / f"{vulnerability.cve_id}.md"
    target.write_text(markdown, encoding="utf-8")
    return target
