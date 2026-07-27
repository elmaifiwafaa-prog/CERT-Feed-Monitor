from __future__ import annotations

from pathlib import Path
import yaml

from .models import Asset, Contact, Software


def load_assets(path: str | Path) -> list[Asset]:
    with Path(path).open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    assets = []
    for item in data.get("assets", []):
        contacts_data = item.get("contacts", [])
        contact_data = item.get("contact") or (contacts_data[0] if contacts_data else None)
        if not contact_data:
            raise ValueError(f"Actif {item['id']} sans contact responsable")
        assets.append(Asset(
            id=item["id"], name=item["name"], owner_team=item["owner_team"],
            contact=Contact(**contact_data), environment=item.get("environment", "unknown"),
            criticality=item.get("criticality", "medium"),
            software=tuple(Software(
                vendor=str(software["vendor"]), product=str(software["product"]),
                version=str(software["version"]),
            ) for software in item.get("software", [])),
            contacts=tuple(Contact(**contact) for contact in contacts_data),
        ))
    return assets
