from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Contact:
    name: str
    email: str
    escalation_email: str | None = None


@dataclass(frozen=True)
class Software:
    vendor: str
    product: str
    version: str


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    owner_team: str
    contact: Contact
    software: tuple[Software, ...]
    environment: str = "unknown"
    criticality: str = "medium"
    contacts: tuple[Contact, ...] = ()

    @property
    def responsible_contacts(self) -> tuple[Contact, ...]:
        return self.contacts or (self.contact,)


@dataclass
class Vulnerability:
    cve_id: str
    title: str
    description: str
    vendor: str | None = None
    product: str | None = None
    affected_versions: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published_at: datetime | None = None
    # Date at which a CTI source first listed the CVE (for example CISA KEV dateAdded).
    source_added_at: datetime | None = None
    actively_exploited: bool = False
    remediation: str | None = None
    sources: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Match:
    vulnerability: Vulnerability
    asset: Asset
    reason: str
