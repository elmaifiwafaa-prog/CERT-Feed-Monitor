from __future__ import annotations

import json
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from .models import Vulnerability

USER_AGENT = "CERT-Watcher/0.1 (official-source-monitor)"
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def fetch_json(url: str) -> dict:
    return json.loads(fetch_text(url))


def fetch_text(url: str) -> str:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json, application/xml, text/xml"}
    if os.getenv("NVD_API_KEY") and "nvd.nist.gov" in url:
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    request = Request(url, headers=headers)
    with urlopen(request, timeout=30) as response:  # nosec B310: URLs are administrator-controlled official endpoints
        return response.read().decode("utf-8", errors="replace")


class Connector(ABC):
    @abstractmethod
    def collect(self) -> list[Vulnerability]: ...


class CisaKevConnector(Connector):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def collect(self) -> list[Vulnerability]:
        records = fetch_json(self.url).get("vulnerabilities", [])
        return [Vulnerability(
            cve_id=item["cveID"], title=item.get("vulnerabilityName", item["cveID"]),
            description=item.get("shortDescription", ""), vendor=item.get("vendorProject"),
            product=item.get("product"), affected_versions=[],
            actively_exploited=True, remediation=item.get("requiredAction"),
            source_added_at=_parse_date(item.get("dateAdded")), sources=[self.url],
        ) for item in records]


class NvdConnector(Connector):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

    def __init__(self, lookback_days: int = 30):
        self.lookback_days = lookback_days

    def _url(self) -> str:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=self.lookback_days)
        date_format = "%Y-%m-%dT%H:%M:%S.000"
        query = urlencode({"resultsPerPage": 2000, "pubStartDate": start.strftime(date_format), "pubEndDate": end.strftime(date_format)})
        return f"{self.base_url}?{query}"

    def collect(self) -> list[Vulnerability]:
        results = []
        source_url = self._url()
        for item in fetch_json(source_url).get("vulnerabilities", []):
            cve = item["cve"]
            metrics = cve.get("metrics", {})
            metric = next(iter(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []) or metrics.get("cvssMetricV2", [])), {})
            cvss = metric.get("cvssData", {})
            description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            cpes = [match.get("criteria", "").split(":") for node in cve.get("configurations", []) for match in _cpe_matches(node.get("nodes", []))]
            cpe = next((value for value in cpes if len(value) > 5), [])
            results.append(Vulnerability(cve_id=cve["id"], title=cve["id"], description=description,
                vendor=cpe[3] if cpe else None, product=cpe[4] if cpe else None,
                affected_versions=[cpe[5]] if cpe and cpe[5] not in {"*", "-"} else [],
                cvss_score=cvss.get("baseScore"), cvss_vector=cvss.get("vectorString"),
                published_at=_parse_date(cve.get("published")), sources=[source_url]))
        return results


def _cpe_matches(nodes: list[dict]) -> list[dict]:
    """Flatten the recursively nested CPE configuration tree returned by NVD."""
    matches = []
    for node in nodes:
        matches.extend(node.get("cpeMatch", []))
        matches.extend(_cpe_matches(node.get("nodes", [])))
    return matches


class CertFrRssConnector(Connector):
    url = "https://www.cert.ssi.gouv.fr/alerte/feed/"

    def collect(self) -> list[Vulnerability]:
        root = ElementTree.fromstring(fetch_text(self.url))
        output = []
        for item in root.findall(".//item"):
            title = item.findtext("title", default="")
            description = item.findtext("description", default="")
            link = item.findtext("link", default=self.url)
            published_at = _parse_date(item.findtext("pubDate"))
            for cve_id in set(CVE.findall(f"{title} {description}")):
                output.append(Vulnerability(cve_id=cve_id.upper(), title=title, description=description, published_at=published_at, sources=[link]))
        return output


class MitreCveConnector(Connector):
    """MITRE's CVE Services endpoint, used as canonical identifier enrichment."""
    url = "https://cveawg.mitre.org/api/cve-id"

    def collect(self) -> list[Vulnerability]:
        # This endpoint is intentionally not bulk-polled: NVD and KEV drive the MVP.
        # The connector exists for direct CVE lookup extension in a later iteration.
        return []
