from __future__ import annotations

from .models import Asset, Match, Vulnerability


def _same(left: str | None, right: str) -> bool:
    return bool(left and left.casefold().strip() == right.casefold().strip())


def _version_affected(version: str, affected: list[str]) -> bool:
    if not affected:
        return True
    joined = " ".join(affected).casefold()
    return version.casefold() in joined or "all versions" in joined


def match(vulnerability: Vulnerability, assets: list[Asset]) -> list[Match]:
    if not vulnerability.vendor or not vulnerability.product:
        return []
    matches = []
    for asset in assets:
        for installed in asset.software:
            if _same(vulnerability.vendor, installed.vendor) and _same(vulnerability.product, installed.product) and _version_affected(installed.version, vulnerability.affected_versions):
                matches.append(Match(vulnerability, asset, f"{installed.vendor} {installed.product} {installed.version}"))
    return matches
