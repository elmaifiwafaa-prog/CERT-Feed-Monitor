from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .models import Asset, Vulnerability


def latex_escape(value: object) -> str:
    text = str(value or "Non disponible")
    replacements = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}
    for source, replacement in replacements.items():
        text = text.replace(source, replacement)
    return text


def technical_summary(vulnerability: Vulnerability) -> str:
    product = " ".join(part for part in (vulnerability.vendor, vulnerability.product) if part) or "le produit concerné"
    score = vulnerability.cvss_score or 0
    impact = "un impact important sur la confidentialité, l'intégrité ou la disponibilité" if score >= 7 else "un impact nécessitant une analyse de l'exposition"
    exploitation = " Elle est référencée dans le catalogue CISA KEV, ce qui indique une exploitation active connue." if vulnerability.actively_exploited else " Aucune exploitation active n'est confirmée par les sources consultées."
    return f"Cette vulnérabilité concerne {product}. Son niveau CVSS indique {impact}." + exploitation


class LatexReportGenerator:
    def __init__(self, tectonic_binary: str = "tectonic", output_dir: str | Path = "data/reports/tickets"):
        self.tectonic_binary = tectonic_binary
        self.output_dir = Path(output_dir)
        self.environment = Environment(
            loader=FileSystemLoader(Path(__file__).with_name("templates")),
            undefined=StrictUndefined,
            autoescape=False,
        )

    def available(self) -> bool:
        return shutil.which(self.tectonic_binary) is not None

    def generate(self, ticket, vulnerability: Vulnerability, asset: Asset, sources: list[dict]) -> Path:
        if not self.available():
            raise RuntimeError("Tectonic est introuvable. Installez-le ou utilisez l'image Docker SEKERA.")
        workdir = (self.output_dir / ticket["ticket_id"] / f"revision-{ticket['revision']}").resolve()
        workdir.mkdir(parents=True, exist_ok=True)
        logo = Path("sekera.png")
        if not logo.exists():
            raise FileNotFoundError("Logo SEKERA introuvable : sekera.png")
        shutil.copy2(logo, workdir / "sekera.png")
        severity_color = {"CRITICAL": "red", "HIGH": "red!70!black", "MEDIUM": "yellow!50!black", "LOW": "green!50!black"}.get(ticket["severity"], "black")
        template = self.environment.get_template("vulnerability_ticket.tex.j2")
        context = {
            "logo_path": "sekera.png", "ticket_id": latex_escape(ticket["ticket_id"]), "detected_at": latex_escape(ticket["detected_at"][:19].replace("T", " ") + " UTC"),
            "severity": latex_escape(ticket["severity"]), "severity_color": severity_color, "status": latex_escape(ticket["status"]), "revision": ticket["revision"],
            "cve_id": latex_escape(vulnerability.cve_id), "exploitation": "Oui - CISA KEV" if vulnerability.actively_exploited else "Non confirmée",
            "title": latex_escape(vulnerability.title), "technical_summary": latex_escape(technical_summary(vulnerability)),
            "cvss_score": latex_escape(vulnerability.cvss_score), "cvss_vector": latex_escape(vulnerability.cvss_vector),
            "affected_versions": latex_escape(", ".join(vulnerability.affected_versions) if vulnerability.affected_versions else "À confirmer selon l'avis officiel"),
            "asset_name": latex_escape(asset.name), "asset_id": latex_escape(asset.id), "environment": latex_escape(asset.environment), "owner_team": latex_escape(asset.owner_team),
            "contacts": latex_escape(", ".join(f"{contact.name} <{contact.email}>" for contact in asset.responsible_contacts)),
            "remediation": latex_escape(vulnerability.remediation or "Consulter l'avis officiel de l'éditeur et appliquer le correctif ou le contournement recommandé."),
            "sources": [{"name": latex_escape(source["name"]), "url": source["url"]} for source in sources],
        }
        tex_path = workdir / "rapport.tex"
        tex_path.write_text(template.render(**context), encoding="utf-8")
        try:
            subprocess.run(
                [self.tectonic_binary, "--outdir", str(workdir), str(tex_path)],
                cwd=workdir, check=True, timeout=120, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as error:
            details = (error.stderr or error.stdout or "Erreur LaTeX sans sortie.").strip()
            raise RuntimeError(f"Compilation Tectonic échouée pour le ticket {ticket['ticket_id']}: {details}") from error
        pdf_path = workdir / "rapport.pdf"
        if not pdf_path.exists():
            raise RuntimeError("Tectonic n'a pas produit le PDF attendu.")
        return pdf_path
