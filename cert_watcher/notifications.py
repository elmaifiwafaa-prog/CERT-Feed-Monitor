from __future__ import annotations

import base64
import os
from email.message import EmailMessage
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from .models import Contact


GMAIL_SCOPE = ["https://www.googleapis.com/auth/gmail.send"]


class Notifier:
    """Targeted Gmail API notification. Dry-run is the safe default."""

    def mode(self) -> str:
        return os.getenv("GMAIL_MODE", "dry-run").casefold()

    def authorize(self) -> Path:
        """Run the OAuth consent flow once and persist the refresh token."""
        token_path = Path(os.environ["GMAIL_OAUTH_TOKEN"])
        credentials = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPE) if token_path.exists() else None
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            token_path.write_text(credentials.to_json(), encoding="utf-8")
        if not credentials or not credentials.valid:
            client_secrets = os.getenv("GMAIL_OAUTH_CLIENT_SECRETS")
            if not client_secrets:
                raise RuntimeError("OAuth Gmail non initialisé : définissez GMAIL_OAUTH_TOKEN ou GMAIL_OAUTH_CLIENT_SECRETS.")
            port = int(os.getenv("GMAIL_OAUTH_PORT", "8080"))
            flow = InstalledAppFlow.from_client_secrets_file(client_secrets, GMAIL_SCOPE)
            credentials = flow.run_local_server(
                host="localhost", bind_addr="0.0.0.0", port=port, open_browser=False,
                authorization_prompt_message="Ouvrez cette URL dans votre navigateur pour autoriser Gmail : {url}",
            )
            token_path.parent.mkdir(parents=True, exist_ok=True)
            token_path.write_text(credentials.to_json(), encoding="utf-8")
        return token_path

    def _gmail_service(self):
        token_path = self.authorize()
        credentials = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPE)
        return build("gmail", "v1", credentials=credentials, cache_discovery=False)

    def send_ticket_report(self, contact: Contact, ticket_id: str, cve_id: str, asset_name: str, report_path: Path) -> tuple[str, str | None]:
        if self.mode() == "dry-run":
            return "dry-run", None
        if self.mode() != "live":
            raise ValueError("GMAIL_MODE doit valoir dry-run ou live")
        message = EmailMessage()
        message["To"] = contact.email
        message["From"] = os.environ.get("GMAIL_FROM", contact.email)
        message["Subject"] = f"[SEKERA][{ticket_id}] Vulnérabilité {cve_id} - action requise"
        message.set_content(
            f"Bonjour {contact.name},\n\n"
            f"Le ticket {ticket_id} concerne la vulnérabilité {cve_id} détectée sur l'équipement « {asset_name} ».\n"
            "Le rapport PDF joint détaille l'impact, les sources officielles et les recommandations de correction.\n\n"
            "Merci de traiter ce ticket et de mettre à jour son statut.\n\nSEKERA - Veille cybersécurité"
        )
        message.add_attachment(report_path.read_bytes(), maintype="application", subtype="pdf", filename=report_path.name)
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
        response = self._gmail_service().users().messages().send(userId="me", body={"raw": raw}).execute()
        return "sent", response.get("id")

    def send_tracking(self, cve_id: str, recipients: list[str], alert_path: Path, subject_prefix: str) -> list[tuple[str, str]]:
        """Keep the phase-2 reminder adapter safe until it is migrated to Gmail templates."""
        return [(recipient, "dry-run") for recipient in recipients]
