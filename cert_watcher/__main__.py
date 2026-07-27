from __future__ import annotations

import argparse
import logging
import os
import time

from .config import load_assets
from .connectors import CertFrRssConnector, CisaKevConnector, MitreCveConnector, NvdConnector
from .notifications import Notifier
from .repository import Repository
from .service import run_cycle
from .tracking import process_reminders, write_report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--authorize-gmail", action="store_true", help="crée ou renouvelle le jeton OAuth Gmail puis quitte")
    parser.add_argument("--report", action="store_true", help="génère le rapport de suivi puis quitte")
    parser.add_argument("--set-status", nargs=2, metavar=("TICKET_ID", "STATUS"), help="met à jour un ticket")
    parser.add_argument("--comment", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    assets = load_assets(args.config)
    repository, notifier = Repository(), Notifier()
    if args.set_status:
        repository.update_ticket(int(args.set_status[0]), args.set_status[1], comment=args.comment)
        return
    if args.authorize_gmail:
        logging.info("Jeton OAuth Gmail enregistré : %s", notifier.authorize())
        return
    if args.report:
        logging.info("Rapport généré : %s", write_report(repository))
        return
    lookback_days = int(os.getenv("NEW_VULNERABILITY_DAYS", "30"))
    connectors = [CertFrRssConnector(), CisaKevConnector(), NvdConnector(lookback_days), MitreCveConnector()]
    while True:
        logging.info("Relances/escales : %d notification(s)", process_reminders(repository, notifier))
        logging.info("Cycle terminé : %d alerte(s) générée(s)", run_cycle(connectors, assets, repository, notifier))
        if args.once:
            return
        time.sleep(int(os.getenv("POLL_INTERVAL_HOURS", "6")) * 3600)


if __name__ == "__main__":
    main()
