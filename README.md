# CERT Watcher

## Tickets PDF et Gmail API

Chaque correspondance entre une CVE nouvelle ou mise a jour et un materiel cree un ticket distinct `CVE + asset_id`. Un rapport PDF LaTeX est produit par Tectonic et transmis uniquement aux responsables declares dans `contact` ou `contacts` de l'inventaire. Chaque page porte la mention `TLP:AMBER` en pied de page.

Le mode Gmail est `dry-run` par defaut : le PDF est cree et la livraison est journalisee sans envoi. Pour un envoi reel, definir `GMAIL_MODE=live`, `GMAIL_OAUTH_TOKEN` et `GMAIL_FROM`. Le jeton OAuth2 doit avoir le scope Gmail `gmail.send`; ne jamais le versionner.

Les migrations SQLite numerotees de `cert_watcher/migrations/` sont appliquees automatiquement au demarrage et enregistrees dans `schema_version`.

## Rapports PDF par materiel

Lorsqu'une nouvelle vulnerabilite correspond a un materiel, le service cree un rapport PDF distinct dans `data/reports/assets/`. Le rapport contient les vulnerabilites ouvertes, les tickets associes et le logo SEKERA (`sekera.png`). Il est adresse uniquement au contact defini pour ce materiel dans `assets.example.yaml`.

L'envoi cible utilise l'API Gmail OAuth2, jamais SMTP. Conservez les jetons OAuth hors de Git et activez `GMAIL_MODE=live` uniquement apres validation du dry-run.

MVP d'un agent de veille CERT : il collecte des sources officielles, normalise les vulnérabilités, les corrèle à un inventaire interne, produit des fiches d'alerte et journalise une distribution ciblée. Par défaut, les notifications sont simulées : aucun e-mail n'est envoyé.

## Architecture

`connectors` récupère CERT-FR, CISA KEV, NVD et MITRE CVE. NVD est interrogé avec une borne de publication récente et CISA KEV est filtré sur sa date d'ajout. `services` normalise, déduplique et corrèle les données avec les logiciels déclarés dans `config/assets.example.yaml`. Les alertes ne sont créées que pour les actifs correspondants. `repositories` conserve l'audit et les éléments traités dans SQLite. Les adaptateurs de notification sont interchangeables.

Les identifiants CVE sont la clé métier de déduplication. Les connecteurs ne sont jamais une source de vérité unique : plusieurs enregistrements source peuvent enrichir la même vulnérabilité.

## Modèle de données

- `assets` (YAML au MVP) : actif, environnement, équipe, contact et installations logicielles.
- `vulnerabilities` : CVE, description, CVSS, dates de publication et de première/dernière détection, indicateur KEV.
- `source_observations` : plate-forme CTI (NIST NVD, CISA KEV, CERT-FR, MITRE), URL, date d'ajout à la source et dernière observation.
- `matches` : association vulnérabilité-actif avec justification.
- `alerts` / `alert_recipients` : fiche générée, TLP, destinataires ciblés et résultat de distribution.
- `tickets` / `ticket_history` : réservés à la phase 2 pour remédiation, relances et clôture.

## Démarrage

```bash
cp .env.example .env
docker compose up --build
```

Le conteneur exécute un cycle à son démarrage. Pour un essai local :

```bash
python -m pip install -r requirements.txt
python -m cert_watcher --config config/assets.example.yaml --once
pytest
```

Les fiches sont sous `data/alerts/`, la base et le journal sous `data/`. L'exemple de configuration utilise des actifs fictifs. Remplacez-le avant toute utilisation réelle.

L'application utilise les données de l’API NVD et n’est ni approuvée ni certifiée par le NVD.

## Configuration et sécurité

- `GMAIL_MODE=dry-run` est la valeur par défaut. Passez à `live` seulement après avoir provisionné OAuth2 et validé les rapports produits.
- Ne mettez jamais de jeton OAuth, secret client ou adresse de contact dans Git. En production, injectez-les depuis un coffre-fort.
- Montez `data/` sur un volume chiffré et accessible uniquement au compte de service. Les fiches contiennent les actifs internes impactés.
- Le service applique la diffusion au plus petit périmètre : uniquement les contacts des actifs associés à une vulnérabilité.

## Planification

Dans Docker, `POLL_INTERVAL_HOURS` définit la fréquence. En serveur Linux, l'alternative est `cert-watcher --once` via cron. Prévoir des limites de débit, une sortie Internet filtrée vers les sources officielles et une identité Gmail OAuth à privilèges minimaux.

## Vulnérabilités nouvelles uniquement

La fenêtre `NEW_VULNERABILITY_DAYS` vaut `30` par défaut. Une CVE NVD publiée avant cette fenêtre, ou une CVE CISA KEV ajoutée avant cette fenêtre, est ignorée. Les CVE admises sont persistées avec leurs observations CTI ; une CVE déjà connue ne redéclenche pas d'alerte. Ajustez la fenêtre dans `.env`, par exemple `NEW_VULNERABILITY_DAYS=7`.

## Suivi de remédiation (phase 2)

Chaque fiche crée un ticket `OPEN`. Les statuts valides sont `OPEN`, `IN_PROGRESS`, `PATCHED`, `RISK_ACCEPTED` et `CLOSED`. Modifier un ticket :

```bash
python -m cert_watcher --config config/assets.example.yaml --set-status 1 IN_PROGRESS --comment "Correctif en validation"
python -m cert_watcher --config config/assets.example.yaml --report
```

Le cycle automatique envoie une relance à J+7 et une escalade à J+14 uniquement pour les tickets ouverts ou en cours. Pour que l'escalade cible un responsable N+1, ajoutez `escalation_email` au contact de chaque actif :

```yaml
contact:
  name: Alice Martin
  email: alice@example.invalid
  escalation_email: manager.web@example.invalid
```

## Limites du MVP

Le matching est déterministe sur éditeur, produit et version déclarée. La prise en charge complète CPE/versions complexes, l'authentification applicative, PDF, interface et tickets/relances sont prévus pour les phases suivantes.
