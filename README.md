# Incident Radar — GitHub Pages deployment (serverless, refreshed every 10 minutes)

Lactalis Enterprise Security · © Marco Alderisio

GitHub Actions runs `scripts/build.py` every 10 minutes. It reads the public sources below, merges
duplicates, keeps 180 days of history and the time each signal was first detected, and publishes
`index.html` + `data/incidents.json` to `https://<account>.github.io/<repo>/`. The page checks for new
data every 5 minutes and can raise desktop alerts.

| Signal | Sources |
|---|---|
| Leak-site claims | ransomware.live API, ransomware.live GitHub mirror (privtools), ThreatCluster |
| Reported attacks | Cyberwatch (Valéry Rieß-Marchive, LeMagIT: press-reported attacks from ~25 languages, checked by hand), ransomware.live "recent cyberattacks" |
| Regulatory | SEC EDGAR full-text search: Form 8-K Item 1.05 and cyber 8.01 |
| Press | BleepingComputer, The Record, SecurityWeek, The Hacker News, Dark Reading, Security Affairs, DataBreaches.net, Cybernews, The Register, Industrial Cyber, LeMagIT, ZATAZ, Le Monde Informatique, Red Hot Cyber, Cybersecurity360, heise, Una al día |
| Food trade press | Food Dive, Just Food, Food Manufacturing, DairyReporter, FoodNavigator, LSA |
| Aggregator | Google News searches (EN-US/GB/AU, FR, IT, ES, MX, BR, DE) for dairy and food incidents |
| Government | CISA, CERT-FR (alertes, actualité), NCSC UK |

Edit the `RSS`, `GNEWS` and `SEC_QUERIES` lists at the top of `scripts/build.py` to add or remove sources.
A source that fails is reported on the page (Sources tab) and does not stop the others.

## Setup (about 10 minutes)
1. Create a new **public** repository with a neutral name (e.g. `ir-monitor`).
   GitHub Pages on a private repository needs GitHub Team/Enterprise.
2. Upload the contents of this folder, including the hidden `.github` folder, to `main`.
3. Settings → Secrets and variables → Actions → **Variables** → add `IR_UA`, for example
   `IncidentRadar/0.1 (Lactalis Enterprise Security; contact: security@yourdomain.com)`.
   SEC EDGAR refuses requests without a contact address.
4. Settings → Pages → Build and deployment → Source: **GitHub Actions**.
5. Actions → "Refresh incidents and publish" → **Run workflow**. The first run also loads 180 days of
   claim history (≈1 minute).
6. Open `https://<account>.github.io/<repo>/`, then set the mailing list (Alerts & e-mail) and check the
   footprint zones (Footprint & watchlist). "Copy as team configuration" produces a block to paste into
   `IR_CONFIG` in `index.html`, so every colleague gets the same defaults.

## Data branch (live data for every copy)
Each run also force-pushes `incidents.json` and `status.json` to a `data` branch. Set
`remoteData: "https://raw.githubusercontent.com/<account>/<repo>/data/"` in `IR_CONFIG` and any copy of the page
(the standalone file on a laptop, an intranet copy) reads the full live data from there.

## Lactalis footprint (zones and countries)
The footprint changes over time, so it is configurable without code: Footprint & watchlist tab → pick a
zone → click countries on the map (or edit the ISO codes), rename zones, change colours, add or remove
zones, export/import as JSON. These edits are stored in the browser; to make them the default for
everyone, use "Copy as team configuration" and paste the block into `IR_CONFIG` in `index.html`, then commit.

## ransomware.live terms
The free legacy API (`api.ransomware.live/v2`) is rate-limited and intended for personal use. For team
use, create a free personal token at https://my.ransomware.live and set the repository variable
`RL_BASE` (the API base URL given there) and the secret `RL_HEADER` (`Header-Name: token`, as documented there).

## Notes
- GitHub runs schedules on a best-effort basis; at busy times a 10-minute schedule can slip.
- Leak-site (.onion) links and screenshots are never stored or published.
- Alternative hosting: run `python3 scripts/build.py` on any scheduler and copy `site/` to any static
  host (Azure Static Web Apps, an intranet web server…).
