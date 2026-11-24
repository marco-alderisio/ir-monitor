# Incident source collector

Collects public cyber-incident sources every 10 minutes with GitHub Actions and publishes one normalised
dataset on the `data` branch:

- `https://raw.githubusercontent.com/<account>/<repo>/data/incidents.json` — signals of the last 180 days
- `https://raw.githubusercontent.com/<account>/<repo>/data/status.json` — per-source status of the last run

Sources: leak-site claims (ransomware.live, ThreatCluster), press-reported cyberattacks (Cyberwatch,
ransomware.live), SEC Form 8-K cyber disclosures, cybersecurity and food-industry trade press, Google News
searches, and government CERT feeds (CISA, CERT-FR, NCSC). Edit the lists at the top of `scripts/build.py`.

Leak-site (.onion) links and screenshots are never stored. ransomware.live's free API is rate-limited and
intended for personal use; for other use, set `RL_BASE` / `RL_HEADER` with a free token from my.ransomware.live.
