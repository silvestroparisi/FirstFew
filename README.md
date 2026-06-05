# FirstFew

**Stop drowning in findings. Fix the First Few that matter.**

A free, open-source, **fully client-side** vulnerability triage tool. Feed it your scanner's findings and it turns the firehose into a short, ranked **P0–P3** to-do list — so you know the handful to fix *today* instead of staring at thousands of CVEs.

🔗 **Live:** https://silvestroparisi.github.io/FirstFew/

> **Companion — [FixFew](https://github.com/silvestroparisi/FixFew):** once FirstFew has surfaced the few that matter, FixFew helps you actually close them — it verifies whether each finding is really exploitable on your asset and proposes the least-disruptive fix.
>
> **Also in the toolkit — [MaskFew](https://github.com/silvestroparisi/MaskFew):** strip personal data, secrets and identifiers out of a file — locally, in your browser — before you share it with a cloud tool or an AI.

---

## Why

Finding vulnerabilities became almost free. The hard part was never *finding* them — it's deciding **what to fix first**. Raw CVSS doesn't answer that: a "critical" 9.8 sitting on an isolated internal box can matter far less than a "high" that's being actively exploited on your internet edge.

FirstFew scores every finding by **real risk, not raw severity**, and shows the reasoning behind every single verdict — no black box.

## How priority is decided

1. **Is it being exploited right now?** If the CVE is on CISA's **KEV** list → it's **P0**, full stop, wherever it sits and whatever its CVSS.
2. **Otherwise:** `Score = Likelihood × Impact`
   - **Likelihood** = `EPSS × attack-vector × exposure` — how probable exploitation is, combined with whether an attacker can actually *reach* the asset.
   - **Impact** = `max(asset-criticality, core-infra-floor) × CVSS/10` — how much the asset matters; core network gear (routers, switches, firewalls) is floored high even when internal, because compromising it breaks your segmentation.

Weights used:

| Factor | Values |
| --- | --- |
| Attack vector | network `1.0` · adjacent `0.55` · local `0.35` · physical `0.15` |
| Exposure (zone) | internet `1.0` · dmz `0.8` · internal `0.5` · management `0.2` |
| Asset criticality | crown `1.0` · important `0.7` · normal `0.45` · low `0.2` |
| Core-infra floor | `0.85` (for `network-core` assets) |

Tiers: **P0** ≥ 0.45 · **P1** ≥ 0.22 · **P2** ≥ 0.08 · **P3** below. Response targets: P0 ≤ 72h · P1 ≤ 2 weeks · P2 ≤ 90 days.

It's a transparent heuristic, not a guarantee — every finding in the list shows its own arithmetic so you can sanity-check it.

## Privacy

Everything runs **in your browser**. Your list of CVEs and your asset context are never uploaded anywhere — the risk feeds are static files served from the same site, the scoring happens locally, and the CSV/report exports are generated on your machine. Nothing leaves the page.

## Using it

1. Open the [live site](https://silvestroparisi.github.io/FirstFew/) and hit **Reload demo data** to see it in action, or
2. **Upload a CSV** of your own findings.

Only the `cve` column is required — everything else is *your* context. The risk data (CVSS, EPSS, KEV, attack vector) is filled in automatically from the live feeds.

```csv
cve,asset,type,zone,criticality
CVE-2024-3400,edge-fw-01,appliance,internet,crown
CVE-2021-44228,app-java-01,server,internet,important
CVE-2016-5195,host-rhel-19,server,internal,important
```

- `zone`: `internet` · `dmz` · `internal` · `management`
- `criticality`: `crown` · `important` · `normal` · `low`
- `type`: `server` · `network-core` · `appliance` · `endpoint`
- Add `cvss`, `epss`, `kev` or `av` columns to override the feed values.

Export the prioritized list as a **CSV** (worklist) and a printable **HTML report** with one click.

## The data pipeline

A scheduled GitHub Action ([`.github/workflows/enrich.yml`](.github/workflows/enrich.yml)) runs nightly and downloads the three authoritative sources, writing compact snapshots into `/data`, sharded by CVE year so the page only loads what it needs:

```
data/kev.json          # CISA Known Exploited Vulnerabilities
data/epss/<year>.json  # FIRST EPSS scores
data/cvss/<year>.json  # NVD CVSS base score + attack vector
```

The page fetches only the year-shards present in your upload, resolves everything locally, and never sends your CVE list to those services.

## Self-hosting

1. **Fork** this repo.
2. **Settings → Pages →** deploy from branch `main`, folder `/ (root)`.
3. *(Optional, recommended)* add a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) as a repo secret named `NVD_API_KEY` — it speeds up the first full CVSS sync.
4. **Settings → Actions → General →** set *Workflow permissions* to **Read and write**.
5. **Actions → Refresh feeds → Run workflow** once to populate `/data`. (The first run does a full NVD sync and is slow — it's a one-time cost; nightly runs are incremental and fast.)

## Tech

- A single self-contained `index.html` — no build step, no backend, no dependencies (only Google Fonts).
- Bilingual (IT/EN), dark/light themes.
- Scales to 10k+ findings: the list renders only the prioritized head, the quadrant chart uses a canvas density map for large sets.
- Enrichment is a dependency-free Python script ([`scripts/enrich.py`](scripts/enrich.py)) run by GitHub Actions.

## Data sources

- **CISA Known Exploited Vulnerabilities (KEV)** — public domain (CC0).
- **FIRST EPSS** — Exploit Prediction Scoring System.
- **NVD** — National Vulnerability Database (CVSS).

## License

Released under the **MIT License**.

---

Built by **Silvestro Parisi**.
