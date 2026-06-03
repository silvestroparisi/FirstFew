#!/usr/bin/env python3
"""
FirstFew feed enrichment.

Downloads the three authoritative sources and writes compact snapshots into /data,
sharded by CVE year so the static site loads only what it needs:

  data/kev.json            -> { date, count, cves:[...] }          (CISA KEV)
  data/epss/<YEAR>.json    -> { "CVE-...": epss_float, ... }        (FIRST EPSS)
  data/cvss/<YEAR>.json    -> { "CVE-...": {"s":score,"av":"N"} }   (NVD CVSS + attack vector)

Pure standard library, no pip dependencies.
Usage:  python scripts/enrich.py            # all three
        python scripts/enrich.py kev epss   # only some steps
NVD step uses the optional NVD_API_KEY env var (faster). It works without one (slower).
"""
import json, os, sys, time, gzip, re, datetime
import urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
UA = {"User-Agent": "FirstFew-enrich/1.0 (+https://github.com/silvestroparisi/FirstFew)"}


def get(url, headers=None, retries=4, timeout=90):
    h = dict(UA)
    if headers:
        h.update(headers)
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 500, 503) and i < retries - 1:
                time.sleep(6 * (i + 1)); continue
            raise
        except Exception as e:
            last = e
            if i < retries - 1:
                time.sleep(4 * (i + 1)); continue
            raise
    raise last


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, separators=(",", ":"), sort_keys=True)


def year_of(cve):
    m = re.match(r"CVE-(\d{4})-", cve or "", re.I)
    return m.group(1) if m else None


# ---------------------------------------------------------------- KEV (CISA)
def build_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    j = json.loads(get(url))
    cves = sorted({v["cveID"] for v in j.get("vulnerabilities", []) if v.get("cveID")})
    write_json(os.path.join(DATA, "kev.json"),
               {"date": (j.get("dateReleased") or "")[:10], "count": len(cves), "cves": cves})
    print(f"KEV  : {len(cves)} CVEs")


# ---------------------------------------------------------------- EPSS (FIRST)
def build_epss():
    url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    raw = gzip.decompress(get(url, timeout=180))
    text = raw.decode("utf-8", "replace")
    by_year, date = {}, ""
    for line in text.splitlines():
        if line.startswith("#"):
            m = re.search(r"score_date:([0-9-]+)", line)
            if m:
                date = m.group(1)
            continue
        if line.lower().startswith("cve,"):
            continue
        p = line.split(",")
        if len(p) < 2:
            continue
        cve, y = p[0].strip(), year_of(p[0])
        if not y:
            continue
        try:
            by_year.setdefault(y, {})[cve] = round(float(p[1]), 5)
        except ValueError:
            continue
    total = 0
    for y, m in by_year.items():
        write_json(os.path.join(DATA, "epss", f"{y}.json"), m)
        total += len(m)
    write_json(os.path.join(DATA, "epss", "_meta.json"),
               {"date": date, "years": sorted(by_year), "count": total})
    print(f"EPSS : {total} CVEs / {len(by_year)} years (score_date {date})")


# ---------------------------------------------------------------- CVSS (NVD)
AV_MAP = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "ADJACENT": "A", "LOCAL": "L", "PHYSICAL": "P"}


def extract_cvss(cve_obj):
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            score = d.get("baseScore")
            av = d.get("attackVector") or d.get("accessVector")
            if score is not None:
                return round(float(score), 1), AV_MAP.get((av or "").upper(), "N")
    return None, None


def load_existing_cvss():
    out, d = {}, os.path.join(DATA, "cvss")
    if os.path.isdir(d):
        for fn in os.listdir(d):
            if re.match(r"\d{4}\.json$", fn):
                with open(os.path.join(d, fn)) as f:
                    out[fn[:-5]] = json.load(f)
    return out


def build_cvss():
    key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": key} if key else None
    delay = 0.8 if key else 6.5
    by_year = load_existing_cvss()
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    if by_year:  # incremental: only what changed recently (8-day overlap for safety)
        end = datetime.datetime.utcnow()
        start = end - datetime.timedelta(days=8)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        win = f"lastModStartDate={start.strftime(fmt)}&lastModEndDate={end.strftime(fmt)}&"
        mode = "incremental"
    else:
        win, mode = "", "full"
    print(f"CVSS : {mode} sync (api key: {'yes' if key else 'no'})")
    start_index, total, added = 0, None, 0
    while True:
        url = f"{base}?{win}resultsPerPage=2000&startIndex={start_index}"
        data = json.loads(get(url, headers=headers))
        if total is None:
            total = data.get("totalResults", 0)
            print(f"       totalResults={total}")
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for v in vulns:
            c = v.get("cve", {})
            cid = c.get("id")
            y = year_of(cid)
            if not cid or not y:
                continue
            score, av = extract_cvss(c)
            if score is None:
                continue
            by_year.setdefault(y, {})[cid] = {"s": score, "av": av}
            added += 1
        start_index += len(vulns)
        if total and start_index >= total:
            break
        time.sleep(delay)
    cnt = 0
    for y, m in by_year.items():
        write_json(os.path.join(DATA, "cvss", f"{y}.json"), m)
        cnt += len(m)
    write_json(os.path.join(DATA, "cvss", "_meta.json"),
               {"date": datetime.datetime.utcnow().strftime("%Y-%m-%d"),
                "years": sorted(by_year), "count": cnt, "mode": mode})
    print(f"CVSS : +{added} updated, {cnt} total / {len(by_year)} years")


def main():
    os.makedirs(DATA, exist_ok=True)
    steps = [s.lower() for s in sys.argv[1:]] or ["kev", "epss", "cvss"]
    if "kev" in steps:
        build_kev()
    if "epss" in steps:
        build_epss()
    if "cvss" in steps:
        build_cvss()


if __name__ == "__main__":
    main()
