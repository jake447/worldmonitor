"""The Survival Summit intel brief.

Every six hours this pulls a digest from World Monitor, asks Claude to
synthesize a prioritized situation brief, and emails it through Resend.

It replaces the ShadowBroker intel-agent, which read four endpoints off a
backend that no longer exists. Six of that agent's ten digest sections came
from ShadowBroker; they are rebuilt here against World Monitor, which carries
more: military air activity, chokepoint status, UKMTO maritime incidents,
navigational warnings, security advisories and a multi-category news digest.
The keyless external feeds it used (CISA KEV, ransomware.live, GDACS) are
carried over unchanged, since they never depended on a backend.

Read-only. It emails, and writes nothing anywhere. The old agent had a
layer-writing path into the ShadowBroker map; World Monitor has no such API
and the brief never needed one.

World Monitor sits behind the members gate (docker/tss-gate.mjs), so this
signs in the same way a member does: mint an ss-gate token with
MAP_SSO_SECRET, exchange it at /gate/callback for the session cookie, then
mint the data-API token the dashboard uses. No special back door, which means
the gate cannot quietly rot here without the brief noticing.

Every address this sends to comes from BRIEF_RECIPIENTS. Nothing is baked in.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone

import httpx
from anthropic import Anthropic

# ---- Config (env) ---------------------------------------------------------
WM_BASE_URL = os.environ.get("WM_BASE_URL", "https://map.thesurvivalsummit.com").rstrip("/")
MAP_SSO_SECRET = os.environ.get("MAP_SSO_SECRET", "").strip()
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6").strip()
INTERVAL_HOURS = float(os.environ.get("INTERVAL_HOURS", "6"))
# Railway runs this as a cron (every 6h), so one cycle then exit is the
# default. RUN_ONCE=0 restores the legacy sleep-in-process loop for local work.
RUN_ONCE = os.environ.get("RUN_ONCE", "1").strip().lower() in ("1", "true", "yes")
BRIEF_FROM = os.environ.get("BRIEF_FROM", "").strip()
# No default recipients on purpose: a wrong address baked into source is how a
# brief quietly goes to the wrong person for months.
RECIPIENTS = [e.strip() for e in os.environ.get("BRIEF_RECIPIENTS", "").split(",") if e.strip()]
# The identity the gate sees. Not a mailbox, just a label in the audit trail.
SERVICE_IDENTITY = os.environ.get("BRIEF_SERVICE_IDENTITY", "intel-brief@service.local").strip()

# Vessel snapshots are capped at 10 degrees per side by the API, so the
# maritime picture is sampled at the waterways that matter rather than swept
# globally. sw_lat, sw_lon, ne_lat, ne_lon.
CHOKEPOINTS = {
    "Bab el-Mandeb / southern Red Sea": (11.0, 41.5, 16.0, 44.5),
    "Strait of Hormuz": (24.5, 54.0, 27.5, 57.5),
    "Suez / Gulf of Suez": (27.0, 32.0, 31.5, 34.5),
    "Taiwan Strait": (22.0, 117.0, 26.5, 122.0),
    "Black Sea / Odesa approaches": (43.0, 29.0, 47.0, 34.0),
    "Strait of Malacca": (1.0, 99.0, 6.0, 104.0),
}

SYSTEM_PROMPT = """You are the intelligence analyst for "The Survival Summit", an \
OSINT situational-awareness platform. You write a concise, prioritized situation \
brief from the structured digest provided to you.

The digest combines World Monitor platform data (military air activity, vessel \
traffic at named chokepoints, chokepoint transit status, UKMTO maritime incident \
reports, navigational warnings, armed-conflict events, a multi-category news \
digest, and security advisories) with keyless external feeds: CISA \
Known-Exploited-Vulnerabilities, ransomware victim postings, and GDACS global \
disaster alerts.

Hard rules, no exceptions:
- Use ONLY the data provided in the user message. Never invent events, places, \
numbers, or actors. If the data is thin, say so plainly.
- Every priority item must cite its source(s) by name (e.g. "sources: \
military_air + chokepoint_status", "source: CISA KEV", "source: UKMTO").
- State a confidence level (High / Medium / Low) per item, based on how many \
independent sources corroborate it. One source = Low.
- Treat vessel-count changes and single-source anomalies as HYPOTHESES, never \
confirmed fact. A quiet chokepoint is more often a coverage gap or routine \
traffic than a deliberate signal. Label these explicitly as leads.
- Cyber items: a CISA KEV entry or ransomware posting is a real disclosure, but \
do not assert attribution or impact beyond what the data states.
- The digest carries a data_health section listing feeds that are empty or \
stale. Say what those gaps obscure. An empty conflict feed means we are not \
seeing conflict data, NOT that there is no conflict.
- Rank by severity. If little is happening, say so and keep it short. Never \
manufacture urgency.

Output a single self-contained HTML fragment (no <html>/<body> wrapper, no \
markdown fences). Structure:
- <h2> headline: the single most important takeaway
- <p><strong>Bottom line:</strong> ...</p> two or three sentences
- <h3>Priority items</h3> an <ol>; each <li>: what, location, confidence, source(s)
- <h3>Maritime watch</h3> short <ul> from chokepoints, UKMTO and navigational \
warnings, leads marked as hypotheses
- <h3>Air activity</h3> short <ul> from military air movements, if notable
- <h3>Conflict &amp; security</h3> short <ul> from conflict events and advisories
- <h3>Cyber</h3> short <ul> from CISA KEV and ransomware postings, if any
- <h3>Disasters</h3> short <ul> from GDACS, if any
- <h3>Data health</h3> short <ul> of empty or stale feeds and what they obscure
Omit any section with nothing to report. Keep it scannable and tight. Plain, \
factual tone. No emojis, and no em dashes."""


# ---- Carried over unchanged from the ShadowBroker intel-agent. These never
# depended on a backend, so there was nothing to rewrite.
# ---------------------------------------------------------------------------


def _client() -> httpx.Client:
    """Short-lived client for the Resend send. send_email expects this name."""
    return httpx.Client(timeout=30.0)

def _ext_get(url: str, params=None, headers=None, timeout: float = 25.0):
    """GET an external JSON feed. Never raises; returns parsed JSON or error dict."""
    h = {"User-Agent": "survival-summit-intel-brief/2.0"}
    if headers:
        h.update(headers)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as c:
            r = c.get(url, params=params, headers=h)
            r.raise_for_status()
            return r.json()
    except Exception as e:  # noqa: BLE001
        print(f"[warn] ext fetch {url} failed: {e}", flush=True)
        return {"_error": str(e)}


def gather_cyber() -> dict:
    """CISA Known-Exploited-Vulns (recent) + ransomware.live recent victims."""
    from datetime import timedelta

    out: dict = {}
    kev = _ext_get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=30.0,
    )
    if isinstance(kev, dict) and "vulnerabilities" in kev:
        cutoff = (datetime.now(timezone.utc).date() - timedelta(days=14)).isoformat()
        recent = [
            {
                "cve": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "dateAdded": v.get("dateAdded"),
                "ransomwareUse": v.get("knownRansomwareCampaignUse"),
            }
            for v in kev.get("vulnerabilities", [])
            if str(v.get("dateAdded", "")) >= cutoff
        ][:25]
        out["cisa_kev_recent"] = {"count": len(recent), "items": recent}
    else:
        out["cisa_kev_recent"] = {"_error": "unavailable"}

    rl = _ext_get("https://api.ransomware.live/v1/recentvictims", timeout=25.0)
    if isinstance(rl, list):
        out["ransomware_recent"] = [
            {
                "victim": x.get("post_title") or x.get("victim"),
                "group": x.get("group_name") or x.get("group"),
                "country": x.get("country"),
                "discovered": x.get("discovered") or x.get("published"),
            }
            for x in rl[:25]
        ]
    else:
        out["ransomware_recent"] = {"_error": "unavailable"}
    return out


def gather_disaster() -> dict:
    """GDACS active global disaster events. Keyless. (ReliefWeb dropped:
    its v1 API is decommissioned and v2 requires a pre-approved appname.)"""
    g = _ext_get(
        "https://www.gdacs.org/gdacsapi/api/events/geteventlist/EVENTS4APP",
        timeout=25.0,
    )
    feats = g.get("features", []) if isinstance(g, dict) else []
    def _coords(f):
        try:
            c = (f.get("geometry") or {}).get("coordinates") or []
            return float(c[1]), float(c[0])  # GeoJSON is [lon, lat]
        except Exception:  # noqa: BLE001
            return None, None

    events = []
    for f in feats[:25]:
        if not isinstance(f, dict):
            continue
        p = f.get("properties", {}) or {}
        lat, lng = _coords(f)
        events.append(
            {
                "type": p.get("eventtype"),
                "alert": p.get("alertlevel"),
                "name": p.get("name") or p.get("htmldescription"),
                "country": p.get("country"),
                "from": p.get("fromdate"),
                "lat": lat,
                "lng": lng,
            }
        )
    return {"gdacs": events} if events else {"_error": "GDACS unavailable"}


def send_email(subject: str, body_html: str) -> None:
    if not RESEND_API_KEY:
        print("[error] RESEND_API_KEY not set; cannot send. Brief follows:\n", flush=True)
        print(body_html, flush=True)
        return
    wrapped = (
        '<div style="font-family:ui-sans-serif,system-ui,Segoe UI,Arial,sans-serif;'
        'max-width:680px;margin:0 auto;color:#111;line-height:1.5">'
        '<div style="border-left:4px solid #39ff14;padding:6px 14px;margin-bottom:18px">'
        '<strong style="letter-spacing:.15em">SURVIVAL <span style="color:#1f9d1f">'
        "SUMMIT</span></strong>"
        '<div style="font-size:11px;color:#666;letter-spacing:.2em">GLOBAL THREAT '
        "INTERCEPT</div></div>"
        f"{body_html}"
        '<hr style="margin-top:24px;border:none;border-top:1px solid #ddd">'
        '<div style="font-size:11px;color:#888">Automated brief. Generated from '
        "Survival Summit telemetry. Treat correlations as leads, not verdicts.</div></div>"
    )
    with _client() as client:
        r = client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": BRIEF_FROM,
                "to": RECIPIENTS,
                "subject": subject,
                "html": wrapped,
            },
        )
        if r.status_code >= 300:
            print(f"[error] resend send failed {r.status_code}: {r.text}", flush=True)
        else:
            print(f"[ok] brief emailed to {', '.join(RECIPIENTS)}", flush=True)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class WorldMonitor:
    """A signed-in World Monitor reader. Never raises on a failed endpoint."""

    def __init__(self, base_url: str, secret: str):
        self.base = base_url
        self.secret = secret
        self.client = httpx.Client(
            timeout=45.0,
            follow_redirects=False,
            headers={"User-Agent": "survival-summit-intel-brief/2.0"},
        )
        self.cookie = ""
        self.data_key = ""

    def sign_in(self) -> bool:
        """Mint a members token, trade it for the gate cookie and data key."""
        if not self.secret:
            print("[fatal] MAP_SSO_SECRET not set; cannot read World Monitor", flush=True)
            return False
        now = int(time.time())
        claims = {
            "iss": "ss-gate",
            "sub": 1,
            "email": SERVICE_IDENTITY,
            "name": "Intel Brief",
            "member": True,
            "plan": "Service",
            "iat": now,
            "exp": now + 300,
            "jti": f"intel-brief-{now}",
        }
        payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
        sig = _b64url(hmac.new(self.secret.encode(), payload.encode(), hashlib.sha256).digest())
        try:
            r = self.client.get(
                f"{self.base}/gate/callback",
                params={"token": f"{payload}.{sig}", "state": "/"},
            )
        except Exception as e:  # noqa: BLE001
            print(f"[fatal] gate callback failed: {e}", flush=True)
            return False
        raw = r.headers.get("set-cookie", "")
        if "tss_gate=" not in raw:
            # A redirect with no cookie means the gate refused the token, which
            # is almost always MAP_SSO_SECRET drifting from the site's value.
            print(
                f"[fatal] gate refused the service token ({r.status_code}); "
                "check MAP_SSO_SECRET matches the site",
                flush=True,
            )
            return False
        self.cookie = raw.split(";")[0].strip()
        try:
            s = self.client.post(
                f"{self.base}/api/wm-session",
                headers={"cookie": self.cookie, "content-type": "application/json"},
                json={},
            )
            self.data_key = (s.json() or {}).get("token", "")
        except Exception as e:  # noqa: BLE001
            print(f"[warn] wm-session mint failed: {e}", flush=True)
        if not self.data_key:
            print("[warn] no data-API token; gated endpoints will be thin", flush=True)
        print(f"[ok] signed in to {self.base}", flush=True)
        return True

    def get(self, path: str, params=None) -> dict:
        headers = {"cookie": self.cookie}
        if self.data_key:
            headers["X-WorldMonitor-Key"] = self.data_key
        try:
            r = self.client.get(f"{self.base}{path}", params=params, headers=headers)
            if r.status_code >= 300:
                return {"_error": f"HTTP {r.status_code}", "_path": path}
            return r.json()
        except Exception as e:  # noqa: BLE001
            print(f"[warn] fetch {path} failed: {e}", flush=True)
            return {"_error": str(e), "_path": path}


def _is_err(v) -> bool:
    return isinstance(v, dict) and "_error" in v


def gather_world_monitor(wm: WorldMonitor) -> tuple:
    """The platform half of the digest, plus a list of what came back empty.

    Everything here is reduced hard before it reaches Claude. The raw feeds run
    to hundreds of records each (733 feed statuses, 399 navigational warnings),
    and the whole digest has to fit one prompt.
    """
    gaps = []
    out = {}

    def note(label: str, why: str):
        gaps.append({"feed": label, "status": why})

    # Platform health first: it explains every gap below it.
    health = wm.get("/api/health", {"compact": 1})
    if _is_err(health):
        out["platform_health"] = health
        note("platform health", "health endpoint unavailable")
    else:
        out["platform_health"] = {
            "status": health.get("status"),
            "dataStatus": health.get("dataStatus"),
            "checkedAt": health.get("checkedAt"),
            "summary": health.get("summary"),
        }

    air = wm.get(
        "/api/military/v1/list-military-flights",
        {"sw_lat": -60, "sw_lon": -180, "ne_lat": 75, "ne_lon": 180},
    )
    flights = air.get("flights", []) if isinstance(air, dict) else []
    if flights:
        by_country = {}
        for f in flights:
            key = f.get("originCountry") or f.get("country") or "unknown"
            by_country[key] = by_country.get(key, 0) + 1
        out["military_air"] = {
            "tracked": len(flights),
            "by_origin": dict(sorted(by_country.items(), key=lambda kv: -kv[1])[:12]),
            "sample": [
                {
                    "callsign": (f.get("callsign") or "").strip(),
                    "type": f.get("aircraftType") or f.get("type"),
                    "origin": f.get("originCountry") or f.get("country"),
                    "lat": f.get("latitude") or f.get("lat"),
                    "lon": f.get("longitude") or f.get("lon"),
                }
                for f in flights[:20]
            ],
        }
    else:
        note("military air", "no aircraft returned")

    # Maritime: sampled per chokepoint, because the API caps a bbox at 10 deg.
    maritime = {}
    for name, (sw_lat, sw_lon, ne_lat, ne_lon) in CHOKEPOINTS.items():
        snap = wm.get(
            "/api/maritime/v1/get-vessel-snapshot",
            {"sw_lat": sw_lat, "sw_lon": sw_lon, "ne_lat": ne_lat, "ne_lon": ne_lon},
        )
        s = snap.get("snapshot", {}) if isinstance(snap, dict) else {}
        status = s.get("status", {}) if isinstance(s, dict) else {}
        maritime[name] = {
            "vessels_tracked_globally": status.get("vessels"),
            "candidate_reports": len(s.get("candidateReports", []) or []),
            "disruptions": (s.get("disruptions") or [])[:5],
        }
    out["chokepoint_vessels"] = maritime

    cp = wm.get("/api/supply-chain/v1/get-chokepoint-status", {"public": 1})
    points = cp.get("chokepoints", []) if isinstance(cp, dict) else []
    if points:
        out["chokepoint_status"] = [
            {
                "name": p.get("name"),
                "status": p.get("status") or p.get("riskLevel"),
                "transits": p.get("transits") or p.get("transitCount"),
                "note": p.get("note") or p.get("summary"),
            }
            for p in points
        ][:15]
    else:
        note("chokepoint status", "no chokepoints returned")

    ukmto = wm.get("/api/maritime/v1/list-ukmto-incidents")
    incidents = ukmto.get("incidents", []) if isinstance(ukmto, dict) else []
    if incidents:
        out["ukmto_incidents"] = {
            "count": len(incidents),
            "stale": ukmto.get("stale"),
            "recent": incidents[:15],
        }
    else:
        note("UKMTO incidents", "none returned")

    nav = wm.get("/api/maritime/v1/list-navigational-warnings")
    warnings = nav.get("warnings", []) if isinstance(nav, dict) else []
    if warnings:
        out["navigational_warnings"] = {
            "count": len(warnings),
            "recent": [
                {k: w.get(k) for k in ("id", "area", "text", "issued", "lat", "lon") if k in w}
                for w in warnings[:15]
            ],
        }
    else:
        note("navigational warnings", "none returned")

    conflict = {}
    for label, path in (
        ("acled", "/api/conflict/v1/list-acled-events"),
        ("ucdp", "/api/conflict/v1/list-ucdp-events"),
    ):
        res = wm.get(path)
        events = res.get("events", []) if isinstance(res, dict) else []
        conflict[label] = {"count": len(events), "events": events[:20]}
        if not events:
            note(f"{label} conflict events", "feed returned zero events")
    out["conflict"] = conflict

    news = wm.get("/api/news/v1/list-feed-digest", {"variant": "full", "lang": "en", "public": 1})
    cats = news.get("categories", {}) if isinstance(news, dict) else {}
    if cats:
        # Headlines only. The full digest carries 700+ feed statuses.
        trimmed = {}
        items = cats.items() if isinstance(cats, dict) else enumerate(cats)
        for name, body in items:
            entries = body.get("items", []) if isinstance(body, dict) else body
            if not isinstance(entries, list):
                continue
            trimmed[str(name)] = [
                {"title": e.get("title"), "source": e.get("source"), "at": e.get("publishedAt")}
                for e in entries[:6]
                if isinstance(e, dict)
            ]
        out["news"] = trimmed
    else:
        note("news digest", "no categories returned")

    adv = wm.get("/api/intelligence/v1/list-security-advisories", {"public": 1})
    advisories = adv.get("advisories", []) if isinstance(adv, dict) else []
    if advisories:
        out["security_advisories"] = {
            "count": len(advisories),
            "sample": [
                {k: a.get(k) for k in ("country", "level", "title", "updated") if k in a}
                for a in advisories[:20]
            ],
        }
    else:
        note("security advisories", "none returned")

    return out, gaps


def gather(wm: WorldMonitor) -> dict:
    platform, gaps = gather_world_monitor(wm)
    digest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_platform": WM_BASE_URL,
    }
    digest.update(platform)
    digest["cyber_threats"] = gather_cyber()
    digest["disasters"] = gather_disaster()
    digest["data_health"] = gaps
    return digest


def call_claude(digest: dict) -> str:
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    user_payload = (
        "Here is the current World Monitor digest as JSON. Produce the brief "
        "per your instructions.\n\n```json\n"
        + json.dumps(digest, ensure_ascii=False, default=str)[:120000]
        + "\n```"
    )
    resp = client.messages.create(
        model=MODEL,
        max_tokens=2500,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_payload}],
    )
    return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()


def run_once() -> None:
    wm = WorldMonitor(WM_BASE_URL, MAP_SSO_SECRET)
    if not wm.sign_in():
        return
    digest = gather(wm)
    empty = len(digest.get("data_health", []))
    print(f"[digest] built, {empty} feed(s) empty or stale", flush=True)
    body = call_claude(digest)
    if not body:
        print("[error] Claude returned an empty brief; not sending", flush=True)
        return
    stamp = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    send_email(f"Global Threat Intercept: {stamp}", body)


def main() -> int:
    missing = [
        n
        for n, v in (
            ("ANTHROPIC_API_KEY", ANTHROPIC_API_KEY),
            ("MAP_SSO_SECRET", MAP_SSO_SECRET),
            ("BRIEF_RECIPIENTS", ",".join(RECIPIENTS)),
        )
        if not v
    ]
    if missing:
        print(f"[fatal] missing required env: {', '.join(missing)}", flush=True)
        return 1
    print(
        f"[boot] intel brief. source={WM_BASE_URL} model={MODEL} "
        f"every {INTERVAL_HOURS}h to {len(RECIPIENTS)} recipient(s)",
        flush=True,
    )
    while True:
        try:
            run_once()
        except Exception as e:  # noqa: BLE001
            print(f"[error] cycle crashed: {e}", flush=True)
            traceback.print_exc()
        if RUN_ONCE:
            return 0
        time.sleep(max(300.0, INTERVAL_HOURS * 3600.0))


if __name__ == "__main__":
    sys.exit(main())
