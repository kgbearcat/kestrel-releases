#!/usr/bin/env python3
"""Release guard for kgbearcat/kestrel-releases (D-869). Runs in GitHub Actions; standard library plus the openssl command.

On `release: published` for an app tag (v1.2.3): if the release breaks a rule below, it turns the release back into a draft and fails
the run, so even a click on GitHub's Publish button cannot leave a release that no install can update to. Any error while checking
also turns it back (fails closed). On the daily schedule it checks the Latest release and fails the run (no re-draft) when it breaks a
rule or its trust file has under 30 days left, so GitHub emails the repo owner.

Rules: update-trust.stable.txt present; signature verifies against a Kestrel update key (current or next, copied from
win/Kestrel.Core/License/LicenseKeys.cs in the app repo; a test there keeps them equal); product, kind, channel stable; version equals
the tag; sha256 equals the full nupkg (GitHub's digest) and releases.win.json; counter higher than every other published release;
at least 60 days to expiry at publish time; Setup.exe, Portable and nupkg not empty; no delta package attached or listed in
releases.win.json (B-196; only the published v1.0.0 keeps its one historic delta, see HISTORIC_DELTAS).

Copied from tools/release/github-guard/release_guard.py in the Kestrel app repo. Edit it there, test it there, copy it here.
"""
import base64, binascii, json, os, re, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone

UPDATE_KEYS_HEX = [
    "b474caf1b6e754b407e459ed7dd9085858216c4bca6ecfb18a8deba3146e9a79",   # UpdateKeys.ProductionPublicKeyHex
    "fddf092aa51e3510fc6d4011421b7a3646360b542efb9b11b8e4ad1d5cb92c18",   # UpdateKeys.NextPublicKeyHex
]
PRODUCT = "shutterbug"
TRUST = "update-trust.stable.txt"
MANIFEST = "releases.win.json"
SETUP = "Kestrel-win-Setup.exe"
PORTABLE = "Kestrel-win-Portable.zip"
MAX_TEXT = 8192
PUBLISH_MIN_DAYS = 60
AUDIT_MIN_DAYS = 30
TAG = re.compile(r"^v([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")   # DER header of an Ed25519 public key

# B-196: no delta package on a stable release (the app refuses a package Velopack rebuilt from a delta, because its bytes never hash to
# the signed full package). The one exception is the v1.0.0 published before the rule, with these exact bytes; 1.0.0 is the base
# release, so no update goes through its own delta. Never add a row. Equal to HISTORIC_DELTAS in tools/release/verify-release.py (tested).
HISTORIC_DELTAS = {
    "1.0.0": {"name": "Kestrel-1.0.0-delta.nupkg", "sha256": "c8938ce34472a70cea9f8de9994bc6361fd18b82612d1facea3c4d2890365c74", "size": 3661688},
}


def asset_sha(asset):
    d = (asset or {}).get("digest") or ""
    return d[7:].lower() if isinstance(d, str) and d.startswith("sha256:") and HEX64.match(d[7:].lower()) else None


def delta_problems(version, assets, entries):
    """Pure. The guard only ever sees published releases, so the historic exception is keyed on the version and exact bytes alone."""
    allowed = HISTORIC_DELTAS.get(version)
    out = []
    files = [a for a in assets if "delta" in a["name"].lower()]
    for a in files:
        if allowed and len(files) == 1 and a["name"] == allowed["name"] and asset_sha(a) == allowed["sha256"] and a.get("size") == allowed["size"]:
            continue
        out.append("a delta package (%s) is attached; a stable release carries its full package only (B-196)" % a["name"])
    listed = [e for e in entries if not isinstance(e, dict) or e.get("Type") != "Full" or "delta" in str(e.get("FileName", "")).lower()]
    for e in listed:
        if (allowed and len(listed) == 1 and e.get("Type") == "Delta" and e.get("Version") == version and e.get("FileName") == allowed["name"]
                and isinstance(e.get("SHA256"), str) and e["SHA256"].lower() == allowed["sha256"] and e.get("Size") == allowed["size"]):
            continue
        out.append("releases.win.json lists a delta package (%s); a stable feed lists full packages only (B-196)"
                   % (e.get("FileName") if isinstance(e, dict) else None))
    return out


def applies(tag):
    return bool(TAG.match(tag or ""))


def b64u_canonical(text):
    if not text or not re.fullmatch(r"[A-Za-z0-9_-]+", text) or len(text) % 4 == 1:
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return raw if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == text else None


def verify_openssl(payload, sig, key):
    with tempfile.TemporaryDirectory() as d:
        paths = {n: os.path.join(d, n) for n in ("m", "s", "k.pem")}
        open(paths["m"], "wb").write(payload)
        open(paths["s"], "wb").write(sig)
        pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(SPKI_PREFIX + key) + b"\n-----END PUBLIC KEY-----\n"
        open(paths["k.pem"], "wb").write(pem)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", paths["k.pem"], "-rawin", "-in", paths["m"], "-sigfile", paths["s"]],
                           capture_output=True, text=True)
        return r.returncode == 0 and "Verified Successfully" in r.stdout


def read_trust(data, keys):
    """Returns (doc, None) or (None, reason)."""
    if not data or len(data) > MAX_TEXT:
        return None, "the trust file is empty or over %d bytes" % MAX_TEXT
    try:
        parts = data.decode("ascii").split(".")
    except UnicodeDecodeError:
        return None, "the trust file is not ASCII"
    if len(parts) != 2:
        return None, "the trust file is not payload.signature"
    payload, sig = b64u_canonical(parts[0]), b64u_canonical(parts[1])
    if not payload or sig is None or len(sig) != 64:
        return None, "the trust file is not canonical base64url with a 64-byte signature"
    if not any(verify_openssl(payload, sig, k) for k in keys):
        return None, "the trust file signature does not verify against a Kestrel update key"
    try:
        doc = json.loads(payload)
    except ValueError:
        return None, "the signed payload is not JSON"
    return (doc, None) if isinstance(doc, dict) else (None, "the signed payload is not an object")


def utc(s):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def evaluate(rel, files, now, keys, others=(), min_days=PUBLISH_MIN_DAYS):
    """Pure. rel is the GitHub release object; files maps asset name to bytes; others is [(tag, trust bytes or None)]."""
    bad = []
    tag = rel.get("tag_name") or ""
    m = TAG.match(tag)
    if not m:
        return ["%r is not an app release tag" % tag]
    version = tag[1:]
    assets = rel.get("assets")
    if not isinstance(assets, list) or not all(isinstance(a, dict) and isinstance(a.get("name"), str) for a in assets):
        return ["the release asset list could not be read"]
    by = {a["name"]: a for a in assets}
    pkg_name = "Kestrel-%s-full.nupkg" % version
    for name in (pkg_name, SETUP, PORTABLE, MANIFEST, TRUST):
        a = by.get(name)
        if a is None:
            bad.append("%s is missing" % name)
        elif not isinstance(a.get("size"), int) or a["size"] <= 0:
            bad.append("%s is empty" % name)
    pkg_sha = asset_sha(by.get(pkg_name))
    if pkg_name in by and pkg_sha is None:
        bad.append("GitHub gives no sha256 digest for %s" % pkg_name)
    entries = []
    if MANIFEST in by:
        try:
            entries = json.loads(files[MANIFEST].decode("utf-8-sig"))["Assets"]
            if not isinstance(entries, list):
                raise TypeError("no Assets list")
            full = [e for e in entries if e.get("Version") == version and e.get("Type") == "Full"]
            if len(full) != 1 or str(full[0].get("SHA256", "")).lower() != pkg_sha or full[0].get("FileName") != pkg_name:
                bad.append("releases.win.json does not list %s with the uploaded package hash" % pkg_name)
        except (KeyError, TypeError, ValueError, AttributeError, UnicodeDecodeError):
            bad.append("releases.win.json could not be read")
            entries = []
    bad.extend(delta_problems(version, assets, entries))
    if TRUST in by:
        doc, why = read_trust(files.get(TRUST), keys)
        if why:
            bad.append(why)
        else:
            for field, want in (("product", PRODUCT), ("kind", "update-trust"), ("channel", "stable"), ("version", version)):
                if doc.get(field) != want:
                    bad.append("the trust file %s is %r, not %r" % (field, doc.get(field), want))
            if doc.get("sha256") != pkg_sha or pkg_sha is None:
                bad.append("the trust file sha256 does not equal %s" % pkg_name)
            exp, iss = utc(doc.get("expiresAt")), utc(doc.get("issuedAt"))
            if exp is None or iss is None or exp <= iss or exp - now < timedelta(days=min_days):
                bad.append("the trust file expires in under %d days (or its dates are bad)" % min_days)
            counter = doc.get("counter")
            prev = 0
            for otag, otrust in others:
                if otrust is None or otag == tag:
                    continue
                odoc, owhy = read_trust(otrust, keys)
                if owhy or not isinstance(odoc.get("counter"), int):
                    bad.append("the trust file of %s cannot be read, so the counter cannot be checked" % otag)
                    continue
                prev = max(prev, odoc["counter"])
            if not isinstance(counter, int) or isinstance(counter, bool) or counter <= prev:
                bad.append("the trust file counter %r is not higher than the last published counter %d" % (counter, prev))
    return bad


# ---------------------------------------------------------------- GitHub (only runs inside the workflow)

def api(method, path, token, body=None, accept="application/vnd.github+json"):
    url = path if path.startswith("https://") else "https://api.github.com/" + path.lstrip("/")
    req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + token, "Accept": accept, "User-Agent": "kestrel-release-guard",
                                          "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "kestrel-release-guard"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def gather(repo, rel_id, token):
    rel = json.loads(api("GET", "repos/%s/releases/%d" % (repo, rel_id), token))
    files = {}
    for a in rel.get("assets") or []:
        if a.get("name") in (TRUST, MANIFEST):
            files[a["name"]] = api("GET", "repos/%s/releases/assets/%d" % (repo, a["id"]), token, accept="application/octet-stream")
    others = []
    for page in range(1, 11):
        batch = json.loads(api("GET", "repos/%s/releases?per_page=100&page=%d" % (repo, page), token))
        for r in batch:
            if r.get("draft") or not applies(r.get("tag_name")) or r.get("id") == rel_id:
                continue
            t = next((a for a in r.get("assets") or [] if a.get("name") == TRUST), None)
            others.append((r["tag_name"], download(t["browser_download_url"]) if t else None))
        if len(batch) < 100:
            break
    return rel, files, others


def main():
    token, repo = os.environ["GITHUB_TOKEN"], os.environ["GITHUB_REPOSITORY"]
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    keys = [bytes.fromhex(k) for k in UPDATE_KEYS_HEX]
    now = datetime.now(timezone.utc)
    if event_name == "release":
        event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
        rel_id, tag = event["release"]["id"], event["release"]["tag_name"]
        if not applies(tag):
            print("%s is not an app release; nothing to check." % tag)
            return 0
        bad = None
        for attempt in range(3):   # a passing release must not be hidden by one flaky API call, so reading is retried first
            try:
                rel, files, others = gather(repo, rel_id, token)
                bad = evaluate(rel, files, now, keys, others)
                break
            except Exception as e:   # fail closed: still unreadable after the retries is a failure
                bad = ["the guard could not read the release: %s" % type(e).__name__]
                time.sleep(15)
        if not bad:
            print("%s passed the release guard." % tag)
            return 0
        for b in bad:
            print("::error::%s: %s" % (tag, b))
        try:
            api("PATCH", "repos/%s/releases/%d" % (repo, rel_id), token, {"draft": True})
            print("::error::%s was turned back into a draft. Publish it with tools/release/publish-windows.sh from the app repo." % tag)
        except Exception as e:
            print("::error::%s could NOT be turned back into a draft (%s). Make it a draft by hand now." % (tag, type(e).__name__))
        return 1
    # schedule or manual run: audit the Latest release, never change it
    latest = json.loads(api("GET", "repos/%s/releases/latest" % repo, token))
    rel, files, others = gather(repo, latest["id"], token)
    bad = evaluate(rel, files, now, keys, others, min_days=AUDIT_MIN_DAYS)
    for b in bad:
        print("::error::Latest %s: %s" % (latest.get("tag_name"), b))
    if not bad:
        print("Latest %s passed the release guard audit." % latest.get("tag_name"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
