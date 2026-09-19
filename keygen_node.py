#!/usr/bin/env python3
"""
AllAnime crypto key extraction using Playwright to capture the actual AES key
Adapted from extract_keygen.py (keygen_working.json verified)

Run:
  python keygen_node.py                 # extract + verify against the live API
  python keygen_node.py --write-env     # ...and patch toonplex/.env in place (backs it up)
  python keygen_node.py --no-verify     # skip the live source check
  python keygen_node.py --headed        # show browser for Cloudflare challenge
  python keygen_node.py --verify-env    # verify configured values without opening MKissa

Exit code 0 means the extracted key was PROVEN to resolve real sources, so it is safe to
deploy. Any non-zero means do not ship it.
"""

import re
import os
import sys
import time
import base64
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List

# Force UTF-8 on stdout/stderr BEFORE anything prints.
for _stream in ("stdout", "stderr"):
    try:
        getattr(sys, _stream).reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    from Crypto.Cipher import AES
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install requests playwright pycryptodome && playwright install chromium")
    sys.exit(1)

MKISSA_URL = "https://mkissa.to/"
MKISSA_API_URL = "https://api.mkissa.net"
CDN_IMMUTABLE = "https://cdn.mkissa.net/all/mk/_app/immutable"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

STATIC_KEY_SEED = "Xot36i3lK3:v1"

# Current MKissa episode routes
TARGET_URL = "https://mkissa.to/anime/ReooPAxPMsHM4KPMY/p-1-sub"
TARGET_URL2 = "https://mkissa.to/anime/ReooPAxPMsHM4KPMY/p-1178-sub"
TARGET_URL3 = "https://mkissa.to/anime/ReooPAxPMsHM4KPMY/episodes/sub/1"  # Stealth fallback


# Hook injected before any page JS runs — catches the AES key as the browser derives it
CRYPTO_HOOK = """
window.__capturedKeys   = [];
window.__sourceCapture  = null;
window.__bootCapture    = null;

// Intercept WebCrypto importKey — the 32-byte derived AES key passes through here
const _origImportKey = crypto.subtle.importKey.bind(crypto.subtle);
crypto.subtle.importKey = async function(...args) {
    const result = await _origImportKey(...args);
    const [format, keyData] = args;
    if (format === 'raw') {
        let arr = null;
        if (keyData instanceof Uint8Array)  arr = Array.from(keyData);
        if (keyData instanceof ArrayBuffer) arr = Array.from(new Uint8Array(keyData));
        if (arr && arr.length === 32) {
            window.__capturedKeys.push(arr);
        }
    }
    return result;
};

// Intercept fetch — catch the episode source API call
const _origFetch = window.fetch;
window.fetch = async function(...args) {
    const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
    if (url.includes('api.mkissa.net')) {
        try {
            const u    = new URL(url);
            const ext  = JSON.parse(u.searchParams.get('extensions') || '{}');
            const qh   = (ext.persistedQuery || {}).sha256Hash || '';
            const lane = ext.k || '';
            const ar   = ext.aaReq || '';
            const vars = JSON.parse(u.searchParams.get('variables') || '{}');
            if (vars.episodeString !== undefined || ar) {
                window.__sourceCapture = { query_hash: qh, lane: lane || 'k7', has_aaReq: !!ar, variables: vars };
            }
        } catch(_) {}
    }
    return _origFetch(...args);
};
"""

captured = {
    "build_id":   None,
    "boot":       None,
    "query_hash": None,
    "lane":       None,
    "api_body":   None,
}


def stable_title(page, attempts=12):
    """Return a title after Cloudflare's redirect/navigation has settled."""
    for _ in range(attempts):
        try:
            return page.title()
        except PlaywrightError as exc:
            # Cloudflare commonly replaces the main frame while this call is in flight.
            if "Execution context was destroyed" not in str(exc):
                raise
            page.wait_for_timeout(500)
    return ""


def on_request(req):
    if "/client-crypto/v1/bootstrap" in req.url:
        bid = req.headers.get("x-build-id", "")
        captured["build_id"] = bid
        print(f"  [BOOT-REQ]  build_id={bid}")


def on_response(resp):
    if "/client-crypto/v1/bootstrap" in resp.url and resp.status == 200:
        try:
            body = resp.json()
            captured["boot"] = body
            print(f"  [BOOT-RESP] epoch={body.get('epoch')} partB={body.get('partB','')[:20]}...")
        except: pass
    if "api.mkissa.net/api" in resp.url and resp.status == 200:
        try:
            body = resp.json()
            ep   = body.get("data", {}).get("episode", {})
            if ep.get("tobeparsed") or ep.get("sourceUrls"):
                captured["api_body"] = body
                has = "tobeparsed" if ep.get("tobeparsed") else "sourceUrls"
                print(f"  [API-RESP]  has {has} ✓")
        except: pass


def capture_key_with_playwright(headless=False):
    """Capture the actual AES key using Playwright (more reliable than Node.js extraction)"""
    # Reset captured state
    for k in captured:
        captured[k] = None

    print("Launching Chrome with temporary profile...")

    # Create a temporary profile directory
    temp_profile = Path(tempfile.mkdtemp(prefix="chrome_keygen_"))
    
    # Try to use Chrome user data if available (for better Cloudflare bypass)
    chrome_user_data = None
    if sys.platform == "win32":
        # Windows path
        win_path = Path(r"C:\Users\adity\AppData\Local\Google\Chrome\User Data")
        if win_path.exists():
            chrome_user_data = win_path
    else:
        # Linux/macOS - check common locations
        linux_paths = [
            Path.home() / ".config" / "google-chrome",
            Path.home() / ".config" / "chromium",
            Path.home() / "Library" / "Application Support" / "Google" / "Chrome",  # macOS
        ]
        for path in linux_paths:
            if path.exists():
                chrome_user_data = path
                break

    if chrome_user_data:
        print(f"  Using Chrome profile from: {chrome_user_data}")
        # Copy only essential files (cookies, preferences) - not the whole profile
        print("  Copying Chrome cookies and preferences...")
        try:
            default_src = chrome_user_data / "Default"
            temp_dst = temp_profile / "Default"
            temp_dst.mkdir(parents=True, exist_ok=True)

            # Copy cookies and preferences
            for file in ["Cookies", "Preferences", "Network\\Cookies"]:
                src_file = default_src / file
                if src_file.exists():
                    dst_file = temp_dst / file
                    dst_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_file, dst_file)
                    print(f"    ✓ Copied {file}")
        except Exception as e:
            print(f"  ⚠ Could not copy profile: {e}")
            print("  Continuing with fresh profile...")
    else:
        print("  No Chrome profile found, using fresh profile")

    with sync_playwright() as p:
        # Use Chrome channel with the temp profile
        context = p.chromium.launch_persistent_context(
            str(temp_profile),
            headless=headless,
            channel="chrome",
            args=[
                "--disable-blink-features=AutomationControlled",
            ],
            ignore_default_args=["--enable-automation"],
            viewport={"width": 1280, "height": 800},
        )

        # Patch navigator.webdriver = false before any page JS
        context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            window.chrome = { runtime: {} };
        """)
        context.add_init_script(CRYPTO_HOOK)

        page = context.pages[0] if context.pages else context.new_page()
        page.on("request",  on_request)
        page.on("response", on_response)

        # Try the episode page first
        for url in [TARGET_URL, TARGET_URL2, TARGET_URL3]:
            print(f"\nNavigating to {url}...")
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=45000)
            except Exception as e:
                print(f"  goto failed: {e}")
                continue

            # Check if CF blocked us
            page.wait_for_timeout(2000)
            title = stable_title(page)
            print(f"  Page title: {title}")
            if "just a moment" in title.lower() or "cloudflare" in title.lower():
                wait_seconds = 120 if not headless else 8
                if headless:
                    print("  Cloudflare challenge — trying stealth wait...")
                else:
                    print("  Cloudflare challenge — complete it in the open browser (waiting up to 120s)...")
                for _ in range(wait_seconds):
                    page.wait_for_timeout(1000)
                    title = stable_title(page, attempts=3)
                    if title and "just a moment" not in title.lower() and "cloudflare" not in title.lower():
                        break
                if not title or "just a moment" in title.lower() or "cloudflare" in title.lower():
                    print("  Still blocked. Trying next URL...")
                    continue

            # Wait for crypto operations
            print("  Waiting for bootstrap + source request...")
            for i in range(25):
                page.wait_for_timeout(1000)
                keys = page.evaluate("() => window.__capturedKeys.length")
                src  = page.evaluate("() => window.__sourceCapture")
                if keys > 0 and src and captured["boot"]:
                    print(f"  All captured after {i+1}s ✓")
                    break
                if i % 5 == 4:
                    print(f"  {i+1}s — keys={keys} src={'yes' if src else 'no'} boot={'yes' if captured['boot'] else 'no'}")
            break  # got past CF, stop trying URLs

        # Read from JS context
        keys_js    = page.evaluate("() => window.__capturedKeys || []")
        src_js     = page.evaluate("() => window.__sourceCapture")
        context.close()  # Close the persistent context

    # Cleanup temp profile
    try:
        shutil.rmtree(temp_profile, ignore_errors=True)
    except:
        pass

    # ── Assemble results ──────────────────────────────────────────────────
    print("\n--- Captured ---")
    print(f"build_id   : {captured['build_id']}")
    print(f"boot       : {captured['boot']}")
    print(f"keys       : {len(keys_js)} AES key(s)")
    print(f"source     : {src_js}")
    print(f"api_body   : {'yes' if captured['api_body'] else 'no'}")

    # If Playwright failed to get boot, try direct API request with hardcoded values (from user's curl)
    if not captured["boot"]:
        if False:
            pass
            print("\nERROR: Bootstrap not captured — likely Cloudflare blocked the page.")
            print("Try running with --headed for a visible browser.")
            # Return 6 values so unpacking always works; caller will check build_id
            return None, None, None, None, None, None

    epoch  = captured["boot"]["epoch"]
    partB  = base64.b64decode(captured["boot"]["partB"] + "==")
    build  = captured["build_id"] or "92"
    lane   = (src_js or {}).get("lane", "k7") or "k7"
    qh     = (src_js or {}).get("query_hash", "")

    # Derived key — last 32-byte key imported is the one used for aaReq/tobeparsed
    derived_key = None
    for k in reversed(keys_js):
        if len(k) == 32:
            derived_key = bytes(k)
            break

    if not derived_key:
        print("\nWARNING: No AES key captured from WebCrypto hook.")
        print("The bootstrap may have been cached from a previous session.")
        print("Try clearing browser storage and re-running.")
        return None, None, None, None, None, None

    # Decrypt tobeparsed if we have it
    sources = []
    working_key = None
    if captured["api_body"] and derived_key:
        ep  = captured["api_body"].get("data", {}).get("episode", {})
        tp  = ep.get("tobeparsed", "")
        if tp:
            raw   = base64.b64decode(tp + "=" * (-len(tp) % 4))
            nonce = raw[1:13]
            ct2   = raw[13:]
            static_k = hashlib.sha256(STATIC_KEY_SEED.encode()).digest()
            for label, k in [("derived", derived_key), ("static", static_k)]:
                try:
                    c = AES.new(k, AES.MODE_GCM, nonce=nonce)
                    pt = c.decrypt_and_verify(ct2[:-16], ct2[-16:])
                    s  = json.loads(pt)
                    sources = s if isinstance(s, list) else \
                              s.get("sourceUrls", s.get("episode", {}).get("sourceUrls", []))
                    print(f"\n✓ tobeparsed decrypted with {label} key!")
                    working_key = k
                    break
                except Exception as e:
                    print(f"  {label}: {e}")

    if not qh and not sources:
        print("\nThe source API request didn't fire — the page didn't auto-load sources.")
        print("The key and build_id are still captured — using known good query hash from live test.")
        # This is the query hash from the user's working curl command
        qh = "670bbf38d0868f446e2346c1e956ca2c40c416e733ca248fd54e04f1c8b99145"
        print(f"Using query hash: {qh}")

    # Compute mask blocks
    mask_blocks_str = ""
    if derived_key:
        mask = bytes(a ^ b for a, b in zip(derived_key, partB[:32]))
        mask_blocks_str = " ".join(base64.b64encode(mask[i:i+8]).decode() for i in range(0, 32, 8))

    key_hex = derived_key.hex() if derived_key else ""

    # Compute epoch (7-day window with 1-day lookback)
    # IMPORTANT: Uv = 604800000 (7 days), NOT 259200000 (3 days)!
    now_ms = int(time.time() * 1000)
    Uv = 604800000  # 7-day window
    c2 = 86400000   # 1-day grace
    epoch = now_ms // Uv
    if now_ms - epoch * Uv < c2 and epoch > 0:
        epoch -= 1
    epoch_alt = epoch + 1 if now_ms - epoch * Uv < c2 else epoch - 1
    print(f"✓ epoch: {epoch} (from now_ms={now_ms})")
    print(f"  (alternate epoch: {epoch_alt})")

    # Use the epoch from bootstrap since it was successful
    epoch = captured["boot"]["epoch"]

    mask_blocks = mask_blocks_str.split() if mask_blocks_str else []

    return build, epoch, lane, key_hex, qh, mask_blocks


def verify_against_live_api(build_id: str, epoch: int, lane: str,
                            key_hex: str, query_hash: str) -> int:
    """
    Prove the extracted key actually works: build the aaReq envelope, query the real API,
    decrypt `tobeparsed`, and count sourceUrls.

    Returns the number of sources found (0 = do not deploy).
    """
    key = bytes.fromhex(key_hex)
    ts = int(time.time() * 1000) // 300000 * 300000
    payload = json.dumps(
        {"v": 1, "ts": ts, "epoch": epoch, "buildId": build_id, "qh": query_hash, "k": lane},
        separators=(",", ":"),
    ).encode()
    iv = hashlib.sha256(f"{epoch}:{query_hash}:{ts}".encode()).digest()[:12]
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(payload)
    aareq = base64.b64encode(b"\x01" + iv + ct + tag).decode()

    # One Piece — a show that always has episodes available.
    variables = json.dumps({"showId": "ReooPAxPMsHM4KPMY",
                            "translationType": "sub", "episodeString": "1161"})
    extensions = json.dumps({"persistedQuery": {"version": 1, "sha256Hash": query_hash},
                             "aaReq": aareq, "k": lane})

    session = requests.Session()
    session.headers.update({
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "origin": "https://mkissa.to",
        "priority": "u=1, i",
        "referer": "https://mkissa.to/",
        "sec-ch-ua": '"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
        "x-build-id": build_id
    })
    r = session.get(
        f"{MKISSA_API_URL}/api",
        params={"variables": variables, "extensions": extensions},
        timeout=25,
    )
    data = r.json()
    if "errors" in data:
        print(f"  ✗ API rejected the key: {data['errors'][0].get('message', '?')}")
        return 0

    tbp = (data.get("data") or {}).get("tobeparsed")
    if not tbp:
        print(f"  ✗ No tobeparsed in response: {str(data)[:200]}")
        return 0

    raw = base64.b64decode(tbp)
    candidates = [("derived", key),
                  ("static-legacy", hashlib.sha256(STATIC_KEY_SEED.encode()).digest())]
    for name, k in candidates:
        try:
            plain = AES.new(k, AES.MODE_GCM, nonce=raw[1:13]).decrypt_and_verify(
                raw[13:-16], raw[-16:])
        except Exception:
            continue
        sources = (json.loads(plain.decode()).get("episode") or {}).get("sourceUrls", [])
        print(f"  ✓ Decrypted with '{name}' — {len(sources)} source(s):")
        for s in sources:
            print(f"      [{s.get('sourceName','?')}] {str(s.get('sourceUrl',''))[:68]}")
        names = {s.get("sourceName") for s in sources}
        if "Yt-mp4" in names:
            print("  ✓ Yt-mp4 (fast4speed) present — the best provider is available")
        else:
            print("  ! Yt-mp4 NOT present (residential-IP gated, or upstream dropped it)")
        return len(sources)

    print("  ✗ Could not decrypt tobeparsed with either key")
    return 0


ENV_KEYS_ORDER = [
    "ALLANIME_KEY", "ALLANIME_AAREQ_EPOCH", "ALLANIME_AAREQ_BUILD_ID",
    "ALLANIME_LANE", "ALLANIME_VIDEO_HASH", "ALLANIME_STATIC_KEY_SEED",
    "ALLANIME_MASK_BLOCKS", "ALLANIME_AAREQ_EPOCH_MS",
]


def read_env_values(env_path: Path) -> dict:
    """Read the small unquoted KEY=value format used by ToonPlex's .env file."""
    values = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def verify_configured_env() -> int:
    """Validate existing local configuration without navigating to a CF-protected page."""
    env_path = Path(__file__).parent / "toonplex" / ".env"
    if not env_path.exists():
        print(f"✗ {env_path} not found")
        return 1
    values = read_env_values(env_path)
    required = ("ALLANIME_KEY", "ALLANIME_AAREQ_EPOCH", "ALLANIME_AAREQ_BUILD_ID",
                "ALLANIME_LANE", "ALLANIME_VIDEO_HASH")
    missing = [key for key in required if not values.get(key)]
    if missing:
        print("✗ Missing required .env values: " + ", ".join(missing))
        return 1
    try:
        epoch = int(values["ALLANIME_AAREQ_EPOCH"])
        source_count = verify_against_live_api(
            values["ALLANIME_AAREQ_BUILD_ID"], epoch, values["ALLANIME_LANE"],
            values["ALLANIME_KEY"], values["ALLANIME_VIDEO_HASH"])
    except Exception as exc:
        print(f"✗ Configured-value verification error: {exc}")
        return 1
    if source_count <= 0:
        print("✗ Configured values did not resolve any live sources — do not deploy them.")
        return 2
    print(f"✓ Configured .env is live and resolved {source_count} source(s).")
    return 0


def write_env(env_path: Path, values: dict) -> None:
    """
    Patch the ALLANIME_* values in place, preserving everything else and the file's own
    ordering/comments. Takes a timestamped backup first.

    Values are written UNQUOTED and mask blocks SPACE-separated, which is what config.php
    reads most naturally. (It now tolerates quotes and JSON too, but this keeps the file
    consistent with how it already looks.)
    """
    if not env_path.exists():
        print(f"  ✗ {env_path} not found — skipping --write-env")
        return

    backup = env_path.with_suffix(env_path.suffix + f".bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(env_path, backup)

    lines = env_path.read_text(encoding="utf-8").splitlines()
    seen = set()
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in values:
                out.append(f"{k}={values[k]}")
                seen.add(k)
                continue
        out.append(line)

    missing = [k for k in ENV_KEYS_ORDER if k in values and k not in seen]
    if missing:
        out.append("")
        out.append(f"# Added by keygen_node.py {time.strftime('%Y-%m-%d %H:%M:%S')}")
        for k in missing:
            out.append(f"{k}={values[k]}")

    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"  ✓ Updated {env_path}")
    print(f"  ✓ Backup  {backup.name}")
    if missing:
        print(f"  + Added missing keys: {', '.join(missing)}")


def main():
    if "--verify-env" in sys.argv:
        print("="*60)
        print("AllAnime configured-value verification (no browser)")
        print("="*60)
        return verify_configured_env()

    write_env_flag = "--write-env" in sys.argv
    do_verify = "--no-verify" not in sys.argv
    headless = "--headed" not in sys.argv

    print("="*60)
    print("AllAnime Crypto Key Extraction (Playwright method)")
    print("Based on extract_keygen.py")
    print("="*60 + "\n")

    try:
        result = capture_key_with_playwright(headless=headless)
        if not result or len(result) != 6:
            print("\n✗ FAILED: Could not capture key (no result)")
            return 1
        build_id, epoch, lane, key_hex, query_hash, mask_blocks = result

        if not build_id or not key_hex:
            print("\n✗ FAILED: Could not capture key")
            return 1

        # ── Prove it works before anyone deploys it ──────────────────────────
        source_count = -1
        if do_verify:
            print("\n" + "="*60)
            print("VERIFYING against the live API...")
            print("="*60)
            try:
                source_count = verify_against_live_api(build_id, epoch, lane, key_hex, query_hash)
            except ImportError:
                print("  ! pycryptodome not installed (pip install pycryptodome) — skipped")
                source_count = -1
            except Exception as e:
                print(f"  ✗ Verification error: {e}")
                source_count = 0
            if source_count == 0:
                print("\n✗ DO NOT DEPLOY — the extracted key did not resolve any sources.")
                return 2

        # ── .env block (unquoted; config.php reads these directly) ───────────
        env_values = {
            "ALLANIME_KEY":             key_hex,
            "ALLANIME_AAREQ_EPOCH":     str(epoch),
            "ALLANIME_AAREQ_BUILD_ID":  str(build_id),
            "ALLANIME_LANE":            lane,
            "ALLANIME_VIDEO_HASH":      query_hash,
            "ALLANIME_STATIC_KEY_SEED": STATIC_KEY_SEED,
            "ALLANIME_MASK_BLOCKS":     " ".join(mask_blocks),
            "ALLANIME_AAREQ_EPOCH_MS":  "604800000",
        }

        if source_count <= 0:
            print("\n✗ DO NOT DEPLOY — the extracted key is UNVERIFIED or did not resolve any sources.")
            return 2
        print("\n" + "="*60)
        print(f"SUCCESS - VERIFIED ({source_count} live sources). Copy to server .env:")
        print("="*60)
        for k in ENV_KEYS_ORDER:
            print(f"{k}={env_values[k]}")
        print("="*60)

        if write_env_flag:
            print("\n--write-env: patching local toonplex/.env")
            write_env(Path(__file__).parent / "toonplex" / ".env", env_values)
            print("\n  NOTE: this updated your LOCAL copy only — upload it to the server.")
            print("  Also update, together, if you keep them pinned:")
            print("    Testttt/.../Activity/AllAnimeClient.java  (FALLBACK_BUILD_ID + MASK_BLOCKS + FALLBACK_VIDEO_HASH)")
            print("    sync_all.py / sync_sources.py             (BUILD_ID + CRYPTO_MASK_BLOCKS + VIDEO_HASH)")
            print("    toonplex/config.php defaults")
        else:
            print("\nTip: re-run with --write-env to patch toonplex/.env automatically.")

        # Also save as JSON
        output = {
            "build_id": build_id,
            "epoch": epoch,
            "lane": lane,
            "key": key_hex,
            "query_hash": query_hash,
            "mask_blocks": mask_blocks,
            "static_key": STATIC_KEY_SEED, # Matches api/index.php expectation
            "_fetched_at": int(time.time()), # Timestamp for caching logic
            "extracted_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }
        output["verified_sources"] = source_count
        with open("keygen.json", "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"\n✓ Saved to keygen.json")

        return 0

    except Exception as e:
        print(f"\n✗ FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
