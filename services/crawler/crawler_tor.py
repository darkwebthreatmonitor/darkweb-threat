import sys
import os
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional, List

from services.crawler.tor_session import make_tor_session
from services.crawler.tor_control import renew_tor_circuit
from services.crawler.crawler_db import save_page_to_db

PER_HOST_DELAY = 2.0       # polite wait before contacting host
DEFAULT_TIMEOUT = 30
RETRY_ATTEMPTS = 2
RETRY_BACKOFF = 2          # seconds backoff per retry


# ---------------------- URL / SEED HELPERS ----------------------

def load_seeds(seed_path: str) -> List[str]:
    """Load onion URLs from a seed file."""
    with open(seed_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def is_url(text: str) -> bool:
    """Basic check to see if the argument looks like a URL."""
    p = urlparse(text)
    return p.scheme in ("http", "https") and p.netloc != ""


# ---------------------- TOR FETCH LOGIC -------------------------

def fetch_via_tor_once(url: str, rotate_circuit: bool = False, timeout: int = DEFAULT_TIMEOUT, control_port: int = 9051):
    """Perform a single Tor proxied GET request."""
    session = make_tor_session()

    if rotate_circuit:
        try:
            print("Requesting new Tor circuit...")
            renew_tor_circuit(control_port=control_port)
            time.sleep(1.5)
        except Exception as e:
            print("  Tor NEWNYM failed:", e)

    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            print(f"→ Attempt {attempt}: {url}")
            r = session.get(url, timeout=timeout)
            r.raise_for_status()
            return r.status_code, r.text

        except Exception as e:
            print(f" Attempt {attempt} failed:", e)
            if attempt < RETRY_ATTEMPTS:
                sleep_for = RETRY_BACKOFF * attempt
                print(f" Retrying in {sleep_for}s...")
                time.sleep(sleep_for)
            else:
                raise


def fetch_and_save(org_name: str, url: str, query_text: Optional[str] = None, rotate_circuit: bool = False, control_port: int = 9051):
    host = urlparse(url).hostname or "unknown"
    print(f"\n Sleeping {PER_HOST_DELAY}s before contacting: {host}")
    time.sleep(PER_HOST_DELAY)

    try:
        status_code, html = fetch_via_tor_once(
            url,
            rotate_circuit=rotate_circuit,
            timeout=DEFAULT_TIMEOUT,
            control_port=control_port,
        )
    except Exception as e:
        print(f" Fetch failed for {url}: {e}")
        return

    # Save to DB
    try:
        print(f" Saving result for {url}")
        save_page_to_db(
            org_name=org_name,
            url=url,
            query_text=query_text,
            fetched_html=html,
            status_code=status_code,
        )
    except Exception as e:
        print("⚠️  Error saving page to DB:", e)


# ------------------------- MAIN LOGIC ---------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage: python -m services.crawler.crawler_tor <org_name> <url_or_seedfile> [<query_text>] [--rotate]")
        sys.exit(1)

    org_name = sys.argv[1]
    target = sys.argv[2]             # URL or seed file path
    query_text = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else None
    rotate = "--rotate" in sys.argv

    # Determine whether this is a seed file or a single URL
    if os.path.isfile(target):
        print(f" Loading seeds from: {target}")
        urls = load_seeds(target)
        print(f" Loaded {len(urls)} seeds.")
    elif is_url(target):
        urls = [target]
        print(f" Single URL mode: {target}")
    else:
        print(f" ERROR: {target} is neither a file nor a valid URL.")
        sys.exit(1)

    print(f" Starting crawl for org: {org_name}")
    if rotate:
        print(" Tor circuit rotation enabled")

    # Crawl each URL
    for url in urls:
        fetch_and_save(org_name, url, query_text=query_text, rotate_circuit=rotate)


if __name__ == "__main__":
    main()
