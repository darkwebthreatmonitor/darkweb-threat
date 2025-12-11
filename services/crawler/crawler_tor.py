# services/crawler/crawler_tor.py
import sys
import time
from urllib.parse import urlparse
from typing import Optional

from services.crawler.tor_session import make_tor_session
from services.crawler.tor_control import renew_tor_circuit
from services.crawler.crawler_db import save_page_to_db

PER_HOST_DELAY = 2.0  # seconds
DEFAULT_TIMEOUT = 30
RETRY_ATTEMPTS = 2
RETRY_BACKOFF = 2  # seconds

def is_onion(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.hostname is not None and p.hostname.endswith(".onion")
    except Exception:
        return False

def fetch_via_tor_once(url: str, rotate_circuit: bool = False, timeout: int = DEFAULT_TIMEOUT, control_port: int = 9051):
    s = make_tor_session()
    if rotate_circuit:
        try:
            print("Requesting new Tor circuit (NEWNYM)...")
            renew_tor_circuit(control_port=control_port)
            time.sleep(1.5)
        except Exception as e:
            print("Warning: renew_tor_circuit failed:", e)

    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            print(f"Attempt {attempt} fetching via Tor: {url} (timeout={timeout})")
            r = s.get(url, timeout=timeout)
            r.raise_for_status()
            return r.status_code, r.text
        except Exception as e:
            print(f"Fetch attempt {attempt} failed: {e}")
            if attempt < RETRY_ATTEMPTS:
                sleep_for = RETRY_BACKOFF * attempt
                print(f"Sleeping {sleep_for}s before retry")
                time.sleep(sleep_for)
            else:
                raise

def fetch_and_save(org_name: str, url: str, query_text: Optional[str] = None, rotate_circuit: bool = False, control_port: int = 9051):
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    print(f"Sleeping {PER_HOST_DELAY}s for politeness before contacting host {host}")
    time.sleep(PER_HOST_DELAY)

    try:
        status_code, html = fetch_via_tor_once(url, rotate_circuit=rotate_circuit, timeout=DEFAULT_TIMEOUT, control_port=control_port)
    except Exception as e:
        print("Fetch failed via Tor:", e)
        return

    # Save the fetched html directly to DB (no second network call)
    try:
        save_page_to_db(org_name, url, query_text=query_text, fetched_html=html, status_code=status_code)
    except Exception as e:
        print("Error saving page to DB:", e)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m services.crawler.crawler_tor <org_name> <url> [<query_text>] [--rotate]")
        sys.exit(1)
    org_name = sys.argv[1]
    url = sys.argv[2]
    query_text = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith("--") else None
    rotate = "--rotate" in sys.argv
    fetch_and_save(org_name, url, query_text=query_text, rotate_circuit=rotate)
