# services/crawler/crawler_db.py
import sys
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import json
import os

from api.db import SessionLocal, engine
from api.models import Base, Org, Query, CrawledPage, Threat

from services.preprocessor.detectors import detect_indicators, score_indicator

# NOTE: do NOT call Base.metadata.create_all here (Alembic manages schema)

def clean_text(html: str) -> str:
    """
    Clean HTML into normalized plain text suitable for detection.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Remove noisy sections
    for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
        tag.decompose()

    text = soup.get_text(separator=" ")
    text = " ".join(text.split())  # normalize whitespace
    return text.lower()


def fetch_html_using_session(url: str, session: requests.Session = None, timeout: int = 20):
    """Fetch using provided session (which may be Tor); returns (status_code, text)."""
    sess = session or requests
    r = sess.get(url, timeout=timeout)
    r.raise_for_status()
    return r.status_code, r.text


def save_page_to_db(org_name: str, url: str, query_text: str = None,
                    fetched_html: str = None, status_code: int = None,
                    session: requests.Session = None):
    """
    Save crawled page to DB.
    - If fetched_html is provided, will use that (no network fetch).
    - Otherwise will fetch using provided session (or requests).
    """
    db = SessionLocal()
    try:
        # find or create org
        org = db.query(Org).filter(Org.name == org_name).first()
        if not org:
            org = Org(name=org_name)
            db.add(org)
            db.commit()
            db.refresh(org)
            print("Created org:", org.id, org.name)

        # Optionally create a query row (for grouping crawls)
        q = None
        if query_text:
            q = Query(org_id=org.id, q_text=query_text, status="created")
            db.add(q)
            db.commit()
            db.refresh(q)
            print("Created query:", q.id, q.q_text)

        # Fetch only if content not passed in
        if fetched_html is None:
            status_code, html = fetch_html_using_session(url, session=session, timeout=20)
        else:
            html = fetched_html

        # preprocess minimally: prettify and snippet
        soup = BeautifulSoup(html, "html.parser")
        pretty = soup.prettify()
        cleaned_text = clean_text(html)
        snippet = cleaned_text[:500]


        # insert crawled page
        cp = CrawledPage(
            org_id=org.id,
            query_id=q.id if q else None,
            url=url,
            status_code=status_code,
            content=pretty,
            content_snippet=snippet,
            fetched_at=datetime.utcnow()
        )
        db.add(cp)
        db.commit()
        db.refresh(cp)
        print("Saved CrawledPage id=", cp.id, "org_id=", cp.org_id)

        # Run detectors on text
        indicators = detect_indicators(cleaned_text)

        if indicators:
            print("Detections found:", {k: len(v) for k, v in indicators.items()})

            for itype, items in indicators.items():
                sev = score_indicator(itype,item)

                for item in items:
                    # Extract context around match
                    context_index = cleaned_text.find(item.lower())
                    if context_index != -1:
                        start = max(0, context_index - 60)
                        end = min(len(text), context_index + len(item) + 60)
                        evidence_text = text[start:end]
                    else:
                        evidence_text = snippet  # fallback

                    t = Threat(
                        org_id=org.id,
                        crawled_page_id=cp.id,
                        indicator_type=itype,
                        indicator=str(item)[:2000],
                        severity=sev,
                        evidence=evidence_text[:2000],
                        created_at=datetime.utcnow()
                    )
                    db.add(t)

            db.commit()
            print("Inserted threats for crawled_page_id=", cp.id)

        else:
            print("No indicators found for crawled_page_id=", cp.id)

    except Exception as e:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    # usage: python -m services.crawler.crawler_db <org_name> <url> [<query_text>]
    if len(sys.argv) < 3:
        print("Usage: python -m services.crawler.crawler_db <org_name> <url> [<query_text>]")
        sys.exit(1)
    org_name = sys.argv[1]
    url = sys.argv[2]
    query_text = sys.argv[3] if len(sys.argv) > 3 else None
    save_page_to_db(org_name, url, query_text)
