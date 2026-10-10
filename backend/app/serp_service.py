import os
import serpapi
from dotenv import load_dotenv

# Load backend/.env when the app is started from the backend directory.
# Also resolve relative to this file so launching from another directory works.
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))


def search_security(query: str, engine: str = "google"):
    """Search public web sources for security intelligence."""
    api_key = os.getenv("SERPAPI_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "SERPAPI_KEY is missing. Add it to backend/.env and restart FastAPI."
        )

    client = serpapi.Client(api_key=api_key)
    return client.search({
        "engine": engine,
        "q": query,
        "hl": "en",
        "gl": "in",
    })


def get_security_intelligence(findings, ports):
    """
    Retrieve public research relevant to observed findings/services.
    If a scan produces no eligible finding, use a general defensive
    web-security query so the panel does not misleadingly imply the
    integration was never attempted. Results are context, not proof
    that the scanned host is vulnerable.
    """
    intelligence = []
    queries = []

    for finding in findings:
        evidence = finding.get("evidence", "") or ""
        title = finding.get("title", "") or ""

        if "Server:" in evidence:
            server = evidence.split("Server:", 1)[1].strip()
            if server:
                queries.append(f'"{server}" vulnerability security')
        elif finding.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
            if title:
                queries.append(f'"{title}" cybersecurity vulnerability')

    for port in ports:
        if port.get("state") == "OPEN" and port.get("service") in (
            "MySQL", "PostgreSQL", "SSH", "FTP"
        ):
            queries.append(f'{port["service"]} security vulnerabilities')

    queries = list(dict.fromkeys(queries))

    # If nothing target-specific is searchable, retrieve general defensive
    # context rather than returning an empty array without explanation.
    if not queries:
        queries = ["OWASP web application security misconfiguration best practices"]

    # Keep API usage bounded.
    queries = queries[:5]

    for query in queries:
        try:
            results = search_security(query)
            organic = results.get("organic_results", []) or []
            for result in organic[:3]:
                link = result.get("link")
                title = result.get("title")
                if not link or not title:
                    continue
                intelligence.append({
                    "query": query,
                    "title": title,
                    "link": link,
                    "snippet": result.get("snippet"),
                    "source": result.get("source"),
                    "date": result.get("date"),
                })
        except Exception as exc:
            # Leave the scan itself functional if the optional intelligence
            # provider is unavailable, but make the cause visible in terminal.
            print(f"[Threat Intelligence] Search failed for {query!r}: {exc}")

    return intelligence
