import socket
from urllib.parse import urlparse

import requests


COMMON = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    3000: "DEV-HTTP",
    5000: "DEV-HTTP",
    5173: "VITE-DEV",
    8000: "APP-HTTP",
    8888: "ALT-HTTP",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def normalize_target(target: str):
    """
    Return hostname, scheme, and explicitly supplied port.
    """
    target = target.strip()

    if not target:
        raise ValueError("Invalid target")

    candidate = (
        target if "://" in target
        else f"//{target}"
    )

    parsed = urlparse(candidate)

    host = parsed.hostname
    scheme = parsed.scheme.lower() if parsed.scheme else ""

    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid target port") from exc

    if not host:
        raise ValueError("Invalid target")

    if parsed.username or parsed.password:
        raise ValueError("Do not include credentials in a target URL")

    if scheme and scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    return host, scheme, explicit_port


def port_scan(host: str, timeout=0.6, extra_ports=None):
    results = []
    ports_to_check = dict(COMMON)
    for port in extra_ports or []:
        if isinstance(port, int) and 1 <= port <= 65535:
            ports_to_check.setdefault(port, "CUSTOM")

    for port, service in ports_to_check.items():
        connection = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        connection.settimeout(timeout)

        try:
            state = (
                "OPEN"
                if connection.connect_ex((host, port)) == 0
                else "CLOSED"
            )

        except Exception:
            state = "UNREACHABLE"

        finally:
            connection.close()

        risk = (
            "LOW"
            if state == "OPEN"
            and port in (22, 3306, 5432, 8080)
            else "INFO"
        )

        results.append({
            "port": port,
            "protocol": "TCP",
            "state": state,
            "service": service,
            "risk": risk,
        })

    return results


def web_checks(host: str, scheme: str, port=None):
    findings = []

    scheme = scheme or "http"

    default_port = 443 if scheme == "https" else 80

    port_part = (
        f":{port}"
        if port is not None and port != default_port
        else ""
    )

    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    base = f"{scheme}://{display_host}{port_part}"

    try:
        response = requests.get(
            base,
            timeout=5,
            allow_redirects=True,
        )

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        if response.url.startswith("http://"):
            findings.append({
                "title": "HTTPS not enforced",
                "severity": "MEDIUM",
                "category": "Configuration",
                "description": (
                    "The observed endpoint completed over HTTP."
                ),
                "evidence": f"Final URL: {response.url}",
                "impact": (
                    "Traffic may be exposed to interception "
                    "on untrusted networks."
                ),
                "recommendation": (
                    "Serve the application over HTTPS and "
                    "redirect HTTP to HTTPS."
                ),
                "reference": None,
            })

        required_headers = {
            "content-security-policy": "Content-Security-Policy",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "referrer-policy": "Referrer-Policy",
        }

        for key, label in required_headers.items():
            if key not in headers:
                severity = (
                    "MEDIUM"
                    if key == "content-security-policy"
                    else "LOW"
                )

                findings.append({
                    "title": f"Missing {label} header",
                    "severity": severity,
                    "category": "Security Headers",
                    "description": (
                        f"The response did not include {label}."
                    ),
                    "evidence": "HTTP response headers",
                    "impact": (
                        "Missing defensive headers can reduce "
                        "browser-side security controls."
                    ),
                    "recommendation": (
                        f"Configure an appropriate {label} "
                        "policy for the application."
                    ),
                    "reference": None,
                })

        server_header = headers.get("server")

        if server_header:
            findings.append({
                "title": "Server information exposed",
                "severity": "LOW",
                "category": "Information Disclosure",
                "description": (
                    "The HTTP response exposes a Server header."
                ),
                "evidence": f"Server: {server_header}",
                "impact": (
                    "Detailed technology information can "
                    "assist reconnaissance."
                ),
                "recommendation": (
                    "Minimize unnecessary server/version "
                    "disclosure where practical."
                ),
                "reference": None,
            })

    except requests.RequestException as exc:
        findings.append({
            "title": "Web service could not be assessed",
            "severity": "INFO",
            "category": "Scanner",
            "description": (
                "The target did not provide an HTTP response "
                "within the timeout."
            ),
            "evidence": str(exc),
            "impact": (
                "Web configuration checks could not be completed."
            ),
            "recommendation": (
                "Verify the target is an HTTP/HTTPS service "
                "and retry."
            ),
            "reference": None,
        })

    return findings


def score(findings, ports):
    weights = {
        "CRITICAL": 30,
        "HIGH": 18,
        "MEDIUM": 10,
        "LOW": 4,
        "INFO": 0,
    }

    deduction = sum(
        weights.get(
            str(finding.get("severity", "INFO")).upper(),
            0,
        )
        for finding in findings
    )

    deduction += sum(
        2
        for port in ports
        if port.get("state") == "OPEN"
        and port.get("port") in (3306, 5432)
    )

    result = max(0, min(100, 100 - deduction))

    # Failed web checks are an incomplete assessment, never evidence of safety.
    assessment_failed = any(
        finding.get("title") == "Web service could not be assessed"
        for finding in findings
    )
    if assessment_failed:
        result = min(result, 50)

    # A finding-free scan with no completed web assessment is not a clean bill
    # of health. Quick scans intentionally only report the limited port checks.
    return result