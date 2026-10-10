from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime
from fastapi.responses import StreamingResponse

from .database import Base, engine, get_db
from .models import User, Scan, Finding, PortResult, IntelResult
from .security import (
    hash_password,
    verify_password,
    create_token,
    current_user,
)
from .scanner import (
    normalize_target,
    port_scan,
    web_checks,
    score,
)
from .serp_service import get_security_intelligence
from .report_generator import generate_pdf


# Create database tables
Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------

app = FastAPI(
    title="VULN-X API",
    version="1.0.0"
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------

class Register(BaseModel):
    name: str
    username: str
    email: EmailStr
    password: str
    confirm_password: str


class Login(BaseModel):
    identifier: str
    password: str


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "standard"
    authorized: bool


# ---------------------------------------------------------
# Root
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "VULN-X",
        "status": "online"
    }


# =========================================================
# AUTHENTICATION
# =========================================================

@app.post("/api/auth/register")
def register(
    data: Register,
    db: Session = Depends(get_db)
):
    # Password validation
    if (
        len(data.password) < 8
        or data.password.lower() == data.password
        or data.password.upper() == data.password
    ):
        raise HTTPException(
            400,
            "Password must be at least 8 characters and include upper/lowercase characters.",
        )

    if data.password != data.confirm_password:
        raise HTTPException(
            400,
            "Passwords do not match."
        )

    # Check existing user
    if db.scalar(
        select(User).where(
            (User.email == data.email)
            | (User.username == data.username)
        )
    ):
        raise HTTPException(
            409,
            "Email or username already exists."
        )

    # Create user
    u = User(
        name=data.name.strip(),
        username=data.username.strip(),
        email=data.email.lower(),
        password_hash=hash_password(data.password),
    )

    db.add(u)
    db.commit()
    db.refresh(u)

    return {
        "token": create_token(u.id),
        "user": {
            "id": u.id,
            "name": u.name,
            "username": u.username,
            "email": u.email,
        },
    }


@app.post("/api/auth/login")
def login(
    data: Login,
    db: Session = Depends(get_db)
):
    u = db.scalar(
        select(User).where(
            (User.email == data.identifier.lower())
            | (User.username == data.identifier)
        )
    )

    if not u or not verify_password(
        data.password,
        u.password_hash
    ):
        raise HTTPException(
            401,
            "Invalid credentials."
        )

    return {
        "token": create_token(u.id),
        "user": {
            "id": u.id,
            "name": u.name,
            "username": u.username,
            "email": u.email,
        },
    }


@app.get("/api/auth/me")
def me(
    u: User = Depends(current_user)
):
    return {
        "id": u.id,
        "name": u.name,
        "username": u.username,
        "email": u.email,
        "created_at": u.created_at,
    }


# =========================================================
# VULN-X SCANNING
# =========================================================

@app.post("/api/scans")
def create_scan(
    data: ScanRequest,
    u: User = Depends(current_user),
    db: Session = Depends(get_db)
):

    # -----------------------------------------------------
    # 1. Authorization confirmation
    # -----------------------------------------------------

    if not data.authorized:
        raise HTTPException(
            400,
            "Authorization confirmation is required."
        )

    # -----------------------------------------------------
    # 2. Validate scan mode and normalize target
    # -----------------------------------------------------

    if data.scan_type not in ("quick", "standard", "web"):
        raise HTTPException(400, "Unsupported scan type. Choose quick, standard, or web.")

    try:
        host, scheme, explicit_port = normalize_target(data.target)
    except ValueError:
        raise HTTPException(
            400,
            "Invalid target."
        )

    # -----------------------------------------------------
    # 3. Create scan record
    # -----------------------------------------------------

    scan = Scan(
        user_id=u.id,
        target=data.target.strip(),
        scan_type=data.scan_type,
        status="running",
        started_at=datetime.utcnow(),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # -----------------------------------------------------
    # 4. Run scanner + SerpApi intelligence
    # -----------------------------------------------------

    try:

        # Existing VULN-X port scanner
        # Include the explicitly supplied port as well as the common service
        # ports. This makes URLs such as http://127.0.0.1:5173 test the port
        # the user actually entered.
        ports = port_scan(
            host,
            extra_ports=[explicit_port] if explicit_port is not None else [],
        )

        # Web checks receive a normalized hostname, scheme and explicit port.
        findings = (
            web_checks(host, scheme, explicit_port)
            if data.scan_type in ("standard", "web")
            else []
        )

        # -------------------------------------------------
        # SerpApi Security Intelligence
        # -------------------------------------------------

        intelligence = get_security_intelligence(
            findings,
            ports
        )

        # Save SerpApi intelligence
        for item in intelligence:

            intel = IntelResult(
                scan_id=scan.id,
                query=item.get("query", ""),
                title=item.get("title"),
                link=item.get("link"),
                snippet=item.get("snippet"),
                source=item.get("source"),
                date=item.get("date"),
            )

            db.add(intel)

        # -------------------------------------------------
        # 5. Save port results
        # -------------------------------------------------

        for p in ports:

            db.add(
                PortResult(
                    scan_id=scan.id,
                    **p
                )
            )

        # -------------------------------------------------
        # 6. Save vulnerability findings
        # -------------------------------------------------

        for f in findings:

            db.add(
                Finding(
                    scan_id=scan.id,
                    **f
                )
            )

        # -------------------------------------------------
        # 7. Calculate security score
        # -------------------------------------------------

        scan.security_score = score(
            findings,
            ports
        )

        # -------------------------------------------------
        # 8. Mark incomplete web assessments honestly. A failed HTTP check
        # must not be presented as a clean, fully completed assessment.
        # -------------------------------------------------

        web_assessment_failed = any(
            finding.get("title") == "Web service could not be assessed"
            for finding in findings
        )
        scan.status = "incomplete" if web_assessment_failed and data.scan_type in ("standard", "web") else "completed"
        scan.completed_at = datetime.utcnow()

        db.commit()

    except Exception as e:

        print(f"Scan error: {e}")

        scan.status = "failed"

        db.commit()

        raise HTTPException(
            500,
            "Scan failed. Check the target and try again."
        )

    # -----------------------------------------------------
    # 9. Return scan result
    # -----------------------------------------------------

    return {
        "id": scan.id,
        "status": scan.status,
        "intelligence": intelligence,
    }


# =========================================================
# DEMO SCAN
# =========================================================

@app.post("/api/scans/demo")
def demo_scan(
    u: User = Depends(current_user),
    db: Session = Depends(get_db)
):

    scan = Scan(
        user_id=u.id,
        target="demo.local",
        scan_type="demo",
        status="completed",
        security_score=68,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    # -----------------------------------------------------
    # Demo ports
    # -----------------------------------------------------

    ports = [
        (22, "SSH", "LOW"),
        (80, "HTTP", "INFO"),
        (443, "HTTPS", "INFO"),
        (3306, "MySQL", "HIGH"),
    ]

    for port, service, risk in ports:

        db.add(
            PortResult(
                scan_id=scan.id,
                port=port,
                protocol="TCP",
                state="OPEN",
                service=service,
                risk=risk,
            )
        )

    # -----------------------------------------------------
    # Demo findings
    # -----------------------------------------------------

    demo_findings = [

        (
            "Outdated server version",
            "HIGH",
            "Software",
            "A simulated outdated component was detected in demo data.",
        ),

        (
            "Missing Content-Security-Policy",
            "MEDIUM",
            "Security Headers",
            "The demo response omits a CSP header.",
        ),

        (
            "Missing X-Frame-Options",
            "LOW",
            "Security Headers",
            "The demo response omits X-Frame-Options.",
        ),

        (
            "Server information exposed",
            "LOW",
            "Information Disclosure",
            "The demo response exposes a server banner.",
        ),
    ]

    for title, sev, cat, desc in demo_findings:

        db.add(
            Finding(
                scan_id=scan.id,
                title=title,
                severity=sev,
                category=cat,
                description=desc,
                evidence="DEMO DATA",
                impact="Simulated impact for presentation.",
                recommendation="Apply the relevant defensive remediation.",
                reference=None,
            )
        )

    db.commit()

    return {
        "id": scan.id,
        "status": "completed",
        "demo": True,
    }


# =========================================================
# SCAN JSON FORMAT
# =========================================================

def scan_json(
    scan,
    db
):

    findings = db.scalars(
        select(Finding).where(
            Finding.scan_id == scan.id
        )
    ).all()

    ports = db.scalars(
        select(PortResult).where(
            PortResult.scan_id == scan.id
        )
    ).all()

    intelligence = db.scalars(
        select(IntelResult).where(
            IntelResult.scan_id == scan.id
        )
    ).all()

    return {

        "id": scan.id,

        "target": scan.target,

        "scan_type": scan.scan_type,

        "status": scan.status,

        "security_score": scan.security_score,

        "started_at": scan.started_at,

        "completed_at": scan.completed_at,

        # -------------------------------------------------
        # Findings
        # -------------------------------------------------

        "findings": [

            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "evidence": f.evidence,
                "impact": f.impact,
                "recommendation": f.recommendation,
                "reference": f.reference,
            }

            for f in findings
        ],

        # -------------------------------------------------
        # Ports
        # -------------------------------------------------

        "ports": [

            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service,
                "risk": p.risk,
            }

            for p in ports
        ],

        # -------------------------------------------------
        # SerpApi Threat Intelligence
        # -------------------------------------------------

        "intelligence": [

            {
                "query": i.query,
                "title": i.title,
                "link": i.link,
                "snippet": i.snippet,
                "source": i.source,
                "date": i.date,
            }

            for i in intelligence
        ],
    }


# =========================================================
# SCAN HISTORY
# =========================================================

@app.get("/api/scans")
def scans(
    u: User = Depends(current_user),
    db: Session = Depends(get_db)
):

    rows = db.scalars(
        select(Scan)
        .where(Scan.user_id == u.id)
        .order_by(Scan.id.desc())
    ).all()

    return [
        scan_json(s, db)
        for s in rows
    ]


# =========================================================
# SINGLE SCAN
# =========================================================

@app.get("/api/scans/{scan_id}")
def get_scan(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db)
):

    s = db.get(
        Scan,
        scan_id
    )

    if not s or s.user_id != u.id:
        raise HTTPException(
            404,
            "Scan not found."
        )

    return scan_json(
        s,
        db
    )


# =========================================================
# PDF REPORT
# =========================================================

@app.get("/api/reports/{scan_id}/pdf")
def export_pdf(
    scan_id: int,
    u: User = Depends(current_user),
    db: Session = Depends(get_db)
):

    scan = db.get(
        Scan,
        scan_id
    )

    if not scan or scan.user_id != u.id:
        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )

    report = scan_json(
        scan,
        db
    )

    pdf = generate_pdf(
        report
    )

    filename = f"VULN-X-Report-{scan.id}.pdf"

    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            f'attachment; filename="{filename}"'
        },
    )