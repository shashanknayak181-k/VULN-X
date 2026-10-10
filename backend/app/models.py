from sqlalchemy import String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    scans = relationship(
        "Scan",
        back_populates="user",
        cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    target: Mapped[str] = mapped_column(String(255))
    scan_type: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="completed")
    security_score: Mapped[int] = mapped_column(Integer, default=100)
    started_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    user = relationship("User", back_populates="scans")

    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    ports = relationship(
        "PortResult",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    intelligence = relationship(
        "IntelResult",
        back_populates="scan",
        cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    scan = relationship("Scan", back_populates="findings")


class PortResult(Base):
    __tablename__ = "port_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10))
    state: Mapped[str] = mapped_column(String(20))
    service: Mapped[str] = mapped_column(String(50))
    risk: Mapped[str] = mapped_column(String(20))

    scan = relationship("Scan", back_populates="ports")


class IntelResult(Base):
    __tablename__ = "intel_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id")
    )

    query: Mapped[str] = mapped_column(Text)

    title: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True
    )

    link: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    snippet: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    source: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    date: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    scan = relationship(
        "Scan",
        back_populates="intelligence"
    )