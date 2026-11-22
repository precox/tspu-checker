"""Versioned observation format shared by probes and adapters."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import re

LABEL = re.compile(r"[a-z][a-z0-9_-]{0,63}")
ROLES = {"client", "server"}
STAGES = {"baseline", "ingress", "session", "tunnel", "egress", "telemetry"}
PROFILE_STAGES = {"session", "tunnel"}
IP_STAGES = {"tunnel", "egress"}
OUTCOMES = {"pass", "fail", "unknown", "observed"}
SOURCES = {"manual", "probe", "journal", "legacy"}


def label(value: str, name: str) -> str:
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise ValueError(f"{name} must be a short lowercase label")
    return value


def parse_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("expected and observed exit must be valid IP addresses") from None


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Labels:
    run: str
    target: str
    vantage: str
    network: str
    role: str

    def __post_init__(self) -> None:
        for name in ("run", "target", "vantage", "network"):
            label(getattr(self, name), name)
        if self.role not in ROLES:
            raise ValueError("invalid vantage role")


@dataclass(frozen=True)
class Observation:
    labels: Labels
    observed_at: datetime
    stage: str
    method: str
    outcome: str
    reason: str
    metrics: dict[str, int] = field(default_factory=dict)
    source: str = "manual"
    attempt: str | None = None
    profile: str | None = None
    egress_verified: bool = False
    window_start: datetime | None = None

    def __post_init__(self) -> None:
        if self.observed_at.utcoffset() is None:
            raise ValueError("observation time must include a UTC offset")
        if self.stage not in STAGES or self.outcome not in OUTCOMES or self.source not in SOURCES:
            raise ValueError("invalid stage, outcome, or source")
        if (self.stage == "telemetry") != (self.outcome == "observed"):
            raise ValueError("telemetry records use the observed outcome")
        if self.source == "journal" and self.labels.role != "server":
            raise ValueError("systemd journal records use a server vantage")
        label(self.method, "method")
        label(self.reason, "reason")
        if type(self.egress_verified) is not bool:
            raise ValueError("egress_verified must be a boolean")
        if self.egress_verified and (self.stage not in IP_STAGES or self.outcome != "pass" or self.source == "legacy"):
            raise ValueError("only a positive tunnel or egress check can verify egress")
        if not isinstance(self.metrics, dict):
            raise ValueError("metrics must be an object")
        for name, value in self.metrics.items():
            label(name, "metric")
            if type(value) is not int or value < 0:
                raise ValueError("metrics must have non-negative integer values")

        if self.stage == "telemetry":
            if self.window_start is None:
                if self.source != "legacy":
                    raise ValueError("telemetry requires window_start")
            elif self.window_start.utcoffset() is None or self.window_start >= self.observed_at:
                raise ValueError("invalid telemetry window")
        elif self.window_start is not None:
            raise ValueError("only telemetry carries a window_start")

        if self.attempt is not None or (self.stage != "telemetry" and self.source != "legacy"):
            label(self.attempt, "attempt")
        if self.profile is not None or (self.stage in PROFILE_STAGES and self.source != "legacy"):
            label(self.profile, "profile")
        if self.stage in IP_STAGES and self.outcome == "pass" and self.source != "legacy" and not self.egress_verified:
            raise ValueError("positive tunnel and egress observations require a verified exit")

    def as_dict(self) -> dict:
        return {
            "schema": 2,
            **vars(self.labels),
            "observed_at": iso_utc(self.observed_at),
            "stage": self.stage,
            "method": self.method,
            "outcome": self.outcome,
            "reason": self.reason,
            "metrics": self.metrics.copy(),
            "source": self.source,
            "attempt": self.attempt,
            "profile": self.profile,
            "egress_verified": self.egress_verified,
            "window_start": iso_utc(self.window_start) if self.window_start else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Observation":
        if not isinstance(data, dict) or type(data.get("schema")) is not int or data["schema"] not in (1, 2):
            raise ValueError("unsupported observation schema")
        labels = Labels(*(data[name] for name in ("run", "target", "vantage", "network", "role")))
        observed_at = timestamp(data["observed_at"])
        metrics = data.get("metrics", {})
        if not isinstance(metrics, dict):
            raise ValueError("metrics must be an object")
        common = (labels, observed_at, data["stage"], data["method"], data["outcome"], data["reason"], metrics)
        if data["schema"] == 1:
            window_start = None
            if data["stage"] == "telemetry" and type(size := metrics.get("window_ms")) is int and size > 0:
                try:
                    window_start = observed_at - timedelta(milliseconds=size)
                except OverflowError:
                    pass
            return cls(*common, source="legacy", window_start=window_start)
        start = data.get("window_start")
        return cls(
            *common, source=data["source"], attempt=data.get("attempt"), profile=data.get("profile"),
            egress_verified=data.get("egress_verified", False),
            window_start=timestamp(start) if start is not None else None,
        )
