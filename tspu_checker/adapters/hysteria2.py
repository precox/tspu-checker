"""Translate known systemd journal messages from explicitly selected units."""

from datetime import datetime, timedelta, timezone
import re

from ..model import Labels, Observation, timestamp

METRICS = ("udp_in", "udp_out", "initial_like_in", "udp_in_bytes", "udp_out_bytes",
           "observer_drops", "unmeasured_lengths")
PREFIXES = {
    "tunnel": ("hysteria_check=",),
    "http3": ("http3_status=", "http3_error="),
    "telemetry": ("udp443_window_start_utc=",),
}
INVOCATION = re.compile(r"[0-9a-f]{32}")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def message_fields(message: str) -> dict[str, str]:
    result = {}
    for field in message.split():
        if "=" in field:
            key, value = field.split("=", 1)
            if key in result:
                raise ValueError("duplicate message field")
            result[key] = value
    return result


def telemetry(labels: Labels, fields: dict) -> Observation:
    start = timestamp(fields["udp443_window_start_utc"])
    end = timestamp(fields["udp443_window_end_utc"])
    counters = {key: int(fields[key]) for key in METRICS if key in fields}
    if not {"udp_in", "udp_out", "observer_drops"} <= counters.keys():
        raise ValueError("missing required UDP counters")
    return Observation(
        labels, end, "telemetry", "udp_counter", "observed", "udp_window", counters,
        source="journal", window_start=start,
    )


def tunnel(labels: Labels, when: datetime, attempt: str, profile: str, fields: dict) -> list[Observation]:
    state = fields["hysteria_check"]
    step, cause = fields.get("step"), fields.get("reason")
    context = {"source": "journal", "attempt": attempt, "profile": profile}
    if state == "skipped" or cause == "test_account_unavailable" or step in ("local_setup", "hysteria_client"):
        if cause not in ("test_account_unavailable", "local_probe_port_busy"):
            cause = "local_probe_unavailable" if step == "local_setup" else "session_unconfirmed"
        return [Observation(labels, when, "session", "hysteria2", "unknown", cause, **context)]
    if state == "failed" and step in ("https", "udp_dns"):
        reason = "https_probe_failed" if step == "https" else "udp_dns_probe_failed"
        session = Observation(labels, when, "session", "hysteria2", "unknown", "session_unconfirmed", **context)
        return [session, Observation(labels, when, "tunnel", "hysteria2", "fail", reason, **context)]
    if state not in ("passed", "failed") or not all(
        fields.get(field) in ("True", "False") for field in ("https_via_e1", "udp_dns")
    ):
        raise ValueError("unrecognized Hysteria2 outcome")

    egress = fields["https_via_e1"] == "True"
    dns = fields["udp_dns"] == "True"
    passed = egress and dns
    if (state == "passed") != passed:
        raise ValueError("conflicting Hysteria2 result")
    if passed:
        reason = "https_and_udp_dns_passed"
    elif not egress and not dns:
        reason = "unexpected_egress_and_udp_dns_failed"
    else:
        reason = "unexpected_egress" if not egress else "udp_dns_probe_failed"
    metrics = {"expected_egress": int(egress), "udp_dns": int(dns)}
    session = Observation(
        labels, when, "session", "hysteria2", "pass" if egress else "unknown",
        "fresh_session" if egress else "session_unconfirmed", **context,
    )
    return [session, Observation(
        labels, when, "tunnel", "hysteria2", "pass" if passed else "fail", reason, metrics,
        egress_verified=passed, **context,
    )]


def http3(labels: Labels, when: datetime, attempt: str, fields: dict) -> Observation:
    error = fields.get("http3_error")
    status = int(fields["http3_status"] or 0) if error is None else 0
    if error is not None:
        if error in ("TimeoutError", "ConnectionError"):
            outcome, reason = "fail", "http3_timeout" if error == "TimeoutError" else "http3_connection_error"
        elif error in ("local_dependency_missing", "local_fixture_unavailable", "local_tls_configuration"):
            outcome, reason = "unknown", error
        else:
            outcome, reason = "unknown", "local_or_network_probe_error"
    elif status != 200 or fields.get("html") != "True":
        outcome, reason = "fail", "unexpected_http3_response"
    elif fields.get("body_matches") != "True":
        outcome, reason = "fail", "http3_body_mismatch"
    else:
        outcome, reason = "pass", "http3_response_verified"
    return Observation(
        labels, when, "ingress", "http3", outcome, reason, {"http_status": status} if status else {},
        source="journal", attempt=attempt,
    )


def adapt(labels: Labels, entry: dict, units: dict[str, str], profile: str | None) -> list[Observation]:
    if labels.role != "server":
        raise ValueError("the journal adapter requires a server vantage")
    unit = entry.get("_SYSTEMD_UNIT")
    message = entry.get("MESSAGE")
    kind = units.get(unit) if isinstance(unit, str) else None
    if not kind or not isinstance(message, str) or not message.startswith(PREFIXES[kind]):
        return []
    fields = message_fields(message)
    if kind == "telemetry":
        return [telemetry(labels, fields)]

    incarnation = entry.get("_SYSTEMD_INVOCATION_ID")
    if not isinstance(incarnation, str) or not INVOCATION.fullmatch(incarnation):
        raise ValueError("active journal event lacks a systemd invocation ID")
    attempt = f"i-{incarnation}"
    when = EPOCH + timedelta(microseconds=int(entry["__REALTIME_TIMESTAMP"]))
    if kind == "tunnel":
        return tunnel(labels, when, attempt, profile, fields)
    return [http3(labels, when, attempt, fields)]
