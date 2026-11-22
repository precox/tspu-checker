"""Explicit TLS-verified HTTPS control over the route of the invoking process."""

from datetime import datetime, timezone
import http.client
import socket
import ssl
import time
from urllib.parse import urlsplit

from .model import IP_STAGES, Labels, Observation, parse_ip


def check(
    labels: Labels, stage: str, url: str, timeout: float, expected_ip: str | None,
    *, attempt: str, profile: str | None = None, method: str = "https",
) -> Observation:
    try:
        destination = urlsplit(url)
        port = destination.port
    except ValueError:
        raise ValueError("invalid HTTPS URL") from None
    if destination.scheme != "https" or not destination.hostname or destination.username is not None or destination.fragment:
        raise ValueError("use an HTTPS URL without credentials or fragments")
    if stage not in ("baseline", "tunnel", "egress"):
        raise ValueError("HTTPS supports baseline, tunnel and egress checks")
    if stage in IP_STAGES and expected_ip is None:
        raise ValueError("tunnel and egress HTTPS checks require --expect-ip")
    expected = parse_ip(expected_ip) if expected_ip is not None else None
    # Validate measurement labels before making a network request.
    Observation(labels, datetime.now(timezone.utc), stage, method, "unknown", "not_run",
                source="probe", attempt=attempt, profile=profile)

    path = destination.path or "/"
    if destination.query:
        path += "?" + destination.query
    connection = http.client.HTTPSConnection(
        destination.hostname, 443 if port is None else port, timeout=timeout, context=ssl.create_default_context(),
    )
    started = time.monotonic()
    metrics = {}
    outcome, reason = "fail", "http_failure"
    try:
        connection.request("GET", path, headers={"User-Agent": "tspu-checker/0.2"})
        response = connection.getresponse()
        metrics["http_status"] = response.status
        if not 200 <= response.status < 300:
            reason = "unexpected_http_status"
        elif expected is None:
            outcome, reason = "pass", "http_success"
        else:
            body = response.read(129)
            try:
                if len(body) > 128:
                    raise ValueError("IP response is too long")
                actual = parse_ip(body.decode("ascii").strip())
            except ValueError:
                reason = "invalid_ip_response"
            else:
                outcome, reason = ("pass", "expected_egress") if actual == expected else ("fail", "unexpected_egress")
    except ssl.SSLCertVerificationError:
        reason = "certificate_verification_failed"
    except ssl.SSLError:
        reason = "tls_error"
    except socket.gaierror:
        reason = "dns_error"
    except TimeoutError:
        reason = "timeout"
    except http.client.HTTPException:
        reason = "http_protocol_error"
    except OSError:
        reason = "connection_error"
    finally:
        connection.close()
    metrics["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return Observation(
        labels, datetime.now(timezone.utc), stage, method, outcome, reason, metrics, source="probe",
        attempt=attempt, profile=profile, egress_verified=outcome == "pass" and stage in IP_STAGES,
    )
