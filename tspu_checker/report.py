"""Compare fresh, identified measurements without attributing operator filtering."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .model import Observation, iso_utc
from .telemetry import coverage

PATH_FAILURES = {"client_timeout", "connection_error", "timeout"}


def summarize(
    observations: Iterable[Observation], window_seconds: int,
    *, as_of: datetime | None = None, control_skew: int = 120,
) -> list[dict]:
    reference = as_of if as_of is not None else datetime.now(timezone.utc)
    if reference.utcoffset() is None or window_seconds <= 0 or control_skew <= 0:
        raise ValueError("comparison needs a timezone-aware reference and positive durations")
    oldest = datetime.min.replace(tzinfo=timezone.utc)
    window = min(window_seconds, (reference - oldest) // timedelta(seconds=1))
    since = reference - timedelta(seconds=window)
    skew = min(window_seconds, control_skew)

    groups = defaultdict(list)
    for observation in observations:
        groups[observation.labels.run, observation.labels.target].append(observation)
    return [
        assess(run, target, group, since, reference, skew)
        for (run, target), group in sorted(groups.items())
    ]


def attempt_key(item: Observation) -> tuple:
    return item.labels, item.attempt


def nearby(first: Observation, second: Observation, seconds: int) -> bool:
    return abs((first.observed_at - second.observed_at).total_seconds()) <= seconds


def verified_tunnels(checks: list[Observation], skew: int) -> list[Observation]:
    sessions = defaultdict(list)
    tunnel_failures = defaultdict(list)
    for item in checks:
        if item.stage == "session":
            sessions[attempt_key(item), item.profile].append(item)
        elif item.stage == "tunnel" and item.outcome == "fail":
            tunnel_failures[attempt_key(item), item.profile].append(item)

    verified = []
    for item in checks:
        if item.stage != "tunnel" or not item.egress_verified:
            continue
        key = attempt_key(item), item.profile
        if any(nearby(other, item, skew) for other in tunnel_failures[key]):
            continue
        candidates = sessions[key]
        states = {
            session.outcome for session in candidates
            if session.observed_at <= item.observed_at and nearby(session, item, skew)
        }
        if states == {"pass"}:
            verified.append(item)
    return verified


def server_controls_pass(
    attempt: Observation, server_checks: list[Observation], server_tunnels: list[Observation], skew: int,
) -> bool:
    controls = [item for item in server_checks if item.stage != "baseline" and nearby(attempt, item, skew)]
    if any(item.outcome == "fail" for item in controls):
        return False
    egress = any(item.stage == "egress" and item.egress_verified for item in controls)
    ingress = any(item.stage == "ingress" and item.outcome == "pass" for item in controls)
    tunnel = any(nearby(attempt, item, skew) for item in server_tunnels)
    return egress and (ingress or tunnel)


def suspect_paths(
    clients: list[Observation], good: list[Observation], servers: list[Observation],
    server_tunnels: list[Observation], skew: int,
) -> list[dict]:
    baselines = defaultdict(list)
    for item in clients:
        if item.stage == "baseline":
            baselines[attempt_key(item)].append(item)
    successful_profiles = {(item.labels, item.profile, item.method, item.source) for item in good}

    failures = defaultdict(set)
    for item in clients:
        if item.stage not in ("tunnel", "session") or item.outcome != "fail" or item.reason not in PATH_FAILURES:
            continue
        if (item.labels, item.profile, item.method, item.source) in successful_profiles:
            continue
        baseline = {control.outcome for control in baselines[attempt_key(item)] if nearby(control, item, skew)}
        if baseline != {"pass"} or not server_controls_pass(item, servers, server_tunnels, skew):
            continue
        if not any(
            other.labels.network != item.labels.network and other.profile == item.profile
            and other.method == item.method and other.source == item.source and nearby(other, item, skew)
            for other in good
        ):
            continue
        key = (item.labels.network, item.labels.vantage, item.profile, item.method, item.stage, item.reason, item.source)
        failures[key].add((item.attempt, item.observed_at))

    return [
        {
            "network": key[0], "vantage": key[1], "profile": key[2], "method": key[3],
            "stage": key[4], "reason": key[5], "source": key[6], "distinct_attempts": len(attempts),
        }
        for key, records in sorted(failures.items())
        if len(attempts := {attempt for attempt, _ in records}) >= 2
        and len({instant for _, instant in records}) >= 2
    ]


def stage_results(checks: list[Observation]) -> dict:
    by_stage = defaultdict(set)
    for item in checks:
        by_stage[item.stage].add(item.outcome)
    return {stage: sorted(states) for stage, states in sorted(by_stage.items())}


def assess(
    run: str, target: str, group: list[Observation], since: datetime, reference: datetime, skew: int,
) -> dict:
    checks = [item for item in group if item.stage != "telemetry"]
    current = [item for item in checks if since <= item.observed_at <= reference]
    qualified = [item for item in current if item.source != "legacy" and item.outcome != "unknown"]
    servers = [item for item in qualified if item.labels.role == "server"]
    clients = [item for item in qualified if item.labels.role == "client"]
    verified = verified_tunnels(qualified, skew)
    working = [item for item in verified if item.labels.role == "client"]
    fails = [item for item in clients if item.stage in ("session", "tunnel") and item.outcome == "fail"]
    suspects = suspect_paths(
        clients, working, servers, [item for item in verified if item.labels.role == "server"], skew,
    )
    failed_egress = [item for item in servers if item.stage == "egress" and item.outcome == "fail"]
    passed_egress = any(item.stage == "egress" and item.egress_verified for item in servers)

    if failed_egress and not passed_egress:
        result = "egress_check_failed"
    elif suspects:
        result = "client_path_issue_suspected"
    elif fails:
        result = "client_failures_need_controls"
    elif any(item.outcome == "fail" for item in servers):
        result = "server_checks_need_review"
    elif working:
        result = "reachable_from_tested_networks"
    else:
        result = "no_comparable_client_result"

    client_checks = defaultdict(list)
    for item in current:
        if item.labels.role == "client" and item.source != "legacy":
            client_checks[item.labels.network, item.labels.vantage].append(item)
    return {
        "run": run,
        "target": target,
        "result": result,
        "attribution": "unestablished",
        "comparison_from": iso_utc(since),
        "comparison_as_of": iso_utc(reference),
        "control_skew_seconds": skew,
        "checks_outside_window": sum(item.observed_at < since for item in checks),
        "future_checks": sum(item.observed_at > reference for item in checks),
        "unknown_checks_in_window": sum(item.outcome == "unknown" for item in current),
        "legacy_checks_in_window": sum(item.source == "legacy" for item in current),
        "working_client_networks": sorted({item.labels.network for item in working}),
        "client_networks_with_failures": sorted({item.labels.network for item in fails}),
        "client_checks": [
            {"network": network, "vantage": vantage, "stages": stage_results(rows)}
            for (network, vantage), rows in sorted(client_checks.items())
        ],
        "suspected_client_paths": suspects,
        "server_checks": stage_results([
            item for item in current if item.labels.role == "server" and item.source != "legacy"
        ]),
        "telemetry": coverage([item for item in group if item.stage == "telemetry"], since, reference),
    }
