"""Commands for recording, importing and comparing path measurements."""

import argparse
from datetime import datetime, timezone
import gzip
import json
import math
from pathlib import Path
import sys

from .adapters.hysteria2 import adapt
from .https import check
from .incident import VERSION, journal_timeline, session_timeline, timeline
from .model import IP_STAGES, Labels, Observation, ROLES, label, parse_ip, timestamp
from .report import summarize


def add_labels(parser: argparse.ArgumentParser, roles=ROLES) -> None:
    for name in ("run", "target", "vantage", "network"):
        parser.add_argument("--" + name, required=True, help=f"Short label for the {name}")
    parser.add_argument("--role", choices=sorted(roles), required=True)


def add_attempt(parser: argparse.ArgumentParser, default_method: str) -> None:
    parser.add_argument("--attempt", required=True, help="Stable label for one actual attempt")
    parser.add_argument("--profile", help="Alias for comparable tunnel/session configuration")
    parser.add_argument("--method", default=default_method, help="Short label for the measurement method")


def positive_timeout(value: str) -> float:
    timeout = float(value)
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise argparse.ArgumentTypeError("timeout must be greater than zero and at most 60 seconds")
    return timeout


def positive_seconds(value: str) -> int:
    seconds = int(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be greater than zero")
    return seconds


def write_observation(observation: Observation) -> None:
    print(json.dumps(observation.as_dict(), separators=(",", ":")))


def unit_filter(args: argparse.Namespace) -> dict[str, str]:
    units = {}
    for kind, names in (("tunnel", args.tunnel_unit), ("http3", args.http3_unit), ("telemetry", args.telemetry_unit)):
        for name in names:
            if not name or name in units or any(character.isspace() or character == "\x00" for character in name):
                raise ValueError("journal unit names must be nonempty and unique")
            units[name] = kind
    if not units:
        raise ValueError("select at least one expected systemd unit")
    if args.tunnel_unit:
        label(args.profile, "profile")
    return units


def import_log(labels: Labels, args: argparse.Namespace) -> int:
    units = unit_filter(args)
    errors = ignored = records = 0
    reported = set()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError("journal entry must be an object")
            observations = adapt(labels, entry, units, args.profile)
        except (ValueError, KeyError, TypeError, OverflowError):
            errors += 1
            continue
        if not observations:
            ignored += 1
            continue
        reported.add(entry["_SYSTEMD_UNIT"])
        for observation in observations:
            write_observation(observation)
            records += 1
    missing = len(units.keys() - reported)
    print(
        f"Journal import: records={records} ignored={ignored} malformed={errors} units_without_results={missing}",
        file=sys.stderr,
    )
    return 2 if errors or missing else 0


def read_observations(stream) -> list[Observation]:
    observations = []
    try:
        for number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                observations.append(Observation.from_dict(json.loads(line)))
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                raise ValueError(f"Invalid observation on line {number}") from None
    finally:
        if stream is not sys.stdin:
            stream.close()
    return observations


def run_report(args: argparse.Namespace) -> int:
    try:
        observations = read_observations(args.file)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    print(json.dumps(summarize(observations, args.window, as_of=args.as_of, control_skew=args.control_skew), indent=2))
    return 0


def run_incident(args: argparse.Namespace) -> int:
    if args.start >= args.end:
        raise ValueError("incident start must precede end")
    local = {label(value, "local vantage") for value in args.local_vantage}
    run, target = label(args.run, "run"), label(args.target, "target")
    resource, gateway = set(args.resource_unit), set(args.gateway_unit)
    if bool(args.journal) != bool(resource | gateway) or resource & gateway:
        raise ValueError("provide a journal and distinct expected resource or gateway units together")
    version = args.hysteria_version
    if version is not None:
        if not args.hysteria_log or not VERSION.fullmatch(version):
            raise ValueError("provide a numeric Hysteria version alongside the session log")
        version = version.removeprefix("v")

    observations = read_observations(args.file)
    context, malformed = [], 0
    if args.journal:
        with args.journal.open(encoding="utf-8") as stream:
            context, malformed = journal_timeline(stream, resource, gateway, args.start, args.end)
    broken_session_lines = 0
    for path in args.hysteria_log:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as stream:
            events, broken = session_timeline(stream, version, args.start, args.end)
        context.extend(events)
        broken_session_lines += broken
    result = timeline(observations, run, target, args.start, args.end, local, context)
    result["inputs"] = {"journal_supplied": bool(args.journal), "hysteria_log_files": len(args.hysteria_log),
                        "malformed_journal_records": malformed, "malformed_session_records": broken_session_lines}
    print(json.dumps(result, indent=2))
    return 2 if malformed or broken_session_lines else 0


def record(labels: Labels, args: argparse.Namespace) -> Observation:
    verified = args.stage in IP_STAGES and args.outcome == "pass"
    if verified:
        if args.expect_ip is None or args.observed_ip is None:
            raise ValueError("positive tunnel and egress records require --expect-ip and --observed-ip")
        if parse_ip(args.expect_ip) != parse_ip(args.observed_ip):
            raise ValueError("observed and expected exit do not match")
    return Observation(
        labels, args.at or datetime.now(timezone.utc), args.stage, args.method, args.outcome, args.reason,
        source="manual", attempt=args.attempt, profile=args.profile, egress_verified=verified,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    manual = commands.add_parser("record", help="Record a manually verified result")
    add_labels(manual)
    add_attempt(manual, "manual")
    manual.add_argument("--stage", choices=("baseline", "ingress", "session", "tunnel", "egress"), required=True)
    manual.add_argument("--outcome", choices=("pass", "fail", "unknown"), required=True)
    manual.add_argument("--reason", default="reported_by_operator")
    manual.add_argument("--at", type=timestamp, help="ISO timestamp with UTC offset (default: now)")
    manual.add_argument("--expect-ip")
    manual.add_argument("--observed-ip")

    https = commands.add_parser("check-https", help="Run TLS-verified HTTPS over the current route")
    add_labels(https)
    add_attempt(https, "https")
    https.add_argument("--stage", choices=("baseline", "tunnel", "egress"), required=True)
    https.add_argument("--url", required=True)
    https.add_argument("--expect-ip", help="Expected plain IP in the HTTPS response")
    https.add_argument("--timeout", type=positive_timeout, default=5.0, help="Socket I/O timeout")

    journal = commands.add_parser("import-hysteria2", help="Import selected server units from journalctl -o json")
    add_labels(journal, {"server"})
    journal.add_argument("--profile", help="Profile alias of the monitored Hysteria2 session")
    journal.add_argument("--tunnel-unit", action="append", default=[])
    journal.add_argument("--http3-unit", action="append", default=[])
    journal.add_argument("--telemetry-unit", action="append", default=[])

    report = commands.add_parser("report", help="Compare observations from a JSON Lines file or stdin")
    report.add_argument("file", nargs="?", type=argparse.FileType("r", encoding="utf-8"), default=sys.stdin)
    report.add_argument("--window", type=positive_seconds, default=600, help="Lookback in seconds")
    report.add_argument("--control-skew", type=positive_seconds, default=120, help="Maximum seconds between paired controls")
    report.add_argument("--as-of", type=timestamp, help="Time of report with UTC offset (default: now)")

    incident = commands.add_parser("incident", help="Show an incident timeline over a UTC-bounded interval")
    incident.add_argument("file", type=argparse.FileType("r", encoding="utf-8"), help="Observations JSON Lines file")
    incident.add_argument("--run", required=True)
    incident.add_argument("--target", required=True)
    incident.add_argument("--start", type=timestamp, required=True)
    incident.add_argument("--end", type=timestamp, required=True)
    incident.add_argument("--local-vantage", action="append", default=[])
    incident.add_argument("--journal", type=Path, help="Optional JSON Lines export of the server journal")
    incident.add_argument("--resource-unit", action="append", default=[])
    incident.add_argument("--gateway-unit", action="append", default=[])
    incident.add_argument("--hysteria-log", type=Path, action="append", default=[])
    incident.add_argument("--hysteria-version", help="Exact server version for interpreting close codes")

    args = parser.parse_args()
    if args.command == "report":
        return run_report(args)
    if args.command == "incident":
        try:
            return run_incident(args)
        except (OSError, EOFError, UnicodeError):
            parser.error("unable to read an incident input")
        except ValueError as error:
            parser.error(str(error))
    try:
        labels = Labels(args.run, args.target, args.vantage, args.network, args.role)
        if args.command == "import-hysteria2":
            return import_log(labels, args)
        if args.command == "record":
            write_observation(record(labels, args))
            return 0
        result = check(
            labels, args.stage, args.url, args.timeout, args.expect_ip, attempt=args.attempt,
            profile=args.profile, method=args.method,
        )
        write_observation(result)
        return 0 if result.outcome == "pass" else 1
    except ValueError as error:
        parser.error(str(error))
    except OSError:
        parser.error("unable to start the HTTPS probe")
    return 2


if __name__ == "__main__":
    sys.exit(main())
