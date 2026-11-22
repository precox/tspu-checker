"""Commands for recording, importing and comparing path measurements."""

import argparse
from datetime import datetime, timezone
import json
import math
import sys

from .adapters.hysteria2 import adapt
from .https import check
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


def run_report(args: argparse.Namespace) -> int:
    observations = []
    try:
        for number, line in enumerate(args.file, start=1):
            if not line.strip():
                continue
            try:
                observations.append(Observation.from_dict(json.loads(line)))
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                print(f"Invalid observation on line {number}", file=sys.stderr)
                return 2
    finally:
        if args.file is not sys.stdin:
            args.file.close()
    print(json.dumps(summarize(observations, args.window, as_of=args.as_of, control_skew=args.control_skew), indent=2))
    return 0


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

    args = parser.parse_args()
    if args.command == "report":
        return run_report(args)
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
