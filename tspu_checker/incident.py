"""Build a sanitized incident timeline from observations and selected server logs."""

from collections import defaultdict
from datetime import timedelta
from decimal import Decimal, InvalidOperation
import json
import re

from .adapters.hysteria2 import EPOCH, message_fields
from .model import iso_utc, timestamp

UDP_FIELDS = ("udp_in", "udp_out", "observer_drops", "unmeasured_lengths")
RESOURCE_PCTS = ("cpu_steal_pct", "cpu_busy_pct", "cpu_iowait_pct",
                 "cpu_psi_some_pct", "memory_psi_some_pct")
RESOURCE_COUNTS = ("mem_available_kib", "swap_in_pages", "swap_out_pages",
                   "udp_rcvbuf_errors", "udp_sndbuf_errors")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
TCP_TIMEOUT = re.compile(r"\bdial tcp[46]?\b.*(?:\btimeout\b|\btimed out\b|\bETIMEDOUT\b)", re.I)
SESSION_LINE = re.compile(
    r"^(?P<when>\S+)\s+(?:(?:INFO|WARN|ERROR|DEBUG|server|hysteria2)\s+)*"
    r"(?P<event>client connected|client disconnected|TCP error|UDP error)\b"
)
CLOSE = re.compile(r"\bApplication error (0x[0-9a-fA-F]{1,16}) \((local|remote)\)")
VERSION = re.compile(r"v?\d{1,3}\.\d{1,3}\.\d{1,3}")


def scope(labels, local_vantages):
    if labels.role == "client":
        return "client_network"
    return "local_server" if labels.vantage in local_vantages else "server_vantage"


def udp_spans(windows, start, end):
    """Describe coverage and trusted zero windows, preserving overlap uncertainty."""
    starts, stops = defaultdict(set), defaultdict(set)
    for begin, finish in windows:
        if begin < end and start < finish:
            starts[max(start, begin)].add((begin, finish))
            stops[min(end, finish)].add((begin, finish))
    edges = sorted({start, end, *starts, *stops})
    spans, active = [], set()
    for begin, finish in zip(edges, edges[1:]):
        active.difference_update(stops[begin])
        active.update(starts[begin])
        status = "missing"
        if len(active) > 1:
            status = "unreliable"
        elif active:
            variants = windows[next(iter(active))]
            if len(variants) != 1:
                status = "unreliable"
            else:
                packets, _, drops, unmeasured = next(iter(variants))
                if packets is None or drops != 0 or unmeasured not in (None, 0):
                    status = "unreliable"
                else:
                    status = "zero_udp" if packets == 0 else "measured"
        if spans and spans[-1]["status"] == status:
            spans[-1]["end"] = iso_utc(finish)
        else:
            spans.append({"start": iso_utc(begin), "end": iso_utc(finish), "status": status})
    return spans


def udp_timeline(observations, start, end, local_vantages):
    streams = defaultdict(lambda: defaultdict(set))
    for item in observations:
        if item.stage == "telemetry" and item.method == "udp_counter" and item.window_start:
            labels = item.labels
            stream = (labels.vantage, labels.network, scope(labels, local_vantages))
            streams[stream][item.window_start, item.observed_at].add(
                tuple(item.metrics.get(key) for key in UDP_FIELDS)
            )
    summaries, events = [], []
    for (vantage, network, observed_scope), windows in sorted(streams.items()):
        identity = {"vantage": vantage, "network": network, "scope": observed_scope}
        summaries.append({**identity, "spans": udp_spans(windows, start, end)})
        for (begin, finish), variants in sorted(windows.items()):
            if begin >= end or finish <= start:
                continue
            for variant in sorted(variants, key=lambda values: tuple(-1 if v is None else v for v in values)):
                counters = {key: value for key, value in zip(UDP_FIELDS, variant) if value is not None}
                events.append({"at": iso_utc(begin), "end": iso_utc(finish), "kind": "udp_window",
                               **identity, "counters": counters})
    return summaries, events


def journal_timeline(stream, resource_units, gateway_units, start, end):
    events, malformed = [], 0
    for line in stream:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            unit = entry.get("_SYSTEMD_UNIT")
            message = entry.get("MESSAGE")
            if not isinstance(unit, str) or (unit not in resource_units and unit not in gateway_units):
                continue
            if isinstance(message, list):
                message = bytes(message).decode("utf-8", errors="replace")
            if not isinstance(message, str):
                raise ValueError("missing journal message")
            if unit in resource_units:
                if not message.startswith("resource_window_start_utc="):
                    continue
                fields = message_fields(message)
                begin = timestamp(fields["resource_window_start_utc"])
                finish = timestamp(fields["resource_window_end_utc"])
                if finish <= begin:
                    raise ValueError("invalid resource window")
                if begin >= end or finish <= start:
                    continue
                stats = {}
                for key in RESOURCE_PCTS + RESOURCE_COUNTS:
                    value = fields.get(key)
                    if value is None or value == "unknown":
                        continue
                    amount = Decimal(value) if key in RESOURCE_PCTS else int(value)
                    if not amount >= 0 or (key in RESOURCE_PCTS and amount > 100):
                        raise ValueError("invalid resource counter")
                    stats[key] = float(amount) if key in RESOURCE_PCTS else amount
                events.append({"at": iso_utc(begin), "end": iso_utc(finish),
                               "kind": "resource_window", "scope": "server_context", "metrics": stats})
            elif TCP_TIMEOUT.search(ANSI.sub("", message)):
                when = EPOCH + timedelta(microseconds=int(entry["__REALTIME_TIMESTAMP"]))
                if start <= when < end:
                    events.append({"at": iso_utc(when), "kind": "gateway_tcp_timeout", "scope": "server_context"})
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError, InvalidOperation):
            malformed += 1
    return events, malformed


def session_timeline(stream, version, start, end):
    events, malformed = [], 0
    for line in stream:
        if line.lstrip().startswith("{"):
            try:
                entry = json.loads(line)
                line = entry.get("msg")
                if not isinstance(line, str):
                    raise ValueError("missing H-UI message")
            except (AttributeError, ValueError):
                malformed += 1
                continue
        line = ANSI.sub("", line).strip()
        match = SESSION_LINE.match(line)
        if not match:
            continue
        event = match["event"]
        close = CLOSE.search(line, match.end()) if event != "client connected" else None
        if event in ("TCP error", "UDP error") and close is None:
            continue
        try:
            when = timestamp(match["when"])
        except (ValueError, OverflowError):
            malformed += 1
            continue
        if not start <= when < end:
            continue
        if event.startswith("client "):
            events.append({"at": iso_utc(when), "scope": "server_context",
                           "kind": event.replace("client ", "session_")})
        if close is None:
            continue
        code, side = close.groups()
        reason = "unestablished"
        if version == "2.14.0":
            numeric = int(code, 16)
            if numeric == 0x100:
                reason = "application_no_error"
            elif numeric == 0x107 and side == "local":
                reason = "traffic_stats_kick"
        events.append({"at": iso_utc(when), "scope": "server_context", "kind": "quic_close",
                       "code": code.lower(), "side": side, "hysteria_version": version, "reason": reason})
    return events, malformed


def timeline(observations, run, target, start, end, local_vantages, context):
    selected = [item for item in observations if (item.labels.run, item.labels.target) == (run, target)]
    streams, events = udp_timeline(selected, start, end, local_vantages)
    udp_coverage = "measured" if events else "unavailable"
    events.extend(context)
    for item in selected:
        if item.stage == "telemetry" or not start <= item.observed_at < end:
            continue
        events.append({"at": iso_utc(item.observed_at), "kind": "probe",
                       "scope": scope(item.labels, local_vantages), "vantage": item.labels.vantage,
                       "network": item.labels.network, "stage": item.stage, "method": item.method,
                       "outcome": item.outcome, "reason": item.reason,
                       "egress_verified": item.egress_verified})
    events.sort(key=lambda row: timestamp(row["at"]))
    return {"run": run, "target": target, "start": iso_utc(start), "end": iso_utc(end),
            "attribution": "unestablished", "udp_coverage": udp_coverage,
            "udp_streams": streams, "events": events}
