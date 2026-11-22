"""Describe telemetry coverage without adding overlapping counters."""

from collections import defaultdict
from datetime import datetime, timedelta

from .model import Observation

QUALITY_METRICS = {"observer_drops", "unmeasured_lengths"}
MILLISECOND = timedelta(milliseconds=1)


def coverage(samples: list[Observation], start: datetime, end: datetime) -> dict:
    streams = defaultdict(list)
    missing_bounds = outside = future = 0
    for sample in samples:
        if sample.observed_at > end:
            future += 1
        elif sample.observed_at <= start:
            outside += 1
        elif sample.window_start is None:
            missing_bounds += 1
        else:
            streams[sample.labels.network, sample.labels.vantage, sample.method].append(sample)

    summaries = []
    for (network, vantage, method), stream in sorted(streams.items()):
        windows = defaultdict(list)
        for sample in stream:
            windows[sample.window_start, sample.observed_at].append(sample)

        duplicates = conflicts = overlaps = incomplete = unknown_quality = 0
        covered = timedelta()
        cursor = start
        for (begin, finish), records in sorted(windows.items()):
            variants = {tuple(sorted(sample.metrics.items())) for sample in records}
            duplicates += len(records) - len(variants)
            conflicts += len(variants) > 1
            if any(sample.metrics.get(key, 0) for sample in records for key in QUALITY_METRICS):
                incomplete += 1
            if len(variants) > 1 or any(QUALITY_METRICS - sample.metrics.keys() for sample in records):
                unknown_quality += 1
            bounded_start = max(begin, start)
            overlaps += bounded_start < cursor
            if finish > cursor:
                covered += finish - max(bounded_start, cursor)
                cursor = finish

        summaries.append({
            "network": network,
            "vantage": vantage,
            "method": method,
            "windows": len(windows),
            "duplicate_samples": duplicates,
            "conflicting_windows": conflicts,
            "overlapping_windows": overlaps,
            "uncovered_ms": (end - start - covered) // MILLISECOND,
            "incomplete_windows": incomplete,
            "unknown_quality_windows": unknown_quality,
        })

    return {
        "status": "measured" if summaries else "unavailable",
        "streams": summaries,
        "outside_window_samples": outside,
        "future_samples": future,
        "missing_bounds_samples": missing_bounds,
    }
