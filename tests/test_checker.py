import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from tspu_checker.adapters.hysteria2 import adapt
from tspu_checker.https import check
from tspu_checker.model import Labels, Observation, timestamp
from tspu_checker.report import summarize

NOW = timestamp("2030-01-01T10:05:00Z")
WIFI = Labels("test-run", "edge", "phone-wifi", "wifi-isp", "client")
OTHER_WIFI = replace(WIFI, vantage="laptop")
LTE = Labels("test-run", "edge", "phone-lte", "mobile-isp", "client")
SERVER = Labels("test-run", "edge", "entry", "server-segment", "server")


def record(labels, stage, outcome, seconds_ago=0, *, attempt="try-a", reason="test",
           profile="test-profile", method="test", source="manual"):
    return Observation(
        labels, NOW - timedelta(seconds=seconds_ago), stage, method, outcome, reason,
        attempt=attempt, profile=profile if stage in ("session", "tunnel") else None, source=source,
        egress_verified=stage in ("tunnel", "egress") and outcome == "pass" and source != "legacy",
    )


def assess(rows, window=600, *, skew=120):
    report, = summarize(rows, window, as_of=NOW, control_skew=skew)
    return report


def controls():
    return [
        record(WIFI, "baseline", "pass", 100, attempt="try-a"),
        record(WIFI, "baseline", "pass", 40, attempt="try-b"),
        record(LTE, "session", "pass", 50),
        record(LTE, "tunnel", "pass", 40),
        record(SERVER, "ingress", "pass", 50),
        record(SERVER, "egress", "pass", 55),
    ]


def failures(**changes):
    return [
        record(WIFI, "tunnel", "fail", 95, attempt="try-a", **{"reason": "client_timeout", **changes}),
        record(WIFI, "tunnel", "fail", 30, attempt="try-b", **{"reason": "client_timeout", **changes}),
    ]


def sample(begin, end, metrics, vantage=SERVER):
    return Observation(
        vantage, NOW + timedelta(seconds=end), "telemetry", "udp_counter", "observed", "udp_window",
        metrics, source="journal", window_start=NOW + timedelta(seconds=begin),
    )


class ReportTests(unittest.TestCase):
    def test_comparable_failures_and_controls_localize_the_client_path(self):
        data = assess(controls() + failures())
        self.assertEqual(data["result"], "client_path_issue_suspected")
        self.assertEqual(data["suspected_client_paths"][0]["network"], "wifi-isp")
        self.assertEqual(data["suspected_client_paths"][0]["distinct_attempts"], 2)
        self.assertEqual(data["attribution"], "unestablished")

    def test_control_from_another_device_does_not_verify_wifi_attempt(self):
        data = [replace(item, labels=OTHER_WIFI) if item.labels == WIFI else item for item in controls()]
        self.assertEqual(assess(data + failures())["result"], "client_failures_need_controls")

    def test_same_attempt_at_two_timestamps_is_not_a_retry(self):
        first, second = failures()
        data = controls() + [first, replace(second, attempt=first.attempt)]
        self.assertEqual(assess(data)["suspected_client_paths"], [])

    def test_two_attempt_labels_at_identical_time_do_not_verify_repetition(self):
        first, second = failures()
        data = controls() + [first, replace(second, observed_at=first.observed_at)]
        self.assertEqual(assess(data)["suspected_client_paths"], [])

    def test_same_vantage_must_use_same_profile_and_method(self):
        for field, value in (("method", "different-method"), ("profile", "other-profile"), ("source", "probe")):
            data = [replace(item, **{field: value}) if item.labels == LTE else item for item in controls()]
            with self.subTest(field=field):
                self.assertEqual(assess(data + failures())["suspected_client_paths"], [])

    def test_one_early_success_does_not_confirm_both_failure_controls(self):
        self.assertEqual(assess(controls() + failures(), skew=45)["suspected_client_paths"], [])

    def test_tls_failure_is_not_a_path_failure_signal(self):
        data = assess(controls() + failures(reason="certificate_verification_failed"))
        self.assertEqual(data["result"], "client_failures_need_controls")
        self.assertEqual(data["suspected_client_paths"], [])

    def test_unverified_server_egress_does_not_support_suspicion(self):
        data = [replace(item, source="legacy", egress_verified=False)
                if item.stage == "egress" else item for item in controls()]
        self.assertEqual(assess(data + failures())["suspected_client_paths"], [])

    def test_conflicting_server_control_blocks_classification(self):
        data = controls() + failures() + [record(SERVER, "ingress", "fail", 32, attempt="try-b")]
        self.assertEqual(assess(data)["suspected_client_paths"], [])

    def test_verified_route_without_fresh_session_is_not_reachability_proof(self):
        outcome = record(WIFI, "tunnel", "pass", 20)
        late_session = record(WIFI, "session", "pass", 10)
        unrelated_session = replace(late_session, attempt="other-attempt", observed_at=outcome.observed_at)
        for data in ([outcome], [outcome, late_session], [outcome, unrelated_session]):
            self.assertEqual(assess(data)["working_client_networks"], [])

    def test_conflicting_outcomes_in_one_tunnel_attempt_do_not_confirm_reachability(self):
        proof = record(WIFI, "tunnel", "pass", 10)
        failure = record(WIFI, "tunnel", "fail", 11, reason="timeout")
        self.assertEqual(
            assess([record(WIFI, "session", "pass", 12), proof, failure])["working_client_networks"], []
        )

    def test_future_unknown_does_not_displace_valid_records(self):
        future = record(WIFI, "tunnel", "unknown", -7200)
        report = assess(controls() + failures() + [future])
        self.assertEqual(report["result"], "client_path_issue_suspected")
        self.assertEqual(report["future_checks"], 1)

    def test_stale_successes_are_not_current(self):
        row = record(WIFI, "tunnel", "pass", 7200)
        self.assertEqual(assess([row])["checks_outside_window"], 1)
        self.assertEqual(assess([row])["result"], "no_comparable_client_result")

    def test_ingress_and_egress_client_results_remain_visible(self):
        control = [record(WIFI, "ingress", "fail"), record(WIFI, "egress", "pass")]
        stages = assess(control)["client_checks"][0]["stages"]
        self.assertEqual(stages, {"egress": ["pass"], "ingress": ["fail"]})

    def test_v1_observations_are_read_as_legacy_only(self):
        row = record(WIFI, "tunnel", "pass")
        data = row.as_dict()
        data["schema"] = 1
        restored = Observation.from_dict(data)
        self.assertEqual(restored.source, "legacy")
        self.assertFalse(restored.egress_verified)
        self.assertEqual(assess([restored])["legacy_checks_in_window"], 1)
        self.assertEqual(assess([restored])["working_client_networks"], [])

    def test_telemetry_coverage_handles_gaps_duplicates_conflicts_and_overlap(self):
        known = {"observer_drops": 0, "unmeasured_lengths": 0}
        first = sample(-180, -120, known)
        conflicting = sample(-180, -120, {"observer_drops": 3, "unmeasured_lengths": 0})
        rows = [
            sample(-240, -180, known), first, first, conflicting,
            sample(-140, -80, known), sample(-50, -20, {"observer_drops": 0}), sample(-10, 20, known),
        ]
        telemetry = assess(rows, 180)["telemetry"]
        stream, = telemetry["streams"]
        self.assertEqual(telemetry["outside_window_samples"], 1)
        self.assertEqual(telemetry["future_samples"], 1)
        self.assertEqual(stream["windows"], 3)
        self.assertEqual(stream["duplicate_samples"], 1)
        self.assertEqual(stream["conflicting_windows"], 1)
        self.assertEqual(stream["overlapping_windows"], 1)
        self.assertEqual(stream["uncovered_ms"], 50000)
        self.assertEqual(stream["unknown_quality_windows"], 2)
        self.assertEqual(stream["incomplete_windows"], 1)

    def test_telemetry_only_cannot_set_client_path_outcome(self):
        report = assess([sample(-60, 0, {"observer_drops": 4})])
        self.assertEqual(report["result"], "no_comparable_client_result")
        self.assertEqual(report["telemetry"]["streams"][0]["incomplete_windows"], 1)

    def test_experimental_sample(self):
        with Path("examples/observations.jsonl").open() as data:
            rows = [Observation.from_dict(json.loads(line)) for line in data]
        report = assess(rows)
        self.assertEqual(report["attribution"], "unestablished")
        self.assertEqual(report["result"], "client_path_issue_suspected")


class AdapterTests(unittest.TestCase):
    units = {"tunnel.service": "tunnel", "web.service": "http3", "udp.service": "telemetry"}
    prefix = {"__REALTIME_TIMESTAMP": "1893492300000000", "_SYSTEMD_INVOCATION_ID": "a" * 32}

    def event(self, unit, message, labels=SERVER, **fields):
        entry = {**self.prefix, "_SYSTEMD_UNIT": unit, "MESSAGE": message, "PRIVATE": "ignored", **fields}
        return adapt(labels, entry, self.units, "test-profile")

    def test_hysteria_success_produces_route_and_session_evidence(self):
        events = self.event("tunnel.service", "hysteria_check=passed https_via_e1=True udp_dns=True")
        self.assertEqual([(row.stage, row.outcome) for row in events], [("session", "pass"), ("tunnel", "pass")])
        self.assertEqual(events[0].attempt, events[1].attempt)
        self.assertEqual(events[1].source, "journal")
        self.assertTrue(events[1].egress_verified)
        self.assertNotIn("PRIVATE", events[0].as_dict())

    def test_unknown_unit_and_wrong_message_family_are_ignored(self):
        self.assertEqual(self.event("other.service", "hysteria_check=passed https_via_e1=True udp_dns=True"), [])
        self.assertEqual(self.event("tunnel.service", "http3_status=200 html=True body_matches=True"), [])

    def test_journal_roles_are_restricted(self):
        with self.assertRaises(ValueError):
            self.event("tunnel.service", "hysteria_check=passed https_via_e1=True udp_dns=True", WIFI)

    def test_active_event_requires_traceable_invocation(self):
        with self.assertRaises(ValueError):
            self.event("web.service", "http3_error=TimeoutError", _SYSTEMD_INVOCATION_ID=None)

    def test_missing_account_is_unknown_and_keeps_reason(self):
        session, = self.event("tunnel.service", "hysteria_check=failed step=hysteria_client reason=test_account_unavailable")
        self.assertEqual((session.outcome, session.reason), ("unknown", "test_account_unavailable"))

    def test_distinguishes_https_dns_and_exit_failure(self):
        controls = (
            ("hysteria_check=failed step=https reason=RuntimeError", "https_probe_failed"),
            ("hysteria_check=failed step=udp_dns reason=RuntimeError", "udp_dns_probe_failed"),
            ("hysteria_check=failed https_via_e1=False udp_dns=True", "unexpected_egress"),
        )
        for message, reason in controls:
            with self.subTest(reason=reason):
                session, tunnel = self.event("tunnel.service", message)
                self.assertEqual(session.outcome, "unknown")
                self.assertEqual((tunnel.outcome, tunnel.reason), ("fail", reason))

    def test_http3_distinguishes_local_fixture_and_network_error(self):
        local, = self.event("web.service", "http3_error=local_fixture_unavailable")
        timeout, = self.event("web.service", "http3_error=TimeoutError")
        mismatch, = self.event("web.service", "http3_status=200 html=True body_matches=False")
        self.assertEqual(local.outcome, "unknown")
        self.assertEqual(timeout.reason, "http3_timeout")
        self.assertEqual(mismatch.reason, "http3_body_mismatch")

    def test_telemetry_keeps_window_and_allowlisted_counters_only(self):
        result, = self.event("udp.service",
            "udp443_window_start_utc=2030-01-01T10:00:00Z udp443_window_end_utc=2030-01-01T10:01:00Z "
            "udp_in=19 udp_out=20 udp_in_bytes=5 observer_drops=1 source=private-value")
        self.assertEqual(result.metrics, {"udp_in": 19, "udp_out": 20, "udp_in_bytes": 5, "observer_drops": 1})
        self.assertEqual(result.window_start, timestamp("2030-01-01T10:00:00Z"))


class HTTPSTests(unittest.TestCase):
    @patch("tspu_checker.https.http.client.HTTPSConnection")
    def test_tunnel_and_egress_require_expected_ip_before_network_io(self, connection):
        for stage in ("tunnel", "egress"):
            with self.assertRaisesRegex(ValueError, "require --expect-ip"):
                check(WIFI, stage, "https://check.example.org/", 5, None, attempt="try-a", profile="profile-a")
        connection.assert_not_called()

    @patch("tspu_checker.https.http.client.HTTPSConnection")
    def test_expected_exit_does_not_expose_ip_or_url(self, connection):
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.read.return_value = b"192.0.2.10\n"
        result = check(WIFI, "tunnel", "https://check.example.org/", 5, "192.0.2.10", attempt="try-a", profile="profile-a")
        self.assertEqual((result.outcome, result.egress_verified), ("pass", True))
        self.assertNotIn("192.0.2.10", json.dumps(result.as_dict()))
        self.assertNotIn("example.org", json.dumps(result.as_dict()))

    @patch("tspu_checker.https.http.client.HTTPSConnection")
    def test_redirect_does_not_pass_control(self, connection):
        connection.return_value.getresponse.return_value.status = 302
        result = check(WIFI, "baseline", "https://check.example.org/", 5, None, attempt="try-a")
        self.assertEqual(result.outcome, "fail")

    def test_non_https_and_embedded_credentials_are_rejected(self):
        for url in ("http://check.example.org/", "https://alice:secret@check.example.org/"):
            with self.assertRaises(ValueError):
                check(WIFI, "baseline", url, 5, None, attempt="try-a")


class CLITests(unittest.TestCase):
    def run_cli(self, *args, supplied=""):
        return subprocess.run(
            [sys.executable, "-B", "-m", "tspu_checker", *args], input=supplied, text=True, capture_output=True,
        )

    def test_invalid_jsonl_diagnostic_does_not_echo_line(self):
        outcome = self.run_cli("report", supplied="private-value\n")
        self.assertEqual(outcome.returncode, 2)
        self.assertIn("line 1", outcome.stderr)
        self.assertNotIn("private-value", outcome.stderr)

    def test_empty_expected_units_are_disclosed(self):
        outcome = self.run_cli("import-hysteria2", "--run", "fixture", "--target", "edge", "--role", "server",
                               "--vantage", "host", "--network", "host-net", "--http3-unit", "http3.service")
        self.assertEqual(outcome.returncode, 2)
        self.assertEqual(outcome.stdout, "")
        self.assertIn("units_without_results=1", outcome.stderr)

    def test_manual_tunnel_positive_requires_observed_and_expected_ip(self):
        arguments = ("record", "--run", "fixture", "--target", "edge", "--role", "client", "--vantage", "phone",
                     "--network", "wifi-isp", "--stage", "tunnel", "--outcome", "pass",
                     "--profile", "example", "--attempt", "try-a", "--expect-ip", "192.0.2.10")
        self.assertEqual(self.run_cli(*arguments).returncode, 2)
        result = self.run_cli(*arguments, "--observed-ip", "192.0.2.10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["egress_verified"])
        self.assertNotIn("192.0.2.", result.stdout)


if __name__ == "__main__":
    unittest.main()
