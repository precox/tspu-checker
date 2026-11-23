import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

from tspu_checker.incident import journal_timeline, session_timeline, udp_spans
from tspu_checker.model import timestamp

START = timestamp("2030-01-01T10:00:00Z")
END = timestamp("2030-01-01T10:05:00Z")


class IncidentTests(unittest.TestCase):
    def test_coverage_flags_loss_overlaps_and_conflicting_windows(self):
        one = timestamp("2030-01-01T10:01:00Z")
        two = timestamp("2030-01-01T10:02:00Z")
        three = timestamp("2030-01-01T10:03:00Z")
        four = timestamp("2030-01-01T10:04:00Z")
        windows = {
            (START, one): {(0, 0, 0, None)},
            (one, two): {(0, 0, 1, None)},
            (two, four): {(0, 0, 0, 0), (1, 1, 0, 0)},
            (three, four): {(0, 0, 0, 0)},
        }
        spans = udp_spans(windows, START, END)
        self.assertEqual([item["status"] for item in spans], ["zero_udp", "unreliable", "missing"])
        self.assertEqual(spans[1]["end"], "2030-01-01T10:04:00Z")

    def test_version_and_close_direction_are_both_required_to_label_kick(self):
        record = '2030-01-01T10:00:01Z TCP error {"error":"Application error 0x107 (local)","id":"private-id"}'
        for version, side, expected in (("2.14.0","local","traffic_stats_kick"),
                                         ("2.14.0","remote","unestablished"),
                                         ("2.13.0","local","unestablished"),
                                         (None,"local","unestablished")):
            with self.subTest(version=version, side=side):
                events, errors = session_timeline(io.StringIO(record.replace("local",side)),version,START,END)
                self.assertEqual(errors, 0)
                self.assertEqual(events[0]["reason"], expected)
                self.assertNotIn("private-id", json.dumps(events))

    def test_remote_no_error_close_keeps_side_and_code(self):
        record = '2030-01-01T10:00:01Z client disconnected {"error":"Application error 0x100 (remote)"}'
        events, errors = session_timeline(io.StringIO(record), "2.14.0", START, END)
        self.assertEqual(errors, 0)
        self.assertEqual([event["kind"] for event in events], ["session_disconnected", "quic_close"])
        self.assertEqual(events[-1]["side"], "remote")
        self.assertEqual(events[-1]["reason"], "application_no_error")

    def test_hui_wraps_colored_hysteria_messages_in_json(self):
        message = (
            '\x1b[32m2030-01-01T10:00:01Z\x1b[0m client connected '
            '{"id":"secret-account","addr":"192.0.2.1:1234"}'
        )
        wrapper = json.dumps({"level": "info", "msg": message, "time": "untrusted-outer-time"})
        events, errors = session_timeline(io.StringIO(wrapper), "2.14.0", START, END)
        self.assertEqual(errors, 0)
        self.assertEqual(events, [{"at": "2030-01-01T10:00:01Z",
                                   "scope": "server_context", "kind": "session_connected"}])

    def test_gateway_uses_allowlist_and_decodes_binary_messages(self):
        message = "\x1b[31merror\x1b[0m dial tcp 192.0.2.1:443: i/o timeout"
        entry = {"MESSAGE":list(message.encode()),"__REALTIME_TIMESTAMP":str(int(START.timestamp())*1000000)}
        rows = [{**entry,"_SYSTEMD_UNIT":name} for name in ("other.service","gateway.service")]
        events, errors = journal_timeline(io.StringIO("\n".join(map(json.dumps,rows))),set(),
                                          {"gateway.service"},START,END)
        self.assertEqual(errors, 0)
        self.assertEqual([event["kind"] for event in events], ["gateway_tcp_timeout"])
        self.assertNotIn("192.0.2.1", json.dumps(events))

    def test_documented_example_distinguishes_scope_and_observation_gaps(self):
        root = Path("examples/incident")
        command = [sys.executable,"-B","-m","tspu_checker","incident",str(root/"observations.jsonl"),
                   "--run","example-incident","--target","vpn-edge",
                   "--start","2030-01-01T10:00:00Z","--end","2030-01-01T10:09:00Z",
                   "--local-vantage","entry","--journal",str(root/"server-journal.jsonl"),
                   "--resource-unit","example-resources.service","--gateway-unit","example-gateway.service",
                   "--hysteria-log",str(root/"hysteria2.log"),"--hysteria-version","2.14.0"]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        report = json.loads(result.stdout)
        self.assertEqual(report["attribution"], "unestablished")
        stream, = report["udp_streams"]
        self.assertEqual([span["status"] for span in stream["spans"]], ["measured","zero_udp","missing","measured"])
        self.assertEqual(stream["spans"][1]["end"], "2030-01-01T10:06:00Z")
        events = report["events"]
        self.assertEqual({e["scope"] for e in events if e["kind"]=="probe"}, {"local_server","client_network"})
        self.assertTrue({"session_connected","session_disconnected","quic_close","resource_window",
                         "gateway_tcp_timeout"} <= {e["kind"] for e in events})
        self.assertNotIn("synthetic-user", result.stdout)
        self.assertNotIn("192.0.2.", result.stdout)
