#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for eve_processor.py: rotation handling, offset tracking, and row building."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import eve_processor as ep


COMMON_MAP = {
    "common": {
        "timestamp": ["timestamp"],
        "event_type": ["event_type"],
        "src_ip": ["src_ip"],
        "src_port": ["src_port"],
        "dest_ip": ["dest_ip"],
        "dest_port": ["dest_port"],
        "clientIp": [],
        "clientPort": [],
        "serverIp": [],
        "serverPort": [],
    },
    "ldap": {
        "ldap_bind_result_code": ["ldap", "responses", 0, "bind_response", "result_code"],
    },
}
COLUMNS = ["timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "clientIp", "clientPort", "serverIp", "serverPort", "ldap_bind_result_code"]
COLS_IDXS = [2, 4, 3, 5, 8, 6, 9, 7]


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def dumps(ev):
    # Match Suricata's own eve.json serialization: no whitespace around separators.
    return json.dumps(ev, separators=(",", ":"))


def make_event(event_type="anomaly", **extra):
    ev = {
        "timestamp": "2026-09-18T10:00:00.000000+0000",
        "event_type": event_type,
        "src_ip": "10.0.0.1",
        "src_port": 5000,
        "dest_ip": "10.0.0.2",
        "dest_port": 80,
    }
    ev.update(extra)
    return ev


class TestRotation:
    def test_copytruncate_same_inode_smaller_size_is_rotation(self, tmp_path):
        p = tmp_path / "eve.json"
        write_lines(p, [dumps(make_event())] * 10)
        st = os.stat(p)
        prev_state = {"dev": st.st_dev, "inode": st.st_ino, "offset": st.st_size, "size": st.st_size}

        # Truncate in place (copytruncate): same inode, smaller size.
        write_lines(p, [dumps(make_event())])
        st2 = os.stat(p)

        assert ep.is_rotation(prev_state, st2) is True

    def test_create_new_inode_is_rotation(self, tmp_path):
        p = tmp_path / "eve.json"
        write_lines(p, [dumps(make_event())])
        st = os.stat(p)
        prev_state = {"dev": st.st_dev, "inode": st.st_ino, "offset": st.st_size, "size": st.st_size}

        p.unlink()
        write_lines(p, [dumps(make_event())])
        st2 = os.stat(p)

        assert ep.is_rotation(prev_state, st2) is True

    def test_no_rotation_when_file_grew_in_place(self, tmp_path):
        p = tmp_path / "eve.json"
        write_lines(p, [dumps(make_event())])
        st = os.stat(p)
        prev_state = {"dev": st.st_dev, "inode": st.st_ino, "offset": st.st_size, "size": st.st_size}

        with open(p, "a", encoding="utf-8") as f:
            f.write(dumps(make_event()) + "\n")
        st2 = os.stat(p)

        assert ep.is_rotation(prev_state, st2) is False

    def test_full_rotation_tail_read_no_loss_no_duplication(self, tmp_path):
        old_path = tmp_path / "eve.json"
        cfg = {"event_types": ["anomaly"], "filter_keys": {}, "suricata_eve_json_path": str(old_path)}
        write_lines(old_path, [dumps(make_event()) for _ in range(5)])
        st = os.stat(old_path)
        state = {"dev": st.st_dev, "inode": st.st_ino, "offset": 0, "size": 0, "last_timestamp": None}

        # First run: consume all 5 lines from the old file.
        columns, column_map, cols_idxs = COLUMNS, COMMON_MAP, COLS_IDXS
        rows, counts, state = ep.process_log_file(cfg, columns, column_map, cols_idxs, {}, state)
        assert counts["processed"] == 5

        # Rotate: old file -> eve.json.1 (create-style rotation), write 3 new lines to eve.json.
        rotated_path = tmp_path / "eve.json.1"
        os.rename(old_path, rotated_path)
        write_lines(old_path, [dumps(make_event()) for _ in range(3)])

        rows, counts, state = ep.process_log_file(cfg, columns, column_map, cols_idxs, {}, state)
        # All 5 old-file lines were already consumed before rotation; only the 3 new lines are new.
        assert counts["processed"] == 3

    def test_copytruncate_rotation_tail_read(self, tmp_path):
        path = tmp_path / "eve.json"
        cfg = {"event_types": ["anomaly"], "filter_keys": {}, "suricata_eve_json_path": str(path)}
        write_lines(path, [dumps(make_event()) for _ in range(4)])
        st = os.stat(path)
        state = {"dev": st.st_dev, "inode": st.st_ino, "offset": 0, "size": 0, "last_timestamp": None}

        columns, column_map, cols_idxs = COLUMNS, COMMON_MAP, COLS_IDXS
        rows, counts, state = ep.process_log_file(cfg, columns, column_map, cols_idxs, {}, state)
        assert counts["processed"] == 4

        # copytruncate: logrotate copies eve.json to eve.json.1, then truncates eve.json in place (same inode).
        rotated_path = tmp_path / "eve.json.1"
        write_lines(rotated_path, [dumps(make_event()) for _ in range(4)])
        # os.replace with truncate to simulate in-place truncation, same inode preserved via open("w")
        with open(path, "w", encoding="utf-8") as f:
            pass
        write_lines(path, [dumps(make_event()) for _ in range(2)])

        rows, counts, state = ep.process_log_file(cfg, columns, column_map, cols_idxs, {}, state)
        assert counts["processed"] == 2


class TestIncompleteLine:
    def test_incomplete_last_line_not_consumed(self, tmp_path):
        path = tmp_path / "eve.json"
        complete = dumps(make_event())
        with open(path, "w", encoding="utf-8") as f:
            f.write(complete + "\n")
            f.write('{"event_type": "anomaly", "incomplete')  # no trailing newline

        lines, new_offset = ep.read_new_lines(str(path), 0)
        assert lines == [complete]
        assert new_offset == len(complete) + 1

    def test_incomplete_line_completed_next_cycle(self, tmp_path):
        path = tmp_path / "eve.json"
        complete = dumps(make_event())
        with open(path, "w", encoding="utf-8") as f:
            f.write(complete + "\n")
            f.write('{"partial"')

        lines, offset = ep.read_new_lines(str(path), 0)
        assert len(lines) == 1

        with open(path, "a", encoding="utf-8") as f:
            f.write(': "now complete"}\n')

        lines2, offset2 = ep.read_new_lines(str(path), offset)
        assert len(lines2) == 1
        parsed = json.loads(lines2[0])
        assert parsed["partial"] == "now complete"


class TestFlatten:
    def test_flatten_list_to_comma_string(self):
        assert ep.flatten_value(["a", "b", "c"]) == "a,b,c"

    def test_flatten_bool_true(self):
        assert ep.flatten_value(True) == "true"

    def test_flatten_bool_false(self):
        assert ep.flatten_value(False) == "false"

    def test_flatten_dict_to_none(self):
        assert ep.flatten_value({"nested": "value"}) is None

    def test_flatten_scalar_passthrough(self):
        assert ep.flatten_value("plain") == "plain"
        assert ep.flatten_value(42) == 42
        assert ep.flatten_value(None) is None


class TestResolvePath:
    def test_list_index_in_path(self):
        ev = {"ldap": {"responses": [{"bind_response": {"result_code": "success"}}]}}
        path = ["ldap", "responses", 0, "bind_response", "result_code"]
        assert ep.resolve_path(ev, path) == "success"

    def test_list_index_out_of_range_returns_none(self):
        ev = {"ldap": {"responses": []}}
        path = ["ldap", "responses", 0, "bind_response", "result_code"]
        assert ep.resolve_path(ev, path) is None

    def test_missing_dict_key_returns_none(self):
        ev = {"ldap": {}}
        path = ["ldap", "request", "operation"]
        assert ep.resolve_path(ev, path) is None

    def test_index_path_segment_on_non_list_returns_none(self):
        ev = {"ldap": {"responses": "not-a-list"}}
        path = ["ldap", "responses", 0]
        assert ep.resolve_path(ev, path) is None


class TestBackwardCompat70:
    def test_70_style_event_missing_80_fields_does_not_raise(self):
        # Suricata 7.0 tls event has no ja4/client_alpns/subjectaltname.
        ev = make_event(event_type="tls")
        ev["tls"] = {"subject": "CN=example.com", "version": "TLS 1.3"}

        column_map = {
            "common": COMMON_MAP["common"],
            "tls": {
                "tls_ja4": ["tls", "ja4"],
                "tls_client_alpns": ["tls", "client_alpns"],
                "tls_subjectaltname": ["tls", "subjectaltname"],
            },
        }
        columns = COLUMNS + ["tls_ja4", "tls_client_alpns", "tls_subjectaltname"]

        row = ep.build_row(ev, columns, column_map, COLS_IDXS, {})
        assert row[columns.index("tls_ja4")] is None
        assert row[columns.index("tls_client_alpns")] is None
        assert row[columns.index("tls_subjectaltname")] is None

    def test_should_process_missing_filter_field_rejects_gracefully(self):
        cfg = {"event_types": ["alert"], "filter_keys": {"alert": ["alert", "signature_id"]}}
        ev = make_event(event_type="alert")  # no "alert" key at all (malformed/old-style)
        ok, dt = ep.should_process(ev, cfg, None)
        assert ok is False


class TestGenericFilter:
    def test_blacklist_rejects_configured_value(self):
        cfg = {
            "event_types": ["smb"],
            "filter_keys": {"smb": ["smb", "command"]},
            "smb_blacklist_set": {"SMB2_COMMAND_CREATE"},
        }
        ev = make_event(event_type="smb", smb={"command": "SMB2_COMMAND_CREATE"})
        ok, dt = ep.should_process(ev, cfg, None)
        assert ok is False

    def test_blacklist_allows_unlisted_value(self):
        cfg = {
            "event_types": ["smb"],
            "filter_keys": {"smb": ["smb", "command"]},
            "smb_blacklist_set": {"SMB2_COMMAND_CREATE"},
        }
        ev = make_event(event_type="smb", smb={"command": "SMB2_COMMAND_READ"})
        ok, dt = ep.should_process(ev, cfg, None)
        assert ok is True

    def test_whitelist_takes_precedence_over_blacklist(self):
        cfg = {
            "event_types": ["smb"],
            "filter_keys": {"smb": ["smb", "command"]},
            "smb_whitelist_set": {"SMB2_COMMAND_CREATE"},
            "smb_blacklist_set": {"SMB2_COMMAND_CREATE"},
        }
        ev = make_event(event_type="smb", smb={"command": "SMB2_COMMAND_CREATE"})
        ok, dt = ep.should_process(ev, cfg, None)
        assert ok is True


class TestPoisonPillTimestamp:
    """
    A malformed timestamp must reject the event, not crash the run - a
    crash here means save_state() is never reached, so the offset never
    advances past the bad line and every subsequent cycle re-reads and
    re-crashes on the exact same line forever.
    """

    def test_malformed_timestamp_string_does_not_raise(self):
        cfg = {"event_types": ["anomaly"], "filter_keys": {}}
        ev = make_event(event_type="anomaly")
        ev["timestamp"] = "not-a-timestamp-at-all"
        ok, dt = ep.should_process(ev, cfg, None)
        assert ok is False
        assert dt is None

    def test_truncated_timestamp_does_not_raise(self):
        # Simulates a write cut short by e.g. a full disk.
        cfg = {"event_types": ["anomaly"], "filter_keys": {}}
        ev = make_event(event_type="anomaly")
        ev["timestamp"] = "2026-09-18T10:0"
        ok, dt = ep.should_process(ev, cfg, None)
        assert ok is False

    def test_poison_pill_line_does_not_stop_processing_of_later_lines(self, tmp_path):
        path = tmp_path / "eve.json"
        good_before = make_event(event_type="anomaly")
        bad = make_event(event_type="anomaly")
        bad["timestamp"] = "garbage"
        good_after = make_event(event_type="anomaly")
        write_lines(path, [dumps(good_before), dumps(bad), dumps(good_after)])

        cfg = {"event_types": ["anomaly"], "filter_keys": {}, "suricata_eve_json_path": str(path)}
        rows, counts, new_offset, max_dt = ep.process_file_from(
            str(path), 0, cfg, COLUMNS, COMMON_MAP, COLS_IDXS, {}, ep.build_prefilter_needles(["anomaly"])
        )
        assert counts["processed"] == 2
        assert counts["skipped"] == 1
        # Offset must still advance past all three lines - the bad line
        # must not wedge processing at its own byte offset.
        assert new_offset == len(dumps(good_before)) + 1 + len(dumps(bad)) + 1 + len(dumps(good_after)) + 1

    def test_non_dict_event_does_not_raise(self):
        # A value that survived JSON parsing but isn't a dict (defensive
        # case - should_process must not crash regardless of how it got
        # here, e.g. a future orjson edge case or a non-object top-level
        # JSON value that still passed the raw-string prefilter).
        cfg = {"event_types": ["anomaly"], "filter_keys": {}}
        ok, dt = ep.should_process(["not", "a", "dict"], cfg, None)
        assert ok is False


class TestAtomicSaveState:
    def test_save_state_is_atomic_no_partial_file_left_on_disk(self, tmp_path):
        path = tmp_path / "state.json"
        ep.save_state(str(path), {"dev": 1, "inode": 2, "offset": 3, "size": 3})

        assert path.exists()
        assert not (tmp_path / "state.json.tmp").exists()
        with open(path) as f:
            assert json.load(f) == {"dev": 1, "inode": 2, "offset": 3, "size": 3}

    def test_corrupt_state_file_is_treated_as_missing_not_fatal(self, tmp_path):
        path = tmp_path / "state.json"
        with open(path, "w") as f:
            f.write('{"dev": 1, "inode": 2, "offset":')  # truncated JSON

        assert ep.load_state(str(path)) is None


class TestReadCap:
    def test_read_new_lines_respects_max_bytes_cap(self, tmp_path):
        path = tmp_path / "eve.json"
        lines = [dumps(make_event()) for _ in range(20)]
        write_lines(path, lines)
        full_size = os.path.getsize(path)

        # Cap smaller than the full file - must return a strict subset and
        # an offset short of full_size, never read past the cap.
        cap = full_size // 2
        got_lines, new_offset = ep.read_new_lines(str(path), 0, max_bytes=cap)
        assert new_offset <= cap
        assert new_offset < full_size
        assert len(got_lines) < len(lines)

    def test_capped_backlog_drains_fully_across_multiple_calls(self, tmp_path):
        path = tmp_path / "eve.json"
        lines = [dumps(make_event()) for _ in range(50)]
        write_lines(path, lines)
        full_size = os.path.getsize(path)

        offset = 0
        total_lines = 0
        cap = max(1, full_size // 10)
        for _ in range(30):  # generous bound on cycles needed
            got_lines, offset = ep.read_new_lines(str(path), offset, max_bytes=cap)
            total_lines += len(got_lines)
            if offset >= full_size:
                break
        assert total_lines == len(lines)
        assert offset == full_size


class TestMultiLevelRotation:
    def test_finds_match_two_rotations_back(self, tmp_path):
        eve_path = tmp_path / "eve.json"
        write_lines(eve_path, [dumps(make_event())])
        st = os.stat(eve_path)

        # Simulate: the tracked file got moved to .1, then .2 by two
        # logrotate cycles, and a fresh eve.json (and .1) were created.
        rotated_2 = tmp_path / "eve.json.2"
        os.rename(eve_path, rotated_2)
        write_lines(tmp_path / "eve.json.1", [dumps(make_event())])
        write_lines(eve_path, [dumps(make_event())])

        match_path, match_stat = ep.find_matching_rotated_file(str(eve_path), st.st_dev, st.st_ino)
        assert match_path == str(rotated_2)

    def test_no_match_within_depth_returns_none(self, tmp_path):
        eve_path = tmp_path / "eve.json"
        write_lines(eve_path, [dumps(make_event())])
        match_path, match_stat = ep.find_matching_rotated_file(str(eve_path), dev=999999, inode=999999)
        assert match_path is None

    def test_multi_rotation_backlog_no_loss_no_duplication(self, tmp_path):
        eve_path = tmp_path / "eve.json"
        cfg = {"event_types": ["anomaly"], "filter_keys": {}, "suricata_eve_json_path": str(eve_path)}
        columns, column_map, cols_idxs = COLUMNS, COMMON_MAP, COLS_IDXS

        # Cycle 1: consume 2 lines from the original file.
        write_lines(eve_path, [dumps(make_event()) for _ in range(2)])
        st = os.stat(eve_path)
        state = {"dev": st.st_dev, "inode": st.st_ino, "offset": 0, "size": 0, "last_timestamp": None}
        rows, counts, state = ep.process_log_file(cfg, columns, column_map, cols_idxs, {}, state)
        assert counts["processed"] == 2

        # Two logrotate cycles happen while the processor is "down":
        # original file -> .2, a new file (3 lines) becomes .1, and a
        # fresh eve.json (2 lines) is current.
        os.rename(eve_path, tmp_path / "eve.json.2")
        write_lines(tmp_path / "eve.json.1", [dumps(make_event()) for _ in range(3)])
        write_lines(eve_path, [dumps(make_event()) for _ in range(2)])

        rows, counts, state = ep.process_log_file(cfg, columns, column_map, cols_idxs, {}, state)
        # All events across .1 (3) and the new current file (2) are new;
        # the 2 already consumed from the original (.2) file are not
        # re-read.
        assert counts["processed"] == 5

        # No pending backlog should remain once everything is drained.
        assert "pending_backlog" not in state or not state["pending_backlog"]
