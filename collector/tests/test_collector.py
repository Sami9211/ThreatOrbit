"""Collector core: tailing, checkpointing, rotation, batching, at-least-once.

These pin the durability contract that makes the agent enterprise-safe — a
restart never re-ships or drops a line, a rotation resets cleanly, and a failed
ship leaves the checkpoint untouched so the batch is retried.
"""
import importlib.util
import os
import pathlib

# Import the single-file agent without packaging it.
_MOD = pathlib.Path(__file__).resolve().parents[1] / "threatorbit_collector.py"
_spec = importlib.util.spec_from_file_location("threatorbit_collector", _MOD)
tc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tc)


def test_read_new_lines_leaves_partial(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("line1\nline2\npartial-no-newline")
    lines, offset, inode = tc.read_new_lines(str(f), 0, 100)
    assert lines == ["line1", "line2"]            # partial line withheld
    assert offset == len("line1\nline2\n")
    # appending the rest of the partial line completes it on the next read
    with open(f, "a") as fh:
        fh.write("-now-done\n")
    lines2, offset2, _ = tc.read_new_lines(str(f), offset, 100)
    assert lines2 == ["partial-no-newline-now-done"]
    assert offset2 == f.stat().st_size


def test_read_respects_batch_cap(tmp_path):
    f = tmp_path / "b.log"
    f.write_text("".join(f"l{i}\n" for i in range(10)))
    lines, _, _ = tc.read_new_lines(str(f), 0, 3)
    assert lines == ["l0", "l1", "l2"]


def test_checkpoint_persist_resume_and_rotation(tmp_path):
    state = tmp_path / "state.json"
    cp = tc.Checkpoint(str(state))
    cp.set("/var/log/x", inode=111, offset=42)
    cp.save()
    # reload from disk → resumes
    cp2 = tc.Checkpoint(str(state))
    assert cp2.offset_for("/var/log/x", inode=111) == 42
    # rotation: a new inode means start from the top
    assert cp2.offset_for("/var/log/x", inode=222) == 0
    # truncation handled in read_new_lines (offset > size → 0)


def test_run_pass_ships_and_advances(tmp_path):
    f = tmp_path / "c.log"
    f.write_text("a\nb\nc\n")
    cp = tc.Checkpoint(str(tmp_path / "s.json"))
    shipped_batches = []

    class FakeShipper:
        def ship(self, lines):
            shipped_batches.append(list(lines))

    n = tc.run_pass([str(f)], cp, FakeShipper(), batch=500, dry_run=False, log=lambda *_: None)
    assert n == 3 and shipped_batches == [["a", "b", "c"]]
    # checkpoint advanced to EOF → a second pass ships nothing
    n2 = tc.run_pass([str(f)], cp, FakeShipper(), batch=500, dry_run=False, log=lambda *_: None)
    assert n2 == 0


def test_run_pass_failure_does_not_advance(tmp_path):
    f = tmp_path / "d.log"
    f.write_text("x\ny\n")
    state = tmp_path / "s.json"
    cp = tc.Checkpoint(str(state))

    class FailingShipper:
        def ship(self, lines):
            raise tc.urllib.error.URLError("connection refused")

    n = tc.run_pass([str(f)], cp, FailingShipper(), batch=500, dry_run=False, log=lambda *_: None)
    assert n == 0
    # checkpoint NOT advanced → next pass with a working shipper re-ships (at-least-once)
    got = []

    class OkShipper:
        def ship(self, lines):
            got.append(list(lines))

    cp2 = tc.Checkpoint(str(state))
    tc.run_pass([str(f)], cp2, OkShipper(), batch=500, dry_run=False, log=lambda *_: None)
    assert got == [["x", "y"]]


def test_discover_globs_and_dedup(tmp_path):
    (tmp_path / "one.log").write_text("")
    (tmp_path / "two.log").write_text("")
    (tmp_path / "skip.txt").write_text("")
    found = tc.discover([str(tmp_path / "*.log"), str(tmp_path / "one.log")])
    assert found == sorted([str(tmp_path / "one.log"), str(tmp_path / "two.log")])


def test_ssl_context_selection(tmp_path):
    assert tc.build_ssl_context(None, None, None, False) is None      # plain http
    ctx = tc.build_ssl_context(None, None, None, True)                # insecure lab
    assert ctx is not None and ctx.verify_mode == __import__("ssl").CERT_NONE
