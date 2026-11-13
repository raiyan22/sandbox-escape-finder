"""End-to-end prober tests.

The task requires "an end-to-end run of the full corpus against
RestrictedPython". These tests exercise the isolated subprocess path against
the real library, and the in-process path against a toy broken sandbox.
"""

from sandbox_escape_finder import CanaryOracle, DynamicProber, make_restricted_exec


def test_end_to_end_real_restrictedpython_blocks_everything():
    """Full corpus vs. real RestrictedPython: nothing should escape.

    This is both an integration test and the experiment that produces the
    report. Against the real, documented sandbox we expect zero escapes.
    """
    prober = DynamicProber(config={"seed": 1})
    report = prober.run()  # isolated subprocess path, built-in corpus

    assert len(report) == 13
    # Report shape: every row carries the required columns.
    for row in report:
        assert set(row) >= {
            "id", "technique", "static_flagged", "compiled",
            "executed", "escaped", "seconds",
        }

    summary = prober.analyze(report)
    assert summary["escaped"] == 0, "real RestrictedPython should block all payloads"
    # No false negatives: nothing escaped that the analyzer failed to flag.
    assert summary["escaped_but_not_flagged"] == []


def test_prober_in_process_with_broken_sandbox_reports_escape(tmp_path):
    """The in-process path with a broken sandbox must report an escape.

    Mirrors the oracle test but drives it through DynamicProber.run(
    isolate=False), proving the prober wires sandbox+oracle together correctly.
    """
    canary = str(tmp_path / "canary.txt")
    broken = make_restricted_exec(extra_globals={"open": open, "CANARY": canary})
    oracle = CanaryOracle(canary)

    prober = DynamicProber(sandbox_exec=broken, oracle=oracle)
    corpus = [{"id": "toy_escape", "technique": "builtins_restoration",
               "source": "test", "code": "open(CANARY, 'w').write('x')"}]
    report = prober.run(corpus, isolate=False)

    assert report[0]["escaped"] is True


def test_custom_payload_via_config_is_included():
    """Payloads added through config.extra_payloads appear in the report."""
    cfg = {"extra_payloads": [{"code": "result = 1", "technique": "import_usage"}]}
    prober = DynamicProber(config=cfg)
    report = prober.run()
    assert any(r["technique"] == "import_usage" and r["id"].startswith("custom")
               for r in report)


def test_run_is_reproducible_with_seed():
    """The same seed yields the same payload ordering (reproducibility)."""
    ids_a = [r["id"] for r in DynamicProber(config={"seed": 42}).run()]
    ids_b = [r["id"] for r in DynamicProber(config={"seed": 42}).run()]
    assert ids_a == ids_b
