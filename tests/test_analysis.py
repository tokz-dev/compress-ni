import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("analysis", ROOT / "analyze.py")
analysis = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(analysis)
spec_runner = importlib.util.spec_from_file_location("reproduce", ROOT / "reproduce.py")
runner = importlib.util.module_from_spec(spec_runner)
assert spec_runner and spec_runner.loader
spec_runner.loader.exec_module(runner)


class AnalysisTests(unittest.TestCase):
    def test_summary_math(self):
        row = {
            "firewallFixedStable": True,
            "firewallProtectedRetention": 1,
            "firewallControlRetention": 1,
            "firewallEvidenceRetained": True,
            "firewallKeptRatio": 0.2,
            "firewallBudgetExceeded": False,
            "budgetOvershootBytes": 0,
            "flatProtectedRetention": 0,
            "flatControlRetention": 0.5,
            "flatEvidenceRetained": False,
            "flatKeptRatio": 0.2,
            "flatRatioAbsoluteError": 0,
            "reserveHeadEvidenceRetained": False,
            "reserveHeadKeptRatio": 0.2,
        }
        stress = {
            "format": "json",
            "dataMethod": "structural",
            "violated": False,
            "replayChecked": True,
            "replayMismatch": False,
        }
        report = {"comparison": [row, {**row, "budgetOvershootBytes": 8}], "stress": [stress]}
        result = analysis.summarize_run(report)
        self.assertEqual(result["comparison"]["summary"]["firewallP95BudgetOvershootBytes"], 8)
        self.assertEqual(result["stress"]["methods"]["json"]["structural"], 1)

    def test_malformed_input(self):
        with self.assertRaises(ValueError):
            analysis.summarize_run({"comparison": [], "stress": []})

    def test_checked_in_summary_is_consistent(self):
        summary = json.loads((ROOT / "results" / "summary.json").read_text(encoding="utf-8"))
        analysis.validate_paper_summary(summary)

    def test_summary_rejects_inconsistent_stress_counts(self):
        summary = json.loads((ROOT / "results" / "summary.json").read_text(encoding="utf-8"))
        summary["paperRun"]["stress"]["formats"]["json"] -= 1
        with self.assertRaises(ValueError):
            analysis.validate_paper_summary(summary)

    def test_fixtures_are_deterministic(self):
        self.assertEqual(runner.fixture(runner.DOMAINS[0], 32, 4), runner.fixture(runner.DOMAINS[0], 32, 4))

    def test_comparison_fixture_matches_frozen_typescript_snapshot(self):
        rows, _ = runner.fixture(runner.DOMAINS[0], 32, 8, runner.ATTACKS[8])
        digest = hashlib.sha256(runner.compact_json(rows).encode()).hexdigest()
        self.assertEqual(
            digest,
            "fffd3510d0a0c01be673f47c5d67e16496e96a3a54889ca5e2cbe91e3f280064",
        )

    def test_stress_fixtures_match_frozen_typescript_snapshots(self):
        expected = {
            0: (
                "json",
                "0956cb8be70d76d035fa390e2088fe9e88122c01f99a6c1612019d8788acb48f",
                "d7e9072f2701e1e3dbbbcd8c4ea22868a98a8148bcb8c4ee19e8e52a748e75fe",
            ),
            1: (
                "log",
                "3b0f771108eee1cfc99511ca92c9ed51123ef1518c9362d3640af66957ab8a59",
                "2bd1ea8ef0e28de09253f71865d28c77332a2ed4d1f3c535068ec93b319a3e13",
            ),
            3: (
                "jsonl",
                "bfa644da7aa7f70429ad9b037a7e63669b00de48b24378662eaafc4cccbce6f6",
                "8b086801a9de59c90b5a30bd0b45d43440123349e49cc8b6de84eda49d6d72c0",
            ),
            4: (
                "unknown",
                "0b33e2e8e3b52ffefae2a7ead63983d1e505897847098d22733cbc72f6e3b29e",
                "4137fa6b06339a5f0a126d2fca903f2bcf3b2fe034ea982db33e80df39f86a7b",
            ),
            9: (
                "prose",
                "038fab24210b310e8d62b272073565cdc58726cd308fbb9a6b3731e9bb7af4a1",
                "ded85494d09d9b87021e2799eefa6e99504433b05b0301133cbb1b999a6b84f1",
            ),
            17: (
                "csv",
                "3ca3775c441829b1f78d036c5df3cdd837133b3bd334ac82fa991d8c1e4c354f",
                "a2379ee03cfd7d5bfa75dfafe1f3e06d6070ce7a2f7c0b47355b0a8e15a0984d",
            ),
        }
        for trial, (fmt, clean_hash, attacked_hash) in expected.items():
            fixture = runner.stress_fixture(trial)
            self.assertEqual(fixture["format"], fmt)
            self.assertEqual(
                hashlib.sha256(str(fixture["cleanData"]).encode()).hexdigest(),
                clean_hash,
            )
            self.assertEqual(
                hashlib.sha256(str(fixture["attackedData"]).encode()).hexdigest(),
                attacked_hash,
            )

    def test_stress_format_sequence_matches_paper(self):
        formats = ("json", "jsonl", "csv", "log", "prose", "unknown")
        counts = {name: 0 for name in formats}
        random = runner.xorshift32(0x544F4B5A)
        for _ in range(2000):
            counts[formats[int(next(random) * len(formats))]] += 1
            next(random)
        self.assertEqual(
            counts,
            {"json": 363, "jsonl": 334, "csv": 343, "log": 319, "prose": 322, "unknown": 319},
        )

    def test_smoke_trials_cover_every_format(self):
        formats = ("json", "jsonl", "csv", "log", "prose", "unknown")
        selected = set()
        for trial in runner.SMOKE_STRESS_TRIALS:
            random = runner.xorshift32(0x544F4B5A)
            for _ in range(trial * 2 + 1):
                value = next(random)
            selected.add(formats[int(value * len(formats))])
        self.assertEqual(selected, set(formats))

    def test_reserve_head_uses_achieved_utf8_bytes(self):
        retained, ratio = runner.reserve_head_metrics(
            "\u00e9\u00e9TARGET database timeout tail",
            fixed_bytes=10,
            kept_bytes=37,
            source_bytes=50,
            marker="TARGET",
            failure="database timeout",
        )
        self.assertTrue(retained)
        self.assertEqual(ratio, 37 / 50)

    def test_hosted_calls_disable_unmetered_sdk_retries(self):
        class Client:
            def compress_context(self, *args, **kwargs):
                self.retries = kwargs["retries"]
                return {"ok": True}

        client = Client()
        limiter = type("Limiter", (), {"wait": lambda self: None})()
        runner.call_context(client, limiter, [], "query", 10)
        self.assertEqual(client.retries, runner.SDK_RETRIES)

    def test_resume_rejects_a_different_protocol(self):
        report = {
            "schema": 1,
            "execution": "hosted-current-service",
            "baseUrl": "https://api.tokz.dev",
            "sdkVersion": "0.3.0",
            "protocol": {"mode": "full"},
            "comparison": [],
            "stress": [],
        }
        with self.assertRaisesRegex(ValueError, "same smoke/full protocol"):
            runner.validate_resume(
                report,
                "https://api.tokz.dev",
                "0.3.0",
                {"mode": "smoke"},
            )

    def test_runner_help_needs_no_key_or_network(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "reproduce.py"), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("--full", completed.stdout)

    def test_runner_rejects_credentials_in_base_url(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "reproduce.py"),
                "--base-url",
                "https://user:secret@example.com",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must not contain credentials", completed.stderr)


if __name__ == "__main__":
    unittest.main()
