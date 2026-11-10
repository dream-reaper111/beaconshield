import json
from pathlib import Path
import tempfile
import unittest

from beaconshield.core import analyze, frames
from beaconshield.cli import main

STAMP = "2026-11-09T12:00:00Z"
IBEACON = "1aff4c00021500112233445566778899aabbccddeeff00010002c5"
EDDYSTONE = "1716aafe00c500112233445566778899aabbccddeeff0000"


class Tests(unittest.TestCase):
    def test_frames_and_baseline(self):
        self.assertEqual(frames(bytes.fromhex(IBEACON))[0]["format"], "iBeacon")
        self.assertEqual(frames(bytes.fromhex(EDDYSTONE))[0]["format"], "Eddystone-UID")
        obs = [{"timestamp": STAMP, "address": "AA", "raw_ad_hex": IBEACON, "rssi": -50},
               {"timestamp": STAMP, "address": "BB", "raw_ad_hex": IBEACON, "rssi": -60}]
        result = analyze(obs, {"expected": {"firmware": "1.0"}})
        self.assertEqual(len(result["inventory"]), 1)
        self.assertEqual(len(result["alerts"]), 3)

    def test_malformed(self):
        with self.assertRaises(ValueError):
            frames(b"\x05\xff\x4c")
        with self.assertRaises(ValueError):
            analyze([{"timestamp": STAMP, "raw_ad_hex": "xyz"}])
        with self.assertRaises(ValueError):
            analyze([{"timestamp": "2026-11-09T12:00:00", "raw_ad_hex": IBEACON}])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / "input.jsonl").write_text(json.dumps({"timestamp": STAMP, "raw_ad_hex": IBEACON}) + "\n")
            self.assertEqual(main([str(p / "input.jsonl"), "--output", str(p / "report.json")]), 0)
            self.assertEqual(json.loads((p / "report.json").read_text())["inventory"][0]["format"], "iBeacon")


if __name__ == "__main__":
    unittest.main()
