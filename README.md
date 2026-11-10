# BeaconShield

BeaconShield reviews authorized BLE beacon advertisement observations from bounded offline JSONL files. It parses iBeacon, Eddystone UID, and manufacturer-specific fields; inventories identifiers; estimates observed gaps and RSSI distributions; compares expected identifiers; and reports duplicate configuration and missing baseline indicators. Similar advertisements alone are not proof of spoofing.

```sh
python3 -m beaconshield.cli authorized-observations.jsonl --baseline expected.json --output review.json
```

Each JSONL line needs `timestamp` with timezone and `raw_ad_hex`; optional `address` and `rssi` are accepted. Baseline JSON maps expected identifiers to optional `firmware` metadata. Input is capped at 25 MB, 8192 characters per line, and 100,000 observations. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [HARDWARE.md](HARDWARE.md), [DEPENDENCIES.md](DEPENDENCIES.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md).
