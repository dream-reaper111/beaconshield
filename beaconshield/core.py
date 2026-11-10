from collections import defaultdict
from datetime import datetime
from statistics import median


def frames(raw: bytes) -> list[dict]:
    if len(raw) > 1650:
        raise ValueError("advertisement exceeds limit")
    result = []
    pos = 0
    while pos < len(raw):
        size = raw[pos]
        pos += 1
        if size == 0:
            break
        if pos + size > len(raw):
            raise ValueError("truncated advertisement")
        kind, payload = raw[pos], raw[pos + 1:pos + size]
        pos += size
        if kind == 0xFF:
            if len(payload) < 2:
                raise ValueError("short manufacturer field")
            company = int.from_bytes(payload[:2], "little")
            body = payload[2:]
            if company == 0x004C and len(body) == 23 and body[:2] == b"\x02\x15":
                ident = body[2:18].hex()
                result.append({"format": "iBeacon", "identifier": f"{ident[:8]}-{ident[8:12]}-{ident[12:16]}-{ident[16:20]}-{ident[20:]}:{int.from_bytes(body[18:20], 'big')}:{int.from_bytes(body[20:22], 'big')}", "calibrated_tx_power_metadata": int.from_bytes(body[22:23], "big", signed=True), "company_id": company})
            else:
                result.append({"format": "manufacturer_specific", "identifier": f"company:{company}:data:{body.hex()[:32]}", "company_id": company})
        elif kind == 0x16 and len(payload) >= 2 and payload[:2] == b"\xaa\xfe":
            body = payload[2:]
            if len(body) >= 20 and body[0] == 0x00:
                result.append({"format": "Eddystone-UID", "identifier": body[2:18].hex(), "tx_power_metadata": int.from_bytes(body[1:2], "big", signed=True)})
            elif body:
                result.append({"format": "Eddystone-other", "identifier": f"frame:{body[0]:02x}:data:{body[1:17].hex()}"})
    return result


def analyze(observations: list[dict], baseline: dict | None = None) -> dict:
    if not isinstance(observations, list) or len(observations) > 100_000:
        raise ValueError("invalid observation count")
    if baseline is not None and not isinstance(baseline, dict):
        raise ValueError("invalid baseline")
    grouped = defaultdict(list)
    for item in observations:
        if not isinstance(item, dict) or not isinstance(item.get("raw_ad_hex"), str):
            raise ValueError("observation requires raw_ad_hex")
        stamp = item.get("timestamp")
        if not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("timestamp requires timezone")
        rssi = item.get("rssi")
        if rssi is not None and (not isinstance(rssi, (int, float)) or not -127 <= rssi <= 20):
            raise ValueError("invalid RSSI")
        for frame in frames(bytes.fromhex(item["raw_ad_hex"])):
            grouped[frame["identifier"]].append({"timestamp": stamp, "rssi": rssi, "address": item.get("address"), "frame": frame})
    inventory = []
    alerts = []
    for ident, items in grouped.items():
        items.sort(key=lambda x: x["timestamp"])
        rssis = [x["rssi"] for x in items if x["rssi"] is not None]
        gaps = [(datetime.fromisoformat(b["timestamp"].replace("Z", "+00:00")) - datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))).total_seconds() for a, b in zip(items, items[1:])]
        addresses = {x["address"] for x in items if x["address"]}
        inventory.append({"identifier": ident, "format": items[0]["frame"]["format"], "observations": len(items), "first_seen": items[0]["timestamp"], "last_seen": items[-1]["timestamp"], "rssi_median_dbm": median(rssis) if rssis else None, "observed_gap_median_seconds": median(x for x in gaps if x > 0) if any(x > 0 for x in gaps) else None, "distinct_addresses": len(addresses), "firmware_metadata": (baseline or {}).get(ident, {}).get("firmware")})
        if len(addresses) > 1:
            alerts.append({"identifier": ident, "indicator": "duplicate identifier across observed addresses", "confidence": "low", "note": "randomized addresses or fleet configuration can explain this; not proof of spoofing"})
        if baseline is not None and ident not in baseline:
            alerts.append({"identifier": ident, "indicator": "identifier outside baseline", "confidence": "medium"})
    if baseline:
        for ident in baseline:
            if ident not in grouped:
                alerts.append({"identifier": ident, "indicator": "expected identifier not observed", "confidence": "low"})
    return {"inventory": sorted(inventory, key=lambda x: x["identifier"]), "alerts": alerts, "interpretation": "advertisement observations only; no person tracking or spoofing proof"}
