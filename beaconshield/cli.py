import argparse
import hashlib
import json
from pathlib import Path
import sys
from .hardware import capabilities

from .core import analyze


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv == ["hardware"]:
        print(json.dumps(capabilities(), indent=2))
        return 0
    parser = argparse.ArgumentParser(prog="beaconshield")
    parser.add_argument("input", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > 25_000_000:
            raise ValueError("input exceeds 25 MB")
        data = args.input.read_bytes()
        lines = data.decode().splitlines()
        if any(len(line) > 8192 for line in lines):
            raise ValueError("line exceeds limit")
        baseline = None
        if args.baseline:
            if args.baseline.stat().st_size > 1_000_000:
                raise ValueError("baseline exceeds 1 MB")
            baseline = json.loads(args.baseline.read_text())
        report = analyze([json.loads(line) for line in lines if line.strip()], baseline)
        report["evidence_sha256"] = hashlib.sha256(data).hexdigest()
        result = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(result)
        else:
            print(result, end="")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"beaconshield: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
