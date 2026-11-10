# Hardware support

Run `python3 -m beaconshield.cli hardware` for local capability reporting. Adapter sysfs presence is not proof of usable hardware.

Offline JSONL import works without hardware. No local BLE adapter, dedicated sniffer, or SDR integration is implemented. The source may be a separately authorized BLE observation export, but BeaconShield does not claim HCI logs contain all over-the-air advertisements. No hardware was verified here. Frequency range and sample rate are not measured by this offline parser.
