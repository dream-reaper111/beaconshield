# Architecture

The CLI preserves evidence by reading it without changes and hashing the source. The bounded parser extracts advertisement structures, normalizes recognized frame identifiers, groups observations by identifier, and compares them with a supplied authorized fleet baseline. Gaps are between observed events and are not confirmed beacon advertising intervals. RSSI is descriptive, not physical distance. This independent offline utility has no shared runtime dependency.
