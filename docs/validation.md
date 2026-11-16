# Validation on real data

Counts below were produced by running the tool on public data, not on the synthetic samples in `examples/`.

## Corpus
SigmaHQ/sigma at commit `54967d6` (3,165 files) checked against the official ATT&CK STIX data at `a8db2f5` (ATT&CK v20.1).

## Result
121 findings: 87 MIT003, 31 MIT002 (retired technique ids still used in rules), 2 info and 1 MIT005.

## What the real data exposed (all fixed, with regression tests)
- The tactic list was out of date. ATT&CK v20 has 15 Enterprise tactics and splits the old Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112). `attack.defense-evasion` now raises MIT006.
- Technique ids were validated only by shape. The catalogue is now generated from the official STIX files (`scripts/gen_attack_data.py`) for Enterprise, ICS and Mobile, so an id like `T9999` raises MIT007 and a retired id names its replacement.
- Group and software ids (`G`, `S`) are checked against the same catalogue.

## Limits
The mapping is only as current as the generated data. Re-run the generator after each ATT&CK release.
