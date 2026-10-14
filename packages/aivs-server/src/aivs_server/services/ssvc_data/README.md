# Vendored SSVC data

`cisa_coordinator_2_0_3.csv` is copied verbatim from the CERT/CC SSVC repository,
`data/csv/cisa/cisa_coordinator_2_0_3.csv`, at commit
`c5be80f180f031257b680c8f83e0e092387d29ef`, under the licence in `LICENSE`
(MIT, SEI-style) that covers that repository's `data/` directory.

It is CISA's SSVC decision table: Exploitation, Automatable, Technical Impact and
Mission and Well-Being Impact to Track, Track*, Attend or Act. `services/priority.py`
reads it unchanged; do not edit it here. To adopt a newer table, copy the new
file, record its commit, and let `test_priority.py` show what changed.
