# Example output

These files were produced by running `./bin/seclog demo` (that is, `seclog` 1.0.0 on the synthetic file
`samples/auth.log`). They are committed so that you can see the result without running anything, and a test
(`test_example_output_is_up_to_date`) fails if they ever differ from what the tool produces.

The report time is fixed (`SECLOG_FIXED_TIME=2026-10-03T00:00:00Z`) so the files can be compared byte for byte.
Regenerate them with `make example-output`.

| File | Content |
|---|---|
| `report.md` | Human-readable report |
| `summary.json` | Everything in one JSON document |
| `events.csv` | Every parsed security event |
| `findings.csv` | One row per detection |
| `sources.csv` | Failed-login statistics per source address |
