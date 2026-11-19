# Using the output in Splunk or Elastic

`seclog` does not talk to any SIEM. It produces files that a SIEM can ingest. **None of the steps below has been
tested against a real Splunk or Elastic installation by the author** — they are written from the products' documentation
and marked accordingly. The `jq` commands in section 3 were run locally and their output checked.

## 1. Splunk (NOT TESTED against a real instance)

### Upload the CSV files (simplest)

1. In Splunk Web: **Settings → Add Data → Upload**.
2. Select `findings.csv` (or `events.csv`). Splunk recognises the header row. Choose source type `csv`.
3. Set the time field to `time` (findings) or `timestamp` (events), format `%Y-%m-%dT%H:%M:%S`. Note that the logs have no
   time zone; set the one the server used.
4. Choose or create an index, for example `seclog`.

### Example searches over the uploaded findings

```spl
index=seclog sourcetype=csv rule_id=SL-003 | table time host subject details

index=seclog sourcetype=csv severity=high | stats count by rule_id subject

index=seclog sourcetype=csv | stats count by severity | sort - count
```

### Monitor a results folder

If cron writes a result folder per day (`~/seclog-reports/<date>/`), a Splunk `[monitor://…/findings.csv]` input
with `sourcetype = csv` and `INDEXED_EXTRACTIONS = csv` picks up each file. Check Splunk's documentation for the
exact stanza for your version.

## 2. Elastic / Kibana (NOT TESTED against a real instance)

### Bulk-load the findings

`findings.bulk.ndjson` is created with `jq` (see section 3) and sent to Elasticsearch's `_bulk` API:

```bash
curl -s -H 'Content-Type: application/x-ndjson' -X POST 'https://localhost:9200/_bulk' \
     --data-binary @findings.bulk.ndjson -u elastic     # curl asks for the password
```

Use your own host and credentials. Do not put passwords in scripts or commit them. In Kibana create a data view for
`seclog-findings` and use `time` as the timestamp field after mapping it as `date` (`yyyy-MM-dd'T'HH:mm:ss`).

### Example Kibana (KQL) queries

```text
rule_id : "SL-003"
severity : "high" and subject : "svc-backup"
mitre_technique : "T1110.001"
```

## 3. Preparing JSON Lines files (tested locally with jq 1.7)

```bash
# One JSON object per finding (for Splunk monitor inputs or Filebeat's ndjson parser)
jq -c '.findings[]' summary.json > findings.ndjson

# The same, with the action lines that Elasticsearch's _bulk API expects
jq -c '.findings[] | {"index":{"_index":"seclog-findings"}}, .' summary.json > findings.bulk.ndjson

# Only high severity findings as a table
jq -r '.findings[] | select(.severity=="high") | [.time, .rule_id, .subject] | @tsv' summary.json
```

For the `example-output` in this repository the second command produces 22 lines (11 findings, each with an action line).

## 4. Where this fits with the other projects

The SOC lab project in this portfolio contains Splunk SPL and Elastic queries that work on the *raw* logs. This tool
is the step before: it turns a raw log into a short list of leads and a report, and the files above let you pivot from
a finding (for example `203.0.113.45`) back to the raw events in the SIEM.
