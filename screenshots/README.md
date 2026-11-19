# Screenshot guide

The four images in this folder are rendered from the real output of the commands below, run on a clean clone of the repository.
They are not photographs of a terminal window, and nothing in them is edited. To replace one with a native screenshot, run the same
command on your own machine, keep the file name and overwrite the file. A screenshot must show a real run; do not edit or fabricate results.

| File | Open | Run | What must be visible |
|---|---|---|---|
| `01-demo-terminal.png` | A terminal in the repository folder (dark or light theme, wide enough for 110 columns) | `./bin/seclog demo` | The coloured summary: "Findings : 11 (high 6, medium 4, low 1)" and the table with SL-001 … SL-008, plus the "Results written to" line |
| `02-report-markdown.png` | The generated `report.md` in a Markdown viewer (VS Code preview or GitHub) | open `seclog-output/demo-*/report.md` | The "Findings" table with severities and MITRE IDs |
| `03-json-output.png` | A terminal | `jq '.summary, .findings[0]' seclog-output/demo-*/summary.json` | Valid JSON with `findings_total: 11` and the first finding |
| `04-test-results.png` | A terminal with the virtual environment active | `python3 -m pytest -q` | The final line with the number of passed tests and no failures |

Embed in `README.md` with: `![seclog demo output](screenshots/01-demo-terminal.png)`

Before uploading, check each image for personal information (user name in the prompt, real host names, e-mail
addresses). Blur or crop anything that is not part of the demo.
