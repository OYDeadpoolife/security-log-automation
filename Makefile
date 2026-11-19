# Convenience targets. Every target only runs commands shown here.
.PHONY: test lint format demo example-output

test:            ## run the whole test suite
	python3 -m pytest -v

lint:            ## ShellCheck and shfmt (formatting check only)
	shellcheck -x bin/seclog lib/*.sh scripts/*.sh
	shfmt -d -i 4 -ci bin/seclog lib/*.sh scripts/*.sh

format:          ## rewrite shell files with the project formatting
	shfmt -w -i 4 -ci bin/seclog lib/*.sh scripts/*.sh

demo:            ## analyse the bundled synthetic sample into ./seclog-output
	./bin/seclog demo

# The committed example output uses a fixed report time so it can be compared byte for byte.
example-output:  ## regenerate examples/example-output (deletes that folder first)
	rm -rf examples/example-output
	SECLOG_FIXED_TIME=2026-10-03T00:00:00Z ./bin/seclog demo --output-dir examples/example-output --quiet --no-color
