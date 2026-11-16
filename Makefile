.PHONY: test sample

test:
	php tests/run.php && bash tests/cli.sh

sample:
	mkdir -p docs site
	bin/mitre-map examples > docs/sample-output.txt; true
	bin/mitre-map examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "mitre-map" "Checks MITRE ATT&CK references in detection content: malformed technique IDs, deprecated IDs with their replacement, redundant parent tags, unknown tags and tactic coverage gaps. PHP." "Synthetic data."
