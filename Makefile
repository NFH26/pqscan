# Thin aliases. All real logic lives in ./pqc so there is one entry point, and so the
# tool behaves the same on a machine without make (notably Windows).
.PHONY: setup test selftest lint verify scan help
setup:    ; ./pqc setup
test:     ; ./pqc test
# One real scan across every protocol, checked against known answers.
selftest: ; ./pqc selftest
lint:     ; ./pqc lint
verify:   ; ./pqc verify --pq --scores
help:     ; ./pqc --help
