
DIAG=diag.log
BTEST=../../aux/btest/btest

all: cleanup btest-verbose coverage

# Showing all tests.
btest-verbose:
	@$(BTEST) -j -f $(DIAG)

brief: cleanup btest-brief coverage

# Brief output showing only failed tests.
btest-brief:
	@$(BTEST) -j -b -f $(DIAG)

coverage:
	@../scripts/coverage-calc ".tmp/script-coverage*" coverage.log `pwd`/../../scripts

cleanup:
	@rm -f $(DIAG)
	@rm -f .tmp/script-coverage*

# Updates the three coverage tests that usually need tweaking when
# scripts get added/removed.
update-coverage-tests:
	btest -qU coverage.bare-load-baseline
	btest -qU coverage.default-load-baseline
	@echo "Use 'git diff' to check updates look right."

.PHONY: all btest-verbose brief btest-brief coverage cleanup
