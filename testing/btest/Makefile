
DIAG=diag.log
BTEST=../../aux/btest/btest

all: cleanup btest-verbose coverage

# Showing all tests.
btest-verbose:
	@$(BTEST) -f $(DIAG)

brief: cleanup btest-brief coverage

# Brief output showing only failed tests.
btest-brief:
	@$(BTEST) -b -f $(DIAG)

coverage:
	@../scripts/coverage-calc ".tmp/script-coverage*" coverage.log `pwd`/../../scripts

cleanup:
	@rm -f $(DIAG)
	@rm -f .tmp/script-coverage*

.PHONY: all btest-verbose brief btest-brief coverage cleanup
