
DIAG=diag.log
BTEST=../../aux/btest/btest

all: cleanup
    # Showing all tests.
	@$(BTEST) -f $(DIAG)
	@../scripts/coverage-calc ".tmp/script-coverage*" coverage.log `pwd`/../../scripts

brief: cleanup
    # Brief output showing only failed tests.
	@$(BTEST) -b -f $(DIAG)
	@../scripts/coverage-calc ".tmp/script-coverage*" coverage.log `pwd`/../../scripts

cleanup:
	@rm -f $(DIAG)
	@rm -f .tmp/script-coverage*
