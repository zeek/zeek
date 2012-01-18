
DIAG=diag.log
BTEST=../../aux/btest/btest

all:
    # Showing all tests.
	@rm -f $(DIAG)
	@rm -f .tmp/script-coverage*
	@$(BTEST) -f $(DIAG)
	@../scripts/coverage-calc ".tmp/script-coverage*" coverage.log `pwd`/../../scripts

brief:
    # Brief output showing only failed tests.
	@rm -f $(DIAG)
	@$(BTEST) -b -f $(DIAG)
