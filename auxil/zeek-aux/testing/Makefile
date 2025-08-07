BTEST=../../btest/btest
DIAG=diag.log

all: cleanup btest-verbose

# Showing all tests.
btest-verbose:
	@test -x $(BTEST) && bt=$(BTEST) || bt=btest; $$bt -j -f $(DIAG)

brief: cleanup btest-brief

# Brief output showing only failed tests.
btest-brief:
	@test -x $(BTEST) && bt=$(BTEST) || bt=btest; $$bt -j -b -f $(DIAG)

cleanup:
	@rm -f $(DIAG)

.PHONY: all btest-verbose brief btest-brief cleanup
