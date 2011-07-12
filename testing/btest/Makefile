
DIAG=diag.log
BTEST=../../aux/btest/btest

all:
    # Showing all tests.
	@rm -f $(DIAG)
	@$(BTEST) -f $(DIAG)

brief:
    # Brief output showing only failed tests.
	@rm -f $(DIAG)
	@$(BTEST) -b -f $(DIAG)
