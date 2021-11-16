DIAG=diag.log
BTEST=../../auxil/btest/btest

all: btest-verbose clean

# Showing all tests.
btest-verbose:
	@$(BTEST) -d -j -f $(DIAG)

clean:
	@rm -rf $(DIAG) .tmp .btest.failed.dat
