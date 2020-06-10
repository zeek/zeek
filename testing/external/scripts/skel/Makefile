
DIAG=diag.log
BTEST=../../../auxil/btest/btest

all: update-traces
	@rm -f $(DIAG)
	@$(BTEST) -f $(DIAG)

brief: update-traces
	@rm -f $(DIAG)
	@$(BTEST) -b -f $(DIAG)

update-traces:
	../scripts/update-traces Traces
