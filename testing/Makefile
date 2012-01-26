
DIRS=btest external

all: make-verbose coverage

brief: make-brief coverage

make-verbose:
	@for repo in $(DIRS); do (cd $$repo && make ); done

make-brief:
	@for repo in $(DIRS); do (cd $$repo && make brief ); done

coverage:
	@cp btest/coverage.log `mktemp brocov.tmp.XXX`
	@for f in external/*/coverage.log; do cp $$f `mktemp brocov.tmp.XXX`; done
	@echo "Complete test suite code coverage:"
	@./scripts/coverage-calc "brocov.tmp.*" coverage.log `pwd`/../scripts
	@rm -f brocov.tmp.*

