
DIRS=btest external

all:
	@for repo in $(DIRS); do (cd $$repo && make ); done
	@cp btest/coverage.log `mktemp brocov.tmp.XXX`
	@for f in external/*/coverage.log; do cp $$f `mktemp brocov.tmp.XXX`; done
	@echo "Complete test suite code coverage:"
	@./scripts/coverage-calc "brocov.tmp.*" coverage.log `pwd`
	@rm -f brocov.tmp.*

brief:
	@for repo in $(DIRS); do (cd $$repo && make brief ); done
