coverage: cleanup
	@./code_coverage.sh

cleanup:
	@rm -f coverage.log
	@find ../../ -name "*.gcov" -exec rm {} \;

distclean: cleanup
	@find ../../ -name "*.gcno" -exec rm {} \;

html:
	@(cd ../../; if which lcov; then\
		lcov --capture --directory . --output-file coverage.info \
		&& genhtml coverage.info && rm coverage.info; \
	fi)
