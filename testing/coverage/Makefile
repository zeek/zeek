coverage: cleanup
	@./code_coverage.sh

cleanup:
	@rm -f coverage.log
	@find ../../ -name "*.gcov" -exec rm {} \;

distclean: cleanup
	@find ../../ -name "*.gcno" -exec rm {} \;

html:
	@./lcov_html.sh $(COVERAGE_HTML_DIR)
