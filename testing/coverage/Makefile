coverage: cleanup
	@./code_coverage.sh

cleanup:
	@rm -f coverage.log
	@find ../../ -name "*.gcov" -exec rm {} \;

distclean: cleanup
	@find ../../ -name "*.gcno" -exec rm {} \;

html:
	@./lcov_html.sh --html $(COVERAGE_HTML_DIR)

coveralls:
	@./lcov_html.sh --coveralls $(ZEEK_COVERALLS_REPO_TOKEN)
