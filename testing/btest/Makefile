
all:
    # Showing all tests.
	@btest

brief:
    # Brief output showing only failed tests.
	@btest -b

brief-debug:
    # Verbose output for failed tests, also recorded in test.log.
	@rm -f test.log
	@btest -b -d -f test.log
	@echo Output in test.log
