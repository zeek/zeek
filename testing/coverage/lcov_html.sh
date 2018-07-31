#!/usr/bin/env bash
#
# On a Bro build configured with --enable-coverage, this script
# produces a code coverage report in HTML format after Bro has been invoked. The
# intended application of this script is after the btest testsuite has run.

# This depends on lcov to run.

function die {
	echo "$@"
	exit 1
}
function finish {
	rm -rf "$TMP"
}
function verify_run {
	if bash -c "$1" > /dev/null 2>&1; then
		echo ${2:-"ok"}
	else
		die ${3:-"error, abort"}
	fi
}
trap finish EXIT 

TMP=".tmp.$$"
COVERAGE_FILE="./$TMP/coverage.info"
COVERAGE_HTML_DIR="${1:-"coverage-html"}"
REMOVE_TARGETS="*.yy *.ll *.y *.l */bro.dir/* *.bif"

# 1. Move to base dir, create tmp dir
cd ../../; 
mkdir "$TMP"

# 2. Check for .gcno and .gcda file presence
echo -n "Checking for coverage files... "
for pat in gcda gcno; do
    if [ -z "$(find . -name "*.$pat" 2>/dev/null)" ]; then
        echo "no .$pat files, nothing to do"
	exit 0
    fi
done
echo "ok"

# 3. If lcov does not exist, abort process. 
echo -n "Checking for lcov... "
verify_run "which lcov" \
	"lcov installed on system, continue" \
	"lcov not installed, abort"

# 4. Create a "tracefile" through lcov, which is necessary to create html files later on.
echo -n "Creating tracefile for html generation... " 
verify_run "lcov --no-external --capture --directory . --output-file $COVERAGE_FILE"

for TARGET in $REMOVE_TARGETS; do
	echo -n "Getting rid of $TARGET files from tracefile... "
	verify_run "lcov --remove $COVERAGE_FILE $TARGET --output-file $COVERAGE_FILE"
done

# 5. Create HTML files. 
echo -n "Creating HTML files... "
verify_run "genhtml -o $COVERAGE_HTML_DIR $COVERAGE_FILE"
