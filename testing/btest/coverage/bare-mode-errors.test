# Makes sure any given zeek script in the scripts/ tree can be loaded in
# bare mode without error.
#
# Commonly, this test may fail if one forgets to @load some base/ scripts
# when writing a new zeek scripts.
#
# @TEST-EXEC: test -d $DIST/scripts
# @TEST-EXEC: for script in `find $DIST/scripts/ -name \*\.zeek`; do zeek -b --parse-only $script >>errors 2>&1; done
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-sort" btest-diff errors
