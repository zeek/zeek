# @TEST-DOC: Test for regression in printing line numbers out-of-order
#
# Older versions of Zeek would sometimes print statement line numbers
# reversed (like "lines 49-48"). The issue most noticeably occurs in
# script profiling, so this test uses script profiling to look for any
# instances.
# @TEST-EXEC: ZEEK_PROFILER_FILE=test.prof zeek -b /dev/null
# @TEST-EXEC: grep 'lines [0-9]*-[0-9]' test.prof >multi-lines
# @TEST-EXEC: awk <multi-lines '{ split($4, lines, "-"); if ( lines[1] > lines[2] ) print }' >output
#
# The output should be empty.
# @TEST-EXEC: btest-diff output
