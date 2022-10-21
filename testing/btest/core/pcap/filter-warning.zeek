# Don't run for C++ scripts, since first invocation doesn't use the input
# and hence leads to complaints that there are no scripts.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: zeek -r $TRACES/ieee80211.15.4.pcap >output 2>&1
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-canonifier | $SCRIPTS/diff-remove-abspath' btest-diff reporter.log
# @TEST-EXEC: btest-diff packet_filter.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
