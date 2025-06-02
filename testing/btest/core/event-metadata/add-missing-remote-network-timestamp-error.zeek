# @TEST-DOC: Using add_missing_remote_network_timestamp without add_network_timestamp is an error.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

redef EventMetadata::add_network_timestamp = F;
redef EventMetadata::add_missing_remote_network_timestamp = T;
