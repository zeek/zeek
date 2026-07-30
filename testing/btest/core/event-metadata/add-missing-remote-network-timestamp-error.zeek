# @TEST-DOC: Using add_missing_remote_network_timestamp without add_network_timestamp is an error.
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

redef EventMetadata::add_network_timestamp = F;
redef EventMetadata::add_missing_remote_network_timestamp = T;
