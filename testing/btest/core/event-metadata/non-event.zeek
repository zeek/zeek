# @TEST-DOC: Ensure EventMetadata::current() and EventMetadata::current_all() in non-event context returns empty vectors.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr

assert |EventMetadata::current(EventMetadata::NETWORK_TIMESTAMP)| == 0;
assert |EventMetadata::current_all()| == 0;
