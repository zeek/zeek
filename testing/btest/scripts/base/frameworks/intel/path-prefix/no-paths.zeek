# This test verifies that when setting neither InputAscii::path_prefix
# nor Intel::path_prefix, Zeek correctly locates local intel files.
#
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/intel/path-prefix zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE test.data
#fields	indicator	indicator_type	meta.source
127.0.0.1	Intel::ADDR	this btest
127.0.0.2	Intel::ADDR	this btest
127.0.0.3	Intel::ADDR	this btest 
@TEST-END-FILE

@load path-prefix-common.zeek

redef Intel::read_files += { "test.data" };
