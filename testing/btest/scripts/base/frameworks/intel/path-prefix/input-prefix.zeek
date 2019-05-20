# This test verifies that specifying an Input::path_prefix
# also affects the Intel framework since it relies on the
# former for loading data. (Note that this also tests the
# Input::REREAD ingestion mode.)
#
# @TEST-EXEC: mkdir -p alternative
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/intel/path-prefix zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE alternative/test.data
#fields	indicator	indicator_type	meta.source
127.0.0.1	Intel::ADDR	this btest
127.0.0.2	Intel::ADDR	this btest
127.0.0.3	Intel::ADDR	this btest 
@TEST-END-FILE

@load path-prefix-common.zeek

redef Intel::read_files += { "test.data" };
redef InputAscii::path_prefix = "alternative";
