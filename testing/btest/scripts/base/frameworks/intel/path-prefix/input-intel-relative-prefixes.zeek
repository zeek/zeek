# This test verifies that combining Input::path_prefix and
# Intel::path_prefix works as intended: the intel path gets
# prepended first, then the input framework one.
#
# @TEST-EXEC: mkdir -p input/intel
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/intel/path-prefix zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE input/intel/test.data
#fields	indicator	indicator_type	meta.source
127.0.1.1	Intel::ADDR	this btest
127.0.1.2	Intel::ADDR	this btest
127.0.1.3	Intel::ADDR	this btest 
@TEST-END-FILE

@load path-prefix-common.zeek

redef Intel::read_files += { "test.data" };
redef InputAscii::path_prefix = "input";
redef Intel::path_prefix = "intel";
