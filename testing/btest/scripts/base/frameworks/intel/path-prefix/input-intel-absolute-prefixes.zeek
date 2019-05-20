# This test verifies that an absolute Intel::path_prefix overrides any
# set for the Input framework. We still want the Intel framework to
# "break out" of any file system location specified for the input
# framework, e.g. when their paths live side-by-side (/foo/bar/input,
# /foo/bar/intel).
#
# @TEST-EXEC: mkdir -p intel
# @TEST-EXEC: cat %INPUT | sed "s|@path_prefix@|$PWD/intel|" >input.zeek
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/intel/path-prefix zeek -b input.zeek >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE intel/test.data
#fields	indicator	indicator_type	meta.source
127.0.2.1	Intel::ADDR	this btest
127.0.2.2	Intel::ADDR	this btest
127.0.2.3	Intel::ADDR	this btest 
@TEST-END-FILE

@load path-prefix-common.zeek

redef Intel::read_files += { "test.data" };
redef InputAscii::path_prefix = "/this/does/not/exist";
redef Intel::path_prefix = "@path_prefix@";
