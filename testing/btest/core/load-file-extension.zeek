# Test loading scripts with different file extensions.
#
# Test that ".zeek" can be loaded without specifying extension
# @TEST-EXEC: cp x/foo.zeek .
# @TEST-EXEC: zeek -b load_foo > zeek_only
# @TEST-EXEC: btest-diff zeek_only
# @TEST-EXEC: rm foo.zeek
#
# Test that a script with no file extension can be loaded
# @TEST-EXEC: cp x2/foo .
# @TEST-EXEC: zeek -b load_foo > no_extension
# @TEST-EXEC: btest-diff no_extension
# @TEST-EXEC: rm foo
#
# Test that a ".zeek" script is preferred over a script package of same name
# @TEST-EXEC: cp -r x/foo* .
# @TEST-EXEC: zeek -b load_foo > zeek_script_preferred
# @TEST-EXEC: btest-diff zeek_script_preferred
# @TEST-EXEC: rm -r foo*
#
# Test that unrecognized file extensions can be loaded explicitly
# @TEST-EXEC: cp x/foo.* .
# @TEST-EXEC: zeek -b load_foo_xyz > xyz_preferred
# @TEST-EXEC: btest-diff xyz_preferred
# @TEST-EXEC: rm foo.*
#
# @TEST-EXEC: cp x/foo.xyz .
# @TEST-EXEC-FAIL: zeek -b load_foo
# @TEST-EXEC: rm foo.xyz

@TEST-START-FILE load_foo
@load foo
@TEST-END-FILE

@TEST-START-FILE load_foo_xyz
@load foo.xyz
@TEST-END-FILE


@TEST-START-FILE x/foo.zeek
print "Zeek script loaded";
@TEST-END-FILE

@TEST-START-FILE x/foo.xyz
print "Non-standard file extension script loaded";
@TEST-END-FILE

@TEST-START-FILE x/foo/__load__.zeek
@load ./main
@TEST-END-FILE

@TEST-START-FILE x/foo/main.zeek
print "Script package loaded";
@TEST-END-FILE

@TEST-START-FILE x2/foo
print "No file extension script loaded";
@TEST-END-FILE
