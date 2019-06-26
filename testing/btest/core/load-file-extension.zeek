# Test loading scripts with different file extensions.
#
# Test that either ".zeek" or ".bro" can be loaded without specifying extension
# @TEST-EXEC: cp x/foo.bro .
# @TEST-EXEC: zeek -b load_foo > bro_only
# @TEST-EXEC: btest-diff bro_only
# @TEST-EXEC: rm foo.bro
#
# @TEST-EXEC: cp x/foo.zeek .
# @TEST-EXEC: zeek -b load_foo > zeek_only
# @TEST-EXEC: btest-diff zeek_only
# @TEST-EXEC: rm foo.zeek
#
# Test that ".zeek" is the preferred file extension, unless ".bro" is specified
# @TEST-EXEC: cp x/foo.* .
# @TEST-EXEC: cp x2/foo .
# @TEST-EXEC: zeek -b load_foo > zeek_preferred
# @TEST-EXEC: btest-diff zeek_preferred
#
# @TEST-EXEC: zeek -b load_foo_bro > bro_preferred
# @TEST-EXEC: btest-diff bro_preferred
# @TEST-EXEC: rm foo*
#
# Test that ".bro" is preferred over a script with no file extension (when
# there is no ".zeek" script)
# @TEST-EXEC: cp x/foo.bro .
# @TEST-EXEC: cp x2/foo .
# @TEST-EXEC: zeek -b load_foo > bro_preferred_2
# @TEST-EXEC: btest-diff bro_preferred_2
# @TEST-EXEC: rm foo*
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

@TEST-START-FILE load_foo_bro
@load foo.bro
@TEST-END-FILE

@TEST-START-FILE load_foo_xyz
@load foo.xyz
@TEST-END-FILE


@TEST-START-FILE x/foo.bro
print "Bro script loaded";
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
