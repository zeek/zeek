# @TEST-DOC: Test find_in_zeekpath() and demo conditional @load'ing.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr
#
# @TEST-EXEC: zeek -b errors.zeek >errors.stdout 2>errors.stderr
# @TEST-EXEC: btest-diff errors.stdout
# @TEST-EXEC: btest-diff errors.stderr


@if ( find_in_zeekpath("pkg1") != "" )
@load pkg1
@endif

@if ( find_in_zeekpath("pkg2") != "" )
@load pkg2
@endif

@if ( find_in_zeekpath("pkg3") != "" )
@load pkg3
@endif

function path_tail(r: string): string
	{
	if ( |r| == 0 )
		return r;
	local parts = split_string(r, /\//);
	return join_string_vec(parts[-4:], "/");
	}

print "find_in_zeekpath base/protocols/conn", path_tail(find_in_zeekpath("base/protocols/conn"));
print "find_in_zeekpath protocols/conn (empty expected, no __load__.zeek)", find_in_zeekpath("protocols/conn");
print "find_in_zeekpath protocols/conn/vlan-logging", path_tail(find_in_zeekpath("protocols/conn/vlan-logging"));

print "find_in_zeekpath pkg1", find_in_zeekpath("pkg1");
print "find_in_zeekpath pkg1.zeek", find_in_zeekpath("pkg1.zeek");
print "find_in_zeekpath pkg2", find_in_zeekpath("pkg2");
print "find_in_zeekpath pkg3", find_in_zeekpath("pkg3");

# @TEST-START-FILE pkg1.zeek
event zeek_init()
	{
	print "pkg1!";
	}
# @TEST-END-FILE

# @TEST-START-FILE pkg2/__load__.zeek
event zeek_init()
	{
	print "pkg2!";
	}
# @TEST-END-FILE

# @TEST-START-FILE errors.zeek
# Using relative and absolute paths is an error (empty string)
print "relative", find_in_zeekpath("./pkg1.zeek");
print "absolute", find_in_zeekpath("/pkg1");
# @TEST-END-FILE
