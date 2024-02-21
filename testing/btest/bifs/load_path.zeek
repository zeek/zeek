# @TEST-DOC: Test load_path() and demo conditional @load'ing.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr


@if ( load_path("pkg1") != "" )
@load pkg1
@endif

@if ( load_path("pkg2") != "" )
@load pkg2
@endif

@if ( load_path("pkg3") != "" )
@load pkg3
@endif

function path_tail(r: string): string
	{
	if ( |r| == 0 )
		return r;
	local parts = split_string(r, /\//);
	return join_string_vec(parts[-4:], "/");
	}

print "load_path base/protocols/conn", path_tail(load_path("base/protocols/conn"));
print "load_path protocols/conn (empty expected, no __load__.zeek)", load_path("protocols/conn");
print "load_path protocols/conn/vlan-logging", path_tail(load_path("protocols/conn/vlan-logging"));

print "load_path pkg1", load_path("pkg1");
print "load_path pkg1.zeek", load_path("pkg1");
print "load_path pkg2", load_path("pkg2");
print "load_path pkg3", load_path("pkg3");

@TEST-START-FILE pkg1.zeek
event zeek_init()
	{
	print "pkg1!";
	}
@TEST-END-FILE

@TEST-START-FILE pkg2/__load__.zeek
event zeek_init()
	{
	print "pkg2!";
	}
@TEST-END-FILE
