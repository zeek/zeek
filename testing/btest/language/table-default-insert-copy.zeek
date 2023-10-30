# @TEST-DOC: Ensure &default_insert is copied with a table.
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global tbl: table[count] of string &default_insert="<default>";

event zeek_init()
	{
	tbl[0] = "no-default";
	local copy_tbl = copy(tbl);
	print "copy_tbl[0]", copy_tbl[0];
	print "copy_tbl[1]", copy_tbl[1];
	print "copy_tbl", copy_tbl;
	print "tbl", tbl;

	assert 0 in copy_tbl;
	assert 1 in copy_tbl;
	assert |copy_tbl| == 2;
	assert |tbl| == 1;
	}
