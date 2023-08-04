# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

global tbl: table[count] of string &default_insert="<default>";
global tbl_vec: table[count] of vector of string &default_insert=vector("a", "b");

type R: record {
	a: string;
};
global tbl_def_func: table[count] of R &default_insert=function(c: count): R { return R($a=cat(c)); };

# This takes a different code path than without a table constructor.
global tbl_construct = table([1] = R($a="1")) &default_insert=function(c: count): R { return R($a=cat(c)); };

event zeek_init()
	{
	print type_name(tbl_construct);

	print "===";
	print tbl[0];
	print tbl;

	print "===";
	print tbl_vec[0];
	print tbl_vec[1];
	tbl_vec[0] += "c";
	tbl_vec[1] += "d";
	print tbl_vec;

	print "===";
	print tbl_def_func[0];
	print tbl_def_func[1];
	print tbl_def_func;

	print "===";
	print tbl_construct[0];
	print tbl_construct[1];
	print tbl_construct;
	}
