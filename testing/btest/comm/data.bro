# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

type bro_set: set[string];
type bro_table: table[string] of count;
type bro_vector: vector of string;

type bro_record : record {
	a: string &optional;
	b: string &default = "bee";
	c: count;
};

function comm_record_to_bro_record_recurse(it: opaque of Comm::RecordIterator,
                                           rval: bro_record,
                                           idx: count): bro_record
	{
	if ( Comm::record_iterator_last(it) )
		return rval;

	local field_value = Comm::record_iterator_value(it);

	if ( field_value?$d )
		switch ( idx ) {
		case 0:
			rval$a = Comm::refine_to_string(field_value);
			break;
		case 1:
			rval$b = Comm::refine_to_string(field_value);
			break;
		case 2:
			rval$c = Comm::refine_to_count(field_value);
			break;
		};

	++idx;
	Comm::record_iterator_next(it);
	return comm_record_to_bro_record_recurse(it, rval, idx);
	}

function comm_record_to_bro_record(d: Comm::Data): bro_record
	{
	return comm_record_to_bro_record_recurse(Comm::record_iterator(d),
	                                         bro_record($c = 0), 0);
	}

function
comm_set_to_bro_set_recurse(it: opaque of Comm::SetIterator,
                            rval: bro_set): bro_set
	{
	if ( Comm::set_iterator_last(it) )
		return rval;

	add rval[Comm::refine_to_string(Comm::set_iterator_value(it))];
	Comm::set_iterator_next(it);
	return comm_set_to_bro_set_recurse(it, rval);
	}


function comm_set_to_bro_set(d: Comm::Data): bro_set
	{
	return comm_set_to_bro_set_recurse(Comm::set_iterator(d), bro_set());
	}

function
comm_table_to_bro_table_recurse(it: opaque of Comm::TableIterator,
                                rval: bro_table): bro_table
	{
	if ( Comm::table_iterator_last(it) )
		return rval;

	local item = Comm::table_iterator_value(it);
	rval[Comm::refine_to_string(item$key)] = Comm::refine_to_count(item$val);
	Comm::table_iterator_next(it);
	return comm_table_to_bro_table_recurse(it, rval);
	}

function comm_table_to_bro_table(d: Comm::Data): bro_table
	{
	return comm_table_to_bro_table_recurse(Comm::table_iterator(d),
	                                       bro_table());
	}

function comm_vector_to_bro_vector_recurse(it: opaque of Comm::VectorIterator,
                                           rval: bro_vector): bro_vector
	{
	if ( Comm::vector_iterator_last(it) )
		return rval;

	rval[|rval|] = Comm::refine_to_string(Comm::vector_iterator_value(it));
	Comm::vector_iterator_next(it);
	return comm_vector_to_bro_vector_recurse(it, rval);
	}

function comm_vector_to_bro_vector(d: Comm::Data): bro_vector
	{
	return comm_vector_to_bro_vector_recurse(Comm::vector_iterator(d),
	                                         bro_vector());
	}

event bro_init()
{
print Comm::data_type(Comm::data(T));
print Comm::data_type(Comm::data(+1));
print Comm::data_type(Comm::data(1));
print Comm::data_type(Comm::data(1.1));
print Comm::data_type(Comm::data("1 (how creative)"));
print Comm::data_type(Comm::data(1.1.1.1));
print Comm::data_type(Comm::data(1.1.1.1/1));
print Comm::data_type(Comm::data(1/udp));
print Comm::data_type(Comm::data(double_to_time(1)));
print Comm::data_type(Comm::data(1sec));
print Comm::data_type(Comm::data(Comm::BOOL));
local s: bro_set = bro_set("one", "two", "three");
local t: bro_table = bro_table(["one"] = 1, ["two"] = 2, ["three"] = 3);
local v: bro_vector = bro_vector("zero", "one", "two");
local r: bro_record = bro_record($c = 1);
print Comm::data_type(Comm::data(s));
print Comm::data_type(Comm::data(t));
print Comm::data_type(Comm::data(v));
print Comm::data_type(Comm::data(r));

print "***************************";

print Comm::refine_to_bool(Comm::data(T));
print Comm::refine_to_bool(Comm::data(F));
print Comm::refine_to_int(Comm::data(+1));
print Comm::refine_to_int(Comm::data(+0));
print Comm::refine_to_int(Comm::data(-1));
print Comm::refine_to_count(Comm::data(1));
print Comm::refine_to_count(Comm::data(0));
print Comm::refine_to_double(Comm::data(1.1));
print Comm::refine_to_double(Comm::data(-11.1));
print Comm::refine_to_string(Comm::data("hello"));
print Comm::refine_to_addr(Comm::data(1.2.3.4));
print Comm::refine_to_subnet(Comm::data(192.168.1.1/16));
print Comm::refine_to_port(Comm::data(22/tcp));
print Comm::refine_to_time(Comm::data(double_to_time(42)));
print Comm::refine_to_interval(Comm::data(3min));
print Comm::refine_to_enum_name(Comm::data(Comm::BOOL));

print "***************************";

local cs = Comm::data(s);
print comm_set_to_bro_set(cs);
cs = Comm::set_create();
print Comm::set_size(cs);
print Comm::set_insert(cs, Comm::data("hi"));
print Comm::set_size(cs);
print Comm::set_contains(cs, Comm::data("hi"));
print Comm::set_contains(cs, Comm::data("bye"));
print Comm::set_insert(cs, Comm::data("bye"));
print Comm::set_size(cs);
print Comm::set_remove(cs, Comm::data("hi"));
print Comm::set_size(cs);
print Comm::set_remove(cs, Comm::data("hi"));
print comm_set_to_bro_set(cs);
Comm::set_clear(cs);
print Comm::set_size(cs);

print "***************************";

local ct = Comm::data(t);
print comm_table_to_bro_table(ct);
ct = Comm::table_create();
print Comm::table_size(ct);
print Comm::table_insert(ct, Comm::data("hi"), Comm::data(42));
print Comm::table_size(ct);
print Comm::table_contains(ct, Comm::data("hi"));
print Comm::refine_to_count(Comm::table_lookup(ct, Comm::data("hi")));
print Comm::table_contains(ct, Comm::data("bye"));
print Comm::table_insert(ct, Comm::data("bye"), Comm::data(7));
print Comm::table_size(ct);
print Comm::table_insert(ct, Comm::data("bye"), Comm::data(37));
print Comm::table_size(ct);
print Comm::refine_to_count(Comm::table_lookup(ct, Comm::data("bye")));
print Comm::table_remove(ct, Comm::data("hi"));
print Comm::table_size(ct);

print "***************************";

local cv = Comm::data(v);
print comm_vector_to_bro_vector(cv);
cv = Comm::vector_create();
print Comm::vector_size(cv);
print Comm::vector_insert(cv, Comm::data("hi"), 0);
print Comm::vector_insert(cv, Comm::data("hello"), 1);
print Comm::vector_insert(cv, Comm::data("greetings"), 2);
print Comm::vector_insert(cv, Comm::data("salutations"), 1);
print comm_vector_to_bro_vector(cv);
print Comm::vector_size(cv);
print Comm::vector_replace(cv, Comm::data("bah"), 2);
print Comm::vector_lookup(cv, 2);
print Comm::vector_lookup(cv, 0);
print comm_vector_to_bro_vector(cv);
print Comm::vector_remove(cv, 2);
print comm_vector_to_bro_vector(cv);
print Comm::vector_size(cv);

print "***************************";

local cr = Comm::data(r);
print comm_record_to_bro_record(cr);
r$a = "test";
cr = Comm::data(r);
print comm_record_to_bro_record(cr);
r$b = "testagain";
cr = Comm::data(r);
print comm_record_to_bro_record(cr);
cr = Comm::record_create(3);
print Comm::record_size(cr);
print Comm::record_assign(cr, Comm::data("hi"), 0);
print Comm::record_assign(cr, Comm::data("hello"), 1);
print Comm::record_assign(cr, Comm::data(37), 2);
print Comm::record_lookup(cr, 0);
print Comm::record_lookup(cr, 1);
print Comm::record_lookup(cr, 2);
print Comm::record_size(cr);
}
