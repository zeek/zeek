# @TEST-REQUIRES: grep -q ENABLE_BROKER $BUILD/CMakeCache.txt

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

function comm_record_to_bro_record_recurse(it: opaque of BrokerComm::RecordIterator,
                                           rval: bro_record,
                                           idx: count): bro_record
	{
	if ( BrokerComm::record_iterator_last(it) )
		return rval;

	local field_value = BrokerComm::record_iterator_value(it);

	if ( field_value?$d )
		switch ( idx ) {
		case 0:
			rval$a = BrokerComm::refine_to_string(field_value);
			break;
		case 1:
			rval$b = BrokerComm::refine_to_string(field_value);
			break;
		case 2:
			rval$c = BrokerComm::refine_to_count(field_value);
			break;
		};

	++idx;
	BrokerComm::record_iterator_next(it);
	return comm_record_to_bro_record_recurse(it, rval, idx);
	}

function comm_record_to_bro_record(d: BrokerComm::Data): bro_record
	{
	return comm_record_to_bro_record_recurse(BrokerComm::record_iterator(d),
	                                         bro_record($c = 0), 0);
	}

function
comm_set_to_bro_set_recurse(it: opaque of BrokerComm::SetIterator,
                            rval: bro_set): bro_set
	{
	if ( BrokerComm::set_iterator_last(it) )
		return rval;

	add rval[BrokerComm::refine_to_string(BrokerComm::set_iterator_value(it))];
	BrokerComm::set_iterator_next(it);
	return comm_set_to_bro_set_recurse(it, rval);
	}


function comm_set_to_bro_set(d: BrokerComm::Data): bro_set
	{
	return comm_set_to_bro_set_recurse(BrokerComm::set_iterator(d), bro_set());
	}

function
comm_table_to_bro_table_recurse(it: opaque of BrokerComm::TableIterator,
                                rval: bro_table): bro_table
	{
	if ( BrokerComm::table_iterator_last(it) )
		return rval;

	local item = BrokerComm::table_iterator_value(it);
	rval[BrokerComm::refine_to_string(item$key)] = BrokerComm::refine_to_count(item$val);
	BrokerComm::table_iterator_next(it);
	return comm_table_to_bro_table_recurse(it, rval);
	}

function comm_table_to_bro_table(d: BrokerComm::Data): bro_table
	{
	return comm_table_to_bro_table_recurse(BrokerComm::table_iterator(d),
	                                       bro_table());
	}

function comm_vector_to_bro_vector_recurse(it: opaque of BrokerComm::VectorIterator,
                                           rval: bro_vector): bro_vector
	{
	if ( BrokerComm::vector_iterator_last(it) )
		return rval;

	rval[|rval|] = BrokerComm::refine_to_string(BrokerComm::vector_iterator_value(it));
	BrokerComm::vector_iterator_next(it);
	return comm_vector_to_bro_vector_recurse(it, rval);
	}

function comm_vector_to_bro_vector(d: BrokerComm::Data): bro_vector
	{
	return comm_vector_to_bro_vector_recurse(BrokerComm::vector_iterator(d),
	                                         bro_vector());
	}

event bro_init()
{
BrokerComm::enable();
print BrokerComm::data_type(BrokerComm::data(T));
print BrokerComm::data_type(BrokerComm::data(+1));
print BrokerComm::data_type(BrokerComm::data(1));
print BrokerComm::data_type(BrokerComm::data(1.1));
print BrokerComm::data_type(BrokerComm::data("1 (how creative)"));
print BrokerComm::data_type(BrokerComm::data(1.1.1.1));
print BrokerComm::data_type(BrokerComm::data(1.1.1.1/1));
print BrokerComm::data_type(BrokerComm::data(1/udp));
print BrokerComm::data_type(BrokerComm::data(double_to_time(1)));
print BrokerComm::data_type(BrokerComm::data(1sec));
print BrokerComm::data_type(BrokerComm::data(BrokerComm::BOOL));
local s: bro_set = bro_set("one", "two", "three");
local t: bro_table = bro_table(["one"] = 1, ["two"] = 2, ["three"] = 3);
local v: bro_vector = bro_vector("zero", "one", "two");
local r: bro_record = bro_record($c = 1);
print BrokerComm::data_type(BrokerComm::data(s));
print BrokerComm::data_type(BrokerComm::data(t));
print BrokerComm::data_type(BrokerComm::data(v));
print BrokerComm::data_type(BrokerComm::data(r));

print "***************************";

print BrokerComm::refine_to_bool(BrokerComm::data(T));
print BrokerComm::refine_to_bool(BrokerComm::data(F));
print BrokerComm::refine_to_int(BrokerComm::data(+1));
print BrokerComm::refine_to_int(BrokerComm::data(+0));
print BrokerComm::refine_to_int(BrokerComm::data(-1));
print BrokerComm::refine_to_count(BrokerComm::data(1));
print BrokerComm::refine_to_count(BrokerComm::data(0));
print BrokerComm::refine_to_double(BrokerComm::data(1.1));
print BrokerComm::refine_to_double(BrokerComm::data(-11.1));
print BrokerComm::refine_to_string(BrokerComm::data("hello"));
print BrokerComm::refine_to_addr(BrokerComm::data(1.2.3.4));
print BrokerComm::refine_to_subnet(BrokerComm::data(192.168.1.1/16));
print BrokerComm::refine_to_port(BrokerComm::data(22/tcp));
print BrokerComm::refine_to_time(BrokerComm::data(double_to_time(42)));
print BrokerComm::refine_to_interval(BrokerComm::data(3min));
print BrokerComm::refine_to_enum_name(BrokerComm::data(BrokerComm::BOOL));

print "***************************";

local cs = BrokerComm::data(s);
print comm_set_to_bro_set(cs);
cs = BrokerComm::set_create();
print BrokerComm::set_size(cs);
print BrokerComm::set_insert(cs, BrokerComm::data("hi"));
print BrokerComm::set_size(cs);
print BrokerComm::set_contains(cs, BrokerComm::data("hi"));
print BrokerComm::set_contains(cs, BrokerComm::data("bye"));
print BrokerComm::set_insert(cs, BrokerComm::data("bye"));
print BrokerComm::set_size(cs);
print BrokerComm::set_remove(cs, BrokerComm::data("hi"));
print BrokerComm::set_size(cs);
print BrokerComm::set_remove(cs, BrokerComm::data("hi"));
print comm_set_to_bro_set(cs);
BrokerComm::set_clear(cs);
print BrokerComm::set_size(cs);

print "***************************";

local ct = BrokerComm::data(t);
print comm_table_to_bro_table(ct);
ct = BrokerComm::table_create();
print BrokerComm::table_size(ct);
print BrokerComm::table_insert(ct, BrokerComm::data("hi"), BrokerComm::data(42));
print BrokerComm::table_size(ct);
print BrokerComm::table_contains(ct, BrokerComm::data("hi"));
print BrokerComm::refine_to_count(BrokerComm::table_lookup(ct, BrokerComm::data("hi")));
print BrokerComm::table_contains(ct, BrokerComm::data("bye"));
print BrokerComm::table_insert(ct, BrokerComm::data("bye"), BrokerComm::data(7));
print BrokerComm::table_size(ct);
print BrokerComm::table_insert(ct, BrokerComm::data("bye"), BrokerComm::data(37));
print BrokerComm::table_size(ct);
print BrokerComm::refine_to_count(BrokerComm::table_lookup(ct, BrokerComm::data("bye")));
print BrokerComm::table_remove(ct, BrokerComm::data("hi"));
print BrokerComm::table_size(ct);

print "***************************";

local cv = BrokerComm::data(v);
print comm_vector_to_bro_vector(cv);
cv = BrokerComm::vector_create();
print BrokerComm::vector_size(cv);
print BrokerComm::vector_insert(cv, BrokerComm::data("hi"), 0);
print BrokerComm::vector_insert(cv, BrokerComm::data("hello"), 1);
print BrokerComm::vector_insert(cv, BrokerComm::data("greetings"), 2);
print BrokerComm::vector_insert(cv, BrokerComm::data("salutations"), 1);
print comm_vector_to_bro_vector(cv);
print BrokerComm::vector_size(cv);
print BrokerComm::vector_replace(cv, BrokerComm::data("bah"), 2);
print BrokerComm::vector_lookup(cv, 2);
print BrokerComm::vector_lookup(cv, 0);
print comm_vector_to_bro_vector(cv);
print BrokerComm::vector_remove(cv, 2);
print comm_vector_to_bro_vector(cv);
print BrokerComm::vector_size(cv);

print "***************************";

local cr = BrokerComm::data(r);
print comm_record_to_bro_record(cr);
r$a = "test";
cr = BrokerComm::data(r);
print comm_record_to_bro_record(cr);
r$b = "testagain";
cr = BrokerComm::data(r);
print comm_record_to_bro_record(cr);
cr = BrokerComm::record_create(3);
print BrokerComm::record_size(cr);
print BrokerComm::record_assign(cr, BrokerComm::data("hi"), 0);
print BrokerComm::record_assign(cr, BrokerComm::data("hello"), 1);
print BrokerComm::record_assign(cr, BrokerComm::data(37), 2);
print BrokerComm::record_lookup(cr, 0);
print BrokerComm::record_lookup(cr, 1);
print BrokerComm::record_lookup(cr, 2);
print BrokerComm::record_size(cr);
}
