# @TEST-REQUIRES: grep -q ENABLE_BROKER:BOOL=true $BUILD/CMakeCache.txt
# @TEST-REQUIRES: bro --help 2>&1 | grep -q mem-leaks
# @TEST-GROUP: leaks

# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: btest-diff bro/.stdout

type bro_set: set[string];
type bro_table: table[string] of count;
type bro_vector: vector of string;

type bro_record : record {
	a: string &optional;
	b: string &default = "bee";
	c: count;
};

function broker_to_bro_record_recurse(it: opaque of Broker::RecordIterator,
                                           rval: bro_record,
                                           idx: count): bro_record
	{
	if ( Broker::record_iterator_last(it) )
		return rval;

	local field_value = Broker::record_iterator_value(it);

	if ( field_value?$d )
		switch ( idx ) {
		case 0:
			rval$a = Broker::refine_to_string(field_value);
			break;
		case 1:
			rval$b = Broker::refine_to_string(field_value);
			break;
		case 2:
			rval$c = Broker::refine_to_count(field_value);
			break;
		};

	++idx;
	Broker::record_iterator_next(it);
	return broker_to_bro_record_recurse(it, rval, idx);
	}

function broker_to_bro_record(d: Broker::Data): bro_record
	{
	return broker_to_bro_record_recurse(Broker::record_iterator(d),
	                                         bro_record($c = 0), 0);
	}

function
broker_to_bro_set_recurse(it: opaque of Broker::SetIterator,
                            rval: bro_set): bro_set
	{
	if ( Broker::set_iterator_last(it) )
		return rval;

	add rval[Broker::refine_to_string(Broker::set_iterator_value(it))];
	Broker::set_iterator_next(it);
	return broker_to_bro_set_recurse(it, rval);
	}


function broker_to_bro_set(d: Broker::Data): bro_set
	{
	return broker_to_bro_set_recurse(Broker::set_iterator(d), bro_set());
	}

function
broker_to_bro_table_recurse(it: opaque of Broker::TableIterator,
                                rval: bro_table): bro_table
	{
	if ( Broker::table_iterator_last(it) )
		return rval;

	local item = Broker::table_iterator_value(it);
	rval[Broker::refine_to_string(item$key)] = Broker::refine_to_count(item$val);
	Broker::table_iterator_next(it);
	return broker_to_bro_table_recurse(it, rval);
	}

function broker_to_bro_table(d: Broker::Data): bro_table
	{
	return broker_to_bro_table_recurse(Broker::table_iterator(d),
	                                       bro_table());
	}

function broker_to_bro_vector_recurse(it: opaque of Broker::VectorIterator,
                                           rval: bro_vector): bro_vector
	{
	if ( Broker::vector_iterator_last(it) )
		return rval;

	rval[|rval|] = Broker::refine_to_string(Broker::vector_iterator_value(it));
	Broker::vector_iterator_next(it);
	return broker_to_bro_vector_recurse(it, rval);
	}

function broker_to_bro_vector(d: Broker::Data): bro_vector
	{
	return broker_to_bro_vector_recurse(Broker::vector_iterator(d),
	                                         bro_vector());
	}

event bro_init()
{
Broker::enable();
}

global did_it = F;

event new_connection(c: connection)
{
if ( did_it ) return;
did_it = T;

### Print every broker data type

print Broker::data_type(Broker::data(T));
print Broker::data_type(Broker::data(+1));
print Broker::data_type(Broker::data(1));
print Broker::data_type(Broker::data(1.1));
print Broker::data_type(Broker::data("1 (how creative)"));
print Broker::data_type(Broker::data(1.1.1.1));
print Broker::data_type(Broker::data(1.1.1.1/1));
print Broker::data_type(Broker::data(1/udp));
print Broker::data_type(Broker::data(double_to_time(1)));
print Broker::data_type(Broker::data(1sec));
print Broker::data_type(Broker::data(Broker::BOOL));
local s: bro_set = bro_set("one", "two", "three");
local t: bro_table = bro_table(["one"] = 1, ["two"] = 2, ["three"] = 3);
local v: bro_vector = bro_vector("zero", "one", "two");
local r: bro_record = bro_record($c = 1);
print Broker::data_type(Broker::data(s));
print Broker::data_type(Broker::data(t));
print Broker::data_type(Broker::data(v));
print Broker::data_type(Broker::data(r));

print "***************************";

### Convert a Bro value to a broker value, then print the result

print Broker::refine_to_bool(Broker::data(T));
print Broker::refine_to_bool(Broker::data(F));
print Broker::refine_to_int(Broker::data(+1));
print Broker::refine_to_int(Broker::data(+0));
print Broker::refine_to_int(Broker::data(-1));
print Broker::refine_to_count(Broker::data(1));
print Broker::refine_to_count(Broker::data(0));
print Broker::refine_to_double(Broker::data(1.1));
print Broker::refine_to_double(Broker::data(-11.1));
print Broker::refine_to_string(Broker::data("hello"));
print Broker::refine_to_addr(Broker::data(1.2.3.4));
print Broker::refine_to_subnet(Broker::data(192.168.1.1/16));
print Broker::refine_to_port(Broker::data(22/tcp));
print Broker::refine_to_time(Broker::data(double_to_time(42)));
print Broker::refine_to_interval(Broker::data(3min));
print Broker::refine_to_enum_name(Broker::data(Broker::BOOL));

local cs = Broker::data(s);
print broker_to_bro_set(cs);

local ct = Broker::data(t);
print broker_to_bro_table(ct);

local cv = Broker::data(v);
print broker_to_bro_vector(cv);

local cr = Broker::data(r);
print broker_to_bro_record(cr);

r$a = "test";
cr = Broker::data(r);
print broker_to_bro_record(cr);

r$b = "testagain";
cr = Broker::data(r);
print broker_to_bro_record(cr);

print "***************************";

### Test the broker set BIFs

cs = Broker::set_create();
print Broker::set_size(cs);
print Broker::set_insert(cs, Broker::data("hi"));
print Broker::set_size(cs);
print Broker::set_contains(cs, Broker::data("hi"));
print Broker::set_contains(cs, Broker::data("bye"));
print Broker::set_insert(cs, Broker::data("bye"));
print Broker::set_size(cs);
print Broker::set_insert(cs, Broker::data("bye"));
print Broker::set_size(cs);
print Broker::set_remove(cs, Broker::data("hi"));
print Broker::set_size(cs);
print Broker::set_remove(cs, Broker::data("hi"));
print broker_to_bro_set(cs);
print Broker::set_clear(cs);
print Broker::set_size(cs);
print broker_to_bro_set(cs);

print "***************************";

### Test the broker table BIFs

ct = Broker::table_create();
print Broker::table_size(ct);
print Broker::table_insert(ct, Broker::data("hi"), Broker::data(42));
print Broker::table_size(ct);
print Broker::table_contains(ct, Broker::data("hi"));
print Broker::refine_to_count(Broker::table_lookup(ct, Broker::data("hi")));
print Broker::table_contains(ct, Broker::data("bye"));
print Broker::table_insert(ct, Broker::data("bye"), Broker::data(7));
print Broker::table_size(ct);
print Broker::table_insert(ct, Broker::data("bye"), Broker::data(37));
print Broker::table_size(ct);
print Broker::refine_to_count(Broker::table_lookup(ct, Broker::data("bye")));
print Broker::table_remove(ct, Broker::data("hi"));
print Broker::table_size(ct);
print Broker::table_remove(ct, Broker::data("hi"));
print Broker::table_size(ct);
print Broker::table_clear(ct);
print Broker::table_size(ct);
print broker_to_bro_table(ct);

print "***************************";

### Test the broker vector BIFs

cv = Broker::vector_create();
print Broker::vector_size(cv);
print Broker::vector_insert(cv, Broker::data("hi"), 0);
print Broker::vector_insert(cv, Broker::data("hello"), 1);
print Broker::vector_insert(cv, Broker::data("greetings"), 2);
print Broker::vector_insert(cv, Broker::data("salutations"), 1);
print broker_to_bro_vector(cv);
print Broker::vector_size(cv);
print Broker::vector_replace(cv, Broker::data("bah"), 2);
print Broker::vector_lookup(cv, 2);
print Broker::vector_lookup(cv, 0);
print broker_to_bro_vector(cv);
print Broker::vector_remove(cv, 2);
print broker_to_bro_vector(cv);
print Broker::vector_size(cv);
print Broker::vector_clear(cv);
print Broker::vector_size(cv);
print broker_to_bro_vector(cv);

print "***************************";

### Test the broker record BIFs

cr = Broker::record_create(3);
print Broker::record_size(cr);
print Broker::record_assign(cr, Broker::data("hi"), 0);
print Broker::record_assign(cr, Broker::data("hello"), 1);
print Broker::record_assign(cr, Broker::data(37), 2);
print Broker::record_lookup(cr, 0);
print Broker::record_lookup(cr, 1);
print Broker::record_lookup(cr, 2);
print Broker::record_size(cr);
print Broker::record_assign(cr, Broker::data("goodbye"), 1);
print Broker::record_size(cr);
print Broker::record_lookup(cr, 1);
}
