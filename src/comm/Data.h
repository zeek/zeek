#ifndef BRO_COMM_DATA_H
#define BRO_COMM_DATA_H

#include <broker/data.hh>
#include "Val.h"
#include "Reporter.h"
#include "Frame.h"
#include "Expr.h"

namespace comm {

extern OpaqueType* opaque_of_data_type;
extern OpaqueType* opaque_of_set_iterator;
extern OpaqueType* opaque_of_table_iterator;
extern OpaqueType* opaque_of_vector_iterator;
extern OpaqueType* opaque_of_record_iterator;

TransportProto to_bro_port_proto(broker::port::protocol tp);

RecordVal* make_data_val(Val* v);

RecordVal* make_data_val(broker::data d);

EnumVal* get_data_type(RecordVal* v, Frame* frame);

broker::util::optional<broker::data> val_to_data(Val* v);

Val* data_to_val(broker::data d, BroType* type);

class DataVal : public OpaqueVal {
public:

	DataVal(broker::data arg_data)
		: OpaqueVal(comm::opaque_of_data_type), data(std::move(arg_data))
		{}

	void ValDescribe(ODesc* d) const override
		{
		d->Add("broker::data{");
		d->Add(broker::to_string(data));
		d->Add("}");
		}

	broker::data data;
};

struct type_name_getter {
	using result_type = const char*;

	result_type operator()(bool a)
		{ return "bool"; }

	result_type operator()(uint64_t a)
		{ return "uint64_t"; }

	result_type operator()(int64_t a)
		{ return "int64_t"; }

	result_type operator()(double a)
		{ return "double"; }

	result_type operator()(const std::string& a)
		{ return "string"; }

	result_type operator()(const broker::address& a)
		{ return "address"; }

	result_type operator()(const broker::subnet& a)
		{ return "subnet"; }

	result_type operator()(const broker::port& a)
		{ return "port"; }

	result_type operator()(const broker::time_point& a)
		{ return "time"; }

	result_type operator()(const broker::time_duration& a)
		{ return "interval"; }

	result_type operator()(const broker::enum_value& a)
		{ return "enum"; }

	result_type operator()(const broker::set& a)
		{ return "set"; }

	result_type operator()(const broker::table& a)
		{ return "table"; }

	result_type operator()(const broker::vector& a)
		{ return "vector"; }

	result_type operator()(const broker::record& a)
		{ return "record"; }
};

broker::data& opaque_field_to_data(RecordVal* v, Frame* f);

template <typename T>
T& require_data_type(broker::data& d, TypeTag tag, Frame* f)
	{
	auto ptr = broker::get<T>(d);

	if ( ! ptr )
		reporter->RuntimeError(f->GetCall()->GetLocationInfo(),
		                       "data is of type '%s' not of type '%s'",
		                       broker::visit(type_name_getter{}, d),
		                       type_name(tag));

	return *ptr;
	}

template <typename T>
inline T& require_data_type(RecordVal* v, TypeTag tag, Frame* f)
	{
	return require_data_type<T>(opaque_field_to_data(v, f), tag, f);
	}

template <typename T>
inline Val* refine(RecordVal* v, TypeTag tag, Frame* f)
	{
	return new Val(require_data_type<T>(v, tag, f), tag);
	}

// Copying data in to iterator vals is not the fastest approach, but safer...

class SetIterator : public OpaqueVal {
public:

	SetIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(comm::opaque_of_set_iterator),
	      dat(require_data_type<broker::set>(v, TYPE_TABLE, f)),
	      it(dat.begin())
		{}

	broker::set dat;
	broker::set::iterator it;
};

class TableIterator : public OpaqueVal {
public:

	TableIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(comm::opaque_of_table_iterator),
	      dat(require_data_type<broker::table>(v, TYPE_TABLE, f)),
	      it(dat.begin())
		{}

	broker::table dat;
	broker::table::iterator it;
};

class VectorIterator : public OpaqueVal {
public:

	VectorIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(comm::opaque_of_vector_iterator),
	      dat(require_data_type<broker::vector>(v, TYPE_VECTOR, f)),
	      it(dat.begin())
		{}

	broker::vector dat;
	broker::vector::iterator it;
};

class RecordIterator : public OpaqueVal {
public:

	RecordIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(comm::opaque_of_record_iterator),
	      dat(require_data_type<broker::record>(v, TYPE_VECTOR, f)),
	      it(dat.fields.begin())
		{}

	broker::record dat;
	decltype(broker::record::fields)::iterator it;
};

} // namespace comm

#endif // BRO_COMM_DATA_H
