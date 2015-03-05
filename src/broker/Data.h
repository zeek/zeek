#ifndef BRO_COMM_DATA_H
#define BRO_COMM_DATA_H

#include <broker/data.hh>
#include "Val.h"
#include "Reporter.h"
#include "Frame.h"
#include "Expr.h"

namespace bro_broker {

extern OpaqueType* opaque_of_data_type;
extern OpaqueType* opaque_of_set_iterator;
extern OpaqueType* opaque_of_table_iterator;
extern OpaqueType* opaque_of_vector_iterator;
extern OpaqueType* opaque_of_record_iterator;

/**
 * Convert a broker port protocol to a bro port protocol.
 */
TransportProto to_bro_port_proto(broker::port::protocol tp);

/**
 * Create a BrokerComm::Data value from a Bro value.
 * @param v the Bro value to convert to a Broker data value.
 * @return a BrokerComm::Data value, where the optional field is set if the conversion
 * was possible, else it is unset.
 */
RecordVal* make_data_val(Val* v);

/**
 * Create a BrokerComm::Data value from a Broker data value.
 * @param d the Broker value to wrap in an opaque type.
 * @return a BrokerComm::Data value that wraps the Broker value.
 */
RecordVal* make_data_val(broker::data d);

/**
 * Get the type of Broker data that BrokerComm::Data wraps.
 * @param v a BrokerComm::Data value.
 * @param frame used to get location info upon error.
 * @return a BrokerComm::DataType value.
 */
EnumVal* get_data_type(RecordVal* v, Frame* frame);

/**
 * Convert a Bro value to a Broker data value.
 * @param v a Bro value.
 * @return a Broker data value if the Bro value could be converted to one.
 */
broker::util::optional<broker::data> val_to_data(Val* v);

/**
 * Convert a Broker data value to a Bro value.
 * @param d a Broker data value.
 * @param type the expected type of the value to return.
 * @param require_log_attr if true, skip over record fields that don't have the
 * &log attribute.
 * @return a pointer to a new Bro value or a nullptr if the conversion was not
 * possible.
 */
Val* data_to_val(broker::data d, BroType* type, bool require_log_attr = false);

/**
 * A Bro value which wraps a Broker data value.
 */
class DataVal : public OpaqueVal {
public:

	DataVal(broker::data arg_data)
		: OpaqueVal(bro_broker::opaque_of_data_type), data(std::move(arg_data))
		{}

	void ValDescribe(ODesc* d) const override
		{
		d->Add("broker::data{");
		d->Add(broker::to_string(data));
		d->Add("}");
		}

	DECLARE_SERIAL(DataVal);

	broker::data data;

protected:

	DataVal()
		{}
};

/**
 * Visitor for retrieving type names a Broker data value.
 */
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

/**
 * Retrieve Broker data value associated with a BrokerComm::Data Bro value.
 * @param v a BrokerComm::Data value.
 * @param f used to get location information on error.
 * @return a reference to the wrapped Broker data value.  A runtime interpreter
 * exception is thrown if the the optional opaque value of \a v is not set.
 */
broker::data& opaque_field_to_data(RecordVal* v, Frame* f);

/**
 * Retrieve variant data from a Broker data value.
 * @tparam T a type that the variant may contain.
 * @param d a Broker data value to get variant data out of.
 * @param tag a Bro tag which corresponds to T (just used for error reporting).
 * @param f used to get location information on error.
 * @return a refrence to the requested type in the variant Broker data.
 * A runtime interpret exception is thrown if trying to access a type which
 * is not currently stored in the Broker data.
 */
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

/**
 * @see require_data_type() and opaque_field_to_data().
 */
template <typename T>
inline T& require_data_type(RecordVal* v, TypeTag tag, Frame* f)
	{
	return require_data_type<T>(opaque_field_to_data(v, f), tag, f);
	}

/**
 * Convert a BrokerComm::Data Bro value to a Bro value of a given type.
 * @tparam a type that a Broker data variant may contain.
 * @param v a BrokerComm::Data value.
 * @param tag a Bro type to convert to.
 * @param f used to get location information on error.
 * A runtime interpret exception is thrown if trying to access a type which
 * is not currently stored in the Broker data.
 */
template <typename T>
inline Val* refine(RecordVal* v, TypeTag tag, Frame* f)
	{
	return new Val(require_data_type<T>(v, tag, f), tag);
	}

// Copying data in to iterator vals is not the fastest approach, but safer...

class SetIterator : public OpaqueVal {
public:

	SetIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(bro_broker::opaque_of_set_iterator),
	      dat(require_data_type<broker::set>(v, TYPE_TABLE, f)),
	      it(dat.begin())
		{}

	broker::set dat;
	broker::set::iterator it;
};

class TableIterator : public OpaqueVal {
public:

	TableIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(bro_broker::opaque_of_table_iterator),
	      dat(require_data_type<broker::table>(v, TYPE_TABLE, f)),
	      it(dat.begin())
		{}

	broker::table dat;
	broker::table::iterator it;
};

class VectorIterator : public OpaqueVal {
public:

	VectorIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(bro_broker::opaque_of_vector_iterator),
	      dat(require_data_type<broker::vector>(v, TYPE_VECTOR, f)),
	      it(dat.begin())
		{}

	broker::vector dat;
	broker::vector::iterator it;
};

class RecordIterator : public OpaqueVal {
public:

	RecordIterator(RecordVal* v, TypeTag tag, Frame* f)
	    : OpaqueVal(bro_broker::opaque_of_record_iterator),
	      dat(require_data_type<broker::record>(v, TYPE_VECTOR, f)),
	      it(dat.fields.begin())
		{}

	broker::record dat;
	decltype(broker::record::fields)::iterator it;
};

} // namespace bro_broker

#endif // BRO_COMM_DATA_H
