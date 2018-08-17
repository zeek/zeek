#ifndef BRO_COMM_DATA_H
#define BRO_COMM_DATA_H

#include <broker/broker.hh>
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
 * Create a Broker::Data value from a Bro value.
 * @param v the Bro value to convert to a Broker data value.
 * @return a Broker::Data value, where the optional field is set if the conversion
 * was possible, else it is unset.
 */
RecordVal* make_data_val(Val* v);

/**
 * Create a Broker::Data value from a Broker data value.
 * @param d the Broker value to wrap in an opaque type.
 * @return a Broker::Data value that wraps the Broker value.
 */
RecordVal* make_data_val(broker::data d);

/**
 * Get the type of Broker data that Broker::Data wraps.
 * @param v a Broker::Data value.
 * @param frame used to get location info upon error.
 * @return a Broker::DataType value.
 */
EnumVal* get_data_type(RecordVal* v, Frame* frame);

/**
 * Convert a Bro value to a Broker data value.
 * @param v a Bro value.
 * @return a Broker data value if the Bro value could be converted to one.
 */
broker::expected<broker::data> val_to_data(Val* v);

/**
 * Convert a Broker data value to a Bro value.
 * @param d a Broker data value.
 * @param type the expected type of the value to return.
 * @return a pointer to a new Bro value or a nullptr if the conversion was not
 * possible.
 */
Val* data_to_val(broker::data d, BroType* type);

/**
 * Convert a Bro threading::Value to a Broker data value.
 * @param v a Bro threading::Value.
 * @return a Broker data value if the Bro threading::Value could be converted to one.
 */
broker::expected<broker::data> threading_val_to_data(const threading::Value* v);

/**
 * Convert a Bro threading::Field to a Broker data value.
 * @param f a Bro threading::Field.
 * @return a Broker data value if the Bro threading::Field could be converted to one.
 */
broker::data threading_field_to_data(const threading::Field* f);

/**
 * Convert a Broker data value to a Bro threading::Value.
 * @param d a Broker data value.
 * @return a pointer to a new Bro threading::Value or a nullptr if the conversion was not
 * possible.
 */
threading::Value* data_to_threading_val(broker::data d);

/**
 * Convert a Broker data value to a Bro threading::Value.
 * @param d a Broker data value.
 * @return a pointer to a new Bro threading::Value or a nullptr if the conversion was not
 * possible.
 */
threading::Field* data_to_threading_field(broker::data d);

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

	Val* castTo(BroType* t);
	bool canCastTo(BroType* t) const;

	// Returns the Bro type that scripts use to represent a Broker data
	// instance. This may be wrapping the opaque value inside another
	// type.
	static BroType* ScriptDataType()
		{
		if ( ! script_data_type )
			script_data_type = internal_type("Broker::Data");

		return script_data_type;
		}

	DECLARE_SERIAL(DataVal);

	broker::data data;

protected:
	DataVal()
		{}

	static BroType* script_data_type;
};

/**
 * Visitor for retrieving type names a Broker data value.
 */
struct type_name_getter {
	using result_type = const char*;

	result_type operator()(broker::none)
		{ return "NONE"; } // FIXME: what's the right thing to return here?

	result_type operator()(bool)
		{ return "bool"; }

	result_type operator()(uint64_t)
		{ return "uint64_t"; }

	result_type operator()(int64_t)
		{ return "int64_t"; }

	result_type operator()(double)
		{ return "double"; }

	result_type operator()(const std::string&)
		{ return "string"; }

	result_type operator()(const broker::address&)
		{ return "address"; }

	result_type operator()(const broker::subnet&)
		{ return "subnet"; }

	result_type operator()(const broker::port&)
		{ return "port"; }

	result_type operator()(const broker::timestamp&)
		{ return "time"; }

	result_type operator()(const broker::timespan&)
		{ return "interval"; }

	result_type operator()(const broker::enum_value&)
		{ return "enum"; }

	result_type operator()(const broker::set&)
		{ return "set"; }

	result_type operator()(const broker::table&)
		{ return "table"; }

	result_type operator()(const broker::vector&)
		{ 
		assert(tag == TYPE_VECTOR || tag == TYPE_RECORD);
	 	return tag == TYPE_VECTOR ? "vector" : "record";
		}

	TypeTag tag;
};

/**
 * Retrieve Broker data value associated with a Broker::Data Bro value.
 * @param v a Broker::Data value.
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
	auto ptr = caf::get_if<T>(&d);
	if ( ! ptr )
		reporter->RuntimeError(f->GetCall()->GetLocationInfo(),
		                       "data is of type '%s' not of type '%s'",
		                       caf::visit(type_name_getter{tag}, d),
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
	      dat(require_data_type<broker::vector>(v, TYPE_RECORD, f)),
	      it(dat.begin())
		{}

	broker::vector dat;
	broker::vector::iterator it;
};

} // namespace bro_broker

#endif // BRO_COMM_DATA_H
