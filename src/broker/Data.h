#pragma once

#include "zeek/Expr.h"
#include "zeek/Frame.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Reporter.h"

#include "broker/data.hh"

namespace zeek
	{

class ODesc;

namespace threading
	{

struct Value;
struct Field;

	} // namespace threading

namespace Broker::detail
	{

extern OpaqueTypePtr opaque_of_data_type;
extern OpaqueTypePtr opaque_of_set_iterator;
extern OpaqueTypePtr opaque_of_table_iterator;
extern OpaqueTypePtr opaque_of_vector_iterator;
extern OpaqueTypePtr opaque_of_record_iterator;

/**
 * Convert a broker port protocol to a zeek port protocol.
 */
TransportProto to_zeek_port_proto(broker::port::protocol tp);

/**
 * Create a Broker::Data value from a Zeek value.
 * @param v the Zeek value to convert to a Broker data value.
 * @return a Broker::Data value, where the optional field is set if the conversion
 * was possible, else it is unset.
 */
RecordValPtr make_data_val(Val* v);

/**
 * Create a Broker::Data value from a Broker data value.
 * @param d the Broker value to wrap in an opaque type.
 * @return a Broker::Data value that wraps the Broker value.
 */
RecordValPtr make_data_val(broker::data d);

/**
 * Get the type of Broker data that Broker::Data wraps.
 * @param v a Broker::Data value.
 * @param frame used to get location info upon error.
 * @return a Broker::DataType value.
 */
EnumValPtr get_data_type(RecordVal* v, zeek::detail::Frame* frame);

/**
 * Convert a Zeek value to a Broker data value.
 * @param v a Zeek value.
 * @return a Broker data value if the Zeek value could be converted to one.
 */
broker::expected<broker::data> val_to_data(const Val* v);

/**
 * Convert a Broker data value to a Zeek value.
 * @param d a Broker data value.
 * @param type the expected type of the value to return.
 * @return a pointer to a new Zeek value or a nullptr if the conversion was not
 * possible.
 */
ValPtr data_to_val(broker::data d, Type* type);

/**
 * Convert a zeek::threading::Field to a Broker data value.
 * @param f a zeek::threading::Field.
 * @return a Broker data value if the zeek::threading::Field could be converted to one.
 */
broker::data threading_field_to_data(const threading::Field* f);

/**
 * Convert a Broker data value to a zeek::threading::Value.
 * @param d a Broker data value.
 * @return a pointer to a new zeek::threading::Value or a nullptr if the conversion was not
 * possible.
 */
threading::Field* data_to_threading_field(broker::data d);

/**
 * A Zeek value which wraps a Broker data value.
 */
class DataVal : public OpaqueVal
	{
public:
	DataVal(broker::data arg_data) : OpaqueVal(opaque_of_data_type), data(std::move(arg_data)) { }

	void ValDescribe(ODesc* d) const override;

	ValPtr castTo(zeek::Type* t);
	bool canCastTo(zeek::Type* t) const;

	// Returns the Zeek type that scripts use to represent a Broker data
	// instance. This may be wrapping the opaque value inside another
	// type.
	static const TypePtr& ScriptDataType();

	broker::data data;

protected:
	DataVal() : OpaqueVal(opaque_of_data_type) { }

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::DataVal)
	};

/**
 * Visitor for retrieving type names a Broker data value.
 */
struct type_name_getter
	{
	using result_type = const char*;

	result_type operator()(broker::none)
		{
		return "NONE";
		} // FIXME: what's the right thing to return here?

	result_type operator()(bool) { return "bool"; }

	result_type operator()(uint64_t) { return "uint64_t"; }

	result_type operator()(int64_t) { return "int64_t"; }

	result_type operator()(double) { return "double"; }

	result_type operator()(const std::string&) { return "string"; }

	result_type operator()(const broker::address&) { return "address"; }

	result_type operator()(const broker::subnet&) { return "subnet"; }

	result_type operator()(const broker::port&) { return "port"; }

	result_type operator()(const broker::timestamp&) { return "time"; }

	result_type operator()(const broker::timespan&) { return "interval"; }

	result_type operator()(const broker::enum_value&) { return "enum"; }

	result_type operator()(const broker::set&) { return "set"; }

	result_type operator()(const broker::table&) { return "table"; }

	result_type operator()(const broker::vector&)
		{
		assert(tag == zeek::TYPE_VECTOR || tag == zeek::TYPE_RECORD);
		return tag == zeek::TYPE_VECTOR ? "vector" : "record";
		}

	zeek::TypeTag tag;
	};

/**
 * Retrieve Broker data value associated with a Broker::Data Zeek value.
 * @param v a Broker::Data value.
 * @param f used to get location information on error.
 * @return a reference to the wrapped Broker data value.  A runtime interpreter
 * exception is thrown if the the optional opaque value of \a v is not set.
 */
broker::data& opaque_field_to_data(zeek::RecordVal* v, zeek::detail::Frame* f);

/**
 * Retrieve variant data from a Broker data value.
 * @tparam T a type that the variant may contain.
 * @param d a Broker data value to get variant data out of.
 * @param tag a Zeek tag which corresponds to T (just used for error reporting).
 * @param f used to get location information on error.
 * @return a refrence to the requested type in the variant Broker data.
 * A runtime interpret exception is thrown if trying to access a type which
 * is not currently stored in the Broker data.
 */
template <typename T>
T& require_data_type(broker::data& d, zeek::TypeTag tag, zeek::detail::Frame* f)
	{
	auto ptr = broker::get_if<T>(&d);
	if ( ! ptr )
		zeek::reporter->RuntimeError(f->GetCallLocation(), "data is of type '%s' not of type '%s'",
		                             visit(type_name_getter{tag}, d), zeek::type_name(tag));

	return *ptr;
	}

/**
 * @see require_data_type() and opaque_field_to_data().
 */
template <typename T>
inline T& require_data_type(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
	{
	return require_data_type<T>(opaque_field_to_data(v, f), tag, f);
	}

// Copying data into iterator vals is not the fastest approach, but safer...

class SetIterator : public zeek::OpaqueVal
	{
public:
	SetIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
		: zeek::OpaqueVal(opaque_of_set_iterator),
		  dat(require_data_type<broker::set>(v, zeek::TYPE_TABLE, f)), it(dat.begin())
		{
		}

	broker::set dat;
	broker::set::iterator it;

protected:
	SetIterator() : zeek::OpaqueVal(opaque_of_set_iterator) { }

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::SetIterator)
	};

class TableIterator : public zeek::OpaqueVal
	{
public:
	TableIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
		: zeek::OpaqueVal(opaque_of_table_iterator),
		  dat(require_data_type<broker::table>(v, zeek::TYPE_TABLE, f)), it(dat.begin())
		{
		}

	broker::table dat;
	broker::table::iterator it;

protected:
	TableIterator() : zeek::OpaqueVal(opaque_of_table_iterator) { }

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::TableIterator)
	};

class VectorIterator : public zeek::OpaqueVal
	{
public:
	VectorIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
		: zeek::OpaqueVal(opaque_of_vector_iterator),
		  dat(require_data_type<broker::vector>(v, zeek::TYPE_VECTOR, f)), it(dat.begin())
		{
		}

	broker::vector dat;
	broker::vector::iterator it;

protected:
	VectorIterator() : zeek::OpaqueVal(opaque_of_vector_iterator) { }

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::VectorIterator)
	};

class RecordIterator : public zeek::OpaqueVal
	{
public:
	RecordIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
		: zeek::OpaqueVal(opaque_of_record_iterator),
		  dat(require_data_type<broker::vector>(v, zeek::TYPE_RECORD, f)), it(dat.begin())
		{
		}

	broker::vector dat;
	broker::vector::iterator it;

protected:
	RecordIterator() : zeek::OpaqueVal(opaque_of_record_iterator) { }

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::RecordIterator)
	};

	} // namespace Broker::detail
	} // namespace zeek
