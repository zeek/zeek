#pragma once

#include "OpaqueVal.h"
#include "Reporter.h"
#include "Frame.h"
#include "Expr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(ODesc, zeek);
namespace zeek::threading {
	struct Value;
	struct Field;
}
namespace threading {
	using Value [[deprecated("Remove in v4.1. Use zeek::threading::Value.")]] = zeek::threading::Value;
	using Field [[deprecated("Remove in v4.1. Use zeek::threading::Field.")]] = zeek::threading::Field;
}

namespace zeek::Broker::detail {

extern zeek::OpaqueTypePtr opaque_of_data_type;
extern zeek::OpaqueTypePtr opaque_of_set_iterator;
extern zeek::OpaqueTypePtr opaque_of_table_iterator;
extern zeek::OpaqueTypePtr opaque_of_vector_iterator;
extern zeek::OpaqueTypePtr opaque_of_record_iterator;

/**
 * Convert a broker port protocol to a zeek port protocol.
 */
TransportProto to_zeek_port_proto(broker::port::protocol tp);

/**
 * Create a Broker::Data value from a Bro value.
 * @param v the Bro value to convert to a Broker data value.
 * @return a Broker::Data value, where the optional field is set if the conversion
 * was possible, else it is unset.
 */
zeek::RecordValPtr make_data_val(zeek::Val* v);

/**
 * Create a Broker::Data value from a Broker data value.
 * @param d the Broker value to wrap in an opaque type.
 * @return a Broker::Data value that wraps the Broker value.
 */
zeek::RecordValPtr make_data_val(broker::data d);

/**
 * Get the type of Broker data that Broker::Data wraps.
 * @param v a Broker::Data value.
 * @param frame used to get location info upon error.
 * @return a Broker::DataType value.
 */
zeek::EnumValPtr get_data_type(zeek::RecordVal* v, zeek::detail::Frame* frame);

/**
 * Convert a Bro value to a Broker data value.
 * @param v a Bro value.
 * @return a Broker data value if the Bro value could be converted to one.
 */
broker::expected<broker::data> val_to_data(const zeek::Val* v);

/**
 * Convert a Broker data value to a Bro value.
 * @param d a Broker data value.
 * @param type the expected type of the value to return.
 * @return a pointer to a new Bro value or a nullptr if the conversion was not
 * possible.
 */
zeek::ValPtr data_to_val(broker::data d, zeek::Type* type);

/**
 * Convert a zeek::threading::Value to a Broker data value.
 * @param v a zeek::threading::Value.
 * @return a Broker data value if the zeek::threading::Value could be converted to one.
 */
broker::expected<broker::data> threading_val_to_data(const zeek::threading::Value* v);

/**
 * Convert a zeek::threading::Field to a Broker data value.
 * @param f a zeek::threading::Field.
 * @return a Broker data value if the zeek::threading::Field could be converted to one.
 */
broker::data threading_field_to_data(const zeek::threading::Field* f);

/**
 * Convert a Broker data value to a zeek::threading::Value.
 * @param d a Broker data value.
 * @return a pointer to a new zeek::threading::Value or a nullptr if the conversion was not
 * possible.
 */
zeek::threading::Value* data_to_threading_val(broker::data d);

/**
 * Convert a Broker data value to a zeek::threading::Value.
 * @param d a Broker data value.
 * @return a pointer to a new zeek::threading::Value or a nullptr if the conversion was not
 * possible.
 */
zeek::threading::Field* data_to_threading_field(broker::data d);

/**
 * A Bro value which wraps a Broker data value.
 */
class DataVal : public zeek::OpaqueVal {
public:

	DataVal(broker::data arg_data)
		: OpaqueVal(zeek::Broker::detail::opaque_of_data_type), data(std::move(arg_data))
		{}

	void ValDescribe(zeek::ODesc* d) const override;

	zeek::ValPtr castTo(zeek::Type* t);
	bool canCastTo(zeek::Type* t) const;

	// Returns the Bro type that scripts use to represent a Broker data
	// instance. This may be wrapping the opaque value inside another
	// type.
	static const zeek::TypePtr& ScriptDataType();

	broker::data data;

protected:
	DataVal()
		: OpaqueVal(zeek::Broker::detail::opaque_of_data_type)
		{}

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::DataVal)
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
		assert(tag == zeek::TYPE_VECTOR || tag == zeek::TYPE_RECORD);
		return tag == zeek::TYPE_VECTOR ? "vector" : "record";
		}

	zeek::TypeTag tag;
};

/**
 * Retrieve Broker data value associated with a Broker::Data Bro value.
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
 * @param tag a Bro tag which corresponds to T (just used for error reporting).
 * @param f used to get location information on error.
 * @return a refrence to the requested type in the variant Broker data.
 * A runtime interpret exception is thrown if trying to access a type which
 * is not currently stored in the Broker data.
 */
template <typename T>
T& require_data_type(broker::data& d, zeek::TypeTag tag, zeek::detail::Frame* f)
	{
	auto ptr = caf::get_if<T>(&d);
	if ( ! ptr )
		zeek::reporter->RuntimeError(f->GetCall()->GetLocationInfo(),
		                             "data is of type '%s' not of type '%s'",
		                             caf::visit(type_name_getter{tag}, d),
		                             zeek::type_name(tag));

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

// Copying data in to iterator vals is not the fastest approach, but safer...

class SetIterator : public zeek::OpaqueVal {
public:

	SetIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
	    : zeek::OpaqueVal(zeek::Broker::detail::opaque_of_set_iterator),
	      dat(require_data_type<broker::set>(v, zeek::TYPE_TABLE, f)),
	      it(dat.begin())
		{}

	broker::set dat;
	broker::set::iterator it;

protected:
	SetIterator()
		: zeek::OpaqueVal(zeek::Broker::detail::opaque_of_set_iterator)
		{}

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::SetIterator)
};

class TableIterator : public zeek::OpaqueVal {
public:

	TableIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
	    : zeek::OpaqueVal(zeek::Broker::detail::opaque_of_table_iterator),
	      dat(require_data_type<broker::table>(v, zeek::TYPE_TABLE, f)),
	      it(dat.begin())
		{}

	broker::table dat;
	broker::table::iterator it;

protected:
	TableIterator()
		: zeek::OpaqueVal(zeek::Broker::detail::opaque_of_table_iterator)
		{}

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::TableIterator)
};

class VectorIterator : public zeek::OpaqueVal {
public:

	VectorIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
	    : zeek::OpaqueVal(zeek::Broker::detail::opaque_of_vector_iterator),
	      dat(require_data_type<broker::vector>(v, zeek::TYPE_VECTOR, f)),
	      it(dat.begin())
		{}

	broker::vector dat;
	broker::vector::iterator it;

protected:
	VectorIterator()
		: zeek::OpaqueVal(zeek::Broker::detail::opaque_of_vector_iterator)
		{}

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::VectorIterator)
};

class RecordIterator : public zeek::OpaqueVal {
public:

	RecordIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
	    : zeek::OpaqueVal(zeek::Broker::detail::opaque_of_record_iterator),
	      dat(require_data_type<broker::vector>(v, zeek::TYPE_RECORD, f)),
	      it(dat.begin())
		{}

	broker::vector dat;
	broker::vector::iterator it;

protected:
	RecordIterator()
		: zeek::OpaqueVal(zeek::Broker::detail::opaque_of_record_iterator)
		{}

	DECLARE_OPAQUE_VALUE(zeek::Broker::detail::RecordIterator)
};

} // namespace zeek::Broker

namespace bro_broker {
	extern zeek::OpaqueTypePtr& opaque_of_data_type;
	extern zeek::OpaqueTypePtr& opaque_of_set_iterator;
	extern zeek::OpaqueTypePtr& opaque_of_table_iterator;
	extern zeek::OpaqueTypePtr& opaque_of_vector_iterator;
	extern zeek::OpaqueTypePtr& opaque_of_record_iterator;

	constexpr auto to_bro_port_proto [[deprecated("Remove in v4.1. Use zeek::Broker::detail::to_zeek_port_proto.")]] = zeek::Broker::detail::to_zeek_port_proto;

	[[deprecated("Remove in v4.1. Use zeek::Broker::detail::make_data_val.")]]
	inline zeek::RecordValPtr make_data_val(zeek::Val* v)	 { return zeek::Broker::detail::make_data_val(v); }
	[[deprecated("Remove in v4.1. Use zeek::Broker::detail::make_data_val.")]]
	inline zeek::RecordValPtr make_data_val(broker::data d)	 { return zeek::Broker::detail::make_data_val(d); }

	constexpr auto get_data_type [[deprecated("Remove in v4.1. Use zeek::Broker::detail::get_data_type.")]] = zeek::Broker::detail::get_data_type;
	constexpr auto val_to_data [[deprecated("Remove in v4.1. Use zeek::Broker::detail::val_to_data.")]] = zeek::Broker::detail::val_to_data;
	constexpr auto data_to_val [[deprecated("Remove in v4.1. Use zeek::Broker::detail::data_to_val.")]] = zeek::Broker::detail::data_to_val;
	constexpr auto threading_val_to_data [[deprecated("Remove in v4.1. Use zeek::Broker::detail::threading_val_to_data.")]] = zeek::Broker::detail::threading_val_to_data;
	constexpr auto threading_field_to_data [[deprecated("Remove in v4.1. Use zeek::Broker::detail::threading_field_to_data.")]] = zeek::Broker::detail::threading_field_to_data;
	constexpr auto data_to_threading_val [[deprecated("Remove in v4.1. Use zeek::Broker::detail::data_to_threading_val.")]] = zeek::Broker::detail::data_to_threading_val;
	constexpr auto data_to_threading_field [[deprecated("Remove in v4.1. Use zeek::Broker::detail::data_to_threading_field.")]] = zeek::Broker::detail::data_to_threading_field;

	using DataVal [[deprecated("Remove in v4.1. Use zeek::Broker::detail::DataVal.")]] = zeek::Broker::detail::DataVal;
	using type_name_getter [[deprecated("Remove in v4.1. Use zeek::Broker::detail::type_name_getter.")]] = zeek::Broker::detail::type_name_getter;

	constexpr auto opaque_field_to_data [[deprecated("Remove in v4.1. Use zeek::Broker::detail::opaque_field_to_data.")]] = zeek::Broker::detail::opaque_field_to_data;

	template <typename T>
	[[deprecated("Remove in v4.1. Use zeek::Broker::detail::require_data_type.")]]
	T& require_data_type(broker::data& d, zeek::TypeTag tag, zeek::detail::Frame* f)
		{
		return zeek::Broker::detail::require_data_type<T>(d, tag, f);
		}

	template <typename T>
	[[deprecated("Remove in v4.1. Use zeek::Broker::detail::require_data_type.")]]
	inline T& require_data_type(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
		{
		return zeek::Broker::detail::require_data_type<T>(v, tag, f);
		}

	using SetIterator [[deprecated("Remove in v4.1. Use zeek::Broker::detail::SetIterator.")]] = zeek::Broker::detail::SetIterator;
	using TableIterator [[deprecated("Remove in v4.1. Use zeek::Broker::detail::TableIterator.")]] = zeek::Broker::detail::TableIterator;
	using VectorIterator [[deprecated("Remove in v4.1. Use zeek::Broker::detail::VectorIterator.")]] = zeek::Broker::detail::VectorIterator;
	using RecordIterator [[deprecated("Remove in v4.1. Use zeek::Broker::detail::RecordIterator.")]] = zeek::Broker::detail::RecordIterator;

} // namespace bro_broker
