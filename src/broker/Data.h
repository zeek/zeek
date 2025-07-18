// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cassert>
#include <memory>
#include <type_traits>

#include "zeek/Expr.h"
#include "zeek/Frame.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Reporter.h"

#include "broker/data.hh"

namespace zeek {

/// A 64-bit timestamp with nanosecond precision.
using BrokerTimespan = std::chrono::duration<int64_t, std::nano>;

class ODesc;

} // namespace zeek

namespace zeek::Broker {

class Manager;

} // namespace zeek::Broker

namespace zeek::threading {

struct Value;
struct Field;

} // namespace zeek::threading

namespace zeek::Broker::detail {

class StoreHandleVal;

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
std::optional<broker::data> val_to_data(const Val* v);

/**
 * Convert a Broker data value to a Zeek value.
 * @param d a Broker data value.
 * @param type the expected type of the value to return.
 * @return a pointer to a new Zeek value or a nullptr if the conversion was not
 * possible.
 */
ValPtr data_to_val(broker::data& d, Type* type);

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
threading::Field* data_to_threading_field(const broker::data& d);

/**
 * A Zeek value which wraps a Broker data value.
 */
class DataVal : public OpaqueVal {
public:
    DataVal(broker::data arg_data) : OpaqueVal(opaque_of_data_type), data(std::move(arg_data)) {}

    void ValDescribe(ODesc* d) const override;

    ValPtr castTo(zeek::Type* t);
    bool canCastTo(zeek::Type* t) const;

    // Returns the Zeek type that scripts use to represent a Broker data
    // instance. This may be wrapping the opaque value inside another
    // type.
    static const TypePtr& ScriptDataType();

    broker::data data;

protected:
    DataVal() : OpaqueVal(opaque_of_data_type) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::DataVal)
};

/**
 * Visitor for retrieving type names a Broker data value.
 */
struct type_name_getter {
    using result_type = const char*;

    result_type operator()(broker::none) { return "NONE"; } // FIXME: what's the right thing to return here?

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

    result_type operator()(const broker::vector&) {
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
 * exception is thrown if the optional opaque value of \a v is not set.
 */
broker::data& opaque_field_to_data(zeek::RecordVal* v, zeek::detail::Frame* f);

/**
 * Retrieve variant data from a Broker data value.
 * @tparam T a type that the variant may contain.
 * @param d a Broker data value to get variant data out of.
 * @param tag a Zeek tag which corresponds to T (just used for error reporting).
 * @param f used to get location information on error.
 * @return a reference to the requested type in the variant Broker data.
 * A runtime interpret exception is thrown if trying to access a type which
 * is not currently stored in the Broker data.
 */
template<typename T>
T& require_data_type(broker::data& d, zeek::TypeTag tag, zeek::detail::Frame* f) {
    auto ptr = broker::get_if<T>(&d);
    if ( ! ptr )
        zeek::reporter->RuntimeError(f->GetCallLocation(), "data is of type '%s' not of type '%s'",
                                     visit(type_name_getter{tag}, d), zeek::type_name(tag));

    return *ptr;
}

/**
 * @see require_data_type() and opaque_field_to_data().
 */
template<typename T>
inline T& require_data_type(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f) {
    return require_data_type<T>(opaque_field_to_data(v, f), tag, f);
}

// Copying data into iterator vals is not the fastest approach, but safer...

class SetIterator : public zeek::OpaqueVal {
public:
    SetIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_set_iterator),
          dat(require_data_type<broker::set>(v, zeek::TYPE_TABLE, f)),
          it(dat.begin()) {}

    broker::set dat;
    broker::set::iterator it;

protected:
    SetIterator() : zeek::OpaqueVal(opaque_of_set_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::SetIterator)
};

class TableIterator : public zeek::OpaqueVal {
public:
    TableIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_table_iterator),
          dat(require_data_type<broker::table>(v, zeek::TYPE_TABLE, f)),
          it(dat.begin()) {}

    broker::table dat;
    broker::table::iterator it;

protected:
    TableIterator() : zeek::OpaqueVal(opaque_of_table_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::TableIterator)
};

class VectorIterator : public zeek::OpaqueVal {
public:
    VectorIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_vector_iterator),
          dat(require_data_type<broker::vector>(v, zeek::TYPE_VECTOR, f)),
          it(dat.begin()) {}

    broker::vector dat;
    broker::vector::iterator it;

protected:
    VectorIterator() : zeek::OpaqueVal(opaque_of_vector_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::VectorIterator)
};

class RecordIterator : public zeek::OpaqueVal {
public:
    RecordIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_record_iterator),
          dat(require_data_type<broker::vector>(v, zeek::TYPE_RECORD, f)),
          it(dat.begin()) {}

    broker::vector dat;
    broker::vector::iterator it;

protected:
    RecordIterator() : zeek::OpaqueVal(opaque_of_record_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::RecordIterator)
};

} // namespace zeek::Broker::detail

namespace zeek {

class BrokerData;
class BrokerDataView;
class BrokerListView;

} // namespace zeek

namespace zeek::detail {

class BrokerDataAccess;

} // namespace zeek::detail

namespace zeek {

/**
 * Non-owning reference (view) to a Broker data value.
 */
class BrokerDataView {
public:
    friend class zeek::detail::BrokerDataAccess;
    friend class zeek::Broker::detail::DataVal;
    friend class zeek::Broker::detail::SetIterator;
    friend class zeek::Broker::detail::TableIterator;
    friend class zeek::Broker::detail::VectorIterator;
    friend class zeek::Broker::detail::RecordIterator;

    BrokerDataView() = delete;

    BrokerDataView(const BrokerDataView&) noexcept = default;

    explicit BrokerDataView(const broker::data* value) noexcept : value_(value) { assert(value != nullptr); }

    /**
     * Checks whether the value represents the `nil` value.
     */
    [[nodiscard]] bool IsNil() const noexcept { return broker::is<broker::none>(*value_); }

    /**
     * Checks whether the value is a Boolean.
     */
    [[nodiscard]] bool IsBool() const noexcept { return broker::is<bool>(*value_); }

    /**
     * Converts the value to a Boolean.
     */
    [[nodiscard]] bool ToBool(bool fallback = false) const noexcept {
        if ( auto val = broker::get_if<bool>(value_); val ) {
            return *val;
        }
        return fallback;
    }

    /**
     * Checks whether the value is a string.
     */
    [[nodiscard]] bool IsString() const noexcept { return broker::is<std::string>(*value_); }

    /**
     * Converts the value to a string.
     */
    [[nodiscard]] std::string_view ToString() const noexcept {
        if ( auto val = broker::get_if<std::string>(value_); val ) {
            return *val;
        }
        return std::string_view{};
    }

    /**
     * Checks whether the value is an integer.
     */
    [[nodiscard]] bool IsInteger() const noexcept { return broker::is<broker::integer>(*value_); }

    /**
     * Converts the value to an integer.
     */
    [[nodiscard]] int64_t ToInteger(int64_t fallback = 0) const noexcept {
        if ( auto val = broker::get_if<broker::integer>(value_); val ) {
            return *val;
        }
        return fallback;
    }

    /**
     * Checks whether the value is a count.
     */
    [[nodiscard]] bool IsCount() const noexcept { return broker::is<broker::count>(*value_); }

    /**
     * Converts the value to a count.
     */
    [[nodiscard]] uint64_t ToCount(uint64_t fallback = 0) const noexcept {
        if ( auto val = broker::get_if<broker::count>(value_); val ) {
            return *val;
        }
        return fallback;
    }

    /**
     * Checks whether the value is a real (double).
     */
    [[nodiscard]] bool IsReal() const noexcept { return broker::is<broker::real>(*value_); }

    /**
     * Converts the value to a real (double).
     */
    [[nodiscard]] double ToReal(double fallback = 0) const noexcept {
        if ( auto val = broker::get_if<broker::real>(value_); val ) {
            return *val;
        }
        return fallback;
    }

    /**
     * Checks whether the value is a list.
     */
    [[nodiscard]] bool IsList() const noexcept { return broker::is<broker::vector>(*value_); }

    /**
     * Converts the value to a list.
     * @pre IsList()
     */
    [[nodiscard]] BrokerListView ToList() noexcept;

    /**
     * Tries to convert this view to a Zeek value.
     * @returns a Zeek value or nullptr if the conversion failed.
     */
    [[nodiscard]] ValPtr ToVal(Type* type);

    /**
     * Renders the value as a string.
     */
    friend std::string to_string(const BrokerDataView& data) { return broker::to_string(*data.value_); }

private:
    const broker::data* value_;
};

/**
 * Convenience function to check whether a list of Broker data values are all of type `count`.
 */
template<typename... Args>
[[nodiscard]] bool are_all_counts(BrokerDataView arg, Args&&... args) {
    return arg.IsCount() && (args.IsCount() && ...);
}

/**
 * Convenience function to check whether a list of Broker data values are all of type `integer`.
 */
template<typename... Args>
[[nodiscard]] auto to_count(BrokerDataView arg, Args&&... args) {
    return std::tuple{arg.ToCount(), args.ToCount()...};
}

/**
 * Non-owning reference (view) to a Broker list value.
 */
class BrokerListView {
public:
    friend class zeek::detail::BrokerDataAccess;

    BrokerListView() = delete;

    BrokerListView(const BrokerListView&) noexcept = default;

    explicit BrokerListView(const broker::vector* values) noexcept : values_(values) { assert(values != nullptr); }

    /**
     * Returns a view to the first element.
     * @pre Size() > 0
     */
    [[nodiscard]] BrokerDataView Front() const { return BrokerDataView{std::addressof(values_->front())}; }

    /**
     * Returns a view to the last element.
     * @pre Size() > 0
     */
    [[nodiscard]] BrokerDataView Back() const { return BrokerDataView{std::addressof(values_->back())}; }

    /**
     * Returns a view to the element at the given index.
     * @pre index < Size()
     */
    [[nodiscard]] BrokerDataView operator[](size_t index) const {
        return BrokerDataView{std::addressof((*values_)[index])};
    }

    /**
     * Returns the number of elements in the list.
     */
    [[nodiscard]] size_t Size() const noexcept { return values_->size(); }

    /**
     * Checks whether the list is empty.
     */
    [[nodiscard]] size_t IsEmpty() const noexcept { return values_->empty(); }

private:
    const broker::vector* values_;
};

class BrokerListBuilder;

/**
 * Owning wrapper for a Broker data value.
 */
class BrokerData {
public:
    friend class BrokerListBuilder;
    friend class zeek::Broker::Manager;
    friend class zeek::Broker::detail::StoreHandleVal;
    friend class zeek::detail::BrokerDataAccess;

    BrokerData() = default;

    template<class DataType>
    explicit BrokerData(DataType value)
        requires std::is_same_v<DataType, broker::data>
        : value_(std::move(value)) {
        // Note: we use enable_if here to avoid nasty implicit conversions of broker::data.
    }

    BrokerDataView AsView() noexcept { return BrokerDataView{std::addressof(value_)}; }

    /**
     * Attempts to parse a Zeek value into a Broker value. On success, the Broker
     * value is stored in this object.
     * @returns `true` if the conversion succeeded, `false` otherwise.
     */
    [[nodiscard]] bool Convert(const Val* value);

    /**
     * @copydoc Convert(const Val*)
     */
    [[nodiscard]] bool Convert(const ValPtr& value) { return Convert(value.get()); }

    /**
     * Converts this value to a Zeek record.
     */
    [[nodiscard]] RecordValPtr ToRecordVal() &&;

    /**
     * Convenience function for converting a Zeek value to a Broker value and then
     * to a Zeek record.
     */
    [[nodiscard]] static RecordValPtr ToRecordVal(const Val* value);

    /**
     * @copydoc ToRecordVal(const Val*)
     */
    [[nodiscard]] static RecordValPtr ToRecordVal(const ValPtr& value) { return ToRecordVal(value.get()); }

    /**
     * Creates a Broker value from a string.
     */
    [[nodiscard]] static BrokerData FromString(const char* cstr, size_t len) {
        return BrokerData{broker::data{std::string{cstr, len}}};
    }

    /**
     * Renders the value as a string.
     */
    friend std::string to_string(const BrokerData& data) { return broker::to_string(data.value_); }

private:
    broker::data value_;
};

/**
 * Utility class for building a BrokerData containing a list of values.
 */
class BrokerListBuilder {
public:
    friend class zeek::Broker::Manager;

    /**
     * Reserves space for up to `n` elements.
     */
    void Reserve(size_t n) { values_.reserve(n); }

    /**
     * Tries to convert a Zeek value into a Broker value and adds it to the list on success.
     */
    [[nodiscard]] bool Add(const Val* value);

    /**
     * @copydoc Add(const Val*)
     */
    [[nodiscard]] bool Add(const ValPtr& value) { return Add(value.get()); }

    /**
     * Adds `value` as a Broker `count` to the list, automatically converting it if necessary.
     */
    template<typename T>
    void AddCount(T value) {
        if constexpr ( std::is_enum_v<T> ) {
            AddCount(static_cast<std::underlying_type_t<T>>(value));
        }
        else {
            static_assert(std::is_integral_v<T> && ! std::is_same_v<bool, T>);
            static_assert(std::is_unsigned_v<T>);
            static_assert(sizeof(T) <= sizeof(broker::count));
            values_.emplace_back(static_cast<broker::count>(value));
        }
    }

    /**
     * Adds `value` as a Broker `integer` to the list, automatically converting it if necessary.
     */
    template<typename T>
    void AddInteger(T value) {
        if constexpr ( std::is_enum_v<T> ) {
            AddInteger(static_cast<std::underlying_type_t<T>>(value));
        }
        else {
            static_assert(std::is_integral_v<T> && ! std::is_same_v<bool, T>);
            static_assert(std::is_signed_v<T>);
            static_assert(sizeof(T) <= sizeof(broker::integer));
            values_.emplace_back(static_cast<broker::integer>(value));
        }
    }

    /**
     * Appends `value` to the end of the list.
     */
    void Add(uint64_t value) { values_.emplace_back(static_cast<broker::count>(value)); }

    /**
     * Appends `value` to the end of the list.
     */
    void Add(int64_t value) { values_.emplace_back(static_cast<broker::integer>(value)); }

    /**
     * Appends `value` to the end of the list.
     */
    void Add(double value) { values_.emplace_back(value); }

    /**
     * Appends `value` to the end of the list.
     */
    void Add(bool value) { values_.emplace_back(value); }

    /**
     * Appends `value` to the end of the list.
     */
    void Add(std::string value) { values_.emplace_back(std::move(value)); }

    /**
     * Appends a string to the end of the list.
     * @param cstr The characters to append.
     * @param len The number of characters to append.
     */
    void Add(const char* cstr, size_t len) { values_.emplace_back(std::string{cstr, len}); }

    /**
     * Appends `value` to the end of the list.
     */
    void Add(BrokerData value) { values_.emplace_back(std::move(value.value_)); }

    /**
     * Appends all elements from `builder` to the end of the list as a single element.
     */
    void Add(BrokerListBuilder&& builder) { values_.emplace_back(std::move(builder.values_)); }

    /**
     * Appends the `nil` value to the end of the list.
     */
    void AddNil() { values_.emplace_back(); }

    /**
     * Adds a list of values to the list (as a single element).
     */
    template<class... Ts>
    void AddList(Ts&&... values) {
        BrokerListBuilder sub;
        (sub.Add(std::forward<Ts>(values)), ...);
        values_.emplace_back(std::move(sub.values_));
    }

    /**
     * Builds a `BrokerData` containing the list of values.
     */
    BrokerData Build() && { return BrokerData{broker::data{std::move(values_)}}; }

private:
    broker::vector values_;
};

} // namespace zeek

namespace zeek::detail {

class BrokerDataAccess {
public:
    static broker::data& Unbox(BrokerData& data) { return data.value_; }

    static const broker::data& Unbox(const BrokerData& data) { return data.value_; }

    static broker::data&& Unbox(BrokerData&& data) { return std::move(data.value_); }

    static const broker::data& Unbox(const BrokerDataView& data) { return *data.value_; }
};

} // namespace zeek::detail
