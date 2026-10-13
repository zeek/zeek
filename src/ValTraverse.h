// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Func.h"
#include "zeek/RE.h"
#include "zeek/Type.h"


namespace zeek {

namespace detail {

/**
 * Related to TraversalCallback, but traverses a a Val instance instead.
 *
 * The Time() and Interval() callbacks take doubles. We should eventually
 * switch to uint64_t with nanoseconds or some such, but we're not there
 * today.
 */
class ValTraversalCallback {
public:
    virtual ~ValTraversalCallback() = default;

    virtual bool Bool(bool b) = 0;
    virtual bool Int(zeek_int_t i) = 0;
    virtual bool Count(zeek_uint_t u) = 0;
    virtual bool Double(double d) = 0;
    virtual bool Time(double t) = 0;
    virtual bool Interval(double i) = 0;
    virtual bool String(std::string_view sv) = 0;

    // Can get to the text via PatternText() and AnywherePatternText()
    // and there's also IsSingleLine() and IsCaseInsensitive()
    virtual bool Pattern(const RE_Matcher& m) = 0;
    virtual bool Enum(zeek_int_t, std::string_view sv, EnumTypePtr& et) = 0;

    virtual bool Port(uint16_t port, TransportProto proto) = 0;

    // ????
    virtual bool Opaque() = 0;

    virtual bool Func(Func& f) = 0;

    // Container values.

    virtual bool StartRecord(const TypePtr& rt) = 0;
    virtual bool RecordField(const zeek::TypeDecl& td) = 0;
    virtual bool EndRecord() = 0;

    virtual bool StartTable(const TableTypePtr& tt, size_t size) = 0;
    // Two calls for every key-value entry in -between.
    virtual bool EndTable() = 0;

    virtual bool StartSet(const SetType& tt, size_t size) = 0;
    // One call every key in-between.
    virtual bool EndSet() = 0;

    virtual bool StartArray(const VectorTypePtr& vt, size_t size) = 0;
    virtual bool EndArray() = 0;
};

class ValTraverser {
    void Traverse(const Val& v);
};

} // namespace detail
} // namespace zeek
