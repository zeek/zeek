// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/Traverse.h"
#include "zeek/ZeekList.h"

// Note that there are two kinds of attributes: the kind (here) which
// modify expressions or supply metadata on types, and the kind that
// are extra metadata on every variable instance.

namespace zeek {

class Type;
using TypePtr = IntrusivePtr<Type>;

namespace detail {

class Expr;
using ExprPtr = IntrusivePtr<Expr>;

enum AttrTag : uint8_t {
    ATTR_OPTIONAL,
    ATTR_DEFAULT,
    ATTR_DEFAULT_INSERT, // insert default value on failed lookups
    ATTR_REDEF,
    ATTR_ADD_FUNC,
    ATTR_DEL_FUNC,
    ATTR_EXPIRE_FUNC,
    ATTR_EXPIRE_READ,
    ATTR_EXPIRE_WRITE,
    ATTR_EXPIRE_CREATE,
    ATTR_RAW_OUTPUT,
    ATTR_PRIORITY,
    ATTR_GROUP,
    ATTR_LOG,
    ATTR_ERROR_HANDLER,
    ATTR_TYPE_COLUMN,                // for input framework
    ATTR_TRACKED,                    // hidden attribute, tracked by NotifierRegistry
    ATTR_ON_CHANGE,                  // for table change tracking
    ATTR_BROKER_STORE,               // for Broker store backed tables
    ATTR_BROKER_STORE_ALLOW_COMPLEX, // for Broker store backed tables
    ATTR_BACKEND,                    // for Broker store backed tables
    ATTR_DEPRECATED,
    ATTR_IS_ASSIGNED, // to suppress usage warnings
    ATTR_IS_USED,     // to suppress usage warnings
    ATTR_ORDERED,     // used to store tables in ordered mode
    ATTR_NO_ZAM_OPT,  // avoid ZAM optimization
    ATTR_NO_CPP_OPT,  // avoid -O gen-C++ optimization
    NUM_ATTRS         // this item should always be last
};

class Attr;
using AttrPtr = IntrusivePtr<Attr>;
class Attributes;
using AttributesPtr = IntrusivePtr<Attributes>;

class Attr final : public Obj {
public:
    static inline const AttrPtr nil;

    Attr(AttrTag t, ExprPtr e);
    explicit Attr(AttrTag t);

    AttrTag Tag() const { return tag; }

    const ExprPtr& GetExpr() const { return expr; }

    void SetAttrExpr(ExprPtr e);

    void Describe(ODesc* d) const override;
    void DescribeReST(ODesc* d, bool shorten = false) const;

    /**
     * Returns the deprecation string associated with a &deprecated attribute
     * or an empty string if this is not such an attribute.
     */
    std::string DeprecationMessage() const;

    bool operator==(const Attr& other) const {
        if ( tag != other.tag )
            return false;

        if ( expr || other.expr )
            // Too hard to check for equivalency, since one
            // might be expressed/compiled differently than
            // the other, so assume they're compatible, as
            // long as both are present.
            return expr && other.expr;

        return true;
    }

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

protected:
    void AddTag(ODesc* d) const;

    AttrTag tag;
    ExprPtr expr;
};

// Manages a collection of attributes.
class Attributes final : public Obj {
public:
    Attributes(std::vector<AttrPtr> a, TypePtr t, bool in_record, bool is_global, bool is_param);

    Attributes(TypePtr t, bool in_record, bool is_global)
        : Attributes(std::vector<AttrPtr>{}, std::move(t), in_record, is_global, false) {}

    Attributes(std::vector<AttrPtr> a, TypePtr t, bool in_record, bool is_global)
        : Attributes(std::move(a), std::move(t), in_record, is_global, false) {}


    void AddAttr(AttrPtr a, bool is_redef = false);

    void AddAttrs(const AttributesPtr& a, bool is_redef = false);

    const AttrPtr& Find(AttrTag t) const;

    void RemoveAttr(AttrTag t);

    void Describe(ODesc* d) const override;
    void DescribeReST(ODesc* d, bool shorten = false) const;

    const std::vector<AttrPtr>& GetAttrs() const { return attrs; }

    bool operator==(const Attributes& other) const;

    detail::TraversalCode Traverse(detail::TraversalCallback* cb) const;

protected:
    // Returns true if the attribute is okay, false if not.
    bool CheckAttr(Attr* attr, const TypePtr& attrs_t);

    // Reports an attribute error and returns false (handy for CheckAttr()).
    bool AttrError(const char* msg);

    TypePtr type;
    std::vector<AttrPtr> attrs;

    bool in_record;
    bool global_var;
    bool is_param;
};

// Checks whether default attribute "a" is compatible with the given type.
// "global_var" specifies whether the attribute is being associated with
// a global variable, and "in_record" whether it's occurring inside of
// a record declaration.
//
// Returns true on compatibility (which might include modifying "a"), false
// on an error.  If an error message hasn't been directly generated, then
// it will be returned in err_msg.
extern bool check_default_attr(Attr* a, const TypePtr& type, bool global_var, bool in_record, std::string& err_msg);

// Returns the script-level name associated with an attribute, e.g. "&default".
extern const char* attr_name(AttrTag t);

} // namespace detail
} // namespace zeek
