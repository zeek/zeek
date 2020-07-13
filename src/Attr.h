// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>
#include <string>

#include "Obj.h"
#include "BroList.h"
#include "IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

// Note that there are two kinds of attributes: the kind (here) which
// modify expressions or supply metadata on types, and the kind that
// are extra metadata on every variable instance.


namespace zeek {

class Type;
using TypePtr = IntrusivePtr<Type>;

namespace detail {

using ExprPtr = zeek::IntrusivePtr<zeek::detail::Expr>;

enum AttrTag {
	ATTR_OPTIONAL,
	ATTR_DEFAULT,
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
	ATTR_TYPE_COLUMN,	// for input framework
	ATTR_TRACKED,	// hidden attribute, tracked by NotifierRegistry
	ATTR_ON_CHANGE, // for table change tracking
	ATTR_DEPRECATED,
	NUM_ATTRS // this item should always be last
};

class Attr;
using AttrPtr = zeek::IntrusivePtr<Attr>;
class Attributes;
using AttributesPtr = zeek::IntrusivePtr<Attributes>;

class Attr final : public Obj {
public:
	static inline const AttrPtr nil;

	Attr(AttrTag t, ExprPtr e);
	explicit Attr(AttrTag t);

	~Attr() override = default;

	AttrTag Tag() const	{ return tag; }

	[[deprecated("Remove in v4.1.  Use GetExpr().")]]
	zeek::detail::Expr* AttrExpr() const	{ return expr.get(); }

	const ExprPtr& GetExpr() const
		{ return expr; }

	void SetAttrExpr(ExprPtr e);

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool shorten = false) const;

	/**
	 * Returns the deprecation string associated with a &deprecated attribute
	 * or an empty string if this is not such an attribute.
	 */
	std::string DeprecationMessage() const;

	bool operator==(const Attr& other) const
		{
		if ( tag != other.tag )
			return false;

		if ( expr || other.expr )
			// If any has an expression and they aren't the same object, we
			// declare them unequal, as we can't really find out if the two
			// expressions are equivalent.
			return (expr == other.expr);

		return true;
		}

protected:
	void AddTag(ODesc* d) const;

	AttrTag tag;
	ExprPtr expr;
};

// Manages a collection of attributes.
class Attributes final : public Obj {
public:
	[[deprecated("Remove in v4.1.  Construct using IntrusivePtrs instead.")]]
	Attributes(attr_list* a, zeek::TypePtr t, bool in_record, bool is_global);

	Attributes(std::vector<AttrPtr> a, zeek::TypePtr t,
	           bool in_record, bool is_global);
	Attributes(TypePtr t, bool in_record, bool is_global);

	~Attributes() override = default;

	void AddAttr(AttrPtr a);

	void AddAttrs(const AttributesPtr& a);

	[[deprecated("Remove in v4.1. Pass IntrusivePtr instead.")]]
	void AddAttrs(Attributes* a);	// Unref's 'a' when done

	[[deprecated("Remove in v4.1. Use Find().")]]
	Attr* FindAttr(AttrTag t) const;

	const AttrPtr& Find(AttrTag t) const;

	void RemoveAttr(AttrTag t);

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool shorten = false) const;

	[[deprecated("Remove in v4.1. Use GetAttrs().")]]
	const attr_list* Attrs() const
		{ return &attrs_list; }

	const std::vector<AttrPtr>& GetAttrs() const
		{ return attrs; }

	bool operator==(const Attributes& other) const;

protected:
	void CheckAttr(Attr* attr);

	TypePtr type;
	std::vector<AttrPtr> attrs;

	// Remove in v4.1. This is used by Attrs(), which is deprecated.
	attr_list attrs_list;
	bool in_record;
	bool global_var;
};

} // namespace detail
} // namespace zeek

using Attr [[deprecated("Remove in v4.1. Use zeek::detail::Attr instead.")]] = zeek::detail::Attr;
using Attributes [[deprecated("Remove in v4.1. Use zeek::detail::Attr instead.")]] = zeek::detail::Attributes;

using AttrTag [[deprecated("Remove in v4.1. Use zeek::detail::AttrTag instead.")]] = zeek::detail::AttrTag;

[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_OPTIONAL instead.")]]
constexpr auto ATTR_OPTIONAL = zeek::detail::ATTR_OPTIONAL;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_DEFAULT instead.")]]
constexpr auto ATTR_DEFAULT = zeek::detail::ATTR_DEFAULT;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_REDEF instead.")]]
constexpr auto ATTR_REDEF = zeek::detail::ATTR_REDEF;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_ADD_FUNC instead.")]]
constexpr auto ATTR_ADD_FUNC = zeek::detail::ATTR_ADD_FUNC;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_DEL_FUNC instead.")]]
constexpr auto ATTR_DEL_FUNC = zeek::detail::ATTR_DEL_FUNC;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_EXPIRE_FUNC instead.")]]
constexpr auto ATTR_EXPIRE_FUNC = zeek::detail::ATTR_EXPIRE_FUNC;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_EXPIRE_READ instead.")]]
constexpr auto ATTR_EXPIRE_READ = zeek::detail::ATTR_EXPIRE_READ;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_EXPIRE_WRITE instead.")]]
constexpr auto ATTR_EXPIRE_WRITE = zeek::detail::ATTR_EXPIRE_WRITE;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_EXPIRE_CREATE instead.")]]
constexpr auto ATTR_EXPIRE_CREATE = zeek::detail::ATTR_EXPIRE_CREATE;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_RAW_OUTPUT instead.")]]
constexpr auto ATTR_RAW_OUTPUT = zeek::detail::ATTR_RAW_OUTPUT;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_PRIORITY instead.")]]
constexpr auto ATTR_PRIORITY = zeek::detail::ATTR_PRIORITY;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_GROUP instead.")]]
constexpr auto ATTR_GROUP = zeek::detail::ATTR_GROUP;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_LOG instead.")]]
constexpr auto ATTR_LOG = zeek::detail::ATTR_LOG;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_ERROR_HANDLER instead.")]]
constexpr auto ATTR_ERROR_HANDLER = zeek::detail::ATTR_ERROR_HANDLER;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_TYPE_COLUMN instead.")]]
constexpr auto ATTR_TYPE_COLUMN = zeek::detail::ATTR_TYPE_COLUMN;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_TRACKED instead.")]]
constexpr auto ATTR_TRACKED = zeek::detail::ATTR_TRACKED;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_ON_CHANGE instead.")]]
constexpr auto ATTR_ON_CHANGE = zeek::detail::ATTR_ON_CHANGE;
[[deprecated("Remove in v4.1. Use zeek::detail::ATTR_DEPRECATED instead.")]]
constexpr auto ATTR_DEPRECATED = zeek::detail::ATTR_DEPRECATED;
[[deprecated("Remove in v4.1. Use zeek::detail::NUM_ATTRS instead.")]]
constexpr auto NUM_ATTRS = zeek::detail::NUM_ATTRS;
