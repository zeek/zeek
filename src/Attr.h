// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>
#include <string>

#include "zeek/Obj.h"
#include "zeek/ZeekList.h"
#include "zeek/IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Expr, zeek::detail);

// Note that there are two kinds of attributes: the kind (here) which
// modify expressions or supply metadata on types, and the kind that
// are extra metadata on every variable instance.

namespace zeek {

class Type;
using TypePtr = IntrusivePtr<Type>;

namespace detail {

using ExprPtr = IntrusivePtr<Expr>;

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
	ATTR_BROKER_STORE, // for Broker store backed tables
	ATTR_BROKER_STORE_ALLOW_COMPLEX, // for Broker store backed tables
	ATTR_BACKEND, // for Broker store backed tables
	ATTR_DEPRECATED,
	NUM_ATTRS // this item should always be last
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

	~Attr() override = default;

	AttrTag Tag() const	{ return tag; }

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
	Attributes(std::vector<AttrPtr> a, TypePtr t,
	           bool in_record, bool is_global);
	Attributes(TypePtr t, bool in_record, bool is_global);

	~Attributes() override = default;

	void AddAttr(AttrPtr a, bool is_redef = false);

	void AddAttrs(const AttributesPtr& a, bool is_redef = false);

	const AttrPtr& Find(AttrTag t) const;

	void RemoveAttr(AttrTag t);

	void Describe(ODesc* d) const override;
	void DescribeReST(ODesc* d, bool shorten = false) const;

	const std::vector<AttrPtr>& GetAttrs() const
		{ return attrs; }

	bool operator==(const Attributes& other) const;

protected:
	void CheckAttr(Attr* attr);

	TypePtr type;
	std::vector<AttrPtr> attrs;

	bool in_record;
	bool global_var;
};

} // namespace detail
} // namespace zeek
