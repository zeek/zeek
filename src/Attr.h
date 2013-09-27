// See the file "COPYING" in the main distribution directory for copyright.

#ifndef attr_h
#define attr_h

#include "Obj.h"

class Expr;

// Note that there are two kinds of attributes: the kind (here) which
// modify expressions or supply metadata on types, and the kind that
// are extra metadata on every variable instance.

typedef enum {
	ATTR_OPTIONAL,
	ATTR_DEFAULT,
	ATTR_REDEF,
	ATTR_ROTATE_INTERVAL,
	ATTR_ROTATE_SIZE,
	ATTR_ADD_FUNC,
	ATTR_DEL_FUNC,
	ATTR_EXPIRE_FUNC,
	ATTR_EXPIRE_READ,
	ATTR_EXPIRE_WRITE,
	ATTR_EXPIRE_CREATE,
	ATTR_PERSISTENT,
	ATTR_SYNCHRONIZED,
	ATTR_ENCRYPT,
	ATTR_RAW_OUTPUT,
	ATTR_MERGEABLE,
	ATTR_PRIORITY,
	ATTR_GROUP,
	ATTR_LOG,
	ATTR_ERROR_HANDLER,
	ATTR_TYPE_COLUMN,	// for input framework
	ATTR_TRACKED,	// hidden attribute, tracked by NotifierRegistry
#define NUM_ATTRS (int(ATTR_TRACKED) + 1)
} attr_tag;

class Attr : public BroObj {
public:
	Attr(attr_tag t, Expr* e = 0);
	~Attr();

	attr_tag Tag() const	{ return tag; }
	Expr* AttrExpr() const	{ return expr; }

	int RedundantAttrOkay() const
		{ return tag == ATTR_REDEF || tag == ATTR_OPTIONAL; }

	void Describe(ODesc* d) const;
	void DescribeReST(ODesc* d) const;

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

	attr_tag tag;
	Expr* expr;
};

// Manages a collection of attributes.
class Attributes : public BroObj {
public:
	Attributes(attr_list* a, BroType* t, bool in_record);
	~Attributes();

	void AddAttr(Attr* a);
	void AddAttrs(Attributes* a);	// Unref's 'a' when done

	Attr* FindAttr(attr_tag t) const;

	void RemoveAttr(attr_tag t);

	void Describe(ODesc* d) const;
	void DescribeReST(ODesc* d) const;

	attr_list* Attrs()	{ return attrs; }

	bool Serialize(SerialInfo* info) const;
	static Attributes* Unserialize(UnserialInfo* info);

	bool operator==(const Attributes& other) const;

protected:
	Attributes() : type(), attrs(), in_record()	{ }
	void CheckAttr(Attr* attr);

	DECLARE_SERIAL(Attributes);

	BroType* type;
	attr_list* attrs;
	bool in_record;
};

#endif
