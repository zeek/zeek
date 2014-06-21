// See the file "COPYING" in the main distribution directory for copyright.

#ifndef id_h
#define id_h

#include "Type.h"
#include "Attr.h"
#include "StateAccess.h"
#include "TraverseTypes.h"
#include <string>

class Val;
class SerialInfo;

typedef enum { INIT_NONE, INIT_FULL, INIT_EXTRA, INIT_REMOVE, } init_class;
typedef enum { SCOPE_FUNCTION, SCOPE_MODULE, SCOPE_GLOBAL } IDScope;

class ID : public BroObj {
public:
	ID(const char* name, IDScope arg_scope, bool arg_is_export);
	~ID();

	const char* Name() const	{ return name; }

	int Scope() const		{ return scope; }
	bool IsGlobal() const           { return scope != SCOPE_FUNCTION; }

	bool IsExport() const           { return is_export; }
	void SetExport()                { is_export = true; }

	string ModuleName() const;

	void SetType(BroType* t)	{ Unref(type); type = t; }
	BroType* Type()			{ return type; }

	void MakeType()			{ is_type = 1; }
	BroType* AsType()		{ return is_type ? Type() : 0; }

	// If weak_ref is false, the Val is assumed to be already ref'ed
	// and will be deref'ed when the ID is deleted.
	//
	// If weak_ref is true, we store the Val but don't ref/deref it.
	// That means that when the ID becomes the only one holding a
	// reference to the Val, the Val will be destroyed (naturally,
	// you have to take care that it will not be accessed via
	// the ID afterwards).
	void SetVal(Val* v, Opcode op = OP_ASSIGN, bool weak_ref = false);

	void SetVal(Val* v, init_class c);
	void SetVal(Expr* ev, init_class c);

	int HasVal() const		{ return val != 0; }
	Val* ID_Val()			{ return val; }
	const Val* ID_Val() const	{ return val; }
	void ClearVal();

	void SetConst()			{ is_const = 1; }
	int IsConst() const		{ return is_const; }

	void SetEnumConst()		{ is_enum_const = 1; }
	int IsEnumConst() const		{ return is_enum_const; }

	void SetOffset(int arg_offset)	{ offset = arg_offset; }
	int Offset() const		{ return offset; }

	int IsRedefinable() const	{ return FindAttr(ATTR_REDEF) != 0; }

	// Returns true if ID is one of those internal globally unique IDs
	// to which MutableVals are bound (there name start with a '#').
	bool IsInternalGlobal() const	{ return name && name[0] == '#'; }

	void SetAttrs(Attributes* attr);
	void AddAttrs(Attributes* attr);
	void RemoveAttr(attr_tag a);
	void UpdateValAttrs();
	Attributes* Attrs() const	{ return attrs; }

	Attr* FindAttr(attr_tag t) const
		{ return attrs ? attrs->FindAttr(t) : 0; }

	void Error(const char* msg, const BroObj* o2 = 0);

	void Describe(ODesc* d) const;
	// Adds type and value to description.
	void DescribeExtended(ODesc* d) const;
	// Produces a description that's reST-ready.
	void DescribeReST(ODesc* d, bool roles_only = false) const;
	void DescribeReSTShort(ODesc* d) const;

	bool Serialize(SerialInfo* info) const;
	static ID* Unserialize(UnserialInfo* info);

	bool DoInferReturnType()        { return infer_return_type; }
	void SetInferReturnType(bool infer)
	        { infer_return_type = infer; }

	virtual TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	ID()	{ name = 0; type = 0; val = 0; attrs = 0; }

	void CheckAttr(Attr* attr);
	void EvalFunc(Expr* ef, Expr* ev);

#ifdef DEBUG
	void UpdateValID();
#endif

	DECLARE_SERIAL(ID);

	const char* name;
	IDScope scope;
	bool is_export;
	BroType* type;
	int is_const, is_enum_const, is_type;
	int offset;
	Val* val;
	Attributes* attrs;

	bool infer_return_type;
	bool weak_ref;
};

#endif
