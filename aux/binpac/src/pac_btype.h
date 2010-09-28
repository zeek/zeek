#ifndef pac_btype_h
#define pac_btype_h

#include "pac_type.h"

class BuiltInType : public Type
{
public:
	enum BITType {
#		define TYPE_DEF(name, pactype, ctype, size)	name,
#		include "pac_type.def"
#		undef TYPE_DEF
	};

	static int LookUpByName(const char *name);

	BuiltInType(BITType bit_type)
		: Type(bit_type == BuiltInType::EMPTY ? Type::EMPTY : BUILTIN),
		  bit_type_(bit_type) {}

	BITType bit_type() const	{ return bit_type_; }

	bool IsNumericType() const;

	bool DefineValueVar() const;
	string DataTypeStr() const;
	string DefaultValue() const	{ return "0"; }

	int StaticSize(Env *env) const;

	bool IsPointerType() const	{ return false; }

	bool ByteOrderSensitive() const { return StaticSize(0) >= 2; }

	void GenInitCode(Output *out_cc, Env *env);

	void DoMarkIncrementalInput();

protected:
	void DoGenParseCode(Output *out, Env *env, const DataPtr& data, int flags);
	void GenDynamicSize(Output *out, Env *env, const DataPtr& data);
	Type *DoClone() const;

	BITType bit_type_;

public:
	static void static_init();
	static bool CompatibleBuiltInTypes(BuiltInType *type1, 
	                                   BuiltInType *type2);
};

#endif  // pac_btype_h
