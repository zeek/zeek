#ifndef pac_btype_h
#define pac_btype_h

#include "pac_type.h"

class BuiltInType : public Type
	{
public:
	enum BITType
		{
#define TYPE_DEF(name, pactype, ctype, size) name,
#include "pac_type.def"
#undef TYPE_DEF
		};

	static int LookUpByName(const char* name);

	BuiltInType(BITType bit_type)
		: Type(bit_type == BuiltInType::EMPTY ? Type::EMPTY : BUILTIN), bit_type_(bit_type)
		{
		}

	BITType bit_type() const { return bit_type_; }

	bool IsNumericType() const override;

	bool DefineValueVar() const override;
	string DataTypeStr() const override;
	string DefaultValue() const override { return "0"; }

	int StaticSize(Env* env) const override;

	bool IsPointerType() const override { return false; }

	bool ByteOrderSensitive() const override { return StaticSize(0) >= 2; }

	void GenInitCode(Output* out_cc, Env* env) override;

	void DoMarkIncrementalInput() override;

protected:
	void DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags) override;
	void GenDynamicSize(Output* out, Env* env, const DataPtr& data) override;
	Type* DoClone() const override;

	BITType bit_type_;

public:
	static void static_init();
	static bool CompatibleBuiltInTypes(BuiltInType* type1, BuiltInType* type2);
	};

#endif // pac_btype_h
