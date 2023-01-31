#ifndef pac_strtype_h
#define pac_strtype_h

#include "pac_type.h"

// TODO: question: shall we merge it with ArrayType?
class StringType : public Type
	{
public:
	enum StringTypeEnum
		{
		CSTR,
		REGEX,
		ANYSTR
		};

	explicit StringType(StringTypeEnum anystr);
	explicit StringType(ConstString* str);
	explicit StringType(RegEx* regex);
	~StringType() override;

	bool DefineValueVar() const override;
	string DataTypeStr() const override;
	string DefaultValue() const override { return "0"; }
	Type* ElementDataType() const override;

	void Prepare(Env* env, int flags) override;

	void GenPubDecls(Output* out, Env* env) override;
	void GenPrivDecls(Output* out, Env* env) override;

	void GenInitCode(Output* out, Env* env) override;
	void GenCleanUpCode(Output* out, Env* env) override;

	void DoMarkIncrementalInput() override;

	int StaticSize(Env* env) const override;

	bool IsPointerType() const override { return false; }

	void ProcessAttr(Attr* a) override;

protected:
	void init();

	// Generate computation of size of the string and returns the string
	// representing a constant integer or name of the length variable.
	string GenStringSize(Output* out_cc, Env* env, const DataPtr& data);

	// Generate a string mismatch exception
	void GenStringMismatch(Output* out_cc, Env* env, const DataPtr& data, string pattern);

	void DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags) override;

	void GenCheckingCStr(Output* out, Env* env, const DataPtr& data, const string& str_size);

	void GenDynamicSize(Output* out, Env* env, const DataPtr& data) override;
	void GenDynamicSizeAnyStr(Output* out_cc, Env* env, const DataPtr& data);
	void GenDynamicSizeRegEx(Output* out_cc, Env* env, const DataPtr& data);

	Type* DoClone() const override;

	// TODO: insensitive towards byte order till we support unicode
	bool ByteOrderSensitive() const override { return false; }

protected:
	bool DoTraverse(DataDepVisitor* visitor) override;

private:
	const ID* string_length_var() const;

	StringTypeEnum type_;
	ConstString* str_;
	RegEx* regex_;
	Field* string_length_var_field_;
	Type* elem_datatype_;

public:
	static void static_init();

private:
	static const char* kStringTypeName;
	static const char* kConstStringTypeName;
	};

#endif // pac_strtype_h
