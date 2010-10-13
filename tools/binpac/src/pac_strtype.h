#ifndef pac_strtype_h
#define pac_strtype_h

#include "pac_type.h"

// TODO: question: shall we merge it with ArrayType?
class StringType : public Type
{
public:
	enum StringTypeEnum { CSTR, REGEX, ANYSTR };

	explicit StringType(StringTypeEnum anystr);
	explicit StringType(ConstString *str);
	explicit StringType(RegEx *regex);
	~StringType();

	bool DefineValueVar() const;
	string DataTypeStr() const;
	string DefaultValue() const	{ return "0"; }
	Type *ElementDataType() const;

	void Prepare(Env* env, int flags);

	void GenPubDecls(Output* out, Env* env);
	void GenPrivDecls(Output* out, Env* env);

	void GenInitCode(Output* out, Env* env);
	void GenCleanUpCode(Output* out, Env* env);

	void DoMarkIncrementalInput();

	int StaticSize(Env* env) const;

	bool IsPointerType() const	{ return false; }

	void ProcessAttr(Attr *a);

protected:
	void init();

	// Generate computation of size of the string and returns the string 
	// representing a constant integer or name of the length variable.
	string GenStringSize(Output* out_cc, Env* env, const DataPtr& data);

	// Generate a string mismatch exception
	void GenStringMismatch(Output* out_cc, Env* env, 
		const DataPtr& data, const char *pattern);

	void DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags);

	void GenCheckingCStr(Output* out, Env* env, 
		const DataPtr& data, const string &str_size);

	void GenDynamicSize(Output* out, Env* env, const DataPtr& data);
	void GenDynamicSizeAnyStr(Output* out_cc, Env* env, const DataPtr& data);
	void GenDynamicSizeRegEx(Output* out_cc, Env* env, const DataPtr& data);

	Type *DoClone() const;

	// TODO: insensitive towards byte order till we support unicode
	bool ByteOrderSensitive() const 	{ return false; }

protected:
	bool DoTraverse(DataDepVisitor *visitor);

private:
	const ID *string_length_var() const;

	StringTypeEnum type_;
	ConstString *str_;
	RegEx *regex_;
	Field *string_length_var_field_;
	Type *elem_datatype_;

public:
	static void static_init();
private:
	static const char *kStringTypeName;
	static const char *kConstStringTypeName;
};

#endif  // pac_strtype_h
