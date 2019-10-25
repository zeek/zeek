#ifndef bif_arg_h
#define bif_arg_h

#include <stdio.h>

enum builtin_func_arg_type {
#define DEFINE_BIF_TYPE(id, bif_type, bro_type, c_type, accessor, constructor) \
	id,
#include "bif_type.def"
#undef DEFINE_BIF_TYPE
/*
	TYPE_ANY,
	TYPE_BOOL,
	TYPE_COUNT,
	TYPE_INT,
	TYPE_STRING,
	TYPE_PATTERN,
	TYPE_PORT,
	TYPE_OTHER,
*/
};

extern const char* builtin_func_arg_type_bro_name[];

class BuiltinFuncArg {
public:
	BuiltinFuncArg(const char* arg_name, int arg_type);
	BuiltinFuncArg(const char* arg_name, const char* arg_type_str,
	               const char* arg_attr_str = "");

	void SetAttrStr(const char* arg_attr_str)
		{
		attr_str = arg_attr_str;
		};

	const char* Name() const	{ return name; }
	int Type() const		{ return type; }

	void PrintBro(FILE* fp);
	void PrintCDef(FILE* fp, int n);
	void PrintCArg(FILE* fp, int n);
	void PrintBroValConstructor(FILE* fp);

protected:
	const char* name;
	int type;
	const char* type_str;
	const char* attr_str;
};

#endif
