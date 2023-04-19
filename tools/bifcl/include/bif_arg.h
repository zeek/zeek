#pragma once

#include <stdio.h>

enum builtin_func_arg_type
	{
#define DEFINE_BIF_TYPE(id, bif_type, bro_type, c_type, c_type_smart, accessor, accessor_smart,    \
                        cast_smart, constructor, ctor_smart)                                       \
	id,
#include "bif_type.def"
#undef DEFINE_BIF_TYPE
	};

extern const char* builtin_func_arg_type_bro_name[];

class BuiltinFuncArg final
	{
public:
	BuiltinFuncArg(const char* arg_name, int arg_type);
	BuiltinFuncArg(const char* arg_name, const char* arg_type_str, const char* arg_attr_str = "");

	void SetAttrStr(const char* arg_attr_str) { attr_str = arg_attr_str; };

	const char* Name() const { return name; }
	int Type() const { return type; }

	void PrintZeek(FILE* fp);
	void PrintCDef(FILE* fp, int n, bool runtime_type_check = false);
	void PrintCArg(FILE* fp, int n);
	void PrintValConstructor(FILE* fp);

private:
	const char* name;
	int type;
	const char* type_str;
	const char* attr_str;
	};
