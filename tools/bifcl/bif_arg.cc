
#include <set>
#include <string>
using namespace std;

#include <string.h>

#include "bif_arg.h"

static struct
	{
	const char* type_enum;
	const char* bif_type;
	const char* zeek_type;
	const char* c_type;
	const char* c_type_smart;
	const char* accessor;
	const char* accessor_smart;
	const char* cast_smart;
	const char* constructor;
	const char* ctor_smart;
	} builtin_func_arg_type[] = {
#define DEFINE_BIF_TYPE(id, bif_type, zeek_type, c_type, c_type_smart, accessor, accessor_smart,   \
                        cast_smart, constructor, ctor_smart)                                       \
	{#id,      bif_type,       zeek_type,  c_type,      c_type_smart,                              \
	 accessor, accessor_smart, cast_smart, constructor, ctor_smart},
#include "bif_type.def"
#undef DEFINE_BIF_TYPE
	};

extern const char* arg_list_name;

BuiltinFuncArg::BuiltinFuncArg(const char* arg_name, int arg_type)
	{
	name = arg_name;
	type = arg_type;
	type_str = "";
	attr_str = "";
	}

BuiltinFuncArg::BuiltinFuncArg(const char* arg_name, const char* arg_type_str,
                               const char* arg_attr_str)
	{
	name = arg_name;
	type = TYPE_OTHER;
	type_str = arg_type_str;
	attr_str = arg_attr_str;

	for ( int i = 0; builtin_func_arg_type[i].bif_type[0] != '\0'; ++i )
		if ( ! strcmp(builtin_func_arg_type[i].bif_type, arg_type_str) )
			{
			type = i;
			type_str = "";
			}
	}

void BuiltinFuncArg::PrintZeek(FILE* fp)
	{
	fprintf(fp, "%s: %s%s %s", name, builtin_func_arg_type[type].zeek_type, type_str, attr_str);
	}

void BuiltinFuncArg::PrintCDef(FILE* fp, int n, bool runtime_type_check)
	{
	// Generate a runtime type-check pre-amble for types we understand
	if ( runtime_type_check && type != TYPE_OTHER && type != TYPE_ANY )
		{
		fprintf(fp, "\t\t{\n");
		fprintf(fp, "\t\t// Runtime type check for %s argument\n", name);
		fprintf(fp, "\t\tzeek::TypeTag __tag = (*%s)[%d]->GetType()->Tag();\n", arg_list_name, n);
		fprintf(fp, "\t\tif ( __tag != %s )\n", builtin_func_arg_type[type].type_enum);
		fprintf(fp, "\t\t\t{\n");
		fprintf(fp,
		        "\t\t\tzeek::emit_builtin_error(zeek::util::fmt(\"expected type %s for %s, got "
		        "%%s\", zeek::type_name(__tag)));\n",
		        builtin_func_arg_type[type].zeek_type, name);
		fprintf(fp, "\t\t\treturn nullptr;\n");
		fprintf(fp, "\t\t\t}\n");
		fprintf(fp, "\t\t}\n");
		}
	fprintf(fp, "\t%s %s = (%s) (", builtin_func_arg_type[type].c_type, name,
	        builtin_func_arg_type[type].c_type);

	char buf[1024];
	snprintf(buf, sizeof(buf), "(*%s)[%d].get()", arg_list_name, n);
	// Print the accessor expression.
	fprintf(fp, builtin_func_arg_type[type].accessor, buf);

	fprintf(fp, ");\n");
	}

void BuiltinFuncArg::PrintCArg(FILE* fp, int n)
	{
	fprintf(fp, "%s %s", builtin_func_arg_type[type].c_type_smart, name);
	}

void BuiltinFuncArg::PrintValConstructor(FILE* fp)
	{
	fprintf(fp, builtin_func_arg_type[type].ctor_smart, name);
	}
