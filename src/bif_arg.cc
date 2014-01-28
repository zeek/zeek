#include "config.h"

#include <set>
#include <string>
using namespace std;

#include <string.h>

#include "bif_arg.h"

static struct {
	const char* bif_type;
	const char* bro_type;
	const char* c_type;
	const char* accessor;
	const char* constructor;
} builtin_func_arg_type[] = {
#define DEFINE_BIF_TYPE(id, bif_type, bro_type, c_type, accessor, constructor) \
	{bif_type, bro_type, c_type, accessor, constructor},
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

void BuiltinFuncArg::PrintBro(FILE* fp)
	{
	fprintf(fp, "%s: %s%s %s", name, builtin_func_arg_type[type].bro_type,
	        type_str, attr_str);
	}

void BuiltinFuncArg::PrintCDef(FILE* fp, int n)
	{
	fprintf(fp,
		"\t%s %s = (%s) (",
		builtin_func_arg_type[type].c_type,
		name,
		builtin_func_arg_type[type].c_type);

	char buf[1024];
	snprintf(buf, sizeof(buf), "(*%s)[%d]", arg_list_name, n);
	// Print the accessor expression.
	fprintf(fp, builtin_func_arg_type[type].accessor, buf);

	fprintf(fp, ");\n");
	}

void BuiltinFuncArg::PrintCArg(FILE* fp, int n)
	{
	const char* ctype = builtin_func_arg_type[type].c_type;
	char buf[1024];

	fprintf(fp, "%s %s", ctype, name);
	}

void BuiltinFuncArg::PrintBroValConstructor(FILE* fp)
	{
	fprintf(fp, builtin_func_arg_type[type].constructor, name);
	}
