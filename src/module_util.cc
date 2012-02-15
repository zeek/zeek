//
// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <string.h>
#include "module_util.h"

static int streq(const char* s1, const char* s2)
	{
	return ! strcmp(s1, s2);
	}

// Returns it without trailing "::".
string extract_module_name(const char* name)
	{
	string module_name = name;
	string::size_type pos = module_name.rfind("::");

	if ( pos == string::npos )
		return string(GLOBAL_MODULE_NAME);

	module_name.erase(pos);

	return module_name;
	}

string extract_var_name(const char *name)
	{
	string var_name = name;
	string::size_type pos = var_name.rfind("::");

	if ( pos == string::npos )
		return var_name;

	if ( pos + 2 > var_name.size() )
		return string("");

	return var_name.substr(pos+2);
	}

string normalized_module_name(const char* module_name)
	{
	int mod_len;
	if ( (mod_len = strlen(module_name)) >= 2 &&
	     streq(module_name + mod_len - 2, "::") )
		mod_len -= 2;

	return string(module_name, mod_len);
	}

string make_full_var_name(const char* module_name, const char* var_name)
	{
	if ( ! module_name || streq(module_name, GLOBAL_MODULE_NAME) ||
	     strstr(var_name, "::") )
		return string(var_name);

	string full_name = normalized_module_name(module_name);
	full_name += "::";
	full_name += var_name;

	return full_name;
	}
