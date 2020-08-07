//
// See the file "COPYING" in the main distribution directory for copyright.

#include "module_util.h"

#include <string.h>
#include <iostream>
#include <string>

#include "3rdparty/doctest.h"

using namespace std;

namespace zeek::detail {

static int streq(const char* s1, const char* s2)
	{
	return ! strcmp(s1, s2);
	}

TEST_CASE("module_util streq")
	{
	CHECK(streq("abcd", "abcd") == true);
	CHECK(streq("abcd", "efgh") == false);
	}

TEST_CASE("module_util extract_module_name")
	{
	CHECK(extract_module_name("mod") == GLOBAL_MODULE_NAME);
	CHECK(extract_module_name("mod::") == "mod");
	CHECK(extract_module_name("mod::var") == "mod");
	}

// Returns it without trailing "::" var section.
string extract_module_name(const char* name)
	{
	string module_name = name;
	string::size_type pos = module_name.rfind("::");

	if ( pos == string::npos )
		return string(GLOBAL_MODULE_NAME);

	module_name.erase(pos);

	return module_name;
	}

TEST_CASE("module_util extract_var_name")
	{
	CHECK(extract_var_name("mod") == "mod");
	CHECK(extract_var_name("mod::") == "");
	CHECK(extract_var_name("mod::var") == "var");
	CHECK(extract_var_name("::var") == "var");
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

TEST_CASE("module_util normalized_module_name")
	{
	CHECK(normalized_module_name("a") == "a");
	CHECK(normalized_module_name("module") == "module");
	CHECK(normalized_module_name("module::") == "module");
	}

string normalized_module_name(const char* module_name)
	{
	int mod_len;
	if ( (mod_len = strlen(module_name)) >= 2 &&
	     streq(module_name + mod_len - 2, "::") )
		mod_len -= 2;

	return string(module_name, mod_len);
	}

TEST_CASE("module_util make_full_var_name")
	{
	CHECK(make_full_var_name(nullptr, "GLOBAL::var") == "var");
	CHECK(make_full_var_name(GLOBAL_MODULE_NAME, "var") == "var");
	CHECK(make_full_var_name(nullptr, "notglobal::var") == "notglobal::var");
	CHECK(make_full_var_name(nullptr, "::var") == "::var");

	CHECK(make_full_var_name("module", "var") == "module::var");
	CHECK(make_full_var_name("module::", "var") == "module::var");
	CHECK(make_full_var_name("", "var") == "::var");
	}

string make_full_var_name(const char* module_name, const char* var_name)
	{
	if ( ! module_name || streq(module_name, GLOBAL_MODULE_NAME) ||
	     strstr(var_name, "::") )
		{
		if ( streq(GLOBAL_MODULE_NAME, extract_module_name(var_name).c_str()) )
			return extract_var_name(var_name);

		return string(var_name);
		}

	string full_name = normalized_module_name(module_name);
	full_name += "::";
	full_name += var_name;

	return full_name;
	}

} // namespace zeek::detail
