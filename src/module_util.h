//
// These functions are used by both Bro and bifcl.
//

#include <string>

using namespace std;

static const char* GLOBAL_MODULE_NAME = "GLOBAL";

extern string extract_module_name(const char* name);
extern string extract_var_name(const char* name);
extern string normalized_module_name(const char* module_name); // w/o ::

// Concatenates module_name::var_name unless var_name is already fully
// qualified, in which case it is returned unmodified.
extern string make_full_var_name(const char* module_name, const char* var_name);
