//
// Runtime functions supporting the generated HILTI/BinPAC++ code.
//
// These function all assume either "HILTI-C" linkage.

extern "C" {

#include <libhilti/libhilti.h>

// Returns the ConnVal corresponding to the connection currently being
// analyzed. The cookie is a pointer to a Pac2Analyzer::Cookie instance.
void* libbro_cookie_to_conn_val(void* cookie, hlt_exception** excpt, hlt_execution_context* ctx);

// Returns a boolean value corresponding whether we're currently parsing the
// originator side of a connection. The cookie is a pointer to a
// Pac2Analyzer::Cookie instance.
void* libbro_cookie_to_is_orig(void* cookie, hlt_exception** excpt, hlt_execution_context* ctx);

// Converts a HILTI bytes value into a Bro StringVal.
void* libbro_h2b_bytes(hlt_bytes* value, hlt_exception** excpt, hlt_execution_context* ctx);

// Raises a given Bro events. The arguments are given as a tuple of Bro Val
// instances. The function takes ownership of those instances.
void libbro_raise_event(hlt_bytes* name, const hlt_type_info* type, const void* tuple, hlt_exception** excpt, hlt_execution_context* ctx);

}

