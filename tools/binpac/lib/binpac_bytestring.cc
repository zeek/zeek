// See the file "COPYING" in the main distribution directory for copyright.

#define binpac_regex_h

#include "binpac_bytestring.h"

#include <cstdlib>

namespace binpac {

std::string std_string(bytestring const* s) {
    return {reinterpret_cast<const char*>(s->begin()), reinterpret_cast<const char*>(s->end())};
}

int bytestring_to_int(bytestring const* s) { return atoi(reinterpret_cast<const char*>(s->begin())); }

double bytestring_to_double(bytestring const* s) { return atof(reinterpret_cast<const char*>(s->begin())); }

} // namespace binpac
