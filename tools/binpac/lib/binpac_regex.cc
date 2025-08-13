// See the file "COPYING" in the main distribution directory for copyright.

#include <vector>

namespace zeek {
class RE_Matcher;
}

namespace binpac {

std::vector<zeek::RE_Matcher*>* uncompiled_re_matchers = nullptr;

}
