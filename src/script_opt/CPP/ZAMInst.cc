// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "zeek/script_opt/ZAM/ZOp.h"

using std::string;

namespace zeek::detail {

struct ZAMInstDesc {
    string op_type;
    string op_desc;
};

std::unordered_map<ZOp, ZAMInstDesc> zam_inst_desc = {

#include "ZAM-Desc.h"

};

} // namespace zeek::detail
