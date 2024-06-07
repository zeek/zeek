// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "zeek/script_opt/ZAM/ZBody.h"
#include "zeek/script_opt/ZAM/ZOp.h"

using std::string;

namespace zeek::detail {

struct ZAMInstDesc {
    string op_class;
    string op_types;
    string op_desc;
};

std::unordered_map<ZOp, ZAMInstDesc> zam_inst_desc = {

#include "ZAM-Desc.h"

};

static std::map<char, string> type_pats = {
    {'a', "any_val|AsAny\\(\\)"},
    {'A', "addr_val|AsAddr\\(\\)"},
    {'D', "double_val|AsDouble\\(\\)"},
    {'F', "func_val|AsFunc\\(\\)"},
    {'I', "int_val|AsInt\\(\\)"},
    {'L', "list_val"},
    {'N', "subnet_val|AsSubNet\\(\\)"},
    {'P', "re_val|AsPattern\\(\\)"},
    {'R', "record_val|AsRecord\\(\\)"},
    {'S', "string_val|AsString\\(\\)"},
    {'T', "table_val|AsTable\\(\\)"},
    {'U', "uint_val|AsCount\\(\\)"},
    {'V', "vector_val|AsVector(Ref)?\\(\\)"},
};

void analyze_ZAM_inst(const char* op_name, const ZAMInstDesc& zid) {
    if ( ! zid.op_types.empty() ) {
        auto& oc = zid.op_class;
        auto& ot = zid.op_types;
        auto& eval = zid.op_desc;

        if ( oc.size() != ot.size() )
            reporter->InternalError("%s: instruction class/types mismatch (%s/%s)", op_name, oc.c_str(), ot.c_str());

        int nslot = 0;

        for ( size_t i = 0; i < oc.size(); ++i ) {
            string op;

            switch ( oc[i] ) {
                case 'V': op = "frame\\[z\\.v" + std::to_string(++nslot) + "\\]"; break;

                case 'i': op = "z\\.v" + std::to_string(++nslot); break;

                case 'C': op = "z\\.c"; break;

                default:
                    if ( ot[i] != 'X' )
                        reporter->InternalError("instruction types mismatch: %s (%c)", op_name, oc[i]);
            }

            if ( ot[i] == 'X' || oc[i] == 'i' ) {
                if ( ot[i] == 'X' && oc[i] == 'i' )
                    reporter->InternalError("empty instruction type for 'i' class element: %s", op_name);

                if ( ! std::regex_search(eval, std::regex(op)) )
                    reporter->InternalError("%s: operand %s not found", op_name, op.c_str());

                continue;
            }

            auto tp = type_pats.find(ot[i]);
            if ( tp == type_pats.end() )
                reporter->InternalError("%s: instruction type %c not found", op_name, ot[i]);

            auto match_pat = op + "." + string("(") + tp->second + ")";
            if ( ! std::regex_search(eval, std::regex(match_pat)) )
                reporter->InternalError("%s: did not find /%s/ in %s", op_name, match_pat.c_str(), eval.c_str());
        }
    }
}

void analyze_ZAM_insts() {
    for ( auto& zid : zam_inst_desc )
        analyze_ZAM_inst(ZOP_name(zid.first), zid.second);
}

} // namespace zeek::detail
