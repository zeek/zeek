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
    {'A', "addr_val|AsAddr\\(\\)"},     {'a', "any_val|AsAny\\(\\)"},
    {'D', "double_val|AsDouble\\(\\)"}, {'F', "func_val|AsFunc\\(\\)"},
    {'I', "int_val|AsInt\\(\\)"},       {'L', "list_val"},
    {'N', "subnet_val|AsSubNet\\(\\)"}, {'P', "re_val|AsPattern\\(\\)"},
    {'R', "record_val|AsRecord\\(\\)"}, {'S', "string_val|AsString\\(\\)"},
    {'T', "table_val|AsTable\\(\\)"},   {'t', "type_val|AsType\\(\\)"},
    {'U', "uint_val|AsCount\\(\\)"},    {'V', "vector_val|AsVector(Ref)?\\(\\)"},
};

int num_valid = 0;

void analyze_ZAM_inst(const char* op_name, const ZAMInstDesc& zid) {
    auto& oc = zid.op_class;
    auto& ot = zid.op_types;
    auto& eval = zid.op_desc;

    bool have_ot = ! ot.empty();

    if ( have_ot && oc.size() != ot.size() )
        reporter->InternalError("%s: instruction class/types mismatch (%s/%s)", op_name, oc.c_str(), ot.c_str());

    int nslot = 0;

    for ( size_t i = 0; i < oc.size(); ++i ) {
        string op;

        switch ( oc[i] ) {
            case 'V':
            case 'R': op = "frame\\[z\\.v" + std::to_string(++nslot) + "\\]"; break;

            case 'i': op = "z\\.v" + std::to_string(++nslot); break;

            case 'C': op = "z\\.c"; break;

            default:
                if ( have_ot && ot[i] != 'X' )
                    reporter->InternalError("instruction types mismatch: %s (%c)", op_name, oc[i]);
        }

        auto match_pat = op;
        if ( have_ot ) {
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
            match_pat += ".(" + tp->second + ")";
        }

        if ( ! std::regex_search(eval, std::regex(match_pat)) )
            reporter->InternalError("%s: did not find /%s/ in %s", op_name, match_pat.c_str(), eval.c_str());
    }
    ++num_valid;
}

void analyze_ZAM_insts() {
    (void)AssignmentFlavor(OP_NOP, TYPE_VOID, false);

    for ( int i = 0; i < int(OP_NOP); ++i ) {
        auto zop = ZOp(i);
        if ( zam_inst_desc.find(zop) == zam_inst_desc.end() && assignment_flavor.find(zop) == assignment_flavor.end() )
            reporter->InternalError("op %s missing from description", ZOP_name(zop));
    }

    for ( auto& zid : zam_inst_desc )
        analyze_ZAM_inst(ZOP_name(zid.first), zid.second);

    printf("%d valid\n", num_valid);
}

} // namespace zeek::detail
