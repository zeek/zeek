// See the file "COPYING" in the main distribution directory for copyright.

#include <map>
#include <regex>
#include <string>

#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/ZInst.h"
#include "zeek/script_opt/ZAM/ZOp.h"

using std::string;

namespace zeek::detail {

std::unordered_map<ZOp, ZAMInstDesc> zam_inst_desc = {
#include "ZAM-OpDesc.h"
};

std::vector<std::pair<string, string>> zam_macro_desc = {
#include "ZAM-MacroDesc.h"
};

// While the following has commonalities that could be factored out,
// for now we keep this form because it provides flexibility for
// accommodating other forms of accessors.
static std::map<char, string> type_pats = {
    {'A', "Addr"},   {'a', "Any"},    {'D', "Double"}, {'F', "Func"},    {'I', "Int"},
    {'L', "List"},   {'N', "SubNet"}, {'O', "Opaque"}, {'P', "Pattern"}, {'R', "Record"},
    {'S', "String"}, {'T', "Table"},  {'t', "Type"},   {'U', "Count"},   {'V', "Vector"},
};

static int num_valid = 0;
static int num_tested = 0;
static int num_skipped = 0;

void analyze_ZAM_inst(const char* op_name, const ZAMInstDesc& zid) {
    auto& oc = zid.op_class;
    auto& ot = zid.op_types;
    auto& eval = zid.op_eval;

    bool have_ot = ! ot.empty();

    if ( have_ot && oc.size() != ot.size() )
        reporter->InternalError("%s: instruction class/types mismatch (%s/%s)", op_name, oc.c_str(), ot.c_str());

    int nslot = 0;

    for ( size_t i = 0; i < oc.size(); ++i ) {
        auto oc_i = oc[i];

        string op;

        switch ( oc_i ) {
            case 'V':
            case 'R': op = "frame\\[z\\.v" + std::to_string(++nslot) + "\\]"; break;

            case 'b':
            case 'f':
            case 'g':
            case 's':
            case 'i': op = "z\\.v" + std::to_string(++nslot); break;

            case 'C': op = "z\\.c"; break;

            default:
                if ( have_ot && ot[i] != 'X' )
                    reporter->InternalError("instruction types mismatch: %s (%c)", op_name, oc_i);
        }

        auto match_pat = op;
        if ( have_ot ) {
            auto ot_i = ot[i];

            bool bare_int = std::string("bfgis").find(oc_i) != std::string::npos;

            if ( ot_i == 'X' || bare_int ) {
                if ( ot_i == 'X' && bare_int )
                    reporter->InternalError("empty instruction type for '%c' class element: %s", oc_i, op_name);

                if ( ! std::regex_search(eval, std::regex(op)) )
                    reporter->InternalError("%s: operand %s not found", op_name, op.c_str());

                ++num_skipped;
                continue;
            }

            auto tp = type_pats.find(ot_i);
            if ( tp == type_pats.end() )
                reporter->InternalError("%s: instruction type %c not found", op_name, ot_i);
            match_pat += ".As" + tp->second + "(Ref)?\\(\\)";
            ++num_tested;
        }

        if ( ! std::regex_search(eval, std::regex(match_pat)) )
            reporter->InternalError("%s: did not find /%s/ in %s", op_name, match_pat.c_str(), eval.c_str());
    }
    ++num_valid;
}

void validate_ZAM_insts() {
    // The following primes a data structure we access.
    (void)AssignmentFlavor(OP_NOP, TYPE_VOID, false);

    for ( int i = 0; i < static_cast<int>(OP_NOP); ++i ) {
        auto zop = ZOp(i);
        if ( ! zam_inst_desc.contains(zop) && ! assignment_flavor.contains(zop) )
            reporter->InternalError("op %s missing from description", ZOP_name(zop));
    }

    for ( auto& zid : zam_inst_desc )
        analyze_ZAM_inst(ZOP_name(zid.first), zid.second);

    int num_valid_macros = 0;
    for ( auto& md : zam_macro_desc ) {
        if ( std::regex_search(md.second, std::regex("\\$[0-9$]")) )
            reporter->InternalError("macro %s contains dollar parameter: %s", md.first.c_str(), md.second.c_str());
        ++num_valid_macros;
    }

    printf("%d valid ops, %d tested, %d skipped, %d valid macros\n", num_valid, num_tested, num_skipped,
           num_valid_macros);
}

} // namespace zeek::detail
