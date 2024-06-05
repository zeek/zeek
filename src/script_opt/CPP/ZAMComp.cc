// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/ZAM/ZBody.h"
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

void CPPCompile::GenFromZAM(const ZBody* z) {
    auto insts = z->Instructions();
    auto ninsts = z->NumInsts();

    for ( unsigned int i = 0; i < ninsts; ++i )
        GenFromZAMInst(&insts[i]);

    reporter->InternalError("yep got called");
}

void CPPCompile::GenFromZAMInst(const ZInst* inst) {
    auto idesc = zam_inst_desc.find(inst->op);
    if ( idesc == zam_inst_desc.end() )
        reporter->InternalError("instruction operand missing from descriptions");

    printf("// %s %s\n", ZOP_name(inst->op), idesc->second.op_type.c_str());

    printf("\t%s\n", ExpandInst(inst, idesc->second).c_str());
}

string CPPCompile::ExpandInst(const ZInst* inst, const ZAMInstDesc& desc) {
    auto eval = desc.op_desc;
    int numV = 0;
    for ( auto t : desc.op_type ) {
        string orig, resp;

        switch ( t ) {
            case 'V': {
                orig = "frame\\[z\\.v" + std::to_string(++numV) + "\\]";
                int slot = GetSlot(inst, numV);
                resp = "frame[" + std::to_string(slot) + "]";
                break;
            }

            case 'i': {
                orig = "z\\.v" + std::to_string(++numV);
                resp = std::to_string(GetSlot(inst, numV));
                break;
            }

            case 'C': {
                orig = "z\\.c";
                // Do this the lazy way for now.
                auto c = make_intrusive<ConstExpr>(inst->c.ToVal(inst->t));
                resp = GenConstExpr(c.get(), GEN_VAL_PTR);
                break;
            }
        }

        if ( ! orig.empty() )
            eval = std::regex_replace(eval, std::regex(orig), resp);
    }

    return eval;
}

int CPPCompile::GetSlot(const ZInst* inst, int numV) {
    switch ( numV ) {
        case 1: return inst->v1;
        case 2: return inst->v2;
        case 3: return inst->v3;
        case 4: return inst->v4;

        default: return -1;
    }
}

} // namespace zeek::detail
