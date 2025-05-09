// See the file "COPYING" in the main distribution directory for copyright.

// Methods relating to low-level ZAM instruction manipulation.

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

const ZAMStmt ZAMCompiler::StartingBlock() { return ZAMStmt(insts1.size()); }

const ZAMStmt ZAMCompiler::FinishBlock(const ZAMStmt /* start */) { return ZAMStmt(insts1.size() - 1); }

bool ZAMCompiler::NullStmtOK() const {
    // They're okay iff they're the entire statement body.
    return insts1.empty();
}

const ZAMStmt ZAMCompiler::EmptyStmt() { return ZAMStmt(insts1.size() - 1); }

const ZAMStmt ZAMCompiler::ErrorStmt() { return ZAMStmt(0); }

const ZAMStmt ZAMCompiler::LastInst() { return ZAMStmt(insts1.size() - 1); }

void ZAMCompiler::AddCFT(ZInstI* inst, ControlFlowType cft) {
    if ( cft == CFT_NONE )
        return;

    if ( ! inst->aux )
        inst->aux = new ZInstAux(0);

    auto cft_entry = inst->aux->cft.find(cft);
    if ( cft_entry == inst->aux->cft.end() )
        inst->aux->cft[cft] = 1;
    else {
        ASSERT(cft == CFT_BLOCK_END || cft == CFT_LOOP_END || cft == CFT_BREAK);
        ++cft_entry->second;
    }
}

std::unique_ptr<OpaqueVals> ZAMCompiler::BuildVals(const ListExprPtr& l) {
    return std::make_unique<OpaqueVals>(InternalBuildVals(l.get()));
}

ZInstAux* ZAMCompiler::InternalBuildVals(const ListExpr* l, int stride) {
    auto exprs = l->Exprs();
    int n = exprs.length();

    auto aux = new ZInstAux(n * stride);

    int offset = 0; // offset into aux info
    for ( int i = 0; i < n; ++i ) {
        auto& e = exprs[i];
        int num_vals = InternalAddVal(aux, offset, e);
        ASSERT(num_vals == stride);
        offset += num_vals;
    }

    return aux;
}

int ZAMCompiler::InternalAddVal(ZInstAux* zi, int i, Expr* e) {
    if ( e->Tag() == EXPR_ASSIGN ) { // We're building up a table constructor
        auto& indices = e->GetOp1()->AsListExpr()->Exprs();
        auto val = e->GetOp2();
        int width = indices.length();
        int num_vals;

        for ( int j = 0; j < width; ++j ) {
            num_vals = InternalAddVal(zi, i + j, indices[j]);
            ASSERT(num_vals == 1);
        }

        num_vals = InternalAddVal(zi, i + width, val.get());
        ASSERT(num_vals == 1);

        return width + 1;
    }

    if ( e->Tag() == EXPR_LIST ) { // We're building up a set constructor
        auto& indices = e->AsListExpr()->Exprs();
        int width = indices.length();

        for ( int j = 0; j < width; ++j ) {
            int num_vals = InternalAddVal(zi, i + j, indices[j]);
            ASSERT(num_vals == 1);
        }

        return width;
    }

    if ( e->Tag() == EXPR_FIELD_ASSIGN ) {
        // These can appear when we're processing the expression
        // list for a record constructor.
        auto fa = e->AsFieldAssignExpr();
        e = fa->GetOp1().get();

        if ( e->GetType()->Tag() == TYPE_TYPE ) {
            // Ugh - we actually need a "type" constant.
            auto v = e->Eval(nullptr);
            ASSERT(v);
            zi->Add(i, v);
            return 1;
        }

        // Now that we've adjusted, fall through.
    }

    if ( e->Tag() == EXPR_NAME )
        zi->Add(i, FrameSlot(e->AsNameExpr()), e->GetType());

    else
        zi->Add(i, e->AsConstExpr()->ValuePtr());

    return 1;
}

const ZAMStmt ZAMCompiler::AddInst(const ZInstI& inst, bool suppress_non_local) {
    ZInstI* i;

    if ( pending_inst ) {
        i = pending_inst;
        pending_inst = nullptr;
    }
    else
        i = new ZInstI();

    *i = inst;

    insts1.push_back(i);

    top_main_inst = insts1.size() - 1;

    if ( suppress_non_local )
        return ZAMStmt(top_main_inst);

    // Ensure we haven't confused ourselves about any pending stores.
    ASSERT(pending_global_store == -1 || pending_capture_store == -1);

    if ( pending_global_store >= 0 ) {
        auto gs = pending_global_store;
        pending_global_store = -1;

        auto store_inst = ZInstI(OP_STORE_GLOBAL_g, gs);
        store_inst.op_type = OP_V_I1;
        store_inst.SetType(globalsI[gs].id->GetType());

        return AddInst(store_inst);
    }

    if ( pending_capture_store >= 0 ) {
        auto cs = pending_capture_store;
        pending_capture_store = -1;

        auto& cv = *func->GetType()->GetCaptures();
        auto& c_id = cv[cs].Id();

        ZOp op;

        if ( ZVal::IsManagedType(c_id->GetType()) )
            op = OP_STORE_MANAGED_CAPTURE_Vi;
        else
            op = OP_STORE_CAPTURE_Vi;

        auto store_inst = ZInstI(op, RawSlot(c_id.get()), cs);
        store_inst.op_type = OP_VV_I2;

        return AddInst(store_inst);
    }

    return ZAMStmt(top_main_inst);
}

const Stmt* ZAMCompiler::LastStmt(const Stmt* s) const {
    if ( s->Tag() == STMT_LIST ) {
        auto sl = s->AsStmtList()->Stmts();
        ASSERT(! sl.empty());
        return sl.back().get();
    }

    else
        return s;
}

ZAMStmt ZAMCompiler::PrevStmt(const ZAMStmt s) { return ZAMStmt(s.stmt_num - 1); }

} // namespace zeek::detail
