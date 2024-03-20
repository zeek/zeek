// See the file "COPYING" in the main distribution directory for copyright.

// ZAM methods associated with instructions that replace calls to
// built-in functions.

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

class ZAMBuiltIn {
public:
    ZAMBuiltIn(bool _ret_val_matters) : ret_val_matters(_ret_val_matters) {}

    virtual ~ZAMBuiltIn() = default;

    bool ReturnValMatters() const { return ret_val_matters; }
    bool HaveBothReturnValAndNon() const { return have_both; }

    virtual bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const = 0;

protected:
    bool ret_val_matters = true;
    bool have_both = false;
};

class DirectBuiltIn : public ZAMBuiltIn {
public:
    DirectBuiltIn(ZOp _op, int _nargs, bool _ret_val_matters = true)
        : ZAMBuiltIn(_ret_val_matters), op(_op), nargs(_nargs) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        ZInstI z;
        if ( nargs == 0 ) {
            if ( n )
                z = ZInstI(op, zam->Frame1Slot(n, OP1_WRITE));
            else
                z = ZInstI(op);
        }
        else {
            ASSERT(nargs == 1);
            auto a0 = zam->FrameSlot(args[0]->AsNameExpr());
            if ( n )
                z = ZInstI(op, zam->Frame1Slot(n, OP1_WRITE), a0);
            else
                z = ZInstI(op, a0);
            z.t = args[0]->GetType();
        }

        zam->AddInst(z);

        return true;
    }

protected:
    ZOp op;
    int nargs;
};

class DirectBuiltInOptAssign : public DirectBuiltIn {
public:
    // First argument is assignment flavor, second is assignment-less flavor.
    DirectBuiltInOptAssign(ZOp _op, ZOp _op2, int _nargs) : DirectBuiltIn(_op, _nargs, false), op2(_op2) {
        have_both = true;
    }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        if ( n )
            return DirectBuiltIn::Build(zam, n, args);

        ZInstI z;
        if ( nargs == 0 )
            z = ZInstI(op2);
        else {
            ASSERT(nargs == 1);
            auto a0 = zam->FrameSlot(args[0]->AsNameExpr());
            z = ZInstI(op, a0);
            z.t = args[0]->GetType();
        }

        zam->AddInst(z);

        return true;
    }

protected:
    ZOp op2;
};

enum ArgsType {
    VV = 0x0,
    VC = 0x1,
    CV = 0x2,
    CC = 0x3,

    VVV = 0x0,
    VVC = 0x1,
    VCV = 0x2,
    VCC = 0x3,
    CVV = 0x4,
    CVC = 0x5,
    CCV = 0x6,
    CCC = 0x7,
};

struct ArgInfo {
    ZOp op;
    ZAMOpType op_type;
};

using BifArgsInfo = std::map<ArgsType, ArgInfo>;

class MultiArgBuiltIn : public ZAMBuiltIn {
public:
    MultiArgBuiltIn(bool _ret_val_matters, BifArgsInfo _args_info)
        : ZAMBuiltIn(_ret_val_matters), args_info(std::move(_args_info)) {}

    MultiArgBuiltIn(BifArgsInfo _args_info, BifArgsInfo _assign_args_info) : MultiArgBuiltIn(false, _args_info) {
        assign_args_info = std::move(_assign_args_info);
        have_both = true;
    }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        auto ai = &args_info;
        if ( n && have_both ) {
            ai = &assign_args_info;
            ASSERT(! ai->empty());
        }

        auto bif_arg_info = ai->find(ComputeArgsType(args));
        if ( bif_arg_info == ai->end() )
            return false;

        const auto& bi = bif_arg_info->second;
        auto op = bi.op;

        std::vector<ValPtr> consts;
        std::vector<int> v;

        for ( auto i = 0U; i < args.size(); ++i ) {
            auto a = args[i];
            if ( a->Tag() == EXPR_NAME )
                v.push_back(zam->FrameSlot(a->AsNameExpr()));
            else
                consts.push_back(a->AsConstExpr()->ValuePtr());
        }

        auto nslot = n ? zam->Frame1Slot(n, OP1_WRITE) : -1;

        ZInstI z;

        if ( args.size() == 2 ) {
            if ( consts.empty() ) {
                if ( n )
                    z = ZInstI(op, nslot, v[0], v[1]);
                else
                    z = ZInstI(op, v[0], v[1]);
            }
            else {
                ASSERT(consts.size() == 1);
                if ( n )
                    z = ZInstI(op, nslot, v[0]);
                else
                    z = ZInstI(op, v[0]);
            }
        }

        else if ( args.size() == 3 ) {
            switch ( consts.size() ) {
                case 0:
                    if ( n )
                        z = ZInstI(op, nslot, v[0], v[1], v[2]);
                    else
                        z = ZInstI(op, v[0], v[1], v[2]);
                    break;

                case 1:
                    if ( n )
                        z = ZInstI(op, nslot, v[0], v[1]);
                    else
                        z = ZInstI(op, v[0], v[1]);
                    break;

                case 2: {
                    auto c2 = consts[1];
                    auto c2_t = c2->GetType()->Tag();

                    ASSERT(c2_t == TYPE_BOOL || c2_t == TYPE_INT || c2_t == TYPE_COUNT);
                    int slot_val;
                    if ( c2_t == TYPE_COUNT )
                        slot_val = static_cast<int>(c2->AsCount());
                    else
                        slot_val = c2->AsInt();

                    if ( n )
                        z = ZInstI(op, nslot, v[0], slot_val);
                    else
                        z = ZInstI(op, v[0], slot_val);
                    break;
                }

                default: reporter->InternalError("inconsistency in MultiArgBuiltIn::Build");
            }
        }

        else
            reporter->InternalError("inconsistency in MultiArgBuiltIn::Build");

        z.op_type = bi.op_type;

        if ( ! consts.empty() ) {
            z.t = consts[0]->GetType();
            z.c = ZVal(consts[0], z.t);
        }

        zam->AddInst(z);

        return true;
    }

private:
    // Returns a bit mask of which of the arguments in the given list
    // correspond to constants, with the high-ordered bit being the first
    // argument (argument "0" in the list) and the low-ordered bit being
    // the last. These correspond to the ArgsType enum integer values.
    ArgsType ComputeArgsType(const ExprPList& args) const {
        zeek_uint_t mask = 0;

        for ( int i = 0; i < args.size(); ++i ) {
            mask <<= 1;
            if ( args[i]->Tag() == EXPR_CONST )
                mask |= 1;
        }

        return ArgsType(mask);
    }

    BifArgsInfo args_info;
    BifArgsInfo assign_args_info;
};

class SortBiF : public DirectBuiltIn {
public:
    SortBiF() : DirectBuiltIn(OP_SORT_V, 1, false) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        if ( args.size() > 2 )
            return false;

        auto v = args[0]->AsNameExpr();
        if ( v->GetType()->Tag() != TYPE_VECTOR )
            return false;

        const auto& elt_type = v->GetType()->Yield();

        if ( args.size() == 1 ) {
            if ( ! IsIntegral(elt_type->Tag()) && elt_type->InternalType() != TYPE_INTERNAL_DOUBLE )
                return false;

            return DirectBuiltIn::Build(zam, n, args);
        }

        const auto& comp_val = args[1];
        if ( ! IsFunc(comp_val->GetType()->Tag()) )
            return false;

        if ( comp_val->Tag() != EXPR_NAME )
            return false;

        auto comp_func_val = comp_val->AsNameExpr()->Id()->GetVal();
        if ( ! comp_func_val )
            return false;

        auto comp = comp_func_val->AsFunc();
        const auto& comp_type = comp->GetType();

        if ( comp_type->Yield()->Tag() != TYPE_INT || ! comp_type->ParamList()->AllMatch(elt_type, 0) ||
             comp_type->ParamList()->GetTypes().size() != 2 )
            return false;

        zam->AddInst(ZInstI(OP_SORT_WITH_CMP_VV, zam->FrameSlot(v), zam->FrameSlot(comp_val->AsNameExpr())));

        return true;
    }
};

class CatBiF : public ZAMBuiltIn {
public:
    CatBiF() : ZAMBuiltIn(true) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        auto nslot = zam->Frame1Slot(n, OP1_WRITE);
        auto& a0 = args[0];
        ZInstI z;

        if ( args.empty() ) {
            // Weird, but easy enough to support.
            z = ZInstI(OP_CAT1_VC, nslot);
            z.t = n->GetType();
            z.c = ZVal(val_mgr->EmptyString());
        }

        else if ( args.size() > 1 ) {
            switch ( args.size() ) {
                case 2: z = zam->GenInst(OP_CAT2_V, n); break;
                case 3: z = zam->GenInst(OP_CAT3_V, n); break;
                case 4: z = zam->GenInst(OP_CAT4_V, n); break;
                case 5: z = zam->GenInst(OP_CAT5_V, n); break;
                case 6: z = zam->GenInst(OP_CAT6_V, n); break;
                case 7: z = zam->GenInst(OP_CAT7_V, n); break;
                case 8: z = zam->GenInst(OP_CAT8_V, n); break;

                default: z = zam->GenInst(OP_CATN_V, n); break;
            }

            z.aux = BuildCatAux(zam, args);
        }

        else if ( a0->GetType()->Tag() != TYPE_STRING ) {
            if ( a0->Tag() == EXPR_NAME ) {
                z = zam->GenInst(OP_CAT1FULL_VV, n, a0->AsNameExpr());
                z.t = a0->GetType();
            }
            else {
                z = ZInstI(OP_CAT1_VC, nslot);
                z.t = n->GetType();
                z.c = ZVal(ZAM_val_cat(a0->AsConstExpr()->ValuePtr()));
            }
        }

        else if ( a0->Tag() == EXPR_CONST ) {
            z = zam->GenInst(OP_CAT1_VC, n, a0->AsConstExpr());
            z.t = n->GetType();
        }

        else
            z = zam->GenInst(OP_CAT1_VV, n, a0->AsNameExpr());

        zam->AddInst(z);

        return true;
    }

private:
    ZInstAux* BuildCatAux(ZAMCompiler* zam, const ExprPList& args) const {
        auto n = args.size();
        auto aux = new ZInstAux(n);
        aux->cat_args = new std::unique_ptr<CatArg>[n];

        for ( size_t i = 0; i < n; ++i ) {
            auto& a_i = args[i];
            auto& t = a_i->GetType();

            std::unique_ptr<CatArg> ca;

            if ( a_i->Tag() == EXPR_CONST ) {
                auto c = a_i->AsConstExpr()->ValuePtr();
                aux->Add(i, c); // it will be ignored
                auto sv = ZAM_val_cat(c);
                auto s = sv->AsString();
                auto b = reinterpret_cast<char*>(s->Bytes());
                ca = std::make_unique<CatArg>(std::string(b, s->Len()));
            }

            else {
                auto slot = zam->FrameSlot(a_i->AsNameExpr());
                aux->Add(i, slot, t);

                switch ( t->Tag() ) {
                    case TYPE_BOOL:
                    case TYPE_INT:
                    case TYPE_COUNT:
                    case TYPE_DOUBLE:
                    case TYPE_TIME:
                    case TYPE_ENUM:
                    case TYPE_PORT:
                    case TYPE_ADDR:
                    case TYPE_SUBNET: ca = std::make_unique<FixedCatArg>(t); break;

                    case TYPE_STRING: ca = std::make_unique<StringCatArg>(); break;

                    case TYPE_PATTERN: ca = std::make_unique<PatternCatArg>(); break;

                    default: ca = std::make_unique<DescCatArg>(t); break;
                }
            }

            aux->cat_args[i] = std::move(ca);
        }

        return aux;
    }
};

class LogWriteBiF : public ZAMBuiltIn {
public:
    LogWriteBiF() : ZAMBuiltIn(false) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override {
        auto id = args[0];
        auto columns = args[1];

        if ( columns->Tag() != EXPR_NAME )
            return false;

        auto columns_n = columns->AsNameExpr();
        auto col_slot = zam->FrameSlot(columns_n);

        bool const_id = (id->Tag() == EXPR_CONST);

        ZInstAux* aux = nullptr;

        if ( const_id ) {
            aux = new ZInstAux(1);
            aux->Add(0, id->AsConstExpr()->ValuePtr());
        }

        ZInstI z;

        if ( n ) {
            auto nslot = zam->Frame1Slot(n, OP1_WRITE);

            if ( const_id ) {
                z = ZInstI(OP_LOG_WRITEC_VV, nslot, col_slot);
                z.aux = aux;
            }
            else
                z = ZInstI(OP_LOG_WRITE_VVV, nslot, zam->FrameSlot(id->AsNameExpr()), col_slot);
        }
        else {
            if ( const_id ) {
                z = ZInstI(OP_LOG_WRITEC_V, col_slot, id->AsConstExpr());
                z.aux = aux;
            }
            else
                z = ZInstI(OP_LOG_WRITE_VV, zam->FrameSlot(id->AsNameExpr()), col_slot);
        }

        z.SetType(columns_n->GetType());

        zam->AddInst(z);

        return true;
    }
};

bool ZAMCompiler::IsZAM_BuiltIn(const Expr* e) {
    // The expression e is either directly a call (in which case there's
    // no return value), or an assignment to a call.
    const CallExpr* c;

    if ( e->Tag() == EXPR_CALL )
        c = e->AsCallExpr();
    else
        c = e->GetOp2()->AsCallExpr();

    auto func_expr = c->Func();
    if ( func_expr->Tag() != EXPR_NAME )
        // An indirect call.
        return false;

    auto func_val = func_expr->AsNameExpr()->Id()->GetVal();
    if ( ! func_val )
        // A call to a function that hasn't been defined.
        return false;

    auto func = func_val->AsFunc();
    if ( func->GetKind() != BuiltinFunc::BUILTIN_FUNC )
        return false;

    static BifArgsInfo get_bytes_thresh_info;
    static BifArgsInfo sub_bytes_info;
    static BifArgsInfo set_bytes_thresh_info, set_bytes_thresh_assign_info;
    static BifArgsInfo set_reassem_info, set_reassem_assign_info;
    static BifArgsInfo strstr_info;

    static bool did_init = false;
    if ( ! did_init ) {
        get_bytes_thresh_info[VV] = {OP_GET_BYTES_THRESH_VVV, OP_VVV};
        get_bytes_thresh_info[VC] = {OP_GET_BYTES_THRESH_VVi, OP_VVC};

        sub_bytes_info[VVV] = {OP_SUB_BYTES_VVVV, OP_VVVV};
        sub_bytes_info[VVC] = {OP_SUB_BYTES_VVVi, OP_VVVC};
        sub_bytes_info[VCV] = {OP_SUB_BYTES_VViV, OP_VVVC};
        sub_bytes_info[VCC] = {OP_SUB_BYTES_VVii, OP_VVVC_I3};
        sub_bytes_info[CVV] = {OP_SUB_BYTES_VVVC, OP_VVVC};
        sub_bytes_info[CVC] = {OP_SUB_BYTES_VViC, OP_VVVC_I3};
        sub_bytes_info[CCV] = {OP_SUB_BYTES_ViVC, OP_VVVC_I3};

        set_bytes_thresh_info[VVV] = {OP_SET_BYTES_THRESH_VVV, OP_VVV};
        set_bytes_thresh_info[VVC] = {OP_SET_BYTES_THRESH_VVi, OP_VVC};
        set_bytes_thresh_info[VCV] = {OP_SET_BYTES_THRESH_ViV, OP_VVC};
        set_bytes_thresh_info[VCC] = {OP_SET_BYTES_THRESH_Vii, OP_VVC_I2};

        set_bytes_thresh_assign_info[VVV] = {OP_SET_BYTES_THRESH_VVVV, OP_VVVV};
        set_bytes_thresh_assign_info[VVC] = {OP_SET_BYTES_THRESH_VVVi, OP_VVVC};
        set_bytes_thresh_assign_info[VCV] = {OP_SET_BYTES_THRESH_VViV, OP_VVVC};
        set_bytes_thresh_assign_info[VCC] = {OP_SET_BYTES_THRESH_VVii, OP_VVVC_I3};

        set_reassem_info[VV] = {OP_FILES_SET_REASSEMBLY_BUFFER_VV, OP_VV};
        set_reassem_info[VC] = {OP_FILES_SET_REASSEMBLY_BUFFER_VC, OP_VV_I2};
        set_reassem_assign_info[VV] = {OP_FILES_SET_REASSEMBLY_BUFFER_VVV, OP_VVV};
        set_reassem_assign_info[VC] = {OP_FILES_SET_REASSEMBLY_BUFFER_VVC, OP_VVV_I3};

        strstr_info[VV] = {OP_STRSTR_VVV, OP_VVV};
        strstr_info[VC] = {OP_STRSTR_VVC, OP_VVC};
        strstr_info[CV] = {OP_STRSTR_VCV, OP_VVC};

        did_init = true;
    }

    static std::map<std::string, std::shared_ptr<ZAMBuiltIn>> builtins = {
        {"Analyzer::__name", std::make_shared<DirectBuiltIn>(OP_ANALYZER_NAME_VV, 1)},
        {"Broker::__flush_logs",
         std::make_shared<DirectBuiltInOptAssign>(OP_BROKER_FLUSH_LOGS_V, OP_BROKER_FLUSH_LOGS_X, 0)},
        {"Files::__enable_reassembly", std::make_shared<DirectBuiltIn>(OP_FILES_ENABLE_REASSEMBLY_V, 1, false)},
        {"Files::__set_reassembly_buffer",
         std::make_shared<MultiArgBuiltIn>(set_reassem_info, set_reassem_assign_info)},
        {"Log::__write", std::make_shared<LogWriteBiF>()},
        {"cat", std::make_shared<CatBiF>()},
        {"current_time", std::make_shared<DirectBuiltIn>(OP_CURRENT_TIME_V, 0)},
        {"get_current_conn_bytes_threshold", std::make_shared<MultiArgBuiltIn>(true, get_bytes_thresh_info)},
        {"get_port_transport_proto", std::make_shared<DirectBuiltIn>(OP_GET_PORT_TRANSPORT_PROTO_VV, 1)},
        {"is_v4_addr", std::make_shared<DirectBuiltIn>(OP_IS_V4_ADDR_VV, 1)},
        {"is_v6_addr", std::make_shared<DirectBuiltIn>(OP_IS_V6_ADDR_VV, 1)},
        {"network_time", std::make_shared<DirectBuiltIn>(OP_NETWORK_TIME_V, 0)},
        {"reading_live_traffic", std::make_shared<DirectBuiltIn>(OP_READING_LIVE_TRAFFIC_V, 0)},
        {"reading_traces", std::make_shared<DirectBuiltIn>(OP_READING_TRACES_V, 0)},
        {"set_current_conn_bytes_threshold",
         std::make_shared<MultiArgBuiltIn>(set_bytes_thresh_info, set_bytes_thresh_assign_info)},
        {"sort", std::make_shared<SortBiF>()},
        {"strstr", std::make_shared<MultiArgBuiltIn>(true, strstr_info)},
        {"sub_bytes", std::make_shared<MultiArgBuiltIn>(true, sub_bytes_info)},
        {"to_lower", std::make_shared<DirectBuiltIn>(OP_TO_LOWER_VV, 1)},
    };

    auto b = builtins.find(func->Name());
    if ( b == builtins.end() )
        return false;

    const auto& bi = b->second;

    const NameExpr* n = nullptr; // name to assign to, if any
    if ( e->Tag() != EXPR_CALL )
        n = e->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();

    if ( bi->ReturnValMatters() ) {
        if ( ! n ) {
            reporter->Warning("return value from built-in function ignored");

            // The call is a no-op. We could return false here and have it
            // execute (for no purpose). We can also return true, which will
            // have the effect of just ignoring the statement.
            return true;
        }
    }
    else if ( n && ! bi->HaveBothReturnValAndNon() ) {
        // Because the return value "doesn't matter", we've built the
        // BiF replacement operation assuming we don't need a version that
        // does the assignment. If we *do* have an assignment, let the usual
        // call take its place.
        return false;
    }

    return bi->Build(this, n, c->Args()->Exprs());
}

} // namespace zeek::detail
