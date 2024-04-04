// See the file "COPYING" in the main distribution directory for copyright.

// ZAM methods associated with instructions that replace calls to
// built-in functions.

#include "zeek/script_opt/ZAM/BuiltIn.h"

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

std::map<std::string, const ZAMBuiltIn*> builtins;

ZAMBuiltIn::ZAMBuiltIn(std::string name, bool _ret_val_matters) : ret_val_matters(_ret_val_matters) {
    builtins[name] = this;
}

SimpleZBI::SimpleZBI(std::string name, ZOp _op, int _nargs, bool _ret_val_matters)
    : ZAMBuiltIn(std::move(name), _ret_val_matters), op(_op), nargs(_nargs) {}

SimpleZBI::SimpleZBI(std::string name, ZOp _const_op, ZOp _op, bool _ret_val_matters)
    : ZAMBuiltIn(std::move(name), _ret_val_matters), op(_op), const_op(_const_op), nargs(1) {}

bool SimpleZBI::Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const {
    ZInstI z;
    if ( nargs == 0 ) {
        if ( n )
            z = ZInstI(op, zam->Frame1Slot(n, OP1_WRITE));
        else
            z = ZInstI(op);
    }
    else {
        ASSERT(nargs == 1);
        auto& t = args[0]->GetType();

        if ( args[0]->Tag() == EXPR_NAME ) {
            auto a0 = zam->FrameSlot(args[0]->AsNameExpr());
            if ( n )
                z = ZInstI(op, zam->Frame1Slot(n, OP1_WRITE), a0);
            else
                z = ZInstI(op, a0);
        }

        else {
            if ( const_op == OP_NOP )
                // This can happen for BiFs that aren't foldable, and for
                // which it's implausible they'll be called with a constant
                // argument.
                return false;
            if ( n )
                z = ZInstI(const_op, zam->Frame1Slot(n, OP1_WRITE));
            else
                z = ZInstI(const_op);
            z.c = ZVal(args[0]->AsConstExpr()->ValuePtr(), t);
        }

        z.t = t;
    }

    if ( n )
        z.is_managed = ZVal::IsManagedType(n->GetType());

    zam->AddInst(z);

    return true;
}

CondZBI::CondZBI(std::string name, ZOp _op, ZOp _cond_op, int _nargs)
    : SimpleZBI(std::move(name), _op, _nargs, true), cond_op(_cond_op) {}

bool CondZBI::BuildCond(ZAMCompiler* zam, const ExprPList& args, int& branch_v) const {
    if ( cond_op == OP_NOP )
        return false;

    if ( nargs == 1 && args[0]->Tag() != EXPR_NAME )
        return false;

    if ( ! zam )
        // This was just a check, not an actual build.
        return true;

    ZInstI z;

    if ( nargs == 0 ) {
        z = ZInstI(cond_op, 0);
        z.op_type = OP_V_I1;
        branch_v = 1;
    }

    else {
        ASSERT(nargs == 1);

        auto a0 = args[0];
        auto a0_slot = zam->FrameSlot(a0->AsNameExpr());
        z = ZInstI(cond_op, a0_slot, 0);
        z.op_type = OP_VV_I2;
        z.t = a0->GetType();
        branch_v = 2;
    }

    zam->AddInst(z);

    return true;
}

OptAssignZBI::OptAssignZBI(std::string name, ZOp _op, ZOp _op2, int _nargs)
    : SimpleZBI(std::move(name), _op, _nargs, false), op2(_op2) {
    have_both = true;
}

bool OptAssignZBI::Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const {
    if ( n )
        return SimpleZBI::Build(zam, n, args);

    ZInstI z;
    if ( nargs == 0 )
        z = ZInstI(op2);
    else {
        ASSERT(nargs == 1);
        auto a0 = zam->FrameSlot(args[0]->AsNameExpr());
        z = ZInstI(op2, a0);
        z.t = args[0]->GetType();
    }

    zam->AddInst(z);

    return true;
}

bool CatZBI::Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const {
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

ZInstAux* CatZBI::BuildCatAux(ZAMCompiler* zam, const ExprPList& args) const {
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

bool SortZBI::Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const {
    if ( args.size() > 2 )
        return false;

    auto v = args[0]->AsNameExpr();
    if ( v->GetType()->Tag() != TYPE_VECTOR )
        return false;

    const auto& elt_type = v->GetType()->Yield();

    if ( args.size() == 1 ) {
        if ( ! IsIntegral(elt_type->Tag()) && elt_type->InternalType() != TYPE_INTERNAL_DOUBLE )
            return false;

        return OptAssignZBI::Build(zam, n, args);
    }

    const auto& comp_val = args[1];
    if ( ! IsFunc(comp_val->GetType()->Tag()) )
        return false;

    if ( comp_val->Tag() != EXPR_NAME )
        return false;

    auto comp_func = comp_val->AsNameExpr();
    auto comp_type = comp_func->GetType()->AsFuncType();

    if ( comp_type->Yield()->Tag() != TYPE_INT || ! comp_type->ParamList()->AllMatch(elt_type, 0) ||
         comp_type->ParamList()->GetTypes().size() != 2 )
        return false;

    ZInstI z;

    if ( n )
        z = ZInstI(OP_SORT_WITH_CMP_VVV, zam->Frame1Slot(n, OP1_WRITE), zam->FrameSlot(v), zam->FrameSlot(comp_func));
    else
        z = ZInstI(OP_SORT_WITH_CMP_VV, zam->FrameSlot(v), zam->FrameSlot(comp_func));

    zam->AddInst(z);

    return true;
}

bool LogWriteZBI::Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const {
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

    zam->AddInst(z);

    return true;
}

MultiZBI::MultiZBI(std::string name, bool _ret_val_matters, BiFArgsInfo _args_info, int _type_arg)
    : ZAMBuiltIn(std::move(name), _ret_val_matters), args_info(std::move(_args_info)), type_arg(_type_arg) {}

MultiZBI::MultiZBI(std::string name, BiFArgsInfo _args_info, BiFArgsInfo _assign_args_info, int _type_arg)
    : MultiZBI(std::move(name), false, _args_info, _type_arg) {
    assign_args_info = std::move(_assign_args_info);
    have_both = true;
}

bool MultiZBI::Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const {
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

            default: reporter->InternalError("inconsistency in MultiZBI::Build");
        }
    }

    else
        reporter->InternalError("inconsistency in MultiZBI::Build");

    z.op_type = bi.op_type;

    if ( n )
        z.is_managed = ZVal::IsManagedType(n->GetType());

    if ( ! consts.empty() ) {
        z.t = consts[0]->GetType();
        z.c = ZVal(consts[0], z.t);
    }

    if ( type_arg >= 0 && ! z.t )
        z.t = args[type_arg]->GetType();

    zam->AddInst(z);

    return true;
}

BiFArgsType MultiZBI::ComputeArgsType(const ExprPList& args) const {
    zeek_uint_t mask = 0;

    for ( auto i = 0U; i < args.size(); ++i ) {
        mask <<= 1;
        if ( args[i]->Tag() == EXPR_CONST )
            mask |= 1;
    }

    return BiFArgsType(mask);
}

SimpleZBI an_ZBI{"Analyzer::__name", OP_ANALYZER_NAME_VC, OP_ANALYZER_NAME_VV};
SimpleZBI ae_ZBI{"Files::__analyzer_enabled", OP_ANALYZER_ENABLED_VC, OP_ANALYZER_ENABLED_VV};
SimpleZBI fan_ZBI{"Files::__analyzer_name", OP_FILE_ANALYZER_NAME_VC, OP_FILE_ANALYZER_NAME_VV};
SimpleZBI fer_ZBI{"Files::__enable_reassembly", OP_FILES_ENABLE_REASSEMBLY_V, 1, false};
SimpleZBI ct_ZBI{"clear_table", OP_CLEAR_TABLE_V, 1, false};
SimpleZBI currt_ZBI_BIF{"current_time", OP_CURRENT_TIME_V, 0};
SimpleZBI gptp_ZBI{"get_port_transport_proto", OP_GET_PORT_TRANSPORT_PROTO_VV, 1};
SimpleZBI ipa_ZBI{"is_protocol_analyzer", OP_IS_PROTOCOL_ANALYZER_VC, OP_IS_PROTOCOL_ANALYZER_VV, true};
SimpleZBI lc_ZBI{"lookup_connection", OP_LOOKUP_CONN_VV, 1};
SimpleZBI nt_ZBI{"network_time", OP_NETWORK_TIME_V, 0};
SimpleZBI sfh_ZBI{"set_file_handle", OP_SET_FILE_HANDLE_V, 1, false};
SimpleZBI sta_ZBI{"subnet_to_addr", OP_SUBNET_TO_ADDR_VV, 1};
SimpleZBI ttd_ZBI{"time_to_double", OP_TIME_TO_DOUBLE_VV, 1};
SimpleZBI tl_ZBI{"to_lower", OP_TO_LOWER_VV, 1};

CondZBI ce_ZBI{"connection_exists", OP_CONN_EXISTS_VV, OP_CONN_EXISTS_COND_VV, 1};
CondZBI iip_ZBI{"is_icmp_port", OP_IS_ICMP_PORT_VV, OP_IS_ICMP_PORT_COND_VV, 1};
CondZBI itp_ZBI{"is_tcp_port", OP_IS_TCP_PORT_VV, OP_IS_TCP_PORT_COND_VV, 1};
CondZBI iup_ZBI{"is_udp_port", OP_IS_UDP_PORT_VV, OP_IS_UDP_PORT_COND_VV, 1};
CondZBI iv4_ZBI{"is_v4_addr", OP_IS_V4_ADDR_VV, OP_IS_V4_ADDR_COND_VV, 1};
CondZBI iv6_ZBI{"is_v6_addr", OP_IS_V6_ADDR_VV, OP_IS_V6_ADDR_COND_VV, 1};
CondZBI rlt_ZBI{"reading_live_traffic", OP_READING_LIVE_TRAFFIC_V, OP_READING_LIVE_TRAFFIC_COND_V, 0};
CondZBI rt_ZBI{"reading_traces", OP_READING_TRACES_V, OP_READING_TRACES_COND_V, 0};

LogWriteZBI lw1_ZBI("Log::write");
LogWriteZBI lw2_ZBI("Log::__write");

auto cat_ZBI = CatZBI();
auto sort_ZBI = SortZBI();

// For the following, clang-format makes them hard to follow compared to
// a manual layout.
//
// clang-format off

OptAssignZBI bfl_ZBI{ "Broker::__flush_logs",
    OP_BROKER_FLUSH_LOGS_V, OP_BROKER_FLUSH_LOGS_X,
    0
};

OptAssignZBI rgc_ZBI{ "PacketAnalyzer::GTPV1::remove_gtpv1_connection",
    OP_REMOVE_GTPV1_VV, OP_REMOVE_GTPV1_V,
    1
};
OptAssignZBI rtc_ZBI{ "PacketAnalyzer::TEREDO::remove_teredo_connection",
    OP_REMOVE_TEREDO_VV, OP_REMOVE_TEREDO_V,
    1
};

MultiZBI faa_ZBI{ "Files::__add_analyzer",
    {{{VVV}, {OP_FILES_ADD_ANALYZER_VVV, OP_VVV}},
     {{VCV}, {OP_FILES_ADD_ANALYZER_ViV, OP_VVC}}},
    {{{VVV}, {OP_FILES_ADD_ANALYZER_VVVV, OP_VVVV}},
     {{VCV}, {OP_FILES_ADD_ANALYZER_VViV, OP_VVVC}}},
    1
};

MultiZBI fra_ZBI{ "Files::__remove_analyzer",
    {{{VVV}, {OP_FILES_REMOVE_ANALYZER_VVV, OP_VVV}},
     {{VCV}, {OP_FILES_REMOVE_ANALYZER_ViV, OP_VVC}}},
    {{{VVV}, {OP_FILES_REMOVE_ANALYZER_VVVV, OP_VVVV}},
     {{VCV}, {OP_FILES_REMOVE_ANALYZER_VViV, OP_VVVC}}},
    1
};

MultiZBI fsrb_ZBI{ "Files::__set_reassembly_buffer",
    {{{VV}, {OP_FILES_SET_REASSEMBLY_BUFFER_VV, OP_VV}},
     {{VC}, {OP_FILES_SET_REASSEMBLY_BUFFER_VC, OP_VV_I2}}},
    {{{VV}, {OP_FILES_SET_REASSEMBLY_BUFFER_VVV, OP_VVV}},
     {{VC}, {OP_FILES_SET_REASSEMBLY_BUFFER_VVC, OP_VVV_I3}}}
};

MultiZBI gccbt_ZBI{ "get_current_conn_bytes_threshold", true,
    {{{VV}, {OP_GET_BYTES_THRESH_VVV, OP_VVV}},
     {{VC}, {OP_GET_BYTES_THRESH_VVi, OP_VVC}}}
};

MultiZBI sccbt_ZBI{ "set_current_conn_bytes_threshold",
    {{{VVV}, {OP_SET_BYTES_THRESH_VVV, OP_VVV}},
     {{VVC}, {OP_SET_BYTES_THRESH_VVi, OP_VVC}},
     {{VCV}, {OP_SET_BYTES_THRESH_ViV, OP_VVC}},
     {{VCC}, {OP_SET_BYTES_THRESH_Vii, OP_VVC_I2}}},
    {{{VVV}, {OP_SET_BYTES_THRESH_VVVV, OP_VVVV}},
     {{VVC}, {OP_SET_BYTES_THRESH_VVVi, OP_VVVC}},
     {{VCV}, {OP_SET_BYTES_THRESH_VViV, OP_VVVC}},
     {{VCC}, {OP_SET_BYTES_THRESH_VVii, OP_VVVC_I3}}}
};

MultiZBI sw_ZBI{ "starts_with", true,
    {{{VV}, {OP_STARTS_WITH_VVV, OP_VVV}},
     {{VC}, {OP_STARTS_WITH_VVC, OP_VVC}},
     {{CV}, {OP_STARTS_WITH_VCV, OP_VVC}}}
};

MultiZBI strcmp_ZBI{ "strcmp", true,
    {{{VV}, {OP_STRCMP_VVV, OP_VVV}},
     {{VC}, {OP_STRCMP_VVC, OP_VVC}},
     {{CV}, {OP_STRCMP_VCV, OP_VVC}}}
};

MultiZBI strstr_ZBI{ "strstr", true,
    {{{VV}, {OP_STRSTR_VVV, OP_VVV}},
     {{VC}, {OP_STRSTR_VVC, OP_VVC}},
     {{CV}, {OP_STRSTR_VCV, OP_VVC}}}
};

MultiZBI sb_ZBI{ "sub_bytes", true,
    {{{VVV}, {OP_SUB_BYTES_VVVV, OP_VVVV}},
     {{VVC}, {OP_SUB_BYTES_VVVi, OP_VVVC}},
     {{VCV}, {OP_SUB_BYTES_VViV, OP_VVVC}},
     {{VCC}, {OP_SUB_BYTES_VVii, OP_VVVC_I3}},
     {{CVV}, {OP_SUB_BYTES_VVVC, OP_VVVC}},
     {{CVC}, {OP_SUB_BYTES_VViC, OP_VVVC_I3}},
     {{CCV}, {OP_SUB_BYTES_ViVC, OP_VVVC_I3}}}
};

// clang-format on

static const Func* get_func(const CallExpr* c) {
    auto func_expr = c->Func();
    if ( func_expr->Tag() != EXPR_NAME )
        // An indirect call.
        return nullptr;

    auto func_val = func_expr->AsNameExpr()->Id()->GetVal();
    if ( ! func_val )
        // A call to a function that hasn't been defined.
        return nullptr;

    return func_val->AsFunc();
}

bool IsZAM_BuiltIn(ZAMCompiler* zam, const Expr* e) {
    // The expression e is either directly a call (in which case there's
    // no return value), or an assignment to a call.
    const CallExpr* c;

    if ( e->Tag() == EXPR_CALL )
        c = e->AsCallExpr();
    else
        c = e->GetOp2()->AsCallExpr();

    auto func = get_func(c);
    if ( ! func )
        return false;

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

    return bi->Build(zam, n, c->Args()->Exprs());
}

bool IsZAM_BuiltInCond(ZAMCompiler* zam, const CallExpr* c, int& branch_v) {
    auto func = get_func(c);
    if ( ! func )
        return false;

    auto b = builtins.find(func->Name());
    if ( b == builtins.end() )
        return false;

    return b->second->BuildCond(zam, c->Args()->Exprs(), branch_v);
}

bool IsZAM_BuiltInCond(const CallExpr* c) {
    int branch_v; // ignored
    return IsZAM_BuiltInCond(nullptr, c, branch_v);
}

} // namespace zeek::detail
