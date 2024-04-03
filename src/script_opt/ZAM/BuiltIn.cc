// See the file "COPYING" in the main distribution directory for copyright.

// ZAM methods associated with instructions that replace calls to
// built-in functions.

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

class ZAMBuiltIn;
std::map<std::string, const ZAMBuiltIn*> new_builtins;

class ZAMBuiltIn {
public:
    ZAMBuiltIn(bool _ret_val_matters) : ret_val_matters(_ret_val_matters) {}
    ZAMBuiltIn(std::string name, bool _ret_val_matters) :
	ret_val_matters(_ret_val_matters)
	{
	new_builtins[name] = this;
	}

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
    DirectBuiltIn(ZOp _op, int _nargs, bool _ret_val_matters = true, TypeTag _arg_type = TYPE_VOID)
        : ZAMBuiltIn(_ret_val_matters), op(_op), nargs(_nargs), arg_type(_arg_type) {}

    DirectBuiltIn(std::string name, ZOp _op, int _nargs, bool _ret_val_matters = true, TypeTag _arg_type = TYPE_VOID)
        : ZAMBuiltIn(std::move(name), _ret_val_matters), op(_op), nargs(_nargs), arg_type(_arg_type) {}

    DirectBuiltIn(ZOp _const_op, ZOp _op, int _nargs, bool _ret_val_matters = true, TypeTag _arg_type = TYPE_VOID)
        : ZAMBuiltIn(_ret_val_matters), op(_op), const_op(_const_op), nargs(_nargs), arg_type(_arg_type) {}

    DirectBuiltIn(std::string name, ZOp _const_op, ZOp _op, int _nargs, bool _ret_val_matters = true, TypeTag _arg_type = TYPE_VOID)
        : ZAMBuiltIn(std::move(name), _ret_val_matters), op(_op), const_op(_const_op), nargs(_nargs), arg_type(_arg_type) {}

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
            auto& t = args[0]->GetType();

            if ( arg_type != TYPE_VOID && t->Tag() != arg_type )
                return false;

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

protected:
    ZOp op;
    ZOp const_op = OP_NOP;
    int nargs;
    TypeTag arg_type;
};

class DirectBuiltInOptAssign : public DirectBuiltIn {
public:
    // First argument is assignment flavor, second is assignment-less flavor.
    DirectBuiltInOptAssign(ZOp _op, ZOp _op2, int _nargs) : DirectBuiltIn(_op, _nargs, false), op2(_op2) {
        have_both = true;
    }

    DirectBuiltInOptAssign(std::string(name), ZOp _op, ZOp _op2, int _nargs) : DirectBuiltIn(std::move(name), _op, _nargs, false), op2(_op2) {
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
            z = ZInstI(op2, a0);
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
    MultiArgBuiltIn(bool _ret_val_matters, BifArgsInfo _args_info, int _type_arg = -1)
        : ZAMBuiltIn(_ret_val_matters), args_info(std::move(_args_info)), type_arg(_type_arg) {}

    MultiArgBuiltIn(std::string name, bool _ret_val_matters, BifArgsInfo _args_info, int _type_arg = -1)
        : ZAMBuiltIn(std::move(name), _ret_val_matters), args_info(std::move(_args_info)), type_arg(_type_arg) {}

    MultiArgBuiltIn(BifArgsInfo _args_info, BifArgsInfo _assign_args_info, int _type_arg = -1)
        : MultiArgBuiltIn(false, _args_info, _type_arg) {
        assign_args_info = std::move(_assign_args_info);
        have_both = true;
    }

    MultiArgBuiltIn(std::string name, BifArgsInfo _args_info, BifArgsInfo _assign_args_info, int _type_arg = -1)
        : MultiArgBuiltIn(std::move(name), false, _args_info, _type_arg) {
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

private:
    // Returns a bit mask of which of the arguments in the given list
    // correspond to constants, with the high-ordered bit being the first
    // argument (argument "0" in the list) and the low-ordered bit being
    // the last. These correspond to the ArgsType enum integer values.
    ArgsType ComputeArgsType(const ExprPList& args) const {
        zeek_uint_t mask = 0;

        for ( auto i = 0U; i < args.size(); ++i ) {
            mask <<= 1;
            if ( args[i]->Tag() == EXPR_CONST )
                mask |= 1;
        }

        return ArgsType(mask);
    }

    BifArgsInfo args_info;
    BifArgsInfo assign_args_info;
    int type_arg;
};

class SortBiF : public DirectBuiltInOptAssign {
public:
    SortBiF() : DirectBuiltInOptAssign("sort", OP_SORT_V, OP_SORT_VV, 1) {}

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

            return DirectBuiltInOptAssign::Build(zam, n, args);
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
            z = ZInstI(OP_SORT_WITH_CMP_VVV, zam->Frame1Slot(n, OP1_WRITE), zam->FrameSlot(v),
                       zam->FrameSlot(comp_func));
        else
            z = ZInstI(OP_SORT_WITH_CMP_VV, zam->FrameSlot(v), zam->FrameSlot(comp_func));

        zam->AddInst(z);

        return true;
    }
};

class CatBiF : public ZAMBuiltIn {
public:
    CatBiF() : ZAMBuiltIn("cat", true) {}

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
    LogWriteBiF() : ZAMBuiltIn(false) { have_both = true; }
    LogWriteBiF(std::string name) : ZAMBuiltIn(std::move(name), false) { have_both = true; }

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

        zam->AddInst(z);

        return true;
    }
};

// clang-format off

DirectBuiltIn analyzer_name_BIF{
    "Analyzer::__name", OP_ANALYZER_NAME_VC, OP_ANALYZER_NAME_VV, 1
};

DirectBuiltInOptAssign broker_flush_logs_BIF{
    "Broker::__flush_logs", OP_BROKER_FLUSH_LOGS_V, OP_BROKER_FLUSH_LOGS_X, 0
};

MultiArgBuiltIn files_add_analyzer_BIF{
    "Files::__add_analyzer",

    {{{VVV}, {OP_FILES_ADD_ANALYZER_VVV, OP_VVV}},
     {{VCV}, {OP_FILES_ADD_ANALYZER_ViV, OP_VVC}}},

    {{{VVV}, {OP_FILES_ADD_ANALYZER_VVVV, OP_VVVV}},
     {{VCV}, {OP_FILES_ADD_ANALYZER_VViV, OP_VVVC}}},

    1
};

MultiArgBuiltIn files_remove_analyzer_BIF{
    "Files::__remove_analyzer",

    {{{VVV}, {OP_FILES_REMOVE_ANALYZER_VVV, OP_VVV}},
     {{VCV}, {OP_FILES_REMOVE_ANALYZER_ViV, OP_VVC}}},

    {{{VVV}, {OP_FILES_REMOVE_ANALYZER_VVVV, OP_VVVV}},
     {{VCV}, {OP_FILES_REMOVE_ANALYZER_VViV, OP_VVVC}}},

    1
};

DirectBuiltIn analyzer_enabled_BIF{"Files::__analyzer_enabled", OP_ANALYZER_ENABLED_VC, OP_ANALYZER_ENABLED_VV, 1};

DirectBuiltIn file_analyzer_name_BIF{ "Files::__analyzer_name", OP_FILE_ANALYZER_NAME_VC, OP_FILE_ANALYZER_NAME_VV, 1 };

DirectBuiltIn files_enable_reassembly_BIF{"Files::__enable_reassembly", OP_FILES_ENABLE_REASSEMBLY_V, 1, false};

MultiArgBuiltIn files_set_reassem_buf_BIF{
    "Files::__set_reassembly_buffer",

    {{{VV}, {OP_FILES_SET_REASSEMBLY_BUFFER_VV, OP_VV}},
     {{VC}, {OP_FILES_SET_REASSEMBLY_BUFFER_VC, OP_VV_I2}}},

    {{{VV}, {OP_FILES_SET_REASSEMBLY_BUFFER_VVV, OP_VVV}},
     {{VC}, {OP_FILES_SET_REASSEMBLY_BUFFER_VVC, OP_VVV_I3}}}
};

LogWriteBiF log_write_BIF("Log::write");
LogWriteBiF log___write_BIF("Log::__write");

CatBiF cat_BIF();

DirectBuiltIn clear_table_BIF{"clear_table", OP_CLEAR_TABLE_V, 1, false};

DirectBuiltIn connection_exists_BIF{"connection_exists", OP_CONN_EXISTS_VV, 1};

DirectBuiltIn current_time_BIF{"current_time", OP_CURRENT_TIME_V, 0};

MultiArgBuiltIn get_bytes_thresh_BIF{
    "get_current_conn_bytes_threshold",
    true,
    {{{VV}, {OP_GET_BYTES_THRESH_VVV, OP_VVV}},
     {{VC}, {OP_GET_BYTES_THRESH_VVi, OP_VVC}}}
};

DirectBuiltIn get_port_transport_proto_BIF{"get_port_transport_proto", OP_GET_PORT_TRANSPORT_PROTO_VV, 1};

DirectBuiltIn is_icmp_port_BIF{"is_icmp_port", OP_IS_ICMP_PORT_VV, 1};
DirectBuiltIn is_protocol_analyzer_BIF{"is_protocol_analyzer", OP_IS_PROTOCOL_ANALYZER_VC, OP_IS_PROTOCOL_ANALYZER_VV, 1 };
DirectBuiltIn is_tcp_port_BIF{"is_tcp_port", OP_IS_TCP_PORT_VV, 1};
DirectBuiltIn is_udp_port_BIF{"is_udp_port", OP_IS_UDP_PORT_VV, 1};
DirectBuiltIn is_v4_addr_BIF{"is_v4_addr", OP_IS_V4_ADDR_VV, 1};
DirectBuiltIn is_v6_addr_BIF{"is_v6_addr", OP_IS_V6_ADDR_VV, 1};
DirectBuiltIn lookup_connection_BIF{"lookup_connection", OP_LOOKUP_CONN_VV, 1};
DirectBuiltIn network_time_BIF{"network_time", OP_NETWORK_TIME_V, 0};
DirectBuiltIn reading_live_traffic_BIF{"reading_live_traffic", OP_READING_LIVE_TRAFFIC_V, 0};
DirectBuiltIn reading_traces_BIF{"reading_traces", OP_READING_TRACES_V, 0};

DirectBuiltInOptAssign remove_gtpv1_BIF{"PacketAnalyzer::GTPV1::remove_gtpv1_connection", OP_REMOVE_GTPV1_VV, OP_REMOVE_GTPV1_V, 1};
DirectBuiltInOptAssign remove_teredo_BIF{"PacketAnalyzer::TEREDO::remove_teredo_connection", OP_REMOVE_TEREDO_VV, OP_REMOVE_TEREDO_V, 1};

MultiArgBuiltIn set_bytes_thresh_BIF{
    "set_current_conn_bytes_threshold",

    {{{VVV}, {OP_SET_BYTES_THRESH_VVV, OP_VVV}},
     {{VVC}, {OP_SET_BYTES_THRESH_VVi, OP_VVC}},
     {{VCV}, {OP_SET_BYTES_THRESH_ViV, OP_VVC}},
     {{VCC}, {OP_SET_BYTES_THRESH_Vii, OP_VVC_I2}}},

    {{{VVV}, {OP_SET_BYTES_THRESH_VVVV, OP_VVVV}},
     {{VVC}, {OP_SET_BYTES_THRESH_VVVi, OP_VVVC}},
     {{VCV}, {OP_SET_BYTES_THRESH_VViV, OP_VVVC}},
     {{VCC}, {OP_SET_BYTES_THRESH_VVii, OP_VVVC_I3}}}
};

DirectBuiltIn set_file_handle_BIF{"set_file_handle", OP_SET_FILE_HANDLE_V, 1, false};

SortBiF sort_BIF();

MultiArgBuiltIn starts_with_BIF{
    "starts_with",
    true,
    {{{VV}, {OP_STARTS_WITH_VVV, OP_VVV}},
     {{VC}, {OP_STARTS_WITH_VVC, OP_VVC}},
     {{CV}, {OP_STARTS_WITH_VCV, OP_VVC}}}
};

MultiArgBuiltIn strcmp_BIF{
    "strcmp",
    true,
    {{{VV}, {OP_STRCMP_VVV, OP_VVV}},
     {{VC}, {OP_STRCMP_VVC, OP_VVC}},
     {{CV}, {OP_STRCMP_VCV, OP_VVC}}}
};

MultiArgBuiltIn strstr_BIF{
    "strstr",
    true,
    {{{VV}, {OP_STRSTR_VVV, OP_VVV}},
     {{VC}, {OP_STRSTR_VVC, OP_VVC}},
     {{CV}, {OP_STRSTR_VCV, OP_VVC}}}
};

MultiArgBuiltIn sub_bytes_BIF{
    "sub_bytes",
    true,
    {{{VVV}, {OP_SUB_BYTES_VVVV, OP_VVVV}},
     {{VVC}, {OP_SUB_BYTES_VVVi, OP_VVVC}},
     {{VCV}, {OP_SUB_BYTES_VViV, OP_VVVC}},
     {{VCC}, {OP_SUB_BYTES_VVii, OP_VVVC_I3}},
     {{CVV}, {OP_SUB_BYTES_VVVC, OP_VVVC}},
     {{CVC}, {OP_SUB_BYTES_VViC, OP_VVVC_I3}},
     {{CCV}, {OP_SUB_BYTES_ViVC, OP_VVVC_I3}}}
};

DirectBuiltIn subnet_to_addr_BIF{"subnet_to_addr", OP_SUBNET_TO_ADDR_VV, 1};
DirectBuiltIn time_to_double_BIF{"time_to_double", OP_TIME_TO_DOUBLE_VV, 1};
DirectBuiltIn to_lower_BIF{"to_lower", OP_TO_LOWER_VV, 1};

// clang-format on

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

    static BifArgsInfo files_add_analyzer_info, files_add_analyzer_assign_info;
    static BifArgsInfo files_remove_analyzer_info, files_remove_analyzer_assign_info;
    static BifArgsInfo get_bytes_thresh_info;
    static BifArgsInfo sub_bytes_info;
    static BifArgsInfo set_bytes_thresh_info, set_bytes_thresh_assign_info;
    static BifArgsInfo set_reassem_info, set_reassem_assign_info;
    static BifArgsInfo starts_with_info;
    static BifArgsInfo strcmp_info;
    static BifArgsInfo strstr_info;

    static bool did_init = false;
    if ( ! did_init ) {
        files_add_analyzer_info[VVV] = {OP_FILES_ADD_ANALYZER_VVV, OP_VVV};
        files_add_analyzer_info[VCV] = {OP_FILES_ADD_ANALYZER_ViV, OP_VVC};

        files_add_analyzer_assign_info[VVV] = {OP_FILES_ADD_ANALYZER_VVVV, OP_VVVV};
        files_add_analyzer_assign_info[VCV] = {OP_FILES_ADD_ANALYZER_VViV, OP_VVVC};

        files_remove_analyzer_info[VVV] = {OP_FILES_REMOVE_ANALYZER_VVV, OP_VVV};
        files_remove_analyzer_info[VCV] = {OP_FILES_REMOVE_ANALYZER_ViV, OP_VVC};

        files_remove_analyzer_assign_info[VVV] = {OP_FILES_REMOVE_ANALYZER_VVVV, OP_VVVV};
        files_remove_analyzer_assign_info[VCV] = {OP_FILES_REMOVE_ANALYZER_VViV, OP_VVVC};

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

        starts_with_info[VV] = {OP_STARTS_WITH_VVV, OP_VVV};
        starts_with_info[VC] = {OP_STARTS_WITH_VVC, OP_VVC};
        starts_with_info[CV] = {OP_STARTS_WITH_VCV, OP_VVC};

        strcmp_info[VV] = {OP_STRCMP_VVV, OP_VVV};
        strcmp_info[VC] = {OP_STRCMP_VVC, OP_VVC};
        strcmp_info[CV] = {OP_STRCMP_VCV, OP_VVC};

        strstr_info[VV] = {OP_STRSTR_VVV, OP_VVV};
        strstr_info[VC] = {OP_STRSTR_VVC, OP_VVC};
        strstr_info[CV] = {OP_STRSTR_VCV, OP_VVC};

        did_init = true;
    }

    static std::map<std::string, std::shared_ptr<ZAMBuiltIn>> builtins = {
        {"Analyzer::__name", std::make_shared<DirectBuiltIn>(OP_ANALYZER_NAME_VC, OP_ANALYZER_NAME_VV, 1)},
        {"Broker::__flush_logs",
         std::make_shared<DirectBuiltInOptAssign>(OP_BROKER_FLUSH_LOGS_V, OP_BROKER_FLUSH_LOGS_X, 0)},
        {"Files::__add_analyzer",
         std::make_shared<MultiArgBuiltIn>(files_add_analyzer_info, files_add_analyzer_assign_info, 1)},
        {"Files::__remove_analyzer",
         std::make_shared<MultiArgBuiltIn>(files_remove_analyzer_info, files_remove_analyzer_assign_info, 1)},
        {"Files::__analyzer_enabled",
         std::make_shared<DirectBuiltIn>(OP_ANALYZER_ENABLED_VC, OP_ANALYZER_ENABLED_VV, 1)},
        {"Files::__analyzer_name",
         std::make_shared<DirectBuiltIn>(OP_FILE_ANALYZER_NAME_VC, OP_FILE_ANALYZER_NAME_VV, 1)},
        {"Files::__enable_reassembly", std::make_shared<DirectBuiltIn>(OP_FILES_ENABLE_REASSEMBLY_V, 1, false)},
        {"Files::__set_reassembly_buffer",
         std::make_shared<MultiArgBuiltIn>(set_reassem_info, set_reassem_assign_info)},
        {"Log::write", std::make_shared<LogWriteBiF>()},
        {"Log::__write", std::make_shared<LogWriteBiF>()},
        {"cat", std::make_shared<CatBiF>()},
        {"clear_table", std::make_shared<DirectBuiltIn>(OP_CLEAR_TABLE_V, 1, false, TYPE_TABLE)},
        {"connection_exists", std::make_shared<DirectBuiltIn>(OP_CONN_EXISTS_VV, 1)},
        {"current_time", std::make_shared<DirectBuiltIn>(OP_CURRENT_TIME_V, 0)},
        {"get_current_conn_bytes_threshold", std::make_shared<MultiArgBuiltIn>(true, get_bytes_thresh_info)},
        {"get_port_transport_proto", std::make_shared<DirectBuiltIn>(OP_GET_PORT_TRANSPORT_PROTO_VV, 1)},
        {"is_icmp_port", std::make_shared<DirectBuiltIn>(OP_IS_ICMP_PORT_VV, 1)},
        {"is_protocol_analyzer",
         std::make_shared<DirectBuiltIn>(OP_IS_PROTOCOL_ANALYZER_VC, OP_IS_PROTOCOL_ANALYZER_VV, 1)},
        {"is_tcp_port", std::make_shared<DirectBuiltIn>(OP_IS_TCP_PORT_VV, 1)},
        {"is_udp_port", std::make_shared<DirectBuiltIn>(OP_IS_UDP_PORT_VV, 1)},
        {"is_v4_addr", std::make_shared<DirectBuiltIn>(OP_IS_V4_ADDR_VV, 1)},
        {"is_v6_addr", std::make_shared<DirectBuiltIn>(OP_IS_V6_ADDR_VV, 1)},
        {"lookup_connection", std::make_shared<DirectBuiltIn>(OP_LOOKUP_CONN_VV, 1)},
        {"network_time", std::make_shared<DirectBuiltIn>(OP_NETWORK_TIME_V, 0)},
        {"reading_live_traffic", std::make_shared<DirectBuiltIn>(OP_READING_LIVE_TRAFFIC_V, 0)},
        {"reading_traces", std::make_shared<DirectBuiltIn>(OP_READING_TRACES_V, 0)},
        {"PacketAnalyzer::GTPV1::remove_gtpv1_connection",
         std::make_shared<DirectBuiltInOptAssign>(OP_REMOVE_GTPV1_VV, OP_REMOVE_GTPV1_V, 1)},
        {"PacketAnalyzer::TEREDO::remove_teredo_connection",
         std::make_shared<DirectBuiltInOptAssign>(OP_REMOVE_TEREDO_VV, OP_REMOVE_TEREDO_V, 1)},
        {"set_current_conn_bytes_threshold",
         std::make_shared<MultiArgBuiltIn>(set_bytes_thresh_info, set_bytes_thresh_assign_info)},
        {"set_file_handle", std::make_shared<DirectBuiltIn>(OP_SET_FILE_HANDLE_V, 1, false)},
        {"sort", std::make_shared<SortBiF>()},
        {"starts_with", std::make_shared<MultiArgBuiltIn>(true, starts_with_info)},
        {"strcmp", std::make_shared<MultiArgBuiltIn>(true, strcmp_info)},
        {"strstr", std::make_shared<MultiArgBuiltIn>(true, strstr_info)},
        {"sub_bytes", std::make_shared<MultiArgBuiltIn>(true, sub_bytes_info)},
        {"subnet_to_addr", std::make_shared<DirectBuiltIn>(OP_SUBNET_TO_ADDR_VV, 1)},
        {"time_to_double", std::make_shared<DirectBuiltIn>(OP_TIME_TO_DOUBLE_VV, 1)},
        {"to_lower", std::make_shared<DirectBuiltIn>(OP_TO_LOWER_VV, 1)},
    };

    auto func = func_val->AsFunc();
#if 0
    auto b = builtins.find(func->Name());
    if ( b == builtins.end() )
        return false;
#else
    auto b = new_builtins.find(func->Name());
    if ( b == new_builtins.end() )
        return false;
#endif

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
