// See the file "COPYING" in the main distribution directory for copyright.

// ZAM methods associated with instructions that replace built-in functions.

#include "ZAM.h"
#include "ZGen.h"
#include "Reporter.h"


bool ZAM::IsZAM_BuiltIn(const Expr* e)
	{
	// The expression is either directly a call (in which case there's
	// no return value), or an assignment to a call.
	const CallExpr* c;

	if ( e->Tag() == EXPR_CALL )
		c = e->AsCallExpr();
	else
		c = e->GetOp2()->AsCallExpr();

	auto func_expr = c->Func();
	if ( func_expr->Tag() != EXPR_NAME )
		return false;

	auto func_val = func_expr->AsNameExpr()->Id()->ID_Val();
	if ( ! func_val )
		return false;

	auto func = func_val->AsFunc();
	if ( func->GetKind() != BuiltinFunc::BUILTIN_FUNC )
		return false;

	auto& args = c->Args()->Exprs();

	const NameExpr* n;	// name to assign to, if any

	if ( e->Tag() == EXPR_CALL )
		n = nullptr;
	else
		n = e->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();

	if ( streq(func->Name(), "sub_bytes") )
		return BuiltIn_sub_bytes(n, args);

	else if ( streq(func->Name(), "to_lower") )
		return BuiltIn_to_lower(n, args);

	else if ( streq(func->Name(), "Log::__write") )
		return BuiltIn_Log__write(n, args);

	else if ( streq(func->Name(), "Broker::__flush_logs") )
		return BuiltIn_Broker__flush_logs(n, args);

	else if ( streq(func->Name(), "get_port_transport_proto") )
		return BuiltIn_get_port_etc(n, args);

	else if ( streq(func->Name(), "network_time") )
		return BuiltIn_network_time(n, args);

	else if ( streq(func->Name(), "current_time") )
		return BuiltIn_current_time(n, args);

	else if ( streq(func->Name(), "reading_live_traffic") )
		return BuiltIn_reading_live_traffic(n, args);

	else if ( streq(func->Name(), "reading_traces") )
		return BuiltIn_reading_traces(n, args);

	else if ( streq(func->Name(), "strstr") )
		return BuiltIn_strstr(n, args);

	else if ( streq(func->Name(), "Analyzer::__name") )
		return BuiltIn_Analyzer__name(n, args);

	else if ( streq(func->Name(), "Files::__enable_reassembly") )
		return BuiltIn_Files__enable_reassembly(n, args);

	else if ( streq(func->Name(), "Files::__set_reassembly_buffer") )
		return BuiltIn_Files__set_reassembly_buffer(n, args);

	return false;
	}

bool ZAM::BuiltIn_to_lower(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	if ( args[0]->Tag() == EXPR_CONST )
		{
		auto arg_c = args[0]->AsConstExpr()->Value()->AsStringVal();
		IntrusivePtr<Val> arg_lc = {AdoptRef{}, ZAM_to_lower(arg_c)};
		auto arg_lce = make_intrusive<ConstExpr>(arg_lc);
		auto z = ZInstI(OP_ASSIGN_CONST_VC, nslot, arg_lce.get());
		z.is_managed = true;
		AddInst(z);
		}

	else
		{
		auto arg_s = args[0]->AsNameExpr();

		AddInst(ZInstI(OP_TO_LOWER_VV, nslot, FrameSlot(arg_s)));
		}

	return true;
	}

bool ZAM::BuiltIn_sub_bytes(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto arg_s = args[0];
	auto arg_start = args[1];
	auto arg_n = args[2];

	int nslot = Frame1Slot(n, OP1_WRITE);

	int v2 = FrameSlotIfName(arg_s);
	int v3 = ConvertToCount(arg_start);
	int v4 = ConvertToInt(arg_n);

	auto c = arg_s->Tag() == EXPR_CONST ? arg_s->AsConstExpr() : nullptr;

	ZInstI z;

	switch ( ConstArgsMask(args, 3) ) {
	case 0x0:	// all variable
		z = ZInstI(OP_SUB_BYTES_VVVV, nslot, v2, v3, v4);
		z.op_type = OP_VVVV;
		break;

	case 0x1:	// last argument a constant
		z = ZInstI(OP_SUB_BYTES_VVVi, nslot, v2, v3, v4);
		z.op_type = OP_VVVV_I4;
		break;

	case 0x2:	// 2nd argument a constant; flip!
		z = ZInstI(OP_SUB_BYTES_VViV, nslot, v2, v4, v3);
		z.op_type = OP_VVVV_I4;
		break;

	case 0x3:	// both 2nd and third are constants
		z = ZInstI(OP_SUB_BYTES_VVii, nslot, v2, v3, v4);
		z.op_type = OP_VVVV_I3_I4;
		break;

	case 0x4:	// first argument a constant
		z = ZInstI(OP_SUB_BYTES_VVVC, nslot, v3, v4, c);
		z.op_type = OP_VVVC;
		break;

	case 0x5:	// first and third constant
		z = ZInstI(OP_SUB_BYTES_VViC, nslot, v3, v4, c);
		z.op_type = OP_VVVC_I3;
		break;

	case 0x6:	// first and second constant - flip!
		z = ZInstI(OP_SUB_BYTES_ViVC, nslot, v4, v3, c);
		z.op_type = OP_VVVC_I3;
		break;

	case 0x7:	// whole shebang
		z = ZInstI(OP_SUB_BYTES_ViiC, nslot, v3, v4, c);
		z.op_type = OP_VVVC_I2_I3;
		break;

	default:
		reporter->InternalError("bad constant mask");
	}

	AddInst(z);

	return true;
	}

bool ZAM::BuiltIn_Log__write(const NameExpr* n, const expr_list& args)
	{
	auto id = args[0];
	auto columns = args[1];

	if ( columns->Tag() != EXPR_NAME )
		return false;

	auto columns_n = columns->AsNameExpr();
	auto col_slot = FrameSlot(columns_n);

	bool const_id = (id->Tag() == EXPR_CONST);

	ZInstAux* aux = nullptr;

	if ( const_id )
		{
		aux = new ZInstAux(1);
		aux->Add(0, id->AsConstExpr()->ValuePtr());
		}

	ZInstI z;

	if ( n )
		{
		int nslot = Frame1Slot(n, OP1_WRITE);
		if ( const_id )
			{
			z = ZInstI(OP_LOG_WRITEC_VV, nslot, col_slot);
			z.aux = aux;
			}
		else
			z = ZInstI(OP_LOG_WRITE_VVV, nslot,
					FrameSlot(id->AsNameExpr()), col_slot);
		}
	else
		{
		if ( const_id )
			{
			z = ZInstI(OP_LOG_WRITEC_V, col_slot, id->AsConstExpr());
			z.aux = aux;
			}
		else
			z = ZInstI(OP_LOG_WRITE_VV, FrameSlot(id->AsNameExpr()),
					col_slot);
		}

	z.SetType(columns_n->Type());

	AddInst(z);

	return true;
	}

bool ZAM::BuiltIn_Broker__flush_logs(const NameExpr* n, const expr_list& args)
	{
	if ( n )
		AddInst(ZInstI(OP_BROKER_FLUSH_LOGS_V,
				Frame1Slot(n, OP1_WRITE)));
	else
		AddInst(ZInstI(OP_BROKER_FLUSH_LOGS_X));

	return true;
	}

bool ZAM::BuiltIn_get_port_etc(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto p = args[0];

	if ( p->Tag() != EXPR_NAME )
		return false;

	auto pn = p->AsNameExpr();
	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_GET_PORT_TRANSPORT_PROTO_VV, nslot, FrameSlot(pn)));

	return true;
	}

bool ZAM::BuiltIn_network_time(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_NETWORK_TIME_V, nslot));

	return true;
	}

bool ZAM::BuiltIn_current_time(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_CURRENT_TIME_V, nslot));

	return true;
	}

bool ZAM::BuiltIn_reading_live_traffic(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_READING_LIVE_TRAFFIC_V, nslot));

	return true;
	}

bool ZAM::BuiltIn_reading_traces(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	int nslot = Frame1Slot(n, OP1_WRITE);

	AddInst(ZInstI(OP_READING_TRACES_V, nslot));

	return true;
	}

bool ZAM::BuiltIn_strstr(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto big = args[0];
	auto little = args[1];

	auto big_n = big->Tag() == EXPR_NAME ? big->AsNameExpr() : nullptr;
	auto little_n =
		little->Tag() == EXPR_NAME ? little->AsNameExpr() : nullptr;

	ZInstI z;

	if ( big_n && little_n )
		z = GenInst(this, OP_STRSTR_VVV, n, big_n, little_n);
	else if ( big_n )
		z = GenInst(this, OP_STRSTR_VVC, n, big_n, little->AsConstExpr());
	else if ( little_n )
		z = GenInst(this, OP_STRSTR_VCV, n, little_n, big->AsConstExpr());
	else
		return false;

	AddInst(z);

	return true;
	}

bool ZAM::BuiltIn_Analyzer__name(const NameExpr* n, const expr_list& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	if ( args[0]->Tag() == EXPR_CONST )
		// Doesn't seem worth developing a variant for this weird
		// usage cast.
		return false;

	int nslot = Frame1Slot(n, OP1_WRITE);
	auto arg_t = args[0]->AsNameExpr();

	auto z = ZInstI(OP_ANALYZER__NAME_VV, nslot, FrameSlot(arg_t));
	z.SetType(args[0]->Type());

	AddInst(z);

	return true;
	}

bool ZAM::BuiltIn_Files__enable_reassembly(const NameExpr* n,
						const expr_list& args)
	{
	if ( n )
		// While this built-in nominally returns a value, existing
		// script code ignores it, so for now we don't bother
		// special-casing the possibility that it doesn't.
		return false;

	if ( args[0]->Tag() == EXPR_CONST )
		// Weird!
		return false;

	auto arg_f = args[0]->AsNameExpr();

	AddInst(ZInstI(OP_FILES__ENABLE_REASSEMBLY_V, FrameSlot(arg_f)));

	return true;
	}

bool ZAM::BuiltIn_Files__set_reassembly_buffer(const NameExpr* n,
						const expr_list& args)
	{
	if ( n )
		// See above for enable_reassembly
		return false;

	if ( args[0]->Tag() == EXPR_CONST )
		// Weird!
		return false;

	auto arg_f = FrameSlot(args[0]->AsNameExpr());

	ZInstI z;

	if ( args[1]->Tag() == EXPR_CONST )
		{
		auto arg_cnt = args[1]->AsConstExpr()->Value()->ForceAsUInt();
		z = ZInstI(OP_FILES__SET_REASSEMBLY_BUFFER_VC, arg_f, arg_cnt);
		z.op_type = OP_VV_I2;
		}
	else
		z = ZInstI(OP_FILES__SET_REASSEMBLY_BUFFER_VV, arg_f,
				FrameSlot(args[1]->AsNameExpr()));

	AddInst(z);

	return true;
	}
