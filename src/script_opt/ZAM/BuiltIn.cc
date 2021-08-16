// See the file "COPYING" in the main distribution directory for copyright.

// ZAM methods associated with instructions that replace calls to
// built-in functions.

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

bool ZAMCompiler::IsZAM_BuiltIn(const Expr* e)
	{
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

	auto& args = c->Args()->Exprs();

	const NameExpr* n = nullptr;	// name to assign to, if any

	if ( e->Tag() != EXPR_CALL )
		n = e->GetOp1()->AsRefExpr()->GetOp1()->AsNameExpr();

	using GenBuiltIn = bool (ZAMCompiler::*)(const NameExpr* n,
	                                         const ExprPList& args);
	static std::vector<std::pair<const char*, GenBuiltIn>> builtins = {
		{ "Analyzer::__name", &ZAMCompiler::BuiltIn_Analyzer__name },
		{ "Broker::__flush_logs",
		  &ZAMCompiler::BuiltIn_Broker__flush_logs },
		{ "Files::__enable_reassembly",
		  &ZAMCompiler::BuiltIn_Files__enable_reassembly },
		{ "Files::__set_reassembly_buffer",
		  &ZAMCompiler::BuiltIn_Files__set_reassembly_buffer },
		{ "Log::__write", &ZAMCompiler::BuiltIn_Log__write },
		{ "current_time", &ZAMCompiler::BuiltIn_current_time },
		{ "get_port_transport_proto",
		  &ZAMCompiler::BuiltIn_get_port_etc },
		{ "network_time", &ZAMCompiler::BuiltIn_network_time },
		{ "reading_live_traffic",
		  &ZAMCompiler::BuiltIn_reading_live_traffic },
		{ "reading_traces", &ZAMCompiler::BuiltIn_reading_traces },
		{ "strstr", &ZAMCompiler::BuiltIn_strstr },
		{ "sub_bytes", &ZAMCompiler::BuiltIn_sub_bytes },
		{ "to_lower", &ZAMCompiler::BuiltIn_to_lower },
	};

	for ( auto& b : builtins )
		if ( util::streq(func->Name(), b.first) )
			return (this->*(b.second))(n ,args);

	return false;
	}


bool ZAMCompiler::BuiltIn_Analyzer__name(const NameExpr* n,
                                         const ExprPList& args)
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
	z.SetType(args[0]->GetType());

	AddInst(z);

	return true;
	}

bool ZAMCompiler::BuiltIn_Broker__flush_logs(const NameExpr* n,
                                             const ExprPList& args)
	{
	if ( n )
		AddInst(ZInstI(OP_BROKER_FLUSH_LOGS_V,
		               Frame1Slot(n, OP1_WRITE)));
	else
		AddInst(ZInstI(OP_BROKER_FLUSH_LOGS_X));

	return true;
	}

bool ZAMCompiler::BuiltIn_Files__enable_reassembly(const NameExpr* n,
                                                   const ExprPList& args)
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

bool ZAMCompiler::BuiltIn_Files__set_reassembly_buffer(const NameExpr* n,
                                                       const ExprPList& args)
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
		auto arg_cnt = args[1]->AsConstExpr()->Value()->AsCount();
		z = ZInstI(OP_FILES__SET_REASSEMBLY_BUFFER_VC, arg_f, arg_cnt);
		z.op_type = OP_VV_I2;
		}
	else
		z = ZInstI(OP_FILES__SET_REASSEMBLY_BUFFER_VV, arg_f,
		           FrameSlot(args[1]->AsNameExpr()));

	AddInst(z);

	return true;
	}

bool ZAMCompiler::BuiltIn_Log__write(const NameExpr* n, const ExprPList& args)
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

	z.SetType(columns_n->GetType());

	AddInst(z);

	return true;
	}

bool ZAMCompiler::BuiltIn_current_time(const NameExpr* n, const ExprPList& args)
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

bool ZAMCompiler::BuiltIn_get_port_etc(const NameExpr* n, const ExprPList& args)
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

bool ZAMCompiler::BuiltIn_network_time(const NameExpr* n, const ExprPList& args)
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

bool ZAMCompiler::BuiltIn_reading_live_traffic(const NameExpr* n,
                                               const ExprPList& args)
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

bool ZAMCompiler::BuiltIn_reading_traces(const NameExpr* n,
                                         const ExprPList& args)
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

bool ZAMCompiler::BuiltIn_strstr(const NameExpr* n, const ExprPList& args)
	{
	if ( ! n )
		{
		reporter->Warning("return value from built-in function ignored");
		return true;
		}

	auto big = args[0];
	auto little = args[1];

	auto big_n = big->Tag() == EXPR_NAME ? big->AsNameExpr() : nullptr;
	auto little_n = little->Tag() == EXPR_NAME ?
	                little->AsNameExpr() : nullptr;

	ZInstI z;

	if ( big_n && little_n )
		z = GenInst(OP_STRSTR_VVV, n, big_n, little_n);
	else if ( big_n )
		z = GenInst(OP_STRSTR_VVC, n, big_n, little->AsConstExpr());
	else if ( little_n )
		z = GenInst(OP_STRSTR_VCV, n, little_n, big->AsConstExpr());
	else
		return false;

	AddInst(z);

	return true;
	}

bool ZAMCompiler::BuiltIn_sub_bytes(const NameExpr* n, const ExprPList& args)
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

bool ZAMCompiler::BuiltIn_to_lower(const NameExpr* n, const ExprPList& args)
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
		ValPtr arg_lc = {AdoptRef{}, ZAM_to_lower(arg_c)};
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

bro_uint_t ZAMCompiler::ConstArgsMask(const ExprPList& args, int nargs) const
	{
	ASSERT(args.length() == nargs);

	bro_uint_t mask = 0;

	for ( int i = 0; i < nargs; ++i )
		{
		mask <<= 1;
		if ( args[i]->Tag() == EXPR_CONST )
			mask |= 1;
		}

	return mask;
	}

} // zeek::detail
