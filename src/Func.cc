// $Id: Func.cc 6703 2009-05-13 22:27:44Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <sys/resource.h>

#include <netinet/in.h>

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <sys/param.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>

#include <algorithm>

#include "md5.h"
#include "Base64.h"
#include "Stmt.h"
#include "Scope.h"
#include "Net.h"
#include "NetVar.h"
#include "File.h"
#include "Func.h"
#include "Frame.h"
#include "Var.h"
#include "Login.h"
#include "Sessions.h"
#include "RE.h"
#include "Serializer.h"
#include "RemoteSerializer.h"
#include "Event.h"
#include "Traverse.h"

extern	RETSIGTYPE sig_handler(int signo);

const Expr* calling_expr = 0;
bool did_builtin_init = false;


Func::~Func()
	{
	}

void Func::AddBody(Stmt* /* new_body */, id_list* /* new_inits */,
			int /* new_frame_size */, int /* priority */)
	{
	Internal("Func::AddBody called");
	}

bool Func::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Func* Func::Unserialize(UnserialInfo* info)
	{
	Func* f = (Func*) SerialObj::Unserialize(info, SER_FUNC);

	// For builtins, we return a reference to the (hopefully) already
	// existing function.
	if ( f && f->kind == BUILTIN_FUNC )
		{
		const char* name = ((BuiltinFunc*) f)->Name();
		ID* id = global_scope()->Lookup(name);
		if ( ! id )
			{
			info->s->Error(fmt("can't find built-in %s", name));
			return 0;
			}

		if ( ! (id->HasVal() && id->ID_Val()->Type()->Tag() == TYPE_FUNC) )
			{
			info->s->Error(fmt("ID %s is not a built-in", name));
			return false;
			}

		Unref(f);
		f = id->ID_Val()->AsFunc();
		Ref(f);
		}

	return f;
	}

bool Func::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FUNC, BroObj);

	if ( ! SERIALIZE(int(bodies.size())) )
		return false;

	for ( unsigned int i = 0; i < bodies.size(); ++i )
		{
		if ( ! bodies[i].stmts->Serialize(info) )
			return false;
		if ( ! SERIALIZE(bodies[i].priority) )
			return false;
		}

	if ( ! SERIALIZE(char(kind) ) )
		return false;

	// We don't serialize scope as only global functions are considered here
	// anyway.
	return true;
	}

bool Func::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	while ( len-- )
		{
		Body b;
		b.stmts = Stmt::Unserialize(info);
		if ( ! b.stmts )
			return false;

		if ( ! UNSERIALIZE(&b.priority) )
			return false;

		bodies.push_back(b);
		}

	char c;
	if ( ! UNSERIALIZE(&c) )
		return false;

	kind = (Kind) c;
	return true;
	}

void Func::DescribeDebug(ODesc* d, const val_list* args) const
	{
	id->Describe(d);
	RecordType* func_args = FType()->Args();

	if ( args )
		{
		d->Add("(");

		for ( int i = 0; i < args->length(); ++i )
			{
			// Handle varargs case (more args than formals).
			if ( i >= func_args->NumFields() )
				{
				d->Add("vararg");
				d->Add(i - func_args->NumFields());
				}
			else
				d->Add(func_args->FieldName(i));

			d->Add(" = '");
			(*args)[i]->Describe(d);

			if ( i < args->length() - 1 )
				d->Add("', ");
			else
				d->Add("'");
			}

		d->Add(")");
		}
	}

void Func::SetID(ID *arg_id)
	{
	id = arg_id;

	return_value =
		new ID(string(string(id->Name()) + "_returnvalue").c_str(),
			SCOPE_FUNCTION, false);
	return_value->SetType(FType()->YieldType()->Ref());
	}

ID* Func::GetReturnValueID() const
	{
	return return_value;
	}

TraversalCode Func::Traverse(TraversalCallback* cb) const
	{
	// FIXME: Make a fake scope for builtins?
	Scope* old_scope = cb->current_scope;
	cb->current_scope = scope;

	TraversalCode tc = cb->PreFunction(this);
	HANDLE_TC_STMT_PRE(tc);

	// FIXME: Traverse arguments to builtin functions, too.
	if ( kind == BRO_FUNC )
		{
		tc = scope->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);

		if ( GetReturnValueID() )
			{
			tc = GetReturnValueID()->Traverse(cb);
			HANDLE_TC_STMT_PRE(tc);
			}

		for ( unsigned int i = 0; i < bodies.size(); ++i )
			{
			tc = bodies[i].stmts->Traverse(cb);
			HANDLE_TC_STMT_PRE(tc);
			}
		}

	tc = cb->PostFunction(this);

	cb->current_scope = old_scope;
	HANDLE_TC_STMT_POST(tc);
	}

BroFunc::BroFunc(ID* arg_id, Stmt* arg_body, id_list* aggr_inits,
		int arg_frame_size)
: Func(BRO_FUNC)
	{
	id = arg_id;
	Body b;
	b.stmts = AddInits(arg_body, aggr_inits);
	b.priority = 0;
	bodies.push_back(b);
	frame_size = arg_frame_size;
	}

BroFunc::~BroFunc()
	{
	Unref(id);
	for ( unsigned int i = 0; i < bodies.size(); ++i )
		Unref(bodies[i].stmts);
	}

int BroFunc::IsPure() const
	{
	for ( unsigned int i = 0; i < bodies.size(); ++i )
		if ( ! bodies[i].stmts->IsPure() )
			return 0;

	return 1;
	}

Val* BroFunc::Call(val_list* args, Frame* parent) const
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Function: %s\n", id->Name());
#endif
	SegmentProfiler(segment_logger, location);
	Frame* f = new Frame(frame_size, this, args);

	// Hand down any trigger.
	if ( parent )
		{
		f->SetTrigger(parent->GetTrigger());
		f->SetCall(parent->GetCall());
		}

	g_frame_stack.push_back(f);	// used for backtracing

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		DescribeDebug(&d, args);

		g_trace_state.LogTrace("%s called: %s\n",
			IsEvent() ? "event" : "function", d.Description());
		}

	loop_over_list(*args, i)
		f->SetElement(i, (*args)[i]);

	stmt_flow_type flow;

	Val* result = 0;

	if ( sample_logger )
		sample_logger->FunctionSeen(this);

	for ( unsigned int i = 0; i < bodies.size(); ++i )
		{
		if ( sample_logger )
			sample_logger->LocationSeen(
				bodies[i].stmts->GetLocationInfo());

		Unref(result);
		result = bodies[i].stmts->Exec(f, flow);

		if ( f->HasDelayed() )
			{
			assert(! result);
			assert(parent);
			parent->SetDelayed();
			break;
			}
		}

	// Warn if the function returns something, but we returned from
	// the function without an explicit return, or without a value.
	if ( FType()->YieldType() && FType()->YieldType()->Tag() != TYPE_VOID &&
	     (flow != FLOW_RETURN /* we fell off the end */ ||
	      ! result /* explicit return with no result */) &&
	     ! f->HasDelayed() )
		warn("non-void function returns without a value:", id->Name());

	if ( result && g_trace_state.DoTrace() )
		{
		ODesc d;
		result->Describe(&d);

		g_trace_state.LogTrace("Function return: %s\n", d.Description());
		}

	g_frame_stack.pop_back();
	Unref(f);

	return result;
	}

void BroFunc::AddBody(Stmt* new_body, id_list* new_inits, int new_frame_size,
		int priority)
	{
	if ( new_frame_size > frame_size )
		frame_size = new_frame_size;

	new_body = AddInits(new_body, new_inits);

	if ( ! IsEvent() )
		{
		// For functions, we replace the old body with the new one.
		assert(bodies.size() <= 1);
		for ( unsigned int i = 0; i < bodies.size(); ++i )
			Unref(bodies[i].stmts);
		bodies.clear();
		}

	Body b;
	b.stmts = new_body;
	b.priority = priority;

	bodies.push_back(b);
	sort(bodies.begin(), bodies.end());
	}

void BroFunc::Describe(ODesc* d) const
	{
	if ( id )
		id->Describe(d);

	d->NL();
	d->AddCount(frame_size);
	for ( unsigned int i = 0; i < bodies.size(); ++i )
		{
		bodies[i].stmts->AccessStats(d);
		bodies[i].stmts->Describe(d);
		}
	}

Stmt* BroFunc::AddInits(Stmt* body, id_list* inits)
	{
	if ( ! inits || inits->length() == 0 )
		return body;

	StmtList* stmt_series = new StmtList;
	stmt_series->Stmts().append(new InitStmt(inits));
	stmt_series->Stmts().append(body);

	return stmt_series;
	}

IMPLEMENT_SERIAL(BroFunc, SER_BRO_FUNC);

bool BroFunc::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BRO_FUNC, Func);
	return id->Serialize(info) && SERIALIZE(frame_size);
	}

bool BroFunc::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Func);
	id = ID::Unserialize(info);
	return id && UNSERIALIZE(&frame_size);
	}

BuiltinFunc::BuiltinFunc(built_in_func arg_func, const char* arg_name,
			int arg_is_pure)
: Func(BUILTIN_FUNC)
	{
	func = arg_func;
	name = copy_string(make_full_var_name(GLOBAL_MODULE_NAME, arg_name).c_str());
	is_pure = arg_is_pure;

	id = lookup_ID(name, GLOBAL_MODULE_NAME, false);
	if ( ! id )
		internal_error("built-in function %s missing", name);
	if ( id->HasVal() )
		internal_error("built-in function %s multiply defined", name);

	id->SetVal(new Val(this));
	}

BuiltinFunc::~BuiltinFunc()
	{
	}

int BuiltinFunc::IsPure() const
	{
	return is_pure;
	}

Val* BuiltinFunc::Call(val_list* args, Frame* parent) const
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Function: %s\n", Name());
#endif
	SegmentProfiler(segment_logger, name);

	if ( sample_logger )
		sample_logger->FunctionSeen(this);

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		DescribeDebug(&d, args);

		g_trace_state.LogTrace("\tBuiltin Function called: %s\n", d.Description());
		}

	Val* result = func(parent, args);
	loop_over_list(*args, i)
		Unref((*args)[i]);

	// Don't Unref() args, that's the caller's responsibility.
	if ( result && g_trace_state.DoTrace() )
		{
		ODesc d;
		result->Describe(&d);

		g_trace_state.LogTrace("\tFunction return: %s\n", d.Description());
		}

	return result;
	}

void BuiltinFunc::Describe(ODesc* d) const
	{
	if ( id )
	id->Describe(d);
	d->AddCount(is_pure);
	}

IMPLEMENT_SERIAL(BuiltinFunc, SER_BUILTIN_FUNC);

bool BuiltinFunc::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BUILTIN_FUNC, Func);

	// We ignore the ID. Func::Serialize() will rebind us anyway.
	return SERIALIZE(name);
	}

bool BuiltinFunc::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Func);
	id = 0;
	return UNSERIALIZE_STR(&name, 0);
	}

void builtin_run_time(const char* msg, BroObj* arg)
	{
	if ( calling_expr )
		calling_expr->RunTime(msg, arg);
	else
		run_time(msg, arg);
	}

#include "bro.bif.func_def"
#include "strings.bif.func_def"

void init_builtin_funcs()
	{
	ftp_port = internal_type("ftp_port")->AsRecordType();
	bro_resources = internal_type("bro_resources")->AsRecordType();
	matcher_stats = internal_type("matcher_stats")->AsRecordType();
	var_sizes = internal_type("var_sizes")->AsTableType();
	gap_info = internal_type("gap_info")->AsRecordType();

#include "bro.bif.func_init"

#include "common-rw.bif.func_init"
#include "finger-rw.bif.func_init"
#include "ftp-rw.bif.func_init"
#include "http-rw.bif.func_init"
#include "ident-rw.bif.func_init"
#include "smtp-rw.bif.func_init"
#include "strings.bif.func_init"
#include "dns-rw.bif.func_init"

	did_builtin_init = true;
	}

bool check_built_in_call(BuiltinFunc* f, CallExpr* call)
	{
	if ( f->TheFunc() != bro_fmt )
		return true;

	const expr_list& args = call->Args()->Exprs();
	if ( args.length() == 0 )
		{
		// Empty calls are allowed, since you can't just
		// use "print;" to get a blank line.
		return true;
		}

	const Expr* fmt_str_arg = args[0];
	if ( fmt_str_arg->Type()->Tag() != TYPE_STRING )
		{
		call->Error("first argument to fmt() needs to be a format string");
		return false;
		}

	Val* fmt_str_val = fmt_str_arg->Eval(0);

	if ( fmt_str_val )
		{
		const char* fmt_str = fmt_str_val->AsStringVal()->CheckString();

		int num_fmt = 0;
		while ( *fmt_str )
			{
			if ( *(fmt_str++) != '%' )
				continue;

			if ( ! *fmt_str )
				{
				call->Error("format string ends with bare '%'");
				return false;
				}

			if ( *(fmt_str++) != '%' )
				// Not a "%%" escape.
				++num_fmt;
			}

		if ( args.length() != num_fmt + 1 )
			{
			call->Error("mismatch between format string to fmt() and number of arguments passed");
			return false;
			}
		}

	return true;
	}
