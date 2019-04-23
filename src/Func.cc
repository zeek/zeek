// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
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

#include "Base64.h"
#include "Stmt.h"
#include "Scope.h"
#include "Net.h"
#include "NetVar.h"
#include "File.h"
#include "Func.h"
#include "Frame.h"
#include "Var.h"
#include "analyzer/protocol/login/Login.h"
#include "Sessions.h"
#include "RE.h"
#include "Serializer.h"
#include "RemoteSerializer.h"
#include "Event.h"
#include "Traverse.h"
#include "Reporter.h"
#include "plugin/Manager.h"

extern	RETSIGTYPE sig_handler(int signo);

vector<CallInfo> call_stack;
bool did_builtin_init = false;

vector<Func*> Func::unique_ids;
static const std::pair<bool, Val*> empty_hook_result(false, NULL);

std::string render_call_stack()
	{
	std::string rval;
	int lvl = 0;

	if ( ! call_stack.empty() )
		rval += "| ";

	for ( auto it = call_stack.rbegin(); it != call_stack.rend(); ++it )
		{
		if ( lvl > 0 )
			rval += " | ";

		auto& ci = *it;
		auto name = ci.func->Name();
		std::string arg_desc;

		if ( ci.args )
			{
			loop_over_list(*ci.args, i)
				{
				ODesc d;
				d.SetShort();
				(*ci.args)[i]->Describe(&d);

				if ( ! arg_desc.empty() )
					arg_desc += ", ";

				arg_desc += d.Description();
				}
			}

		rval += fmt("#%d %s(%s)", lvl, name, arg_desc.data());

		if ( ci.call )
			{
			auto loc = ci.call->GetLocationInfo();
			rval += fmt(" at %s:%d", loc->filename, loc->first_line);
			}

		++lvl;
		}

	if ( ! call_stack.empty() )
		rval += " |";

	return rval;
	}

Func::Func() : scope(0), type(0)
	{
	unique_id = unique_ids.size();
	unique_ids.push_back(this);
	}

Func::Func(Kind arg_kind) : scope(0), kind(arg_kind), type(0)
	{
	unique_id = unique_ids.size();
	unique_ids.push_back(this);
	}

Func::~Func()
	{
	Unref(type);
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
			return 0;
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

	if ( ! type->Serialize(info) )
		return false;

	if ( ! SERIALIZE(Name()) )
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

	type = BroType::Unserialize(info);
	if ( ! type )
		return false;

	const char* n;
	if ( ! UNSERIALIZE_STR(&n, 0) )
		return false;

	name = n;
	delete [] n;

	return true;
	}

void Func::DescribeDebug(ODesc* d, const val_list* args) const
	{
	d->Add(Name());

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

TraversalCode Func::Traverse(TraversalCallback* cb) const
	{
	// FIXME: Make a fake scope for builtins?
	Scope* old_scope = cb->current_scope;
	cb->current_scope = scope;

	TraversalCode tc = cb->PreFunction(this);
	HANDLE_TC_STMT_PRE(tc);

	// FIXME: Traverse arguments to builtin functions, too.
	if ( kind == BRO_FUNC && scope )
		{
		tc = scope->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);

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

std::pair<bool, Val*> Func::HandlePluginResult(std::pair<bool, Val*> plugin_result, val_list* args, function_flavor flavor) const
	{
	// Helper function factoring out this code from BroFunc:Call() for
	// better readability.

	if( ! plugin_result.first )
		{
		if( plugin_result.second )
			reporter->InternalError("plugin set processed flag to false but actually returned a value");

		// The plugin result hasn't been processed yet (read: fall
		// into ::Call method).
		return plugin_result;
		}

	switch ( flavor ) {
	case FUNC_FLAVOR_EVENT:
		if( plugin_result.second )
			reporter->InternalError("plugin returned non-void result for event %s", this->Name());

		break;

	case FUNC_FLAVOR_HOOK:
		if ( plugin_result.second->Type()->Tag() != TYPE_BOOL )
			reporter->InternalError("plugin returned non-bool for hook %s", this->Name());

		break;

	case FUNC_FLAVOR_FUNCTION:
		{
		BroType* yt = FType()->YieldType();

		if ( (! yt) || yt->Tag() == TYPE_VOID )
			{
			if( plugin_result.second )
				reporter->InternalError("plugin returned non-void result for void method %s", this->Name());
			}

		else if ( plugin_result.second && plugin_result.second->Type()->Tag() != yt->Tag() && yt->Tag() != TYPE_ANY)
			{
			reporter->InternalError("plugin returned wrong type (got %d, expecting %d) for %s",
						plugin_result.second->Type()->Tag(), yt->Tag(), this->Name());
			}

		break;
		}
	}

	loop_over_list(*args, i)
		Unref((*args)[i]);

	return plugin_result;
	}

BroFunc::BroFunc(ID* arg_id, Stmt* arg_body, id_list* aggr_inits,
		int arg_frame_size, int priority)
: Func(BRO_FUNC)
	{
	name = arg_id->Name();
	type = arg_id->Type()->Ref();
	frame_size = arg_frame_size;

	if ( arg_body )
		{
		Body b;
		b.stmts = AddInits(arg_body, aggr_inits);
		b.priority = priority;
		bodies.push_back(b);
		}
	}

BroFunc::~BroFunc()
	{
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
	DEBUG_MSG("Function: %s\n", Name());
#endif

	SegmentProfiler(segment_logger, location);

	if ( sample_logger )
		sample_logger->FunctionSeen(this);

	std::pair<bool, Val*> plugin_result = PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION, HookCallFunction(this, parent, args), empty_hook_result);

	plugin_result = HandlePluginResult(plugin_result, args, Flavor());

	if( plugin_result.first )
		{
		Val *result = plugin_result.second;
		return result;
		}

	if ( bodies.empty() )
		{
		// Can only happen for events and hooks.
		assert(Flavor() == FUNC_FLAVOR_EVENT || Flavor() == FUNC_FLAVOR_HOOK);
		loop_over_list(*args, i)
			Unref((*args)[i]);

		return Flavor() == FUNC_FLAVOR_HOOK ? val_mgr->GetTrue() : 0;
		}

	Frame* f = new Frame(frame_size, this, args);

	// Hand down any trigger.
	if ( parent )
		{
		f->SetTrigger(parent->GetTrigger());
		f->SetCall(parent->GetCall());
		}

	g_frame_stack.push_back(f);	// used for backtracing
	const CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
	call_stack.emplace_back(CallInfo{call_expr, this, args});

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		DescribeDebug(&d, args);

		g_trace_state.LogTrace("%s called: %s\n",
			FType()->FlavorString().c_str(), d.Description());
		}

	stmt_flow_type flow = FLOW_NEXT;
	Val* result = 0;

	for ( size_t i = 0; i < bodies.size(); ++i )
		{
		if ( sample_logger )
			sample_logger->LocationSeen(
				bodies[i].stmts->GetLocationInfo());

		Unref(result);

		loop_over_list(*args, j)
			{
			Val* arg = (*args)[j];

			if ( f->NthElement(j) != arg )
				{
				// Either not yet set, or somebody reassigned
				// the frame slot.
				Ref(arg);
				f->SetElement(j, arg);
				}
			}

		f->Reset(args->length());

		try
			{
			result = bodies[i].stmts->Exec(f, flow);
			}

		catch ( InterpreterException& e )
			{
			// Already reported, but now determine whether to unwind further.
			if ( Flavor() == FUNC_FLAVOR_FUNCTION )
				throw;

			// Continue exec'ing remaining bodies of hooks/events.
			continue;
			}

		if ( f->HasDelayed() )
			{
			assert(! result);
			assert(parent);
			parent->SetDelayed();
			break;
			}

		if ( Flavor() == FUNC_FLAVOR_HOOK )
			{
			// Ignore any return values of hook bodies, final return value
			// depends on whether a body returns as a result of break statement.
			Unref(result);
			result = 0;

			if ( flow == FLOW_BREAK )
				{
				// Short-circuit execution of remaining hook handler bodies.
				result = val_mgr->GetFalse();
				break;
				}
			}
		}

	call_stack.pop_back();

	// We have an extra Ref for each argument (so that they don't get
	// deleted between bodies), release that.
	loop_over_list(*args, k)
		Unref((*args)[k]);

	if ( Flavor() == FUNC_FLAVOR_HOOK )
		{
		if ( ! result )
			result = val_mgr->GetTrue();
		}

	// Warn if the function returns something, but we returned from
	// the function without an explicit return, or without a value.
	else if ( FType()->YieldType() && FType()->YieldType()->Tag() != TYPE_VOID &&
		 (flow != FLOW_RETURN /* we fell off the end */ ||
		  ! result /* explicit return with no result */) &&
		 ! f->HasDelayed() )
		reporter->Warning("non-void function returns without a value: %s",
				  Name());

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

	if ( Flavor() == FUNC_FLAVOR_FUNCTION )
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
	d->Add(Name());

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
	return SERIALIZE(frame_size);
	}

bool BroFunc::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Func);

	return UNSERIALIZE(&frame_size);
	}

BuiltinFunc::BuiltinFunc(built_in_func arg_func, const char* arg_name,
			int arg_is_pure)
: Func(BUILTIN_FUNC)
	{
	func = arg_func;
	name = make_full_var_name(GLOBAL_MODULE_NAME, arg_name);
	is_pure = arg_is_pure;

	ID* id = lookup_ID(Name(), GLOBAL_MODULE_NAME, false);
	if ( ! id )
		reporter->InternalError("built-in function %s missing", Name());
	if ( id->HasVal() )
		reporter->InternalError("built-in function %s multiply defined", Name());

	type = id->Type()->Ref();
	id->SetVal(new Val(this));
	Unref(id);
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
	SegmentProfiler(segment_logger, Name());

	if ( sample_logger )
		sample_logger->FunctionSeen(this);

	std::pair<bool, Val*> plugin_result = PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION, HookCallFunction(this, parent, args), empty_hook_result);

	plugin_result = HandlePluginResult(plugin_result, args, FUNC_FLAVOR_FUNCTION);

	if ( plugin_result.first )
		{
		Val *result = plugin_result.second;
		return result;
		}

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		DescribeDebug(&d, args);

		g_trace_state.LogTrace("\tBuiltin Function called: %s\n", d.Description());
		}

	const CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
	call_stack.emplace_back(CallInfo{call_expr, this, args});
	Val* result = func(parent, args);
	call_stack.pop_back();

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
	d->Add(Name());
	d->AddCount(is_pure);
	}

IMPLEMENT_SERIAL(BuiltinFunc, SER_BUILTIN_FUNC);

bool BuiltinFunc::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BUILTIN_FUNC, Func);
	return true;
	}

bool BuiltinFunc::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Func);
	return true;
	}

void builtin_error(const char* msg, BroObj* arg)
	{
	auto emit = [=](const CallExpr* ce)
		{
		if ( ce )
			ce->Error(msg, arg);
		else
			reporter->Error(msg, arg);
		};


	if ( call_stack.empty() )
		{
		emit(nullptr);
		return;
		}

	auto last_call = call_stack.back();

	if ( call_stack.size() < 2 )
		{
		// Don't need to check for wrapper function like "<module>::__<func>"
		emit(last_call.call);
		return;
		}

	auto starts_with_double_underscore = [](const std::string& name) -> bool
		{ return name.size() > 2 && name[0] == '_' && name[1] == '_'; };
	std::string last_func = last_call.func->Name();

	auto pos = last_func.find_first_of("::");
	std::string wrapper_func;

	if ( pos == std::string::npos )
		{
		if ( ! starts_with_double_underscore(last_func) )
			{
			emit(last_call.call);
			return;
			}

		wrapper_func = last_func.substr(2);
		}
	else
		{
		auto module_name = last_func.substr(0, pos);
		auto func_name = last_func.substr(pos + 2);

		if ( ! starts_with_double_underscore(func_name) )
			{
			emit(last_call.call);
			return;
			}

		wrapper_func = module_name + "::" + func_name.substr(2);
		}

	auto parent_call = call_stack[call_stack.size() - 2];
	auto parent_func = parent_call.func->Name();

	if ( wrapper_func == parent_func )
		emit(parent_call.call);
	else
		emit(last_call.call);
	}

#include "bro.bif.func_h"
#include "stats.bif.func_h"
#include "reporter.bif.func_h"
#include "strings.bif.func_h"
#include "option.bif.func_h"

#include "bro.bif.func_def"
#include "stats.bif.func_def"
#include "reporter.bif.func_def"
#include "strings.bif.func_def"
#include "option.bif.func_def"

#include "__all__.bif.cc" // Autogenerated for compiling in the bif_target() code.
#include "__all__.bif.register.cc" // Autogenerated for compiling in the bif_target() code.

void init_builtin_funcs()
	{
	ProcStats = internal_type("ProcStats")->AsRecordType();
	NetStats = internal_type("NetStats")->AsRecordType();
	MatcherStats = internal_type("MatcherStats")->AsRecordType();
	ConnStats = internal_type("ConnStats")->AsRecordType();
	ReassemblerStats = internal_type("ReassemblerStats")->AsRecordType();
	DNSStats = internal_type("DNSStats")->AsRecordType();
	GapStats = internal_type("GapStats")->AsRecordType();
	EventStats = internal_type("EventStats")->AsRecordType();
	TimerStats = internal_type("TimerStats")->AsRecordType();
	FileAnalysisStats = internal_type("FileAnalysisStats")->AsRecordType();
	ThreadStats = internal_type("ThreadStats")->AsRecordType();
	BrokerStats = internal_type("BrokerStats")->AsRecordType();
	ReporterStats = internal_type("ReporterStats")->AsRecordType();

	var_sizes = internal_type("var_sizes")->AsTableType();

#include "bro.bif.func_init"
#include "stats.bif.func_init"
#include "reporter.bif.func_init"
#include "strings.bif.func_init"
#include "option.bif.func_init"

	did_builtin_init = true;
	}

void init_builtin_funcs_subdirs()
{
	#include "__all__.bif.init.cc" // Autogenerated for compiling in the bif_target() code.
}

bool check_built_in_call(BuiltinFunc* f, CallExpr* call)
	{
	if ( f->TheFunc() != BifFunc::bro_fmt )
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
