// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "Func.h"

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

#include <broker/error.hh>

#include "Base64.h"
#include "Debug.h"
#include "Desc.h"
#include "Expr.h"
#include "Stmt.h"
#include "Scope.h"
#include "Net.h"
#include "NetVar.h"
#include "File.h"
#include "Frame.h"
#include "Var.h"
#include "analyzer/protocol/login/Login.h"
#include "Sessions.h"
#include "RE.h"
#include "Event.h"
#include "Traverse.h"
#include "Reporter.h"
#include "plugin/Manager.h"
#include "module_util.h"
#include "iosource/PktSrc.h"
#include "iosource/PktDumper.h"

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
			for ( const auto& arg : *ci.args )
				{
				ODesc d;
				d.SetShort();
				arg->Describe(&d);

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
		   size_t /* new_frame_size */, int /* priority */)
	{
	Internal("Func::AddBody called");
	}

Func* Func::DoClone()
	{
	// By default, ok just to return a reference. Func does not have any state
	// that is different across instances.
	::Ref(this);
	return this;
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

void Func::CopyStateInto(Func* other) const
	{
	std::for_each(bodies.begin(), bodies.end(), [](const Body& b) { Ref(b.stmts); });

	other->bodies = bodies;
	other->scope = scope;
	other->kind = kind;

	Ref(type);
	other->type = type;

	other->name = name;
	other->unique_id = unique_id;
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

	for ( const auto& arg : *args )
		Unref(arg);

	return plugin_result;
	}

BroFunc::BroFunc(ID* arg_id, Stmt* arg_body, id_list* aggr_inits,
		 size_t arg_frame_size, int priority) : Func(BRO_FUNC)
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
	std::for_each(bodies.begin(), bodies.end(),
		[](Body& b) { Unref(b.stmts); });

	if ( ! weak_closure_ref )
		Unref(closure);
	}

int BroFunc::IsPure() const
	{
	return std::all_of(bodies.begin(), bodies.end(),
		[](const Body& b) { return b.stmts->IsPure(); });
	}

Val* BroFunc::Call(val_list* args, Frame* parent) const
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Function: %s\n", Name());
#endif
	SegmentProfiler prof(segment_logger, location);

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
		for ( const auto& arg : *args )
			Unref(arg);

		return Flavor() == FUNC_FLAVOR_HOOK ? val_mgr->GetTrue() : 0;
		}

	Frame* f = new Frame(frame_size, this, args);

	if ( closure )
		f->CaptureClosure(closure, outer_ids);

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

	for ( const auto& body : bodies )
		{
		if ( sample_logger )
			sample_logger->LocationSeen(
				body.stmts->GetLocationInfo());

		Unref(result);

		// Fill in the rest of the frame with the function's arguments.
		loop_over_list(*args, j)
			{
			Val* arg = (*args)[j];

			if ( f->NthElement(j) != arg )
				{
				// Either not yet set, or somebody reassigned the frame slot.
				Ref(arg);
				f->SetElement(j, arg);
				}
			}

		f->Reset(args->length());

		try
			{
			result = body.stmts->Exec(f, flow);
			}

		catch ( InterpreterException& e )
			{
			// Already reported, but now determine whether to unwind further.
			if ( Flavor() == FUNC_FLAVOR_FUNCTION )
				{
				Unref(f);
				// Result not set b/c exception was thrown
				throw;
				}

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
	for ( const auto& arg : *args )
		Unref(arg);

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
		reporter->Warning("non-void function returning without a value: %s",
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

void BroFunc::AddBody(Stmt* new_body, id_list* new_inits,
		      size_t new_frame_size, int priority)
	{
	if ( new_frame_size > frame_size )
		frame_size = new_frame_size;

	new_body = AddInits(new_body, new_inits);

	if ( Flavor() == FUNC_FLAVOR_FUNCTION )
		{
		// For functions, we replace the old body with the new one.
		assert(bodies.size() <= 1);
		for ( const auto& body : bodies )
			Unref(body.stmts);
		bodies.clear();
		}

	Body b;
	b.stmts = new_body;
	b.priority = priority;

	bodies.push_back(b);
	sort(bodies.begin(), bodies.end());
	}

void BroFunc::AddClosure(id_list ids, Frame* f)
	{
	if ( ! f )
		return;

	SetOuterIDs(std::move(ids));
	SetClosureFrame(f);
	}

bool BroFunc::StrengthenClosureReference(Frame* f)
	{
	if ( closure != f )
		return false;

	if ( ! weak_closure_ref )
		return false;

	closure = closure->SelectiveClone(outer_ids, this);
	weak_closure_ref = false;
	return true;
	}

void BroFunc::SetClosureFrame(Frame* f)
	{
	if ( closure )
		reporter->InternalError("Tried to override closure for BroFunc %s.",
					Name());

	// Have to use weak references initially because otherwise Ref'ing the
	// original frame creates a circular reference: the function holds a
	// reference to the frame and the frame contains a reference to this
	// function value.  And we can't just do a shallow clone of the frame
	// up front because the closure semantics in Zeek allow mutating
	// the outer frame.

	closure = f;
	weak_closure_ref = true;
	f->AddFunctionWithClosureRef(this);
	}

bool BroFunc::UpdateClosure(const broker::vector& data)
	{
	auto result = Frame::Unserialize(data);
	if ( ! result.first )
		return false;

	Frame* new_closure = result.second;
	if ( new_closure )
		new_closure->SetFunction(this);

	if ( ! weak_closure_ref )
		Unref(closure);

	weak_closure_ref = false;
	closure = new_closure;

	return true;
	}


Func* BroFunc::DoClone()
	{
	// BroFunc could hold a closure. In this case a clone of it must
	// store a copy of this closure.
	BroFunc* other = new BroFunc();

	CopyStateInto(other);

	other->frame_size = frame_size;
	other->closure = closure ? closure->SelectiveClone(outer_ids, this) : nullptr;
	other->weak_closure_ref = false;
	other->outer_ids = outer_ids;

	return other;
	}

broker::expected<broker::data> BroFunc::SerializeClosure() const
	{
	return Frame::Serialize(closure, outer_ids);
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
	stmt_series->Stmts().push_back(new InitStmt(inits));
	stmt_series->Stmts().push_back(body);

	return stmt_series;
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
	SegmentProfiler prof(segment_logger, Name());

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

	for ( const auto& arg : *args )
		Unref(arg);

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

#include "zeek.bif.func_h"
#include "stats.bif.func_h"
#include "reporter.bif.func_h"
#include "strings.bif.func_h"
#include "option.bif.func_h"
#include "supervisor.bif.func_h"

#include "zeek.bif.func_def"
#include "stats.bif.func_def"
#include "reporter.bif.func_def"
#include "strings.bif.func_def"
#include "option.bif.func_def"
#include "supervisor.bif.func_def"

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

#include "zeek.bif.func_init"
#include "stats.bif.func_init"
#include "reporter.bif.func_init"
#include "strings.bif.func_init"
#include "option.bif.func_init"
#include "supervisor.bif.func_init"

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

// Gets a function's priority from its Scope's attributes. Errors if it sees any
// problems.
static int get_func_priority(const attr_list& attrs)
	{
	int priority = 0;

	for ( const auto& a : attrs )
		{
		if ( a->Tag() == ATTR_DEPRECATED )
			continue;

		if ( a->Tag() != ATTR_PRIORITY )
			{
			a->Error("illegal attribute for function body");
			continue;
			}

		Val* v = a->AttrExpr()->Eval(0);
		if ( ! v )
			{
			a->Error("cannot evaluate attribute expression");
			continue;
			}

		if ( ! IsIntegral(v->Type()->Tag()) )
			{
			a->Error("expression is not of integral type");
			continue;
			}

		priority = v->InternalInt();
		}

	return priority;
	}

function_ingredients::function_ingredients(Scope* scope, Stmt* body)
	{
	frame_size = scope->Length();
	inits = scope->GetInits();

	this->scope = scope;
	::Ref(this->scope);
	id = scope->ScopeID();
	::Ref(id);

	auto attrs = scope->Attrs();

	priority = (attrs ? get_func_priority(*attrs) : 0);
	this->body = body;
	::Ref(this->body);
	}

function_ingredients::~function_ingredients()
	{
	Unref(id);
	Unref(body);
	Unref(scope);

	for ( const auto& i : *inits )
		Unref(i);

	delete inits;
	}
