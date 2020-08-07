
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

extern	RETSIGTYPE sig_handler(int signo);

namespace zeek::detail {
std::vector<CallInfo> call_stack;
bool did_builtin_init = false;
static const std::pair<bool, zeek::ValPtr> empty_hook_result(false, nullptr);
} // namespace zeek::detail

namespace zeek {

std::string render_call_stack()
	{
	std::string rval;
	int lvl = 0;

	if ( ! detail::call_stack.empty() )
		rval += "| ";

	for ( auto it = detail::call_stack.rbegin(); it != detail::call_stack.rend(); ++it )
		{
		if ( lvl > 0 )
			rval += " | ";

		auto& ci = *it;
		auto name = ci.func->Name();
		std::string arg_desc;

		for ( const auto& arg : ci.args )
			{
			ODesc d;
			d.SetShort();
			arg->Describe(&d);

			if ( ! arg_desc.empty() )
				arg_desc += ", ";

			arg_desc += d.Description();
			}

		rval += zeek::util::fmt("#%d %s(%s)", lvl, name, arg_desc.data());

		if ( ci.call )
			{
			auto loc = ci.call->GetLocationInfo();
			rval += zeek::util::fmt(" at %s:%d", loc->filename, loc->first_line);
			}

		++lvl;
		}

	if ( ! detail::call_stack.empty() )
		rval += " |";

	return rval;
	}

Func::Func()
	{
	unique_id = unique_ids.size();
	unique_ids.push_back({zeek::NewRef{}, this});
	}

Func::Func(Kind arg_kind) : kind(arg_kind)
	{
	unique_id = unique_ids.size();
	unique_ids.push_back({zeek::NewRef{}, this});
	}

Func::~Func() = default;

void Func::AddBody(zeek::detail::StmtPtr /* new_body */,
                   const std::vector<zeek::detail::IDPtr>& /* new_inits */,
                   size_t /* new_frame_size */, int /* priority */)
	{
	Internal("Func::AddBody called");
	}

void Func::SetScope(zeek::detail::ScopePtr newscope)
	{
	scope = std::move(newscope);
	}

zeek::FuncPtr Func::DoClone()
	{
	// By default, ok just to return a reference. Func does not have any state
	// that is different across instances.
	return {zeek::NewRef{}, this};
	}

void Func::DescribeDebug(ODesc* d, const zeek::Args* args) const
	{
	d->Add(Name());

	if ( args )
		{
		d->Add("(");
		const auto& func_args = GetType()->Params();
		auto num_fields = static_cast<size_t>(func_args->NumFields());

		for ( auto i = 0u; i < args->size(); ++i )
			{
			// Handle varargs case (more args than formals).
			if ( i >= num_fields )
				{
				d->Add("vararg");
				int va_num = i - num_fields;
				d->Add(va_num);
				}
			else
				d->Add(func_args->FieldName(i));

			d->Add(" = '");
			(*args)[i]->Describe(d);

			if ( i < args->size() - 1 )
				d->Add("', ");
			else
				d->Add("'");
			}

		d->Add(")");
		}
	}

detail::TraversalCode Func::Traverse(detail::TraversalCallback* cb) const
	{
	// FIXME: Make a fake scope for builtins?
	zeek::detail::Scope* old_scope = cb->current_scope;
	cb->current_scope = scope.get();

	detail::TraversalCode tc = cb->PreFunction(this);
	HANDLE_TC_STMT_PRE(tc);

	// FIXME: Traverse arguments to builtin functions, too.
	if ( kind == SCRIPT_FUNC && scope )
		{
		tc = scope->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);

		for ( const auto& body : bodies )
			{
			tc = body.stmts->Traverse(cb);
			HANDLE_TC_STMT_PRE(tc);
			}
		}

	tc = cb->PostFunction(this);

	cb->current_scope = old_scope;
	HANDLE_TC_STMT_POST(tc);
	}

void Func::CopyStateInto(Func* other) const
	{
	other->bodies = bodies;
	other->scope = scope;
	other->kind = kind;

	other->type = type;

	other->name = name;
	other->unique_id = unique_id;
	}

void Func::CheckPluginResult(bool handled, const zeek::ValPtr& hook_result,
                             zeek::FunctionFlavor flavor) const
	{
	// Helper function factoring out this code from ScriptFunc:Call() for
	// better readability.

	if ( ! handled )
		{
		if ( hook_result )
			zeek::reporter->InternalError("plugin set processed flag to false but actually returned a value");

		// The plugin result hasn't been processed yet (read: fall
		// into ::Call method).
		return;
		}

	switch ( flavor ) {
	case zeek::FUNC_FLAVOR_EVENT:
		if ( hook_result )
			zeek::reporter->InternalError("plugin returned non-void result for event %s",
			                              this->Name());

		break;

	case zeek::FUNC_FLAVOR_HOOK:
		if ( hook_result->GetType()->Tag() != zeek::TYPE_BOOL )
			zeek::reporter->InternalError("plugin returned non-bool for hook %s",
			                              this->Name());

		break;

	case zeek::FUNC_FLAVOR_FUNCTION:
		{
		const auto& yt = GetType()->Yield();

		if ( (! yt) || yt->Tag() == zeek::TYPE_VOID )
			{
			if ( hook_result )
				zeek::reporter->InternalError("plugin returned non-void result for void method %s",
				                              this->Name());
			}

		else if ( hook_result && hook_result->GetType()->Tag() != yt->Tag() && yt->Tag() != zeek::TYPE_ANY )
			{
			zeek::reporter->InternalError("plugin returned wrong type (got %d, expecting %d) for %s",
			                              hook_result->GetType()->Tag(), yt->Tag(), this->Name());
			}

		break;
		}
	}
	}

zeek::Val* Func::Call(val_list* args, zeek::detail::Frame* parent) const
	{
	auto zargs = zeek::val_list_to_args(*args);
	return Invoke(&zargs, parent).release();
	};

namespace detail {

ScriptFunc::ScriptFunc(const zeek::detail::IDPtr& arg_id, zeek::detail::StmtPtr arg_body,
                       const std::vector<zeek::detail::IDPtr>& aggr_inits,
                       size_t arg_frame_size, int priority)
	: Func(SCRIPT_FUNC)
	{
	name = arg_id->Name();
	type = arg_id->GetType<zeek::FuncType>();
	frame_size = arg_frame_size;

	if ( arg_body )
		{
		Body b;
		b.stmts = AddInits(std::move(arg_body), aggr_inits);
		b.priority = priority;
		bodies.push_back(b);
		}
	}

ScriptFunc::~ScriptFunc()
	{
	if ( ! weak_closure_ref )
		Unref(closure);
	}

bool ScriptFunc::IsPure() const
	{
	return std::all_of(bodies.begin(), bodies.end(),
		[](const Body& b) { return b.stmts->IsPure(); });
	}

zeek::ValPtr ScriptFunc::Invoke(zeek::Args* args, zeek::detail::Frame* parent) const
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Function: %s\n", Name());
#endif
	SegmentProfiler prof(segment_logger, location);

	if ( sample_logger )
		sample_logger->FunctionSeen(this);

	auto [handled, hook_result] = PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION,
	                                                      HookCallFunction(this, parent, args),
	                                                      empty_hook_result);

	CheckPluginResult(handled, hook_result, Flavor());

	if ( handled )
		return hook_result;

	if ( bodies.empty() )
		{
		// Can only happen for events and hooks.
		assert(Flavor() == zeek::FUNC_FLAVOR_EVENT || Flavor() == zeek::FUNC_FLAVOR_HOOK);
		return Flavor() == zeek::FUNC_FLAVOR_HOOK ? zeek::val_mgr->True() : nullptr;
		}

	auto f = zeek::make_intrusive<zeek::detail::Frame>(frame_size, this, args);

	if ( closure )
		f->CaptureClosure(closure, outer_ids);

	// Hand down any trigger.
	if ( parent )
		{
		f->SetTrigger({zeek::NewRef{}, parent->GetTrigger()});
		f->SetCall(parent->GetCall());
		}

	g_frame_stack.push_back(f.get());	// used for backtracing
	const zeek::detail::CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
	call_stack.emplace_back(CallInfo{call_expr, this, *args});

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		DescribeDebug(&d, args);

		g_trace_state.LogTrace("%s called: %s\n",
			GetType()->FlavorString().c_str(), d.Description());
		}

	StmtFlowType flow = FLOW_NEXT;
	zeek::ValPtr result;

	for ( const auto& body : bodies )
		{
		if ( sample_logger )
			sample_logger->LocationSeen(
				body.stmts->GetLocationInfo());

		// Fill in the rest of the frame with the function's arguments.
		for ( auto j = 0u; j < args->size(); ++j )
			{
			const auto& arg = (*args)[j];

			if ( f->GetElement(j) != arg )
				// Either not yet set, or somebody reassigned the frame slot.
				f->SetElement(j, arg);
			}

		f->Reset(args->size());

		try
			{
			result = body.stmts->Exec(f.get(), flow);
			}

		catch ( InterpreterException& e )
			{
			// Already reported, but now determine whether to unwind further.
			if ( Flavor() == zeek::FUNC_FLAVOR_FUNCTION )
				{
				g_frame_stack.pop_back();
				call_stack.pop_back();
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

		if ( Flavor() == zeek::FUNC_FLAVOR_HOOK )
			{
			// Ignore any return values of hook bodies, final return value
			// depends on whether a body returns as a result of break statement.
			result = nullptr;

			if ( flow == FLOW_BREAK )
				{
				// Short-circuit execution of remaining hook handler bodies.
				result = zeek::val_mgr->False();
				break;
				}
			}
		}

	call_stack.pop_back();

	if ( Flavor() == zeek::FUNC_FLAVOR_HOOK )
		{
		if ( ! result )
			result = zeek::val_mgr->True();
		}

	// Warn if the function returns something, but we returned from
	// the function without an explicit return, or without a value.
	else if ( GetType()->Yield() && GetType()->Yield()->Tag() != zeek::TYPE_VOID &&
		 (flow != FLOW_RETURN /* we fell off the end */ ||
		  ! result /* explicit return with no result */) &&
		 ! f->HasDelayed() )
		zeek::reporter->Warning("non-void function returning without a value: %s",
		                        Name());

	if ( result && g_trace_state.DoTrace() )
		{
		ODesc d;
		result->Describe(&d);

		g_trace_state.LogTrace("Function return: %s\n", d.Description());
		}

	g_frame_stack.pop_back();

	return result;
	}

void ScriptFunc::AddBody(zeek::detail::StmtPtr new_body,
                         const std::vector<zeek::detail::IDPtr>& new_inits,
                         size_t new_frame_size, int priority)
	{
	if ( new_frame_size > frame_size )
		frame_size = new_frame_size;

	auto num_args = GetType()->Params()->NumFields();

	if ( num_args > static_cast<int>(frame_size) )
		frame_size = num_args;

	new_body = AddInits(std::move(new_body), new_inits);

	if ( Flavor() == zeek::FUNC_FLAVOR_FUNCTION )
		{
		// For functions, we replace the old body with the new one.
		assert(bodies.size() <= 1);
		bodies.clear();
		}

	Body b;
	b.stmts = new_body;
	b.priority = priority;

	bodies.push_back(b);
	sort(bodies.begin(), bodies.end());
	}

void ScriptFunc::AddClosure(id_list ids, zeek::detail::Frame* f)
	{
	if ( ! f )
		return;

	SetOuterIDs(std::move(ids));
	SetClosureFrame(f);
	}

bool ScriptFunc::StrengthenClosureReference(zeek::detail::Frame* f)
	{
	if ( closure != f )
		return false;

	if ( ! weak_closure_ref )
		return false;

	closure = closure->SelectiveClone(outer_ids, this);
	weak_closure_ref = false;
	return true;
	}

void ScriptFunc::SetClosureFrame(zeek::detail::Frame* f)
	{
	if ( closure )
		zeek::reporter->InternalError("Tried to override closure for ScriptFunc %s.",
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

bool ScriptFunc::UpdateClosure(const broker::vector& data)
	{
	auto result = zeek::detail::Frame::Unserialize(data);

	if ( ! result.first )
		return false;

	auto& new_closure = result.second;

	if ( new_closure )
		new_closure->SetFunction(this);

	if ( ! weak_closure_ref )
		Unref(closure);

	weak_closure_ref = false;
	closure = new_closure.release();

	return true;
	}


zeek::FuncPtr ScriptFunc::DoClone()
	{
	// ScriptFunc could hold a closure. In this case a clone of it must
	// store a copy of this closure.
	auto other = zeek::IntrusivePtr{zeek::AdoptRef{}, new ScriptFunc()};

	CopyStateInto(other.get());

	other->frame_size = frame_size;
	other->closure = closure ? closure->SelectiveClone(outer_ids, this) : nullptr;
	other->weak_closure_ref = false;
	other->outer_ids = outer_ids;

	return other;
	}

broker::expected<broker::data> ScriptFunc::SerializeClosure() const
	{
	return zeek::detail::Frame::Serialize(closure, outer_ids);
	}

void ScriptFunc::Describe(ODesc* d) const
	{
	d->Add(Name());

	d->NL();
	d->AddCount(frame_size);
	for ( const auto& body : bodies )
		{
		body.stmts->AccessStats(d);
		body.stmts->Describe(d);
		}
	}

zeek::detail::StmtPtr ScriptFunc::AddInits(
	zeek::detail::StmtPtr body,
	const std::vector<zeek::detail::IDPtr>& inits)
	{
	if ( inits.empty() )
		return body;

	auto stmt_series = zeek::make_intrusive<zeek::detail::StmtList>();
	stmt_series->Stmts().push_back(new zeek::detail::InitStmt(inits));
	stmt_series->Stmts().push_back(body.release());

	return stmt_series;
	}

BuiltinFunc::BuiltinFunc(built_in_func arg_func, const char* arg_name,
                         bool arg_is_pure)
: Func(BUILTIN_FUNC)
	{
	func = arg_func;
	name = make_full_var_name(GLOBAL_MODULE_NAME, arg_name);
	is_pure = arg_is_pure;

	const auto& id = zeek::detail::lookup_ID(Name(), GLOBAL_MODULE_NAME, false);
	if ( ! id )
		zeek::reporter->InternalError("built-in function %s missing", Name());
	if ( id->HasVal() )
		zeek::reporter->InternalError("built-in function %s multiply defined", Name());

	type = id->GetType<zeek::FuncType>();
	id->SetVal(zeek::make_intrusive<zeek::Val>(zeek::IntrusivePtr{zeek::NewRef{}, this}));
	}

BuiltinFunc::~BuiltinFunc()
	{
	}

bool BuiltinFunc::IsPure() const
	{
	return is_pure;
	}

zeek::ValPtr BuiltinFunc::Invoke(zeek::Args* args, zeek::detail::Frame* parent) const
	{
#ifdef PROFILE_BRO_FUNCTIONS
	DEBUG_MSG("Function: %s\n", Name());
#endif
	SegmentProfiler prof(segment_logger, Name());

	if ( sample_logger )
		sample_logger->FunctionSeen(this);

	auto [handled, hook_result] = PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION,
	                                                      HookCallFunction(this, parent, args),
	                                                      empty_hook_result);

	CheckPluginResult(handled, hook_result, zeek::FUNC_FLAVOR_FUNCTION);

	if ( handled )
		return hook_result;

	if ( g_trace_state.DoTrace() )
		{
		ODesc d;
		DescribeDebug(&d, args);

		g_trace_state.LogTrace("\tBuiltin Function called: %s\n", d.Description());
		}

	const zeek::detail::CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
	call_stack.emplace_back(CallInfo{call_expr, this, *args});
	auto result = std::move(func(parent, args).rval);
	call_stack.pop_back();

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

bool check_built_in_call(BuiltinFunc* f, zeek::detail::CallExpr* call)
	{
	if ( f->TheFunc() != zeek::BifFunc::fmt_bif)
		return true;

	const expr_list& args = call->Args()->Exprs();
	if ( args.length() == 0 )
		{
		// Empty calls are allowed, since you can't just
		// use "print;" to get a blank line.
		return true;
		}

	const zeek::detail::Expr* fmt_str_arg = args[0];
	if ( fmt_str_arg->GetType()->Tag() != zeek::TYPE_STRING )
		{
		call->Error("first argument to zeek::util::fmt() needs to be a format string");
		return false;
		}

	auto fmt_str_val = fmt_str_arg->Eval(nullptr);

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
			call->Error("mismatch between format string to zeek::util::fmt() and number of arguments passed");
			return false;
			}
		}

	return true;
	}

// Gets a function's priority from its Scope's attributes. Errors if it sees any
// problems.
static int get_func_priority(const std::vector<zeek::detail::AttrPtr>& attrs)
	{
	int priority = 0;

	for ( const auto& a : attrs )
		{
		if ( a->Tag() == zeek::detail::ATTR_DEPRECATED )
			continue;

		if ( a->Tag() != zeek::detail::ATTR_PRIORITY )
			{
			a->Error("illegal attribute for function body");
			continue;
			}

		auto v = a->GetExpr()->Eval(nullptr);

		if ( ! v )
			{
			a->Error("cannot evaluate attribute expression");
			continue;
			}

		if ( ! zeek::IsIntegral(v->GetType()->Tag()) )
			{
			a->Error("expression is not of integral type");
			continue;
			}

		priority = v->InternalInt();
		}

	return priority;
	}

function_ingredients::function_ingredients(zeek::detail::ScopePtr scope, zeek::detail::StmtPtr body)
	{
	frame_size = scope->Length();
	inits = scope->GetInits();

	this->scope = std::move(scope);
	id = this->scope->GetID();

	const auto& attrs = this->scope->Attrs();

	priority = (attrs ? get_func_priority(*attrs) : 0);
	this->body = std::move(body);
	}

static void emit_builtin_error_common(const char* msg, Obj* arg, bool unwind)
	{
	auto emit = [=](const zeek::detail::CallExpr* ce)
		{
		if ( ce )
			{
			if ( unwind )
				{
				if ( arg )
					{
					ODesc d;
					arg->Describe(&d);
					zeek::reporter->ExprRuntimeError(ce, "%s (%s), during call:", msg,
					                                 d.Description());
					}
				else
					zeek::reporter->ExprRuntimeError(ce, "%s", msg);
				}
			else
				ce->Error(msg, arg);
			}
		else
			{
			if ( arg )
				{
				if ( unwind )
					zeek::reporter->RuntimeError(arg->GetLocationInfo(), "%s", msg);
				else
					arg->Error(msg);
				}
			else
				{
				if ( unwind )
					zeek::reporter->RuntimeError(nullptr, "%s", msg);
				else
					zeek::reporter->Error("%s", msg);
				}
			}
		};


	if ( zeek::detail::call_stack.empty() )
		{
		// Shouldn't happen unless someone (mistakenly) calls builtin_error()
		// from somewhere that's not even evaluating script-code.
		emit(nullptr);
		return;
		}

	auto last_call = zeek::detail::call_stack.back();

	if ( zeek::detail::call_stack.size() < 2 )
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

	auto parent_call = zeek::detail::call_stack[zeek::detail::call_stack.size() - 2];
	auto parent_func = parent_call.func->Name();

	if ( wrapper_func == parent_func )
		emit(parent_call.call);
	else
		emit(last_call.call);
	}

void emit_builtin_exception(const char* msg)
	{
	emit_builtin_error_common(msg, nullptr, true);
	}

void emit_builtin_exception(const char* msg, const zeek::ValPtr& arg)
	{
	emit_builtin_error_common(msg, arg.get(), true);
	}

void emit_builtin_exception(const char* msg, Obj* arg)
	{
	emit_builtin_error_common(msg, arg, true);
	}

} // namespace detail


void emit_builtin_error(const char* msg)
	{
	zeek::detail::emit_builtin_error_common(msg, nullptr, false);
	}

void emit_builtin_error(const char* msg, const zeek::ValPtr& arg)
	{
	zeek::detail::emit_builtin_error_common(msg, arg.get(), false);
	}

void emit_builtin_error(const char* msg, Obj* arg)
	{
	zeek::detail::emit_builtin_error_common(msg, arg, false);
	}

} // namespace zeek

void builtin_error(const char* msg)
	{
	zeek::emit_builtin_error(msg);
	}

void builtin_error(const char* msg, const zeek::ValPtr& arg)
	{
	zeek::emit_builtin_error(msg, arg);
	}

void builtin_error(const char* msg, zeek::Obj* arg)
	{
	zeek::emit_builtin_error(msg, arg);
	}

#include "__all__.bif.cc" // Autogenerated for compiling in the bif_target() code.
#include "__all__.bif.register.cc" // Autogenerated for compiling in the bif_target() code.

void init_builtin_funcs()
	{
	ProcStats = zeek::id::find_type<zeek::RecordType>("ProcStats");
	NetStats = zeek::id::find_type<zeek::RecordType>("NetStats");
	MatcherStats = zeek::id::find_type<zeek::RecordType>("MatcherStats");
	ConnStats = zeek::id::find_type<zeek::RecordType>("ConnStats");
	ReassemblerStats = zeek::id::find_type<zeek::RecordType>("ReassemblerStats");
	DNSStats = zeek::id::find_type<zeek::RecordType>("DNSStats");
	GapStats = zeek::id::find_type<zeek::RecordType>("GapStats");
	EventStats = zeek::id::find_type<zeek::RecordType>("EventStats");
	TimerStats = zeek::id::find_type<zeek::RecordType>("TimerStats");
	FileAnalysisStats = zeek::id::find_type<zeek::RecordType>("FileAnalysisStats");
	ThreadStats = zeek::id::find_type<zeek::RecordType>("ThreadStats");
	BrokerStats = zeek::id::find_type<zeek::RecordType>("BrokerStats");
	ReporterStats = zeek::id::find_type<zeek::RecordType>("ReporterStats");

	var_sizes = zeek::id::find_type("var_sizes")->AsTableType();

#include "zeek.bif.func_init"
#include "stats.bif.func_init"
#include "reporter.bif.func_init"
#include "strings.bif.func_init"
#include "option.bif.func_init"
#include "supervisor.bif.func_init"

	zeek::detail::did_builtin_init = true;
	}

void init_builtin_funcs_subdirs()
	{
#include "__all__.bif.init.cc" // Autogenerated for compiling in the bif_target() code.
	}
