// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "Var.h"

#include <memory>

#include "Val.h"
#include "Expr.h"
#include "Func.h"
#include "IntrusivePtr.h"
#include "Stmt.h"
#include "Scope.h"
#include "Reporter.h"
#include "EventRegistry.h"
#include "Traverse.h"
#include "module_util.h"
#include "ID.h"

using namespace zeek::detail;

static zeek::ValPtr init_val(zeek::detail::Expr* init,
                             const zeek::Type* t,
                             zeek::ValPtr aggr)
	{
	try
		{
		return init->InitVal(t, std::move(aggr));
		}
	catch ( InterpreterException& e )
		{
		return nullptr;
		}
	}

static bool add_prototype(const zeek::detail::IDPtr& id, zeek::Type* t,
                          std::vector<AttrPtr>* attrs,
                          const zeek::detail::ExprPtr& init)
	{
	if ( ! zeek::IsFunc(id->GetType()->Tag()) )
		return false;

	if ( ! zeek::IsFunc(t->Tag()) )
		{
		t->Error("type incompatible with previous definition", id.get());
		return false;
		}

	auto canon_ft = id->GetType()->AsFuncType();
	auto alt_ft = t->AsFuncType();

	if ( canon_ft->Flavor() != alt_ft->Flavor() )
		{
		alt_ft->Error("incompatible function flavor", canon_ft);
		return false;
		}

	if ( canon_ft->Flavor() == zeek::FUNC_FLAVOR_FUNCTION )
		{
		alt_ft->Error("redeclaration of function", canon_ft);
		return false;
		}

	if ( init )
		{
		init->Error("initialization not allowed during event/hook alternate prototype declaration");
		return false;
		}

	const auto& canon_args = canon_ft->Params();
	const auto& alt_args = alt_ft->Params();

	if ( auto p = canon_ft->FindPrototype(*alt_args); p )
		{
		alt_ft->Error("alternate function prototype already exists", p->args.get());
		return false;
		}

	std::map<int, int> offsets;

	for ( auto i = 0; i < alt_args->NumFields(); ++i )
		{
		auto field = alt_args->FieldName(i);

		if ( alt_args->FieldDecl(i)->attrs )
			{
			alt_ft->Error(fmt("alternate function prototype arguments may not have attributes: arg '%s'", field), canon_ft);
			return false;
			}

		auto o = canon_args->FieldOffset(field);

		if ( o < 0 )
			{
			alt_ft->Error(fmt("alternate function prototype arg '%s' not found in canonical prototype", field), canon_ft);
			return false;
			}

		offsets[i] = o;
		}

	auto deprecated = false;

	if ( attrs )
		for ( const auto& a : *attrs )
			if ( a->Tag() == zeek::detail::ATTR_DEPRECATED )
				deprecated = true;

	zeek::FuncType::Prototype p{deprecated, alt_args, std::move(offsets)};
	canon_ft->AddPrototype(std::move(p));
	return true;
	}

static void make_var(const zeek::detail::IDPtr& id, zeek::TypePtr t,
                     zeek::detail::InitClass c,
                     zeek::detail::ExprPtr init,
                     std::unique_ptr<std::vector<AttrPtr>> attr,
                     decl_type dt,
                     bool do_init)
	{
	if ( id->GetType() )
		{
		if ( id->IsRedefinable() || (! init && attr && ! zeek::IsFunc(id->GetType()->Tag())) )
			{
			zeek::Obj* redef_obj = init ? (zeek::Obj*) init.get() : (zeek::Obj*) t.get();
			if ( dt != VAR_REDEF )
				id->Warn("redefinition requires \"redef\"", redef_obj, true);
			}

		else if ( dt != VAR_REDEF || init || ! attr )
			{
			if ( zeek::IsFunc(id->GetType()->Tag()) )
				add_prototype(id, t.get(), attr.get(), init);
			else
				id->Error("already defined", init.get());

			return;
			}
		}

	if ( dt == VAR_REDEF )
		{
		if ( ! id->GetType() )
			{
			id->Error("\"redef\" used but not previously defined");
			return;
			}

		if ( ! t )
			t = id->GetType();
		}

	if ( id->GetType() && id->GetType()->Tag() != zeek::TYPE_ERROR )
		{
		if ( dt != VAR_REDEF &&
 		     (! init || ! do_init || (! t && ! (t = zeek::init_type(init.get())))) )
			{
			id->Error("already defined", init.get());
			return;
			}

		// Allow redeclaration in order to initialize.
		if ( ! same_type(t, id->GetType()) )
			{
			id->Error("redefinition changes type", init.get());
			return;
			}
		}

	if ( t && t->IsSet() )
		{ // Check for set with explicit elements.
		zeek::SetType* st = t->AsTableType()->AsSetType();
		const auto& elements = st->Elements();

		if ( elements )
			{
			if ( init )
				{
				id->Error("double initialization", init.get());
				return;
				}

			init = elements;
			}
		}

	if ( ! t )
		{ // Take type from initialization.
		if ( ! init )
			{
			id->Error("no type given");
			return;
			}

		t = zeek::init_type(init.get());
		if ( ! t )
			{
			id->SetType(zeek::error_type());
			return;
			}
		}

	id->SetType(t);

	if ( attr )
		id->AddAttrs(zeek::make_intrusive<zeek::detail::Attributes>(std::move(*attr), t, false, id->IsGlobal()));

	if ( init )
		{
		switch ( init->Tag() ) {
		case zeek::detail::EXPR_TABLE_CONSTRUCTOR:
			{
			auto* ctor = static_cast<zeek::detail::TableConstructorExpr*>(init.get());
			if ( ctor->GetAttrs() )
				id->AddAttrs(ctor->GetAttrs());
			}
			break;

		case zeek::detail::EXPR_SET_CONSTRUCTOR:
			{
			auto* ctor = static_cast<zeek::detail::SetConstructorExpr*>(init.get());
			if ( ctor->GetAttrs() )
				id->AddAttrs(ctor->GetAttrs());
			}
			break;

		default:
			break;
		}
		}

	if ( do_init )
		{
		if ( c == zeek::detail::INIT_NONE && dt == VAR_REDEF && t->IsTable() &&
		     init && init->Tag() == zeek::detail::EXPR_ASSIGN )
			// e.g. 'redef foo["x"] = 1' is missing an init class, but the
			// intention clearly isn't to overwrite entire existing table val.
			c = zeek::detail::INIT_EXTRA;

		if ( init && ((c == zeek::detail::INIT_EXTRA && id->GetAttr(zeek::detail::ATTR_ADD_FUNC)) ||
		              (c == zeek::detail::INIT_REMOVE && id->GetAttr(zeek::detail::ATTR_DEL_FUNC)) ))
			// Just apply the function.
			id->SetVal(init, c);

		else if ( dt != VAR_REDEF || init || ! attr )
			{
			zeek::ValPtr aggr;

			if ( t->Tag() == zeek::TYPE_RECORD )
				{
				aggr = zeek::make_intrusive<zeek::RecordVal>(zeek::cast_intrusive<zeek::RecordType>(t));

				if ( init && t )
					// Have an initialization and type is not deduced.
					init = zeek::make_intrusive<zeek::detail::RecordCoerceExpr>(
						std::move(init),
						zeek::IntrusivePtr{zeek::NewRef{}, t->AsRecordType()});
				}

			else if ( t->Tag() == zeek::TYPE_TABLE )
				aggr = zeek::make_intrusive<zeek::TableVal>(zeek::cast_intrusive<zeek::TableType>(t),
				                                id->GetAttrs());

			else if ( t->Tag() == zeek::TYPE_VECTOR )
				aggr = zeek::make_intrusive<zeek::VectorVal>(zeek::cast_intrusive<zeek::VectorType>(t));

			zeek::ValPtr v;

			if ( init )
				{
				v = init_val(init.get(), t.get(), aggr);

				if ( ! v )
					return;
				}

			if ( aggr )
				id->SetVal(std::move(aggr), c);
			else if ( v )
				id->SetVal(std::move(v), c);
			}
		}

	if ( dt == VAR_CONST )
		{
		if ( ! init && ! id->IsRedefinable() )
			id->Error("const variable must be initialized");

		id->SetConst();
		}

	if ( dt == VAR_OPTION )
		{
		if ( ! init )
			id->Error("option variable must be initialized");

		id->SetOption();
		}

	id->UpdateValAttrs();

	if ( t && t->Tag() == zeek::TYPE_FUNC &&
	     (t->AsFuncType()->Flavor() == zeek::FUNC_FLAVOR_EVENT ||
	      t->AsFuncType()->Flavor() == zeek::FUNC_FLAVOR_HOOK) )
		{
		// For events, add a function value (without any body) here so that
		// we can later access the ID even if no implementations have been
		// defined.
		std::vector<zeek::detail::IDPtr> inits;
		auto f = zeek::make_intrusive<zeek::detail::ScriptFunc>(id, nullptr, inits, 0, 0);
		id->SetVal(zeek::make_intrusive<zeek::Val>(std::move(f)));
		}
	}

void add_global(
	const zeek::detail::IDPtr& id,
	zeek::TypePtr t,
	zeek::detail::InitClass c, zeek::detail::ExprPtr init,
	std::unique_ptr<std::vector<AttrPtr>> attr,
	decl_type dt)
	{
	make_var(id, std::move(t), c, std::move(init), std::move(attr), dt, true);
	}

zeek::detail::StmtPtr add_local(
	zeek::detail::IDPtr id, zeek::TypePtr t,
	zeek::detail::InitClass c, zeek::detail::ExprPtr init,
	std::unique_ptr<std::vector<AttrPtr>> attr,
	decl_type dt)
	{
	make_var(id, std::move(t), c, init, std::move(attr), dt, false);

	if ( init )
		{
		if ( c != zeek::detail::INIT_FULL )
			id->Error("can't use += / -= for initializations of local variables");

		// copy Location to the stack, because AssignExpr may free "init"
		const zeek::detail::Location location = init->GetLocationInfo() ?
			*init->GetLocationInfo() : zeek::detail::no_location;

		auto name_expr = zeek::make_intrusive<zeek::detail::NameExpr>(id, dt == VAR_CONST);
		auto assign_expr = zeek::make_intrusive<zeek::detail::AssignExpr>(std::move(name_expr),
		                                                            std::move(init), 0,
		                                                            nullptr, id->GetAttrs());
		auto stmt = zeek::make_intrusive<zeek::detail::ExprStmt>(std::move(assign_expr));
		stmt->SetLocationInfo(&location);
		return stmt;
		}

	else
		{
		zeek::detail::current_scope()->AddInit(std::move(id));
		return zeek::make_intrusive<zeek::detail::NullStmt>();
		}
	}

extern zeek::detail::ExprPtr add_and_assign_local(
	zeek::detail::IDPtr id,
	zeek::detail::ExprPtr init,
	zeek::ValPtr val)
	{
	make_var(id, nullptr, zeek::detail::INIT_FULL, init, nullptr, VAR_REGULAR, false);
	auto name_expr = zeek::make_intrusive<zeek::detail::NameExpr>(std::move(id));
	return zeek::make_intrusive<zeek::detail::AssignExpr>(
		std::move(name_expr), std::move(init), false, std::move(val));
	}

void add_type(zeek::detail::ID* id, zeek::TypePtr t,
              std::unique_ptr<std::vector<AttrPtr>> attr)
	{
	std::string new_type_name = id->Name();
	std::string old_type_name = t->GetName();
	zeek::TypePtr tnew;

	if ( (t->Tag() == zeek::TYPE_RECORD || t->Tag() == zeek::TYPE_ENUM) &&
	     old_type_name.empty() )
		// An extensible type (record/enum) being declared for first time.
		tnew = std::move(t);
	else
		// Clone the type to preserve type name aliasing.
		tnew = t->ShallowClone();

	zeek::Type::AddAlias(new_type_name, tnew.get());

	if ( new_type_name != old_type_name && ! old_type_name.empty() )
		zeek::Type::AddAlias(old_type_name, tnew.get());

	tnew->SetName(id->Name());

	id->SetType(tnew);
	id->MakeType();

	if ( attr )
		id->SetAttrs(zeek::make_intrusive<zeek::detail::Attributes>(std::move(*attr), tnew, false, false));
	}

static void transfer_arg_defaults(zeek::RecordType* args, zeek::RecordType* recv)
	{
	for ( int i = 0; i < args->NumFields(); ++i )
		{
		zeek::TypeDecl* args_i = args->FieldDecl(i);
		zeek::TypeDecl* recv_i = recv->FieldDecl(i);

		const auto& def = args_i->attrs ? args_i->attrs->Find(zeek::detail::ATTR_DEFAULT) : nullptr;

		if ( ! def )
			continue;

		if ( ! recv_i->attrs )
			{
			std::vector<AttrPtr> a{def};
			recv_i->attrs = zeek::make_intrusive<zeek::detail::Attributes>(std::move(a),
			                                                               recv_i->type,
			                                                               true, false);
			}

		else if ( ! recv_i->attrs->Find(zeek::detail::ATTR_DEFAULT) )
			recv_i->attrs->AddAttr(def);
		}
	}

static zeek::detail::Attr* find_attr(const std::vector<AttrPtr>* al,
                                     zeek::detail::AttrTag tag)
	{
	if ( ! al )
		return nullptr;

	for ( size_t i = 0; i < al->size(); ++i )
		if ( (*al)[i]->Tag() == tag )
			return (*al)[i].get();

	return nullptr;
	}

static std::optional<zeek::FuncType::Prototype> func_type_check(const zeek::FuncType* decl, const zeek::FuncType* impl)
	{
	if ( decl->Flavor() != impl->Flavor() )
		{
		impl->Error("incompatible function flavor", decl);
		return {};
		}

	if ( impl->Flavor() == zeek::FUNC_FLAVOR_FUNCTION )
		{
		if ( same_type(decl, impl) )
			return decl->Prototypes()[0];

		impl->Error("incompatible function types", decl);
		return {};
		}

	auto rval = decl->FindPrototype(*impl->Params());

	if ( rval )
		for ( auto i = 0; i < rval->args->NumFields(); ++i )
			if ( rval->args->FieldDecl(i)->GetAttr(zeek::detail::ATTR_DEPRECATED) )
				impl->Warn(fmt("use of deprecated parameter '%s'",
				               rval->args->FieldName(i)), decl, true);

	return rval;
	}

static bool canonical_arg_types_match(const zeek::FuncType* decl, const zeek::FuncType* impl)
	{
	const auto& canon_args = decl->Params();
	const auto& impl_args = impl->Params();

	if ( canon_args->NumFields() != impl_args->NumFields() )
		return false;

	for ( auto i = 0; i < canon_args->NumFields(); ++i )
		if ( ! same_type(canon_args->GetFieldType(i), impl_args->GetFieldType(i)) )
			return false;

	return true;
	}

void begin_func(zeek::detail::IDPtr id, const char* module_name,
                zeek::FunctionFlavor flavor, bool is_redef,
                zeek::FuncTypePtr t,
                std::unique_ptr<std::vector<AttrPtr>> attrs)
	{
	if ( flavor == zeek::FUNC_FLAVOR_EVENT )
		{
		const auto& yt = t->Yield();

		if ( yt && yt->Tag() != zeek::TYPE_VOID )
			id->Error("event cannot yield a value", t.get());

		t->ClearYieldType(flavor);
		}

	std::optional<zeek::FuncType::Prototype> prototype;

	if ( id->GetType() )
		{
		auto decl = id->GetType()->AsFuncType();
		prototype = func_type_check(decl, t.get());

		if ( prototype )
			{
			if ( decl->Flavor() == zeek::FUNC_FLAVOR_FUNCTION )
				{
				// If a previous declaration of the function had &default
				// params, automatically transfer any that are missing
				// (convenience so that implementations don't need to specify
				// the &default expression again).
				transfer_arg_defaults(prototype->args.get(), t->Params().get());
				}
			else
				{
				// Warn for trying to use &default parameters in hook/event
				// handler body when it already has a declaration since only
				// &default in the declaration has any effect.
				const auto& args = t->Params();

				for ( int i = 0; i < args->NumFields(); ++i )
					{
					auto f = args->FieldDecl(i);

					if ( f->attrs && f->attrs->Find(zeek::detail::ATTR_DEFAULT) )
						{
						reporter->PushLocation(args->GetLocationInfo());
						reporter->Warning(
						    "&default on parameter '%s' has no effect (not a %s declaration)",
						    args->FieldName(i), t->FlavorString().data());
						reporter->PopLocation();
						}
					}
				}

			if ( prototype->deprecated )
				t->Warn("use of deprecated prototype", id.get());
			}
		else
			{
			// Allow renaming arguments, but only for the canonical
			// prototypes of hooks/events.
			if ( canonical_arg_types_match(decl, t.get()) )
				prototype = decl->Prototypes()[0];
			else
				t->Error("use of undeclared alternate prototype", id.get());
			}
		}

	else if ( is_redef )
		id->Error("redef of not-previously-declared value");

	if ( id->HasVal() )
		{
		zeek::FunctionFlavor id_flavor = id->GetVal()->AsFunc()->Flavor();

		if ( id_flavor != flavor )
			id->Error("inconsistent function flavor", t.get());

		switch ( id_flavor ) {

		case zeek::FUNC_FLAVOR_EVENT:
		case zeek::FUNC_FLAVOR_HOOK:
			if ( is_redef )
				// Clear out value so it will be replaced.
				id->SetVal(nullptr);
			break;

		case zeek::FUNC_FLAVOR_FUNCTION:
			if ( ! id->IsRedefinable() )
				id->Error("already defined");
			break;

		default:
			reporter->InternalError("invalid function flavor");
			break;
		}
		}
	else
		id->SetType(t);

	zeek::detail::push_scope(std::move(id), std::move(attrs));

	const auto& args = t->Params();
	int num_args = args->NumFields();

	for ( int i = 0; i < num_args; ++i )
		{
		zeek::TypeDecl* arg_i = args->FieldDecl(i);
		auto arg_id = zeek::detail::lookup_ID(arg_i->id, module_name);

		if ( arg_id && ! arg_id->IsGlobal() )
			arg_id->Error("argument name used twice");

		arg_id = zeek::detail::install_ID(arg_i->id, module_name, false, false);
		arg_id->SetType(arg_i->type);

		if ( prototype )
			arg_id->SetOffset(prototype->offsets[i]);
		}

	if ( zeek::detail::Attr* depr_attr = find_attr(zeek::detail::current_scope()->Attrs().get(),
	                                               zeek::detail::ATTR_DEPRECATED) )
		zeek::detail::current_scope()->GetID()->MakeDeprecated(depr_attr->GetExpr());
	}

class OuterIDBindingFinder : public TraversalCallback {
public:
	OuterIDBindingFinder(zeek::detail::Scope* s)
		{
		scopes.emplace_back(s);
		}

	TraversalCode PreExpr(const zeek::detail::Expr*) override;
	TraversalCode PostExpr(const zeek::detail::Expr*) override;

	std::vector<zeek::detail::Scope*> scopes;
	std::vector<const zeek::detail::NameExpr*> outer_id_references;
};

TraversalCode OuterIDBindingFinder::PreExpr(const zeek::detail::Expr* expr)
	{
	if ( expr->Tag() == zeek::detail::EXPR_LAMBDA )
		{
		auto le = static_cast<const zeek::detail::LambdaExpr*>(expr);
		scopes.emplace_back(le->GetScope());
		return TC_CONTINUE;
		}

	if ( expr->Tag() != zeek::detail::EXPR_NAME )
		return TC_CONTINUE;

	auto* e = static_cast<const zeek::detail::NameExpr*>(expr);

	if ( e->Id()->IsGlobal() )
		return TC_CONTINUE;

	for ( const auto& scope : scopes )
		if ( scope->Find(e->Id()->Name()) )
			// Shadowing is not allowed, so if it's found at inner scope, it's
			// not something we have to worry about also being at outer scope.
			return TC_CONTINUE;

	outer_id_references.push_back(e);
	return TC_CONTINUE;
	}

TraversalCode OuterIDBindingFinder::PostExpr(const zeek::detail::Expr* expr)
	{
	if ( expr->Tag() == zeek::detail::EXPR_LAMBDA )
		scopes.pop_back();

	return TC_CONTINUE;
	}

void end_func(zeek::detail::StmtPtr body)
	{
	auto ingredients = std::make_unique<zeek::detail::function_ingredients>(zeek::detail::pop_scope(),
	                                                                        std::move(body));

	if ( ingredients->id->HasVal() )
		ingredients->id->GetVal()->AsFunc()->AddBody(
			ingredients->body,
			ingredients->inits,
			ingredients->frame_size,
			ingredients->priority);
	else
		{
		auto f = zeek::make_intrusive<zeek::detail::ScriptFunc>(
			ingredients->id,
			ingredients->body,
			ingredients->inits,
			ingredients->frame_size,
			ingredients->priority);

		ingredients->id->SetVal(zeek::make_intrusive<zeek::Val>(std::move(f)));
		ingredients->id->SetConst();
		}

	ingredients->id->GetVal()->AsFunc()->SetScope(ingredients->scope);
	// Note: ideally, something would take ownership of this memory until the
	// end of script execution, but that's essentially the same as the
	// lifetime of the process at the moment, so ok to "leak" it.
	ingredients.release();
	}

zeek::Val* internal_val(const char* name)
	{
	return zeek::id::find_val(name).get();
	}

id_list gather_outer_ids(zeek::detail::Scope* scope, zeek::detail::Stmt* body)
	{
	OuterIDBindingFinder cb(scope);
	body->Traverse(&cb);

	id_list idl ( cb.outer_id_references.size() );

	for ( size_t i = 0; i < cb.outer_id_references.size(); ++i )
		{
		auto id = cb.outer_id_references[i]->Id();

		if ( idl.is_member(id) )
			continue;

		idl.append(id);
		}

	return idl;
	}

zeek::Val* internal_const_val(const char* name)
	{
	return zeek::id::find_const(name).get();
	}

zeek::Val* opt_internal_val(const char* name)
	{
	const auto& id = zeek::detail::lookup_ID(name, GLOBAL_MODULE_NAME);
	return id ? id->GetVal().get() : nullptr;
	}

double opt_internal_double(const char* name)
	{
	const auto& id = zeek::detail::lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return 0.0;
	const auto& v = id->GetVal();
	return v ? v->InternalDouble() : 0.0;
	}

bro_int_t opt_internal_int(const char* name)
	{
	const auto& id = zeek::detail::lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return 0;
	const auto& v = id->GetVal();
	return v ? v->InternalInt() : 0;
	}

bro_uint_t opt_internal_unsigned(const char* name)
	{
	const auto& id = zeek::detail::lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return 0;
	const auto& v = id->GetVal();
	return v ? v->InternalUnsigned() : 0;
	}

zeek::StringVal* opt_internal_string(const char* name)
	{
	const auto& id = zeek::detail::lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return nullptr;
	const auto& v = id->GetVal();
	return v ? v->AsStringVal() : nullptr;
	}

zeek::TableVal* opt_internal_table(const char* name)
	{
	const auto& id = zeek::detail::lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return nullptr;
	const auto& v = id->GetVal();
	return v ? v->AsTableVal() : nullptr;
	}

zeek::ListVal* internal_list_val(const char* name)
	{
	const auto& id = zeek::detail::lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		return nullptr;

	zeek::Val* v = id->GetVal().get();

	if ( v )
		{
		if ( v->GetType()->Tag() == zeek::TYPE_LIST )
			return (zeek::ListVal*) v;

		else if ( v->GetType()->IsSet() )
			{
			zeek::TableVal* tv = v->AsTableVal();
			auto lv = tv->ToPureListVal();
			return lv.release();
			}

		else
			reporter->InternalError("internal variable %s is not a list", name);
		}

	return nullptr;
	}

zeek::Type* internal_type(const char* name)
	{
	return zeek::id::find_type(name).get();
	}

zeek::Func* internal_func(const char* name)
	{
	const auto& v = zeek::id::find_val(name);

	if ( v )
		return v->AsFunc();
	else
		return nullptr;
	}

EventHandlerPtr internal_handler(const char* name)
	{
	return event_registry->Register(name);
	}
