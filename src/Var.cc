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

static IntrusivePtr<Val> init_val(Expr* init, const BroType* t,
                                  IntrusivePtr<Val> aggr)
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

static bool add_prototype(ID* id, BroType* t, attr_list* attrs,
                          const IntrusivePtr<Expr>& init)
	{
	if ( ! IsFunc(id->GetType()->Tag()) )
		return false;

	if ( ! IsFunc(t->Tag()) )
		{
		t->Error("type incompatible with previous definition", id);
		return false;
		}

	auto canon_ft = id->GetType()->AsFuncType();
	auto alt_ft = t->AsFuncType();

	if ( canon_ft->Flavor() != alt_ft->Flavor() )
		{
		alt_ft->Error("incompatible function flavor", canon_ft);
		return false;
		}

	if ( canon_ft->Flavor() == FUNC_FLAVOR_FUNCTION )
		{
		alt_ft->Error("redeclaration of function", canon_ft);
		return false;
		}

	if ( init )
		{
		init->Error("initialization not allowed during event/hook alternate prototype declaration");
		return false;
		}

	auto canon_args = canon_ft->Args();
	auto alt_args = alt_ft->Args();

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
			if ( a->Tag() == ATTR_DEPRECATED )
				deprecated = true;

	FuncType::Prototype p{deprecated, {NewRef{}, alt_args}, std::move(offsets)};
	canon_ft->AddPrototype(std::move(p));
	return true;
	}

static void make_var(ID* id, IntrusivePtr<BroType> t, init_class c,
                     IntrusivePtr<Expr> init, attr_list* attr, decl_type dt,
                     bool do_init)
	{
	if ( id->GetType() )
		{
		if ( id->IsRedefinable() || (! init && attr && ! IsFunc(id->GetType()->Tag())) )
			{
			BroObj* redef_obj = init ? (BroObj*) init.get() : (BroObj*) t.get();
			if ( dt != VAR_REDEF )
				id->Warn("redefinition requires \"redef\"", redef_obj, true);
			}

		else if ( dt != VAR_REDEF || init || ! attr )
			{
			if ( IsFunc(id->GetType()->Tag()) )
				add_prototype(id, t.get(), attr, init);
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

	if ( id->GetType() && id->GetType()->Tag() != TYPE_ERROR )
		{
		if ( dt != VAR_REDEF &&
		     (! init || ! do_init || (! t && ! (t = init_type(init.get())))) )
			{
			id->Error("already defined", init.get());
			return;
			}

		// Allow redeclaration in order to initialize.
		if ( ! same_type(t.get(), id->GetType().get()) )
			{
			id->Error("redefinition changes type", init.get());
			return;
			}
		}

	if ( t && t->IsSet() )
		{ // Check for set with explicit elements.
		SetType* st = t->AsTableType()->AsSetType();
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

		t = init_type(init.get());
		if ( ! t )
			{
			id->SetType(error_type());
			return;
			}
		}

	id->SetType(t);

	if ( attr )
		id->AddAttrs(make_intrusive<Attributes>(attr, t, false, id->IsGlobal()));

	if ( init )
		{
		switch ( init->Tag() ) {
		case EXPR_TABLE_CONSTRUCTOR:
			{
			TableConstructorExpr* ctor = (TableConstructorExpr*) init.get();
			if ( ctor->Attrs() )
				id->AddAttrs({NewRef{}, ctor->Attrs()});
			}
			break;

		case EXPR_SET_CONSTRUCTOR:
			{
			SetConstructorExpr* ctor = (SetConstructorExpr*) init.get();
			if ( ctor->Attrs() )
				id->AddAttrs({NewRef{}, ctor->Attrs()});
			}
			break;

		default:
			break;
		}
		}

	if ( do_init )
		{
		if ( c == INIT_NONE && dt == VAR_REDEF && t->IsTable() &&
		     init && init->Tag() == EXPR_ASSIGN )
			// e.g. 'redef foo["x"] = 1' is missing an init class, but the
			// intention clearly isn't to overwrite entire existing table val.
			c = INIT_EXTRA;

		if ( init && ((c == INIT_EXTRA && id->FindAttr(ATTR_ADD_FUNC)) ||
		              (c == INIT_REMOVE && id->FindAttr(ATTR_DEL_FUNC)) ))
			// Just apply the function.
			id->SetVal(init, c);

		else if ( dt != VAR_REDEF || init || ! attr )
			{
			IntrusivePtr<Val> aggr;

			if ( t->Tag() == TYPE_RECORD )
				{
				aggr = make_intrusive<RecordVal>(t->AsRecordType());

				if ( init && t )
					// Have an initialization and type is not deduced.
					init = make_intrusive<RecordCoerceExpr>(std::move(init),
					        IntrusivePtr{NewRef{}, t->AsRecordType()});
				}

			else if ( t->Tag() == TYPE_TABLE )
				aggr = make_intrusive<TableVal>(IntrusivePtr{NewRef{}, t->AsTableType()},
				                                IntrusivePtr{NewRef{}, id->Attrs()});

			else if ( t->Tag() == TYPE_VECTOR )
				aggr = make_intrusive<VectorVal>(cast_intrusive<VectorType>(t));

			IntrusivePtr<Val> v;

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

	if ( t && t->Tag() == TYPE_FUNC &&
	     (t->AsFuncType()->Flavor() == FUNC_FLAVOR_EVENT ||
	      t->AsFuncType()->Flavor() == FUNC_FLAVOR_HOOK) )
		{
		// For events, add a function value (without any body) here so that
		// we can later access the ID even if no implementations have been
		// defined.
		Func* f = new BroFunc(id, nullptr, nullptr, 0, 0);
		id->SetVal(make_intrusive<Val>(f));
		}
	}


void add_global(ID* id, IntrusivePtr<BroType> t, init_class c,
                IntrusivePtr<Expr> init, attr_list* attr, decl_type dt)
	{
	make_var(id, std::move(t), c, std::move(init), attr, dt, true);
	}

IntrusivePtr<Stmt> add_local(IntrusivePtr<ID> id, IntrusivePtr<BroType> t,
                             init_class c, IntrusivePtr<Expr> init,
                             attr_list* attr, decl_type dt)
	{
	make_var(id.get(), std::move(t), c, init, attr, dt, false);

	if ( init )
		{
		if ( c != INIT_FULL )
			id->Error("can't use += / -= for initializations of local variables");

		// copy Location to the stack, because AssignExpr may free "init"
		const Location location = init->GetLocationInfo() ?
		        *init->GetLocationInfo() : no_location;

		auto name_expr = make_intrusive<NameExpr>(id, dt == VAR_CONST);
		auto attrs = id->Attrs() ? id->Attrs()->Attrs() : nullptr;
		auto assign_expr = make_intrusive<AssignExpr>(std::move(name_expr),
		                                              std::move(init), 0,
		                                              nullptr, attrs);
		auto stmt = make_intrusive<ExprStmt>(std::move(assign_expr));
		stmt->SetLocationInfo(&location);
		return stmt;
		}

	else
		{
		current_scope()->AddInit(std::move(id));
		return make_intrusive<NullStmt>();
		}
	}

extern IntrusivePtr<Expr> add_and_assign_local(IntrusivePtr<ID> id,
                                               IntrusivePtr<Expr> init,
                                               IntrusivePtr<Val> val)
	{
	make_var(id.get(), nullptr, INIT_FULL, init, nullptr, VAR_REGULAR, false);
	auto name_expr = make_intrusive<NameExpr>(std::move(id));
	return make_intrusive<AssignExpr>(std::move(name_expr), std::move(init),
	                                  false, std::move(val));
	}

void add_type(ID* id, IntrusivePtr<BroType> t, attr_list* attr)
	{
	std::string new_type_name = id->Name();
	std::string old_type_name = t->GetName();
	IntrusivePtr<BroType> tnew;

	if ( (t->Tag() == TYPE_RECORD || t->Tag() == TYPE_ENUM) &&
	     old_type_name.empty() )
		// An extensible type (record/enum) being declared for first time.
		tnew = std::move(t);
	else
		// Clone the type to preserve type name aliasing.
		tnew = t->ShallowClone();

	BroType::AddAlias(new_type_name, tnew.get());

	if ( new_type_name != old_type_name && ! old_type_name.empty() )
		BroType::AddAlias(old_type_name, tnew.get());

	tnew->SetName(id->Name());

	id->SetType(tnew);
	id->MakeType();

	if ( attr )
		id->SetAttrs(make_intrusive<Attributes>(attr, tnew, false, false));
	}

static void transfer_arg_defaults(RecordType* args, RecordType* recv)
	{
	for ( int i = 0; i < args->NumFields(); ++i )
		{
		TypeDecl* args_i = args->FieldDecl(i);
		TypeDecl* recv_i = recv->FieldDecl(i);

		Attr* def = args_i->attrs ? args_i->attrs->FindAttr(ATTR_DEFAULT) : nullptr;

		if ( ! def )
			continue;

		if ( ! recv_i->attrs )
			{
			attr_list* a = new attr_list{def};
			recv_i->attrs = make_intrusive<Attributes>(a, recv_i->type, true, false);
			}

		else if ( ! recv_i->attrs->FindAttr(ATTR_DEFAULT) )
			recv_i->attrs->AddAttr({NewRef{}, def});
		}
	}

static Attr* find_attr(const attr_list* al, attr_tag tag)
	{
	if ( ! al )
		return nullptr;

	for ( int i = 0; i < al->length(); ++i )
		if ( (*al)[i]->Tag() == tag )
			return (*al)[i];

	return nullptr;
	}

static bool has_attr(const attr_list* al, attr_tag tag)
	{
	return find_attr(al, tag) != nullptr;
	}

static std::optional<FuncType::Prototype> func_type_check(const FuncType* decl, const FuncType* impl)
	{
	if ( decl->Flavor() != impl->Flavor() )
		{
		impl->Error("incompatible function flavor", decl);
		return {};
		}

	if ( impl->Flavor() == FUNC_FLAVOR_FUNCTION )
		{
		if ( same_type(decl, impl) )
			return decl->Prototypes()[0];

		impl->Error("incompatible function types", decl);
		return {};
		}

	return decl->FindPrototype(*impl->Args());
	}

static bool canonical_arg_types_match(const FuncType* decl, const FuncType* impl)
	{
	auto canon_args = decl->Args();
	auto impl_args = impl->Args();

	if ( canon_args->NumFields() != impl_args->NumFields() )
		return false;

	for ( auto i = 0; i < canon_args->NumFields(); ++i )
		if ( ! same_type(canon_args->GetFieldType(i).get(), impl_args->GetFieldType(i).get()) )
			return false;

	return true;
	}

void begin_func(ID* id, const char* module_name, function_flavor flavor,
                bool is_redef, IntrusivePtr<FuncType> t, attr_list* attrs)
	{
	if ( flavor == FUNC_FLAVOR_EVENT )
		{
		const auto& yt = t->Yield();

		if ( yt && yt->Tag() != TYPE_VOID )
			id->Error("event cannot yield a value", t.get());

		t->ClearYieldType(flavor);
		}

	std::optional<FuncType::Prototype> prototype;

	if ( id->GetType() )
		{
		auto decl = id->GetType()->AsFuncType();
		prototype = func_type_check(decl, t.get());

		if ( prototype )
			{
			if ( decl->Flavor() == FUNC_FLAVOR_FUNCTION )
				{
				// If a previous declaration of the function had &default
				// params, automatically transfer any that are missing
				// (convenience so that implementations don't need to specify
				// the &default expression again).
				transfer_arg_defaults(prototype->args.get(), t->Args());
				}
			else
				{
				// Warn for trying to use &default parameters in hook/event
				// handler body when it already has a declaration since only
				// &default in the declaration has any effect.
				auto args = t->Args();

				for ( int i = 0; i < args->NumFields(); ++i )
					{
					auto f = args->FieldDecl(i);

					if ( f->attrs && f->attrs->FindAttr(ATTR_DEFAULT) )
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
				t->Warn("use of deprecated prototype", id);
			}
		else
			{
			// Allow renaming arguments, but only for the canonical
			// prototypes of hooks/events.
			if ( canonical_arg_types_match(decl, t.get()) )
				prototype = decl->Prototypes()[0];
			else
				t->Error("use of undeclared alternate prototype", id);
			}
		}

	else if ( is_redef )
		id->Error("redef of not-previously-declared value");

	if ( id->HasVal() )
		{
		function_flavor id_flavor = id->GetVal()->AsFunc()->Flavor();

		if ( id_flavor != flavor )
			id->Error("inconsistent function flavor", t.get());

		switch ( id_flavor ) {

		case FUNC_FLAVOR_EVENT:
		case FUNC_FLAVOR_HOOK:
			if ( is_redef )
				// Clear out value so it will be replaced.
				id->SetVal(nullptr);
			break;

		case FUNC_FLAVOR_FUNCTION:
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

	push_scope({NewRef{}, id}, attrs);

	RecordType* args = t->Args();
	int num_args = args->NumFields();

	for ( int i = 0; i < num_args; ++i )
		{
		TypeDecl* arg_i = args->FieldDecl(i);
		auto arg_id = lookup_ID(arg_i->id, module_name);

		if ( arg_id && ! arg_id->IsGlobal() )
			arg_id->Error("argument name used twice");

		arg_id = install_ID(arg_i->id, module_name, false, false);
		arg_id->SetType(arg_i->type);

		if ( prototype )
			arg_id->SetOffset(prototype->offsets[i]);
		}

	if ( Attr* depr_attr = find_attr(attrs, ATTR_DEPRECATED) )
		id->MakeDeprecated({NewRef{}, depr_attr->AttrExpr()});
	}

class OuterIDBindingFinder : public TraversalCallback {
public:
	OuterIDBindingFinder(Scope* s)
		{
		scopes.emplace_back(s);
		}

	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	std::vector<Scope*> scopes;
	std::vector<const NameExpr*> outer_id_references;
};

TraversalCode OuterIDBindingFinder::PreExpr(const Expr* expr)
	{
	if ( expr->Tag() == EXPR_LAMBDA )
		{
		auto le = static_cast<const LambdaExpr*>(expr);
		scopes.emplace_back(le->GetScope());
		return TC_CONTINUE;
		}

	if ( expr->Tag() != EXPR_NAME )
		return TC_CONTINUE;

	const NameExpr* e = static_cast<const NameExpr*>(expr);

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

TraversalCode OuterIDBindingFinder::PostExpr(const Expr* expr)
	{
	if ( expr->Tag() == EXPR_LAMBDA )
		scopes.pop_back();

	return TC_CONTINUE;
	}

void end_func(IntrusivePtr<Stmt> body)
	{
	auto ingredients = std::make_unique<function_ingredients>(pop_scope(), std::move(body));

	if ( ingredients->id->HasVal() )
		ingredients->id->GetVal()->AsFunc()->AddBody(
			ingredients->body,
			ingredients->inits,
			ingredients->frame_size,
			ingredients->priority);
	else
		{
		Func* f = new BroFunc(
			ingredients->id.get(),
			ingredients->body,
			ingredients->inits,
			ingredients->frame_size,
			ingredients->priority);

		ingredients->id->SetVal(make_intrusive<Val>(f));
		ingredients->id->SetConst();
		}

	ingredients->id->GetVal()->AsFunc()->SetScope(ingredients->scope);
	// Note: ideally, something would take ownership of this memory until the
	// end of script execution, but that's essentially the same as the
	// lifetime of the process at the moment, so ok to "leak" it.
	ingredients.release();
	}

Val* internal_val(const char* name)
	{
	return zeek::id::lookup_val(name).get();
	}

id_list gather_outer_ids(Scope* scope, Stmt* body)
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

Val* internal_const_val(const char* name)
	{
	return zeek::id::lookup_const(name).get();
	}

Val* opt_internal_val(const char* name)
	{
	const auto& id = lookup_ID(name, GLOBAL_MODULE_NAME);
	return id ? id->GetVal().get() : nullptr;
	}

double opt_internal_double(const char* name)
	{
	const auto& id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return 0.0;
	const auto& v = id->GetVal();
	return v ? v->InternalDouble() : 0.0;
	}

bro_int_t opt_internal_int(const char* name)
	{
	const auto& id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return 0;
	const auto& v = id->GetVal();
	return v ? v->InternalInt() : 0;
	}

bro_uint_t opt_internal_unsigned(const char* name)
	{
	const auto& id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return 0;
	const auto& v = id->GetVal();
	return v ? v->InternalUnsigned() : 0;
	}

StringVal* opt_internal_string(const char* name)
	{
	const auto& id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return nullptr;
	const auto& v = id->GetVal();
	return v ? v->AsStringVal() : nullptr;
	}

TableVal* opt_internal_table(const char* name)
	{
	const auto& id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id ) return nullptr;
	const auto& v = id->GetVal();
	return v ? v->AsTableVal() : nullptr;
	}

ListVal* internal_list_val(const char* name)
	{
	const auto& id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		return nullptr;

	Val* v = id->GetVal().get();

	if ( v )
		{
		if ( v->GetType()->Tag() == TYPE_LIST )
			return (ListVal*) v;

		else if ( v->GetType()->IsSet() )
			{
			TableVal* tv = v->AsTableVal();
			auto lv = tv->ToPureListVal();
			return lv.release();
			}

		else
			reporter->InternalError("internal variable %s is not a list", name);
		}

	return nullptr;
	}

BroType* internal_type(const char* name)
	{
	return zeek::id::lookup_type(name).get();
	}

Func* internal_func(const char* name)
	{
	const auto& v = zeek::id::lookup_val(name);

	if ( v )
		return v->AsFunc();
	else
		return nullptr;
	}

EventHandlerPtr internal_handler(const char* name)
	{
	// If there already is an entry in the registry, we have a
	// local handler on the script layer.
	EventHandler* h = event_registry->Lookup(name);
	if ( h )
		{
		h->SetUsed();
		return h;
		}

	h = new EventHandler(name);
	event_registry->Register(h);

	h->SetUsed();

	return h;
	}
