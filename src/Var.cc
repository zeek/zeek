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

static void make_var(ID* id, IntrusivePtr<BroType> t, init_class c,
                     IntrusivePtr<Expr> init, attr_list* attr, decl_type dt,
                     int do_init)
	{
	if ( id->Type() )
		{
		if ( id->IsRedefinable() || (! init && attr) )
			{
			BroObj* redef_obj = init ? (BroObj*) init.get() : (BroObj*) t.get();
			if ( dt != VAR_REDEF )
				id->Warn("redefinition requires \"redef\"", redef_obj, 1);
			}

		else if ( dt != VAR_REDEF || init || ! attr )
			{
			id->Error("already defined", init.get());
			return;
			}
		}

	if ( dt == VAR_REDEF )
		{
		if ( ! id->Type() )
			{
			id->Error("\"redef\" used but not previously defined");
			return;
			}

		if ( ! t )
			t = {NewRef{}, id->Type()};
		}

	if ( id->Type() && id->Type()->Tag() != TYPE_ERROR )
		{
		if ( dt != VAR_REDEF &&
		     (! init || ! do_init || (! t && ! (t = init_type(init.get())))) )
			{
			id->Error("already defined", init.get());
			return;
			}

		// Allow redeclaration in order to initialize.
		if ( ! same_type(t.get(), id->Type()) )
			{
			id->Error("redefinition changes type", init.get());
			return;
			}
		}

	if ( t && t->IsSet() )
		{ // Check for set with explicit elements.
		SetType* st = t->AsTableType()->AsSetType();
		ListExpr* elements = st->SetElements();

		if ( elements )
			{
			if ( init )
				{
				id->Error("double initialization", init.get());
				return;
				}

			init = {NewRef{}, elements};
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
				aggr = make_intrusive<VectorVal>(t->AsVectorType());

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
		Func* f = new BroFunc(id, 0, 0, 0, 0);
		id->SetVal(make_intrusive<Val>(f));
		}
	}


void add_global(ID* id, IntrusivePtr<BroType> t, init_class c,
                IntrusivePtr<Expr> init, attr_list* attr, decl_type dt)
	{
	make_var(id, std::move(t), c, std::move(init), attr, dt, 1);
	}

IntrusivePtr<Stmt> add_local(IntrusivePtr<ID> id, IntrusivePtr<BroType> t,
                             init_class c, IntrusivePtr<Expr> init,
                             attr_list* attr, decl_type dt)
	{
	make_var(id.get(), std::move(t), c, init, attr, dt, 0);

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
	make_var(id.get(), 0, INIT_FULL, init, 0, VAR_REGULAR, 0);
	auto name_expr = make_intrusive<NameExpr>(std::move(id));
	return make_intrusive<AssignExpr>(std::move(name_expr), std::move(init),
	                                  0, std::move(val));
	}

void add_type(ID* id, IntrusivePtr<BroType> t, attr_list* attr)
	{
	string new_type_name = id->Name();
	string old_type_name = t->GetName();
	IntrusivePtr<BroType> tnew;

	if ( (t->Tag() == TYPE_RECORD || t->Tag() == TYPE_ENUM) &&
	     old_type_name.empty() )
		// An extensible type (record/enum) being declared for first time.
		tnew = std::move(t);
	else
		// Clone the type to preserve type name aliasing.
		tnew = {AdoptRef{}, t->ShallowClone()};

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

		Attr* def = args_i->attrs ? args_i->attrs->FindAttr(ATTR_DEFAULT) : 0;

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

void begin_func(ID* id, const char* module_name, function_flavor flavor,
                int is_redef, IntrusivePtr<FuncType> t, attr_list* attrs)
	{
	if ( flavor == FUNC_FLAVOR_EVENT )
		{
		const BroType* yt = t->YieldType();

		if ( yt && yt->Tag() != TYPE_VOID )
			id->Error("event cannot yield a value", t.get());

		t->ClearYieldType(flavor);
		}

	if ( id->Type() )
		{
		if ( ! same_type(id->Type(), t.get()) )
			id->Type()->Error("incompatible types", t.get());

		else
			// If a previous declaration of the function had &default params,
			// automatically transfer any that are missing (convenience so that
			// implementations don't need to specify the &default expression again).
			transfer_arg_defaults(id->Type()->AsFuncType()->Args(), t->Args());
		}

	else if ( is_redef )
		id->Error("redef of not-previously-declared value");

	if ( id->HasVal() )
		{
		function_flavor id_flavor = id->ID_Val()->AsFunc()->Flavor();

		if ( id_flavor != flavor )
			id->Error("inconsistent function flavor", t.get());

		switch ( id_flavor ) {

		case FUNC_FLAVOR_EVENT:
		case FUNC_FLAVOR_HOOK:
			if ( is_redef )
				// Clear out value so it will be replaced.
				id->SetVal(0);
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
		}

	if ( Attr* depr_attr = find_attr(attrs, ATTR_DEPRECATED) )
		id->MakeDeprecated({NewRef{}, depr_attr->AttrExpr()});
	}

class OuterIDBindingFinder : public TraversalCallback {
public:
	OuterIDBindingFinder(Scope* s)
		: scope(s) { }

	virtual TraversalCode PreExpr(const Expr*);
	virtual TraversalCode PostExpr(const Expr*);

	Scope* scope;
	vector<const NameExpr*> outer_id_references;
	int lambda_depth = 0;
	// Note: think we really ought to toggle this to false to prevent
	// considering locals within inner-lambdas as "outer", but other logic
	// for "selective cloning" and locating IDs in the closure chain may
	// depend on current behavior and also needs to be changed.
	bool search_inner_lambdas = true;
};

TraversalCode OuterIDBindingFinder::PreExpr(const Expr* expr)
	{
	if ( expr->Tag() == EXPR_LAMBDA )
		++lambda_depth;

	if ( lambda_depth > 0 && ! search_inner_lambdas )
		// Don't inspect the bodies of inner lambdas as they will have their
		// own traversal to find outer IDs and we don't want to detect
		// references to local IDs inside and accidentally treat them as
		// "outer" since they can't be found in current scope.
		return TC_CONTINUE;

	if ( expr->Tag() != EXPR_NAME )
		return TC_CONTINUE;

	const NameExpr* e = static_cast<const NameExpr*>(expr);

	if ( e->Id()->IsGlobal() )
		return TC_CONTINUE;

	if ( scope->Lookup(e->Id()->Name()) )
		return TC_CONTINUE;

	outer_id_references.push_back(e);
	return TC_CONTINUE;
	}

TraversalCode OuterIDBindingFinder::PostExpr(const Expr* expr)
	{
	if ( expr->Tag() == EXPR_LAMBDA )
		{
		--lambda_depth;
		assert(lambda_depth >= 0);
		}

	return TC_CONTINUE;
	}

void end_func(IntrusivePtr<Stmt> body)
	{
	auto ingredients = std::make_unique<function_ingredients>(pop_scope(), std::move(body));

	if ( streq(ingredients->id->Name(), "anonymous-function") )
		{
		OuterIDBindingFinder cb(ingredients->scope.get());
		ingredients->body->Traverse(&cb);

		for ( size_t i = 0; i < cb.outer_id_references.size(); ++i )
			cb.outer_id_references[i]->Error(
						"referencing outer function IDs not supported");
		}

	if ( ingredients->id->HasVal() )
		ingredients->id->ID_Val()->AsFunc()->AddBody(
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

	ingredients->id->ID_Val()->AsFunc()->SetScope(ingredients->scope);
	// Note: ideally, something would take ownership of this memory until the
	// end of script execution, but that's essentially the same as the
	// lifetime of the process at the moment, so ok to "leak" it.
	ingredients.release();
	}

Val* internal_val(const char* name)
	{
	auto id = lookup_ID(name, GLOBAL_MODULE_NAME);

	if ( ! id )
		reporter->InternalError("internal variable %s missing", name);

	return id->ID_Val();
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
	auto id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		reporter->InternalError("internal variable %s missing", name);

	if ( ! id->IsConst() )
		reporter->InternalError("internal variable %s is not constant", name);

	return id->ID_Val();
	}

Val* opt_internal_val(const char* name)
	{
	auto id = lookup_ID(name, GLOBAL_MODULE_NAME);
	return id ? id->ID_Val() : nullptr;
	}

double opt_internal_double(const char* name)
	{
	Val* v = opt_internal_val(name);
	return v ? v->InternalDouble() : 0.0;
	}

bro_int_t opt_internal_int(const char* name)
	{
	Val* v = opt_internal_val(name);
	return v ? v->InternalInt() : 0;
	}

bro_uint_t opt_internal_unsigned(const char* name)
	{
	Val* v = opt_internal_val(name);
	return v ? v->InternalUnsigned() : 0;
	}

StringVal* opt_internal_string(const char* name)
	{
	Val* v = opt_internal_val(name);
	return v ? v->AsStringVal() : nullptr;
	}

TableVal* opt_internal_table(const char* name)
	{
	Val* v = opt_internal_val(name);
	return v ? v->AsTableVal() : nullptr;
	}

ListVal* internal_list_val(const char* name)
	{
	auto id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		return nullptr;

	Val* v = id->ID_Val();

	if ( v )
		{
		if ( v->Type()->Tag() == TYPE_LIST )
			return (ListVal*) v;

		else if ( v->Type()->IsSet() )
			{
			TableVal* tv = v->AsTableVal();
			ListVal* lv = tv->ConvertToPureList();
			return lv;
			}

		else
			reporter->InternalError("internal variable %s is not a list", name);
		}

	return nullptr;
	}

BroType* internal_type(const char* name)
	{
	auto id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		reporter->InternalError("internal type %s missing", name);

	return id->Type();
	}

Func* internal_func(const char* name)
	{
	Val* v = internal_val(name);
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
