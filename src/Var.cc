// See the file "COPYING" in the main distribution directory for copyright.

#include <memory>

#include "zeek-config.h"

#include "Var.h"
#include "Func.h"
#include "Stmt.h"
#include "Scope.h"
#include "EventRegistry.h"
#include "Traverse.h"

static Val* init_val(Expr* init, const BroType* t, Val* aggr)
	{
	try
		{
		return init->InitVal(t, aggr);
		}
	catch ( InterpreterException& e )
		{
		return nullptr;
		}
	}

static void make_var(ID* id, BroType* t, init_class c, Expr* init,
			attr_list* attr, decl_type dt, int do_init)
	{
	if ( id->Type() )
		{
		if ( id->IsRedefinable() || (! init && attr) )
			{
			BroObj* redef_obj = init ? (BroObj*) init : (BroObj*) t;
			if ( dt != VAR_REDEF )
				id->Warn("redefinition requires \"redef\"", redef_obj, 1);
			}

		else if ( dt != VAR_REDEF || init || ! attr )
			{
			id->Error("already defined", init);
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
			t = id->Type();
		}

	if ( id->Type() && id->Type()->Tag() != TYPE_ERROR )
		{
		if ( dt != VAR_REDEF &&
		     (! init || ! do_init || (! t && ! (t = init_type(init)))) )
			{
			id->Error("already defined", init);
			return;
			}

		// Allow redeclaration in order to initialize.
		if ( ! same_type(t, id->Type()) )
			{
			id->Error("redefinition changes type", init);
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
				id->Error("double initialization", init);
				return;
				}

			Ref(elements);
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

		t = init_type(init);
		if ( ! t )
			{
			id->SetType(error_type());
			return;
			}
		}
	else
		Ref(t);

	id->SetType(t);

	if ( attr )
		id->AddAttrs(new Attributes(attr, t, false, id->IsGlobal()));

	if ( init )
		{
		switch ( init->Tag() ) {
		case EXPR_TABLE_CONSTRUCTOR:
			{
			TableConstructorExpr* ctor = (TableConstructorExpr*) init;
			if ( ctor->Attrs() )
				{
				::Ref(ctor->Attrs());
				id->AddAttrs(ctor->Attrs());
				}
			}
			break;

		case EXPR_SET_CONSTRUCTOR:
			{
			SetConstructorExpr* ctor = (SetConstructorExpr*) init;
			if ( ctor->Attrs() )
				{
				::Ref(ctor->Attrs());
				id->AddAttrs(ctor->Attrs());
				}
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
			Val* aggr;
			if ( t->Tag() == TYPE_RECORD )
				{
				aggr = new RecordVal(t->AsRecordType());

				if ( init && t )
					// Have an initialization and type is not deduced.
					init = new RecordCoerceExpr(init, t->AsRecordType());
				}

			else if ( t->Tag() == TYPE_TABLE )
				aggr = new TableVal(t->AsTableType(), id->Attrs());

			else if ( t->Tag() == TYPE_VECTOR )
				aggr = new VectorVal(t->AsVectorType());

			else
				aggr = 0;

			Val* v = 0;
			if ( init )
				{
				v = init_val(init, t, aggr);
				if ( ! v )
					return;
				}

			if ( aggr )
				id->SetVal(aggr, c);
			else if ( v )
				id->SetVal(v, c);
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
		id->SetVal(new Val(f));
		}
	}


void add_global(ID* id, BroType* t, init_class c, Expr* init,
		attr_list* attr, decl_type dt)
	{
	make_var(id, t, c, init, attr, dt, 1);
	}

Stmt* add_local(ID* id, BroType* t, init_class c, Expr* init,
		attr_list* attr, decl_type dt)
	{
	make_var(id, t, c, init, attr, dt, 0);

	if ( init )
		{
		if ( c != INIT_FULL )
			id->Error("can't use += / -= for initializations of local variables");

		Ref(id);

		Expr* name_expr = new NameExpr(id, dt == VAR_CONST);
		Stmt* stmt =
		    new ExprStmt(new AssignExpr(name_expr, init, 0, 0,
		        id->Attrs() ? id->Attrs()->Attrs() : 0 ));
		stmt->SetLocationInfo(init->GetLocationInfo());

		return stmt;
		}

	else
		{
		current_scope()->AddInit(id);
		return new NullStmt;
		}
	}

extern Expr* add_and_assign_local(ID* id, Expr* init, Val* val)
	{
	make_var(id, 0, INIT_FULL, init, 0, VAR_REGULAR, 0);
	Ref(id);
	return new AssignExpr(new NameExpr(id), init, 0, val);
	}

void add_type(ID* id, BroType* t, attr_list* attr)
	{
	string new_type_name = id->Name();
	string old_type_name = t->GetName();
	BroType* tnew = 0;

	if ( (t->Tag() == TYPE_RECORD || t->Tag() == TYPE_ENUM) &&
	     old_type_name.empty() )
		// An extensible type (record/enum) being declared for first time.
		tnew = t;
	else
		// Clone the type to preserve type name aliasing.
		tnew = t->ShallowClone();

	BroType::AddAlias(new_type_name, tnew);

	if ( new_type_name != old_type_name && ! old_type_name.empty() )
		BroType::AddAlias(old_type_name, tnew);

	tnew->SetName(id->Name());

	id->SetType(tnew);
	id->MakeType();

	if ( attr )
		id->SetAttrs(new Attributes(attr, tnew, false, false));
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
			recv_i->attrs = new Attributes(a, recv_i->type, true, false);
			}

		else if ( ! recv_i->attrs->FindAttr(ATTR_DEFAULT) )
			recv_i->attrs->AddAttr(def);
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
		int is_redef, FuncType* t, attr_list* attrs)
	{
	if ( flavor == FUNC_FLAVOR_EVENT )
		{
		const BroType* yt = t->YieldType();

		if ( yt && yt->Tag() != TYPE_VOID )
			id->Error("event cannot yield a value", t);

		t->ClearYieldType(flavor);
		}

	if ( id->Type() )
		{
		if ( ! same_type(id->Type(), t) )
			id->Type()->Error("incompatible types", t);

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
			id->Error("inconsistent function flavor", t);

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

	push_scope(id, attrs);

	RecordType* args = t->Args();
	int num_args = args->NumFields();

	for ( int i = 0; i < num_args; ++i )
		{
		TypeDecl* arg_i = args->FieldDecl(i);
		ID* arg_id = lookup_ID(arg_i->id, module_name);

		if ( arg_id && ! arg_id->IsGlobal() )
			arg_id->Error("argument name used twice");

		Unref(arg_id);

		arg_id = install_ID(arg_i->id, module_name, false, false);
		arg_id->SetType(arg_i->type->Ref());
		}

	if ( Attr* depr_attr = find_attr(attrs, ATTR_DEPRECATED) )
		id->MakeDeprecated(depr_attr->AttrExpr());
	}

class OuterIDBindingFinder : public TraversalCallback {
public:
	OuterIDBindingFinder(Scope* s)
		{
		scopes.emplace_back(s);
		}

	virtual TraversalCode PreExpr(const Expr*);
	virtual TraversalCode PostExpr(const Expr*);

	std::vector<Scope*> scopes;
	vector<const NameExpr*> outer_id_references;
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

	for ( auto it = scopes.rbegin(); it != scopes.rend(); ++it )
		{
		auto scope = *it;

		if ( scope->Lookup(e->Id()->Name()) )
			return TC_CONTINUE;
		}

	outer_id_references.push_back(e);
	return TC_CONTINUE;
	}

TraversalCode OuterIDBindingFinder::PostExpr(const Expr* expr)
	{
	if ( expr->Tag() == EXPR_LAMBDA )
		scopes.pop_back();

	return TC_CONTINUE;
	}

void end_func(Stmt* body)
	{
	auto ingredients = std::make_unique<function_ingredients>(pop_scope(), body);

	if ( ingredients->id->HasVal() )
		ingredients->id->ID_Val()->AsFunc()->AddBody(
			ingredients->body,
			ingredients->inits,
			ingredients->frame_size,
			ingredients->priority);
	else
		{
		Func* f = new BroFunc(
			ingredients->id,
			ingredients->body,
			ingredients->inits,
			ingredients->frame_size,
			ingredients->priority);

		ingredients->id->SetVal(new Val(f));
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
	ID* id = lookup_ID(name, GLOBAL_MODULE_NAME);

	if ( ! id )
		reporter->InternalError("internal variable %s missing", name);

	Val* rval = id->ID_Val();
	Unref(id);
	return rval;
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
	ID* id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		reporter->InternalError("internal variable %s missing", name);

	if ( ! id->IsConst() )
		reporter->InternalError("internal variable %s is not constant", name);

	Val* rval = id->ID_Val();
	Unref(id);
	return rval;
	}

Val* opt_internal_val(const char* name)
	{
	ID* id = lookup_ID(name, GLOBAL_MODULE_NAME);
	Val* rval = id ? id->ID_Val() : 0;
	Unref(id);
	return rval;
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
	return v ? v->AsStringVal() : 0;
	}

TableVal* opt_internal_table(const char* name)
	{
	Val* v = opt_internal_val(name);
	return v ? v->AsTableVal() : 0;
	}

ListVal* internal_list_val(const char* name)
	{
	ID* id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		return 0;

	Val* v = id->ID_Val();
	Unref(id);

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

	return 0;
	}

BroType* internal_type(const char* name)
	{
	ID* id = lookup_ID(name, GLOBAL_MODULE_NAME);
	if ( ! id )
		reporter->InternalError("internal type %s missing", name);

	BroType* rval = id->Type();
	Unref(id);
	return rval;
	}

Func* internal_func(const char* name)
	{
	Val* v = internal_val(name);
	if ( v )
		return v->AsFunc();
	else
		return 0;
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
