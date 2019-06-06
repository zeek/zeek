// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "ID.h"
#include "Expr.h"
#include "Dict.h"
#include "EventRegistry.h"
#include "Func.h"
#include "Scope.h"
#include "File.h"
#include "Scope.h"
#include "Traverse.h"
#include "zeekygen/Manager.h"

ID::ID(const char* arg_name, IDScope arg_scope, bool arg_is_export)
	{
	name = copy_string(arg_name);
	scope = arg_scope;
	is_export = arg_is_export;
	is_option = false;
	type = 0;
	val = 0;
	attrs = 0;
	is_const = false;
	is_enum_const = false;
	is_type = false;
	offset = 0;

	infer_return_type = false;
	weak_ref = false;

	SetLocationInfo(&start_location, &end_location);
	}

ID::~ID()
	{
	delete [] name;
	Unref(type);
	Unref(attrs);

	for ( auto element : option_handlers )
		Unref(element.second);

	if ( ! weak_ref )
		Unref(val);
	}

string ID::ModuleName() const
	{
	return extract_module_name(name);
	}

void ID::ClearVal()
	{
	if ( ! weak_ref )
		Unref(val);

	val = 0;
	}

void ID::SetVal(Val* v, bool arg_weak_ref)
	{
	if ( ! weak_ref )
		Unref(val);

	val = v;
	weak_ref = arg_weak_ref;
	notifiers.Modified(this);

#ifdef DEBUG
	UpdateValID();
#endif

	if ( type && val &&
	     type->Tag() == TYPE_FUNC &&
	     type->AsFuncType()->Flavor() == FUNC_FLAVOR_EVENT )
		{
		EventHandler* handler = event_registry->Lookup(name);
		if ( ! handler )
			{
			handler = new EventHandler(name);
			handler->SetLocalHandler(val->AsFunc());
			event_registry->Register(handler);
			}
		else
			{
			// Otherwise, internally defined events cannot
			// have local handler.
			handler->SetLocalHandler(val->AsFunc());
			}
		}
	}

void ID::SetVal(Val* v, init_class c)
	{
	if ( c == INIT_NONE || c == INIT_FULL )
		{
		SetVal(v);
		return;
		}

	if ( type->Tag() != TYPE_TABLE &&
	     (type->Tag() != TYPE_PATTERN || c == INIT_REMOVE) &&
	     (type->Tag() != TYPE_VECTOR  || c == INIT_REMOVE) )
		{
		if ( c == INIT_EXTRA )
			Error("+= initializer only applies to tables, sets, vectors and patterns", v);
		else
			Error("-= initializer only applies to tables and sets", v);
		}

	else
		{
		if ( c == INIT_EXTRA )
			{
			if ( ! val )
				{
				SetVal(v);
				return;
				}
			else
				v->AddTo(val, 0);
			}
		else
			{
			if ( val )
				v->RemoveFrom(val);
			}
		}

	Unref(v);
	}

void ID::SetVal(Expr* ev, init_class c)
	{
	Attr* a = attrs->FindAttr(c == INIT_EXTRA ?
					ATTR_ADD_FUNC : ATTR_DEL_FUNC);

	if ( ! a )
		Internal("no add/delete function in ID::SetVal");

	EvalFunc(a->AttrExpr(), ev);
	}

void ID::SetAttrs(Attributes* a)
	{
	Unref(attrs);
	attrs = 0;
	AddAttrs(a);
	}

void ID::UpdateValAttrs()
	{
	if ( ! attrs )
		return;

	MutableVal::Properties props = 0;

	if ( val && val->IsMutableVal() )
		{
		if ( attrs->FindAttr(ATTR_TRACKED) )
			props |= MutableVal::TRACKED;

		val->AsMutableVal()->AddProperties(props);
		}

	if ( val && val->Type()->Tag() == TYPE_TABLE )
		val->AsTableVal()->SetAttrs(attrs);

	if ( val && val->Type()->Tag() == TYPE_FILE )
		val->AsFile()->SetAttrs(attrs);

	if ( Type()->Tag() == TYPE_FUNC )
		{
		Attr* attr = attrs->FindAttr(ATTR_ERROR_HANDLER);

		if ( attr )
			event_registry->SetErrorHandler(Name());
		}

	if ( Type()->Tag() == TYPE_RECORD )
		{
		Attr* attr = attrs->FindAttr(ATTR_LOG);
		if ( attr )
			{
			// Apply &log to all record fields.
			RecordType* rt = Type()->AsRecordType();
			for ( int i = 0; i < rt->NumFields(); ++i )
				{
				TypeDecl* fd = rt->FieldDecl(i);

				if ( ! fd->attrs )
					fd->attrs = new Attributes(new attr_list, rt->FieldType(i), true);

				fd->attrs->AddAttr(new Attr(ATTR_LOG));
				}
			}
		}
	}

void ID::MakeDeprecated()
	{
	if ( IsDeprecated() )
		return;

	attr_list* attr = new attr_list{new Attr(ATTR_DEPRECATED)};
	AddAttrs(new Attributes(attr, Type(), false));
	}

void ID::AddAttrs(Attributes* a)
	{
	if ( attrs )
		attrs->AddAttrs(a);
	else
		attrs = a;

	UpdateValAttrs();
	}

void ID::RemoveAttr(attr_tag a)
	{
	if ( attrs )
		attrs->RemoveAttr(a);

	if ( val && val->IsMutableVal() )
		{
		MutableVal::Properties props = 0;

		if ( a == ATTR_TRACKED )
			props |= MutableVal::TRACKED;

		val->AsMutableVal()->RemoveProperties(props);
		}
	}

void ID::SetOption()
	{
	if ( is_option )
		return;

	is_option = true;

	// option implied redefinable
	if ( ! IsRedefinable() )
		{
		attr_list* attr = new attr_list{new Attr(ATTR_REDEF)};
		AddAttrs(new Attributes(attr, Type(), false));
		}
	}

void ID::EvalFunc(Expr* ef, Expr* ev)
	{
	Expr* arg1 = new ConstExpr(val->Ref());
	ListExpr* args = new ListExpr();
	args->Append(arg1);
	args->Append(ev->Ref());

	CallExpr* ce = new CallExpr(ef->Ref(), args);

	SetVal(ce->Eval(0));
	Unref(ce);
	}

#if 0
void ID::CopyFrom(const ID* id)
	{
	is_export = id->is_export;
	is_const = id->is_const;
	is_enum_const = id->is_enum_const;
	is_type = id->is_type;
	offset = id->offset ;
	infer_return_type = id->infer_return_type;

	if ( id->type )
		Ref(id->type);
	if ( id->val && ! id->weak_ref )
		Ref(id->val);
	if ( id->attrs )
		Ref(id->attrs);

	Unref(type);
	Unref(attrs);
	if ( ! weak_ref )
		Unref(val);

	type = id->type;
	val = id->val;
	attrs = id->attrs;
	weak_ref = id->weak_ref;

#ifdef DEBUG
	UpdateValID();
#endif
#endif

TraversalCode ID::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreID(this);
	HANDLE_TC_STMT_PRE(tc);

	if ( is_type )
		{
		tc = cb->PreTypedef(this);
		HANDLE_TC_STMT_PRE(tc);

		tc = cb->PostTypedef(this);
		HANDLE_TC_STMT_PRE(tc);
		}

	// FIXME: Perhaps we should be checking at other than global scope.
	else if ( val && IsFunc(val->Type()->Tag()) &&
		  cb->current_scope == global_scope() )
		{
		tc = val->AsFunc()->Traverse(cb);
		HANDLE_TC_STMT_PRE(tc);
		}

	else if ( ! is_enum_const )
		{
		tc = cb->PreDecl(this);
		HANDLE_TC_STMT_PRE(tc);

		tc = cb->PostDecl(this);
		HANDLE_TC_STMT_PRE(tc);
		}

	tc = cb->PostID(this);
	HANDLE_TC_EXPR_POST(tc);
	}

void ID::Error(const char* msg, const BroObj* o2)
	{
	BroObj::Error(msg, o2, 1);
	SetType(error_type());
	}

void ID::Describe(ODesc* d) const
	{
	d->Add(name);
	}

void ID::DescribeExtended(ODesc* d) const
	{
	d->Add(name);

	if ( type )
		{
		d->Add(" : ");
		type->Describe(d);
		}

	if ( val )
		{
		d->Add(" = ");
		val->Describe(d);
		}

	if ( attrs )
		{
		d->Add(" ");
		attrs->Describe(d);
		}
	}

void ID::DescribeReSTShort(ODesc* d) const
	{
	if ( is_type )
		d->Add(":zeek:type:`");
	else
		d->Add(":zeek:id:`");

	d->Add(name);
	d->Add("`");

	if ( type )
		{
		d->Add(": ");
		d->Add(":zeek:type:`");

		if ( ! is_type && ! type->GetName().empty() )
			d->Add(type->GetName().c_str());
		else
			{
			TypeTag t = type->Tag();

			switch ( t ) {
			case TYPE_TABLE:
				d->Add(type->IsSet() ? "set" : type_name(t));
				break;

			case TYPE_FUNC:
				d->Add(type->AsFuncType()->FlavorString().c_str());
				break;

			case TYPE_ENUM:
				if ( is_type )
					d->Add(type_name(t));
				else
					d->Add(zeekygen_mgr->GetEnumTypeName(Name()).c_str());
				break;

			default:
				d->Add(type_name(t));
				break;
			}
			}

		d->Add("`");
		}

	if ( attrs )
		{
		d->SP();
		attrs->DescribeReST(d);
		}
	}

void ID::DescribeReST(ODesc* d, bool roles_only) const
	{
	if ( roles_only )
		{
		if ( is_type )
			d->Add(":zeek:type:`");
		else
			d->Add(":zeek:id:`");
		d->Add(name);
		d->Add("`");
		}
	else
		{
		if ( is_type )
			d->Add(".. zeek:type:: ");
		else
			d->Add(".. zeek:id:: ");
		d->Add(name);
		}

	d->PushIndent();
	d->NL();

	if ( type )
		{
		d->Add(":Type: ");

		if ( ! is_type && ! type->GetName().empty() )
			{
			d->Add(":zeek:type:`");
			d->Add(type->GetName());
			d->Add("`");
			}
		else
			type->DescribeReST(d, roles_only);

		d->NL();
		}

	if ( attrs )
		{
		d->Add(":Attributes: ");
		attrs->DescribeReST(d);
		d->NL();
		}

	if ( val && type &&
		type->Tag() != TYPE_FUNC &&
		type->InternalType() != TYPE_INTERNAL_VOID &&
		// Values within Version module are likely to include a
		// constantly-changing version number and be a frequent
		// source of error/desynchronization, so don't include them.
		ModuleName() != "Version" )
		{
		d->Add(":Default:");

		if ( type->InternalType() == TYPE_INTERNAL_OTHER )
			{
			switch ( type->Tag() ) {
			case TYPE_TABLE:
				if ( val->AsTable()->Length() == 0 )
					{
					d->Add(" ``{}``");
					d->NL();
					break;
					}
				// Fall-through.

			default:
				d->NL();
				d->NL();
				d->Add("::");
				d->NL();
				d->PushIndent();
				val->DescribeReST(d);
				d->PopIndent();
			}
			}

		else
			{
			d->SP();
			val->DescribeReST(d);
			d->NL();
			}
		}
	}

#ifdef DEBUG
void ID::UpdateValID()
	{
	if ( IsGlobal() && val && name && name[0] != '#' )
		val->SetID(this);
	}
#endif

void ID::AddOptionHandler(Func* callback, int priority)
	{
	option_handlers.insert({priority, callback});
	}

vector<Func*> ID::GetOptionHandlers() const
	{
	// multimap is sorted
	// It might be worth caching this if we expect it to be called
	// a lot...
	vector<Func*> v;
	for ( auto& element : option_handlers )
		v.push_back(element.second);
	return v;
	}
