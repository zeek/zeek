// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "ID.h"
#include "Expr.h"
#include "Dict.h"
#include "EventRegistry.h"
#include "Func.h"
#include "Scope.h"
#include "File.h"
#include "Serializer.h"
#include "RemoteSerializer.h"
#include "PersistenceSerializer.h"
#include "Scope.h"
#include "Traverse.h"
#include "broxygen/Manager.h"

ID::ID(const char* arg_name, IDScope arg_scope, bool arg_is_export)
	{
	name = copy_string(arg_name);
	scope = arg_scope;
	is_export = arg_is_export;
	type = 0;
	val = 0;
	attrs = 0;
	is_const = 0;
	is_enum_const = 0;
	is_type = 0;
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

void ID::SetVal(Val* v, Opcode op, bool arg_weak_ref)
	{
	if ( op != OP_NONE )
		{
		if ( type && val && type->Tag() == TYPE_TABLE &&
		     val->AsTableVal()->FindAttr(ATTR_MERGEABLE) &&
		     v->AsTableVal()->FindAttr(ATTR_MERGEABLE) )
			{
			StateAccess::Log(new StateAccess(OP_ASSIGN, this,
								v, val));
			v->AsTableVal()->AddTo(val->AsTableVal(), 0, false);
			return;
			}

		MutableVal::Properties props = 0;

		if ( attrs && attrs->FindAttr(ATTR_SYNCHRONIZED) )
			props |= MutableVal::SYNCHRONIZED;

		if ( attrs && attrs->FindAttr(ATTR_PERSISTENT) )
			props |= MutableVal::PERSISTENT;

		if ( attrs && attrs->FindAttr(ATTR_TRACKED) )
			props |= MutableVal::TRACKED;

		if ( props )
			{
			if ( v->IsMutableVal() )
				v->AsMutableVal()->AddProperties(props);
			}

#ifndef DEBUG
		if ( props )
#else
		if ( debug_logger.IsVerbose() || props )
#endif
			StateAccess::Log(new StateAccess(op, this, v, val));
		}

	if ( ! weak_ref )
		Unref(val);

	val = v;
	weak_ref = arg_weak_ref;

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
	     (type->Tag() != TYPE_PATTERN || c == INIT_REMOVE) )
		{
		if ( c == INIT_EXTRA )
			Error("+= initializer only applies to tables, sets and patterns", v);
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
		if ( attrs->FindAttr(ATTR_SYNCHRONIZED) )
			props |= MutableVal::SYNCHRONIZED;

		if ( attrs->FindAttr(ATTR_PERSISTENT) )
			props |= MutableVal::PERSISTENT;

		if ( attrs->FindAttr(ATTR_TRACKED) )
			props |= MutableVal::TRACKED;

		val->AsMutableVal()->AddProperties(props);
		}

	if ( ! IsInternalGlobal() )
		{
		if ( attrs->FindAttr(ATTR_SYNCHRONIZED) )
			remote_serializer->Register(this);

		if ( attrs->FindAttr(ATTR_PERSISTENT) )
			persistence_serializer->Register(this);
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

		if ( a == ATTR_SYNCHRONIZED )
			props |= MutableVal::SYNCHRONIZED;

		if ( a == ATTR_PERSISTENT )
			props |= MutableVal::PERSISTENT;

		if ( a == ATTR_TRACKED )
			props |= MutableVal::TRACKED;

		val->AsMutableVal()->RemoveProperties(props);
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

bool ID::Serialize(SerialInfo* info) const
	{
	return (ID*) SerialObj::Serialize(info);
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

	if ( FindAttr(ATTR_PERSISTENT) )
		persistence_serializer->Unregister(this);

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

	if ( FindAttr(ATTR_PERSISTENT) )
		persistence_serializer->Unregister(this);
	}
#endif

ID* ID::Unserialize(UnserialInfo* info)
	{
	ID* id = (ID*) SerialObj::Unserialize(info, SER_ID);
	if ( ! id )
		return 0;

	if ( ! id->IsGlobal() )
		return id;

	// Globals.
	ID* current = global_scope()->Lookup(id->name);

	if ( ! current )
		{
		if ( ! info->install_globals )
			{
			info->s->Error("undefined");
			Unref(id);
			return 0;
			}

		Ref(id);
		global_scope()->Insert(id->Name(), id);
#ifdef USE_PERFTOOLS_DEBUG
		heap_checker->IgnoreObject(id);
#endif
		}

	else
		{
		if ( info->id_policy != UnserialInfo::InstantiateNew )
			{
			persistence_serializer->Unregister(current);
			remote_serializer->Unregister(current);
			}

		switch ( info->id_policy ) {

		case UnserialInfo::Keep:
			Unref(id);
			Ref(current);
			id = current;
			break;

		case UnserialInfo::Replace:
			Unref(current);
			Ref(id);
			global_scope()->Insert(id->Name(), id);
			break;

		case UnserialInfo::CopyNewToCurrent:
			if ( ! same_type(current->type, id->type) )
				{
				info->s->Error("type mismatch");
				Unref(id);
				return 0;
				}

			if ( ! current->weak_ref )
				Unref(current->val);

			current->val = id->val;
			current->weak_ref = id->weak_ref;
			if ( current->val && ! current->weak_ref )
				Ref(current->val);

#ifdef DEBUG
			current->UpdateValID();
#endif

			Unref(id);
			Ref(current);
			id = current;

		break;

		case UnserialInfo::CopyCurrentToNew:
			if ( ! same_type(current->type, id->type) )
				{
				info->s->Error("type mismatch");
				return 0;
				}
			if ( ! id->weak_ref )
				Unref(id->val);
			id->val = current->val;
			id->weak_ref = current->weak_ref;
			if ( id->val && ! id->weak_ref )
				Ref(id->val);

#ifdef DEBUG
			id->UpdateValID();
#endif

			Unref(current);
			Ref(id);
			global_scope()->Insert(id->Name(), id);
			break;

		case UnserialInfo::InstantiateNew:
			// Do nothing.
			break;

		default:
			reporter->InternalError("unknown type for UnserialInfo::id_policy");
		}
		}

	if ( id->FindAttr(ATTR_PERSISTENT) )
		persistence_serializer->Register(id);

	if ( id->FindAttr(ATTR_SYNCHRONIZED) )
		remote_serializer->Register(id);

	return id;

	}

IMPLEMENT_SERIAL(ID, SER_ID);

bool ID::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE_WITH_SUSPEND(SER_ID, BroObj);

	if ( info->cont.NewInstance() )
		{
		DisableSuspend suspend(info);

		info->s->WriteOpenTag("ID");

		if ( ! (SERIALIZE(name) &&
			SERIALIZE(char(scope)) &&
			SERIALIZE(is_export) &&
			SERIALIZE(is_const) &&
			SERIALIZE(is_enum_const) &&
			SERIALIZE(is_type) &&
			SERIALIZE(offset) &&
			SERIALIZE(infer_return_type) &&
			SERIALIZE(weak_ref) &&
			type->Serialize(info)) )
			return false;

		SERIALIZE_OPTIONAL(attrs);
		}

	SERIALIZE_OPTIONAL(val);

	return true;
	}

bool ID::DoUnserialize(UnserialInfo* info)
	{
	bool installed_tmp = false;

	DO_UNSERIALIZE(BroObj);

	char id_scope;

	if ( ! (UNSERIALIZE_STR(&name, 0) &&
		UNSERIALIZE(&id_scope) &&
		UNSERIALIZE(&is_export) &&
		UNSERIALIZE(&is_const) &&
		UNSERIALIZE(&is_enum_const) &&
		UNSERIALIZE(&is_type) &&
		UNSERIALIZE(&offset) &&
		UNSERIALIZE(&infer_return_type) &&
		UNSERIALIZE(&weak_ref)
	       ) )
		return false;

	scope = IDScope(id_scope);

	info->s->SetErrorDescr(fmt("unserializing ID %s", name));

	type = BroType::Unserialize(info);
	if ( ! type )
		return false;

	UNSERIALIZE_OPTIONAL(attrs, Attributes::Unserialize(info));

	// If it's a global function not currently known,
	// we temporarily install it in global scope.
	// This is necessary for recursive functions.
	if ( IsGlobal() && Type()->Tag() == TYPE_FUNC )
		{
		ID* current = global_scope()->Lookup(name);
		if ( ! current )
			{
			installed_tmp = true;
			global_scope()->Insert(Name(), this);
			}
		}

	UNSERIALIZE_OPTIONAL(val, Val::Unserialize(info));
#ifdef DEBUG
	UpdateValID();
#endif

	if ( weak_ref )
		{
		// At this point at least the serialization cache will hold a
		// reference so this will not delete the val.
		assert(val->RefCnt() > 1);
		Unref(val);
		}

	if ( installed_tmp && ! global_scope()->Remove(name) )
		reporter->InternalWarning("missing tmp ID in %s unserialization", name);

	return true;
	}

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
		d->Add(":bro:type:`");
	else
		d->Add(":bro:id:`");

	d->Add(name);
	d->Add("`");

	if ( type )
		{
		d->Add(": ");
		d->Add(":bro:type:`");

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
					d->Add(broxygen_mgr->GetEnumTypeName(Name()).c_str());
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
			d->Add(":bro:type:`");
		else
			d->Add(":bro:id:`");
		d->Add(name);
		d->Add("`");
		}
	else
		{
		if ( is_type )
			d->Add(".. bro:type:: ");
		else
			d->Add(".. bro:id:: ");
		d->Add(name);
		}

	d->PushIndent();
	d->NL();

	if ( type )
		{
		d->Add(":Type: ");

		if ( ! is_type && ! type->GetName().empty() )
			{
			d->Add(":bro:type:`");
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
		type->InternalType() != TYPE_INTERNAL_VOID )
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

