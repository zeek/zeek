#include "Val.h"
#include "StateAccess.h"
#include "Event.h"
#include "NetVar.h"
#include "DebugLogger.h"

int StateAccess::replaying = 0;

StateAccess::StateAccess(Opcode arg_opcode,
		const MutableVal* arg_target, const Val* arg_op1,
		const Val* arg_op2, const Val* arg_op3)
	{
	opcode = arg_opcode;
	target.val = const_cast<MutableVal*>(arg_target);
	target_type = TYPE_MVAL;
	op1.val = const_cast<Val*>(arg_op1);
	op1_type = TYPE_VAL;
	op2 = const_cast<Val*>(arg_op2);
	op3 = const_cast<Val*>(arg_op3);
	delete_op1_key = false;

	RefThem();
	}

StateAccess::StateAccess(Opcode arg_opcode,
		const ID* arg_target, const Val* arg_op1,
		const Val* arg_op2, const Val* arg_op3)
	{
	opcode = arg_opcode;
	target.id = const_cast<ID*>(arg_target);
	target_type = TYPE_ID;
	op1.val = const_cast<Val*>(arg_op1);
	op1_type = TYPE_VAL;
	op2 = const_cast<Val*>(arg_op2);
	op3 = const_cast<Val*>(arg_op3);
	delete_op1_key = false;

	RefThem();
	}

StateAccess::StateAccess(Opcode arg_opcode,
		const ID* arg_target, const HashKey* arg_op1,
		const Val* arg_op2, const Val* arg_op3)
	{
	opcode = arg_opcode;
	target.id = const_cast<ID*>(arg_target);
	target_type = TYPE_ID;
	op1.key = new HashKey(arg_op1->Key(), arg_op1->Size(), arg_op1->Hash());
	op1_type = TYPE_KEY;
	op2 = const_cast<Val*>(arg_op2);
	op3 = const_cast<Val*>(arg_op3);
	delete_op1_key = true;

	RefThem();
	}

StateAccess::StateAccess(Opcode arg_opcode,
		const MutableVal* arg_target, const HashKey* arg_op1,
		const Val* arg_op2, const Val* arg_op3)
	{
	opcode = arg_opcode;
	target.val = const_cast<MutableVal*>(arg_target);
	target_type = TYPE_MVAL;
	op1.key = new HashKey(arg_op1->Key(), arg_op1->Size(), arg_op1->Hash());
	op1_type = TYPE_KEY;
	op2 = const_cast<Val*>(arg_op2);
	op3 = const_cast<Val*>(arg_op3);
	delete_op1_key = true;

	RefThem();
	}

StateAccess::StateAccess(const StateAccess& sa)
	{
	opcode = sa.opcode;
	target_type = sa.target_type;
	op1_type = sa.op1_type;
	delete_op1_key = false;

	if ( target_type == TYPE_ID )
		target.id = sa.target.id;
	else
		target.val = sa.target.val;

	if ( op1_type == TYPE_VAL )
		op1.val = sa.op1.val;
	else
		{
		// We need to copy the key as the pointer may not be
		// valid anymore later.
		op1.key = new HashKey(sa.op1.key->Key(), sa.op1.key->Size(),
					sa.op1.key->Hash());
		delete_op1_key = true;
		}

	op2 = sa.op2;
	op3 = sa.op3;

	RefThem();
	}

StateAccess::~StateAccess()
	{
	if ( target_type == TYPE_ID )
		Unref(target.id);
	else
		Unref(target.val);

	if ( op1_type == TYPE_VAL )
		Unref(op1.val);
	else if ( delete_op1_key )
		delete op1.key;

	Unref(op2);
	Unref(op3);
	}

void StateAccess::RefThem()
	{
	if ( target_type == TYPE_ID )
		Ref(target.id);
	else
		Ref(target.val);

	if ( op1_type == TYPE_VAL && op1.val )
		Ref(op1.val);

	if ( op2 )
		Ref(op2);
	if ( op3 )
		Ref(op3);
	}

static Val* GetInteger(bro_int_t n, TypeTag t)
	{
	if ( t == TYPE_INT )
		return val_mgr->GetInt(n);

	return val_mgr->GetCount(n);
	}

void StateAccess::Replay()
	{
	// For simplicity we assume that we only replay unserialized accesses.
	assert(target_type == TYPE_ID && op1_type == TYPE_VAL);

	if ( ! target.id )
		return;

	Val* v = target.id->ID_Val();
	TypeTag t = v ? v->Type()->Tag() : TYPE_VOID;

	if ( opcode != OP_ASSIGN && ! v )
		{
		// FIXME: I think this warrants an internal error,
		// but let's check that first ...
		// reporter->InternalError("replay id lacking a value");
		reporter->Error("replay id lacks a value");
		return;
		}

	++replaying;

	switch ( opcode ) {
	case OP_ASSIGN:
		assert(op1.val);
		// There mustn't be a direct assignment to a unique ID.
		assert(target.id->Name()[0] != '#');

		target.id->SetVal(op1.val->Ref());
		break;

	case OP_INCR:
		if ( IsIntegral(t) )
			{
			assert(op1.val && op2);
			// We derive the amount as difference between old
			// and new value.
			bro_int_t amount =
				op1.val->CoerceToInt() - op2->CoerceToInt();

			target.id->SetVal(GetInteger(v->CoerceToInt() + amount, t),
						OP_INCR);
			}
		break;

	case OP_ASSIGN_IDX:
		assert(op1.val);

		if ( t == TYPE_TABLE )
			{
			assert(op2);
			v->AsTableVal()->Assign(op1.val, op2 ? op2->Ref() : 0);
			}

		else if ( t == TYPE_RECORD )
			{
			const char* field = op1.val->AsString()->CheckString();
			int idx = v->Type()->AsRecordType()->FieldOffset(field);

			if ( idx >= 0 )
				v->AsRecordVal()->Assign(idx, op2 ? op2->Ref() : 0);
			else
				reporter->Error("access replay: unknown record field %s for assign", field);
			}

		else if ( t == TYPE_VECTOR )
			{
			assert(op2);
			bro_uint_t index = op1.val->AsCount();
			v->AsVectorVal()->Assign(index, op2 ? op2->Ref() : 0);
			}

		else
			reporter->InternalError("unknown type in replaying index assign");

		break;

	case OP_INCR_IDX:
		{
		assert(op1.val && op2 && op3);

		// We derive the amount as the difference between old
		// and new value.
		bro_int_t amount = op2->CoerceToInt() - op3->CoerceToInt();

		if ( t == TYPE_TABLE )
			{
			t = v->Type()->AsTableType()->YieldType()->Tag();
			Val* lookup_op1 = v->AsTableVal()->Lookup(op1.val);
			int delta = lookup_op1->CoerceToInt() + amount;
			Val* new_val = GetInteger(delta, t);
			v->AsTableVal()->Assign(op1.val, new_val, OP_INCR );
			}

		else if ( t == TYPE_RECORD )
			{
			const char* field = op1.val->AsString()->CheckString();
			int idx = v->Type()->AsRecordType()->FieldOffset(field);
			if ( idx >= 0 )
				{
				t = v->Type()->AsRecordType()->FieldType(idx)->Tag();
				Val* lookup_field =
					v->AsRecordVal()->Lookup(idx);
				bro_int_t delta =
					lookup_field->CoerceToInt() + amount;
				Val* new_val = GetInteger(delta, t);
				v->AsRecordVal()->Assign(idx, new_val, OP_INCR);
				}
			else
				reporter->Error("access replay: unknown record field %s for assign", field);
			}

		else if ( t == TYPE_VECTOR )
			{
			bro_uint_t index = op1.val->AsCount();
			t = v->Type()->AsVectorType()->YieldType()->Tag();
			Val* lookup_op1 = v->AsVectorVal()->Lookup(index);
			int delta = lookup_op1->CoerceToInt() + amount;
			Val* new_val = GetInteger(delta, t);
			v->AsVectorVal()->Assign(index, new_val);
			}

		else
			reporter->InternalError("unknown type in replaying index increment");

		break;
		}

	case OP_ADD:
		assert(op1.val);
		if ( t == TYPE_TABLE )
			{
			v->AsTableVal()->Assign(op1.val, 0);
			}
		break;

	case OP_DEL:
		assert(op1.val);
		if ( t == TYPE_TABLE )
			{
			Unref(v->AsTableVal()->Delete(op1.val));
			}
		break;

	case OP_EXPIRE:
		assert(op1.val);
		if ( t == TYPE_TABLE )
			{
			// No old check for expire.  It may have already
			// been deleted by ourselves.  Furthermore, we
			// ignore the expire_func's return value.
			TableVal* tv = v->AsTableVal();
			if ( tv->Lookup(op1.val, false) )
				{
				// We want to propagate state updates which
				// are performed in the expire_func.
				StateAccess::ResumeReplay();

				tv->CallExpireFunc(op1.val->Ref());

				StateAccess::SuspendReplay();

				Unref(tv->AsTableVal()->Delete(op1.val));
				}
			}

		break;

	case OP_PRINT:
		assert(op1.val);
		reporter->InternalError("access replay for print not implemented");
		break;

	case OP_READ_IDX:
		if ( t == TYPE_TABLE )
			{
			assert(op1.val);
			TableVal* tv = v->AsTableVal();

			// Update the timestamp if we have a read_expire.
			if ( tv->FindAttr(ATTR_EXPIRE_READ) )
				{
				tv->UpdateTimestamp(op1.val);
				}
			}
		else
			reporter->Error("read for non-table");
		break;

	default:
		reporter->InternalError("access replay: unknown opcode for StateAccess");
		break;
		}

	--replaying;
	}

ID* StateAccess::Target() const
	{
	return target_type == TYPE_ID ? target.id : target.val->UniqueID();
	}

void StateAccess::Describe(ODesc* d) const
	{
	const ID* id;
	const char* id_str = "";
	const char* unique_str = "";

	d->SetShort();

	if ( target_type == TYPE_ID )
		{
		id = target.id;

		if ( ! id )
			{
			d->Add("(unknown id)");
			return;
			}

		id_str = id->Name();

		if ( id->ID_Val() && id->ID_Val()->IsMutableVal() &&
		     id->Name()[0] != '#' )
			unique_str = fmt(" [id] (%s)", id->ID_Val()->AsMutableVal()->UniqueID()->Name());
		}
	else
		{
		id = target.val->UniqueID();

#ifdef DEBUG
		if ( target.val->GetID() )
			{
			id_str = target.val->GetID()->Name();
			unique_str = fmt(" [val] (%s)", id->Name());
			}
		else
#endif
			id_str = id->Name();
		}

	const Val* op1 = op1_type == TYPE_VAL ?
		this->op1.val :
		id->ID_Val()->AsTableVal()->RecoverIndex(this->op1.key);

	switch ( opcode ) {
	case OP_ASSIGN:
		assert(op1);
		d->Add(id_str);
		d->Add(" = ");
		op1->Describe(d);
		if ( op2 )
			{
			d->Add(" (");
			op2->Describe(d);
			d->Add(")");
			}
		d->Add(unique_str);
		break;

	case OP_INCR:
		assert(op1 && op2);
		d->Add(id_str);
		d->Add(" += ");
		d->Add(op1->CoerceToInt() - op2->CoerceToInt());
		d->Add(unique_str);
		break;

	case OP_ASSIGN_IDX:
		assert(op1);
		d->Add(id_str);
		d->Add("[");
		op1->Describe(d);
		d->Add("]");
		d->Add(" = ");
		if ( op2 )
			op2->Describe(d);
		else
			d->Add("(null)");
		if ( op3 )
			{
			d->Add(" (");
			op3->Describe(d);
			d->Add(")");
			}
		d->Add(unique_str);
		break;

	case OP_INCR_IDX:
		assert(op1 && op2 && op3);
		d->Add(id_str);
		d->Add("[");
		op1->Describe(d);
		d->Add("]");
		d->Add(" += ");
		d->Add(op2->CoerceToInt() - op3->CoerceToInt());
		d->Add(unique_str);
		break;

	case OP_ADD:
		assert(op1);
		d->Add("add ");
		d->Add(id_str);
		d->Add("[");
		op1->Describe(d);
		d->Add("]");
		if ( op2 )
			{
			d->Add(" (");
			op2->Describe(d);
			d->Add(")");
			}
		d->Add(unique_str);
		break;

	case OP_DEL:
		assert(op1);
		d->Add("del ");
		d->Add(id_str);
		d->Add("[");
		op1->Describe(d);
		d->Add("]");
		if ( op2 )
			{
			d->Add(" (");
			op2->Describe(d);
			d->Add(")");
			}
		d->Add(unique_str);
		break;

	case OP_EXPIRE:
		assert(op1);
		d->Add("expire ");
		d->Add(id_str);
		d->Add("[");
		op1->Describe(d);
		d->Add("]");
		if ( op2 )
			{
			d->Add(" (");
			op2->Describe(d);
			d->Add(")");
			}
		d->Add(unique_str);
		break;

	case OP_PRINT:
		assert(op1);
		d->Add("print ");
		d->Add(id_str);
		op1->Describe(d);
		d->Add(unique_str);
		break;

	case OP_READ_IDX:
		assert(op1);
		d->Add("read ");
		d->Add(id_str);
		d->Add("[");
		op1->Describe(d);
		d->Add("]");
		break;

	default:
		reporter->InternalError("unknown opcode for StateAccess");
		break;
		}

	if ( op1_type != TYPE_VAL )
		Unref(const_cast<Val*>(op1));
	}

void StateAccess::Log(StateAccess* access)
	{
	if ( access->target_type == TYPE_ID )
		{
		if ( access->target.id->FindAttr(ATTR_TRACKED) )
			notifiers.Modified(access->target.id);
		}
	else
		{
		if ( access->target.val->GetProperties() & MutableVal::TRACKED )
			notifiers.Modified(access->target.val);
		}

#ifdef DEBUG
	ODesc desc;
	access->Describe(&desc);
	DBG_LOG(DBG_STATE, "operation: %s%s",
			desc.Description(), replaying > 0 ? " (replay)" : "");
#endif

	delete access;

	}

NotifierRegistry notifiers;

NotifierRegistry::~NotifierRegistry()
	{
	for ( auto i : ids )
		Unref(i.first);

	for ( auto i : vals )
		Unref(i.first);
	}

void NotifierRegistry::Register(ID* id, NotifierRegistry::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "registering ID %s for notifier %s",
		id->Name(), notifier->Name());

	Attr* attr = new Attr(ATTR_TRACKED);

	if ( id->Attrs() )
		{
		if ( ! id->Attrs()->FindAttr(ATTR_TRACKED) )
			id->Attrs()->AddAttr(attr);
		}
	else
		{
		attr_list* a = new attr_list{attr};
		id->SetAttrs(new Attributes(a, id->Type(), false));
		}

	Unref(attr);

	ids.insert({id, notifier});
	Ref(id);
	}

void NotifierRegistry::Register(Val* val, NotifierRegistry::Notifier* notifier)
	{
	if ( ! val->IsMutableVal() )
		return;

	DBG_LOG(DBG_NOTIFIERS, "registering value %p for notifier %s",
		val, notifier->Name());

	vals.insert({val, notifier});
	Ref(val);
	}

void NotifierRegistry::Unregister(ID* id, NotifierRegistry::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering ID %s for notifier %s",
		id->Name(), notifier->Name());

	auto x = ids.equal_range(id);
	for ( auto i = x.first; i != x.second; i++ )
		{
		if ( i->second == notifier )
			{
			ids.erase(i);
			Unref(id);
			break;
			}
		}

	if ( ids.find(id) == ids.end() )
		// Last registered notifier for this ID
		id->Attrs()->RemoveAttr(ATTR_TRACKED);
	}

void NotifierRegistry::Unregister(Val* val, NotifierRegistry::Notifier* notifier)
	{
	DBG_LOG(DBG_NOTIFIERS, "unregistering Val %p for notifier %s",
		val, notifier->Name());

	auto x = vals.equal_range(val);
	for ( auto i = x.first; i != x.second; i++ )
		{
		if ( i->second == notifier )
			{
			vals.erase(i);
			Unref(val);
			break;
			}
		}
	}

void NotifierRegistry::Modified(Val *val)
	{
	DBG_LOG(DBG_NOTIFIERS, "modification to tracked value %p", val);

	auto x = vals.equal_range(val);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(val);
	}

void NotifierRegistry::Modified(ID *id)
	{
	DBG_LOG(DBG_NOTIFIERS, "modification to tracked ID %s", id->Name());

	auto x = ids.equal_range(id);
	for ( auto i = x.first; i != x.second; i++ )
		i->second->Modified(id);
	}

const char* NotifierRegistry::Notifier::Name() const
	{
	return fmt("%p", this);
	}

