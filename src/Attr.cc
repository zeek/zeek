// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Attr.h"
#include "Expr.h"
#include "Serializer.h"
#include "threading/SerialTypes.h"

const char* attr_name(attr_tag t)
	{
	static const char* attr_names[int(NUM_ATTRS)] = {
		"&optional", "&default", "&redef",
		"&rotate_interval", "&rotate_size",
		"&add_func", "&delete_func", "&expire_func",
		"&read_expire", "&write_expire", "&create_expire",
		"&persistent", "&synchronized",
		"&encrypt",
		"&raw_output", "&mergeable", "&priority",
		"&group", "&log", "&error_handler", "&type_column",
		"(&tracked)",
	};

	return attr_names[int(t)];
	}

Attr::Attr(attr_tag t, Expr* e)
	{
	tag = t;
	expr = e;
	SetLocationInfo(&start_location, &end_location);
	}

Attr::~Attr()
	{
	Unref(expr);
	}

void Attr::Describe(ODesc* d) const
	{
	AddTag(d);

	if ( expr )
		{
		if ( ! d->IsBinary() )
			d->Add("=");

		expr->Describe(d);
		}
	}

void Attr::DescribeReST(ODesc* d) const
	{
	d->Add(":bro:attr:`");
	AddTag(d);
	d->Add("`");

	if ( expr )
		{
		d->SP();
		d->Add("=");
		d->SP();


		if ( expr->Tag() == EXPR_NAME )
			{
			d->Add(":bro:see:`");
			expr->Describe(d);
			d->Add("`");
			}

		else if ( expr->Type()->Tag() == TYPE_FUNC )
			{
			d->Add(":bro:type:`");
			d->Add(expr->Type()->AsFuncType()->FlavorString());
			d->Add("`");
			}

		else
			{
			d->Add("``");
			expr->Describe(d);
			d-> Add("``");
			}
		}
	}

void Attr::AddTag(ODesc* d) const
	{
	if ( d->IsBinary() )
		d->Add(static_cast<bro_int_t>(Tag()));
	else
		d->Add(attr_name(Tag()));
	}

Attributes::Attributes(attr_list* a, BroType* t, bool arg_in_record)
	{
	attrs = new attr_list(a->length());
	type = t->Ref();
	in_record = arg_in_record;

	SetLocationInfo(&start_location, &end_location);

	// We loop through 'a' and add each attribute individually,
	// rather than just taking over 'a' for ourselves, so that
	// the necessary checking gets done.

	loop_over_list(*a, i)
		AddAttr((*a)[i]);

	delete a;
	}

Attributes::~Attributes()
	{
	loop_over_list(*attrs, i)
		Unref((*attrs)[i]);

	delete attrs;

	Unref(type);
	}

void Attributes::AddAttr(Attr* attr)
	{
	if ( ! attrs )
		attrs = new attr_list;

	if ( ! attr->RedundantAttrOkay() )
		// We overwrite old attributes by deleting them first.
		RemoveAttr(attr->Tag());

	attrs->append(attr);
	Ref(attr);

	// We only check the attribute after we've added it, to facilitate
	// generating error messages via Attributes::Describe.
	CheckAttr(attr);

	// For ADD_FUNC or DEL_FUNC, add in an implicit REDEF, since
	// those attributes only have meaning for a redefinable value.
	if ( (attr->Tag() == ATTR_ADD_FUNC || attr->Tag() == ATTR_DEL_FUNC) &&
	     ! FindAttr(ATTR_REDEF) )
		attrs->append(new Attr(ATTR_REDEF));

	// For DEFAULT, add an implicit OPTIONAL.
	if ( attr->Tag() == ATTR_DEFAULT && ! FindAttr(ATTR_OPTIONAL) )
		attrs->append(new Attr(ATTR_OPTIONAL));
	}

void Attributes::AddAttrs(Attributes* a)
	{
	attr_list* as = a->Attrs();
	loop_over_list(*as, i)
		AddAttr((*as)[i]);

	Unref(a);
	}

Attr* Attributes::FindAttr(attr_tag t) const
	{
	if ( ! attrs )
		return 0;

	loop_over_list(*attrs, i)
		{
		Attr* a = (*attrs)[i];
		if ( a->Tag() == t )
			return a;
		}

	return 0;
	}

void Attributes::RemoveAttr(attr_tag t)
	{
	for ( int i = 0; i < attrs->length(); i++ )
		if ( (*attrs)[i]->Tag() == t )
			attrs->remove_nth(i--);
	}

void Attributes::Describe(ODesc* d) const
	{
	if ( ! attrs )
		{
		d->AddCount(0);
		return;
		}

	d->AddCount(attrs->length());

	loop_over_list(*attrs, i)
		{
		if ( (d->IsReadable() || d->IsPortable()) && i > 0 )
			d->Add(", ");

		(*attrs)[i]->Describe(d);
		}
	}

void Attributes::DescribeReST(ODesc* d) const
	{
	loop_over_list(*attrs, i)
		{
		if ( i > 0 )
			d->Add(" ");

		(*attrs)[i]->DescribeReST(d);
		}
	}

void Attributes::CheckAttr(Attr* a)
	{
	switch ( a->Tag() ) {
	case ATTR_OPTIONAL:
	case ATTR_REDEF:
		break;

	case ATTR_ADD_FUNC:
	case ATTR_DEL_FUNC:
		{
		int is_add = a->Tag() == ATTR_ADD_FUNC;

		BroType* at = a->AttrExpr()->Type();
		if ( at->Tag() != TYPE_FUNC )
			{
			a->AttrExpr()->Error(
				is_add ?
					"&add_func must be a function" :
					"&delete_func must be a function");
			break;
			}

		FuncType* aft = at->AsFuncType();
		if ( ! same_type(aft->YieldType(), type) )
			{
			a->AttrExpr()->Error(
				is_add ?
					"&add_func function must yield same type as variable" :
					"&delete_func function must yield same type as variable");
			break;
			}
		}
		break;

	case ATTR_DEFAULT:
		{
		BroType* atype = a->AttrExpr()->Type();

		if ( type->Tag() != TYPE_TABLE || (type->IsSet() && ! in_record) )
			{
			if ( same_type(atype, type) )
				// Ok.
				break;

			// Record defaults may be promotable.
			if ( (type->Tag() == TYPE_RECORD && atype->Tag() == TYPE_RECORD &&
			      record_promotion_compatible(atype->AsRecordType(),
							  type->AsRecordType())) )
				// Ok.
				break;

			if ( type->Tag() == TYPE_TABLE &&
			     type->AsTableType()->IsUnspecifiedTable() )
				// Ok.
				break;

			a->AttrExpr()->Error("&default value has inconsistent type", type);
			}

		TableType* tt = type->AsTableType();
		BroType* ytype = tt->YieldType();

		if ( ! in_record )
			{
			// &default applies to the type itself.
			if ( ! same_type(atype, ytype) )
				{
				// It can still be a default function.
				if ( atype->Tag() == TYPE_FUNC )
					{
					FuncType* f = atype->AsFuncType();
					if ( ! f->CheckArgs(tt->IndexTypes()) ||
					     ! same_type(f->YieldType(), ytype) )
						Error("&default function type clash");

					// Ok.
					break;
					}

				// Table defaults may be promotable.
				if ( (ytype->Tag() == TYPE_RECORD && atype->Tag() == TYPE_RECORD &&
				      record_promotion_compatible(atype->AsRecordType(),
								  ytype->AsRecordType())) )
					// Ok.
					break;

				Expr* e = a->AttrExpr();
				if ( check_and_promote_expr(e, ytype) )
					// Ok.
					break;

				Error("&default value has inconsistent type 2");
				}

			// Ok.
			break;
			}

		else
			{
			// &default applies to record field.

			if ( same_type(atype, type) ||
			     (atype->Tag() == TYPE_TABLE && atype->AsTableType()->IsUnspecifiedTable()) )
				// Ok.
				break;

			// Table defaults may be promotable.
			if ( ytype && ytype->Tag() == TYPE_RECORD &&
			     atype->Tag() == TYPE_RECORD &&
			     record_promotion_compatible(atype->AsRecordType(), ytype->AsRecordType()) )
				// Ok.
				break;

			Error("&default value has inconsistent type");
			}
		}
		break;

	case ATTR_ROTATE_INTERVAL:
		if ( type->Tag() != TYPE_FILE )
			Error("&rotate_interval only applicable to files");
		break;

	case ATTR_ROTATE_SIZE:
		if ( type->Tag() != TYPE_FILE )
			Error("&rotate_size only applicable to files");
		break;

	case ATTR_ENCRYPT:
		if ( type->Tag() != TYPE_FILE )
			Error("&encrypt only applicable to files");
		break;

	case ATTR_EXPIRE_READ:
	case ATTR_EXPIRE_WRITE:
	case ATTR_EXPIRE_CREATE:
		if ( type->Tag() != TYPE_TABLE )
			{
			Error("expiration only applicable to tables");
			break;
			}

#if 0
		//### not easy to test this w/o knowing the ID.
		if ( ! IsGlobal() )
			Error("expiration not supported for local variables");
#endif
		break;

	case ATTR_EXPIRE_FUNC:
		{
		if ( type->Tag() != TYPE_TABLE )
			{
			Error("expiration only applicable to tables");
			break;
			}

		const Expr* expire_func = a->AttrExpr();
		const FuncType* e_ft = expire_func->Type()->AsFuncType();

		if ( ((const BroType*) e_ft)->YieldType()->Tag() != TYPE_INTERVAL )
			{
			Error("&expire_func must yield a value of type interval");
			break;
			}

		if ( e_ft->Args()->NumFields() != 2 )
			{
			Error("&expire_func function must take exactly two arguments");
			break;
			}

		// ### Should type-check arguments to make sure first is
		// table type and second is table index type.
		}
		break;

	case ATTR_PERSISTENT:
	case ATTR_SYNCHRONIZED:
	case ATTR_TRACKED:
		// FIXME: Check here for global ID?
		break;

	case ATTR_RAW_OUTPUT:
		if ( type->Tag() != TYPE_FILE )
			Error("&raw_output only applicable to files");
		break;

	case ATTR_MERGEABLE:
		if ( type->Tag() != TYPE_TABLE )
			Error("&mergeable only applicable to tables/sets");
		break;

	case ATTR_PRIORITY:
		Error("&priority only applicable to event bodies");
		break;

	case ATTR_GROUP:
		if ( type->Tag() != TYPE_FUNC ||
		     type->AsFuncType()->Flavor() != FUNC_FLAVOR_EVENT )
			Error("&group only applicable to events");
		break;

	case ATTR_ERROR_HANDLER:
		if ( type->Tag() != TYPE_FUNC ||
		     type->AsFuncType()->Flavor() != FUNC_FLAVOR_EVENT )
			Error("&error_handler only applicable to events");
		break;

	case ATTR_LOG:
		if ( ! threading::Value::IsCompatibleType(type) )
			Error("&log applied to a type that cannot be logged");
		break;

	case ATTR_TYPE_COLUMN:
		{
		if ( type->Tag() != TYPE_PORT )
			{
			Error("type_column tag only applicable to ports");
			break;
			}

		BroType* atype = a->AttrExpr()->Type();

		if ( atype->Tag() != TYPE_STRING ) {
			Error("type column needs to have a string argument");
			break;
		}

		break;
		}


	default:
		BadTag("Attributes::CheckAttr", attr_name(a->Tag()));
	}
	}

bool Attributes::operator==(const Attributes& other) const
	{
	if ( ! attrs )
		return other.attrs;

	if ( ! other.attrs )
		return false;

	loop_over_list(*attrs, i)
		{
		Attr* a = (*attrs)[i];
		Attr* o = other.FindAttr(a->Tag());

		if ( ! o )
			return false;

		if ( ! (*a == *o) )
			return false;
		}

	loop_over_list(*other.attrs, j)
		{
		Attr* o = (*other.attrs)[j];
		Attr* a = FindAttr(o->Tag());

		if ( ! a )
			return false;

		if ( ! (*a == *o) )
			return false;
		}

	return true;
	}

bool Attributes::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Attributes* Attributes::Unserialize(UnserialInfo* info)
	{
	return (Attributes*) SerialObj::Unserialize(info, SER_ATTRIBUTES);
	}

IMPLEMENT_SERIAL(Attributes, SER_ATTRIBUTES);

bool Attributes::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ATTRIBUTES, BroObj);

	info->s->WriteOpenTag("Attributes");
	assert(type);
	if ( ! (type->Serialize(info) && SERIALIZE(attrs->length())) )
		return false;

	loop_over_list((*attrs), i)
		{
		Attr* a = (*attrs)[i];

		// Broccoli doesn't support expressions.
		Expr* e = (! info->broccoli_peer) ? a->AttrExpr() : 0;
		SERIALIZE_OPTIONAL(e);

		if ( ! SERIALIZE(char(a->Tag())) )
			return false;
		}

	info->s->WriteCloseTag("Attributes");
	return true;
	}

bool Attributes::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	type = BroType::Unserialize(info);
	if ( ! type )
		return false;

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	attrs = new attr_list(len);
	while ( len-- )
		{
		Expr* e;
		UNSERIALIZE_OPTIONAL(e, Expr::Unserialize(info))

		char tag;
		if ( ! UNSERIALIZE(&tag) )
			{
			delete e;
			return false;
			}

		attrs->append(new Attr((attr_tag)tag, e));
		}

	return true;
	}

