// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Attr.h"
#include "Expr.h"
#include "threading/SerialTypes.h"

const char* attr_name(attr_tag t)
	{
	static const char* attr_names[int(NUM_ATTRS)] = {
		"&optional", "&default", "&redef",
		"&add_func", "&delete_func", "&expire_func",
		"&read_expire", "&write_expire", "&create_expire",
		"&raw_output", "&priority",
		"&group", "&log", "&error_handler", "&type_column",
		"(&tracked)", "&deprecated",
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

void Attr::DescribeReST(ODesc* d, bool shorten) const
	{
	auto add_long_expr_string = [](ODesc* d, const std::string& s, bool shorten)
		{
		constexpr auto max_expr_chars = 32;
		constexpr auto shortened_expr = "*...*";

		if ( s.size() > max_expr_chars )
			{
			if ( shorten )
				d->Add(shortened_expr);
			else
				{
				// Long inline-literals likely won't wrap well in HTML render
				d->Add("*");
				d->Add(s);
				d->Add("*");
				}
			}
		else
			{
			d->Add("``");
			d->Add(s);
			d->Add("``");
			}
		};

	d->Add(":zeek:attr:`");
	AddTag(d);
	d->Add("`");

	if ( expr )
		{
		d->SP();
		d->Add("=");
		d->SP();

		if ( expr->Tag() == EXPR_NAME )
			{
			d->Add(":zeek:see:`");
			expr->Describe(d);
			d->Add("`");
			}

		else if ( expr->Type()->Tag() == TYPE_FUNC )
			{
			d->Add(":zeek:type:`");
			d->Add(expr->Type()->AsFuncType()->FlavorString());
			d->Add("`");
			}

		else if ( expr->Tag() == EXPR_CONST )
			{
			ODesc dd;
			dd.SetQuotes(1);
			expr->Describe(&dd);
			string s = dd.Description();
			add_long_expr_string(d, s, shorten);
			}

		else
			{
			Val* v = expr->Eval(0);
			ODesc dd;
			v->Describe(&dd);
			Unref(v);
			string s = dd.Description();

			for ( size_t i = 0; i < s.size(); ++i )
				if ( s[i] == '\n' )
					s[i] = ' ';

			add_long_expr_string(d, s, shorten);
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

Attributes::Attributes(attr_list* a, BroType* t, bool arg_in_record, bool is_global)
	{
	attrs = new attr_list(a->length());
	type = t->Ref();
	in_record = arg_in_record;
	global_var = is_global;

	SetLocationInfo(&start_location, &end_location);

	// We loop through 'a' and add each attribute individually,
	// rather than just taking over 'a' for ourselves, so that
	// the necessary checking gets done.

	for ( const auto& attr : *a )
		AddAttr(attr);

	delete a;
	}

Attributes::~Attributes()
	{
	for ( const auto& attr : *attrs )
		Unref(attr);

	delete attrs;

	Unref(type);
	}

void Attributes::AddAttr(Attr* attr)
	{
	if ( ! attrs )
		attrs = new attr_list(1);

	// We overwrite old attributes by deleting them first.
	RemoveAttr(attr->Tag());
	attrs->push_back(attr);
	Ref(attr);

	// We only check the attribute after we've added it, to facilitate
	// generating error messages via Attributes::Describe.
	CheckAttr(attr);

	// For ADD_FUNC or DEL_FUNC, add in an implicit REDEF, since
	// those attributes only have meaning for a redefinable value.
	if ( (attr->Tag() == ATTR_ADD_FUNC || attr->Tag() == ATTR_DEL_FUNC) &&
	     ! FindAttr(ATTR_REDEF) )
		attrs->push_back(new Attr(ATTR_REDEF));

	// For DEFAULT, add an implicit OPTIONAL if it's not a global.
	if ( ! global_var && attr->Tag() == ATTR_DEFAULT &&
	     ! FindAttr(ATTR_OPTIONAL) )
		attrs->push_back(new Attr(ATTR_OPTIONAL));
	}

void Attributes::AddAttrs(Attributes* a)
	{
	attr_list* as = a->Attrs();
	for ( const auto& attr : *as )
		AddAttr(attr);

	Unref(a);
	}

Attr* Attributes::FindAttr(attr_tag t) const
	{
	if ( ! attrs )
		return 0;

	for ( const auto& a : *attrs )
		{
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

void Attributes::DescribeReST(ODesc* d, bool shorten) const
	{
	loop_over_list(*attrs, i)
		{
		if ( i > 0 )
			d->Add(" ");

		(*attrs)[i]->DescribeReST(d, shorten);
		}
	}

void Attributes::CheckAttr(Attr* a)
	{
	switch ( a->Tag() ) {
	case ATTR_DEPRECATED:
	case ATTR_REDEF:
		break;

	case ATTR_OPTIONAL:
		if ( global_var )
			Error("&optional is not valid for global variables");
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
		// &default is allowed for global tables, since it's used in initialization
		// of table fields. it's not allowed otherwise.
		if ( global_var && ! type->IsSet() && type->Tag() != TYPE_TABLE )
			{
			Error("&default is not valid for global variables");
			break;
			}

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

			Expr* e = a->AttrExpr();
			if ( check_and_promote_expr(e, type) )
				{
				a->SetAttrExpr(e);
				// Ok.
				break;
				}

			a->AttrExpr()->Error("&default value has inconsistent type", type);
			return;
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
					{
					a->SetAttrExpr(e);
					// Ok.
					break;
					}

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

	case ATTR_EXPIRE_READ:
	case ATTR_EXPIRE_WRITE:
	case ATTR_EXPIRE_CREATE:
		{
		if ( type->Tag() != TYPE_TABLE )
			{
			Error("expiration only applicable to tables");
			break;
			}

		int num_expires = 0;
		if ( attrs )
			{
			for ( const auto& a : *attrs )
				{
				if ( a->Tag() == ATTR_EXPIRE_READ ||
				     a->Tag() == ATTR_EXPIRE_WRITE ||
				     a->Tag() == ATTR_EXPIRE_CREATE )
					num_expires++;
				}
			}

		if ( num_expires > 1 )
			{
			Error("set/table can only have one of &read_expire, &write_expire, &create_expire");
			break;
			}
		}

#if 0
		//### not easy to test this w/o knowing the ID.
		if ( ! global_var )
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

		if ( expire_func->Type()->Tag() != TYPE_FUNC )
			Error("&expire_func attribute is not a function");

		const FuncType* e_ft = expire_func->Type()->AsFuncType();

		if ( e_ft->YieldType()->Tag() != TYPE_INTERVAL )
			{
			Error("&expire_func must yield a value of type interval");
			break;
			}

		const TableType* the_table = type->AsTableType();

		if (the_table->IsUnspecifiedTable())
			break;

		const type_list* func_index_types = e_ft->ArgTypes()->Types();
		// Keep backwards compatibility with idx: any idiom.
		if ( func_index_types->length() == 2 )
			{
			if ((*func_index_types)[1]->Tag() == TYPE_ANY)
				break;
			}

		const type_list* table_index_types = the_table->IndexTypes();

		type_list expected_args;
		expected_args.push_back(type->AsTableType());
		for (const auto& t : *table_index_types)
			expected_args.push_back(t);

		if ( ! e_ft->CheckArgs(&expected_args) )
			Error("&expire_func argument type clash");
		}
		break;

	case ATTR_TRACKED:
		// FIXME: Check here for global ID?
		break;

	case ATTR_RAW_OUTPUT:
		if ( type->Tag() != TYPE_FILE )
			Error("&raw_output only applicable to files");
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

	for ( const auto& a : *attrs )
		{
		Attr* o = other.FindAttr(a->Tag());

		if ( ! o )
			return false;

		if ( ! (*a == *o) )
			return false;
		}

	for ( const auto& o : *other.attrs )
		{
		Attr* a = FindAttr(o->Tag());

		if ( ! a )
			return false;

		if ( ! (*a == *o) )
			return false;
		}

	return true;
	}

