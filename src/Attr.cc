// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Attr.h"
#include "Expr.h"
#include "Desc.h"
#include "Val.h"
#include "IntrusivePtr.h"
#include "threading/SerialTypes.h"

const char* attr_name(attr_tag t)
	{
	static const char* attr_names[int(NUM_ATTRS)] = {
		"&optional", "&default", "&redef",
		"&add_func", "&delete_func", "&expire_func",
		"&read_expire", "&write_expire", "&create_expire",
		"&raw_output", "&priority",
		"&group", "&log", "&error_handler", "&type_column",
		"(&tracked)", "&on_change", "&deprecated",
	};

	return attr_names[int(t)];
	}

Attr::Attr(attr_tag t, IntrusivePtr<Expr> e)
	: expr(std::move(e))
	{
	tag = t;
	SetLocationInfo(&start_location, &end_location);
	}

Attr::Attr(attr_tag t)
	: Attr(t, nullptr)
	{
	}

Attr::~Attr() = default;

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

		else if ( expr->GetType()->Tag() == TYPE_FUNC )
			{
			d->Add(":zeek:type:`");
			d->Add(expr->GetType()->AsFuncType()->FlavorString());
			d->Add("`");
			}

		else if ( expr->Tag() == EXPR_CONST )
			{
			ODesc dd;
			dd.SetQuotes(true);
			expr->Describe(&dd);
			std::string s = dd.Description();
			add_long_expr_string(d, s, shorten);
			}

		else
			{
			ODesc dd;
			expr->Eval(nullptr)->Describe(&dd);
			std::string s = dd.Description();

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

Attributes::Attributes(attr_list* a, IntrusivePtr<BroType> t, bool arg_in_record, bool is_global)
	: type(std::move(t))
	{
	attrs = new attr_list(a->length());
	in_record = arg_in_record;
	global_var = is_global;

	SetLocationInfo(&start_location, &end_location);

	// We loop through 'a' and add each attribute individually,
	// rather than just taking over 'a' for ourselves, so that
	// the necessary checking gets done.

	for ( const auto& attr : *a )
		AddAttr({NewRef{}, attr});

	delete a;
	}

Attributes::~Attributes()
	{
	for ( const auto& attr : *attrs )
		Unref(attr);

	delete attrs;
	}

void Attributes::AddAttr(IntrusivePtr<Attr> attr)
	{
	if ( ! attrs )
		attrs = new attr_list(1);

	// We overwrite old attributes by deleting them first.
	RemoveAttr(attr->Tag());
	attrs->push_back(IntrusivePtr{attr}.release());

	// We only check the attribute after we've added it, to facilitate
	// generating error messages via Attributes::Describe.
	CheckAttr(attr.get());

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
		AddAttr({NewRef{}, attr});

	Unref(a);
	}

Attr* Attributes::FindAttr(attr_tag t) const
	{
	if ( ! attrs )
		return nullptr;

	for ( const auto& a : *attrs )
		{
		if ( a->Tag() == t )
			return a;
		}

	return nullptr;
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
		bool is_add = a->Tag() == ATTR_ADD_FUNC;

		const auto& at = a->AttrExpr()->GetType();
		if ( at->Tag() != TYPE_FUNC )
			{
			a->AttrExpr()->Error(
				is_add ?
					"&add_func must be a function" :
					"&delete_func must be a function");
			break;
			}

		FuncType* aft = at->AsFuncType();
		if ( ! same_type(aft->Yield().get(), type.get()) )
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
		if ( global_var && ! type->IsTable() )
			{
			Error("&default is not valid for global variables except for tables");
			break;
			}

		BroType* atype = a->AttrExpr()->GetType().get();

		if ( type->Tag() != TYPE_TABLE || (type->IsSet() && ! in_record) )
			{
			if ( same_type(atype, type.get()) )
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

			auto e = check_and_promote_expr(a->AttrExpr(), type.get());

			if ( e )
				{
				a->SetAttrExpr(std::move(e));
				// Ok.
				break;
				}

			a->AttrExpr()->Error("&default value has inconsistent type", type.get());
			return;
			}

		TableType* tt = type->AsTableType();
		BroType* ytype = tt->Yield().get();

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
					     ! same_type(f->Yield().get(), ytype) )
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

				auto e = check_and_promote_expr(a->AttrExpr(), ytype);

				if ( e )
					{
					a->SetAttrExpr(std::move(e));
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

			if ( same_type(atype, type.get()) )
				// Ok.
				break;

			if ( (atype->Tag() == TYPE_TABLE && atype->AsTableType()->IsUnspecifiedTable()) )
				{
				auto e = check_and_promote_expr(a->AttrExpr(), type.get());

				if ( e )
					{
					a->SetAttrExpr(std::move(e));
					break;
					}
				}

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
			Error("expiration only applicable to sets/tables");
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

		if ( expire_func->GetType()->Tag() != TYPE_FUNC )
			Error("&expire_func attribute is not a function");

		const FuncType* e_ft = expire_func->GetType()->AsFuncType();

		if ( e_ft->Yield()->Tag() != TYPE_INTERVAL )
			{
			Error("&expire_func must yield a value of type interval");
			break;
			}

		const TableType* the_table = type->AsTableType();

		if (the_table->IsUnspecifiedTable())
			break;

		const auto& func_index_types = e_ft->ArgTypes()->Types();
		// Keep backwards compatibility with idx: any idiom.
		if ( func_index_types.size() == 2 )
			{
			if (func_index_types[1]->Tag() == TYPE_ANY)
				break;
			}

		const auto& table_index_types = the_table->IndexTypes();

		type_list expected_args(1 + static_cast<int>(table_index_types.size()));
		expected_args.push_back(type->AsTableType());

		for ( const auto& t : table_index_types )
			expected_args.push_back(t.get());

		if ( ! e_ft->CheckArgs(&expected_args) )
			Error("&expire_func argument type clash");
		}
		break;

	case ATTR_ON_CHANGE:
		{
		if ( type->Tag() != TYPE_TABLE )
			{
			Error("&on_change only applicable to tables");
			break;
			}

		const Expr* change_func = a->AttrExpr();

		if ( change_func->GetType()->Tag() != TYPE_FUNC || change_func->GetType()->AsFuncType()->Flavor() != FUNC_FLAVOR_FUNCTION )
			Error("&on_change attribute is not a function");

		const FuncType* c_ft = change_func->GetType()->AsFuncType();

		if ( c_ft->Yield()->Tag() != TYPE_VOID )
			{
			Error("&on_change must not return a value");
			break;
			}

		const TableType* the_table = type->AsTableType();

		if ( the_table->IsUnspecifiedTable() )
			break;

		const auto& args = c_ft->ArgTypes()->Types();
		const auto& t_indexes = the_table->IndexTypes();
		if ( args.size() != ( type->IsSet() ? 2 : 3 ) + t_indexes.size() )
			{
			Error("&on_change function has incorrect number of arguments");
			break;
			}

		if ( ! same_type(args[0].get(), the_table->AsTableType()) )
			{
			Error("&on_change: first argument must be of same type as table");
			break;
			}

		// can't check exact type here yet - the data structures don't exist yet.
		if ( args[1]->Tag() != TYPE_ENUM )
			{
			Error("&on_change: second argument must be a TableChange enum");
			break;
			}

		for ( size_t i = 0; i < t_indexes.size(); i++ )
			{
			if ( ! same_type(args[2+i].get(), t_indexes[i].get()) )
				{
				Error("&on_change: index types do not match table");
				break;
				}
			}

		if ( ! type->IsSet() )
			if ( ! same_type(args[2+t_indexes.size()].get(), the_table->Yield().get()) )
				{
				Error("&on_change: value type does not match table");
				break;
				}
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
		if ( ! threading::Value::IsCompatibleType(type.get()) )
			Error("&log applied to a type that cannot be logged");
		break;

	case ATTR_TYPE_COLUMN:
		{
		if ( type->Tag() != TYPE_PORT )
			{
			Error("type_column tag only applicable to ports");
			break;
			}

		const auto& atype = a->AttrExpr()->GetType();

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
