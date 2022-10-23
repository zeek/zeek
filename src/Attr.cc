// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Attr.h"

#include "zeek/zeek-config.h"

#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Val.h"
#include "zeek/input/Manager.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek::detail
	{

const char* attr_name(AttrTag t)
	{
	static const char* attr_names[int(NUM_ATTRS)] = {
		"&optional",
		"&default",
		"&redef",
		"&add_func",
		"&delete_func",
		"&expire_func",
		"&read_expire",
		"&write_expire",
		"&create_expire",
		"&raw_output",
		"&priority",
		"&group",
		"&log",
		"&error_handler",
		"&type_column",
		"(&tracked)",
		"&on_change",
		"&broker_store",
		"&broker_allow_complex_type",
		"&backend",
		"&deprecated",
		"&is_assigned",
		"&is_used",
		"&ordered",
	};

	return attr_names[int(t)];
	}

Attr::Attr(AttrTag t, ExprPtr e) : expr(std::move(e))
	{
	tag = t;
	SetLocationInfo(&start_location, &end_location);
	}

Attr::Attr(AttrTag t) : Attr(t, nullptr) { }

void Attr::SetAttrExpr(ExprPtr e)
	{
	expr = std::move(e);
	}

std::string Attr::DeprecationMessage() const
	{
	if ( tag != ATTR_DEPRECATED )
		return "";

	if ( ! expr )
		return "";

	auto ce = static_cast<ConstExpr*>(expr.get());
	return ce->Value()->AsStringVal()->CheckString();
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
		d->Add(static_cast<zeek_int_t>(Tag()));
	else
		d->Add(attr_name(Tag()));
	}

detail::TraversalCode Attr::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreAttr(this);
	HANDLE_TC_ATTR_PRE(tc);

	if ( expr )
		{
		auto tc = expr->Traverse(cb);
		HANDLE_TC_ATTR_PRE(tc);
		}

	tc = cb->PostAttr(this);
	HANDLE_TC_ATTR_POST(tc);
	}

Attributes::Attributes(TypePtr t, bool arg_in_record, bool is_global)
	: Attributes(std::vector<AttrPtr>{}, std::move(t), arg_in_record, is_global)
	{
	}

Attributes::Attributes(std::vector<AttrPtr> a, TypePtr t, bool arg_in_record, bool is_global)
	: type(std::move(t))
	{
	attrs.reserve(a.size());
	in_record = arg_in_record;
	global_var = is_global;

	SetLocationInfo(&start_location, &end_location);

	// We loop through 'a' and add each attribute individually,
	// rather than just taking over 'a' for ourselves, so that
	// the necessary checking gets done.

	for ( auto& attr : a )
		AddAttr(std::move(attr));
	}

void Attributes::AddAttr(AttrPtr attr, bool is_redef)
	{
	auto acceptable_duplicate_attr = [](const AttrPtr& attr, const AttrPtr& existing) -> bool
	{
		if ( attr == existing )
			return true;

		AttrTag new_tag = attr->Tag();

		if ( new_tag == ATTR_DEPRECATED )
			{
			if ( ! attr->DeprecationMessage().empty() ||
			     (existing && ! existing->DeprecationMessage().empty()) )
				return false;

			return true;
			}

		return new_tag == ATTR_LOG || new_tag == ATTR_OPTIONAL || new_tag == ATTR_REDEF ||
		       new_tag == ATTR_BROKER_STORE_ALLOW_COMPLEX || new_tag == ATTR_RAW_OUTPUT ||
		       new_tag == ATTR_ERROR_HANDLER;
	};

	// A `redef` is allowed to overwrite an existing attribute instead of
	// flagging it as ambiguous.
	if ( ! is_redef )
		{
		auto existing = Find(attr->Tag());
		if ( existing && ! acceptable_duplicate_attr(attr, existing) )
			reporter->Error("Duplicate %s attribute is ambiguous", attr_name(attr->Tag()));
		}

	// We overwrite old attributes by deleting them first.
	RemoveAttr(attr->Tag());
	attrs.emplace_back(attr);

	// We only check the attribute after we've added it, to facilitate
	// generating error messages via Attributes::Describe.  If the
	// instantiator of the object specified a null type, however, then
	// that's a signal to skip the checking.
	if ( type )
		CheckAttr(attr.get());

	// For ADD_FUNC or DEL_FUNC, add in an implicit REDEF, since
	// those attributes only have meaning for a redefinable value.
	if ( (attr->Tag() == ATTR_ADD_FUNC || attr->Tag() == ATTR_DEL_FUNC) && ! Find(ATTR_REDEF) )
		{
		auto a = make_intrusive<Attr>(ATTR_REDEF);
		attrs.emplace_back(std::move(a));
		}

	// For DEFAULT, add an implicit OPTIONAL if it's not a global.
	if ( ! global_var && attr->Tag() == ATTR_DEFAULT && ! Find(ATTR_OPTIONAL) )
		{
		auto a = make_intrusive<Attr>(ATTR_OPTIONAL);
		attrs.emplace_back(std::move(a));
		}
	}

void Attributes::AddAttrs(const AttributesPtr& a, bool is_redef)
	{
	for ( const auto& attr : a->GetAttrs() )
		AddAttr(attr, is_redef);
	}

const AttrPtr& Attributes::Find(AttrTag t) const
	{
	for ( const auto& a : attrs )
		if ( a->Tag() == t )
			return a;

	return Attr::nil;
	}

void Attributes::RemoveAttr(AttrTag t)
	{
	for ( auto it = attrs.begin(); it != attrs.end(); )
		{
		if ( (*it)->Tag() == t )
			it = attrs.erase(it);
		else
			++it;
		}
	}

void Attributes::Describe(ODesc* d) const
	{
	if ( attrs.empty() )
		{
		d->AddCount(0);
		return;
		}

	d->AddCount(static_cast<uint64_t>(attrs.size()));

	for ( size_t i = 0; i < attrs.size(); ++i )
		{
		if ( d->IsReadable() && i > 0 )
			d->Add(", ");

		attrs[i]->Describe(d);
		}
	}

void Attributes::DescribeReST(ODesc* d, bool shorten) const
	{
	for ( size_t i = 0; i < attrs.size(); ++i )
		{
		if ( i > 0 )
			d->Add(" ");

		attrs[i]->DescribeReST(d, shorten);
		}
	}

void Attributes::CheckAttr(Attr* a)
	{
	switch ( a->Tag() )
		{
		case ATTR_DEPRECATED:
		case ATTR_REDEF:
		case ATTR_IS_ASSIGNED:
		case ATTR_IS_USED:
			break;

		case ATTR_OPTIONAL:
			if ( global_var )
				Error("&optional is not valid for global variables");
			break;

		case ATTR_ADD_FUNC:
		case ATTR_DEL_FUNC:
			{
			bool is_add = a->Tag() == ATTR_ADD_FUNC;

			const auto& at = a->GetExpr()->GetType();
			if ( at->Tag() != TYPE_FUNC )
				{
				a->GetExpr()->Error(is_add ? "&add_func must be a function"
				                           : "&delete_func must be a function");
				break;
				}

			FuncType* aft = at->AsFuncType();
			if ( ! same_type(aft->Yield(), type) )
				{
				a->GetExpr()->Error(is_add
				                        ? "&add_func function must yield same type as variable"
				                        : "&delete_func function must yield same type as variable");
				break;
				}
			}
			break;

		case ATTR_DEFAULT:
			{
			std::string err_msg;
			if ( ! check_default_attr(a, type, global_var, in_record, err_msg) &&
			     ! err_msg.empty() )
				Error(err_msg.c_str());
			break;
			}

		case ATTR_EXPIRE_READ:
			{
			if ( Find(ATTR_BROKER_STORE) )
				Error("&broker_store and &read_expire cannot be used simultaneously");

			if ( Find(ATTR_BACKEND) )
				Error("&backend and &read_expire cannot be used simultaneously");
			}
			// fallthrough

		case ATTR_EXPIRE_WRITE:
		case ATTR_EXPIRE_CREATE:
			{
			if ( type->Tag() != TYPE_TABLE )
				{
				Error("expiration only applicable to sets/tables");
				break;
				}

			int num_expires = 0;

			for ( const auto& a : attrs )
				{
				if ( a->Tag() == ATTR_EXPIRE_READ || a->Tag() == ATTR_EXPIRE_WRITE ||
				     a->Tag() == ATTR_EXPIRE_CREATE )
					num_expires++;
				}

			if ( num_expires > 1 )
				{
				Error("set/table can only have one of &read_expire, &write_expire, "
				      "&create_expire");
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

			type->AsTableType()->CheckExpireFuncCompatibility({NewRef{}, a});

			if ( Find(ATTR_BROKER_STORE) )
				Error("&broker_store and &expire_func cannot be used simultaneously");

			if ( Find(ATTR_BACKEND) )
				Error("&backend and &expire_func cannot be used simultaneously");

			break;
			}

		case ATTR_ON_CHANGE:
			{
			if ( type->Tag() != TYPE_TABLE )
				{
				Error("&on_change only applicable to sets/tables");
				break;
				}

			const auto& change_func = a->GetExpr();

			if ( change_func->GetType()->Tag() != TYPE_FUNC ||
			     change_func->GetType()->AsFuncType()->Flavor() != FUNC_FLAVOR_FUNCTION )
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

			const auto& args = c_ft->ParamList()->GetTypes();
			const auto& t_indexes = the_table->GetIndexTypes();
			if ( args.size() != (type->IsSet() ? 2 : 3) + t_indexes.size() )
				{
				Error("&on_change function has incorrect number of arguments");
				break;
				}

			if ( ! same_type(args[0], the_table->AsTableType()) )
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
				if ( ! same_type(args[2 + i], t_indexes[i]) )
					{
					Error("&on_change: index types do not match table");
					break;
					}
				}

			if ( ! type->IsSet() )
				if ( ! same_type(args[2 + t_indexes.size()], the_table->Yield()) )
					{
					Error("&on_change: value type does not match table");
					break;
					}
			}
			break;

		case ATTR_BACKEND:
			{
			if ( ! global_var || type->Tag() != TYPE_TABLE )
				{
				Error("&backend only applicable to global sets/tables");
				break;
				}

			// cannot do better equality check - the Broker types are not
			// actually existing yet when we are here. We will do that
			// later - before actually attaching to a broker store
			if ( a->GetExpr()->GetType()->Tag() != TYPE_ENUM )
				{
				Error("&backend must take an enum argument");
				break;
				}

			// Only support atomic types for the moment, unless
			// explicitly overridden
			if ( ! type->AsTableType()->IsSet() &&
			     ! input::Manager::IsCompatibleType(type->AsTableType()->Yield().get(), true) &&
			     ! Find(ATTR_BROKER_STORE_ALLOW_COMPLEX) )
				{
				Error("&backend only supports atomic types as table value");
				}

			if ( Find(ATTR_EXPIRE_FUNC) )
				Error("&backend and &expire_func cannot be used simultaneously");

			if ( Find(ATTR_EXPIRE_READ) )
				Error("&backend and &read_expire cannot be used simultaneously");

			if ( Find(ATTR_BROKER_STORE) )
				Error("&backend and &broker_store cannot be used simultaneously");

			break;
			}

		case ATTR_BROKER_STORE:
			{
			if ( type->Tag() != TYPE_TABLE )
				{
				Error("&broker_store only applicable to sets/tables");
				break;
				}

			if ( a->GetExpr()->GetType()->Tag() != TYPE_STRING )
				{
				Error("&broker_store must take a string argument");
				break;
				}

			// Only support atomic types for the moment, unless
			// explicitly overridden
			if ( ! type->AsTableType()->IsSet() &&
			     ! input::Manager::IsCompatibleType(type->AsTableType()->Yield().get(), true) &&
			     ! Find(ATTR_BROKER_STORE_ALLOW_COMPLEX) )
				{
				Error("&broker_store only supports atomic types as table value");
				}

			if ( Find(ATTR_EXPIRE_FUNC) )
				Error("&broker_store and &expire_func cannot be used simultaneously");

			if ( Find(ATTR_EXPIRE_READ) )
				Error("&broker_store and &read_expire cannot be used simultaneously");

			if ( Find(ATTR_BACKEND) )
				Error("&backend and &broker_store cannot be used simultaneously");

			break;
			}

		case ATTR_BROKER_STORE_ALLOW_COMPLEX:
			{
			if ( type->Tag() != TYPE_TABLE )
				{
				Error("&broker_allow_complex_type only applicable to sets/tables");
				break;
				}
			}

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
			if ( type->Tag() != TYPE_FUNC || type->AsFuncType()->Flavor() != FUNC_FLAVOR_EVENT )
				Error("&group only applicable to events");
			break;

		case ATTR_ERROR_HANDLER:
			if ( type->Tag() != TYPE_FUNC || type->AsFuncType()->Flavor() != FUNC_FLAVOR_EVENT )
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

			const auto& atype = a->GetExpr()->GetType();

			if ( atype->Tag() != TYPE_STRING )
				{
				Error("type column needs to have a string argument");
				break;
				}

			break;
			}

		case ATTR_ORDERED:
			if ( type->Tag() != TYPE_TABLE )
				Error("&ordered only applicable to tables");
			break;

		default:
			BadTag("Attributes::CheckAttr", attr_name(a->Tag()));
		}
	}

bool Attributes::operator==(const Attributes& other) const
	{
	if ( attrs.empty() )
		return other.attrs.empty();

	if ( other.attrs.empty() )
		return false;

	for ( const auto& a : attrs )
		{
		const auto& o = other.Find(a->Tag());

		if ( ! o )
			return false;

		if ( ! (*a == *o) )
			return false;
		}

	for ( const auto& o : other.attrs )
		{
		const auto& a = Find(o->Tag());

		if ( ! a )
			return false;

		if ( ! (*a == *o) )
			return false;
		}

	return true;
	}

bool check_default_attr(Attr* a, const TypePtr& type, bool global_var, bool in_record,
                        std::string& err_msg)
	{
	// &default is allowed for global tables, since it's used in
	// initialization of table fields. It's not allowed otherwise.
	if ( global_var && ! type->IsTable() )
		{
		err_msg = "&default is not valid for global variables except for tables";
		return false;
		}

	const auto& atype = a->GetExpr()->GetType();

	if ( type->Tag() != TYPE_TABLE || (type->IsSet() && ! in_record) )
		{
		if ( same_type(atype, type) )
			// Ok.
			return true;

		// Record defaults may be promotable.
		if ( (type->Tag() == TYPE_RECORD && atype->Tag() == TYPE_RECORD &&
		      record_promotion_compatible(atype->AsRecordType(), type->AsRecordType())) )
			// Ok.
			return true;

		if ( type->Tag() == TYPE_TABLE && type->AsTableType()->IsUnspecifiedTable() )
			// Ok.
			return true;

		auto e = check_and_promote_expr(a->GetExpr(), type);

		if ( e )
			{
			a->SetAttrExpr(std::move(e));
			// Ok.
			return true;
			}

		a->GetExpr()->Error("&default value has inconsistent type", type.get());
		return false;
		}

	TableType* tt = type->AsTableType();
	const auto& ytype = tt->Yield();

	if ( ! in_record )
		{ // &default applies to the type itself.
		if ( same_type(atype, ytype) )
			return true;

		// It can still be a default function.
		if ( atype->Tag() == TYPE_FUNC )
			{
			FuncType* f = atype->AsFuncType();
			if ( ! f->CheckArgs(tt->GetIndexTypes()) || ! same_type(f->Yield(), ytype) )
				{
				err_msg = "&default function type clash";
				return false;
				}

			// Ok.
			return true;
			}

		// Table defaults may be promotable.
		if ( (ytype->Tag() == TYPE_RECORD && atype->Tag() == TYPE_RECORD &&
		      record_promotion_compatible(atype->AsRecordType(), ytype->AsRecordType())) )
			// Ok.
			return true;

		auto e = check_and_promote_expr(a->GetExpr(), ytype);

		if ( e )
			{
			a->SetAttrExpr(std::move(e));
			// Ok.
			return true;
			}

		err_msg = "&default value has inconsistent type";
		return false;
		}

	// &default applies to record field.

	if ( same_type(atype, type) )
		return true;

	if ( (atype->Tag() == TYPE_TABLE && atype->AsTableType()->IsUnspecifiedTable()) )
		{
		auto e = check_and_promote_expr(a->GetExpr(), type);

		if ( e )
			{
			a->SetAttrExpr(std::move(e));
			return true;
			}
		}

	// Table defaults may be promotable.
	if ( ytype && ytype->Tag() == TYPE_RECORD && atype->Tag() == TYPE_RECORD &&
	     record_promotion_compatible(atype->AsRecordType(), ytype->AsRecordType()) )
		// Ok.
		return true;

	err_msg = "&default value has inconsistent type";
	return false;
	}

detail::TraversalCode Attributes::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreAttrs(this);
	HANDLE_TC_ATTRS_PRE(tc);

	for ( const auto& a : attrs )
		{
		tc = a->Traverse(cb);
		HANDLE_TC_ATTRS_PRE(tc);
		}

	tc = cb->PostAttrs(this);
	HANDLE_TC_ATTRS_POST(tc);
	}

	}
