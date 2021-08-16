
// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/ID.h"

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Dict.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"
#include "zeek/Type.h"
#include "zeek/File.h"
#include "zeek/Traverse.h"
#include "zeek/Val.h"
#include "zeek/zeekygen/Manager.h"
#include "zeek/zeekygen/IdentifierInfo.h"
#include "zeek/zeekygen/ScriptInfo.h"
#include "zeek/zeekygen/utils.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek {

RecordTypePtr id::conn_id;
RecordTypePtr id::endpoint;
RecordTypePtr id::connection;
RecordTypePtr id::fa_file;
RecordTypePtr id::fa_metadata;
EnumTypePtr id::transport_proto;
TableTypePtr id::string_set;
TableTypePtr id::string_array;
TableTypePtr id::count_set;
VectorTypePtr id::string_vec;
VectorTypePtr id::index_vec;

const detail::IDPtr& id::find(std::string_view name)
	{
	return zeek::detail::global_scope()->Find(name);
	}

const TypePtr& id::find_type(std::string_view name)
	{
	auto id = zeek::detail::global_scope()->Find(name);

	if ( ! id )
		reporter->InternalError("Failed to find type named: %s",
		                              std::string(name).data());

	return id->GetType();
	}

const ValPtr& id::find_val(std::string_view name)
	{
	auto id = zeek::detail::global_scope()->Find(name);

	if ( ! id )
		reporter->InternalError("Failed to find variable named: %s",
		                              std::string(name).data());

	return id->GetVal();
	}

const ValPtr& id::find_const(std::string_view name)
	{
	auto id = zeek::detail::global_scope()->Find(name);

	if ( ! id )
		reporter->InternalError("Failed to find variable named: %s",
		                              std::string(name).data());

	if ( ! id->IsConst() )
		reporter->InternalError("Variable is not 'const', but expected to be: %s",
		                              std::string(name).data());

	return id->GetVal();
	}

FuncPtr id::find_func(std::string_view name)
	{
	const auto& v = id::find_val(name);

	if ( ! v )
		return nullptr;

	if ( ! IsFunc(v->GetType()->Tag()) )
		reporter->InternalError("Expected variable '%s' to be a function",
		                              std::string(name).data());

	return v.get()->As<FuncVal*>()->AsFuncPtr();
	}

void id::detail::init_types()
	{
	conn_id = id::find_type<RecordType>("conn_id");
	endpoint = id::find_type<RecordType>("endpoint");
	connection = id::find_type<RecordType>("connection");
	fa_file = id::find_type<RecordType>("fa_file");
	fa_metadata = id::find_type<RecordType>("fa_metadata");
	transport_proto = id::find_type<EnumType>("transport_proto");
	string_set = id::find_type<TableType>("string_set");
	string_array = id::find_type<TableType>("string_array");
	count_set = id::find_type<TableType>("count_set");
	string_vec = id::find_type<VectorType>("string_vec");
	index_vec = id::find_type<VectorType>("index_vec");
	}

namespace detail {

ID::ID(const char* arg_name, IDScope arg_scope, bool arg_is_export)
	{
	name = util::copy_string(arg_name);
	scope = arg_scope;
	is_export = arg_is_export;
	is_option = false;
	is_const = false;
	is_enum_const = false;
	is_type = false;
	offset = 0;

	opt_info = new IDOptInfo(this);

	infer_return_type = false;

	SetLocationInfo(&start_location, &end_location);
	}

ID::~ID()
	{
	delete [] name;
	delete opt_info;
	}

std::string ID::ModuleName() const
	{
	return extract_module_name(name);
	}

void ID::SetType(TypePtr t)
	{
	type = std::move(t);
	}

void ID::ClearVal()
	{
	val = nullptr;
	}

void ID::SetVal(ValPtr v)
	{
	val = std::move(v);
	Modified();

#ifdef DEBUG
	UpdateValID();
#endif

	if ( type && val &&
	     type->Tag() == TYPE_FUNC &&
	     type->AsFuncType()->Flavor() == FUNC_FLAVOR_EVENT )
		{
		EventHandler* handler = event_registry->Lookup(name);
		auto func = val.get()->As<FuncVal*>()->AsFuncPtr();
		if ( ! handler )
			{
			handler = new EventHandler(name);
			handler->SetFunc(func);
			event_registry->Register(handler);
			}
		else
			{
			// Otherwise, internally defined events cannot
			// have local handler.
			handler->SetFunc(func);
			}
		}
	}

void ID::SetVal(ValPtr v, InitClass c)
	{
	if ( c == INIT_NONE || c == INIT_FULL )
		{
		SetVal(std::move(v));
		return;
		}

	if ( type->Tag() != TYPE_TABLE &&
	     (type->Tag() != TYPE_PATTERN || c == INIT_REMOVE) &&
	     (type->Tag() != TYPE_VECTOR  || c == INIT_REMOVE) )
		{
		if ( c == INIT_EXTRA )
			Error("+= initializer only applies to tables, sets, vectors and patterns", v.get());
		else
			Error("-= initializer only applies to tables and sets", v.get());
		}

	else
		{
		if ( c == INIT_EXTRA )
			{
			if ( ! val )
				{
				SetVal(std::move(v));
				return;
				}
			else
				v->AddTo(val.get(), false);
			}
		else
			{
			if ( val )
				v->RemoveFrom(val.get());
			}
		}
	}

void ID::SetVal(ExprPtr ev, InitClass c)
	{
	const auto& a = attrs->Find(c == INIT_EXTRA ? ATTR_ADD_FUNC : ATTR_DEL_FUNC);

	if ( ! a )
		Internal("no add/delete function in ID::SetVal");

	if ( ! val )
		{
		Error(zeek::util::fmt("%s initializer applied to ID without value",
		                      c == INIT_EXTRA ? "+=" : "-="), this);
		return;
		}

	EvalFunc(a->GetExpr(), std::move(ev));
	}

bool ID::IsRedefinable() const
	{
	return GetAttr(ATTR_REDEF) != nullptr;
	}

void ID::SetAttrs(AttributesPtr a)
	{
	attrs = nullptr;
	AddAttrs(std::move(a));
	}

void ID::UpdateValAttrs()
	{
	if ( ! attrs )
		return;

	if ( val && val->GetType()->Tag() == TYPE_TABLE )
		val->AsTableVal()->SetAttrs(attrs);

	if ( val && val->GetType()->Tag() == TYPE_FILE )
		val->AsFile()->SetAttrs(attrs.get());

	if ( GetType()->Tag() == TYPE_FUNC )
		{
		const auto& attr = attrs->Find(ATTR_ERROR_HANDLER);

		if ( attr )
			event_registry->SetErrorHandler(Name());
		}

	if ( GetType()->Tag() == TYPE_RECORD )
		{
		const auto& attr = attrs->Find(ATTR_LOG);

		if ( attr )
			{
			// Apply &log to all record fields.
			RecordType* rt = GetType()->AsRecordType();
			for ( int i = 0; i < rt->NumFields(); ++i )
				{
				TypeDecl* fd = rt->FieldDecl(i);

				if ( ! fd->attrs )
					fd->attrs = make_intrusive<Attributes>(rt->GetFieldType(i), true, IsGlobal());

				fd->attrs->AddAttr(make_intrusive<Attr>(ATTR_LOG));
				}
			}
		}
	}

const AttrPtr& ID::GetAttr(AttrTag t) const
	{
	return attrs ? attrs->Find(t) : Attr::nil;
	}

bool ID::IsDeprecated() const
	{
	return GetAttr(ATTR_DEPRECATED) != nullptr;
	}

void ID::MakeDeprecated(ExprPtr deprecation)
	{
	if ( IsDeprecated() )
		return;

	std::vector<AttrPtr> attrv{make_intrusive<Attr>(ATTR_DEPRECATED, std::move(deprecation))};
	AddAttrs(make_intrusive<Attributes>(std::move(attrv), GetType(), false, IsGlobal()));
	}

std::string ID::GetDeprecationWarning() const
	{
	std::string result;
	const auto& depr_attr = GetAttr(ATTR_DEPRECATED);

	if ( depr_attr )
		result = depr_attr->DeprecationMessage();

	if ( result.empty() )
		return util::fmt("deprecated (%s)", Name());
	else
		return util::fmt("deprecated (%s): %s", Name(), result.c_str());
	}

void ID::AddAttrs(AttributesPtr a, bool is_redef)
	{
	if ( attrs )
		attrs->AddAttrs(a, is_redef);
	else
		attrs = std::move(a);

	UpdateValAttrs();
	}

void ID::RemoveAttr(AttrTag a)
	{
	if ( attrs )
		attrs->RemoveAttr(a);
	}

void ID::SetOption()
	{
	if ( is_option )
		return;

	is_option = true;

	// option implied redefinable
	if ( ! IsRedefinable() )
		{
		std::vector<AttrPtr> attrv{make_intrusive<Attr>(ATTR_REDEF)};
		AddAttrs(make_intrusive<Attributes>(std::move(attrv), GetType(), false, IsGlobal()));
		}
	}

void ID::EvalFunc(ExprPtr ef, ExprPtr ev)
	{
	auto arg1 = make_intrusive<detail::ConstExpr>(val);
	auto args = make_intrusive<detail::ListExpr>();
	args->Append(std::move(arg1));
	args->Append(std::move(ev));
	auto ce = make_intrusive<CallExpr>(std::move(ef), std::move(args));
	SetVal(ce->Eval(nullptr));
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
	else if ( val && IsFunc(val->GetType()->Tag()) &&
		  cb->current_scope == detail::global_scope() )
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

void ID::Error(const char* msg, const Obj* o2)
	{
	Obj::Error(msg, o2, true);
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
		attrs->DescribeReST(d, true);
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

		if ( auto sc = zeek::zeekygen::detail::source_code_range(this) )
			{
			d->PushIndent();
			d->Add(util::fmt(":source-code: %s", sc->data()));
			d->PopIndentNoNL();
			}
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
			{
			type->DescribeReST(d, roles_only);

			if ( IsFunc(type->Tag()) )
				{
				auto ft = type->AsFuncType();

				if ( ft->Flavor() == FUNC_FLAVOR_EVENT ||
				     ft->Flavor() == FUNC_FLAVOR_HOOK )
					{
					const auto& protos = ft->Prototypes();

					if ( protos.size() > 1 )
						{
						auto first = true;

						for ( const auto& proto : protos )
							{
							if ( first )
								{
								first = false;
								continue;
								}

							d->NL();
							d->Add(":Type: :zeek:type:`");
							d->Add(ft->FlavorString());
							d->Add("` (");
							proto.args->DescribeFieldsReST(d, true);
							d->Add(")");
							}
						}
					}
				}
			}

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
		auto ii = zeekygen_mgr->GetIdentifierInfo(Name());
		auto redefs = ii->GetRedefs();
		const auto& iv = ! redefs.empty() && ii->InitialVal() ? ii->InitialVal()
			                                                  : val;

		if ( type->InternalType() == TYPE_INTERNAL_OTHER )
			{
			switch ( type->Tag() ) {
			case TYPE_TABLE:
				if ( iv->AsTable()->Length() == 0 )
					{
					d->Add(" ``{}``");
					d->NL();
					break;
					}
				// Fall-through.

			default:
				d->NL();
				d->PushIndent();
				d->Add("::");
				d->NL();
				d->PushIndent();
				iv->DescribeReST(d);
				d->PopIndent();
				d->PopIndent();
			}
			}

		else
			{
			d->SP();
			iv->DescribeReST(d);
			d->NL();
			}

		for ( auto& ir : redefs )
			{
			if ( ! ir->init_expr )
				continue;

			if ( ir->ic == INIT_NONE )
				continue;

			std::string redef_str;
			ODesc expr_desc;
			ir->init_expr->Describe(&expr_desc);
			redef_str = expr_desc.Description();
			redef_str = util::strreplace(redef_str, "\n", " ");

			d->Add(":Redefinition: ");
			d->Add(util::fmt("from :doc:`/scripts/%s`", ir->from_script.data()));
			d->NL();
			d->PushIndent();

			if ( ir->ic == INIT_FULL )
				d->Add("``=``");
			else if ( ir->ic == INIT_EXTRA )
				d->Add("``+=``");
			else if ( ir->ic == INIT_REMOVE )
				d->Add("``-=``");
			else
				assert(false);

			d->Add("::");
			d->NL();
			d->PushIndent();
			d->Add(redef_str.data());
			d->PopIndent();
			d->PopIndent();
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

void ID::AddOptionHandler(FuncPtr callback, int priority)
	{
	option_handlers.emplace(priority, std::move(callback));
	}

std::vector<Func*> ID::GetOptionHandlers() const
	{
	// multimap is sorted
	// It might be worth caching this if we expect it to be called
	// a lot...
	std::vector<Func*> v;
	for ( auto& element : option_handlers )
		v.push_back(element.second.get());
	return v;
	}


void IDOptInfo::AddInitExpr(ExprPtr init_expr)
	{
	init_exprs.emplace_back(std::move(init_expr));
	}

} // namespace detail

} // namespace zeek
