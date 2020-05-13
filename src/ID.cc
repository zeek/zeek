// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "ID.h"
#include "Attr.h"
#include "Desc.h"
#include "Expr.h"
#include "Dict.h"
#include "EventRegistry.h"
#include "Func.h"
#include "Scope.h"
#include "Type.h"
#include "File.h"
#include "Traverse.h"
#include "Val.h"
#include "zeekygen/Manager.h"
#include "zeekygen/IdentifierInfo.h"
#include "zeekygen/ScriptInfo.h"
#include "module_util.h"

IntrusivePtr<RecordType> zeek::id::conn_id;
IntrusivePtr<RecordType> zeek::id::endpoint;
IntrusivePtr<RecordType> zeek::id::connection;
IntrusivePtr<RecordType> zeek::id::fa_file;
IntrusivePtr<RecordType> zeek::id::fa_metadata;
IntrusivePtr<EnumType> zeek::id::transport_proto;
IntrusivePtr<TableType> zeek::id::string_set;
IntrusivePtr<TableType> zeek::id::string_array;
IntrusivePtr<TableType> zeek::id::count_set;
IntrusivePtr<VectorType> zeek::id::string_vec;
IntrusivePtr<VectorType> zeek::id::index_vec;

const IntrusivePtr<ID>& zeek::id::lookup(std::string_view name)
	{
	return global_scope()->Find(name);
	}

const IntrusivePtr<BroType>& zeek::id::lookup_type(std::string_view name)
	{
	auto id = global_scope()->Find(name);

	if ( ! id )
		reporter->InternalError("Failed to find type named: %s",
		                        std::string(name).data());

	return id->GetType();
	}

const IntrusivePtr<Val>& zeek::id::lookup_val(std::string_view name)
	{
	auto id = global_scope()->Find(name);

	if ( ! id )
		reporter->InternalError("Failed to find variable named: %s",
		                        std::string(name).data());

	return id->GetVal();
	}

const IntrusivePtr<Val>& zeek::id::lookup_const(std::string_view name)
	{
	auto id = global_scope()->Find(name);

	if ( ! id )
		reporter->InternalError("Failed to find variable named: %s",
		                        std::string(name).data());

	if ( ! id->IsConst() )
		reporter->InternalError("Variable is not 'const', but expected to be: %s",
		                        std::string(name).data());

	return id->GetVal();
	}

IntrusivePtr<Func> zeek::id::lookup_func(std::string_view name)
	{
	const auto& v = zeek::id::lookup_val(name);

	if ( ! v )
		return nullptr;

	if ( ! IsFunc(v->GetType()->Tag()) )
		reporter->InternalError("Expected variable '%s' to be a function",
		                        std::string(name).data());

	return {NewRef{}, v->AsFunc()};
	}

void zeek::id::detail::init()
	{
	conn_id = lookup_type<RecordType>("conn_id");
	endpoint = lookup_type<RecordType>("endpoint");
	connection = lookup_type<RecordType>("connection");
	fa_file = lookup_type<RecordType>("fa_file");
	fa_metadata = lookup_type<RecordType>("fa_metadata");
	transport_proto = lookup_type<EnumType>("transport_proto");
	string_set = lookup_type<TableType>("string_set");
	string_array = lookup_type<TableType>("string_array");
	count_set = lookup_type<TableType>("count_set");
	string_vec = lookup_type<VectorType>("string_vec");
	index_vec = lookup_type<VectorType>("index_vec");
	}

ID::ID(const char* arg_name, IDScope arg_scope, bool arg_is_export)
	{
	name = copy_string(arg_name);
	scope = arg_scope;
	is_export = arg_is_export;
	is_option = false;
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

	if ( weak_ref )
		val.release();
	}

std::string ID::ModuleName() const
	{
	return extract_module_name(name);
	}

void ID::SetType(IntrusivePtr<BroType> t)
	{
	type = std::move(t);
	}

void ID::ClearVal()
	{
	if ( weak_ref )
		val.release();
	}

void ID::SetVal(IntrusivePtr<Val> v, bool arg_weak_ref)
	{
	if ( weak_ref )
		val.release();

	val = std::move(v);
	weak_ref = arg_weak_ref;
	Modified();

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

void ID::SetVal(IntrusivePtr<Val> v, init_class c)
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

void ID::SetVal(IntrusivePtr<Expr> ev, init_class c)
	{
	Attr* a = attrs->FindAttr(c == INIT_EXTRA ?
					ATTR_ADD_FUNC : ATTR_DEL_FUNC);

	if ( ! a )
		Internal("no add/delete function in ID::SetVal");

	EvalFunc({NewRef{}, a->AttrExpr()}, std::move(ev));
	}

bool ID::IsRedefinable() const
	{
	return FindAttr(ATTR_REDEF) != nullptr;
	}

void ID::SetAttrs(IntrusivePtr<Attributes> a)
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
		Attr* attr = attrs->FindAttr(ATTR_ERROR_HANDLER);

		if ( attr )
			event_registry->SetErrorHandler(Name());
		}

	if ( GetType()->Tag() == TYPE_RECORD )
		{
		Attr* attr = attrs->FindAttr(ATTR_LOG);
		if ( attr )
			{
			// Apply &log to all record fields.
			RecordType* rt = GetType()->AsRecordType();
			for ( int i = 0; i < rt->NumFields(); ++i )
				{
				TypeDecl* fd = rt->FieldDecl(i);

				if ( ! fd->attrs )
					fd->attrs = make_intrusive<Attributes>(new attr_list, rt->GetFieldType(i), true, IsGlobal());

				fd->attrs->AddAttr(make_intrusive<Attr>(ATTR_LOG));
				}
			}
		}
	}

Attr* ID::FindAttr(attr_tag t) const
	{
	return attrs ? attrs->FindAttr(t) : nullptr;
	}

bool ID::IsDeprecated() const
	{
	return FindAttr(ATTR_DEPRECATED) != nullptr;
	}

void ID::MakeDeprecated(IntrusivePtr<Expr> deprecation)
	{
	if ( IsDeprecated() )
		return;

	attr_list* attr = new attr_list{new Attr(ATTR_DEPRECATED, std::move(deprecation))};
	AddAttrs(make_intrusive<Attributes>(attr, GetType(), false, IsGlobal()));
	}

std::string ID::GetDeprecationWarning() const
	{
	std::string result;
	Attr* depr_attr = FindAttr(ATTR_DEPRECATED);
	if ( depr_attr )
		{
		ConstExpr* expr = static_cast<ConstExpr*>(depr_attr->AttrExpr());
		if ( expr )
			{
			StringVal* text = expr->Value()->AsStringVal();
			result = text->CheckString();
			}
		}

	if ( result.empty() )
		return fmt("deprecated (%s)", Name());
	else
		return fmt("deprecated (%s): %s", Name(), result.c_str());
	}

void ID::AddAttrs(IntrusivePtr<Attributes> a)
	{
	if ( attrs )
		attrs->AddAttrs(a.release());
	else
		attrs = std::move(a);

	UpdateValAttrs();
	}

void ID::RemoveAttr(attr_tag a)
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
		attr_list* attr = new attr_list{new Attr(ATTR_REDEF)};
		AddAttrs(make_intrusive<Attributes>(attr, GetType(), false, IsGlobal()));
		}
	}

void ID::EvalFunc(IntrusivePtr<Expr> ef, IntrusivePtr<Expr> ev)
	{
	auto arg1 = make_intrusive<ConstExpr>(val);
	auto args = make_intrusive<ListExpr>();
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
	BroObj::Error(msg, o2, true);
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
			redef_str = strreplace(redef_str, "\n", " ");

			d->Add(":Redefinition: ");
			d->Add(fmt("from :doc:`/scripts/%s`", ir->from_script.data()));
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

void ID::AddOptionHandler(IntrusivePtr<Func> callback, int priority)
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
